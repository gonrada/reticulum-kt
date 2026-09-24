package network.reticulum.android.blekiss

import android.Manifest
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCallback
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothProfile
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.util.Log
import androidx.core.content.ContextCompat
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import network.reticulum.interfaces.blekiss.BleKissProfile
import network.reticulum.interfaces.blekiss.NusLink
import java.util.UUID
import java.util.concurrent.atomic.AtomicInteger

/**
 * Android [NusLink] implementation — a single-peripheral GATT client for a KISS
 * TNC exposed over the Nordic UART Service (e.g. Muziworks R1 / MeshCore).
 *
 * This is the platform backend for `BleKissInterface`: it connects to one MAC,
 * discovers NUS, negotiates MTU, enables TX-characteristic notifications (surfaced
 * on [incoming]), and writes KISS frames to the RX characteristic in MTU-sized
 * chunks. Modeled on `BleGattClient` (same callback→coroutine bridging, API-33
 * compat, and permission checks) but reduced to the one connection `NusLink` owns.
 *
 * NOTE: Android BLE cannot be JVM-unit-tested; this is verified by compiling
 * `rns-android` and, ultimately, on a device/emulator (see the R1 emulation
 * harness in the parity plan).
 */
class AndroidNusLink(
    private val context: Context,
    private val bluetoothAdapter: BluetoothAdapter,
    private val address: String,
    private val scope: CoroutineScope = CoroutineScope(Dispatchers.Default + SupervisorJob()),
) : NusLink {

    companion object {
        // Profile-neutral log tag: this link now serves both NUS and KTS, so the
        // class-named "AndroidNusLink" read as a contradiction next to "profile KTS".
        private const val TAG = "AndroidBleKissLink"
        // Kept only as the initial default for the per-connection [activeTxUuid]; the
        // active profile (NUS or KTS) and its characteristics are resolved at connect
        // time via BleKissProfile auto-detection in setupConnection().
        private val TX_CHAR_UUID: UUID = UUID.fromString(NusLink.NUS_TX_CHAR_UUID)
        // Standard Client Characteristic Configuration Descriptor.
        private val CCCD_UUID: UUID = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")

        private const val REQUEST_MTU = 247
        private const val ATT_HEADER = 3
        private const val DEFAULT_MTU = 23
        private const val OP_TIMEOUT_MS = 5_000L
    }

    private val _incoming = MutableSharedFlow<ByteArray>(extraBufferCapacity = 64)
    override val incoming: Flow<ByteArray> = _incoming.asSharedFlow()

    private val _connected = MutableStateFlow(false)
    override val connected: StateFlow<Boolean> = _connected.asStateFlow()

    @Volatile private var gatt: BluetoothGatt? = null
    @Volatile private var rxCharacteristic: BluetoothGattCharacteristic? = null

    // Notify-characteristic UUID of the profile resolved at connect time (NUS or KTS).
    // Defaults to NUS; reassigned in setupConnection() before notifications are enabled,
    // and read by the Callback to route incoming notifications.
    @Volatile private var activeTxUuid: UUID = TX_CHAR_UUID
    @Volatile private var usableMtu = DEFAULT_MTU - ATT_HEADER

    private val writeMutex = Mutex()

    // Every connection attempt takes the next generation, and the callback object it
    // hands to connectGatt carries that generation for life. GATT callbacks arrive on a
    // binder thread and are not cancelled when a client is closed, so a late
    // onConnectionStateChange or onServicesDiscovered from an abandoned attempt can land
    // while a newer attempt is in flight — and every field below is shared between
    // attempts. Each callback therefore drops out unless its generation is still the
    // current one, and the connected branch re-checks after setup because setup suspends
    // for seconds. closeGatt() also advances the generation, so an abandoned attempt is
    // retired the moment it is closed.
    private val generation = AtomicInteger(0)

    private fun isCurrent(gen: Int): Boolean = generation.get() == gen

    // Callback → coroutine bridges (one operation in flight at a time each).
    @Volatile private var pendingReady: CompletableDeferred<Boolean>? = null
    @Volatile private var pendingServices: CompletableDeferred<Boolean>? = null
    @Volatile private var pendingMtu: CompletableDeferred<Unit>? = null
    @Volatile private var pendingWrite: CompletableDeferred<Int>? = null
    @Volatile private var pendingDescriptor: CompletableDeferred<Int>? = null

    private inner class Callback(private val gen: Int) : BluetoothGattCallback() {
        override fun onConnectionStateChange(gatt: BluetoothGatt, status: Int, newState: Int) {
            if (!isCurrent(gen)) return
            scope.launch {
                if (!isCurrent(gen)) return@launch
                when {
                    status == BluetoothGatt.GATT_SUCCESS && newState == BluetoothProfile.STATE_CONNECTED -> {
                        Log.d(TAG, "Connected to $address; discovering services")
                        val ok = setupConnection(gatt, gen)
                        if (!isCurrent(gen)) return@launch
                        _connected.value = ok
                        pendingReady?.complete(ok)
                        if (!ok) closeGatt()
                    }
                    newState == BluetoothProfile.STATE_DISCONNECTED -> {
                        Log.d(TAG, "Disconnected from $address (status $status)")
                        _connected.value = false
                        pendingReady?.complete(false)
                        closeGatt()
                    }
                }
            }
        }

        override fun onServicesDiscovered(gatt: BluetoothGatt, status: Int) {
            if (!isCurrent(gen)) return
            pendingServices?.complete(status == BluetoothGatt.GATT_SUCCESS)
        }

        override fun onMtuChanged(gatt: BluetoothGatt, mtu: Int, status: Int) {
            if (!isCurrent(gen)) return
            if (status == BluetoothGatt.GATT_SUCCESS) usableMtu = mtu - ATT_HEADER
            pendingMtu?.complete(Unit)
        }

        override fun onCharacteristicChanged(
            gatt: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic,
            value: ByteArray,
        ) {
            if (!isCurrent(gen)) return
            if (characteristic.uuid == activeTxUuid) _incoming.tryEmit(value)
        }

        @Suppress("DEPRECATION")
        @Deprecated("Needed for API < 33")
        override fun onCharacteristicChanged(
            gatt: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic,
        ) {
            if (!isCurrent(gen)) return
            if (characteristic.uuid == activeTxUuid) {
                characteristic.value?.let { _incoming.tryEmit(it) }
            }
        }

        override fun onCharacteristicWrite(
            gatt: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic,
            status: Int,
        ) {
            if (!isCurrent(gen)) return
            pendingWrite?.complete(status)
        }

        override fun onDescriptorWrite(
            gatt: BluetoothGatt,
            descriptor: BluetoothGattDescriptor,
            status: Int,
        ) {
            if (!isCurrent(gen)) return
            pendingDescriptor?.complete(status)
        }
    }

    override suspend fun connect(timeoutMs: Long): Boolean {
        if (!hasConnectPermission()) {
            Log.e(TAG, "Missing BLUETOOTH_CONNECT permission")
            return false
        }
        return try {
            val device = bluetoothAdapter.getRemoteDevice(address)
            val gen = generation.incrementAndGet()
            val ready = CompletableDeferred<Boolean>()
            pendingReady = ready
            val g = withContext(Dispatchers.Main) {
                device.connectGatt(context, false, Callback(gen), BluetoothDevice.TRANSPORT_LE)
            } ?: return false
            gatt = g
            val ok = withTimeoutOrNull(timeoutMs) { ready.await() } ?: false
            if (!ok) closeGatt()
            ok
        } catch (e: SecurityException) {
            Log.e(TAG, "Permission denied connecting to $address", e); false
        } catch (e: Exception) {
            Log.e(TAG, "Error connecting to $address", e); false
        }
    }

    /**
     * Discover NUS, negotiate MTU, enable TX notifications. @return true if ready.
     *
     * [gen] is the generation of the attempt this setup belongs to. Setup can suspend for
     * up to three operation timeouts, so it is re-checked at every resume point: once the
     * attempt is superseded, setup must stop writing the shared characteristic, MTU and
     * continuation fields that the newer attempt now owns.
     */
    private suspend fun setupConnection(g: BluetoothGatt, gen: Int): Boolean {
        return try {
            val services = CompletableDeferred<Boolean>()
            pendingServices = services
            withContext(Dispatchers.Main) { g.discoverServices() }
            if (withTimeoutOrNull(OP_TIMEOUT_MS) { services.await() } != true) return false
            if (!isCurrent(gen)) return false

            // Auto-detect the BLE-KISS profile the peripheral exposes (NUS or KTS) and
            // use that profile's characteristics — same transport, only the UUIDs differ.
            val resolved = BleKissProfile.DETECTION_ORDER.firstNotNullOfOrNull { profile ->
                val svc = g.getService(UUID.fromString(profile.serviceUuid)) ?: return@firstNotNullOfOrNull null
                val r = svc.getCharacteristic(UUID.fromString(profile.rxCharUuid)) ?: return@firstNotNullOfOrNull null
                val t = svc.getCharacteristic(UUID.fromString(profile.txCharUuid)) ?: return@firstNotNullOfOrNull null
                Triple(profile, r, t)
            } ?: return false
            val (profile, rx, tx) = resolved
            activeTxUuid = UUID.fromString(profile.txCharUuid)
            rxCharacteristic = rx
            Log.d(TAG, "Using BLE-KISS profile ${profile.name}")

            val mtu = CompletableDeferred<Unit>()
            pendingMtu = mtu
            withContext(Dispatchers.Main) { g.requestMtu(REQUEST_MTU) }
            withTimeoutOrNull(OP_TIMEOUT_MS) { mtu.await() } // usableMtu set in callback; ok if it times out
            if (!isCurrent(gen)) return false

            withContext(Dispatchers.Main) { g.setCharacteristicNotification(tx, true) }
            val cccd = tx.getDescriptor(CCCD_UUID) ?: return false
            val descWrite = CompletableDeferred<Int>()
            pendingDescriptor = descWrite
            withContext(Dispatchers.Main) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    g.writeDescriptor(cccd, BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE)
                } else {
                    @Suppress("DEPRECATION")
                    cccd.value = BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
                    @Suppress("DEPRECATION")
                    g.writeDescriptor(cccd)
                }
            }
            val status = withTimeoutOrNull(OP_TIMEOUT_MS) { descWrite.await() }
            isCurrent(gen) && status == BluetoothGatt.GATT_SUCCESS
        } catch (e: Exception) {
            Log.e(TAG, "Setup failed for $address", e); false
        }
    }

    override suspend fun write(frame: ByteArray): Boolean {
        val g = gatt ?: return false
        val rx = rxCharacteristic ?: return false
        if (!hasConnectPermission()) return false
        return writeMutex.withLock {
            var offset = 0
            val chunkSize = usableMtu.coerceAtLeast(DEFAULT_MTU - ATT_HEADER)
            while (offset < frame.size) {
                val end = minOf(offset + chunkSize, frame.size)
                val chunk = frame.copyOfRange(offset, end)
                val write = CompletableDeferred<Int>()
                pendingWrite = write
                try {
                    withContext(Dispatchers.Main) { writeCharacteristicCompat(g, rx, chunk) }
                } catch (e: Exception) {
                    Log.e(TAG, "Write error to $address", e); return@withLock false
                }
                val status = withTimeoutOrNull(OP_TIMEOUT_MS) { write.await() }
                if (status != BluetoothGatt.GATT_SUCCESS) return@withLock false
                offset = end
            }
            true
        }
    }

    override suspend fun close() {
        _connected.value = false
        closeGatt()
    }

    private fun closeGatt() {
        // Retire the attempt first: anything still in flight for it must stop before the
        // client goes away, whether or not there is a gatt left to close.
        generation.incrementAndGet()
        val g = gatt ?: return
        gatt = null
        rxCharacteristic = null
        try {
            if (hasConnectPermission()) {
                g.disconnect()
                g.close()
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error closing gatt for $address", e)
        }
    }

    @Suppress("DEPRECATION")
    private fun writeCharacteristicCompat(
        g: BluetoothGatt,
        characteristic: BluetoothGattCharacteristic,
        data: ByteArray,
    ) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            g.writeCharacteristic(characteristic, data, BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT)
        } else {
            characteristic.writeType = BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT
            characteristic.value = data
            g.writeCharacteristic(characteristic)
        }
    }

    private fun hasConnectPermission(): Boolean {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            ContextCompat.checkSelfPermission(
                context,
                Manifest.permission.BLUETOOTH_CONNECT,
            ) == PackageManager.PERMISSION_GRANTED
        } else {
            true
        }
    }
}
