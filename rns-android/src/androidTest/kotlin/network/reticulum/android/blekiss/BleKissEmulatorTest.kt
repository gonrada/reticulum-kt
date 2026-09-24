package network.reticulum.android.blekiss

import android.Manifest
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothManager
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanResult
import android.content.Context
import android.os.ParcelUuid
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.rule.GrantPermissionRule
import kotlinx.coroutines.runBlocking
import network.reticulum.interfaces.blekiss.BleKissInterface
import network.reticulum.interfaces.blekiss.NusLink
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import java.util.UUID
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * On-emulator integration test for the BLE-KISS path — the on-device equivalent of
 * the JVM `BleKissInterfaceTest` fake-link round-trip, but exercising the REAL
 * `AndroidNusLink` GATT client against a software NUS/KISS TNC.
 *
 * Requires the R1 emulation harness to be running (see tools/r1-emulation/README.md):
 * an Android emulator with virtual Bluetooth (netsim) and the bumble
 * `meshcore_tnc.py` peripheral advertising the Nordic UART Service and echoing
 * KISS CMD_DATA frames. When no such peripheral is in range the test is skipped
 * (assumeTrue), so it never fails a normal instrumented run without the harness.
 */
@RunWith(AndroidJUnit4::class)
class BleKissEmulatorTest {

    @get:Rule
    val permissions: GrantPermissionRule = GrantPermissionRule.grant(
        Manifest.permission.BLUETOOTH_CONNECT,
        Manifest.permission.BLUETOOTH_SCAN,
    )

    private val context: Context = ApplicationProvider.getApplicationContext()
    private val adapter: BluetoothAdapter? =
        context.getSystemService(BluetoothManager::class.java)?.adapter

    private val nusService = ParcelUuid(UUID.fromString(NusLink.NUS_SERVICE_UUID))
    private var iface: BleKissInterface? = null

    @After
    fun tearDown() {
        iface?.detach()
        iface = null
    }

    /** Scan for the emulated TNC (by NUS service UUID or the "MeshCoreTNC" name). */
    private fun scanForTnc(timeoutMs: Long): String? {
        val scanner = adapter?.bluetoothLeScanner ?: return null
        val found = arrayOfNulls<String>(1)
        val latch = CountDownLatch(1)
        val cb = object : ScanCallback() {
            override fun onScanResult(callbackType: Int, result: ScanResult) {
                val uuids = result.scanRecord?.serviceUuids
                val name = result.scanRecord?.deviceName ?: result.device.name
                if (uuids?.contains(nusService) == true || name == "MeshCoreTNC") {
                    if (found[0] == null) {
                        found[0] = result.device.address
                        latch.countDown()
                    }
                }
            }
        }
        scanner.startScan(cb)
        try {
            latch.await(timeoutMs, TimeUnit.MILLISECONDS)
        } finally {
            scanner.stopScan(cb)
        }
        return found[0]
    }

    @Test
    fun bleKiss_roundTripsThroughEmulatedTnc() = runBlocking {
        assumeTrue("No Bluetooth adapter", adapter != null)
        assumeTrue("Bluetooth not enabled", adapter!!.isEnabled)

        val mac = scanForTnc(timeoutMs = 20_000)
        assumeTrue("No MeshCore/NUS TNC peripheral in range (harness not running)", mac != null)
        assertNotNull(mac)

        val received = CopyOnWriteArrayList<ByteArray>()
        val link = AndroidNusLink(context, adapter, mac!!)
        val bleKiss = BleKissInterface(name = "ble-emu-test", mac = mac, link = link).also { iface = it }
        bleKiss.onPacketReceived = { data, _ -> received.add(data) }

        bleKiss.start()

        // Wait for the GATT link to come online.
        val onlineDeadline = System.currentTimeMillis() + 20_000
        while (!bleKiss.online.value && System.currentTimeMillis() < onlineDeadline) Thread.sleep(50)
        assertTrue("interface never came online (GATT connect/NUS setup failed)", bleKiss.online.value)

        // Send a probe; the emulated TNC echoes CMD_DATA payloads back KISS-framed.
        val probe = "PING-RETICULUM".toByteArray()
        bleKiss.processOutgoing(probe)

        val echoDeadline = System.currentTimeMillis() + 15_000
        while (received.isEmpty() && System.currentTimeMillis() < echoDeadline) Thread.sleep(50)

        assertTrue("no echo returned from the emulated TNC", received.isNotEmpty())
        assertArrayEquals("echoed payload must match the probe", probe, received[0])
    }
}
