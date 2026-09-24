package network.reticulum.android.kiss

import android.bluetooth.BluetoothAdapter
import android.content.Context
import android.hardware.usb.UsbManager
import network.reticulum.android.blekiss.AndroidNusLink
import network.reticulum.interfaces.Interface
import network.reticulum.interfaces.InterfaceAdapter
import network.reticulum.interfaces.blekiss.BleKissInterface
import network.reticulum.interfaces.kiss.KissInterface
import network.reticulum.interfaces.kiss.SppKissSerialPort
import network.reticulum.interfaces.spp.SppDriver
import network.reticulum.transport.Transport

/**
 * Android wiring for the KISS TNC interfaces (lane C #2) — constructs the right
 * interface + platform backend, hooks its RX to Transport, starts it, and
 * registers it, following the same idiom `ReticulumService` uses for its other
 * interfaces. This is the bridge from "which TNC to use" (config) to a live,
 * registered interface.
 *
 * **Contract — these return an already-started, already-registered interface.** Each
 * `start*` helper calls [register], which sets `onPacketReceived`, calls `start()`, and
 * `Transport.registerInterface(...)`. A caller that manages registration itself (for
 * example a factory that returns an *unstarted* interface for its caller to register)
 * must **not** use these helpers — doing so double-registers. Construct
 * `BleKissInterface` / `KissInterface` directly and register once on your side.
 *
 * Full config-field integration (adding TNC entries to `ReticulumConfig` and
 * calling these from `ReticulumService`) is the remaining product hookup; these
 * functions are the reusable, backend-selecting core.
 */
object AndroidKissInterfaces {

    /** BLE KISS TNC over Nordic UART Service (e.g. R1 / MeshCore). */
    fun startBleKiss(
        context: Context,
        bluetoothAdapter: BluetoothAdapter,
        mac: String,
        name: String = "BLE KISS TNC",
    ): Interface {
        val link = AndroidNusLink(context, bluetoothAdapter, mac)
        return register(BleKissInterface(name = name, mac = mac, link = link))
    }

    /** Bluetooth-Classic (RFCOMM) KISS TNC. Pass an `AndroidSppDriver`. */
    fun startBtClassicKiss(
        sppDriver: SppDriver,
        mac: String,
        name: String = "BT KISS TNC",
        secure: Boolean = true,
    ): Interface {
        val port = SppKissSerialPort.create(sppDriver, mac, secure)
        return register(KissInterface(name = name, port = port))
    }

    /** USB-serial KISS TNC (FTDI / CP210x / CH34x / CDC, e.g. TNC4). */
    fun startUsbKiss(
        usbManager: UsbManager,
        name: String = "USB KISS TNC",
        baudRate: Int = UsbKissSerialPort.DEFAULT_BAUD,
    ): Interface {
        val port = UsbKissSerialPort(usbManager, baudRate)
        return register(KissInterface(name = name, port = port))
    }

    private fun register(iface: Interface): Interface {
        iface.onPacketReceived = { data, from ->
            Transport.inbound(data, InterfaceAdapter.getOrCreate(from))
        }
        iface.start()
        Transport.registerInterface(InterfaceAdapter.getOrCreate(iface))
        return iface
    }
}
