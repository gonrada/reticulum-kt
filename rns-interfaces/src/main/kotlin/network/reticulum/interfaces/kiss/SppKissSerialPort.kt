package network.reticulum.interfaces.kiss

import network.reticulum.interfaces.spp.SppConnection
import network.reticulum.interfaces.spp.SppDriver

/**
 * Bluetooth-Classic (RFCOMM/SPP) backend for a KISS TNC — the platform-agnostic
 * half of the Bluetooth-Classic KISS transport. It bridges an [SppDriver] into the [KissSerialPort] seam
 * so [KissInterface] can drive a KISS TNC over an RFCOMM stream.
 *
 * Because [SppDriver] is an abstraction (Android's `AndroidSppDriver` in
 * production, piped streams in tests), this backend is pure-JVM and unit-testable
 * without Bluetooth hardware. The reconnect factory re-opens a fresh RFCOMM
 * connection each time [KissInterface] reconnects, and close tears down the
 * socket via the connection's own close lambda.
 */
object SppKissSerialPort {
    /**
     * Create a [KissSerialPort] that connects to [address] over RFCOMM using [driver].
     *
     * @param secure true for encrypted RFCOMM (requires pairing), false for insecure.
     */
    fun create(driver: SppDriver, address: String, secure: Boolean = true): KissSerialPort {
        // Holds the live connection so close() can invoke its socket-closing lambda;
        // updated on each (re)connect.
        val current = arrayOfNulls<SppConnection>(1)
        return StreamKissSerialPort(
            connect = {
                val conn = driver.connect(address, secure)
                current[0] = conn
                conn.inputStream to conn.outputStream
            },
            onClose = {
                current[0]?.close?.invoke()
                current[0] = null
            },
        )
    }
}
