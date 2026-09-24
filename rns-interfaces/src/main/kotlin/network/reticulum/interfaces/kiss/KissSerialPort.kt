package network.reticulum.interfaces.kiss

/**
 * Byte-stream seam for a KISS TNC reached over a serial-like transport
 * (USB CDC / FTDI / CP210x, or a Bluetooth-Classic RFCOMM stream).
 *
 * Mirrors the surface of Python `pyserial` that the reference `KISSInterface`
 * relies on: an [open] handshake, a non-blocking [read] that returns whatever
 * bytes are available right now (empty when idle, so the read loop can do its
 * flow-control / frame-timeout housekeeping), a [write] that reports how many
 * bytes it accepted, and [close].
 *
 * Keeping this abstract lets [KissInterface] — the KISS deframing, bounded
 * inbound dispatch, flow control, and reconnect/detach lifecycle — stay pure
 * and unit-testable with an in-memory fake, with no serial hardware. The
 * Bluetooth-Classic and USB-serial variants supply real implementations.
 */
interface KissSerialPort {
    /** Whether the port is currently open. */
    val isOpen: Boolean

    /**
     * Open the port. @return true once ready, false on failure (the interface
     * will retry on its reconnect interval).
     */
    suspend fun open(): Boolean

    /**
     * Read the bytes available right now. Returns an empty array when idle —
     * it must not block for long, so the read loop stays responsive to the
     * frame-duration ceiling, flow-control timeout, and shutdown.
     */
    fun read(): ByteArray

    /** Write bytes; @return the number actually written (a short write signals a fault). */
    fun write(bytes: ByteArray): Int

    /** Close the port. Must be idempotent and must not throw. */
    fun close()
}
