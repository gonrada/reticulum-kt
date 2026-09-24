package network.reticulum.cli.config

import com.fazecast.jSerialComm.SerialPort
import network.reticulum.interfaces.kiss.KissSerialPort

/**
 * A [KissSerialPort] over a real serial device for the daemon, through jSerialComm
 * (python uses pyserial with the same parameters, `SerialInterface.open_port`,
 * `KISSInterface.open_port`). Reads are semi-blocking with a short timeout so the
 * interface read loops poll as they do against pyserial's `in_waiting`.
 */
class JSerialCommPort(
    private val portName: String,
    private val speed: Int = 9600,
    private val dataBits: Int = 8,
    private val parity: String = "N",
    private val stopBits: Int = 1,
) : KissSerialPort {
    @Volatile
    private var port: SerialPort? = null
    private val buffer = ByteArray(4096)

    override val isOpen: Boolean get() = port?.isOpen == true

    override suspend fun open(): Boolean {
        val p = SerialPort.getCommPort(portName)
        p.setComPortParameters(speed, dataBits, stopBitsValue(stopBits), parityValue(parity))
        p.setFlowControl(SerialPort.FLOW_CONTROL_DISABLED)
        p.setComPortTimeouts(SerialPort.TIMEOUT_READ_SEMI_BLOCKING, READ_TIMEOUT_MS, 0)
        if (!p.openPort()) return false
        port = p
        return true
    }

    override fun read(): ByteArray {
        val p = port ?: return ByteArray(0)
        val available = p.bytesAvailable()
        if (available <= 0) return ByteArray(0)
        val n = p.readBytes(buffer, minOf(available, buffer.size))
        if (n < 0) throw java.io.IOException("serial read failed on $portName")
        return buffer.copyOf(n)
    }

    override fun write(bytes: ByteArray): Int {
        val p = port ?: return -1
        return p.writeBytes(bytes, bytes.size)
    }

    override fun close() {
        port?.closePort()
        port = null
    }

    private fun parityValue(parity: String): Int =
        when (parity.lowercase()) {
            "e", "even" -> SerialPort.EVEN_PARITY
            "o", "odd" -> SerialPort.ODD_PARITY
            else -> SerialPort.NO_PARITY
        }

    private fun stopBitsValue(stopBits: Int): Int =
        when (stopBits) {
            2 -> SerialPort.TWO_STOP_BITS
            else -> SerialPort.ONE_STOP_BIT
        }

    private companion object {
        const val READ_TIMEOUT_MS = 50
    }
}
