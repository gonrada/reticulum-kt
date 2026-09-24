package network.reticulum.interfaces.serial

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import network.reticulum.interfaces.Interface
import network.reticulum.interfaces.framing.HDLC
import network.reticulum.interfaces.kiss.KissSerialPort
import network.reticulum.interfaces.util.createInterfaceScope
import java.io.ByteArrayOutputStream

/**
 * A raw serial link with simplified HDLC framing (python `SerialInterface`,
 * `RNS/Interfaces/SerialInterface.py`): each packet is sent as `FLAG + escape(data) +
 * FLAG`, and the read loop rebuilds frames byte by byte, dropping a frame that grows
 * past [hwMtu] or stalls longer than [interByteTimeoutMs] between bytes.
 *
 * The port itself is any [KissSerialPort] byte stream: a USB serial adapter on
 * Android, a jSerialComm port on the desktop, or a socket. Like python, the interface
 * reopens the port every [reconnectIntervalMs] after it fails, and the tag is 8 bytes.
 */
class SerialInterface(
    name: String,
    private val port: KissSerialPort,
    /** Line speed in bits per second; python `speed`, also reported as [bitrate]. */
    speed: Int = DEFAULT_SPEED,
    private val interByteTimeoutMs: Long = DEFAULT_INTER_BYTE_TIMEOUT_MS,
    private val reconnectIntervalMs: Long = RECONNECT_INTERVAL_MS,
    override val ifacNetname: String? = null,
    override val ifacNetkey: String? = null,
    private val ifacSizeBits: Int? = null,
    parentScope: CoroutineScope? = null,
) : Interface(name) {
    companion object {
        const val DEFAULT_IFAC_SIZE = 8
        const val HW_MTU = 564
        const val DEFAULT_SPEED = 9600
        const val DEFAULT_INTER_BYTE_TIMEOUT_MS = 100L
        const val RECONNECT_INTERVAL_MS = 5_000L
        const val INBOUND_QUEUE_CAPACITY = 256
        const val INBOUND_QUEUE_TIMEOUT_MS = 1_000L
        const val IDLE_SLEEP_MS = 80L
        private val DEBUG = System.getProperty("reticulum.serial.debug", "false").toBoolean()
    }

    override val bitrate: Int = speed
    override val hwMtu: Int = HW_MTU
    override val defaultIfacSize: Int get() = DEFAULT_IFAC_SIZE
    override val configuredIfacSizeBits: Int? get() = ifacSizeBits

    private val ioScope: CoroutineScope = createInterfaceScope(parentScope, ioDispatcher = false)
    private var sessionJob: Job? = null
    private val inbound = Channel<ByteArray>(INBOUND_QUEUE_CAPACITY)
    private val txLock = Any()

    private fun log(msg: String) {
        if (DEBUG) println("[Serial:$name] $msg")
    }

    override fun start() {
        sessionJob = ioScope.launch { sessionLoop() }
    }

    private suspend fun sessionLoop() {
        var first = true
        while (!detached.get()) {
            if (!first) delay(reconnectIntervalMs)
            first = false
            val opened =
                try {
                    port.open()
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    log("open failed: ${e.message}")
                    false
                }
            if (!opened) continue
            setOnline(true)
            log("port open")
            try {
                runReadAndDispatch()
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                log("session ended: ${e.message}")
            } finally {
                setOnline(false)
                withContext(NonCancellable) { closeQuietly() }
            }
        }
    }

    private suspend fun runReadAndDispatch() =
        coroutineScope {
            val dispatch =
                launch {
                    while (isActive) {
                        val data = inbound.receiveCatching().getOrNull() ?: break
                        processIncoming(data)
                    }
                }
            readLoopBody()
            dispatch.cancel()
        }

    /** Python `readLoop` (SerialInterface.py:150-190). */
    private suspend fun readLoopBody() {
        var inFrame = false
        var escape = false
        val dataBuffer = ByteArrayOutputStream()
        var lastReadMs = System.currentTimeMillis()
        while (port.isOpen && !detached.get()) {
            val bytes = port.read()
            for (b in bytes) {
                lastReadMs = System.currentTimeMillis()
                when {
                    inFrame && b == HDLC.FLAG -> {
                        inFrame = false
                        deliverInbound(dataBuffer.toByteArray())
                        dataBuffer.reset()
                    }
                    b == HDLC.FLAG -> {
                        inFrame = true
                        escape = false
                        dataBuffer.reset()
                    }
                    inFrame && dataBuffer.size() < HW_MTU -> {
                        if (b == HDLC.ESC) {
                            escape = true
                        } else {
                            var v = b
                            if (escape) {
                                if (b == (HDLC.FLAG.toInt() xor HDLC.ESC_MASK.toInt()).toByte()) v = HDLC.FLAG
                                if (b == (HDLC.ESC.toInt() xor HDLC.ESC_MASK.toInt()).toByte()) v = HDLC.ESC
                                escape = false
                            }
                            dataBuffer.write(v.toInt() and 0xFF)
                        }
                    }
                }
            }
            if (bytes.isEmpty()) {
                if (dataBuffer.size() > 0 && System.currentTimeMillis() - lastReadMs > interByteTimeoutMs) {
                    dataBuffer.reset()
                    inFrame = false
                    escape = false
                }
                delay(IDLE_SLEEP_MS)
            }
        }
    }

    private suspend fun deliverInbound(data: ByteArray) {
        if (data.isEmpty()) return
        val accepted = withTimeoutOrNull(INBOUND_QUEUE_TIMEOUT_MS) { inbound.send(data); true }
        if (accepted == null) log("inbound queue full, dropping frame (${data.size} bytes)")
    }

    /** Python `process_outgoing`: HDLC-frame and write; a short write ends the session. */
    override fun processOutgoing(data: ByteArray) {
        if (!online.value) return
        val frame = HDLC.frame(data)
        synchronized(txLock) {
            val written =
                try {
                    port.write(frame)
                } catch (e: Exception) {
                    log("write error: ${e.message}")
                    -1
                }
            if (written == frame.size) {
                txBytes.addAndGet(frame.size.toLong())
            } else {
                log("short/failed write ($written of ${frame.size}), closing to reconnect")
                closeQuietly()
            }
        }
    }

    private fun closeQuietly() {
        try {
            port.close()
        } catch (_: Exception) {
        }
    }

    override fun detach() {
        if (detached.getAndSet(true)) return
        setOnline(false)
        inbound.close()
        ioScope.cancel()
    }

    override fun toString(): String = "SerialInterface[$name]"
}
