package network.reticulum.interfaces.blekiss

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import network.reticulum.interfaces.Interface
import network.reticulum.interfaces.backoff.ExponentialBackoff
import network.reticulum.interfaces.framing.KISS
import network.reticulum.interfaces.util.createInterfaceScope
import java.io.ByteArrayOutputStream
import java.io.IOException

/**
 * BLE KISS interface for KISS TNCs exposed over the Nordic UART Service (NUS) —
 * e.g. Muziworks R1 / R1 Neo running MeshCore firmware.
 *
 * Kotlin port of a Python `BLEKISSInterface` that the reference does not carry.
 * KISS frames are carried as GATT writes/notifications over NUS. The transport
 * is abstracted behind [NusLink] so this class — the KISS deframing, the bounded
 * outbound queue, the reconnect/session lifecycle — is pure and unit-testable
 * without hardware.
 *
 * Design notes:
 *  - **rx_bound = HW_MTU + 1**: the accumulation buffer holds COMMAND byte +
 *    payload, so the bound is one larger than the serial siblings' payload-only
 *    bound. Bounding it stops a peripheral that never sends a FEND from growing
 *    memory without limit, and truncating at the bound matches the Python
 *    behaviour exactly (see the source comment there).
 *  - **Bounded, decoupled outbound**: `processOutgoing` only enqueues; a
 *    dedicated coroutine drains the queue and does the GATT write, so a stalled
 *    peer never blocks the Transport caller. The queue drops the newest frame
 *    when full rather than back-pressuring.
 *  - **No frame-duration ceiling**: that is a serial-only behaviour
 *    (`KissInterface`); BLE relies on `rx_bound` alone. Deliberately omitted.
 *  - **detach()/reconnect are structural**: a single session loop plus
 *    coroutine cancellation, so the Python "detach polarity" bug and the
 *    concurrent-reconnect race cannot occur here.
 */
class BleKissInterface(
    name: String,
    private val mac: String,
    private val link: NusLink,
    override val kissFraming: Boolean = true,
    hwMtuBytes: Int = DEFAULT_HW_MTU,
    bitrateGuess: Int = BITRATE_GUESS,
    private val connectionTimeoutMs: Long = DEFAULT_CONNECTION_TIMEOUT_MS,
    parentScope: CoroutineScope? = null,
) : Interface(name) {

    companion object {
        /**
         * IFAC tag length in bytes. This interface carries KISS frames, so it takes the
         * serial/framed-media tag length python uses for KISS (`KISSInterface.py:63`)
         * rather than the 16-byte packet/IP default — the peer on a KISS link expects 8.
         */
        const val DEFAULT_IFAC_SIZE = 8

        const val DEFAULT_HW_MTU = 244 // BLE typical MTU minus overhead
        const val BITRATE_GUESS = 57600 // approximate effective NUS bitrate
        const val DEFAULT_CONNECTION_TIMEOUT_MS = 10_000L
        const val OUTBOUND_QUEUE_CAPACITY = 64
        const val RECONNECT_WAIT_MIN_MS = 1_000L
        const val RECONNECT_WAIT_MAX_MS = 30_000L
        const val RECONNECT_MULTIPLIER = 1.5
        const val MAX_RECONNECT_ATTEMPTS = 10

        private val DEBUG = System.getProperty("reticulum.blekiss.debug", "false").toBoolean()
    }

    override val bitrate: Int = bitrateGuess
    override val hwMtu: Int = hwMtuBytes

    // The tag is 8 bytes on this medium; see Interface.defaultIfacSize for why a
    // mismatch partitions rather than degrades.
    override val defaultIfacSize: Int
        get() = DEFAULT_IFAC_SIZE


    /** See parity note: the buffer holds command byte + payload, hence +1. */
    private val rxBound: Int = hwMtuBytes + 1

    // With a parent scope this inherits the parent's dispatcher (no Dispatchers.IO pin).
    private val ioScope: CoroutineScope = createInterfaceScope(parentScope, ioDispatcher = false)

    private val outbound = Channel<ByteArray>(OUTBOUND_QUEUE_CAPACITY)
    private var sessionJob: Job? = null

    /**
     * Optional handler for inbound non-DATA KISS frames: (raw command byte, unescaped payload).
     * Default null — non-DATA frames are dropped, matching Python RNS's KISSInterface. Set this
     * to read command responses (e.g. MeshCore HW_RESP 0x8B) and unsolicited stats
     * (0x23 RSSI / 0x24 SNR / 0x25 channel stats). Invoked on the RX coroutine; keep it quick.
     */
    var onCommandFrame: ((command: Byte, payload: ByteArray) -> Unit)? = null

    // KISS deframer state — only ever touched from the single RX coroutine.
    private val kissBuffer = ByteArrayOutputStream()
    private var inFrame = false
    private var escapeNext = false

    private fun log(msg: String) {
        if (DEBUG) println("[BleKiss:$name@$mac] $msg")
    }

    override fun start() {
        sessionJob = ioScope.launch { sessionLoop() }
    }

    /**
     * One coroutine owns the whole connect → serve → disconnect → reconnect
     * lifecycle. Because it is a single coroutine, there is no way for two
     * reconnects to race and no online/offline polarity flag for detach to
     * fight — detach just cancels the scope.
     */
    private suspend fun sessionLoop() {
        val backoff = ExponentialBackoff(
            initialDelayMs = RECONNECT_WAIT_MIN_MS,
            maxDelayMs = RECONNECT_WAIT_MAX_MS,
            multiplier = RECONNECT_MULTIPLIER,
            maxAttempts = MAX_RECONNECT_ATTEMPTS,
        )
        while (!detached.get()) {
            val ok = try {
                link.connect(connectionTimeoutMs)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                log("connect failed: ${e.message}")
                false
            }
            if (!ok) {
                val wait = backoff.nextDelay()
                if (wait == null) {
                    log("giving up after $MAX_RECONNECT_ATTEMPTS reconnect attempts")
                    break
                }
                delay(wait)
                continue
            }

            backoff.reset()
            resetDeframer()
            setOnline(true)
            log("connected")
            try {
                runSession()
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                log("session ended: ${e.message}")
            } finally {
                setOnline(false)
                withContext(NonCancellable) {
                    try {
                        link.close()
                    } catch (_: Exception) {
                    }
                }
            }
            if (detached.get()) break
        }
    }

    /**
     * Runs the RX collector and the outbound writer until the link drops (clean
     * disconnect) or a write fails (thrown → reconnect). Returns to
     * [sessionLoop], which reconnects unless detached.
     */
    private suspend fun runSession() = coroutineScope {
        val rx = launch {
            link.incoming.collect { processIncomingBytes(it) }
        }
        val tx = launch {
            for (frame in outbound) {
                // Frames are already KISS-encoded by the producer (processOutgoing frames DATA,
                // sendCommandFrame frames arbitrary commands), so they share one channel and
                // keep BLE write ordering serialized.
                val written = try {
                    link.write(frame)
                } catch (e: Exception) {
                    false
                }
                if (written) {
                    txBytes.addAndGet(frame.size.toLong())
                } else {
                    throw IOException("BLE write failed")
                }
            }
        }
        // Suspend until the link reports disconnected, then end this session.
        link.connected.first { !it }
        rx.cancel()
        tx.cancel()
    }

    override fun processOutgoing(data: ByteArray) {
        if (!online.value) return
        val frame = if (kissFraming) KISS.frame(data, KISS.CMD_DATA) else data
        if (!outbound.trySend(frame).isSuccess) {
            log("outbound queue full, dropping frame (${data.size} bytes)")
        }
    }

    /**
     * Send a raw KISS command frame over BLE: [command] byte + KISS-escaped [payload],
     * FEND-wrapped. Gives the BLE path the same command channel as the serial KISS interface —
     * e.g. MeshCore SetHardware (0x06) with a SET_RADIO payload (sub_cmd + freq/bw/sf/cr).
     * Queued through the same serialized outbound path as data. Returns false if the interface
     * is offline or the queue is full; read responses via [onCommandFrame].
     */
    fun sendCommandFrame(command: Byte, payload: ByteArray): Boolean {
        if (!online.value) return false
        return outbound.trySend(KISS.frame(payload, command)).isSuccess
    }

    /**
     * KISS deframer, matching the Python `process_incoming_bytes`. The buffer
     * holds command byte + payload and is bounded at [rxBound]; bytes past the
     * bound are dropped and the interface resyncs on the next FEND.
     */
    private fun processIncomingBytes(data: ByteArray) {
        for (b in data) {
            when {
                b == KISS.FEND -> {
                    if (inFrame && kissBuffer.size() > 0) {
                        processKissFrame(kissBuffer.toByteArray())
                    }
                    kissBuffer.reset()
                    inFrame = true
                    escapeNext = false
                }
                inFrame && kissBuffer.size() < rxBound -> {
                    when {
                        escapeNext -> {
                            when (b) {
                                KISS.TFEND -> kissBuffer.write(KISS.FEND.toInt() and 0xFF)
                                KISS.TFESC -> kissBuffer.write(KISS.FESC.toInt() and 0xFF)
                                else -> kissBuffer.write(b.toInt() and 0xFF)
                            }
                            escapeNext = false
                        }
                        b == KISS.FESC -> escapeNext = true
                        else -> kissBuffer.write(b.toInt() and 0xFF)
                    }
                }
                // else: outside a frame, or the buffer is at rx_bound — drop the
                // byte; the next FEND resyncs the deframer.
            }
        }
    }

    private fun processKissFrame(frame: ByteArray) {
        if (frame.isEmpty()) return
        val command = frame[0]
        val payload = frame.copyOfRange(1, frame.size)
        when (command) {
            KISS.CMD_DATA -> if (payload.isNotEmpty()) processIncoming(payload)
            KISS.CMD_READY -> log("KISS TNC ready")
            else -> {
                // Non-DATA command frame — surface to the optional handler (raw command byte +
                // unescaped payload); drop otherwise (matching Python RNS).
                val handler = onCommandFrame
                if (handler != null) {
                    handler(command, payload)
                } else {
                    log("Dropping KISS command 0x${(command.toInt() and 0xFF).toString(16)} (${payload.size} bytes); no onCommandFrame handler")
                }
            }
        }
    }

    private fun resetDeframer() {
        kissBuffer.reset()
        inFrame = false
        escapeNext = false
    }

    override fun detach() {
        if (detached.getAndSet(true)) return
        setOnline(false)
        outbound.close()
        ioScope.cancel() // triggers the session finally, which closes the link under NonCancellable
    }

    override fun toString(): String = "BleKissInterface[$name/$mac]"
}
