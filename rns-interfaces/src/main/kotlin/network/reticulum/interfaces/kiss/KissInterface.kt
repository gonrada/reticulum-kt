package network.reticulum.interfaces.kiss

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
import network.reticulum.interfaces.framing.KISS
import network.reticulum.interfaces.util.createInterfaceScope
import java.io.ByteArrayOutputStream
import java.io.IOException

/**
 * KISS TNC interface over a generic byte stream ([KissSerialPort]) — the shared
 * core the Bluetooth-Classic and USB-serial KISS variants wrap.
 *
 * Kotlin port of the reference `KISSInterface` data path
 * (`RNS/Interfaces/KISSInterface.py`), with these additions over the reference:
 *  - **rx_bound**: the decoded payload buffer is capped; bytes past the
 *    bound are dropped and the deframer resyncs on the next FEND.
 *  - **frame-duration ceiling**: a frame left open longer than
 *    [maxFrameDurationMs] is discarded and resynced — independent of the
 *    inter-byte timeout, so a peer that trickles bytes forever can't wedge the
 *    reader. The ceiling is derived from the bitrate (worst-case KISS-escaped
 *    frame), floored at [MIN_FRAME_DURATION_MS].
 *  - **bounded inbound dispatch**: decoded frames go onto a bounded queue
 *    drained by a dispatch coroutine; a full queue drops after a timeout rather
 *    than wedging the read loop (so shutdown is always noticed).
 *  - **flow control**: `interface_ready` gating + a queued-packet path, unlocked
 *    by a KISS `CMD_READY` from the TNC or a flow-control timeout. The queue is
 *    bounded and the timeout is evaluated on every read-loop iteration, not only
 *    on an idle read — see [OUTBOUND_QUEUE_CAPACITY] and `port-deviations.md`.
 *  - **structural detach/reconnect**: one session loop + coroutine
 *    cancellation, so the Python detach-polarity and concurrent-reconnect races
 *    cannot occur.
 *
 * Beacon transmission, AX.25 framing and the preamble/txtail/persistence/slottime
 * TNC-config commands follow `KISSInterface.py` and `AX25KISSInterface.py`.
 */
class KissInterface(
    name: String,
    private val port: KissSerialPort,
    hwMtuBytes: Int = DEFAULT_HW_MTU,
    bitrateGuess: Int = BITRATE_GUESS,
    private val flowControl: Boolean = false,
    private val interByteTimeoutMs: Long = DEFAULT_INTER_BYTE_TIMEOUT_MS,
    private val flowControlTimeoutMs: Long = DEFAULT_FLOW_CONTROL_TIMEOUT_MS,
    private val ax25: Boolean = false,
    ax25SrcCall: String? = null,
    ax25SrcSsid: Int = 0,
    ax25DstCall: String? = null,
    ax25DstSsid: Int = 0,
    private val configureTnc: Boolean = false,
    private val preambleMs: Int = 350,
    private val txTailMs: Int = 20,
    private val persistence: Int = 64,
    private val slotTimeMs: Int = 20,
    private val configureDelayMs: Long = CONFIGURE_DELAY_MS,
    private val beaconIntervalMs: Long? = null,
    private val beaconData: ByteArray? = null,
    maxFrameDurationMsOverride: Long? = null,
    private val reconnectIntervalMs: Long = RECONNECT_INTERVAL_MS,
    parentScope: CoroutineScope? = null,
    // IFAC, as python applies it to every interface type (Reticulum.py:805-812).
    override val ifacNetname: String? = null,
    override val ifacNetkey: String? = null,
    private val ifacSizeBits: Int? = null,
) : Interface(name) {

    companion object {
        /**
         * IFAC tag length in bytes for KISS-framed media. Both python classes this
         * interface covers use 8: `KISSInterface.py:63` and, in AX.25 mode,
         * `AX25KISSInterface.py:70`.
         */
        const val DEFAULT_IFAC_SIZE = 8

        const val DEFAULT_HW_MTU = 564
        const val BITRATE_GUESS = 1200

        /**
         * Time to let the device initialise after the port opens, before the KISS
         * configuration commands are sent (python `KISSInterface.py:172` sleeps 2 s).
         * A TNC that is still booting silently ignores the commands.
         */
        const val CONFIGURE_DELAY_MS = 2_000L

        /**
         * Minimum length of an identity beacon frame; shorter beacon data is padded
         * with zero bytes (python `KISSInterface.py:352-355`).
         */
        const val BEACON_MIN_SIZE = 15
        const val MIN_FRAME_DURATION_MS = KISS.MIN_FRAME_DURATION_MS
        const val FRAME_DURATION_SAFETY_FACTOR = KISS.FRAME_DURATION_SAFETY_FACTOR
        const val INBOUND_QUEUE_CAPACITY = 256

        /**
         * Cap on frames held behind the flow-control gate. The reference queue is an
         * unbounded list (`KISSInterface.py:282`), so a gate that stays shut grows it for
         * as long as Transport keeps handing frames down. Bounded here; the newest frame
         * is dropped once the cap is reached, as the inbound path already drops rather
         * than block.
         */
        const val OUTBOUND_QUEUE_CAPACITY = 256
        const val INBOUND_QUEUE_TIMEOUT_MS = 1_000L
        const val RECONNECT_INTERVAL_MS = 5_000L
        const val DEFAULT_INTER_BYTE_TIMEOUT_MS = 100L
        const val DEFAULT_FLOW_CONTROL_TIMEOUT_MS = 5_000L
        const val IDLE_SLEEP_MS = 50L

        // Standard KISS TNC command bytes (distinct from framing/KISS.kt's
        // RNode-flavoured 0x01-0x06 meanings, so defined locally).
        private const val KISS_CMD_TXDELAY: Byte = 0x01
        private const val KISS_CMD_P: Byte = 0x02
        private const val KISS_CMD_SLOTTIME: Byte = 0x03
        private const val KISS_CMD_TXTAIL: Byte = 0x04
        private const val KISS_CMD_READY: Byte = 0x0F

        private val DEBUG = System.getProperty("reticulum.kiss.debug", "false").toBoolean()

        /** Derive the max time a single frame may stay open, from the bitrate ([KISS.maxFrameDurationMs]). */
        fun deriveMaxFrameDurationMs(rxBound: Int, bitrate: Int): Long = KISS.maxFrameDurationMs(rxBound, bitrate)
    }

    override val bitrate: Int = bitrateGuess
    override val hwMtu: Int = hwMtuBytes

    // The tag is 8 bytes on this medium; see Interface.defaultIfacSize for why a
    // mismatch partitions rather than degrades.
    override val defaultIfacSize: Int
        get() = DEFAULT_IFAC_SIZE
    override val configuredIfacSizeBits: Int? get() = ifacSizeBits
    override val kissFraming: Boolean = true

    // AX.25 inbound frames carry the 16-byte header on top of a full payload,
    // so the receive bound is widened to avoid truncating them.
    private val rxBound: Int = if (ax25) hwMtuBytes + Ax25.HEADER_SIZE else hwMtuBytes
    private val maxFrameDurationMs: Long = maxFrameDurationMsOverride ?: deriveMaxFrameDurationMs(rxBound, bitrateGuess)

    // Prebuilt AX.25 UI header prepended on transmit; null when AX.25 is off.
    // Construction validates the callsigns/SSIDs and fails fast on bad config.
    private val ax25Header: ByteArray? = if (ax25) {
        val srcCall = Ax25.validateCallsign(ax25SrcCall, "source", name)
        val srcSsid = Ax25.validateSsid(ax25SrcSsid, "source", name)
        val dstRaw = ax25DstCall?.trim()
        val dstCall: String
        val dstSsid: Int
        if (dstRaw.isNullOrEmpty()) {
            dstCall = Ax25.DEFAULT_DEST_CALLSIGN
            dstSsid = Ax25.DEFAULT_DEST_SSID
        } else {
            dstCall = Ax25.validateCallsign(dstRaw, "destination", name, minLength = 1)
            dstSsid = Ax25.validateSsid(ax25DstSsid, "destination", name)
        }
        Ax25.buildHeader(dstCall, dstSsid, srcCall, srcSsid)
    } else {
        null
    }

    // With a parent scope this inherits the parent's dispatcher (no Dispatchers.IO pin).
    private val ioScope: CoroutineScope = createInterfaceScope(parentScope, ioDispatcher = false)

    private var sessionJob: Job? = null
    private val inbound = Channel<ByteArray>(INBOUND_QUEUE_CAPACITY)

    // Flow-control state, guarded by txLock (touched by the Transport caller in
    // processOutgoing and by the read coroutine in processQueue).
    private val txLock = Any()
    private var interfaceReady = true
    private val packetQueue = ArrayDeque<ByteArray>()
    private var flowControlLockedMs = 0L

    // Timestamp of the first non-beacon TX in the current window; the beacon
    // fires beaconIntervalMs after it. Guarded by txLock.
    private var firstTx: Long? = null

    private fun log(msg: String) {
        if (DEBUG) println("[Kiss:$name] $msg")
    }

    override fun start() {
        sessionJob = ioScope.launch { sessionLoop() }
    }

    private suspend fun sessionLoop() {
        var first = true
        while (!detached.get()) {
            if (!first) delay(reconnectIntervalMs)
            first = false

            val opened = try {
                port.open()
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                log("open failed: ${e.message}")
                false
            }
            if (!opened) continue

            synchronized(txLock) {
                interfaceReady = true
                packetQueue.clear()
            }
            setOnline(true)
            log("port open")
            try {
                if (configureTnc) {
                    if (configureDelayMs > 0) delay(configureDelayMs)
                    if (!configureDevice()) throw IOException("KISS device configuration failed")
                }
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

    private suspend fun runReadAndDispatch() = coroutineScope {
        val dispatch = launch {
            while (isActive) {
                val data = inbound.receiveCatching().getOrNull() ?: break
                processIncoming(data)
            }
        }
        readLoopBody()
        dispatch.cancel()
    }

    /** KISS deframer + housekeeping, matching the Python `readLoop`. */
    private suspend fun readLoopBody() {
        var inFrame = false
        var escape = false
        var command = KISS.CMD_UNKNOWN
        val dataBuffer = ByteArrayOutputStream()
        var lastReadMs = System.currentTimeMillis()
        var frameStartedMs = -1L

        while (port.isOpen && !detached.get()) {
            val bytes = port.read()
            val got = bytes.size

            // Frame-duration ceiling, applied BEFORE this chunk is interpreted. The
            // post-loop check below only runs once per iteration, and an iteration can
            // arrive late — the idle delay overshoots under load, or a real line stalls
            // — with a fresh frame's bytes already queued behind the stale open one.
            // Interpreted first, the fresh frame's opening FEND closes the stale frame
            // and its partial contents are delivered as a packet. Discarding first
            // means the new bytes are read on a clean deframer.
            if (got > 0 && inFrame && frameStartedMs >= 0 &&
                System.currentTimeMillis() - frameStartedMs > maxFrameDurationMs
            ) {
                log("discarding a frame open >${maxFrameDurationMs}ms before reading new bytes")
                dataBuffer.reset(); inFrame = false; command = KISS.CMD_UNKNOWN; escape = false; frameStartedMs = -1L
            }

            for (b in bytes) {
                lastReadMs = System.currentTimeMillis()
                when {
                    inFrame && b == KISS.FEND -> {
                        // Closing FEND: deliver DATA to the packet path. Any other command's
                        // frame is dropped, as in python (KISSInterface.py:305-307 only
                        // delivers CMD_DATA).
                        if (command == KISS.CMD_DATA) deliverInbound(dataBuffer.toByteArray())
                        inFrame = false
                        escape = false
                        frameStartedMs = -1L
                        command = KISS.CMD_UNKNOWN
                        dataBuffer.reset()
                    }
                    b == KISS.FEND -> {
                        inFrame = true
                        escape = false // don't let a dangling FESC leak across frames
                        frameStartedMs = lastReadMs
                        command = KISS.CMD_UNKNOWN
                        dataBuffer.reset()
                    }
                    inFrame && dataBuffer.size() < rxBound -> {
                        when {
                            dataBuffer.size() == 0 && command == KISS.CMD_UNKNOWN -> {
                                // First byte after FEND is the command; strip the port nibble
                                // (single HDLC port supported, KISSInterface.py:313-317).
                                command = (b.toInt() and 0x0F).toByte()
                            }
                            command == KISS.CMD_READY -> processQueue()
                            command == KISS.CMD_DATA -> {
                                // DATA payload — unescape + buffer (KISSInterface.py:318-328).
                                if (b == KISS.FESC) {
                                    escape = true
                                } else {
                                    var v = b
                                    if (escape) {
                                        if (b == KISS.TFEND) v = KISS.FEND
                                        if (b == KISS.TFESC) v = KISS.FESC
                                        escape = false
                                    }
                                    dataBuffer.write(v.toInt() and 0xFF)
                                }
                            }
                        }
                    }
                }
            }

            // Frame-duration ceiling: fires even while bytes keep arriving.
            if (inFrame && frameStartedMs >= 0 &&
                System.currentTimeMillis() - frameStartedMs > maxFrameDurationMs
            ) {
                log("discarding a frame open >${maxFrameDurationMs}ms without completing")
                dataBuffer.reset(); inFrame = false; command = KISS.CMD_UNKNOWN; escape = false; frameStartedMs = -1L
            }

            // Flow-control timeout, evaluated on every iteration rather than only on an
            // idle read. The reference checks it inside the `else` of `if
            // self.serial.in_waiting` (KISSInterface.py:331, 340-344), so a stream that always
            // has bytes waiting never reaches it and the gate stays shut for as long as
            // the peer keeps talking. It is a safety timeout for a TNC that missed or
            // does not implement READY; making it depend on the peer going quiet is what
            // lets the peer hold it. Firing it here is a superset of the reference's
            // condition — it still fires on an idle line — and it costs nothing when the
            // gate is open. processQueue re-locks after each released frame, so this
            // cannot drain the queue faster than one frame per timeout.
            if (flowControl) {
                // Both halves of the decision are made under txLock: flowControlLockedMs is a
                // plain Long written by the sender under that lock, so reading it out here
                // could see a stale timestamp and unlock a gate that was just re-armed.
                val expired = synchronized(txLock) {
                    !interfaceReady &&
                        System.currentTimeMillis() > flowControlLockedMs + flowControlTimeoutMs
                }
                if (expired) {
                    log("flow-control timeout unlock")
                    processQueue()
                }
            }

            if (got == 0) {
                // Inter-byte silence: drop a partial frame stuck mid-stream.
                if (dataBuffer.size() > 0 && System.currentTimeMillis() - lastReadMs > interByteTimeoutMs) {
                    dataBuffer.reset(); inFrame = false; command = KISS.CMD_UNKNOWN; escape = false; frameStartedMs = -1L
                }
                delay(IDLE_SLEEP_MS)

                if (beaconIntervalMs != null && beaconData != null) {
                    val due = synchronized(txLock) {
                        val ft = firstTx
                        ft != null && System.currentTimeMillis() > ft + beaconIntervalMs
                    }
                    if (due) {
                        log("transmitting beacon")
                        // python KISSInterface.py:350 clears the marker before sending, then
                        // pads the beacon to BEACON_MIN_SIZE (:352-355). The padded frame is
                        // no longer equal to the configured beacon data, so the send below
                        // re-arms the marker and the station identifies once per interval
                        // rather than once per idle period. That is the reference's own
                        // behaviour; do not "fix" it without changing python too.
                        synchronized(txLock) { firstTx = null }
                        processOutgoing(
                            if (beaconData.size >= BEACON_MIN_SIZE) beaconData else beaconData.copyOf(BEACON_MIN_SIZE),
                        )
                    }
                }
            }
        }
    }

    private suspend fun deliverInbound(raw: ByteArray) {
        val data = if (ax25) {
            if (raw.size <= Ax25.HEADER_SIZE) return // header-only / runt frame
            raw.copyOfRange(Ax25.HEADER_SIZE, raw.size)
        } else {
            raw
        }
        val accepted = withTimeoutOrNull(INBOUND_QUEUE_TIMEOUT_MS) { inbound.send(data); true }
        if (accepted == null) log("inbound queue full, dropping frame (${data.size} bytes)")
    }

    override fun processOutgoing(data: ByteArray) {
        if (!online.value) return
        synchronized(txLock) {
            if (interfaceReady) {
                sendFrameLocked(data)
            } else if (packetQueue.size < OUTBOUND_QUEUE_CAPACITY) {
                packetQueue.addLast(data)
            } else {
                log("flow-control queue full, dropping frame (${data.size} bytes)")
            }
        }
    }

    /** Must be called holding [txLock]. */
    private fun sendFrameLocked(data: ByteArray) {
        val isBeacon = beaconData != null && data.contentEquals(beaconData)
        if (flowControl) {
            interfaceReady = false
            flowControlLockedMs = System.currentTimeMillis()
        }
        val payload = if (ax25Header != null) ax25Header + data else data
        val frame = KISS.frame(payload, KISS.CMD_DATA)
        val written = try {
            port.write(frame)
        } catch (e: Exception) {
            log("write error: ${e.message}"); -1
        }
        if (written == frame.size) {
            txBytes.addAndGet(data.size.toLong())
            if (isBeacon) firstTx = null
            else if (firstTx == null) firstTx = System.currentTimeMillis()
        } else {
            // python releases the flow-control gate before raising (AX25KISSInterface.py:
            // 299-302), so a queued frame is not stranded behind a write that never
            // completed. We release it too, and additionally close the port: a short write
            // on a serial line means the device is gone or its buffer is wedged, and the
            // read loop's reconnect is the only thing that recovers either.
            if (flowControl) interfaceReady = true
            log("short/failed write ($written of ${frame.size}), closing to reconnect")
            closeQuietly() // read loop sees the port closed -> session ends -> reconnect
        }
    }

    /** Send the KISS TNC configuration commands. @return false on a short write. */
    private fun configureDevice(): Boolean {
        return writeCommand(KISS_CMD_TXDELAY, preambleMs / 10) &&
            writeCommand(KISS_CMD_TXTAIL, txTailMs / 10) &&
            writeCommand(KISS_CMD_P, persistence) &&
            writeCommand(KISS_CMD_SLOTTIME, slotTimeMs / 10) &&
            writeCommand(KISS_CMD_READY, 0x01) // enable flow-control READY
    }

    private fun writeCommand(command: Byte, value: Int): Boolean {
        val v = value.coerceIn(0, 255)
        val frame = byteArrayOf(KISS.FEND, command, v.toByte(), KISS.FEND)
        return try {
            port.write(frame) == frame.size
        } catch (e: Exception) {
            log("config command write error: ${e.message}"); false
        }
    }

    private fun processQueue() {
        synchronized(txLock) {
            if (packetQueue.isNotEmpty()) {
                interfaceReady = true
                sendFrameLocked(packetQueue.removeFirst())
            } else {
                interfaceReady = true
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
        ioScope.cancel() // triggers the session finally, which closes the port under NonCancellable
    }

    override fun toString(): String = "KissInterface[$name]"
}
