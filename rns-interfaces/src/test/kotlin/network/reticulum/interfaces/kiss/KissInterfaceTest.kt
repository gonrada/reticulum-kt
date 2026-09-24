package network.reticulum.interfaces.kiss

import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import network.reticulum.interfaces.framing.KISS
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Assertions.fail
import org.junit.jupiter.api.Test
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicInteger

/**
 * In-memory [KissSerialPort] fake — a test acts as the KISS TNC: [feed] bytes
 * to be read, capture written frames in [written], count opens, and simulate a
 * short write or a link drop. Backed by a concurrent queue so it is safe to
 * feed/inspect from the test thread while the interface reads on Dispatchers.IO.
 */
private class FakeSerialPort : KissSerialPort {
    private val inbox = ConcurrentLinkedQueue<Byte>()

    @Volatile private var open = false
    override val isOpen: Boolean get() = open

    @Volatile var openResult = true
    @Volatile var writeShort = false
    val written = CopyOnWriteArrayList<ByteArray>()
    private val _openCalls = AtomicInteger(0)
    val openCalls: Int get() = _openCalls.get()

    override suspend fun open(): Boolean {
        _openCalls.incrementAndGet()
        open = openResult
        return openResult
    }

    /**
     * When set, an otherwise-empty read returns these bytes instead of nothing, so the
     * read loop never sees an idle iteration. Used to model a TNC that talks continuously.
     * 0x00 outside a frame is ignored by the deframer, so it perturbs nothing else.
     */
    @Volatile var chatter: ByteArray? = null

    override fun read(): ByteArray {
        if (inbox.isEmpty()) {
            val c = chatter
            if (c != null) {
                Thread.sleep(1) // keep the fake off a hot spin; still never an empty read
                return c
            }
        }
        if (inbox.isEmpty()) return ByteArray(0)
        val out = ArrayList<Byte>()
        while (true) {
            val b = inbox.poll() ?: break
            out.add(b)
        }
        return out.toByteArray()
    }

    override fun write(bytes: ByteArray): Int {
        written.add(bytes)
        return if (writeShort) bytes.size - 1 else bytes.size
    }

    override fun close() {
        open = false
    }

    fun feed(bytes: ByteArray) {
        for (b in bytes) inbox.add(b)
    }

    fun drop() {
        open = false
    }
}

/** Little-endian u32 (MeshCore GET_RADIO freq/bw). */
private fun le32(v: Long): ByteArray = byteArrayOf(
    (v and 0xFF).toByte(),
    ((v shr 8) and 0xFF).toByte(),
    ((v shr 16) and 0xFF).toByte(),
    ((v shr 24) and 0xFF).toByte(),
)

/** Big-endian u16 (MeshCore 0x25 CHTM percent*100 fields). */
private fun be16(v: Int): ByteArray =
    byteArrayOf(((v shr 8) and 0xFF).toByte(), (v and 0xFF).toByte())

class KissInterfaceTest {

    private val live = mutableListOf<KissInterface>()

    @AfterEach
    fun tearDown() {
        live.forEach { it.detach() }
        live.clear()
    }

    private fun newInterface(
        port: FakeSerialPort,
        hwMtu: Int = KissInterface.DEFAULT_HW_MTU,
        flowControl: Boolean = false,
        interByteTimeoutMs: Long = KissInterface.DEFAULT_INTER_BYTE_TIMEOUT_MS,
        flowControlTimeoutMs: Long = 100L,
        maxFrameDurationMsOverride: Long? = null,
        reconnectIntervalMs: Long = 50L,
        ax25: Boolean = false,
        ax25SrcCall: String? = null,
        ax25DstCall: String? = null,
        configureTnc: Boolean = false,
        // The production default lets a TNC boot before it is configured; a fake port is
        // ready at once, and waiting for it would eat the assertion timeout.
        configureDelayMs: Long = 0L,
        beaconIntervalMs: Long? = null,
        beaconData: ByteArray? = null,
    ): KissInterface {
        val iface = KissInterface(
            name = "kiss-test",
            port = port,
            hwMtuBytes = hwMtu,
            flowControl = flowControl,
            interByteTimeoutMs = interByteTimeoutMs,
            flowControlTimeoutMs = flowControlTimeoutMs,
            ax25 = ax25,
            ax25SrcCall = ax25SrcCall,
            ax25DstCall = ax25DstCall,
            configureTnc = configureTnc,
            configureDelayMs = configureDelayMs,
            beaconIntervalMs = beaconIntervalMs,
            beaconData = beaconData,
            maxFrameDurationMsOverride = maxFrameDurationMsOverride,
            reconnectIntervalMs = reconnectIntervalMs,
        )
        live += iface
        return iface
    }

    private suspend fun waitUntil(description: String, condition: () -> Boolean) {
        try {
            withTimeout(3_000) {
                while (!condition()) delay(5)
            }
        } catch (e: TimeoutCancellationException) {
            fail<Unit>("timed out waiting for: $description")
        }
    }

    @Test
    fun `opens, goes online, and delivers a CMD_DATA frame`() = runBlocking {
        val port = FakeSerialPort()
        val received = CopyOnWriteArrayList<ByteArray>()
        val iface = newInterface(port)
        iface.onPacketReceived = { data, _ -> received.add(data) }

        iface.start()
        waitUntil("online") { iface.online.value }

        val payload = "hello".toByteArray()
        port.feed(KISS.frame(payload, KISS.CMD_DATA))
        waitUntil("frame received") { received.isNotEmpty() }

        assertEquals(1, received.size)
        assertArrayEquals(payload, received[0])
    }

    @Test
    fun `KISS escape sequences round-trip`() = runBlocking {
        val port = FakeSerialPort()
        val received = CopyOnWriteArrayList<ByteArray>()
        val iface = newInterface(port)
        iface.onPacketReceived = { data, _ -> received.add(data) }
        iface.start()
        waitUntil("online") { iface.online.value }

        val payload = byteArrayOf(0x01, 0xC0.toByte(), 0x02, 0xDB.toByte(), 0x03)
        port.feed(KISS.frame(payload, KISS.CMD_DATA))
        waitUntil("frame received") { received.isNotEmpty() }

        assertArrayEquals(payload, received[0])
    }

    @Test
    fun `a frame split across reads reassembles`() = runBlocking {
        val port = FakeSerialPort()
        val received = CopyOnWriteArrayList<ByteArray>()
        val iface = newInterface(port)
        iface.onPacketReceived = { data, _ -> received.add(data) }
        iface.start()
        waitUntil("online") { iface.online.value }

        val payload = "fragmented".toByteArray()
        val frame = KISS.frame(payload, KISS.CMD_DATA)
        val split = frame.size / 2
        port.feed(frame.copyOfRange(0, split))
        port.feed(frame.copyOfRange(split, frame.size))
        waitUntil("frame reassembled") { received.isNotEmpty() }

        assertArrayEquals(payload, received[0])
    }

    @Test
    fun `rx_bound caps an oversized frame and the reader resyncs`() = runBlocking {
        val port = FakeSerialPort()
        val received = CopyOnWriteArrayList<ByteArray>()
        val iface = newInterface(port, hwMtu = 8)
        iface.onPacketReceived = { data, _ -> received.add(data) }
        iface.start()
        waitUntil("online") { iface.online.value }

        // A CMD_DATA frame whose payload (100 bytes) far exceeds rx_bound (8).
        port.feed(byteArrayOf(KISS.FEND, KISS.CMD_DATA))
        port.feed(ByteArray(100) { 0x41 }) // 'A' * 100
        port.feed(byteArrayOf(KISS.FEND))
        waitUntil("oversized frame closed") { received.isNotEmpty() }

        assertEquals(8, received[0].size, "payload must be capped at rx_bound, not grown to 100")
        assertTrue(received[0].all { it == 0x41.toByte() })

        val payload = "ok".toByteArray()
        port.feed(KISS.frame(payload, KISS.CMD_DATA))
        waitUntil("resynced frame received") { received.size >= 2 }
        assertArrayEquals(payload, received[1])
    }

    @Test
    fun `a dangling FESC does not leak escape state into the next frame`() = runBlocking {
        val port = FakeSerialPort()
        val received = CopyOnWriteArrayList<ByteArray>()
        val iface = newInterface(port)
        iface.onPacketReceived = { data, _ -> received.add(data) }
        iface.start()
        waitUntil("online") { iface.online.value }

        // Frame 1 ends with a dangling FESC just before the closing FEND (malformed).
        // Pre-fix, escape=true leaked into frame 2 and transposed its first byte.
        port.feed(byteArrayOf(KISS.FEND, KISS.CMD_DATA, 0x01, 0x02, KISS.FESC, KISS.FEND))
        waitUntil("frame 1 delivered") { received.isNotEmpty() }
        assertArrayEquals(byteArrayOf(0x01, 0x02), received[0])

        // Frame 2's first data byte is TFEND (0xDC): if escape leaked it would be
        // transposed to FEND (0xC0). It must arrive literally.
        port.feed(byteArrayOf(KISS.FEND, KISS.CMD_DATA, KISS.TFEND, 0x99.toByte(), KISS.FEND))
        waitUntil("frame 2 delivered") { received.size >= 2 }
        assertArrayEquals(byteArrayOf(KISS.TFEND, 0x99.toByte()), received[1])
    }

    @Test
    fun `outgoing data is KISS-framed and written`() = runBlocking {
        val port = FakeSerialPort()
        val iface = newInterface(port)
        iface.start()
        waitUntil("online") { iface.online.value }

        val payload = "hi".toByteArray()
        iface.processOutgoing(payload)
        waitUntil("frame written") { port.written.isNotEmpty() }

        assertEquals(1, port.written.size)
        assertArrayEquals(KISS.frame(payload, KISS.CMD_DATA), port.written[0])
    }

    @Test
    fun `a frame open past the duration ceiling is discarded and the reader resyncs`() = runBlocking {
        val port = FakeSerialPort()
        val received = CopyOnWriteArrayList<ByteArray>()
        // Duration ceiling 50ms; inter-byte timeout high so this isolates the ceiling.
        val iface = newInterface(port, maxFrameDurationMsOverride = 50L, interByteTimeoutMs = 10_000L)
        iface.onPacketReceived = { data, _ -> received.add(data) }
        iface.start()
        waitUntil("online") { iface.online.value }

        // Open a frame and never close it.
        port.feed(byteArrayOf(KISS.FEND, KISS.CMD_DATA, 0x41))
        delay(150) // let the duration ceiling fire and discard the stuck frame

        // A well-formed frame afterwards must still be delivered (resync).
        val payload = "ok".toByteArray()
        port.feed(KISS.frame(payload, KISS.CMD_DATA))
        waitUntil("resynced frame received") { received.isNotEmpty() }

        assertEquals(1, received.size, "the stuck frame must have been discarded, not delivered")
        assertArrayEquals(payload, received[0])
    }

    @Test
    fun `a link drop triggers a reconnect`() = runBlocking {
        val port = FakeSerialPort()
        val iface = newInterface(port)
        iface.start()
        waitUntil("first open") { port.openCalls >= 1 }
        waitUntil("online") { iface.online.value }

        port.drop()
        waitUntil("reopened after drop") { port.openCalls >= 2 }

        assertTrue(port.openCalls >= 2)
    }

    @Test
    fun `a short write closes and reconnects`() = runBlocking {
        val port = FakeSerialPort()
        port.writeShort = true
        val iface = newInterface(port)
        iface.start()
        waitUntil("online") { iface.online.value }

        iface.processOutgoing("x".toByteArray())
        waitUntil("reopened after short write") { port.openCalls >= 2 }

        assertTrue(port.openCalls >= 2)
    }

    @Test
    fun `detach takes the interface offline and closes the port`() = runBlocking {
        val port = FakeSerialPort()
        val received = CopyOnWriteArrayList<ByteArray>()
        val iface = newInterface(port)
        iface.onPacketReceived = { data, _ -> received.add(data) }
        iface.start()
        waitUntil("online") { iface.online.value }

        iface.detach()

        assertFalse(iface.online.value)
        assertTrue(iface.detached.get())
        waitUntil("port closed") { !port.isOpen }

        port.feed(KISS.frame("late".toByteArray(), KISS.CMD_DATA))
        delay(80)
        assertTrue(received.isEmpty())
    }

    @Test
    fun `flow control queues a frame and releases it on timeout unlock`() = runBlocking {
        val port = FakeSerialPort()
        val iface = newInterface(port, flowControl = true, flowControlTimeoutMs = 100L)
        iface.start()
        waitUntil("online") { iface.online.value }

        val a = "a".toByteArray()
        val b = "b".toByteArray()
        iface.processOutgoing(a) // sent immediately, then flow control locks
        waitUntil("first frame written") { port.written.size >= 1 }
        iface.processOutgoing(b) // locked -> queued

        // The flow-control timeout unlock (>100ms) must release the queued frame.
        waitUntil("queued frame released") { port.written.size >= 2 }

        assertArrayEquals(KISS.frame(a, KISS.CMD_DATA), port.written[0])
        assertArrayEquals(KISS.frame(b, KISS.CMD_DATA), port.written[1])
    }

    @Test
    fun `the flow-control queue is bounded and drops the newest past the cap`() = runBlocking {
        val port = FakeSerialPort()
        // A timeout long enough that nothing unlocks the gate on its own during the test:
        // every frame after the first is queued, and only the READY frames fed below
        // release anything.
        val iface = newInterface(port, flowControl = true, flowControlTimeoutMs = 600_000L)
        iface.start()
        waitUntil("online") { iface.online.value }

        val cap = KissInterface.OUTBOUND_QUEUE_CAPACITY
        val overshoot = 50
        val payloads = (0 until 1 + cap + overshoot).map { "p$it".toByteArray() }

        iface.processOutgoing(payloads[0]) // sent immediately, then the gate locks
        waitUntil("first frame written") { port.written.size >= 1 }
        for (i in 1 until payloads.size) iface.processOutgoing(payloads[i])

        // One READY releases one queued frame and re-locks, so feed more READYs than there
        // could ever be queued frames. A READY needs a payload byte: the deframer runs the
        // READY branch per payload byte, and a zero-length READY frame has none.
        repeat(payloads.size + 16) { port.feed(KISS.frame(byteArrayOf(0x01), KISS.CMD_READY)) }

        val expected = 1 + cap
        waitUntil("queue drained") { port.written.size >= expected }
        delay(150) // let any further release land, so an over-count would be caught
        assertEquals(expected, port.written.size, "only the first frame plus a full queue should reach the port")

        // FIFO order is the reference's, and the drops are the newest frames, not the oldest.
        for (i in 0 until expected) {
            assertArrayEquals(KISS.frame(payloads[i], KISS.CMD_DATA), port.written[i], "frame $i")
        }
    }

    @Test
    fun `the flow-control timeout unlocks while the port keeps delivering bytes`() = runBlocking {
        val port = FakeSerialPort()
        val iface = newInterface(port, flowControl = true, flowControlTimeoutMs = 100L)
        iface.start()
        waitUntil("online") { iface.online.value }

        val a = "a".toByteArray()
        val b = "b".toByteArray()
        iface.processOutgoing(a) // sent immediately, then the gate locks
        waitUntil("first frame written") { port.written.size >= 1 }
        iface.processOutgoing(b) // locked -> queued

        // From here the port always has bytes to hand over, so the read loop never has an
        // idle iteration. The flow-control timeout must still fire and release the frame.
        port.chatter = ByteArray(8)

        waitUntil("queued frame released despite continuous inbound bytes") { port.written.size >= 2 }
        assertArrayEquals(KISS.frame(b, KISS.CMD_DATA), port.written[1])

        port.chatter = null
    }

    @Test
    fun `ax25 mode prepends the header on TX and strips it on RX`() = runBlocking {
        val port = FakeSerialPort()
        val received = CopyOnWriteArrayList<ByteArray>()
        val iface = newInterface(port, ax25 = true, ax25SrcCall = "NOCALL", ax25DstCall = "APZRNS")
        iface.onPacketReceived = { data, _ -> received.add(data) }
        iface.start()
        waitUntil("online") { iface.online.value }

        val header = Ax25.buildHeader("APZRNS", 0, "NOCALL", 0)

        // RX: a frame carrying header+payload delivers only the payload.
        val rxPayload = "world".toByteArray()
        port.feed(KISS.frame(header + rxPayload, KISS.CMD_DATA))
        waitUntil("frame received") { received.isNotEmpty() }
        assertArrayEquals(rxPayload, received[0])

        // TX: the written frame carries header+payload.
        val txPayload = "hi".toByteArray()
        iface.processOutgoing(txPayload)
        waitUntil("frame written") { port.written.isNotEmpty() }
        assertArrayEquals(KISS.frame(header + txPayload, KISS.CMD_DATA), port.written[0])
    }

    @Test
    fun `ax25 mode rejects an invalid source callsign at construction`() {
        assertThrows(IllegalArgumentException::class.java) {
            KissInterface(name = "bad", port = FakeSerialPort(), ax25 = true, ax25SrcCall = "X")
        }
    }

    @Test
    fun `configureTnc sends the KISS config commands on open`() = runBlocking {
        val port = FakeSerialPort()
        val iface = newInterface(port, configureTnc = true)
        iface.start()
        waitUntil("config commands sent") { port.written.size >= 5 }

        // FEND CMD value FEND, with ms values divided by 10 (defaults 350/20/64/20).
        assertArrayEquals(byteArrayOf(KISS.FEND, 0x01, 35, KISS.FEND), port.written[0]) // TXDELAY (preamble)
        assertArrayEquals(byteArrayOf(KISS.FEND, 0x04, 2, KISS.FEND), port.written[1])  // TXTAIL
        assertArrayEquals(byteArrayOf(KISS.FEND, 0x02, 64, KISS.FEND), port.written[2]) // P (persistence)
        assertArrayEquals(byteArrayOf(KISS.FEND, 0x03, 2, KISS.FEND), port.written[3])  // SLOTTIME
        assertArrayEquals(byteArrayOf(KISS.FEND, 0x0F, 0x01, KISS.FEND), port.written[4]) // READY (flow control)
    }

    @Test
    fun `beacon is transmitted after the interval following a data frame`() = runBlocking {
        val port = FakeSerialPort()
        val beacon = "BCN".toByteArray()
        val iface = newInterface(port, beaconIntervalMs = 100L, beaconData = beacon)
        iface.start()
        waitUntil("online") { iface.online.value }

        iface.processOutgoing("data".toByteArray()) // starts the beacon timer
        waitUntil("data frame written") { port.written.isNotEmpty() }

        // After the interval, the read loop's housekeeping transmits the beacon, padded
        // with zero bytes to the reference's minimum beacon length.
        waitUntil("beacon transmitted") { port.written.size >= 2 }
        val padded = beacon.copyOf(KissInterface.BEACON_MIN_SIZE)
        assertArrayEquals(KISS.frame(padded, KISS.CMD_DATA), port.written[1])
    }

    @Test
    fun `a beacon at or above the minimum length is sent unpadded`() = runBlocking {
        val port = FakeSerialPort()
        val beacon = "LONGCALLSIGN-15".toByteArray() // exactly BEACON_MIN_SIZE
        assertEquals(KissInterface.BEACON_MIN_SIZE, beacon.size)
        val iface = newInterface(port, beaconIntervalMs = 100L, beaconData = beacon)
        iface.start()
        waitUntil("online") { iface.online.value }

        iface.processOutgoing("data".toByteArray())
        waitUntil("data frame written") { port.written.isNotEmpty() }
        waitUntil("beacon transmitted") { port.written.size >= 2 }
        assertArrayEquals(KISS.frame(beacon, KISS.CMD_DATA), port.written[1])
    }

    @Test
    fun `sendCommandFrame writes a FEND-wrapped, escaped command frame`() = runBlocking {
        val port = FakeSerialPort()
        val iface = newInterface(port)
        iface.start()
        waitUntil("online") { iface.online.value }

        // MeshCore SetHardware (0x06): sub_cmd 0x09 + a payload byte (0xC0) that must be escaped.
        assertTrue(iface.sendCommandFrame(0x06, byteArrayOf(0x09, 0xC0.toByte(), 0x01)))
        waitUntil("command frame written") { port.written.any { it.size >= 2 && it[1] == 0x06.toByte() } }

        val frame = port.written.first { it.size >= 2 && it[1] == 0x06.toByte() }
        assertArrayEquals(
            byteArrayOf(KISS.FEND, 0x06, 0x09, KISS.FESC, KISS.TFEND, 0x01, KISS.FEND),
            frame,
        )
    }

    @Test
    fun `onCommandFrame surfaces a top-level telemetry frame with the raw command byte`() = runBlocking {
        val port = FakeSerialPort()
        val cmds = CopyOnWriteArrayList<Pair<Byte, ByteArray>>()
        val iface = newInterface(port)
        iface.onCommandFrame = { c, p -> cmds.add(c to p) }
        iface.start()
        waitUntil("online") { iface.online.value }

        // MeshCore telemetry is a TOP-LEVEL KISS command byte (not wrapped). 0x23 (RSSI) has a
        // non-zero port nibble; the deframer must surface it as 0x23, NOT strip the nibble to
        // 0x03 (which would collide with the SLOTTIME config command). RSSI is a single byte
        // (dBm+157); use an escapable value (0xC0) to also exercise unescape.
        val payload = byteArrayOf(0xC0.toByte())
        port.feed(KISS.frame(payload, 0x23.toByte()))
        waitUntil("telemetry surfaced") { cmds.isNotEmpty() }

        assertEquals(0x23.toByte(), cmds[0].first)
        assertArrayEquals(payload, cmds[0].second)
    }

    @Test
    fun `onCommandFrame delivers a wrapped MeshCore hardware response (0x06 + sub-command)`() = runBlocking {
        val port = FakeSerialPort()
        val cmds = CopyOnWriteArrayList<Pair<Byte, ByteArray>>()
        val iface = newInterface(port)
        iface.onCommandFrame = { c, p -> cmds.add(c to p) }
        iface.start()
        waitUntil("online") { iface.online.value }

        // MeshCore wraps hardware responses under SetHardware: a GET_RADIO reply on the wire is
        // FEND 0x06 0x8B <10 bytes> FEND. onCommandFrame must deliver cmd=0x06 with the
        // sub-command as payload[0] (NOT cmd=0x8B — 0x8B never arrives top-level). The 10-byte
        // body is freq u32 LE, bw u32 LE, sf u8, cr u8 (the freq's 0xC0 byte also exercises escape).
        val body = le32(915_000_000) + le32(62_500) + byteArrayOf(8, 5)
        val hwResp = byteArrayOf(0x8B.toByte()) + body
        port.feed(KISS.frame(hwResp, 0x06.toByte()))
        waitUntil("hw response surfaced") { cmds.isNotEmpty() }

        assertEquals(0x06.toByte(), cmds[0].first)
        assertEquals(0x8B.toByte(), cmds[0].second[0])
        assertArrayEquals(hwResp, cmds[0].second)
    }

    @Test
    fun `onCommandFrame delivers a top-level 0x25 CHTM telemetry frame intact`() = runBlocking {
        val port = FakeSerialPort()
        val cmds = CopyOnWriteArrayList<Pair<Byte, ByteArray>>()
        val iface = newInterface(port)
        iface.onCommandFrame = { c, p -> cmds.add(c to p) }
        iface.start()
        waitUntil("online") { iface.online.value }

        // MeshCore CHTM (0x25) is top-level, 11 bytes, BIG-ENDIAN: four u16 BE percent*100
        // (airtime short/long, channel-util short/long), then RSSI/noise (u8 dBm+157) and an
        // interference byte (0xFF = none). The interface delivers raw bytes; decoding is the
        // consumer's job. This pins the on-wire size/shape the parser must expect.
        val chtm = be16(1234) + be16(0) + be16(5000) + be16(10000) +
            byteArrayOf(57, 40, 0xFF.toByte())
        port.feed(KISS.frame(chtm, 0x25.toByte()))
        waitUntil("chtm surfaced") { cmds.isNotEmpty() }

        assertEquals(0x25.toByte(), cmds[0].first)
        assertEquals(11, cmds[0].second.size)
        assertArrayEquals(chtm, cmds[0].second)
    }

    @Test
    fun `DATA frames go to the packet path, not to onCommandFrame`() = runBlocking {
        val port = FakeSerialPort()
        val received = CopyOnWriteArrayList<ByteArray>()
        val cmds = CopyOnWriteArrayList<Byte>()
        val iface = newInterface(port)
        iface.onPacketReceived = { d, _ -> received.add(d) }
        iface.onCommandFrame = { c, _ -> cmds.add(c) }
        iface.start()
        waitUntil("online") { iface.online.value }

        port.feed(KISS.frame("data".toByteArray(), KISS.CMD_DATA))
        waitUntil("data received") { received.isNotEmpty() }
        delay(50) // give any stray command callback a chance to (wrongly) fire

        assertEquals(1, received.size)
        assertTrue(cmds.isEmpty(), "a DATA frame must not surface via onCommandFrame")
    }

    @Test
    fun `a non-DATA frame is dropped without a handler and does not disrupt following DATA`() = runBlocking {
        val port = FakeSerialPort()
        val received = CopyOnWriteArrayList<ByteArray>()
        val iface = newInterface(port) // no onCommandFrame handler
        iface.onPacketReceived = { d, _ -> received.add(d) }
        iface.start()
        waitUntil("online") { iface.online.value }

        // A wrapped SET_RADIO ack (0x06, 0xF0) — non-DATA, so dropped with no handler.
        port.feed(KISS.frame(byteArrayOf(0xF0.toByte()), 0x06.toByte()))
        port.feed(KISS.frame("ok".toByteArray(), KISS.CMD_DATA))
        waitUntil("data received") { received.isNotEmpty() }

        assertArrayEquals("ok".toByteArray(), received[0])
    }
}
