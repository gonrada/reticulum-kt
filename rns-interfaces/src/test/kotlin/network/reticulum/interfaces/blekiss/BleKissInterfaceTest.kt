package network.reticulum.interfaces.blekiss

import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import network.reticulum.interfaces.framing.KISS
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Assertions.fail
import org.junit.jupiter.api.Test
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicInteger

/**
 * In-memory [NusLink] fake — lets a test act as the BLE peripheral (a KISS TNC):
 * push notification bytes with [deliver], capture what the interface writes in
 * [writes], and simulate connect/write outcomes and link drops. The incoming
 * channel is buffered, so a [deliver] before the collector subscribes is not
 * lost (avoiding the replay=0 SharedFlow drop the sibling BLE tests warn about).
 */
private class FakeNusLink : NusLink {
    private val inCh = Channel<ByteArray>(Channel.UNLIMITED)
    override val incoming: Flow<ByteArray> = inCh.receiveAsFlow()

    private val _connected = MutableStateFlow(false)
    override val connected: StateFlow<Boolean> = _connected.asStateFlow()

    @Volatile var connectResult = true
    @Volatile var writeResult = true
    private val _connectCalls = AtomicInteger(0)
    val connectCalls: Int get() = _connectCalls.get()
    val writes = CopyOnWriteArrayList<ByteArray>()

    override suspend fun connect(timeoutMs: Long): Boolean {
        _connectCalls.incrementAndGet()
        _connected.value = connectResult
        return connectResult
    }

    override suspend fun write(frame: ByteArray): Boolean {
        if (writeResult) writes.add(frame)
        return writeResult
    }

    override suspend fun close() {
        _connected.value = false
    }

    /** Simulate a NUS TX-characteristic notification from the peripheral. */
    fun deliver(bytes: ByteArray) {
        inCh.trySend(bytes)
    }

    /** Simulate the peripheral / link dropping. */
    fun dropLink() {
        _connected.value = false
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

class BleKissInterfaceTest {

    // Interfaces run on their own Dispatchers.IO scope; detach them so no
    // session/reader coroutine outlives its test.
    private val live = mutableListOf<BleKissInterface>()

    @AfterEach
    fun tearDown() {
        live.forEach { it.detach() }
        live.clear()
    }

    private fun newInterface(fake: FakeNusLink, hwMtu: Int = BleKissInterface.DEFAULT_HW_MTU): BleKissInterface {
        val iface = BleKissInterface("t", "AA:BB:CC:DD:EE:FF", fake, hwMtuBytes = hwMtu)
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
    fun `connects, goes online, and delivers a CMD_DATA frame`() = runBlocking {
        val fake = FakeNusLink()
        val received = CopyOnWriteArrayList<ByteArray>()
        val iface = newInterface(fake)
        iface.onPacketReceived = { data, _ -> received.add(data) }

        iface.start()
        waitUntil("interface online") { iface.online.value }

        val payload = "hello".toByteArray()
        fake.deliver(KISS.frame(payload, KISS.CMD_DATA))
        waitUntil("frame received") { received.isNotEmpty() }

        assertEquals(1, received.size)
        assertArrayEquals(payload, received[0])
    }

    @Test
    fun `KISS escape sequences round-trip through the deframer`() = runBlocking {
        val fake = FakeNusLink()
        val received = CopyOnWriteArrayList<ByteArray>()
        val iface = newInterface(fake)
        iface.onPacketReceived = { data, _ -> received.add(data) }
        iface.start()
        waitUntil("interface online") { iface.online.value }

        // Payload containing raw FEND (0xC0) and FESC (0xDB), which KISS.frame
        // escapes and the deframer must restore.
        val payload = byteArrayOf(0x01, 0xC0.toByte(), 0x02, 0xDB.toByte(), 0x03)
        fake.deliver(KISS.frame(payload, KISS.CMD_DATA))
        waitUntil("frame received") { received.isNotEmpty() }

        assertArrayEquals(payload, received[0])
    }

    @Test
    fun `a frame split across notifications reassembles`() = runBlocking {
        val fake = FakeNusLink()
        val received = CopyOnWriteArrayList<ByteArray>()
        val iface = newInterface(fake)
        iface.onPacketReceived = { data, _ -> received.add(data) }
        iface.start()
        waitUntil("interface online") { iface.online.value }

        val payload = "fragmented".toByteArray()
        val frame = KISS.frame(payload, KISS.CMD_DATA)
        val split = frame.size / 2
        fake.deliver(frame.copyOfRange(0, split))
        fake.deliver(frame.copyOfRange(split, frame.size))
        waitUntil("frame reassembled") { received.isNotEmpty() }

        assertEquals(1, received.size)
        assertArrayEquals(payload, received[0])
    }

    @Test
    fun `rx_bound bounds an oversized frame and the interface resyncs`() = runBlocking {
        val fake = FakeNusLink()
        val received = CopyOnWriteArrayList<ByteArray>()
        // hwMtu 8 -> rx_bound 9 (command byte + 8 payload bytes).
        val iface = newInterface(fake, hwMtu = 8)
        iface.onPacketReceived = { data, _ -> received.add(data) }
        iface.start()
        waitUntil("interface online") { iface.online.value }

        // Open a frame, flood 100 non-FEND bytes with no closing FEND, then close.
        fake.deliver(byteArrayOf(KISS.FEND, KISS.CMD_DATA))
        fake.deliver(ByteArray(100) { 0x41 }) // 'A' * 100
        fake.deliver(byteArrayOf(KISS.FEND))
        waitUntil("oversized frame closed") { received.isNotEmpty() }

        assertEquals(8, received[0].size, "payload must be capped at rx_bound-1, not grown to 100")
        assertTrue(received[0].all { it == 0x41.toByte() })

        // A well-formed frame after the flood must still be delivered (resync).
        val payload = "ok".toByteArray()
        fake.deliver(KISS.frame(payload, KISS.CMD_DATA))
        waitUntil("resynced frame received") { received.size >= 2 }

        assertArrayEquals(payload, received[1])
    }

    @Test
    fun `outgoing data is KISS-framed and written to the link`() = runBlocking {
        val fake = FakeNusLink()
        val iface = newInterface(fake)
        iface.start()
        waitUntil("interface online") { iface.online.value }

        val payload = "hi".toByteArray()
        iface.processOutgoing(payload)
        waitUntil("frame written") { fake.writes.isNotEmpty() }

        assertEquals(1, fake.writes.size)
        assertArrayEquals(KISS.frame(payload, KISS.CMD_DATA), fake.writes[0])
    }

    @Test
    fun `a frame offered while offline is dropped, not buffered`() = runBlocking {
        val fake = FakeNusLink()
        val iface = newInterface(fake)

        // Offline (not started) -> must be dropped, never sent.
        iface.processOutgoing("dropped".toByteArray())

        iface.start()
        waitUntil("interface online") { iface.online.value }
        val kept = "kept".toByteArray()
        iface.processOutgoing(kept)
        waitUntil("kept frame written") { fake.writes.isNotEmpty() }

        // Only the online frame is present; the offline one never made the queue.
        assertEquals(1, fake.writes.size)
        assertArrayEquals(KISS.frame(kept, KISS.CMD_DATA), fake.writes[0])
    }

    @Test
    fun `detach takes the interface offline and closes the link`() = runBlocking {
        val fake = FakeNusLink()
        val received = CopyOnWriteArrayList<ByteArray>()
        val iface = newInterface(fake)
        iface.onPacketReceived = { data, _ -> received.add(data) }
        iface.start()
        waitUntil("interface online") { iface.online.value }

        iface.detach()

        assertFalse(iface.online.value)
        assertTrue(iface.detached.get())
        waitUntil("link closed") { !fake.connected.value }

        // Anything delivered after detach must not be processed.
        fake.deliver(KISS.frame("late".toByteArray(), KISS.CMD_DATA))
        delay(50)
        assertTrue(received.isEmpty())
    }

    @Test
    fun `a failed write ends the session and reconnects`() = runBlocking {
        val fake = FakeNusLink()
        fake.writeResult = false
        val iface = newInterface(fake)
        iface.start()
        waitUntil("first connect") { fake.connectCalls >= 1 }

        iface.processOutgoing("x".toByteArray())
        waitUntil("reconnect after write failure") { fake.connectCalls >= 2 }

        assertTrue(fake.connectCalls >= 2)
    }

    @Test
    fun `a clean disconnect reconnects`() = runBlocking {
        val fake = FakeNusLink()
        val iface = newInterface(fake)
        iface.start()
        waitUntil("interface online") { iface.online.value }

        fake.dropLink()
        waitUntil("reconnect after drop") { fake.connectCalls >= 2 }
        waitUntil("online again") { iface.online.value }

        assertTrue(fake.connectCalls >= 2)
        assertTrue(iface.online.value)
    }

    @Test
    fun `sendCommandFrame queues a FEND-wrapped, escaped command frame`() = runBlocking {
        val fake = FakeNusLink()
        val iface = newInterface(fake)
        iface.start()
        waitUntil("interface online") { iface.online.value }

        // MeshCore SetHardware (0x06): sub_cmd 0x09 + a payload byte (0xC0) that must be escaped.
        assertTrue(iface.sendCommandFrame(0x06, byteArrayOf(0x09, 0xC0.toByte(), 0x01)))
        waitUntil("command frame written") { fake.writes.isNotEmpty() }

        assertArrayEquals(
            byteArrayOf(KISS.FEND, 0x06, 0x09, KISS.FESC, KISS.TFEND, 0x01, KISS.FEND),
            fake.writes[0],
        )
    }

    @Test
    fun `sendCommandFrame while offline returns false and queues nothing`() = runBlocking {
        val fake = FakeNusLink()
        val iface = newInterface(fake)
        // Not started -> offline.
        assertFalse(iface.sendCommandFrame(0x06, byteArrayOf(0x09)))
        assertTrue(fake.writes.isEmpty())
    }

    @Test
    fun `onCommandFrame surfaces a top-level telemetry frame with the raw command byte`() = runBlocking {
        val fake = FakeNusLink()
        val cmds = CopyOnWriteArrayList<Pair<Byte, ByteArray>>()
        val iface = newInterface(fake)
        iface.onCommandFrame = { c, p -> cmds.add(c to p) }
        iface.start()
        waitUntil("interface online") { iface.online.value }

        // MeshCore telemetry is a TOP-LEVEL KISS command byte (not wrapped). 0x23 (RSSI) has a
        // non-zero port nibble; the deframer must surface it as 0x23, NOT strip the nibble to
        // 0x03. RSSI is a single byte (dBm+157); use an escapable value (0xC0) to exercise unescape.
        val payload = byteArrayOf(0xC0.toByte())
        fake.deliver(KISS.frame(payload, 0x23.toByte()))
        waitUntil("telemetry surfaced") { cmds.isNotEmpty() }

        assertEquals(0x23.toByte(), cmds[0].first)
        assertArrayEquals(payload, cmds[0].second)
    }

    @Test
    fun `onCommandFrame delivers a wrapped MeshCore hardware response (0x06 + sub-command)`() = runBlocking {
        val fake = FakeNusLink()
        val cmds = CopyOnWriteArrayList<Pair<Byte, ByteArray>>()
        val iface = newInterface(fake)
        iface.onCommandFrame = { c, p -> cmds.add(c to p) }
        iface.start()
        waitUntil("interface online") { iface.online.value }

        // MeshCore wraps hardware responses under SetHardware: a GET_RADIO reply on the wire is
        // FEND 0x06 0x8B <10 bytes> FEND. onCommandFrame must deliver cmd=0x06 with the
        // sub-command as payload[0] (NOT cmd=0x8B). Body: freq u32 LE, bw u32 LE, sf u8, cr u8.
        val body = le32(915_000_000) + le32(62_500) + byteArrayOf(8, 5)
        val hwResp = byteArrayOf(0x8B.toByte()) + body
        fake.deliver(KISS.frame(hwResp, 0x06.toByte()))
        waitUntil("hw response surfaced") { cmds.isNotEmpty() }

        assertEquals(0x06.toByte(), cmds[0].first)
        assertEquals(0x8B.toByte(), cmds[0].second[0])
        assertArrayEquals(hwResp, cmds[0].second)
    }

    @Test
    fun `onCommandFrame delivers a top-level 0x25 CHTM telemetry frame intact`() = runBlocking {
        val fake = FakeNusLink()
        val cmds = CopyOnWriteArrayList<Pair<Byte, ByteArray>>()
        val iface = newInterface(fake)
        iface.onCommandFrame = { c, p -> cmds.add(c to p) }
        iface.start()
        waitUntil("interface online") { iface.online.value }

        // MeshCore CHTM (0x25) is top-level, 11 bytes, BIG-ENDIAN: four u16 BE percent*100, then
        // RSSI/noise (u8 dBm+157) and an interference byte (0xFF = none). The interface delivers
        // raw bytes; decoding is the consumer's job. This pins the on-wire size/shape.
        val chtm = be16(1234) + be16(0) + be16(5000) + be16(10000) +
            byteArrayOf(57, 40, 0xFF.toByte())
        fake.deliver(KISS.frame(chtm, 0x25.toByte()))
        waitUntil("chtm surfaced") { cmds.isNotEmpty() }

        assertEquals(0x25.toByte(), cmds[0].first)
        assertEquals(11, cmds[0].second.size)
        assertArrayEquals(chtm, cmds[0].second)
    }

    @Test
    fun `DATA frames go to the packet path, not to onCommandFrame`() = runBlocking {
        val fake = FakeNusLink()
        val received = CopyOnWriteArrayList<ByteArray>()
        val cmds = CopyOnWriteArrayList<Byte>()
        val iface = newInterface(fake)
        iface.onPacketReceived = { data, _ -> received.add(data) }
        iface.onCommandFrame = { c, _ -> cmds.add(c) }
        iface.start()
        waitUntil("interface online") { iface.online.value }

        fake.deliver(KISS.frame("data".toByteArray(), KISS.CMD_DATA))
        waitUntil("data received") { received.isNotEmpty() }
        delay(50) // give any stray command callback a chance to (wrongly) fire

        assertEquals(1, received.size)
        assertTrue(cmds.isEmpty(), "a DATA frame must not surface via onCommandFrame")
    }

    @Test
    fun `a non-DATA frame is dropped without a handler and does not disrupt following DATA`() = runBlocking {
        val fake = FakeNusLink()
        val received = CopyOnWriteArrayList<ByteArray>()
        val iface = newInterface(fake) // no onCommandFrame handler
        iface.onPacketReceived = { data, _ -> received.add(data) }
        iface.start()
        waitUntil("interface online") { iface.online.value }

        // A wrapped SET_RADIO ack (0x06, 0xF0) — non-DATA, so dropped with no handler.
        fake.deliver(KISS.frame(byteArrayOf(0xF0.toByte()), 0x06.toByte()))
        fake.deliver(KISS.frame("ok".toByteArray(), KISS.CMD_DATA))
        waitUntil("data received") { received.isNotEmpty() }

        assertArrayEquals("ok".toByteArray(), received[0])
    }
}
