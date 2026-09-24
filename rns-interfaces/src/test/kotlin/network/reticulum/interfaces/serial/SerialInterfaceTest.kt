package network.reticulum.interfaces.serial

import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import network.reticulum.interfaces.framing.HDLC
import network.reticulum.interfaces.kiss.KissSerialPort
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Assertions.fail
import org.junit.jupiter.api.Test
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicInteger

private class FakePort : KissSerialPort {
    private val inbox = ConcurrentLinkedQueue<Byte>()
    @Volatile private var open = false
    override val isOpen: Boolean get() = open
    @Volatile var writeShort = false
    val written = CopyOnWriteArrayList<ByteArray>()
    private val opens = AtomicInteger(0)
    val openCalls: Int get() = opens.get()

    override suspend fun open(): Boolean {
        opens.incrementAndGet()
        open = true
        return true
    }

    override fun read(): ByteArray {
        if (inbox.isEmpty()) return ByteArray(0)
        val out = ArrayList<Byte>()
        while (true) out.add(inbox.poll() ?: break)
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
}

/** HDLC framing over a byte stream, as python `SerialInterface.readLoop` / `process_outgoing`. */
class SerialInterfaceTest {
    private val live = mutableListOf<SerialInterface>()

    @AfterEach
    fun tearDown() {
        live.forEach { it.detach() }
        live.clear()
    }

    private fun newInterface(
        port: FakePort,
        interByteTimeoutMs: Long = SerialInterface.DEFAULT_INTER_BYTE_TIMEOUT_MS,
    ): SerialInterface =
        SerialInterface(
            name = "serial-test",
            port = port,
            speed = 115200,
            interByteTimeoutMs = interByteTimeoutMs,
            reconnectIntervalMs = 50L,
        ).also { live += it }

    private suspend fun waitUntil(
        description: String,
        condition: () -> Boolean,
    ) {
        try {
            withTimeout(3_000) { while (!condition()) delay(5) }
        } catch (e: TimeoutCancellationException) {
            fail<Unit>("timed out waiting for: $description")
        }
    }

    /** A payload long enough to pass the base class's minimum-frame filter. */
    private fun payload(seed: Int): ByteArray = ByteArray(40) { (it + seed).toByte() }

    @Test
    fun `opens, goes online, and delivers an HDLC frame`() = runBlocking {
        val port = FakePort()
        val iface = newInterface(port)
        val received = CopyOnWriteArrayList<ByteArray>()
        iface.onPacketReceived = { data, _ -> received.add(data) }
        iface.start()
        waitUntil("online") { iface.online.value }
        val data = payload(1)
        port.feed(HDLC.frame(data))
        waitUntil("frame delivered") { received.size == 1 }
        assertArrayEquals(data, received[0])
        assertEquals(115200, iface.bitrate)
        assertEquals(SerialInterface.HW_MTU, iface.hwMtu)
    }

    @Test
    fun `escaped FLAG and ESC bytes round-trip`() = runBlocking {
        val port = FakePort()
        val iface = newInterface(port)
        val received = CopyOnWriteArrayList<ByteArray>()
        iface.onPacketReceived = { data, _ -> received.add(data) }
        iface.start()
        waitUntil("online") { iface.online.value }
        val data = payload(2).also { it[3] = HDLC.FLAG; it[7] = HDLC.ESC }
        port.feed(HDLC.frame(data))
        waitUntil("frame delivered") { received.size == 1 }
        assertArrayEquals(data, received[0])
    }

    @Test
    fun `a frame split across reads reassembles and a runt still reaches the owner`() = runBlocking {
        val port = FakePort()
        val iface = newInterface(port)
        val received = CopyOnWriteArrayList<ByteArray>()
        iface.onPacketReceived = { data, _ -> received.add(data) }
        iface.start()
        waitUntil("online") { iface.online.value }
        val data = payload(3)
        val frame = HDLC.frame(data)
        port.feed(frame.copyOfRange(0, 10))
        delay(20)
        port.feed(frame.copyOfRange(10, frame.size))
        waitUntil("frame delivered") { received.size == 1 }
        assertArrayEquals(data, received[0])
        // python process_incoming forwards any non-empty frame; Transport discards a
        // runt itself (SerialInterface.py:118-121).
        port.feed(HDLC.frame(byteArrayOf(1, 2)))
        waitUntil("runt delivered") { received.size == 2 }
        assertArrayEquals(byteArrayOf(1, 2), received[1])
    }

    @Test
    fun `an oversized frame is truncated at HW_MTU and the reader resyncs`() = runBlocking {
        val port = FakePort()
        val iface = newInterface(port)
        val received = CopyOnWriteArrayList<ByteArray>()
        iface.onPacketReceived = { data, _ -> received.add(data) }
        iface.start()
        waitUntil("online") { iface.online.value }
        port.feed(HDLC.frame(ByteArray(SerialInterface.HW_MTU + 100) { 5 }))
        val data = payload(4)
        port.feed(HDLC.frame(data))
        waitUntil("two frames") { received.size == 2 }
        assertEquals(SerialInterface.HW_MTU, received[0].size, "python stops appending at HW_MTU but still delivers the frame")
        assertArrayEquals(data, received[1])
    }

    @Test
    fun `a stalled partial frame is discarded after the inter-byte timeout`() = runBlocking {
        val port = FakePort()
        val iface = newInterface(port, interByteTimeoutMs = 30L)
        val received = CopyOnWriteArrayList<ByteArray>()
        iface.onPacketReceived = { data, _ -> received.add(data) }
        iface.start()
        waitUntil("online") { iface.online.value }
        val frame = HDLC.frame(payload(5))
        port.feed(frame.copyOfRange(0, 8))
        delay(300)
        port.feed(frame.copyOfRange(8, frame.size)) // the tail alone: ends at FLAG with a short buffer
        delay(150)
        assertTrue(received.isEmpty() || received[0].size < 40, "the stalled head was dropped, not glued to the tail")
    }

    @Test
    fun `outgoing data is HDLC-framed and written`() = runBlocking {
        val port = FakePort()
        val iface = newInterface(port)
        iface.start()
        waitUntil("online") { iface.online.value }
        val data = payload(6).also { it[0] = HDLC.FLAG }
        iface.processOutgoing(data)
        waitUntil("written") { port.written.size == 1 }
        val frame = port.written[0]
        assertEquals(HDLC.FLAG, frame.first())
        assertEquals(HDLC.FLAG, frame.last())
        assertArrayEquals(data, HDLC.unescape(frame.copyOfRange(1, frame.size - 1)))
        assertEquals(frame.size.toLong(), iface.txBytes.get())
    }

    @Test
    fun `a short write closes the port and the interface reconnects`() = runBlocking {
        val port = FakePort()
        val iface = newInterface(port)
        iface.start()
        waitUntil("online") { iface.online.value }
        port.writeShort = true
        iface.processOutgoing(payload(7))
        waitUntil("offline") { !iface.online.value }
        port.writeShort = false
        waitUntil("reopened") { port.openCalls >= 2 && iface.online.value }
    }

    @Test
    fun `detach takes the interface offline and closes the port`() = runBlocking {
        val port = FakePort()
        val iface = newInterface(port)
        iface.start()
        waitUntil("online") { iface.online.value }
        iface.detach()
        waitUntil("closed") { !port.isOpen }
        assertFalse(iface.online.value)
        delay(150)
        assertEquals(1, port.openCalls, "no reconnect after detach")
    }
}
