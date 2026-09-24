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
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Assertions.fail
import org.junit.jupiter.api.Test
import java.io.ByteArrayInputStream
import java.io.PipedInputStream
import java.io.PipedOutputStream
import java.util.concurrent.CopyOnWriteArrayList

class StreamKissSerialPortTest {

    private val live = mutableListOf<KissInterface>()

    @AfterEach
    fun tearDown() {
        live.forEach { it.detach() }
        live.clear()
    }

    private suspend fun waitUntil(description: String, condition: () -> Boolean) {
        try {
            withTimeout(3_000) { while (!condition()) delay(5) }
        } catch (e: TimeoutCancellationException) {
            fail<Unit>("timed out waiting for: $description")
        }
    }

    @Test
    fun `reads available bytes and writes to the output stream`() = runBlocking {
        val tncOut = PipedOutputStream()
        val adapterIn = PipedInputStream(tncOut, 4096)
        val adapterOut = PipedOutputStream()
        val tncIn = PipedInputStream(adapterOut, 4096)

        val port = StreamKissSerialPort { adapterIn to adapterOut }
        assertTrue(port.open())
        assertTrue(port.isOpen)

        tncOut.write(byteArrayOf(1, 2, 3)); tncOut.flush()
        // The port's reader thread takes bytes off the stream as they arrive; drain
        // through the port, not the underlying stream.
        val collected = java.io.ByteArrayOutputStream()
        waitUntil("bytes drained through the port") {
            collected.write(port.read())
            collected.size() >= 3
        }
        assertArrayEquals(byteArrayOf(1, 2, 3), collected.toByteArray())
        assertTrue(port.read().isEmpty(), "no bytes available -> empty read")

        assertEquals(2, port.write(byteArrayOf(9, 8)))
        val got = ByteArray(2)
        tncIn.read(got)
        assertArrayEquals(byteArrayOf(9, 8), got)

        port.close()
        assertFalse(port.isOpen)
    }

    @Test
    fun `a write error marks the port closed`() = runBlocking {
        val adapterOut = PipedOutputStream()
        val reader = PipedInputStream(adapterOut, 1024)
        val port = StreamKissSerialPort { ByteArrayInputStream(ByteArray(0)) to adapterOut }
        assertTrue(port.open())

        reader.close() // the sink is gone; the next write must fail

        assertEquals(-1, port.write(byteArrayOf(1)))
        assertFalse(port.isOpen, "a write error should mark the port closed so the interface reconnects")
    }

    /**
     * The defect this pins (Android RFCOMM): on a dead link `available()` is 0
     * forever and never throws, so a port that only looked at liveness inside its
     * `available() > 0` branch stayed open indefinitely. The port must observe
     * end-of-stream WITHOUT anyone calling read().
     */
    @Test
    fun `a stream that dies while idle marks the port closed without a read call`() = runBlocking {
        val tncOut = PipedOutputStream()
        val adapterIn = PipedInputStream(tncOut, 1024)
        val adapterOut = PipedOutputStream()
        PipedInputStream(adapterOut, 1024)

        val port = StreamKissSerialPort { adapterIn to adapterOut }
        assertTrue(port.open())
        assertTrue(port.isOpen)

        tncOut.close() // the far end goes away; nothing was ever sent, nothing is ever read

        waitUntil("port reports closed") { !port.isOpen }
        assertEquals(0, adapterIn.available(), "no bytes: liveness must not depend on available()")
    }

    /** Same scenario one level up: the interface must go offline, not sit online forever. */
    @Test
    fun `KissInterface goes offline when the idle stream dies`() = runBlocking {
        val tncOut = PipedOutputStream()
        val adapterIn = PipedInputStream(tncOut, 1024)
        val adapterOut = PipedOutputStream()
        PipedInputStream(adapterOut, 1024)

        var opens = 0
        val port = StreamKissSerialPort {
            opens++
            if (opens == 1) adapterIn to adapterOut else null // no reconnect target after the drop
        }
        val iface = KissInterface(name = "idle-death", port = port, reconnectIntervalMs = 5_000L)
        live += iface
        iface.start()
        waitUntil("online") { iface.online.value }

        tncOut.close() // radio powered off while idle

        waitUntil("interface offline") { !iface.online.value }
    }

    @Test
    fun `KissInterface round-trips over piped streams`() = runBlocking {
        // TNC -> adapter (what the interface reads)
        val tncOut = PipedOutputStream()
        val adapterIn = PipedInputStream(tncOut, 8192)
        // adapter -> TNC (what the interface writes)
        val adapterOut = PipedOutputStream()
        val tncIn = PipedInputStream(adapterOut, 8192)

        val port = StreamKissSerialPort { adapterIn to adapterOut }
        val received = CopyOnWriteArrayList<ByteArray>()
        val iface = KissInterface(name = "stream-test", port = port, reconnectIntervalMs = 50L)
        live += iface
        iface.onPacketReceived = { data, _ -> received.add(data) }
        iface.start()
        waitUntil("online") { iface.online.value }

        // RX: the TNC sends a KISS frame; the interface delivers the payload.
        val rx = "hello".toByteArray()
        tncOut.write(KISS.frame(rx, KISS.CMD_DATA)); tncOut.flush()
        waitUntil("frame received") { received.isNotEmpty() }
        assertArrayEquals(rx, received[0])

        // TX: the interface sends; the raw KISS frame appears on the TNC side.
        val tx = "hi".toByteArray()
        val expected = KISS.frame(tx, KISS.CMD_DATA)
        iface.processOutgoing(tx)
        waitUntil("frame on the TNC side") { tncIn.available() >= expected.size }
        val buf = ByteArray(expected.size)
        var read = 0
        while (read < expected.size) {
            val n = tncIn.read(buf, read, expected.size - read)
            if (n <= 0) break
            read += n
        }
        assertArrayEquals(expected, buf)
    }
}
