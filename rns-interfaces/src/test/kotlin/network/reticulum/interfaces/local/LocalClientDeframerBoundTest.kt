package network.reticulum.interfaces.local

import network.reticulum.interfaces.framing.HDLC
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Timeout
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * A server-spawned LocalClientInterface must bound its HDLC deframer like python
 * LocalInterface.py:79-80 / util/HDLC.py:81-83: an unterminated run longer than the bound
 * is discarded, not accumulated (and not delivered when a FLAG finally arrives).
 */
class LocalClientDeframerBoundTest {

    private var server: LocalServerInterface? = null
    private var raw: Socket? = null

    @AfterEach
    fun tearDown() {
        try { raw?.close() } catch (_: Exception) {}
        try { server?.detach() } catch (_: Exception) {}
        Thread.sleep(100)
    }

    @Test
    @Timeout(60, unit = TimeUnit.SECONDS)
    fun `an unterminated run longer than the bound is discarded and the deframer resyncs`() {
        val received = CopyOnWriteArrayList<ByteArray>()
        val latch = CountDownLatch(1)

        val srv = LocalServerInterface(name = "BoundServer", tcpPort = 0)
        srv.onPacketReceived = { data, _ -> received.add(data); latch.countDown() }
        server = srv
        srv.start()

        val sock = Socket()
        sock.connect(InetSocketAddress("127.0.0.1", srv.boundPort), 3000)
        raw = sock
        val out = sock.getOutputStream()

        // Open a frame and stream one byte more than the bound with no closing FLAG.
        // An unbounded deframer would accumulate all of it and, on the FLAG below,
        // deliver it as one oversized frame (it is > HEADER_MIN_SIZE).
        out.write(byteArrayOf(HDLC.FLAG))
        val run = ByteArray(64 * 1024) { 0x41 }
        var remaining = LocalClientInterface.MAX_FRAME_BYTES + 1
        while (remaining > 0) {
            val n = minOf(remaining, run.size)
            out.write(run, 0, n)
            remaining -= n
        }
        out.write(byteArrayOf(HDLC.FLAG))

        // A well-formed frame afterwards must still be delivered (resync).
        val payload = ByteArray(40) { (it + 1).toByte() }
        out.write(HDLC.frame(payload))
        out.flush()

        assertTrue(latch.await(30, TimeUnit.SECONDS), "the well-formed frame should be delivered")
        // Give any (wrong) oversized delivery a moment to show up too.
        Thread.sleep(300)

        assertEquals(1, received.size, "only the well-formed frame must be delivered; the over-bound run is discarded")
        assertArrayEquals(payload, received[0])
    }
}
