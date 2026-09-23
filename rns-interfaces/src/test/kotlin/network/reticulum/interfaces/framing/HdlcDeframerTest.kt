package network.reticulum.interfaces.framing

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotSame
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class HdlcDeframerTest {

    // Payload well above HEADER_MIN_SIZE (19), with no FLAG/ESC bytes to escape.
    private val payload = ByteArray(40) { it.toByte() }

    @Test
    fun `unbounded deframer delivers a normal frame`() {
        val got = mutableListOf<ByteArray>()
        val d = HDLC.createDeframer { got.add(it) }
        d.process(HDLC.frame(payload))
        assertEquals(1, got.size)
        assertArrayEquals(payload, got[0])
    }

    @Test
    fun `bounded deframer delivers a frame within the bound`() {
        val got = mutableListOf<ByteArray>()
        val d = HDLC.createDeframer(maxFrameBytes = 64) { got.add(it) }
        d.process(HDLC.frame(payload)) // 40 escaped bytes < 64
        assertEquals(1, got.size)
        assertArrayEquals(payload, got[0])
    }

    @Test
    fun `bounded deframer discards an oversized run and resyncs`() {
        val got = mutableListOf<ByteArray>()
        val d = HDLC.createDeframer(maxFrameBytes = 64) { got.add(it) }

        // Open a frame and stream 200 non-FLAG bytes with no closing FLAG,
        // then close it: the over-bound partial must be discarded, not delivered.
        d.process(byteArrayOf(HDLC.FLAG))
        d.process(ByteArray(200) { 0x41 })
        d.process(byteArrayOf(HDLC.FLAG))
        assertTrue(got.isEmpty(), "an over-bound frame must be discarded")

        // A well-formed frame afterwards must still be delivered (resync).
        d.process(HDLC.frame(payload))
        assertEquals(1, got.size)
        assertArrayEquals(payload, got[0])
    }

    /**
     * A large accumulation must be released when the frame ends, not kept for reuse:
     * `ByteArrayOutputStream.reset()` retains the grown array, which would pin it per
     * connection for the connection's lifetime. Observed through the buffer's identity:
     * a small accumulation keeps the same stream, a large one is replaced.
     */
    @Test
    fun `a large accumulation is released once the frame ends`() {
        val bufferField = HDLC.Deframer::class.java.getDeclaredField("buffer")
            .apply { isAccessible = true }
        val d = HDLC.createDeframer(maxFrameBytes = 1 shl 20) { }

        val small = bufferField.get(d)
        d.process(HDLC.frame(payload))
        assertSame(small, bufferField.get(d), "a small accumulation is reused")

        val before = bufferField.get(d)
        d.process(byteArrayOf(HDLC.FLAG))
        d.process(ByteArray(200_000) { 0x41 })
        d.process(byteArrayOf(HDLC.FLAG))
        assertNotSame(before, bufferField.get(d), "a large accumulation must be released")
    }
}
