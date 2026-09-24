package network.reticulum.interfaces.util

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream

class TransmitBufferTest {

    /** A writer that accepts everything and records it. */
    private class FullSink {
        val out = ByteArrayOutputStream()
        val write: (ByteArray, Int, Int) -> Int = { b, off, len -> out.write(b, off, len); len }
    }

    @Test
    fun `coalesces small frames and drains them in order`() {
        val tb = TransmitBuffer()
        tb.append(byteArrayOf(1, 2, 3))
        tb.append(byteArrayOf(4, 5))
        tb.append(byteArrayOf(6))
        tb.flush()
        val sink = FullSink()
        tb.drainTo(sink.write)
        assertArrayEquals(byteArrayOf(1, 2, 3, 4, 5, 6), sink.out.toByteArray())
        assertEquals(0L, tb.length())
        assertEquals(0L, tb.framesBuffered)
    }

    @Test
    fun `a large frame gets its own chunk and drains intact`() {
        val tb = TransmitBuffer()
        val big = ByteArray(TransmitBuffer.COALESCE_TARGET) { (it % 256).toByte() }
        tb.append(byteArrayOf(1, 2))
        tb.append(big)
        tb.flush()
        assertTrue(tb.chunksBuffered >= 1)
        val sink = FullSink()
        tb.drainTo(sink.write)
        assertArrayEquals(byteArrayOf(1, 2) + big, sink.out.toByteArray())
    }

    @Test
    fun `HWM limit rejects a frame that would exceed it, and frees after drain`() {
        val tb = TransmitBuffer()
        assertTrue(tb.append(ByteArray(100), limit = 150))
        assertFalse(tb.append(ByteArray(100), limit = 150), "a second 100 bytes would exceed 150")
        tb.flush()
        tb.drainTo(FullSink().write)
        assertTrue(tb.append(ByteArray(100), limit = 150), "room frees once the buffer drains")
    }

    @Test
    fun `backpressure stops the drain and it resumes on the next call`() {
        val tb = TransmitBuffer()
        tb.append(byteArrayOf(1, 2, 3, 4, 5, 6))
        tb.flush()

        var budget = 3
        val captured = ByteArrayOutputStream()
        val throttled: (ByteArray, Int, Int) -> Int = { b, off, len ->
            val n = minOf(budget, len)
            if (n <= 0) 0 else { captured.write(b, off, n); budget -= n; n }
        }

        tb.drainTo(throttled)
        assertArrayEquals(byteArrayOf(1, 2, 3), captured.toByteArray())
        assertEquals(3L, tb.length(), "3 of 6 bytes still buffered under backpressure")

        budget = 100
        tb.drainTo(throttled)
        assertArrayEquals(byteArrayOf(1, 2, 3, 4, 5, 6), captured.toByteArray())
        assertEquals(0L, tb.length())
    }

    @Test
    fun `an idle-queue append is immediately sendable without an explicit flush`() {
        val tb = TransmitBuffer()
        tb.append(byteArrayOf(7, 7, 7))
        assertTrue(tb.sendable > 0, "an append onto an idle queue should be immediately visible")
        val sink = FullSink()
        tb.drainTo(sink.write)
        assertArrayEquals(byteArrayOf(7, 7, 7), sink.out.toByteArray())
    }
}
