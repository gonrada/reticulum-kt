package network.reticulum.interfaces.framing

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotSame
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream

class KissDeframerTest {

    private val cmdData = KISS.CMD_DATA

    @Test
    fun `delivers a normal frame`() {
        val got = mutableListOf<ByteArray>()
        val d = KISS.createDeframer(hwMtu = 64) { _, data -> got.add(data) }
        val payload = ByteArray(20) { it.toByte() }
        d.process(KISS.frame(payload, cmdData))
        assertEquals(1, got.size)
        assertArrayEquals(payload, got[0])
    }

    @Test
    fun `truncates a decoded frame to hwMtu`() {
        val got = mutableListOf<ByteArray>()
        val hwMtu = 32
        val d = KISS.createDeframer(hwMtu = hwMtu) { _, data -> got.add(data) }
        val payload = ByteArray(100) { it.toByte() }
        d.process(KISS.frame(payload, cmdData))
        assertEquals(1, got.size)
        assertEquals(hwMtu, got[0].size)
        assertArrayEquals(payload.copyOf(hwMtu), got[0])
    }

    @Test
    fun `resyncs after an over-bound frame`() {
        val got = mutableListOf<ByteArray>()
        val hwMtu = 32
        val d = KISS.createDeframer(hwMtu = hwMtu) { _, data -> got.add(data) }

        d.process(byteArrayOf(KISS.FEND, cmdData))
        d.process(ByteArray(100_000) { 0x41 })
        d.process(byteArrayOf(KISS.FEND)) // close the over-bound frame (delivers truncated)
        got.clear()

        val payload = ByteArray(20) { it.toByte() }
        d.process(KISS.frame(payload, cmdData))
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
        val bufferField = KISS.Deframer::class.java.getDeclaredField("buffer")
            .apply { isAccessible = true }
        val d = KISS.createDeframer(hwMtu = 1 shl 20) { _, _ -> }

        val small = bufferField.get(d)
        d.process(KISS.frame(ByteArray(20) { it.toByte() }, cmdData))
        assertSame(small, bufferField.get(d), "a small accumulation is reused")

        val before = bufferField.get(d)
        d.process(byteArrayOf(KISS.FEND, cmdData))
        d.process(ByteArray(200_000) { 0x41 })
        d.process(byteArrayOf(KISS.FEND))
        assertNotSame(before, bufferField.get(d), "a large accumulation must be released")
    }

    @Test
    fun `bounds the accumulation buffer for a never-closed frame`() {
        val hwMtu = 32
        val d = KISS.createDeframer(hwMtu = hwMtu) { _, _ -> }

        d.process(byteArrayOf(KISS.FEND, cmdData))
        d.process(ByteArray(100_000) { 0x41 }) // stream 100k bytes, no closing FEND

        val bufferField = KISS.Deframer::class.java.getDeclaredField("buffer")
            .apply { isAccessible = true }
        val buffer = bufferField.get(d) as ByteArrayOutputStream
        assertTrue(
            buffer.size() <= hwMtu * 2 + 2,
            "escaped accumulation buffer must stay bounded (was ${buffer.size()})",
        )
    }
}
