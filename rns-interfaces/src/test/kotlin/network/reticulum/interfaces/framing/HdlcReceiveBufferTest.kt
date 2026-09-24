package network.reticulum.interfaces.framing

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class HdlcReceiveBufferTest {

    private fun buffer(
        mtu: Int = 500,
        minFrameLen: Int = 0,
        maxFrameLen: Int? = null,
        onFrame: (ByteArray) -> Unit = {},
        onInvalid: (Int) -> Unit = {},
    ) = HdlcReceiveBuffer({ mtu }, minFrameLen, { maxFrameLen }, onFrame, onInvalid)

    @Test
    fun `delivers a single complete frame unescaped`() {
        val frames = mutableListOf<ByteArray>()
        val rb = buffer(onFrame = { frames += it })
        val payload = byteArrayOf(1, 2, 3, 4, 5)
        rb.feed(HDLC.frame(payload))
        assertEquals(1, frames.size)
        assertArrayEquals(payload, frames[0])
    }

    @Test
    fun `unescapes FLAG and ESC bytes in the payload`() {
        val frames = mutableListOf<ByteArray>()
        val rb = buffer(onFrame = { frames += it })
        val payload = byteArrayOf(HDLC.FLAG, HDLC.ESC, 0x00, HDLC.FLAG)
        rb.feed(HDLC.frame(payload))
        assertEquals(1, frames.size)
        assertArrayEquals(payload, frames[0])
    }

    @Test
    fun `reassembles a frame split across two feeds`() {
        val frames = mutableListOf<ByteArray>()
        val rb = buffer(onFrame = { frames += it })
        val payload = byteArrayOf(9, 8, 7, 6)
        val framed = HDLC.frame(payload)
        rb.feed(framed.copyOfRange(0, 3))
        assertTrue(frames.isEmpty())
        rb.feed(framed.copyOfRange(3, framed.size))
        assertEquals(1, frames.size)
        assertArrayEquals(payload, frames[0])
    }

    @Test
    fun `delivers two frames sharing a delimiter`() {
        val frames = mutableListOf<ByteArray>()
        val rb = buffer(onFrame = { frames += it })
        val a = byteArrayOf(1, 1, 1)
        val b = byteArrayOf(2, 2, 2)
        rb.feed(HDLC.frame(a))
        rb.feed(HDLC.frame(b))
        assertEquals(2, frames.size)
        assertArrayEquals(a, frames[0])
        assertArrayEquals(b, frames[1])
    }

    @Test
    fun `a too-short frame goes to onInvalid`() {
        var invalidLen = -1
        val frames = mutableListOf<ByteArray>()
        val rb = buffer(minFrameLen = 3, onFrame = { frames += it }, onInvalid = { invalidLen = it })
        rb.feed(HDLC.frame(byteArrayOf(1, 2)))
        assertTrue(frames.isEmpty())
        assertEquals(2, invalidLen)
    }

    @Test
    fun `a too-long frame goes to onInvalid`() {
        var invalidLen = -1
        val frames = mutableListOf<ByteArray>()
        val rb = buffer(maxFrameLen = 4, onFrame = { frames += it }, onInvalid = { invalidLen = it })
        rb.feed(HDLC.frame(byteArrayOf(1, 2, 3, 4, 5)))
        assertTrue(frames.isEmpty())
        assertEquals(5, invalidLen)
    }

    @Test
    fun `an unterminated run is bounded at twice the MTU`() {
        val frames = mutableListOf<ByteArray>()
        val rb = buffer(mtu = 8, onFrame = { frames += it })
        rb.feed(byteArrayOf(HDLC.FLAG))
        rb.feed(ByteArray(100) { 0x41 }) // 100 non-flag bytes >> 2*8
        assertEquals(0, rb.length(), "buffer must reset once an unterminated run exceeds 2*MTU")
        assertTrue(frames.isEmpty())
    }

    @Test
    fun `a stream with no flag is dropped`() {
        val rb = buffer(mtu = 8)
        rb.feed(ByteArray(50) { 0x42 })
        assertEquals(0, rb.length())
    }
}
