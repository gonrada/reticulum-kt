package network.reticulum.link

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.msgpack.core.MessagePack

/**
 * Wire compatibility of link request data and response values with python's
 * `Link.request` / `Link.handle_request`, which msgpack arbitrary values. An LXMF
 * propagation node receives lists from python peers and answers with lists, bools
 * and ints, so both directions must survive as native msgpack types.
 */
class RequestWireTest {
    private fun unpack(bytes: ByteArray) = MessagePack.newDefaultUnpacker(bytes)

    @Test
    fun `a value nested beyond any stack decodes by span without recursion`() {
        // 200k nested single-element arrays: 0x91 ... then one nil. A tree decoder
        // recurses once per level and dies; the span decoder walks it in a loop.
        val depth = 200_000
        val encoded = ByteArray(depth + 1) { 0x91.toByte() }.also { it[depth] = 0xc0.toByte() }
        val decoded = RequestWire.valueToBytes(unpack(encoded), encoded)
        assertArrayEquals(encoded, decoded)
    }

    @Test
    fun `a list request value decodes to its msgpack encoding`() {
        // python: link.request("/offer", [b"\x01\x02", b"\x03\x04"])
        val packer = MessagePack.newDefaultBufferPacker()
        packer.packArrayHeader(2)
        packer.packBinaryHeader(2); packer.writePayload(byteArrayOf(1, 2))
        packer.packBinaryHeader(2); packer.writePayload(byteArrayOf(3, 4))
        val encoded = packer.toByteArray()

        val decoded = RequestWire.valueToBytes(unpack(encoded), encoded)

        assertArrayEquals(encoded, decoded, "an array value is handed to the handler as its msgpack bytes")
        val u = unpack(decoded!!)
        assertEquals(2, u.unpackArrayHeader())
        assertArrayEquals(byteArrayOf(1, 2), u.readPayload(u.unpackBinaryHeader()))
    }

    @Test
    fun `bin and nil values keep their previous meaning`() {
        val payload = byteArrayOf(9, 8, 7)
        val bin = MessagePack.newDefaultBufferPacker().apply {
            packBinaryHeader(payload.size); writePayload(payload)
        }.toByteArray()
        assertArrayEquals(payload, RequestWire.valueToBytes(unpack(bin), bin))

        val nil = MessagePack.newDefaultBufferPacker().apply { packNil() }.toByteArray()
        assertNull(RequestWire.valueToBytes(unpack(nil), nil))
    }

    @Test
    fun `a Value response goes on the wire as its msgpack type`() {
        val requestId = ByteArray(16) { it.toByte() }
        val packed = RequestWire.packResponse(requestId, listOf(byteArrayOf(1), 5, true, null))

        val u = unpack(packed)
        assertEquals(2, u.unpackArrayHeader())
        assertArrayEquals(requestId, u.readPayload(u.unpackBinaryHeader()))
        assertEquals(4, u.unpackArrayHeader(), "python receives a native list, not bytes")
        assertArrayEquals(byteArrayOf(1), u.readPayload(u.unpackBinaryHeader()))
        assertEquals(5, u.unpackInt())
        assertTrue(u.unpackBoolean())
        assertTrue(u.tryUnpackNil())
    }

    @Test
    fun `a Bytes response is still a bin`() {
        val requestId = ByteArray(16)
        val packed = RequestWire.packResponse(requestId, byteArrayOf(4, 5, 6))

        val u = unpack(packed)
        assertEquals(2, u.unpackArrayHeader())
        u.readPayload(u.unpackBinaryHeader())
        assertTrue(u.nextFormat.valueType == org.msgpack.value.ValueType.BINARY)
        assertArrayEquals(byteArrayOf(4, 5, 6), u.readPayload(u.unpackBinaryHeader()))
    }

    @Test
    fun `scalar responses round-trip through the bytes form`() {
        // python: return False / return 0xf3 — the requester sees the value's encoding
        val packedFalse = RequestWire.packResponse(ByteArray(16), false)
        val u = unpack(packedFalse)
        u.unpackArrayHeader(); u.readPayload(u.unpackBinaryHeader())
        val asBytes = RequestWire.valueToBytes(u, packedFalse)
        assertFalse(unpack(asBytes!!).unpackBoolean())
    }
}
