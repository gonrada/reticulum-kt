package network.reticulum.resource

import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.msgpack.core.MessagePack
import java.io.ByteArrayOutputStream

/**
 * Pins [ResourceAdvertisement.unpack]'s required-key validation, mirroring
 * python `ResourceAdvertisement.unpack` (Resource.py:1363-1373), which accesses
 * every field as `dictionary["t"]`, `dictionary["h"]`, ... and raises KeyError
 * on a missing key — caught by `Resource.accept` and treated as a dropped
 * advertisement. A previous build tolerated missing keys, returning a degenerate
 * adv with an empty hash that would start a (bogus) transfer.
 */
class ResourceAdvertisementUnpackTest {

    /** Pack a msgpack map for an advertisement, optionally omitting [omit] keys. */
    private fun packAdvMap(omit: Set<String> = emptySet(), t: Int = 100): ByteArray {
        val intFields = mapOf("t" to t, "d" to 90, "n" to 2, "f" to 0x01, "i" to 1, "l" to 1)
        val binFields = mapOf(
            "h" to ByteArray(32) { 1 },
            "r" to ByteArray(4) { 2 },
            "o" to ByteArray(32) { 3 },
            "m" to ByteArray(8) { 4 },
        )
        val keys = listOf("t", "d", "n", "h", "r", "o", "i", "l", "q", "f", "m").filter { it !in omit }

        val out = ByteArrayOutputStream()
        val packer = MessagePack.newDefaultPacker(out)
        packer.packMapHeader(keys.size)
        for (k in keys) {
            packer.packString(k)
            when {
                k == "q" -> packer.packNil()
                intFields.containsKey(k) -> packer.packInt(intFields.getValue(k))
                else -> {
                    val v = binFields.getValue(k)
                    packer.packBinaryHeader(v.size)
                    packer.writePayload(v)
                }
            }
        }
        packer.close()
        return out.toByteArray()
    }

    @Test
    fun `unpack accepts an advertisement with all required keys`() {
        val adv = ResourceAdvertisement.unpack(packAdvMap())
        assertNotNull(adv, "a complete advertisement map must unpack")
        // The required-key set is honoured: fields decoded as expected.
        assertNotNull(adv!!.hash)
        org.junit.jupiter.api.Assertions.assertEquals(32, adv.hash.size)
    }

    @Test
    fun `unpack rejects an advertisement missing the required hash key`() {
        // Mirrors the conformance missing_key injector (wire_tcp.py
        // cmd_wire_inject_malformed_resource_adv): a valid msgpack map missing
        // "h" must be dropped (unpack returns null), not silently accepted.
        val adv = ResourceAdvertisement.unpack(packAdvMap(omit = setOf("h")))
        assertNull(adv, "an advertisement missing the required 'h' key must be rejected")
    }

    @Test
    fun `unpack rejects an implausible transfer size (DoS guard)`() {
        // Python Resource.py:1363 raises ValueError on t > MAX_EFFICIENT_SIZE*3;
        // the port must drop it (return null) before Resource allocates
        // arrayOfNulls(ceil(t/sdu)). A size just over the cap is rejected...
        val tooBig = ResourceConstants.MAX_EFFICIENT_SIZE * 3 + 1
        assertNull(
            ResourceAdvertisement.unpack(packAdvMap(t = tooBig)),
            "a transfer size past MAX_EFFICIENT_SIZE*3 must be rejected",
        )
        // ...a negative size (msgpack-signed) is rejected...
        assertNull(
            ResourceAdvertisement.unpack(packAdvMap(t = -1)),
            "a negative transfer size must be rejected",
        )
        // ...and a size at the cap is still accepted.
        assertNotNull(
            ResourceAdvertisement.unpack(packAdvMap(t = ResourceConstants.MAX_EFFICIENT_SIZE * 3)),
            "a transfer size at the cap must still unpack",
        )
    }

    /**
     * Build an advertisement map whose [key] bin field DECLARES [declaredLen]
     * bytes but is followed by only [actualBody] bytes. msgpack-core's
     * readPayload(n) allocates `new byte[n]` before reading, so without a
     * bounds check a bin32 header claiming 2^31-1 bytes forces a ~2 GiB
     * allocation / OutOfMemoryError from a ~100-byte packet.
     */
    private fun packAdvWithOversizedBin(key: String, declaredLen: Int, actualBody: ByteArray): ByteArray {
        val intFields = mapOf("t" to 100, "d" to 90, "n" to 2, "f" to 0x01, "i" to 1, "l" to 1)
        val binFields = mapOf(
            "h" to ByteArray(32) { 1 },
            "r" to ByteArray(4) { 2 },
            "o" to ByteArray(32) { 3 },
            "m" to ByteArray(8) { 4 },
        )
        val keys = listOf("t", "d", "n", "h", "r", "o", "i", "l", "q", "f", "m")
        val out = ByteArrayOutputStream()
        val packer = MessagePack.newDefaultPacker(out)
        packer.packMapHeader(keys.size)
        for (k in keys) {
            packer.packString(k)
            when {
                k == key -> {
                    // Declare far more than follows; the body is short.
                    packer.packBinaryHeader(declaredLen)
                    packer.writePayload(actualBody)
                }
                k == "q" -> packer.packNil()
                intFields.containsKey(k) -> packer.packInt(intFields.getValue(k))
                else -> {
                    val v = binFields.getValue(k)
                    packer.packBinaryHeader(v.size)
                    packer.writePayload(v)
                }
            }
        }
        packer.close()
        return out.toByteArray()
    }

    @Test
    fun `unpack rejects a bin32 length the buffer cannot back without allocating`() {
        // Python's umsgpack does fp.read(n) and raises InsufficientDataException
        // without allocating; the port must return null the same way. If the
        // guard is missing this test does not fail cleanly - it tries to
        // allocate ~2 GiB - which is precisely the defect.
        for (key in listOf("h", "r", "o", "m", "q")) {
            val packet = packAdvWithOversizedBin(key, Int.MAX_VALUE, ByteArray(16))
            assertTrue(packet.size < 200, "test packet must be tiny, was ${packet.size}")
            assertNull(
                ResourceAdvertisement.unpack(packet),
                "a '$key' bin declaring 2^31-1 bytes in a ${packet.size}-byte buffer must be rejected",
            )
        }
        // A length that fits the buffer but is wrong for a fixed-size field is rejected too.
        assertNull(
            ResourceAdvertisement.unpack(packAdvWithOversizedBin("h", 16, ByteArray(16))),
            "a 16-byte resource hash must be rejected (h is a 32-byte full hash)",
        )
        assertNull(
            ResourceAdvertisement.unpack(packAdvWithOversizedBin("r", 8, ByteArray(8))),
            "an 8-byte random hash must be rejected (r is RANDOM_HASH_SIZE = 4)",
        )
    }

    @Test
    fun `unpack rejects undecodable msgpack`() {
        // 0xC1 is msgpack's reserved/never-used lead byte (the 'garbage' variant).
        val adv = ResourceAdvertisement.unpack(byteArrayOf(0xC1.toByte()) + ByteArray(8))
        assertNull(adv, "undecodable msgpack must be rejected")
    }
}
