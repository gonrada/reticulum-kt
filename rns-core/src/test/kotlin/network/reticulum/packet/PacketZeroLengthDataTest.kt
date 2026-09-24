package network.reticulum.packet

import network.reticulum.common.RnsConstants
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test

/**
 * Packet.unpack must reject a frame with an empty data field
 * (python Packet.py:275 raises ValueError("Zero-length data field")).
 * A 19-byte HEADER_1 frame and a 35-byte HEADER_2 frame are header-only.
 */
class PacketZeroLengthDataTest {

    private fun header1(dataLen: Int): ByteArray {
        val flags = 0x00 // HEADER_1, SINGLE, DATA
        val raw = ByteArray(RnsConstants.HEADER_MIN_SIZE + dataLen)
        raw[0] = flags.toByte()
        raw[1] = 0 // hops
        for (i in 2 until 2 + RnsConstants.TRUNCATED_HASH_BYTES) raw[i] = 0x11
        raw[2 + RnsConstants.TRUNCATED_HASH_BYTES] = 0 // context
        for (i in RnsConstants.HEADER_MIN_SIZE until raw.size) raw[i] = 0x22
        return raw
    }

    private fun header2(dataLen: Int): ByteArray {
        val flags = 0x40 // HEADER_2, SINGLE, DATA
        val raw = ByteArray(RnsConstants.HEADER_MAX_SIZE + dataLen)
        raw[0] = flags.toByte()
        raw[1] = 0
        for (i in 2 until 2 + 2 * RnsConstants.TRUNCATED_HASH_BYTES) raw[i] = 0x11
        raw[2 + 2 * RnsConstants.TRUNCATED_HASH_BYTES] = 0
        for (i in RnsConstants.HEADER_MAX_SIZE until raw.size) raw[i] = 0x22
        return raw
    }

    @Test
    fun `19-byte HEADER_1 frame with no data does not unpack`() {
        assertNull(Packet.unpack(header1(0)), "header-only HEADER_1 frame must be rejected")
    }

    @Test
    fun `35-byte HEADER_2 frame with no data does not unpack`() {
        assertNull(Packet.unpack(header2(0)), "header-only HEADER_2 frame must be rejected")
    }

    @Test
    fun `one data byte is enough to unpack`() {
        val p1 = Packet.unpack(header1(1))
        assertNotNull(p1, "HEADER_1 with 1 data byte must unpack")
        assertNotNull(Packet.unpack(header2(1)), "HEADER_2 with 1 data byte must unpack")
    }
}
