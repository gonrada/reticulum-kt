package network.reticulum.packet

import network.reticulum.common.RnsConstants
import network.reticulum.transport.TransportConstants
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test

/**
 * Packet.unpack must reject a packet whose hop count has reached the ceiling, for
 * ALL packet types (python Packet.unpack raises on hops >= PATHFINDER_M,
 * Packet.py:248-249). Previously only announces were hop-guarded (in
 * processAnnounce).
 */
class PacketHopGuardTest {

    private fun baseRaw(): ByteArray {
        val dest = ByteArray(RnsConstants.TRUNCATED_HASH_BYTES) { 0x11 }
        return Packet.createRaw(destinationHash = dest, data = ByteArray(4) { 7 }).pack()
    }

    @Test
    fun `unpack accepts a packet below the hop ceiling`() {
        val raw = baseRaw() // hops = 0
        assertNotNull(Packet.unpack(raw), "a fresh packet must unpack")

        val atMax = baseRaw().also { it[1] = (TransportConstants.PATHFINDER_M - 1).toByte() }
        assertNotNull(Packet.unpack(atMax), "hops == PATHFINDER_M-1 must still unpack")
    }

    @Test
    fun `unpack rejects a packet at or past the hop ceiling`() {
        val atCeiling = baseRaw().also { it[1] = TransportConstants.PATHFINDER_M.toByte() }
        assertNull(Packet.unpack(atCeiling), "hops == PATHFINDER_M must be rejected")

        val over = baseRaw().also { it[1] = (TransportConstants.PATHFINDER_M + 5).toByte() }
        assertNull(Packet.unpack(over), "hops > PATHFINDER_M must be rejected")
    }
}
