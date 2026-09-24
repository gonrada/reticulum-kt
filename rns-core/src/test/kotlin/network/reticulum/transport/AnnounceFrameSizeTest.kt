package network.reticulum.transport

import network.reticulum.common.DestinationDirection
import network.reticulum.common.DestinationType
import network.reticulum.common.InterfaceMode
import network.reticulum.common.RnsConstants
import network.reticulum.destination.Destination
import network.reticulum.identity.Identity
import network.reticulum.packet.Packet
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.security.SecureRandom

/**
 * An ANNOUNCE whose frame exceeds Reticulum.MTU (500) is a protocol violation
 * dropped BEFORE signature validation (python Transport.py:1804). Interfaces with a
 * larger hwMtu (TCP, Local, Auto, Pipe) otherwise admit it.
 *
 * The announce is hand-built and correctly signed so the drop cannot be explained
 * by validateAnnounce rejecting it: a sub-MTU copy with the same layout MUST create
 * a path, the oversized one MUST NOT (and must not consume a hashlist slot).
 */
class AnnounceFrameSizeTest {

    private class WideInterface(override val name: String) : InterfaceRef {
        override val hash: ByteArray = ByteArray(RnsConstants.TRUNCATED_HASH_BYTES) { 0xA8.toByte() }
        override val canSend = true
        override val canReceive = true
        override val online = true
        override val mode = InterfaceMode.FULL
        override val bitrate = 1_000_000
        // Like TCP/Local/Auto: frames larger than RNS MTU pass the hwMtu gate in inbound().
        override val hwMtu = 1064
        override var tunnelId: ByteArray? = null
        override var wantsTunnel = false
        override fun send(data: ByteArray) = Unit
    }

    private lateinit var iface: WideInterface

    @BeforeEach
    fun setup() {
        try { Transport.stop() } catch (_: Exception) {}
        Transport.start(Identity.create(), enableTransport = false)
        iface = WideInterface("wide-${System.nanoTime()}")
        Transport.registerInterface(iface)
    }

    @AfterEach
    fun teardown() {
        try { Transport.deregisterInterface(iface) } catch (_: Exception) {}
        try { Transport.stop() } catch (_: Exception) {}
    }

    /** Build a correctly signed, ratchetless HEADER_1 announce for [dest] carrying [appData]. */
    private fun signedAnnounceRaw(identity: Identity, dest: Destination, appData: ByteArray): ByteArray {
        val publicKey = identity.getPublicKey()
        val nameHash = dest.nameHash
        val randomHash = ByteArray(10).also { SecureRandom().nextBytes(it) }
        // python Identity.py:545 — signature covers dest_hash‖pub‖name_hash‖random_hash‖app_data
        val signedData = dest.hash + publicKey + nameHash + randomHash + appData
        val signature = identity.sign(signedData)
        val data = publicKey + nameHash + randomHash + signature + appData

        val flags = 0x01 // HEADER_1, ctx flag unset, BROADCAST, SINGLE, ANNOUNCE
        return byteArrayOf(flags.toByte(), 0x00) + dest.hash + byteArrayOf(0x00) + data
    }

    // Destination.create registers with Transport, which would make the announce one for a
    // *local* destination (no path is added for those, as in Transport.py:2176). Deregister so
    // the announce is treated as a remote peer's, which is what the test models.
    private fun foreignDestination(identity: Identity): Destination =
        Destination.create(
            identity = identity,
            direction = DestinationDirection.IN,
            type = DestinationType.SINGLE,
            appName = "secfix",
            aspects = arrayOf("announce", "size"),
        ).also { Transport.deregisterDestination(it) }

    @Test
    fun `sub-MTU signed announce creates a path (control)`() {
        val identity = Identity.create()
        val dest = foreignDestination(identity)
        val raw = signedAnnounceRaw(identity, dest, ByteArray(64) { 0x5A })
        assertTrue(raw.size <= RnsConstants.MTU, "control announce must fit the MTU (${raw.size})")

        Transport.inbound(raw, iface)
        Transport.awaitInboundIdle()

        assertTrue(Transport.hasPath(dest.hash), "a valid sub-MTU announce must create a path")
    }

    @Test
    fun `announce frame larger than MTU is dropped before validation`() {
        val identity = Identity.create()
        val dest = foreignDestination(identity)
        val raw = signedAnnounceRaw(identity, dest, ByteArray(400) { 0x5A })
        assertTrue(raw.size > RnsConstants.MTU, "test announce must exceed the MTU (${raw.size})")
        assertTrue(raw.size <= iface.hwMtu, "test announce must still pass the interface hwMtu gate")
        val packet = Packet.unpack(raw)
        assertNotNull(packet, "oversized announce must still parse (the drop is a Transport policy)")

        Transport.inbound(raw, iface)
        Transport.awaitInboundIdle()

        assertFalse(Transport.hasPath(dest.hash), "oversized announce must not create a path")
        assertFalse(
            Transport.packetHashlistContainsForTest(packet!!.packetHash),
            "oversized announce must be dropped before it consumes a hashlist slot",
        )
    }
}
