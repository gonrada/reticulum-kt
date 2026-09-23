package network.reticulum.transport

import network.reticulum.common.DestinationDirection
import network.reticulum.common.DestinationType
import network.reticulum.common.PacketType
import network.reticulum.common.toKey
import network.reticulum.crypto.defaultCryptoProvider
import network.reticulum.destination.Destination
import network.reticulum.identity.Identity
import network.reticulum.link.Link
import network.reticulum.link.LinkConstants
import network.reticulum.packet.Packet
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

/**
 * The path-table entry registerLinkPath creates for a link id is a short-lived,
 * in-memory routing hint. It must expire on the link establishment timeout (not
 * PATHFINDER_E, 7 days) and be dropped by deregisterLink. Python never puts link ids
 * in path_table, so an unauthenticated LINKREQUEST must not buy a week-long entry.
 */
class LinkPathLifetimeTest {

    private val ifaceHash = ByteArray(16) { 0x42 }

    @BeforeEach
    fun setup() {
        try { Transport.stop() } catch (_: Exception) {}
        Transport.start(Identity.create(), enableTransport = false)
    }

    @AfterEach
    fun cleanup() {
        try { Transport.stop() } catch (_: Exception) {}
    }

    private fun makeReceiverLink(): Link {
        val receiverDestination = Destination.create(
            identity = Identity.create(),
            direction = DestinationDirection.IN,
            type = DestinationType.SINGLE,
            appName = "secfix",
            aspects = arrayOf("linkpath", "lifetime"),
        )
        Transport.registerDestination(receiverDestination)

        val crypto = defaultCryptoProvider()
        val initX = crypto.generateX25519KeyPair()
        val initE = crypto.generateEd25519KeyPair()
        val requestData = initX.publicKey + initE.publicKey

        val packet = Packet.createRaw(
            destinationHash = receiverDestination.hash,
            data = requestData,
            packetType = PacketType.LINKREQUEST,
            destinationType = DestinationType.SINGLE,
        )
        packet.pack()
        packet.receivingInterfaceHash = ifaceHash

        val link = Link.validateRequest(receiverDestination, requestData, packet)
        assertNotNull(link, "validateRequest should build a receiver-side link")
        return link!!
    }

    @Test
    fun `link path entry expires on the establishment timeout, not PATHFINDER_E`() {
        val before = System.currentTimeMillis()
        val link = makeReceiverLink()

        val entry = Transport.pathTable[link.linkId.toKey()]
        assertNotNull(entry, "registerLinkPath must create the in-memory routing hint")
        // hops on a freshly built request packet is 0 -> maxOf(1, hops) = 1
        val window = LinkConstants.ESTABLISHMENT_TIMEOUT_PER_HOP * 1 + LinkConstants.KEEPALIVE
        val lifetime = entry!!.expires - before
        assertTrue(lifetime <= window + 5_000, "lifetime ${lifetime}ms must not exceed the establishment window ${window}ms")
        assertTrue(lifetime < TransportConstants.PATHFINDER_E / 1000, "lifetime must be nowhere near PATHFINDER_E")
        assertTrue(Transport.hasPath(link.linkId), "entry is usable while unexpired")
    }

    @Test
    fun `deregisterLink drops the link path entry`() {
        val link = makeReceiverLink()
        assertTrue(Transport.hasPath(link.linkId))

        Transport.deregisterLink(link)

        assertFalse(Transport.hasPath(link.linkId), "deregisterLink must remove the link path entry")
        assertFalse(Transport.pathTable.containsKey(link.linkId.toKey()))
    }
}
