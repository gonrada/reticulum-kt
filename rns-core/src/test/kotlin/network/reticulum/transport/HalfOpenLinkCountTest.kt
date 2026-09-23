package network.reticulum.transport

import network.reticulum.common.DestinationDirection
import network.reticulum.common.DestinationType
import network.reticulum.common.PacketType
import network.reticulum.crypto.defaultCryptoProvider
import network.reticulum.destination.Destination
import network.reticulum.identity.Identity
import network.reticulum.link.Link
import network.reticulum.link.LinkConstants
import network.reticulum.packet.Packet
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

/**
 * Transport.pendingLinkCount() — the half-open cap a receiver enforces against a
 * LINKREQUEST flood — must count receiver-side links. registerLink puts non-initiator
 * links straight into activeLinks (python parity), so a count of pendingLinks alone
 * never saw the links a LINKREQUEST flood creates.
 */
class HalfOpenLinkCountTest {

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
            aspects = arrayOf("halfopen", "count"),
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

        val link = Link.validateRequest(receiverDestination, requestData, packet)
        assertNotNull(link, "validateRequest should build a receiver-side link")
        return link!!
    }

    @Test
    fun `unproven receiver links are counted as half-open`() {
        val before = Transport.pendingLinkCount()

        val a = makeReceiverLink()
        val b = makeReceiverLink()
        assertNotEquals(LinkConstants.ACTIVE, a.status, "receiver link is not ACTIVE before the first inbound packet")
        assertNotEquals(LinkConstants.ACTIVE, b.status)

        assertEquals(before + 2, Transport.pendingLinkCount(), "two unproven receiver links must be counted")

        Transport.deregisterLink(a)
        assertEquals(before + 1, Transport.pendingLinkCount(), "a deregistered link leaves the count")
    }
}
