package network.reticulum.link

import network.reticulum.common.DestinationDirection
import network.reticulum.common.DestinationType
import network.reticulum.crypto.defaultCryptoProvider
import network.reticulum.destination.Destination
import network.reticulum.identity.Identity
import network.reticulum.common.PacketType
import network.reticulum.packet.Packet
import network.reticulum.resource.Resource
import network.reticulum.resource.ResourceConstants
import network.reticulum.transport.Transport
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

/**
 * Link.teardown() must fail resources still in flight on the link immediately,
 * mirroring python link_closed() (Link.py:704-706), rather than leaving them to time
 * out on their own watchdog (RTT * PART_TIMEOUT_FACTOR * MAX_RETRIES).
 *
 * Builds a receiver-side link in-process via Link.validateRequest (which derives working
 * link crypto), registers an outgoing Resource on it, and asserts teardown() drives that
 * resource to FAILED synchronously.
 */
class LinkTeardownResourceTest {

    @BeforeEach
    fun setup() {
        try { Transport.stop() } catch (_: Exception) {}
        Transport.start(enableTransport = false)
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
            appName = "teardownres",
            aspects = arrayOf("test"),
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
        assertNotNull(link, "validateRequest should build a receiver-side link with derived crypto")
        return link!!
    }

    @Test
    fun `teardown fails an in-flight outgoing resource immediately`() {
        val link = makeReceiverLink()

        // advertise = false: prepare the outgoing resource without sending an advertisement
        // over the (routeless) test link (registration lives in doAdvertise, which we skip),
        // then register it explicitly so it is in the link's outgoing set — the state a
        // real in-flight transfer would be in. teardown() cancels registered resources
        // regardless of link status, and cancel()'s RESOURCE_ICL send is gated on ACTIVE
        // (never true here, since teardown sets the link CLOSED first).
        val resource = Resource.create(
            data = ByteArray(2048) { it.toByte() },
            link = link,
            advertise = false,
        )
        link.registerOutgoingResource(resource)
        assertNotEquals(
            ResourceConstants.FAILED,
            resource.status,
            "resource must not begin in a FAILED state",
        )

        link.teardown()

        assertEquals(
            ResourceConstants.FAILED,
            resource.status,
            "link teardown must fail the in-flight resource immediately, not leave it to its " +
                "own watchdog timeout",
        )
    }
}
