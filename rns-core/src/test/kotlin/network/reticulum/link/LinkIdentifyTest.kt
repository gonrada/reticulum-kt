package network.reticulum.link

import network.reticulum.common.DestinationDirection
import network.reticulum.common.DestinationType
import network.reticulum.common.PacketContext
import network.reticulum.common.PacketType
import network.reticulum.crypto.defaultCryptoProvider
import network.reticulum.destination.Destination
import network.reticulum.identity.Identity
import network.reticulum.packet.Packet
import network.reticulum.transport.Transport
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

/**
 * LINKIDENTIFY on a receiver link must
 * (a) tear the link down when the presented identity is blackholed and
 * (b) set the remote identity once only, so a later identify cannot swap the
 * identity behind ACL decisions (python Link.py:999-1006).
 *
 * Builds a receiver-side link in-process via Link.validateRequest, then feeds it
 * LINKIDENTIFY packets encrypted under the link key, exactly as an initiator's
 * identify() would produce them (Link.py:482-489).
 */
class LinkIdentifyTest {
    private val crypto = defaultCryptoProvider()

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
            appName = "linkidentify",
            aspects = arrayOf("test"),
        )
        Transport.registerDestination(receiverDestination)

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

    /** Build the LINKIDENTIFY packet identify() would send for [identity] over [link]. */
    private fun identifyPacket(link: Link, identity: Identity): Packet {
        val publicKey = identity.getPublicKey()
        val signature = identity.sign(link.linkId + publicKey)
        return Packet.createRaw(
            destinationHash = link.linkId,
            data = link.encrypt(publicKey + signature),
            packetType = PacketType.DATA,
            destinationType = DestinationType.LINK,
            context = PacketContext.LINKIDENTIFY,
        )
    }

    @Test
    fun `remote identity is set once and not replaced by a later identify`() {
        val link = makeReceiverLink()
        assertNull(link.getRemoteIdentity(), "fresh receiver link has no remote identity")

        val first = Identity.create()
        link.receive(identifyPacket(link, first))
        assertArrayEquals(first.hash, link.getRemoteIdentity()?.hash, "first valid identify sets the remote identity")

        val second = Identity.create()
        link.receive(identifyPacket(link, second))
        assertArrayEquals(
            first.hash,
            link.getRemoteIdentity()?.hash,
            "a second identify must not replace the remote identity (Link.py:1005 set-once)",
        )
        assertEquals(LinkConstants.HANDSHAKE, link.status, "a non-blackholed re-identify must not close the link")
    }

    @Test
    fun `identify from a blackholed identity tears the link down`() {
        val link = makeReceiverLink()
        val blackholed = Identity.create()
        Transport.blackholeIdentity(blackholed.hash)

        link.receive(identifyPacket(link, blackholed))

        assertEquals(LinkConstants.CLOSED, link.status, "blackholed identity must end the link (Link.py:1000-1002)")
        assertNull(link.getRemoteIdentity(), "blackholed identity must not be recorded as the remote identity")
    }
}
