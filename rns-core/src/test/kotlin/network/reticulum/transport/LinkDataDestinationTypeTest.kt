package network.reticulum.transport

import network.reticulum.common.DestinationDirection
import network.reticulum.common.DestinationType
import network.reticulum.common.InterfaceMode
import network.reticulum.common.PacketType
import network.reticulum.common.RnsConstants
import network.reticulum.crypto.defaultCryptoProvider
import network.reticulum.destination.Destination
import network.reticulum.identity.Identity
import network.reticulum.link.Link
import network.reticulum.packet.Packet
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.util.concurrent.atomic.AtomicInteger

/**
 * A DATA packet whose destination hash is an active link id reaches
 * link.receive ONLY when its destination type is LINK (python Transport.py:2571).
 *
 * A captured link packet with the destination-type bits rewritten to PLAIN (hops 0)
 * passes packetFilter without a hashlist check, so without the gate it could be
 * replayed to the link without limit.
 */
class LinkDataDestinationTypeTest {

    private class QuietInterface(override val name: String) : InterfaceRef {
        override val hash: ByteArray = ByteArray(RnsConstants.TRUNCATED_HASH_BYTES) { 0xB1.toByte() }
        override val canSend = true
        override val canReceive = true
        override val online = true
        override val mode = InterfaceMode.FULL
        override val bitrate = 1_000_000
        override val hwMtu = RnsConstants.MTU
        override var tunnelId: ByteArray? = null
        override var wantsTunnel = false
        override fun send(data: ByteArray) = Unit
    }

    private lateinit var iface: QuietInterface

    @BeforeEach
    fun setup() {
        try { Transport.stop() } catch (_: Exception) {}
        Transport.start(Identity.create(), enableTransport = false)
        iface = QuietInterface("quiet-${System.nanoTime()}")
        Transport.registerInterface(iface)
    }

    @AfterEach
    fun cleanup() {
        try { Transport.deregisterInterface(iface) } catch (_: Exception) {}
        try { Transport.stop() } catch (_: Exception) {}
    }

    /** Receiver-side link attached to [iface], built the same way LinkTeardownResourceTest does. */
    private fun makeReceiverLink(): Link {
        val receiverDestination = Destination.create(
            identity = Identity.create(),
            direction = DestinationDirection.IN,
            type = DestinationType.SINGLE,
            appName = "secfix",
            aspects = arrayOf("linkdata", "type"),
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
        packet.receivingInterfaceHash = iface.hash

        val link = Link.validateRequest(receiverDestination, requestData, packet)
        assertNotNull(link, "validateRequest should build a receiver-side link")
        return link!!
    }

    private fun linkDataRaw(link: Link, type: DestinationType, fill: Byte): ByteArray =
        Packet.createRaw(
            destinationHash = link.linkId,
            data = ByteArray(48) { fill },
            packetType = PacketType.DATA,
            destinationType = type,
            createReceipt = false,
        ).pack()

    @Test
    fun `DATA flagged PLAIN for an active link id never reaches link receive`() {
        val link = makeReceiverLink()
        val delivered = AtomicInteger(0)
        link.inboundTapForTest = { delivered.incrementAndGet() }

        // Replay twice: PLAIN packets are never hashlist-deduplicated, so without the
        // destination-type gate both copies would be handed to the link.
        val plain = linkDataRaw(link, DestinationType.PLAIN, 0x11)
        Transport.inbound(plain, iface)
        Transport.inbound(plain, iface)
        Transport.awaitInboundIdle()
        assertEquals(0, delivered.get(), "PLAIN-flagged packet must not be delivered to the link")

        val group = linkDataRaw(link, DestinationType.GROUP, 0x22)
        Transport.inbound(group, iface)
        Transport.awaitInboundIdle()
        assertEquals(0, delivered.get(), "GROUP-flagged packet must not be delivered to the link")
    }

    @Test
    fun `DATA flagged LINK for an active link id does reach link receive (control)`() {
        val link = makeReceiverLink()
        val delivered = AtomicInteger(0)
        link.inboundTapForTest = { delivered.incrementAndGet() }

        Transport.inbound(linkDataRaw(link, DestinationType.LINK, 0x33), iface)
        Transport.awaitInboundIdle()
        assertEquals(1, delivered.get(), "LINK-typed packet on the attached interface must reach the link")
    }
}
