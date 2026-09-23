package network.reticulum.link

import network.reticulum.common.DestinationDirection
import network.reticulum.common.DestinationType
import network.reticulum.common.PacketType
import network.reticulum.common.RnsConstants
import network.reticulum.crypto.defaultCryptoProvider
import network.reticulum.destination.Destination
import network.reticulum.identity.Identity
import network.reticulum.packet.Packet
import network.reticulum.transport.Transport
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

/**
 * A LINKREQUEST whose signalling bytes carry an MTU of 0 must not leave link.mtu = 0,
 * which makes mdu (and Resource.sdu) negative and Resource.create throw into the
 * application. python normalises a falsy MTU to the default (Link.py:205:
 * `mtu_from_lr_packet(packet) or RNS.Reticulum.MTU`).
 */
class LinkRequestMtuTest {
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

    @Test
    fun `zero signalled MTU falls back to the default MTU`() {
        val receiverDestination = Destination.create(
            identity = Identity.create(),
            direction = DestinationDirection.IN,
            type = DestinationType.SINGLE,
            appName = "linkmtu",
            aspects = arrayOf("test"),
        )
        Transport.registerDestination(receiverDestination)

        val initX = crypto.generateX25519KeyPair()
        val initE = crypto.generateEd25519KeyPair()
        // Signalling bytes: mode AES256_CBC in the top three bits (0x20), MTU bits all zero.
        val signalling = byteArrayOf(
            (LinkConstants.MODE_AES256_CBC shl 5).toByte(),
            0x00,
            0x00,
        )
        val requestData = initX.publicKey + initE.publicKey + signalling
        val packet = Packet.createRaw(
            destinationHash = receiverDestination.hash,
            data = requestData,
            packetType = PacketType.LINKREQUEST,
            destinationType = DestinationType.SINGLE,
        )
        packet.pack()
        assertEquals(0, Link.mtuFromLrPacket(packet), "test precondition: the request signals an MTU of 0")

        val link = Link.validateRequest(receiverDestination, requestData, packet)
        assertNotNull(link, "a zero-MTU link request must still be accepted, as in python")
        link!!

        assertEquals(RnsConstants.MTU, link.mtu, "signalled MTU of 0 must normalise to the default MTU")
        assertEquals(LinkConstants.calculateMdu(RnsConstants.MTU), link.mdu)
        assertTrue(link.mdu > 0, "mdu must be positive so Resource.sdu cannot go negative")
    }
}
