package network.reticulum.link

import network.reticulum.common.DestinationDirection
import network.reticulum.common.DestinationType
import network.reticulum.common.PacketType
import network.reticulum.crypto.defaultCryptoProvider
import network.reticulum.destination.Destination
import network.reticulum.identity.Identity
import network.reticulum.packet.Packet
import network.reticulum.transport.Transport
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.security.SecureRandom

/**
 * Link.validate() must return the Ed25519 verification result. A version that computed
 * the verification and then returned true regardless let any 64 bytes pass as a link
 * delivery proof, so a third party could mark packets DELIVERED (Link.py validate()
 * raises on a bad signature and returns False). Builds a receiver-side link whose peer
 * signing key is one we hold, then checks that a genuine signature validates and forged /
 * wrong-message / wrong-length signatures do not.
 */
class LinkProofValidationTest {
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
    fun `link validate rejects a forged proof signature and accepts a genuine one`() {
        val receiverDestination = Destination.create(
            identity = Identity.create(),
            direction = DestinationDirection.IN,
            type = DestinationType.SINGLE,
            appName = "proofval",
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
        assertNotNull(link, "validateRequest should build a receiver-side link holding the peer signing key")
        link!!

        val rng = SecureRandom()
        val message = ByteArray(32).also { rng.nextBytes(it) }
        val genuine = crypto.ed25519Sign(initE.privateKey, message)
        assertTrue(link.validate(genuine, message), "genuine peer signature must validate")

        val forged = ByteArray(64).also { rng.nextBytes(it) }
        assertFalse(link.validate(forged, message), "random bytes must not validate as a proof signature")
        assertFalse(link.validate(genuine, message + byteArrayOf(1)), "signature over a different message must not validate")
        assertFalse(link.validate(ByteArray(10), message), "wrong-length signature must not validate")
    }
}
