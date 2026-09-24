package network.reticulum.resource

import network.reticulum.common.DestinationDirection
import network.reticulum.common.DestinationType
import network.reticulum.common.PacketType
import network.reticulum.crypto.defaultCryptoProvider
import network.reticulum.destination.Destination
import network.reticulum.identity.Identity
import network.reticulum.link.Link
import network.reticulum.packet.Packet
import network.reticulum.transport.Transport
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

/**
 * Sender-side recovery:
 *  - the sender watchdog must re-advertise when no part requests arrive (a lost initial
 *    advertisement leaves the receiver unaware; only the sender can recover), mirroring Python's
 *    watchdog ADVERTISED branch (Resource.py:585-598).
 *  - a failed callback passed to Resource.create must be wired before advertise() starts
 *    the watchdog, closing the window where a watchdog timeout could fire against a null callback.
 *
 * Builds a link with real crypto via Link.validateRequest and suppresses the watchdog thread
 * (watchdogDisabledForTest) so the re-advertise path is driven deterministically.
 */
class ResourceSenderRecoveryTest {

    @BeforeEach
    fun setup() {
        try { Transport.stop() } catch (_: Exception) {}
        Transport.start(Identity.create(), enableTransport = false)
        Resource.watchdogDisabledForTest = true
    }

    @AfterEach
    fun cleanup() {
        Resource.watchdogDisabledForTest = false
        try { Transport.stop() } catch (_: Exception) {}
    }

    private fun makeLink(): Link {
        val receiverDestination = Destination.create(
            identity = Identity.create(),
            direction = DestinationDirection.IN,
            type = DestinationType.SINGLE,
            appName = "sendrecovery",
            aspects = arrayOf("test"),
        )
        Transport.registerDestination(receiverDestination)
        val crypto = defaultCryptoProvider()
        val requestData = crypto.generateX25519KeyPair().publicKey + crypto.generateEd25519KeyPair().publicKey
        val packet = Packet.createRaw(
            destinationHash = receiverDestination.hash,
            data = requestData,
            packetType = PacketType.LINKREQUEST,
            destinationType = DestinationType.SINGLE,
        )
        packet.pack()
        return Link.validateRequest(receiverDestination, requestData, packet)!!
    }

    @Test
    fun `sender re-advertises when no part requests arrive`() {
        val resource = Resource.create(
            data = ByteArray(64) { it.toByte() },
            link = makeLink(),
            advertise = true,
        )
        assertEquals(1, resource.advSendCountForTest(), "create should advertise once")

        // The watchdog's ADVERTISED branch re-sends the advertisement; drive it.
        resource.resendAdvertisementForTest()
        assertEquals(2, resource.advSendCountForTest(), "sender must re-advertise, not sit silent")
    }

    @Test
    fun `failed callback passed to create is wired before advertise`() {
        var failedFired = false
        val resource = Resource.create(
            data = ByteArray(64) { it.toByte() },
            link = makeLink(),
            advertise = false,
            failedCallback = { failedFired = true },
        )

        assertNotNull(
            resource.callbacks.failed,
            "failedCallback must be wired at create time, before the watchdog can fire",
        )
        resource.callbacks.failed?.invoke(resource)
        assertTrue(failedFired, "the wired callback must be the one passed to create")
    }
}
