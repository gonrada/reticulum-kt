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
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

/**
 * python Resource.py:264-265 raises on metadata over METADATA_MAX_SIZE. Dropping it
 * silently sent a transfer whose receiver could not interpret the data; the sender must
 * hear about it instead.
 */
class ResourceMetadataLimitTest {
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
            appName = "metadata",
            aspects = arrayOf("limit"),
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
    fun `metadata that fits the first segment is accepted`() {
        // METADATA_MAX_SIZE (16 MiB) is the reference's hard cap, but any metadata block
        // at or above MAX_EFFICIENT_SIZE leaves the first segment no room and the
        // reference's negative first read raises (Resource.py:303); the port throws the
        // same way (ResourceSplitMetadataBudgetGuardTest). Half a megabyte fits.
        val resource = Resource.create(
            data = ByteArray(64) { 1 },
            link = makeLink(),
            metadata = ByteArray(512 * 1024) { 0x2A },
            advertise = false,
            autoCompress = false,
        )
        assertTrue(resource.hasMetadata)
    }

    @Test
    fun `metadata over the limit is refused, not dropped`() {
        assertThrows(IllegalArgumentException::class.java) {
            Resource.create(
                data = ByteArray(64) { 1 },
                link = makeLink(),
                metadata = ByteArray(ResourceConstants.METADATA_MAX_SIZE + 1) { 0x2A },
                advertise = false,
                autoCompress = false,
            )
        }
    }
}
