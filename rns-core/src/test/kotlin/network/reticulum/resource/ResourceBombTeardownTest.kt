package network.reticulum.resource

import network.reticulum.common.DestinationDirection
import network.reticulum.common.DestinationType
import network.reticulum.common.PacketType
import network.reticulum.crypto.defaultCryptoProvider
import network.reticulum.destination.Destination
import network.reticulum.identity.Identity
import network.reticulum.link.Link
import network.reticulum.link.LinkConstants
import network.reticulum.packet.Packet
import network.reticulum.transport.Transport
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import kotlin.random.Random

/**
 * A decompression-bomb verdict must end the link, not just the resource.
 * Python's `Resource.cancel` on a CORRUPT resource rejects the advertisement
 * (RESOURCE_RCL) and calls `link.teardown()` (Resource.py:1096-1099); the port's
 * cancel() is a no-op once status >= COMPLETE, so a peer could previously feed
 * an unbounded sequence of maximum-size inflations over one link. The hash-mismatch
 * CORRUPT path is unchanged: python does not tear down there (Resource.py:728).
 *
 * Sender and receiver are built on the same in-process link (its Token is
 * symmetric), the receiver is fed the sender's parts directly, and assemble()
 * is driven synchronously with the watchdog suppressed, the same shape as the
 * conformance bridge's corrupt-assembled injector.
 */
class ResourceBombTeardownTest {

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
            appName = "bombteardown",
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

    /** Sender + accepted receiver for [payload] on [link]; receiver holds every part. */
    private fun buildPair(link: Link, payload: ByteArray): Pair<Resource, Resource> {
        val sender = Resource.create(payload, link, advertise = false)
        val adv = requireNotNull(ResourceAdvertisement.unpack(ResourceAdvertisement.fromResource(sender).pack(0)))
        val receiver = requireNotNull(Resource.accept(adv, link)) { "Resource.accept must build a receiver" }
        assertEquals(sender.parts.size, receiver.parts.size)
        for (i in receiver.parts.indices) receiver.setPartForTest(i, sender.parts[i]!!)
        return sender to receiver
    }

    @Test
    fun `decompression bomb verdict rejects the resource and tears the link down`() {
        val link = makeLink()
        // Highly compressible payload: bz2 shrinks 50 KB of zeros to a few dozen bytes.
        val (sender, receiver) = buildPair(link, ByteArray(50_000))
        assertEquals(true, sender.compressed, "payload must have been sent compressed")

        // The listener lowers the per-resource bound below the true size, so the
        // bounded decompressor stops early and declares a bomb.
        receiver.setMaxDecompressedSizeForTest(1024)
        receiver.assembleForTest()

        assertEquals(ResourceConstants.CORRUPT, receiver.status, "bomb verdict must be CORRUPT")
        assertEquals(0, receiver.proveCallCountForTest(), "no proof on a CORRUPT verdict")
        assertEquals(LinkConstants.CLOSED, link.status, "the link must be torn down after a bomb (Resource.py:1099)")
    }

    @Test
    fun `hash mismatch CORRUPT verdict leaves the link up`() {
        val link = makeLink()
        val (sender, receiver) = buildPair(link, Random(5).nextBytes(20_000))

        // Corrupt one part in flight: the resource-level Token authentication fails
        // in assemble and the transfer is CORRUPT, but python does not tear the
        // link down on this path (Resource.py:715-728), and neither may the port.
        val j = receiver.parts.size / 2
        receiver.setPartForTest(j, Random(6).nextBytes(sender.parts[j]!!.size))
        receiver.assembleForTest()

        assertEquals(ResourceConstants.CORRUPT, receiver.status)
        assertNotEquals(LinkConstants.CLOSED, link.status, "a hash-mismatch CORRUPT must not tear the link down")
    }
}
