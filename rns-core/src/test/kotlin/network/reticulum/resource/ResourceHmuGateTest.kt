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
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.msgpack.core.MessagePack
import java.io.ByteArrayOutputStream
import kotlin.random.Random

/**
 * RESOURCE_HMU handling must mirror python's guards —
 *  - an HMU is applied only while `waiting_for_hmu` (Resource.py:489-490);
 *  - an HMU carrying no hashes cancels the transfer (Resource.py:506-508);
 *  - a negative segment index is rejected (python would silently write at the
 *    list tail, Resource.py:503-504).
 * Previously every unsolicited HMU rewrote hashmap slots and reflected one
 * RESOURCE_REQ back to the sender.
 */
class ResourceHmuGateTest {

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
            appName = "hmugate",
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

    /** An accepted receiver for a small (single hashmap segment) transfer. */
    private fun makeReceiver(link: Link): Resource {
        val sender = Resource.create(Random(3).nextBytes(4_000), link, advertise = false)
        val adv = requireNotNull(ResourceAdvertisement.unpack(ResourceAdvertisement.fromResource(sender).pack(0)))
        return requireNotNull(Resource.accept(adv, link)) { "Resource.accept must build a receiver" }
    }

    /** Wire form of an HMU plaintext: resource_hash + msgpack([segment, hashmap]) (Resource.py:1069). */
    private fun hmuPlaintext(resourceHash: ByteArray, segment: Int, hashmap: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(resourceHash)
        val packer = MessagePack.newDefaultPacker(out)
        packer.packArrayHeader(2)
        packer.packInt(segment)
        packer.packBinaryHeader(hashmap.size)
        packer.writePayload(hashmap)
        packer.close()
        return out.toByteArray()
    }

    @Test
    fun `an unsolicited HMU is ignored`() {
        val receiver = makeReceiver(makeLink())
        // A 4 KB transfer fits one hashmap segment, so the receiver never asks for an HMU.
        assertFalse(receiver.waitingForHmuForTest(), "precondition: receiver is not waiting for an HMU")
        val before = receiver.hashmapEntriesForTest()
        val reqEmitsBefore = receiver.requestNextEmitCountForTest()

        receiver.handleHashmapUpdate(hmuPlaintext(receiver.hash, 0, ByteArray(4) { 0x55 }))

        assertEquals(0, receiver.hashmapUpdatesReceivedForTest(), "unsolicited HMU must not be counted as applied")
        assertEquals(before.size, receiver.hashmapEntriesForTest().size)
        for (i in before.indices) {
            assertEquals(before[i]?.toList(), receiver.hashmapEntriesForTest()[i]?.toList(), "hashmap slot $i must be untouched")
        }
        assertEquals(reqEmitsBefore, receiver.requestNextEmitCountForTest(), "no RESOURCE_REQ reflected for an unsolicited HMU")
        assertEquals(ResourceConstants.TRANSFERRING, receiver.status)
    }

    @Test
    fun `an HMU with no hashes cancels the transfer`() {
        val receiver = makeReceiver(makeLink())
        receiver.hashmapUpdateForTest(0, ByteArray(0))
        assertEquals(ResourceConstants.FAILED, receiver.status, "hashes < 1 must cancel (Resource.py:506-508)")
    }

    @Test
    fun `an HMU with a negative segment cancels the transfer`() {
        val receiver = makeReceiver(makeLink())
        receiver.hashmapUpdateForTest(-1, ByteArray(4) { 0x55 })
        assertEquals(ResourceConstants.FAILED, receiver.status, "a negative segment must be rejected")
    }
}
