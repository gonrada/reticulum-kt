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
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Timeout
import java.util.concurrent.TimeUnit
import kotlin.random.Random

/**
 * A sender-side Resource created from an in-memory payload larger than
 * MAX_EFFICIENT_SIZE must actually be segmented the way python does it from
 * its tempfile (Resource.py:275-322, 779-792): the first resource carries only
 * the first segment's range, and the next segment can be built from the
 * retained source. A previous build reported split/totalSegments > 1 while
 * packing the whole payload into one resource and had no segment source, so
 * validateProof spun forever on the Transport ingest thread waiting for a
 * segment that could never exist.
 *
 * Every test that touches the next-segment path carries a preemptive
 * @Timeout: the defect under test is a hang.
 */
class ResourceSegmentationTest {

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
            appName = "segmentation",
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

    private val maxEfficient = ResourceConstants.MAX_EFFICIENT_SIZE

    @Test
    fun `payload at or under MAX_EFFICIENT_SIZE is a single segment`() {
        val resource = Resource.create(
            data = Random(7).nextBytes(maxEfficient),
            link = makeLink(),
            advertise = false,
            autoCompress = false,
        )
        assertFalse(resource.split)
        assertEquals(1, resource.totalSegments)
        assertEquals(1, resource.segmentIndex)
        assertEquals(maxEfficient, resource.totalSize)
        assertEquals(maxEfficient, resource.uncompressedSize)
    }

    @Test
    @Timeout(value = 60, unit = TimeUnit.SECONDS, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)
    fun `1_5 MiB payload is split into two consistent segments and the next segment is buildable`() {
        val total = maxEfficient + maxEfficient / 2 // ~1.5 MiB
        val payload = Random(11).nextBytes(total)

        run {
            val first = Resource.create(
                data = payload,
                link = makeLink(),
                advertise = false,
                autoCompress = false,
            )

            // Python: total_segments = ((total_size-1)//MAX_EFFICIENT_SIZE)+1, split = True,
            // and only first_read_size = MAX_EFFICIENT_SIZE bytes go into segment 1.
            assertTrue(first.split, "a >MAX_EFFICIENT_SIZE payload must be split")
            assertEquals(2, first.totalSegments)
            assertEquals(1, first.segmentIndex)
            assertEquals(total, first.totalSize, "total_size spans the whole transfer")
            assertEquals(maxEfficient, first.uncompressedSize, "segment 1 carries only its own range")
            assertTrue(
                first.size < total,
                "segment 1 transfer size ${first.size} must not contain the whole ${total}-byte payload",
            )

            // The path validateProof takes: build (or wait, bounded, for) the next segment.
            val second = requireNotNull(first.awaitNextSegmentForTest()) {
                "the next segment must be buildable from the retained in-memory source"
            }
            assertTrue(second.split)
            assertEquals(2, second.segmentIndex)
            assertEquals(2, second.totalSegments)
            assertEquals(total, second.totalSize)
            assertEquals(total - maxEfficient, second.uncompressedSize, "segment 2 is the remainder")
            assertEquals(ResourceConstants.QUEUED, second.status)
            assertArrayEquals(first.originalHash, second.originalHash, "every segment advertises the first segment's hash as o")
            assertFalse(first.hash.contentEquals(second.hash), "segments have distinct hashes")

            // A second call returns the same, already-built segment instead of rebuilding.
            assertTrue(first.awaitNextSegmentForTest() === second)
        }
    }

    @Test
    @Timeout(value = 60, unit = TimeUnit.SECONDS, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)
    fun `metadata block counts against the first segment only`() {
        val metadata = ByteArray(100) { 0x2A }
        // Packed block = 3-byte prefix + msgpack bin8 header (2) + 100 = 105 bytes.
        val metadataBlock = 3 + 2 + metadata.size
        val dataLen = maxEfficient // + 105 bytes of metadata block pushes it over the limit
        val payload = Random(13).nextBytes(dataLen)

        run {
            val first = Resource.create(
                data = payload,
                link = makeLink(),
                metadata = metadata,
                advertise = false,
                autoCompress = false,
            )
            assertTrue(first.split)
            assertEquals(2, first.totalSegments)
            assertEquals(dataLen + metadataBlock, first.totalSize)
            // Python: first_read_size = MAX_EFFICIENT_SIZE - metadata_size, so segment 1's
            // uncompressed payload (metadata block + first range) is exactly MAX_EFFICIENT_SIZE.
            assertEquals(maxEfficient, first.uncompressedSize)

            val second = requireNotNull(first.awaitNextSegmentForTest())
            // Segment 2 carries the remaining metadataBlock bytes of data and no metadata block,
            // but keeps has_metadata set (sent_metadata_size > 0, Resource.py:270-271).
            assertEquals(metadataBlock, second.uncompressedSize)
            assertTrue(second.hasMetadata)
            assertEquals(first.totalSize, second.totalSize)
        }
    }
}
