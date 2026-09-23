package network.reticulum.resource

import network.reticulum.common.DestinationDirection
import network.reticulum.common.DestinationType
import network.reticulum.destination.Destination
import network.reticulum.identity.Identity
import network.reticulum.link.Link
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import java.util.concurrent.atomic.AtomicBoolean

/**
 * A split transfer whose next segment cannot be produced must FAIL, not be left
 * concluded. validateProof waits a bounded time for the segment and cancels on
 * failure; cancel() is a no-op once status >= COMPLETE, so publishing COMPLETE
 * before that wait left the transfer concluded on the link with neither the
 * completed nor the failed callback fired. The wait has to come first.
 *
 * The sender Resource is built through the private constructor and its private
 * fields set by reflection (the same seam ResourceAssemblyIntegrityFailureTest
 * uses); no input file is set, so the segment preparer has nothing to read from
 * and clears its flag at once.
 */
@DisplayName("Resource next-segment failure")
class ResourceNextSegmentFailureTest {

    private fun freshSingleLink(): Link {
        val dest = Destination.create(
            identity = Identity.create(),
            direction = DestinationDirection.OUT,
            type = DestinationType.SINGLE,
            appName = "nextsegment",
            aspects = arrayOf("failure")
        )
        return Link.create(dest)
    }

    /** Build a sender Resource via the private constructor (no live link). */
    private fun senderResource(link: Link): Resource {
        val ctor = Resource::class.java.getDeclaredConstructor(Link::class.java, Boolean::class.javaPrimitiveType)
        ctor.isAccessible = true
        return ctor.newInstance(link, true) as Resource
    }

    private fun <T> setField(target: Any, name: String, value: T) {
        val f = Resource::class.java.getDeclaredField(name)
        f.isAccessible = true
        f.set(target, value)
    }

    private fun statusOf(target: Any): Int {
        val f = Resource::class.java.getDeclaredField("status")
        f.isAccessible = true
        return f.getInt(target)
    }

    @Test
    @DisplayName("a split transfer whose next segment cannot be produced fails instead of concluding")
    fun `missing next segment fails the transfer`() {
        val res = senderResource(freshSingleLink())
        val hash = ByteArray(32) { 0x11 }
        val proof = ByteArray(32) { 0x22 }
        setField(res, "status", ResourceConstants.AWAITING_PROOF)
        setField(res, "hash", hash)
        setField(res, "expectedProof", proof)
        setField(res, "segmentIndex", 1)
        setField(res, "totalSegments", 2)
        setField(res, "split", true)
        // inputFile stays null: the segment preparer has no source to read from.

        val failed = AtomicBoolean(false)
        val completed = AtomicBoolean(false)
        res.callbacks.failed = { failed.set(true) }
        res.callbacks.completed = { completed.set(true) }

        assertFalse(res.validateProof(hash + proof), "a transfer that cannot continue must not report success")

        assertEquals(ResourceConstants.FAILED, statusOf(res), "the transfer must be FAILED, not left COMPLETE")
        assertTrue(failed.get(), "the failed callback must fire")
        assertFalse(completed.get(), "the completed callback must not fire")
    }
}
