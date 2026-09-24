package network.reticulum.transport

import network.reticulum.common.DestinationDirection
import network.reticulum.common.DestinationType
import network.reticulum.common.toKey
import network.reticulum.destination.Destination
import network.reticulum.identity.Identity
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

/**
 * Covers perf items 3 (O(1) destination index) and 4 (memoized ByteArrayKey.hashCode): the
 * hash->Destination index must stay equivalent to the old linear scan across register /
 * deregister / dedup / direction-filter, and ByteArrayKey must remain a correct, stable map key.
 */
class DestinationIndexTest {

    @BeforeEach
    fun setup() {
        try { Transport.stop() } catch (_: Exception) {}
        Transport.start(Identity.create(), enableTransport = false)
    }

    @AfterEach
    fun cleanup() {
        try { Transport.stop() } catch (_: Exception) {}
    }

    private fun inDest(app: String) = Destination.create(
        identity = Identity.create(),
        direction = DestinationDirection.IN,
        type = DestinationType.SINGLE,
        appName = app,
        aspects = arrayOf("test"),
    )

    @Test
    fun `register indexes the destination, deregister removes it`() {
        val dest = inDest("indexed")
        Transport.registerDestination(dest)
        assertSame(dest, Transport.findDestination(dest.hash), "registered dest must be found via the index")

        Transport.deregisterDestination(dest)
        assertNull(Transport.findDestination(dest.hash), "deregistered dest must no longer be found")
    }

    @Test
    fun `duplicate registration is idempotent`() {
        val dest = inDest("dup")
        Transport.registerDestination(dest)
        Transport.registerDestination(dest)
        assertEquals(1, Transport.getDestinations().count { it.hash.contentEquals(dest.hash) })
    }

    @Test
    fun `OUT destinations are not indexed`() {
        val out = Destination.create(
            identity = Identity.create(),
            direction = DestinationDirection.OUT,
            type = DestinationType.SINGLE,
            appName = "outbound",
            aspects = arrayOf("test"),
        )
        Transport.registerDestination(out)
        assertNull(Transport.findDestination(out.hash), "OUT destinations must not enter the local index")
    }

    @Test
    fun `ByteArrayKey is a stable, correct map key with memoized hashCode`() {
        val a = ByteArray(16) { it.toByte() }.toKey()
        val b = ByteArray(16) { it.toByte() }.toKey()

        assertEquals(a, b, "equal content must be equal keys")
        assertEquals(a.hashCode(), b.hashCode(), "equal keys must share a hashCode")
        assertEquals(a.hashCode(), a.hashCode(), "hashCode must be stable across calls")

        val map = HashMap<network.reticulum.common.ByteArrayKey, Int>()
        map[a] = 7
        assertEquals(7, map[b], "a distinct key with equal content must resolve the same entry")
    }
}
