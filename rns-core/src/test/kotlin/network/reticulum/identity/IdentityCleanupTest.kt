package network.reticulum.identity

import network.reticulum.common.RnsConstants
import network.reticulum.transport.TransportConstants
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

/**
 * [Identity.cleanKnownDestinations]
 * bounds the in-memory identity caches by evicting stale, pathless entries, so a
 * flood of freshly-minted-identity announces can't grow memory without limit.
 * Mirrors the dominant rule of python Identity.clean_known_destinations.
 */
class IdentityCleanupTest {

    @BeforeEach fun clean() = Identity.clearKnownDestinations()
    @AfterEach fun tearDown() = Identity.clearKnownDestinations()

    private fun destHash(b: Int) = ByteArray(RnsConstants.TRUNCATED_HASH_BYTES) { b.toByte() }
    private fun pubKey(b: Int) = ByteArray(RnsConstants.FULL_KEY_SIZE) { b.toByte() }
    private val packetHash = ByteArray(RnsConstants.TRUNCATED_HASH_BYTES) { 9 }

    @Test
    fun `entries within the linger window are retained`() {
        val d = destHash(0x10)
        Identity.remember(packetHash, d, pubKey(1))
        // now only half a linger past the (just-set) timestamp -> not stale yet.
        val removed = Identity.cleanKnownDestinations(
            hasPath = { false },
            now = System.currentTimeMillis() + TransportConstants.UNUSED_DESTINATION_LINGER / 2,
        )
        assertEquals(0, removed)
        assertTrue(Identity.isKnown(d), "an entry within the linger window must be retained")
    }

    @Test
    fun `a stale pathless entry is evicted while a stale entry with a path is retained`() {
        val pathless = destHash(0x20)
        val withPath = destHash(0x30)
        Identity.remember(packetHash, pathless, pubKey(2))
        Identity.remember(packetHash, withPath, pubKey(3))

        // now well past the linger; only `withPath` has an active path.
        val removed = Identity.cleanKnownDestinations(
            hasPath = { it.contentEquals(withPath) },
            now = System.currentTimeMillis() + TransportConstants.UNUSED_DESTINATION_LINGER + 1_000,
        )

        assertEquals(1, removed, "exactly the stale, pathless entry must be evicted")
        assertFalse(Identity.isKnown(pathless), "stale pathless entry must be evicted")
        assertTrue(Identity.isKnown(withPath), "an entry with an active path must be retained")
        // The reverse identity-hash index is cleaned in tandem: the evicted
        // entry's identity is no longer recallable.
        assertFalse(
            Identity.isKnown(pathless),
            "evicted entry must not linger in the identity-hash index",
        )
    }
}
