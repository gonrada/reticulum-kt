package network.reticulum.identity

import network.reticulum.common.ByteArrayKey
import network.reticulum.common.RnsConstants
import network.reticulum.common.toKey
import network.reticulum.storage.IdentityStore
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

/**
 * python's `_usedDestinationData` only touches memory (Identity.py:242-247); the marker
 * reaches disk with the next save. A write-through on every call cost a transport node
 * one database write per forwarded LRPROOF, so the marker is batched and flushed by the
 * known-destinations job.
 */
class IdentityUsedMarkerFlushTest {
    private class CountingStore : IdentityStore {
        val known = HashMap<ByteArrayKey, Identity.IdentityData>()
        var upserts = 0
        override fun upsertKnownDestination(destHash: ByteArray, data: Identity.IdentityData) {
            upserts++
            known[destHash.toKey()] = data
        }
        override fun getKnownDestination(destHash: ByteArray): Identity.IdentityData? = known[destHash.toKey()]
        override fun loadAllKnownDestinations(): Map<ByteArrayKey, Identity.IdentityData> = known
        override fun knownDestinationCount(): Int = known.size
        override fun removeKnownDestination(destHash: ByteArray) { known.remove(destHash.toKey()) }
        override fun upsertRatchet(destHash: ByteArray, ratchet: ByteArray, timestampMs: Long) {}
        override fun getRatchet(destHash: ByteArray): Pair<ByteArray, Long>? = null
        override fun removeExpiredRatchets(maxAgeMs: Long) {}
    }

    private val store = CountingStore()

    @BeforeEach
    fun setup() {
        Identity.clearKnownDestinations()
        Identity.identityStore = store
    }

    @AfterEach
    fun tearDown() {
        Identity.identityStore = null
        Identity.clearKnownDestinations()
    }

    @Test
    fun `marking a destination used does not write through, flushing does`() {
        val destHash = ByteArray(RnsConstants.TRUNCATED_HASH_BYTES) { 7 }
        Identity.remember(ByteArray(32) { 1 }, destHash, ByteArray(RnsConstants.FULL_KEY_SIZE) { 2 })
        val afterRemember = store.upserts

        repeat(50) { Identity.usedDestinationData(destHash) }
        assertEquals(afterRemember, store.upserts, "use markers must not write through per call")

        Identity.flushUsedMarkers()
        assertEquals(afterRemember + 1, store.upserts, "one flush writes the marked entry once")
        assertTrue(store.known[destHash.toKey()]!!.lastUsed > 0, "the flushed record carries the use timestamp")

        Identity.flushUsedMarkers()
        assertEquals(afterRemember + 1, store.upserts, "nothing dirty, nothing written")
    }
}
