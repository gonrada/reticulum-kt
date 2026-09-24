package network.reticulum.interfaces.auto

import network.reticulum.common.toKey
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Pins the multi-interface dedup to Python's mif_deque semantics
 * (RNS/Interfaces/AutoInterface.py:636-648): a packet is a duplicate iff its hash was
 * seen within the TTL; the history is FIFO-bounded at maxLen; a stale re-sighting is
 * re-recorded. The previous implementation never reported a duplicate at all.
 */
class MultiInterfaceDedupTest {
    private fun h(i: Int) = byteArrayOf(i.toByte(), (i shr 8).toByte(), 0x5A, 0x00).toKey()

    @Test
    fun `a packet seen again within the TTL is a duplicate`() {
        val d = MultiInterfaceDedup(maxLen = 48, ttlMs = 750)
        assertFalse(d.isDuplicate(h(1), now = 1_000))
        assertTrue(d.isDuplicate(h(1), now = 1_500)) // 500ms later, inside the 750ms TTL
    }

    @Test
    fun `a packet seen again after the TTL is not a duplicate and is re-recorded`() {
        val d = MultiInterfaceDedup(maxLen = 48, ttlMs = 750)
        assertFalse(d.isDuplicate(h(1), now = 1_000))
        assertFalse(d.isDuplicate(h(1), now = 1_800)) // 800ms later, past the TTL
        // Python re-appends on `not deque_hit`, so it is live again from the new sighting.
        assertTrue(d.isDuplicate(h(1), now = 2_000))
    }

    @Test
    fun `entries are FIFO-evicted past maxLen so an old hash stops being a duplicate`() {
        val d = MultiInterfaceDedup(maxLen = 3, ttlMs = 10_000)
        assertFalse(d.isDuplicate(h(1), now = 100))
        assertFalse(d.isDuplicate(h(2), now = 101))
        assertFalse(d.isDuplicate(h(3), now = 102))
        assertEquals(3, d.size)
        assertFalse(d.isDuplicate(h(4), now = 103)) // evicts h(1)
        assertEquals(3, d.size)
        // h(1) is inside the TTL by time but no longer in the bounded deque -> not a dup.
        assertFalse(d.isDuplicate(h(1), now = 104))
        // h(4) is still present and live.
        assertTrue(d.isDuplicate(h(4), now = 105))
    }

    @Test
    fun `distinct hashes are tracked independently`() {
        val d = MultiInterfaceDedup(maxLen = 48, ttlMs = 750)
        assertFalse(d.isDuplicate(h(10), now = 1_000))
        assertFalse(d.isDuplicate(h(11), now = 1_001))
        assertTrue(d.isDuplicate(h(10), now = 1_002))
        assertTrue(d.isDuplicate(h(11), now = 1_003))
    }
}
