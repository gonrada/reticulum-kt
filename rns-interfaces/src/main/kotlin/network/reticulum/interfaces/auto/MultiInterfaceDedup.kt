package network.reticulum.interfaces.auto

import network.reticulum.common.ByteArrayKey

/**
 * Multi-interface duplicate suppression for [AutoInterface].
 *
 * Mirrors Python's `AutoInterface.mif_deque` / `mif_deque_times`
 * (RNS/Interfaces/AutoInterface.py:136-137, 636-648): a FIFO of (hash, seenAt)
 * bounded at [maxLen] — `deque(maxlen=MULTI_IF_DEQUE_LEN)` — where a packet is a
 * duplicate iff an entry with its hash was recorded within [ttlMs]. A non-duplicate,
 * including a stale re-sighting past the TTL, is appended (evicting the oldest past
 * the cap), exactly as Python re-appends on `not deque_hit`.
 *
 * Replaces a set keyed on (hash, timestamp) that could never match — a fresh
 * timestamp made every insert unique, so nothing was ever detected as a duplicate —
 * and that swept every entry on each packet. The scan here is bounded at [maxLen]
 * entries, as in Python.
 */
internal class MultiInterfaceDedup(
    private val maxLen: Int = AutoInterfaceConstants.MULTI_IF_DEQUE_LEN,
    private val ttlMs: Long = AutoInterfaceConstants.MULTI_IF_DEQUE_TTL_MS,
) {
    private val deque = ArrayDeque<Pair<ByteArrayKey, Long>>(maxLen + 1)

    /**
     * True if [hash] was seen within the TTL (a duplicate to drop). Otherwise records
     * it as seen at [now] and returns false. [now] is injected so tests are deterministic.
     */
    @Synchronized
    fun isDuplicate(hash: ByteArrayKey, now: Long): Boolean {
        // Python: `data_hash in mif_deque` and some time entry for it still inside the TTL.
        for ((seenHash, seenAt) in deque) {
            if (seenHash == hash && now < seenAt + ttlMs) return true
        }
        // Not a live duplicate: append, FIFO-evicting past the cap (deque maxlen).
        deque.addLast(hash to now)
        if (deque.size > maxLen) deque.removeFirst()
        return false
    }

    /** Number of recorded entries (bounded by maxLen). */
    val size: Int
        @Synchronized get() = deque.size
}
