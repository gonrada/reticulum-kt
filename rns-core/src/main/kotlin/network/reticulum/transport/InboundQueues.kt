package network.reticulum.transport

import java.util.ArrayDeque
import java.util.concurrent.TimeUnit
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/**
 * Priority-ordered inbound packet queues, one per traffic class (python Transport.py:46-93,
 * `InboundQueues`, RNS 1.5.2).
 *
 * RNS 1.5.2 made `Transport.inbound` asynchronous: the interface thread that read a frame
 * only classifies it and drops it into one of these queues, and a single drainer thread
 * pulls from them in priority order. Two things follow from the layout, and both are
 * deliberate on the reference's part:
 *
 *  - **Priority is by index.** `get` scans the queues in order and returns the head of the
 *    first non-empty one, so index 0 (TC_DATA) always wins over index 1 (TC_ANNOUNCE), which
 *    wins over TC_PATH_REQUEST, which wins over TC_INGRESS_LIMITED. Link traffic on a busy
 *    node is never starved by an announce storm; a burst of path requests from a peer under
 *    ingress limiting is served last. Within one class the order is FIFO.
 *
 *  - **Each class has its own depth.** A full queue drops the *new* item and counts it, and
 *    never blocks the producer. A flood of one class therefore fills only its own queue; the
 *    data plane keeps its 1024 slots no matter how many announces are arriving.
 *
 * The high-water hook is the reference's `BackboneInterface._throttle_immediate` seam: when a
 * TC_DATA put finds the queue at or above [highWaterMark] the hook fires (under the queue
 * lock, so keep it cheap). There is no backbone interface in this port yet, so it is a
 * no-op unless something installs one — but the seam is here so dataplane ingress control
 * can be wired without touching the queue.
 *
 * Single drainer is assumed: `put` uses `signal`, not `signalAll` (the reference notes the
 * same and flags it for a future multi-drainer change).
 */
class InboundQueues<T>(
    sizes: IntArray,
    highWaterMark: Int? = null,
) {
    /** A consistent-instant view of queue heights and drop counts. */
    data class Snapshot(val total: Int, val heights: IntArray, val dropped: LongArray)

    private val lock = ReentrantLock()
    private val notEmpty = lock.newCondition()
    private val queues = Array(sizes.size) { ArrayDeque<T>() }
    private val sizes = sizes.copyOf()
    private val dropped = LongArray(sizes.size)

    /**
     * TC_DATA depth at which [onDataHighWater] fires. The reference uses
     * `max(128, BackboneInterface.DP_IC_HIGH_WM)` where the backbone mark is 90% of the data
     * queue depth (Reticulum.py:738-739); the same arithmetic is applied here.
     */
    val highWaterMark: Int = highWaterMark ?: maxOf(128, (0.9 * sizes[TransportConstants.TC_DATA]).toInt())

    /** Invoked with the current TC_DATA depth when a put finds it at or above the high-water mark. */
    @Volatile var onDataHighWater: ((depth: Int) -> Unit)? = null

    val classCount: Int get() = queues.size

    /**
     * Enqueue [item] under [trafficClass]. Returns false — and counts a drop — when that
     * class's queue is full. Never blocks.
     */
    fun put(trafficClass: Int, item: T): Boolean = lock.withLock {
        val q = queues[trafficClass]
        val depth = q.size
        if (trafficClass == TransportConstants.TC_DATA && depth >= highWaterMark) {
            onDataHighWater?.invoke(depth)
        }
        if (depth >= sizes[trafficClass]) {
            dropped[trafficClass]++
            return false
        }
        q.addLast(item)
        notEmpty.signal()
        true
    }

    /**
     * Dequeue the highest-priority available item, waiting up to [timeoutMillis] for one to
     * arrive. Returns null on timeout. A negative timeout waits indefinitely.
     */
    fun get(timeoutMillis: Long): T? {
        val deadline = if (timeoutMillis < 0) Long.MAX_VALUE else System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMillis)
        lock.withLock {
            while (true) {
                for (q in queues) {
                    if (q.isNotEmpty()) return q.pollFirst()
                }
                val remaining = deadline - System.nanoTime()
                if (remaining <= 0) return null
                notEmpty.awaitNanos(remaining)
            }
        }
    }

    /** Approximate height of one class, or of all classes when [trafficClass] is null. Never blocks. */
    fun qsize(trafficClass: Int? = null): Int =
        if (trafficClass == null) queues.sumOf { it.size } else queues[trafficClass].size

    /** Drops so far for one class. Never blocks. */
    fun droppedCount(trafficClass: Int): Long = dropped[trafficClass]

    /** Heights and drop counts captured at one instant under the lock. */
    fun snapshot(): Snapshot = lock.withLock {
        val heights = IntArray(queues.size) { queues[it].size }
        Snapshot(heights.sum(), heights, dropped.copyOf())
    }

    /** Discard everything queued. Drop counters are kept — they describe history, not contents. */
    fun clear() = lock.withLock {
        queues.forEach { it.clear() }
    }
}
