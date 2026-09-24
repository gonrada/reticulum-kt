package network.reticulum.interfaces.util

import java.io.ByteArrayOutputStream
import java.util.concurrent.ConcurrentLinkedDeque
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/**
 * Coalescing transmit buffer — Kotlin port of Python RNS's `TransmitBuffer`
 * (RNS/Interfaces/util/TransmitBuffer.py). A single producer [append]s finalized
 * on-wire frames; a single consumer [drainTo]s them to a socket. Small frames are
 * coalesced up to [COALESCE_TARGET] to cut per-write overhead; frames at/above the
 * target get their own chunk. Optional per-append high-water-mark caps buffered bytes.
 *
 * Concurrency (mirrors the Python "almost lock-free" design under the JVM memory model):
 * - The chunk queue is a [ConcurrentLinkedDeque]; the producer only `addLast`, the single
 *   consumer only `peekFirst`/`pollFirst`.
 * - The producer's in-progress coalescing tail is guarded by [tailLock].
 * - Each counter has exactly one writer thread (producer or consumer) and is `@Volatile`
 *   for cross-thread visibility, so the read-only size accessors are consistent.
 *
 * Ported for the BackboneInterface (Backbone drives this into a NIO SocketChannel).
 */
class TransmitBuffer {

    companion object {
        const val COALESCE_TARGET = 65536
    }

    private class Chunk(val bytes: ByteArray, val frames: Int)

    private val tailLock = ReentrantLock()

    // Producer-owned coalescing tail (guarded by tailLock).
    private var cur: ByteArrayOutputStream? = null
    private var curFrames = 0

    // Consumer-owned.
    private var headOffset = 0

    // Shared, immutable chunks; producer appends right, consumer pops left.
    private val chunks = ConcurrentLinkedDeque<Chunk>()

    // Producer-written counters.
    @Volatile private var txTotal = 0L   // total bytes appended
    @Volatile private var txVisible = 0L // total bytes pushed to the chunk queue
    @Volatile private var txFrames = 0L  // total frames appended
    // Consumer-written counters.
    @Volatile private var txSent = 0L        // total bytes written to the socket
    @Volatile private var txFramesSent = 0L  // total frames fully sent

    /**
     * Queue a finalized, complete on-wire [frame]. Producer side only.
     * @param limit optional HWM: if set and buffering this frame would push the
     *   unsent byte count past it, the frame is rejected and false is returned.
     * @return true if queued, false if it would exceed [limit].
     */
    fun append(frame: ByteArray, limit: Int? = null): Boolean {
        tailLock.withLock {
            if (limit != null && (txTotal - txSent) + frame.size > limit) return false

            if (frame.size >= COALESCE_TARGET) {
                // Large frame: its own chunk.
                flushLocked()
                chunks.addLast(Chunk(frame, 1))
                txVisible += frame.size
                txTotal += frame.size
                txFrames += 1
            } else {
                val c = cur
                if (c != null && c.size() + frame.size > COALESCE_TARGET) flushLocked()
                val target = cur ?: ByteArrayOutputStream().also { cur = it; curFrames = 0 }
                target.write(frame)
                curFrames += 1
                txTotal += frame.size
                txFrames += 1
                // Queue idle: make the frame visible immediately so sparse traffic
                // does not incur coalescing latency.
                if (chunks.isEmpty()) flushLocked()
            }
        }
        return true
    }

    /** Make the producer-side coalescing tail visible to the consumer. */
    fun flush() {
        tailLock.withLock { flushLocked() }
    }

    // Must be called with tailLock held.
    private fun flushLocked() {
        val c = cur ?: return
        if (c.size() > 0) {
            chunks.addLast(Chunk(c.toByteArray(), curFrames))
            txVisible += c.size().toLong()
            cur = null
            curFrames = 0
        }
    }

    /**
     * Drain buffered bytes to [write], which sends `(bytes, offset, length)` and returns
     * the number of bytes actually written (0 = backpressure / would-block). Consumer side.
     * If the queue drains completely, the producer's coalescing tail is released under the
     * tail lock and drained in the same cycle.
     * @return total bytes written this call.
     */
    fun drainTo(write: (ByteArray, Int, Int) -> Int): Int {
        var total = 0
        var whole = true
        while (whole) {
            var chunk = chunks.peekFirst()
            if (chunk == null) {
                tailLock.withLock { flushLocked() }
                chunk = chunks.peekFirst() ?: break
            }
            val remaining = chunk.bytes.size - headOffset
            if (remaining <= 0) { popHead(); continue }
            val written = write(chunk.bytes, headOffset, remaining)
            if (written <= 0) break
            total += written
            headOffset += written
            txSent += written
            if (headOffset >= chunk.bytes.size) popHead() else whole = false
        }
        return total
    }

    private fun popHead() {
        val chunk = chunks.pollFirst() ?: return
        txFramesSent += chunk.frames
        headOffset = 0
    }

    /** Total bytes currently buffered (including the in-progress coalescing tail). */
    fun length(): Long = txTotal - txSent

    /** Bytes ready to send (visible to the consumer). */
    val sendable: Long get() = txVisible - txSent

    /** Complete frames currently buffered (including the coalescing tail). */
    val framesBuffered: Long get() = txFrames - txFramesSent

    /** Chunks currently visible to the consumer. */
    val chunksBuffered: Int get() = chunks.size
}
