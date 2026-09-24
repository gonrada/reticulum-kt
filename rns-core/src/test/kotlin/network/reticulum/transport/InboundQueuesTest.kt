package network.reticulum.transport

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.util.concurrent.atomic.AtomicInteger

/**
 * The inbound queue is what RNS 1.5.2's asynchronous `Transport.inbound` rests on (python
 * Transport.py:46-93). Three properties carry the design, and each is pinned here on the
 * class alone, with no transport running:
 *
 *  - the drainer sees classes in index order, so data always beats announces beats path
 *    requests beats ingress-limited traffic, regardless of arrival order;
 *  - a full class drops the NEW item and never blocks, and the drop lands only on that
 *    class's counter — a flood of one kind cannot consume another kind's depth;
 *  - the TC_DATA high-water hook fires for data only, at the mark, under the lock.
 */
class InboundQueuesTest {
    private fun queues(vararg sizes: Int) = InboundQueues<String>(intArrayOf(*sizes))

    @Test
    fun `get returns the head of the lowest-index non-empty class first`() {
        val q = queues(8, 8, 8, 8)
        q.put(TransportConstants.TC_INGRESS_LIMITED, "il")
        q.put(TransportConstants.TC_PATH_REQUEST, "pr")
        q.put(TransportConstants.TC_ANNOUNCE, "an")
        q.put(TransportConstants.TC_DATA, "da")

        assertEquals("da", q.get(0), "TC_DATA must drain before anything else")
        assertEquals("an", q.get(0), "TC_ANNOUNCE must drain before path requests")
        assertEquals("pr", q.get(0), "TC_PATH_REQUEST must drain before ingress-limited traffic")
        assertEquals("il", q.get(0), "TC_INGRESS_LIMITED drains last")
        assertNull(q.get(0), "an empty queue set returns null on a zero timeout")
    }

    @Test
    fun `order within one class is FIFO`() {
        val q = queues(8, 8, 8, 8)
        q.put(TransportConstants.TC_DATA, "1")
        q.put(TransportConstants.TC_DATA, "2")
        q.put(TransportConstants.TC_DATA, "3")
        assertEquals(listOf("1", "2", "3"), listOf(q.get(0), q.get(0), q.get(0)))
    }

    @Test
    fun `a newly arrived data item still jumps ahead of queued announces`() {
        val q = queues(8, 8, 8, 8)
        q.put(TransportConstants.TC_ANNOUNCE, "an1")
        q.put(TransportConstants.TC_ANNOUNCE, "an2")
        assertEquals("an1", q.get(0))
        q.put(TransportConstants.TC_DATA, "da")
        assertEquals("da", q.get(0), "data arriving mid-drain must be served before the remaining announce")
        assertEquals("an2", q.get(0))
    }

    @Test
    fun `a full class drops the new item, counts it, and does not touch other classes`() {
        val q = queues(2, 8, 8, 8)
        assertTrue(q.put(TransportConstants.TC_DATA, "a"))
        assertTrue(q.put(TransportConstants.TC_DATA, "b"))
        assertFalse(q.put(TransportConstants.TC_DATA, "c"), "third put into a depth-2 class must be refused")
        assertEquals(1, q.droppedCount(TransportConstants.TC_DATA))
        assertEquals(0, q.droppedCount(TransportConstants.TC_ANNOUNCE))
        assertTrue(q.put(TransportConstants.TC_ANNOUNCE, "an"), "a full data class must not block announces")

        val snap = q.snapshot()
        assertEquals(3, snap.total)
        assertEquals(2, snap.heights[TransportConstants.TC_DATA])
        assertEquals(1, snap.heights[TransportConstants.TC_ANNOUNCE])
        assertEquals(1L, snap.dropped[TransportConstants.TC_DATA])

        // The two that were accepted are the two that come out; the dropped one is gone.
        assertEquals("a", q.get(0))
        assertEquals("b", q.get(0))
        assertEquals("an", q.get(0))
    }

    @Test
    fun `get waits up to the timeout and wakes on put`() {
        val q = queues(8, 8, 8, 8)
        val started = System.nanoTime()
        assertNull(q.get(50), "nothing queued: must return null after the timeout")
        assertTrue(System.nanoTime() - started >= 40_000_000L, "must actually have waited")

        val t = Thread {
            Thread.sleep(30)
            q.put(TransportConstants.TC_PATH_REQUEST, "late")
        }.apply { isDaemon = true; start() }
        assertEquals("late", q.get(2_000), "a put on another thread must wake a waiting get")
        t.join()
    }

    @Test
    fun `high-water hook fires for data at the mark and never for other classes`() {
        val fired = AtomicInteger(0)
        val q = InboundQueues<String>(intArrayOf(16, 16, 16, 16), highWaterMark = 3)
        q.onDataHighWater = { fired.incrementAndGet() }

        q.put(TransportConstants.TC_DATA, "1")
        q.put(TransportConstants.TC_DATA, "2")
        q.put(TransportConstants.TC_DATA, "3")
        assertEquals(0, fired.get(), "below the mark the hook stays quiet")
        q.put(TransportConstants.TC_DATA, "4") // depth 3 at put time == mark
        assertEquals(1, fired.get(), "a put that finds the data depth at the mark fires the hook")

        repeat(8) { q.put(TransportConstants.TC_ANNOUNCE, "an$it") }
        assertEquals(1, fired.get(), "announce depth never trips the DATA high-water hook")
    }

    @Test
    fun `default high-water mark is the reference arithmetic`() {
        // max(128, 90% of the data depth) — python Reticulum.py:738-739 via InboundQueues.__init__.
        assertEquals(128, queues(100, 8, 8, 8).highWaterMark)
        assertEquals(921, queues(1024, 8, 8, 8).highWaterMark)
    }

    @Test
    fun `clear discards contents but keeps the drop history`() {
        val q = queues(1, 8, 8, 8)
        q.put(TransportConstants.TC_DATA, "a")
        q.put(TransportConstants.TC_DATA, "b") // dropped
        q.clear()
        assertEquals(0, q.qsize())
        assertEquals(1, q.droppedCount(TransportConstants.TC_DATA))
    }
}
