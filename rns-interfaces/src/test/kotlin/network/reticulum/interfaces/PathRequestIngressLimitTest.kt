package network.reticulum.interfaces

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * The path-request ingress limiter (python `Interface.should_ingress_limit_pr`,
 * Interface.py:213-236, and `incoming_pr_frequency`, :366-374). It decides which inbound
 * queue a path request lands in — TC_INGRESS_LIMITED when active — and whether the node
 * will fan a recursive discovery out for it.
 *
 * Pinned here: the frequency reads zero until more than IC_DEQUE_MIN_SAMPLE samples exist;
 * a burst over the new-interface threshold trips the limiter; and it stays active for the
 * burst hold even once the rate has dropped, which is the property that stops it flapping.
 */
class PathRequestIngressLimitTest {
    private class TestIface : Interface("pr-ingress-test") {
        override fun start() {}
        override fun processOutgoing(data: ByteArray) {}
    }

    @Test
    fun `frequency is zero until more than the minimum sample count exists`() {
        val iface = TestIface()
        assertEquals(0.0, iface.incomingPrFrequency())
        iface.recordIncomingPathRequest()
        iface.recordIncomingPathRequest()
        assertEquals(0.0, iface.incomingPrFrequency(), "two samples is the minimum, and the minimum reads zero")
        assertFalse(iface.shouldIngressLimitPr(), "no burst can be declared on too few samples")
    }

    @Test
    fun `a burst of path requests trips the limiter and it holds`() {
        val iface = TestIface()
        // A fresh interface is under IC_NEW_TIME, so the threshold is IC_PR_BURST_FREQ_NEW (3/s).
        // Ten requests inside a few milliseconds is far over it.
        repeat(10) { iface.recordIncomingPathRequest() }
        assertTrue(iface.incomingPrFrequency() > Interface.IC_PR_BURST_FREQ_NEW)

        assertTrue(iface.shouldIngressLimitPr(), "the burst must activate path-request limiting")

        // Still active on every subsequent call inside the hold window, even though no new
        // request arrived: the hold is what makes the limiter settle instead of flap.
        repeat(5) { assertTrue(iface.shouldIngressLimitPr(), "must stay active through the burst hold") }
    }

    @Test
    fun `the announce limiter and the path-request limiter are independent`() {
        val iface = TestIface()
        repeat(10) { iface.recordIncomingPathRequest() }
        assertTrue(iface.shouldIngressLimitPr())
        assertFalse(iface.shouldIngressLimit(), "a path-request burst must not trip the announce limiter")
    }
}
