package network.reticulum.interfaces

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * The announce ingress limiter, the path-request egress limiter and the per-instance
 * tuning that python keeps on the interface (Interface.py:138-150, 188-206, 240-248,
 * 320-329, 346-355, 380-389).
 *
 * Pinned here: the announce frequency reads zero until more than IC_DEQUE_MIN_SAMPLE
 * samples exist (so two lone announces never trip the limiter, without any extra
 * sample gate); a burst trips it; the tuning fields on the instance are what the
 * limiter reads; egress control is off unless enabled and then trips on a burst of
 * outgoing path requests; protocol violations are counted per interface.
 */
class IngressEgressControlTest {
    private class TestIface : Interface("ingress-egress-test") {
        override fun start() {}
        override fun processOutgoing(data: ByteArray) {}
    }

    @Test
    fun `two announces read zero frequency and do not trip the limiter`() {
        val iface = TestIface()
        iface.recordIncomingAnnounce()
        iface.recordIncomingAnnounce()
        assertEquals(0.0, iface.incomingAnnounceFrequency(), "IC_DEQUE_MIN_SAMPLE samples read zero")
        assertFalse(iface.shouldIngressLimit())
    }

    @Test
    fun `a burst of announces trips the limiter and it holds`() {
        val iface = TestIface()
        repeat(10) { iface.recordIncomingAnnounce() }
        assertTrue(iface.incomingAnnounceFrequency() > Interface.IC_BURST_FREQ_NEW)
        assertTrue(iface.shouldIngressLimit(), "a burst over the new-interface threshold must activate limiting")
        repeat(5) { assertTrue(iface.shouldIngressLimit(), "must stay active through the burst hold") }
    }

    @Test
    fun `the limiter reads the instance thresholds, not the class constants`() {
        val iface = TestIface()
        // Ten samples inside one tick read as thousands of hertz; a threshold above that
        // must keep the limiter off, which proves the instance field is the one consulted.
        iface.icBurstFreqNew = 1_000_000.0
        repeat(10) { iface.recordIncomingAnnounce() }
        assertFalse(iface.shouldIngressLimit(), "an instance threshold above the burst rate must not trip")
    }

    @Test
    fun `ingress control can be switched off per instance`() {
        val iface = TestIface()
        assertTrue(iface.ingressControlEnabled())
        iface.setIngressControl(false)
        assertFalse(iface.ingressControlEnabled())
        repeat(10) { iface.recordIncomingAnnounce() }
        assertFalse(iface.shouldIngressLimit(), "python ingress_control = no disables the limiter")
    }

    @Test
    fun `egress control is off by default`() {
        val iface = TestIface()
        repeat(10) { iface.recordOutgoingPathRequest() }
        assertTrue(iface.outgoingPrFrequency(preemptive = true) > Interface.EC_PR_FREQ)
        assertFalse(iface.shouldEgressLimitPr(), "python: egress_control defaults to False")
    }

    @Test
    fun `egress control trips on a burst of outgoing path requests once enabled`() {
        val iface = TestIface()
        iface.egressControl = true
        assertFalse(iface.shouldEgressLimitPr(), "no samples yet")
        iface.recordOutgoingPathRequest()
        assertFalse(iface.shouldEgressLimitPr(), "one sample is under EC_BURST_MIN_SAMPLES")
        repeat(9) { iface.recordOutgoingPathRequest() }
        assertTrue(iface.shouldEgressLimitPr(), "a burst past EC_PR_FREQ with enough samples must limit")
        iface.ecPrFreq = 1_000_000.0
        assertFalse(iface.shouldEgressLimitPr(), "the instance threshold is the one consulted")
    }

    @Test
    fun `protocol violations are counted on the interface`() {
        val iface = TestIface()
        assertEquals(0L, iface.protocolViolationCount.get())
        iface.protocolViolation("first")
        iface.protocolViolation("second")
        assertEquals(2L, iface.protocolViolationCount.get())
        val adapter = InterfaceAdapter.getOrCreate(iface)
        assertEquals(2L, adapter.protocolViolations)
        adapter.protocolViolation("third")
        assertEquals(3L, iface.protocolViolationCount.get())
    }
}
