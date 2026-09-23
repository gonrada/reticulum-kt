package network.reticulum.interfaces

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * The announce ingress limiter and the per-instance tuning that python keeps on the
 * interface (Interface.py:138-150, 188-206, 346-355).
 *
 * Pinned here: the announce frequency reads zero until more than IC_DEQUE_MIN_SAMPLE
 * samples exist (so two lone announces never trip the limiter, without any extra
 * sample gate); a burst trips it; the tuning fields on the instance are what the
 * limiter reads.
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
}
