package network.reticulum.bench

import network.reticulum.common.DestinationDirection
import network.reticulum.common.DestinationType
import network.reticulum.common.InterfaceMode
import network.reticulum.common.RnsConstants
import network.reticulum.destination.Destination
import network.reticulum.identity.Identity
import network.reticulum.packet.Packet
import network.reticulum.transport.InterfaceRef
import network.reticulum.transport.Transport
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Test

/**
 * Tier-1.5 allocation profile driver. NOT a correctness test; self-skips unless run with
 * -Dbench.jfr=<path> (which also arms JFR allocation sampling on the test JVM via the root
 * Test task). Drives a long, tight loop of Transport.inbound(announce) — the ~50 KB/announce
 * hotspot from Step-0 — so JFR's allocation samples are dominated by that one path. Read the
 * result with `jfr view allocation-by-site` / `allocation-by-class`.
 */
class AnnounceAllocProfile {

    private class BenchIface(override val name: String) : InterfaceRef {
        override val hash = ByteArray(RnsConstants.TRUNCATED_HASH_BYTES) { 0xBB.toByte() }
        override val canSend = true
        override val canReceive = true
        override val online = true
        override val mode = InterfaceMode.FULL
        override val bitrate = 1_000_000
        override val hwMtu = RnsConstants.MTU
        override var tunnelId: ByteArray? = null
        override var wantsTunnel = false
        override fun send(data: ByteArray) = Unit
    }

    @Test
    fun profileAnnounceInbound() {
        assumeTrue(System.getProperty("bench.jfr") != null, "JFR alloc profile; run with -Dbench.jfr=<path>")

        try { Transport.stop() } catch (_: Exception) {}
        Transport.start(Identity.create(), enableTransport = false)
        val iface = BenchIface("jfr-${System.nanoTime()}")
        Transport.registerInterface(iface)
        try {
            val dest = Destination.create(
                identity = Identity.create(),
                direction = DestinationDirection.IN,
                type = DestinationType.SINGLE,
                appName = "jfrbench",
                aspects = arrayOf("x"),
            )
            Transport.registerDestination(dest)
            val announce = Packet.createAnnounce(dest)!!
            val raw = announce.raw ?: announce.pack()

            // Warm up (JIT), then a long measured loop for allocation sampling. Synchronous:
            // the profile is of the processing path, and a queued inbound() would only
            // sample the enqueue before the data queue overflowed.
            Transport.useInboundQueue = false
            repeat(10_000) { Transport.inbound(raw, iface) }
            repeat(300_000) { Transport.inbound(raw, iface) }
        } finally {
            Transport.useInboundQueue = true
            try { Transport.deregisterInterface(iface) } catch (_: Exception) {}
            try { Transport.stop() } catch (_: Exception) {}
        }
    }
}
