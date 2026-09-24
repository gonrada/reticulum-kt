package network.reticulum.transport

import network.reticulum.common.DestinationDirection
import network.reticulum.common.DestinationType
import network.reticulum.common.InterfaceMode
import network.reticulum.common.RnsConstants
import network.reticulum.destination.Destination
import network.reticulum.identity.Identity
import network.reticulum.packet.Packet
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

/**
 * `Transport.inbound` is asynchronous as of RNS 1.5.2 (python Transport.py:1891-1911): the
 * caller's thread classifies and queues, a drainer thread processes. These tests pin the
 * contract a caller can rely on across that boundary:
 *
 *  - a queued packet's effect is visible after [Transport.awaitInboundIdle];
 *  - synchronous mode ([Transport.useInboundQueue] = false) keeps the old inline behaviour;
 *  - stop() discards the queue and start() rebuilds it, so a restart never inherits a
 *    previous session's backlog or in-flight count;
 *  - a held announce released with `ifacHandled` and TC_INGRESS_LIMITED is processed in full.
 */
class AsyncInboundTest {
    /** Minimal interface that can also be told to hold everything, and remembers what it held. */
    private class StubInterface(override val name: String) : InterfaceRef {
        override val hash: ByteArray = ByteArray(RnsConstants.TRUNCATED_HASH_BYTES) { 0xA5.toByte() }
        override val canSend = true
        override val canReceive = true
        override val online = true
        override val mode = InterfaceMode.FULL
        override val bitrate = 1_000_000
        override val hwMtu = 1064
        override var tunnelId: ByteArray? = null
        override var wantsTunnel = false
        override fun send(data: ByteArray) = Unit

        @Volatile var limiting = false
        val held = mutableListOf<ByteArray>()

        override fun shouldIngressLimit(): Boolean = limiting

        override fun holdAnnounce(
            destinationHash: ByteArray,
            raw: ByteArray,
            hops: Int,
            receivingInterface: InterfaceRef,
        ) {
            held.add(raw)
        }
    }

    private lateinit var iface: StubInterface

    @BeforeEach
    fun start() {
        try { Transport.stop() } catch (_: Exception) {}
        Transport.useInboundQueue = true
        Transport.start(Identity.create(), enableTransport = false)
        iface = StubInterface("async-${System.nanoTime()}")
        Transport.registerInterface(iface)
    }

    @AfterEach
    fun stop() {
        try { Transport.deregisterInterface(iface) } catch (_: Exception) {}
        try { Transport.stop() } catch (_: Exception) {}
        Transport.useInboundQueue = true
    }

    /** An announce for a destination this node does NOT own, so inbound treats it as foreign. */
    private fun foreignAnnounce(): Pair<Destination, ByteArray> {
        val dest =
            Destination.create(
                identity = Identity.create(),
                direction = DestinationDirection.IN,
                type = DestinationType.SINGLE,
                appName = "asyncinbound",
                aspects = arrayOf("x"),
            )
        Transport.deregisterDestination(dest)
        val announce = Packet.createAnnounce(dest)!!
        return dest to (announce.raw ?: announce.pack())
    }

    @Test
    fun `a queued announce is processed by the drainer and visible after awaitInboundIdle`() {
        val (dest, raw) = foreignAnnounce()

        Transport.inbound(raw, iface)
        assertTrue(Transport.awaitInboundIdle(5_000), "drainer must reach idle within the timeout")

        assertTrue(Transport.hasPath(dest.hash), "the announce must have been processed off the queue")
        val snap = Transport.inboundQueueSnapshot()
        assertNotNull(snap)
        assertEquals(0, snap!!.total, "nothing may remain queued once idle")
    }

    @Test
    fun `synchronous mode processes on the calling thread with nothing queued`() {
        Transport.useInboundQueue = false
        val (dest, raw) = foreignAnnounce()

        Transport.inbound(raw, iface)

        // No await: the path must be there the moment inbound() returns.
        assertTrue(Transport.hasPath(dest.hash), "synchronous inbound must have processed inline")
        assertEquals(0, Transport.inboundQueueSnapshot()!!.total)
        assertTrue(Transport.awaitInboundIdle(0), "synchronous mode never has anything in flight")
    }

    @Test
    fun `awaitInboundIdle returns true immediately when nothing was ever queued`() {
        assertTrue(Transport.awaitInboundIdle(0))
    }

    @Test
    fun `an unsolicited announce is held during preprocessing and never queued`() {
        iface.limiting = true
        val (dest, raw) = foreignAnnounce()

        Transport.inbound(raw, iface)

        // Holding happens on the caller's thread, before the queue: it is observable at once.
        assertEquals(1, iface.held.size, "the announce must have been handed to holdAnnounce")
        assertEquals(0, Transport.inboundQueueSnapshot()!!.total, "a held announce is not queued")
        assertTrue(Transport.awaitInboundIdle(1_000))
        assertFalse(Transport.hasPath(dest.hash), "a held announce must not have been processed")
    }

    @Test
    fun `a held announce released as ingress-limited with ifac handled is processed in full`() {
        iface.limiting = true
        val (dest, raw) = foreignAnnounce()
        Transport.inbound(raw, iface)
        assertEquals(1, iface.held.size)

        // The interface calms down and releases it exactly as Interface.processHeldAnnounces
        // does: the stored (already unmasked) frame, TC_INGRESS_LIMITED, ifacHandled = true.
        iface.limiting = false
        Transport.inbound(
            iface.held.single(),
            iface,
            tc = TransportConstants.TC_INGRESS_LIMITED,
            ifacHandled = true,
        )
        assertTrue(Transport.awaitInboundIdle(5_000))

        assertTrue(Transport.hasPath(dest.hash), "the released announce must be processed and the path learned")
    }

    @Test
    fun `stop discards the queue and start rebuilds it`() {
        val (dest, raw) = foreignAnnounce()
        Transport.inbound(raw, iface)
        assertTrue(Transport.awaitInboundIdle(5_000))
        assertTrue(Transport.hasPath(dest.hash))

        Transport.stop()
        assertTrue(Transport.awaitInboundIdle(0), "stop() must reset the in-flight count")

        Transport.start(Identity.create(), enableTransport = false)
        Transport.registerInterface(iface)
        val (dest2, raw2) = foreignAnnounce()
        Transport.inbound(raw2, iface)
        assertTrue(Transport.awaitInboundIdle(5_000), "a restarted transport must drain again")
        assertTrue(Transport.hasPath(dest2.hash), "the rebuilt queue must feed a live drainer")
    }
}
