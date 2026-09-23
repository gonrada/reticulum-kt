package network.reticulum.transport

import network.reticulum.common.DestinationDirection
import network.reticulum.common.DestinationType
import network.reticulum.common.InterfaceMode
import network.reticulum.common.PacketType
import network.reticulum.common.RnsConstants
import network.reticulum.common.toKey
import network.reticulum.destination.Destination
import network.reticulum.identity.Identity
import network.reticulum.link.Link
import network.reticulum.link.LinkConstants
import network.reticulum.packet.Packet
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.security.SecureRandom

/**
 * python Transport.py:2060-2062: a relayed LINKREQUEST's link-table entry waits for its
 * proof `extra_link_proof_timeout(outbound interface) + 6 s * max(1, remaining hops)`,
 * where the extra term is one MTU at the outbound interface's bitrate. At 1200 bit/s
 * that is 3.3 s; the port used to omit it. The conformance case pins the same formula
 * at 10 Mbit/s, where the term is 0.4 ms and vanishes inside its half-second window.
 */
class LinkTableProofTimeoutTest {
    private class StubInterface(override val name: String, fill: Int, override val bitrate: Int) : InterfaceRef {
        override val hash: ByteArray = ByteArray(RnsConstants.TRUNCATED_HASH_BYTES) { fill.toByte() }
        override val canSend = true
        override val canReceive = true
        override val online = true
        override val mode = InterfaceMode.FULL
        override val hwMtu = 500
        override var tunnelId: ByteArray? = null
        override var wantsTunnel = false
        val sent = java.util.concurrent.CopyOnWriteArrayList<ByteArray>()
        override fun send(data: ByteArray) { sent.add(data) }
    }

    private lateinit var ingress: StubInterface
    private lateinit var slowEgress: StubInterface

    private lateinit var tempDir: java.io.File

    @BeforeEach
    fun setup() {
        try { Transport.stop() } catch (_: Exception) {}
        // Transport-enabled nodes persist their tables at stop; keep that out of the
        // shared default storage path other tests load from.
        tempDir = java.nio.file.Files.createTempDirectory("rns-test").toFile()
        Transport.setStoragePath(tempDir.absolutePath)
        Transport.pathTable.clear()
        Transport.start(Identity.create(), enableTransport = true)
        ingress = StubInterface("ingress-${System.nanoTime()}", 0xE1, bitrate = 1_000_000)
        slowEgress = StubInterface("egress-${System.nanoTime()}", 0xE2, bitrate = 1_200)
        Transport.registerInterface(ingress)
        Transport.registerInterface(slowEgress)
    }

    @AfterEach
    fun teardown() {
        try { Transport.deregisterInterface(ingress) } catch (_: Exception) {}
        try { Transport.deregisterInterface(slowEgress) } catch (_: Exception) {}
        try { Transport.stop() } catch (_: Exception) {}
        Transport.pathTable.clear()
        tempDir.deleteRecursively()
    }

    private fun signedAnnounceRaw(identity: Identity, dest: Destination): ByteArray {
        val publicKey = identity.getPublicKey()
        val randomHash = ByteArray(10).also { SecureRandom().nextBytes(it) }
        val appData = ByteArray(8) { 0x2A }
        val signedData = dest.hash + publicKey + dest.nameHash + randomHash + appData
        val signature = identity.sign(signedData)
        val data = publicKey + dest.nameHash + randomHash + signature + appData
        return byteArrayOf(0x01, 0x00) + dest.hash + byteArrayOf(0x00) + data
    }

    @Test
    fun `awaiting-proof timeout includes one MTU at the outbound bitrate`() {
        val remoteIdentity = Identity.create()
        val dest =
            Destination.create(
                identity = remoteIdentity,
                direction = DestinationDirection.IN,
                type = DestinationType.SINGLE,
                appName = "prooftimeout",
                aspects = arrayOf("relay"),
            ).also { Transport.deregisterDestination(it) }
        // The path to the destination is learned over the slow interface.
        Transport.inbound(signedAnnounceRaw(remoteIdentity, dest), slowEgress)
        assertEquals(1, Transport.hopsTo(dest.hash), "precondition: one-hop path via the slow interface")

        // A LINKREQUEST for it arrives on the fast interface, HEADER_2 and naming this
        // node as the next transport hop (python relays only packets addressed to it,
        // Transport.py:2000-2062), and is relayed onto the slow interface.
        val requestData = Link.buildInitiatorRequestDataForTest().requestData
        val lr =
            Packet.createRaw(
                destinationHash = dest.hash,
                data = requestData,
                packetType = PacketType.LINKREQUEST,
                destinationType = DestinationType.SINGLE,
                headerType = network.reticulum.common.HeaderType.HEADER_2,
                transportType = network.reticulum.common.TransportType.TRANSPORT,
                transportId = Transport.identity!!.hash,
            )
        val raw = lr.pack()
        val before = System.currentTimeMillis()
        Transport.inbound(raw, ingress)
        val after = System.currentTimeMillis()

        val linkId = Link.linkIdFromLrPacket(Packet.unpack(raw)!!)
        val entry = Transport.linkTable[linkId.toKey()]
        assertNotNull(entry, "the relayed LINKREQUEST must create a link-table entry")
        assertTrue(slowEgress.sent.isNotEmpty(), "the request must have been forwarded on the slow interface")

        val extra = Transport.extraLinkProofTimeout(slowEgress)
        assertEquals((RnsConstants.MTU * 8 * 1000L) / 1_200, extra, "one MTU at 1200 bit/s, in ms")
        val base = LinkConstants.ESTABLISHMENT_TIMEOUT_PER_HOP * maxOf(1, entry!!.remainingHops)
        assertTrue(
            entry.proofTimeout in (before + base + extra)..(after + base + extra),
            "proofTimeout ${entry.proofTimeout - before} ms out; want base $base + extra $extra",
        )
    }
}
