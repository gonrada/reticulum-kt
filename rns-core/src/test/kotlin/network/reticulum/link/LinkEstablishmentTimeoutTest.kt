package network.reticulum.link

import network.reticulum.common.DestinationDirection
import network.reticulum.common.DestinationType
import network.reticulum.common.InterfaceMode
import network.reticulum.common.PacketType
import network.reticulum.common.RnsConstants
import network.reticulum.crypto.defaultCryptoProvider
import network.reticulum.destination.Destination
import network.reticulum.identity.Identity
import network.reticulum.packet.Packet
import network.reticulum.transport.InterfaceRef
import network.reticulum.transport.Transport
import network.reticulum.transport.TransportConstants
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.security.SecureRandom

/**
 * python Link.py:293-294: the initiator's establishment timeout is
 * `first_hop_timeout(dest) + ESTABLISHMENT_TIMEOUT_PER_HOP * max(1, hops)`, about 12 s at
 * one hop. The responder's is `ESTABLISHMENT_TIMEOUT_PER_HOP * max(1, hops) + KEEPALIVE`
 * (Link.py:215), about 366 s. Using the responder's formula on both sides made a link
 * attempt on a dead path wait six minutes to fail. Conformance pins only the responder's
 * formula.
 */
class LinkEstablishmentTimeoutTest {
    private class StubInterface(override val name: String, fill: Int) : InterfaceRef {
        override val hash: ByteArray = ByteArray(RnsConstants.TRUNCATED_HASH_BYTES) { fill.toByte() }
        override val canSend = true
        override val canReceive = true
        override val online = true
        override val mode = InterfaceMode.FULL
        override val bitrate = 1_000_000
        override val hwMtu = 1064
        override var tunnelId: ByteArray? = null
        override var wantsTunnel = false
        override fun send(data: ByteArray) = Unit
    }

    private lateinit var iface: StubInterface

    private lateinit var tempDir: java.io.File

    @BeforeEach
    fun setup() {
        try { Transport.stop() } catch (_: Exception) {}
        // Announces injected here are written through to the path store at whatever
        // storage path the previous test left; keep them in a private directory.
        tempDir = java.nio.file.Files.createTempDirectory("rns-test").toFile()
        Transport.setStoragePath(tempDir.absolutePath)
        Transport.pathTable.clear()
        Transport.start(Identity.create(), enableTransport = false)
        iface = StubInterface("establish-${System.nanoTime()}", 0xD3)
        Transport.registerInterface(iface)
    }

    @AfterEach
    fun teardown() {
        try { Transport.deregisterInterface(iface) } catch (_: Exception) {}
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

    private fun remoteDestination(identity: Identity): Destination =
        Destination.create(
            identity = identity,
            direction = DestinationDirection.IN,
            type = DestinationType.SINGLE,
            appName = "establish",
            aspects = arrayOf("timeout"),
        ).also { Transport.deregisterDestination(it) }

    @Test
    fun `initiator waits first-hop timeout plus six seconds per hop`() {
        val remoteIdentity = Identity.create()
        val inDest = remoteDestination(remoteIdentity)
        Transport.inbound(signedAnnounceRaw(remoteIdentity, inDest), iface)
        Transport.awaitInboundIdle()
        assertEquals(1, Transport.hopsTo(inDest.hash), "precondition: a one-hop path")

        val outDest =
            Destination.create(
                identity = remoteIdentity,
                direction = DestinationDirection.OUT,
                type = DestinationType.SINGLE,
                appName = "establish",
                aspects = arrayOf("timeout"),
            )
        val link = Link.create(outDest)
        val expected = Transport.firstHopTimeout(inDest.hash) + LinkConstants.ESTABLISHMENT_TIMEOUT_PER_HOP
        assertEquals(expected, link.establishmentTimeout, "python Link.py:293-294")
        assertTrue(link.establishmentTimeout < 20_000, "about 12 s at one hop, not ${link.establishmentTimeout} ms")
        link.teardown()
    }

    @Test
    fun `an unknown path inherits PATHFINDER_M hops as python hops_to reports`() {
        val remoteIdentity = Identity.create()
        val outDest =
            Destination.create(
                identity = remoteIdentity,
                direction = DestinationDirection.OUT,
                type = DestinationType.SINGLE,
                appName = "establish",
                aspects = arrayOf("nopath"),
            )
        val link = Link.create(outDest)
        val expected = Transport.firstHopTimeout(outDest.hash) + LinkConstants.ESTABLISHMENT_TIMEOUT_PER_HOP * TransportConstants.PATHFINDER_M
        assertEquals(expected, link.establishmentTimeout)
        link.teardown()
    }

    @Test
    fun `responder keeps six seconds per hop plus keepalive`() {
        val receiver =
            Destination.create(
                identity = Identity.create(),
                direction = DestinationDirection.IN,
                type = DestinationType.SINGLE,
                appName = "establish",
                aspects = arrayOf("responder"),
            )
        Transport.registerDestination(receiver)
        val crypto = defaultCryptoProvider()
        val requestData = crypto.generateX25519KeyPair().publicKey + crypto.generateEd25519KeyPair().publicKey
        val packet =
            Packet.createRaw(
                destinationHash = receiver.hash,
                data = requestData,
                packetType = PacketType.LINKREQUEST,
                destinationType = DestinationType.SINGLE,
            )
        packet.pack()
        val link = Link.validateRequest(receiver, requestData, packet)!!
        assertEquals(
            LinkConstants.ESTABLISHMENT_TIMEOUT_PER_HOP * maxOf(1, packet.hops) + LinkConstants.KEEPALIVE,
            link.establishmentTimeout,
            "python Link.py:215",
        )
        link.teardown()
    }
}
