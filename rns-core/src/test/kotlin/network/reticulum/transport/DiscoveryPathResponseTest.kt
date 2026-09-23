package network.reticulum.transport

import network.reticulum.common.DestinationDirection
import network.reticulum.common.DestinationType
import network.reticulum.common.HeaderType
import network.reticulum.common.InterfaceMode
import network.reticulum.common.PacketContext
import network.reticulum.common.RnsConstants
import network.reticulum.destination.Destination
import network.reticulum.identity.Identity
import network.reticulum.packet.Packet
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.security.SecureRandom

/**
 * python Transport.py:2431-2450: when an announce arrives for a destination that a
 * discovery path request is waiting on, the waiting entry is popped and the announce
 * is sent to every interface that asked, as a PATH_RESPONSE in HEADER_2 with this
 * node's identity as transport id. Without this the requester only got an answer if
 * the announce happened to be rebroadcast its way, which on a non-transport node it
 * never is.
 */
class DiscoveryPathResponseTest {

    private class RecordingInterface(override val name: String, fill: Int) : InterfaceRef {
        override val hash: ByteArray = ByteArray(RnsConstants.TRUNCATED_HASH_BYTES) { fill.toByte() }
        override val canSend = true
        override val canReceive = true
        override val online = true
        override val mode = InterfaceMode.FULL
        override val bitrate = 1_000_000
        override val hwMtu = 1064
        override var tunnelId: ByteArray? = null
        override var wantsTunnel = false
        val sent = java.util.concurrent.CopyOnWriteArrayList<ByteArray>()
        override fun send(data: ByteArray) { sent.add(data) }
    }

    private lateinit var requester: RecordingInterface
    private lateinit var source: RecordingInterface

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
        requester = RecordingInterface("requester-${System.nanoTime()}", 0xA1)
        source = RecordingInterface("source-${System.nanoTime()}", 0xB2)
        Transport.registerInterface(requester)
        Transport.registerInterface(source)
    }

    @AfterEach
    fun teardown() {
        try { Transport.deregisterInterface(requester) } catch (_: Exception) {}
        try { Transport.deregisterInterface(source) } catch (_: Exception) {}
        try { Transport.stop() } catch (_: Exception) {}
        Transport.pathTable.clear()
        tempDir.deleteRecursively()
    }

    private fun signedAnnounceRaw(identity: Identity, dest: Destination): ByteArray {
        val publicKey = identity.getPublicKey()
        val nameHash = dest.nameHash
        val randomHash = ByteArray(10).also { SecureRandom().nextBytes(it) }
        val appData = ByteArray(16) { 0x2A }
        val signedData = dest.hash + publicKey + nameHash + randomHash + appData
        val signature = identity.sign(signedData)
        val data = publicKey + nameHash + randomHash + signature + appData
        val flags = 0x01 // HEADER_1, BROADCAST, SINGLE, ANNOUNCE
        return byteArrayOf(flags.toByte(), 0x00) + dest.hash + byteArrayOf(0x00) + data
    }

    private fun foreignDestination(identity: Identity): Destination =
        Destination.create(
            identity = identity,
            direction = DestinationDirection.IN,
            type = DestinationType.SINGLE,
            appName = "discovery",
            aspects = arrayOf("response", "test"),
        ).also { Transport.deregisterDestination(it) }

    @Test
    fun `an announce answering a waiting discovery request is sent to the requesting interface as a path response`() {
        val identity = Identity.create()
        val dest = foreignDestination(identity)
        Transport.addDiscoveryPathRequestForTest(dest.hash, requester)
        assertTrue(Transport.hasPendingPathRequestForTest(dest.hash))

        Transport.inbound(signedAnnounceRaw(identity, dest), source)

        assertTrue(Transport.hasPath(dest.hash), "the announce must have been processed")
        assertFalse(Transport.hasPendingPathRequestForTest(dest.hash), "the waiting entry is popped")
        val answers = requester.sent.mapNotNull { Packet.unpack(it) }.filter { it.context == PacketContext.PATH_RESPONSE }
        assertEquals(1, answers.size, "exactly one path response on the requesting interface")
        val answer = answers.single()
        assertEquals(HeaderType.HEADER_2, answer.headerType)
        assertTrue(answer.transportId!!.contentEquals(Transport.identity!!.hash), "transport id is this node")
        assertTrue(answer.destinationHash.contentEquals(dest.hash))
        assertTrue(source.sent.none { Packet.unpack(it)?.context == PacketContext.PATH_RESPONSE }, "nothing back to the source")
    }

    @Test
    fun `an announce nobody is waiting on produces no path response`() {
        val identity = Identity.create()
        val dest = foreignDestination(identity)

        Transport.inbound(signedAnnounceRaw(identity, dest), source)

        assertTrue(Transport.hasPath(dest.hash))
        assertTrue(requester.sent.none { Packet.unpack(it)?.context == PacketContext.PATH_RESPONSE })
    }
}
