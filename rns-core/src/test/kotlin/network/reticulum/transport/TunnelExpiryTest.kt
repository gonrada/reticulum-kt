package network.reticulum.transport

import network.reticulum.common.InterfaceMode
import network.reticulum.common.RnsConstants
import network.reticulum.identity.Identity
import network.reticulum.link.LinkConstants
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

/**
 * python Transport.py:157-158, :1019-1027, :2821: a tunnel lives TUNNEL_TIMEOUT (8 h)
 * past its last activity, an entry whose expiry is more than two lifetimes out is
 * dropped as corrupt, and LINK_TIMEOUT is STALE_TIME * 1.25. The port used to set
 * tunnel expiry from the path table's week and LINK_TIMEOUT to a literal hour.
 */
class TunnelExpiryTest {
    private class StubInterface(override val name: String) : InterfaceRef {
        override val hash: ByteArray = ByteArray(RnsConstants.TRUNCATED_HASH_BYTES) { 0x7E }
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
        // Transport-enabled nodes persist their tables at stop; keep that out of the
        // shared default storage path other tests load from.
        tempDir = java.nio.file.Files.createTempDirectory("rns-test").toFile()
        Transport.setStoragePath(tempDir.absolutePath)
        Transport.pathTable.clear()
        Transport.start(Identity.create(), enableTransport = true)
        iface = StubInterface("tunnel-${System.nanoTime()}")
        Transport.registerInterface(iface)
    }

    @AfterEach
    fun teardown() {
        try { Transport.deregisterInterface(iface) } catch (_: Exception) {}
        try { Transport.stop() } catch (_: Exception) {}
        Transport.pathTable.clear()
        tempDir.deleteRecursively()
    }

    @Test
    fun `a new tunnel expires eight hours out`() {
        val tunnelId = ByteArray(32) { 0x51 }
        val before = System.currentTimeMillis()
        Transport.establishTunnelForTest(tunnelId, iface)
        val tunnel = Transport.tunnelInfosForTest().single { it.tunnelId.contentEquals(tunnelId) }
        val expected = before + TransportConstants.TUNNEL_TIMEOUT
        assertTrue(tunnel.expires in expected..(expected + 5_000), "expires ${tunnel.expires - before} ms out, want ${TransportConstants.TUNNEL_TIMEOUT}")
        assertEquals(8L * 60 * 60 * 1000, TransportConstants.TUNNEL_TIMEOUT)
    }

    @Test
    fun `a tunnel with an implausible expiry is dropped as corrupt`() {
        val tunnelId = ByteArray(32) { 0x52 }
        Transport.establishTunnelForTest(tunnelId, iface)
        val tunnel = Transport.tunnelInfosForTest().single { it.tunnelId.contentEquals(tunnelId) }
        tunnel.expires = System.currentTimeMillis() + 3 * TransportConstants.TUNNEL_TIMEOUT
        Transport.cleanExpiredTunnels()
        assertTrue(Transport.tunnelInfosForTest().none { it.tunnelId.contentEquals(tunnelId) }, "python Transport.py:1022-1024")
    }

    @Test
    fun `link table lifetime derives from the link stale time`() {
        assertEquals((LinkConstants.STALE_TIME * 1.25).toLong(), TransportConstants.LINK_TIMEOUT)
        assertEquals(900_000L, TransportConstants.LINK_TIMEOUT, "python: STALE_TIME 720 s * 1.25")
    }
}
