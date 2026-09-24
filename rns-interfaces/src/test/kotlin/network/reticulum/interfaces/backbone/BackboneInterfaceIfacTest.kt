package network.reticulum.interfaces.backbone

import network.reticulum.interfaces.IfacUtils
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Timeout
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.TimeUnit

/**
 * IFAC on BackboneInterface and its spawned clients (python BackboneInterface.py:722-730:
 * every spawned interface inherits ifac_size/netname/netkey and derives the same ifac_key).
 */
class BackboneInterfaceIfacTest {

    private var backbone: BackboneInterface? = null
    private var client: Socket? = null

    @AfterEach
    fun cleanup() {
        try { client?.close() } catch (_: Exception) {}
        try { backbone?.detach() } catch (_: Exception) {}
    }

    private fun connectAndWaitForChild(bb: BackboneInterface): BackboneClientInterface {
        bb.start()
        val sock = Socket()
        sock.connect(InetSocketAddress("127.0.0.1", bb.boundPort), 3000)
        client = sock
        val deadline = System.currentTimeMillis() + 5000
        while (bb.spawnedInterfaces.isNullOrEmpty() && System.currentTimeMillis() < deadline) Thread.sleep(20)
        val spawned = bb.spawnedInterfaces?.firstOrNull()
        assertNotNull(spawned, "a client interface should be spawned on connect")
        return spawned as BackboneClientInterface
    }

    @Test
    @Timeout(15, unit = TimeUnit.SECONDS)
    fun `netname and netkey derive IFAC on the parent and every spawned client`() {
        val netname = "backbone-net"
        val netkey = "backbone-secret"
        val bb = BackboneInterface(
            name = "BB-IFAC", bindIp = "127.0.0.1", bindPort = 0,
            ifacNetname = netname, ifacNetkey = netkey,
        )
        backbone = bb

        val expected = IfacUtils.deriveIfacCredentials(netname, netkey)
        assertNotNull(expected)

        assertNotNull(bb.ifacKey, "parent must derive an IFAC key from netname/netkey")
        assertNotNull(bb.ifacIdentity, "parent must derive an IFAC identity")
        assertArrayEquals(expected!!.key, bb.ifacKey)
        assertEquals(16, bb.ifacSize)

        val child = connectAndWaitForChild(bb)
        assertEquals(netname, child.ifacNetname)
        assertEquals(netkey, child.ifacNetkey)
        assertNotNull(child.ifacKey, "spawned client must derive an IFAC key")
        assertNotNull(child.ifacIdentity, "spawned client must derive an IFAC identity")
        assertArrayEquals(bb.ifacKey, child.ifacKey)
        assertArrayEquals(expected.key, child.ifacKey)
        assertEquals(bb.ifacSize, child.ifacSize)
    }

    @Test
    @Timeout(15, unit = TimeUnit.SECONDS)
    fun `no netname or netkey means no IFAC on the parent or the spawned client`() {
        val bb = BackboneInterface(name = "BB-NOIFAC", bindIp = "127.0.0.1", bindPort = 0)
        backbone = bb

        assertNull(bb.ifacKey)
        assertNull(bb.ifacIdentity)
        assertEquals(0, bb.ifacSize)

        val child = connectAndWaitForChild(bb)
        assertNull(child.ifacNetname)
        assertNull(child.ifacNetkey)
        assertNull(child.ifacKey)
        assertNull(child.ifacIdentity)
        assertEquals(0, child.ifacSize)
    }
}
