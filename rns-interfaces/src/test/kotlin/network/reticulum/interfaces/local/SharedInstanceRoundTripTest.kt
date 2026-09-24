package network.reticulum.interfaces.local

import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Timeout
import java.net.ServerSocket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

/**
 * Shared-instance client↔server round-trip over TCP loopback, proving the
 * built-in Local interfaces work end-to-end (not just that they compile). This is the
 * path an app wires by registering LocalClient/LocalServer factories when shareInstance
 * is set; here we drive the two interfaces directly.
 */
class SharedInstanceRoundTripTest {

    private var server: LocalServerInterface? = null
    private var client: LocalClientInterface? = null

    @AfterEach
    fun cleanup() {
        try { client?.detach() } catch (_: Exception) {}
        try { server?.detach() } catch (_: Exception) {}
    }

    @Test
    @Timeout(15, unit = TimeUnit.SECONDS)
    fun `a client packet reaches the shared-instance server`() {
        val port = ServerSocket(0).use { it.localPort }

        val received = CountDownLatch(1)
        val receivedData = AtomicReference<ByteArray>()

        val srv = LocalServerInterface(name = "SharedInstance", tcpPort = port)
        // The server forwards every spawned client's packets to its own hook.
        srv.onPacketReceived = { data, _ ->
            receivedData.set(data)
            received.countDown()
        }
        server = srv
        srv.start()

        val cli = LocalClientInterface(name = "SharedInstanceClient", tcpPort = port, tcpHost = "127.0.0.1")
        client = cli
        cli.start()

        // Wait for the client to connect to the server.
        val onlineDeadline = System.currentTimeMillis() + 8_000
        while (!cli.online.value && System.currentTimeMillis() < onlineDeadline) Thread.sleep(25)
        assertTrue(cli.online.value, "client should connect to the shared-instance server")

        // Send a packet client → server and confirm it arrives intact.
        val payload = "shared-instance round trip".toByteArray()
        cli.processOutgoing(payload)

        assertTrue(received.await(8, TimeUnit.SECONDS), "server should receive the client's packet")
        assertArrayEquals(payload, receivedData.get(), "server should receive the exact payload")
    }
}
