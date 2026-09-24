package network.reticulum.interfaces.local

import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import network.reticulum.transport.Transport
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.file.Path
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/**
 * Tests for LocalInterface IPC communication.
 *
 * All TCP tests bind the server to an OS-assigned ephemeral port (tcpPort = 0) and read the
 * actual port back via [LocalServerInterface.boundPort] after start(), rather than hardcoding
 * ports — which eliminates the BindException class under parallel test runs, leaked sockets,
 * and collisions with a running node on the default range (issue #76).
 */
class LocalInterfaceTest {

    private var server: LocalServerInterface? = null
    private val clients = mutableListOf<LocalClientInterface>()

    @AfterEach
    fun tearDown() {
        // Clean up clients
        clients.forEach { it.detach() }
        clients.clear()

        // Clean up server
        server?.detach()
        server = null

        // Give sockets time to close
        Thread.sleep(100)
    }

    @Test
    fun `test server starts and accepts connections via TCP`() {
        // Create server on random port
        server = LocalServerInterface(name = "TestServer", tcpPort = 0)
        server!!.start()

        assertTrue(server!!.online.value)
        assertTrue(server!!.clientCount() == 0)
    }

    @Test
    fun `test client connects to server via TCP`() {
        // Start server on an OS-assigned port, then read it back for the client.
        server = LocalServerInterface(name = "TestServer", tcpPort = 0)
        server!!.start()
        val tcpPort = server!!.boundPort

        // Start client
        val client = LocalClientInterface(name = "TestClient", tcpPort = tcpPort)
        clients.add(client)
        client.start()

        // Give connection time to establish
        Thread.sleep(200)

        assertTrue(server!!.online.value)
        assertTrue(client.online.value)
        assertEquals(1, server!!.clientCount())
    }

    @Test
    fun `test packet transmission from client to server via TCP`() {
        // Data must be > HEADER_MIN_SIZE (19) bytes to pass HDLC deframer validation
        val testData = "Hello from client!!!!".toByteArray()
        val receivedLatch = CountDownLatch(1)
        var receivedData: ByteArray? = null

        // Start server
        server = LocalServerInterface(name = "TestServer", tcpPort = 0)
        server!!.onPacketReceived = { data, _ ->
            receivedData = data
            receivedLatch.countDown()
        }
        server!!.start()
        val tcpPort = server!!.boundPort

        // Start client
        val client = LocalClientInterface(name = "TestClient", tcpPort = tcpPort)
        clients.add(client)
        client.start()

        // Give connection time to establish
        Thread.sleep(200)

        // Send data from client
        client.processOutgoing(testData)

        // Wait for server to receive
        assertTrue(receivedLatch.await(2, TimeUnit.SECONDS))
        assertNotNull(receivedData)
        assertArrayEquals(testData, receivedData)
    }

    @Test
    fun `test packet transmission from server to client via TCP`() {
        // Data must be > HEADER_MIN_SIZE (19) bytes to pass HDLC deframer validation
        val testData = "Hello from server!!!!".toByteArray()
        val receivedLatch = CountDownLatch(1)
        var receivedData: ByteArray? = null

        // Start server
        server = LocalServerInterface(name = "TestServer", tcpPort = 0)
        server!!.start()
        val tcpPort = server!!.boundPort

        // Start client
        val client = LocalClientInterface(name = "TestClient", tcpPort = tcpPort)
        client.onPacketReceived = { data, _ ->
            receivedData = data
            receivedLatch.countDown()
        }
        clients.add(client)
        client.start()

        // Give connection time to establish
        Thread.sleep(200)

        // In production, Transport calls each spawned interface's processOutgoing() directly.
        // server.processOutgoing() is intentionally a no-op to prevent double-send.
        val spawnedClient = server!!.getClients().first()
        spawnedClient.processOutgoing(testData)

        // Wait for client to receive
        assertTrue(receivedLatch.await(2, TimeUnit.SECONDS))
        assertNotNull(receivedData)
        assertArrayEquals(testData, receivedData)
    }

    @Test
    fun `test broadcast to multiple clients via TCP`() {
        // Data must be > HEADER_MIN_SIZE (19) bytes to pass HDLC deframer validation
        val testData = "Broadcast message!!!!!".toByteArray()
        val numClients = 3
        val receivedLatch = CountDownLatch(numClients)
        val receivedDataList = mutableListOf<ByteArray>()

        // Start server
        server = LocalServerInterface(name = "TestServer", tcpPort = 0)
        server!!.start()
        val tcpPort = server!!.boundPort

        // Start multiple clients
        repeat(numClients) { i ->
            val client = LocalClientInterface(name = "TestClient$i", tcpPort = tcpPort)
            client.onPacketReceived = { data, _ ->
                synchronized(receivedDataList) {
                    receivedDataList.add(data)
                }
                receivedLatch.countDown()
            }
            clients.add(client)
            client.start()
            Thread.sleep(50) // Stagger connections
        }

        // Give connections time to establish
        Thread.sleep(200)

        assertEquals(numClients, server!!.clientCount())

        // In production, Transport calls each spawned interface's processOutgoing() directly.
        // Simulate that broadcast pattern here.
        for (spawnedClient in server!!.getClients()) {
            spawnedClient.processOutgoing(testData)
        }

        // Wait for all clients to receive
        assertTrue(receivedLatch.await(2, TimeUnit.SECONDS))
        assertEquals(numClients, receivedDataList.size)

        // Verify all received the same data
        receivedDataList.forEach { data ->
            assertArrayEquals(testData, data)
        }
    }

    @Test
    fun `test client disconnect via TCP`() {
        // Start server
        server = LocalServerInterface(name = "TestServer", tcpPort = 0)
        server!!.start()
        val tcpPort = server!!.boundPort

        // Start client
        val client = LocalClientInterface(name = "TestClient", tcpPort = tcpPort)
        clients.add(client)
        client.start()

        // Give connection time to establish
        Thread.sleep(200)

        assertEquals(1, server!!.clientCount())

        // Disconnect client
        client.detach()
        Thread.sleep(200)

        assertEquals(0, server!!.clientCount())
    }

    @Test
    fun `test Unix socket support detection`() {
        // Just verify the method works
        val supportsUnix = LocalServerInterface.supportsUnixSockets()
        // Don't assert a specific value, as it depends on platform
        println("Unix socket support: $supportsUnix")
    }

    @Test
    fun `test server with Unix socket if supported`(@TempDir tempDir: Path) {
        if (!LocalServerInterface.supportsUnixSockets()) {
            println("Skipping Unix socket test - not supported on this platform")
            return
        }

        val socketPath = tempDir.resolve("test.socket").toString()

        try {
            // Start server
            server = LocalServerInterface(name = "TestServer", socketPath = socketPath)
            server!!.start()

            assertTrue(server!!.online.value)

            // Start client
            val client = LocalClientInterface(name = "TestClient", socketPath = socketPath)
            clients.add(client)
            client.start()

            // Give connection time to establish
            Thread.sleep(200)

            assertTrue(client.online.value)
            assertEquals(1, server!!.clientCount())
        } catch (e: UnsupportedOperationException) {
            // Unix sockets detected but not fully supported by JVM implementation
            println("Unix sockets partially supported, skipping: ${e.message}")
        }
    }

    @Test
    fun `test bidirectional communication via TCP`() {
        // Data must be > HEADER_MIN_SIZE (19) bytes to pass HDLC deframer validation
        val clientToServerData = "Client to server!!!!!".toByteArray()
        val serverToClientData = "Server to client!!!!!".toByteArray()

        val serverReceivedLatch = CountDownLatch(1)
        val clientReceivedLatch = CountDownLatch(1)

        var serverReceived: ByteArray? = null
        var clientReceived: ByteArray? = null

        // Start server
        server = LocalServerInterface(name = "TestServer", tcpPort = 0)
        server!!.onPacketReceived = { data, _ ->
            serverReceived = data
            serverReceivedLatch.countDown()
        }
        server!!.start()
        val tcpPort = server!!.boundPort

        // Start client
        val client = LocalClientInterface(name = "TestClient", tcpPort = tcpPort)
        client.onPacketReceived = { data, _ ->
            clientReceived = data
            clientReceivedLatch.countDown()
        }
        clients.add(client)
        client.start()

        // Give connection time to establish
        Thread.sleep(200)

        // Client sends to server
        client.processOutgoing(clientToServerData)

        // Server sends to client (via spawned interface, as Transport would)
        val spawnedClient = server!!.getClients().first()
        spawnedClient.processOutgoing(serverToClientData)

        // Wait for both to receive
        assertTrue(serverReceivedLatch.await(2, TimeUnit.SECONDS))
        assertTrue(clientReceivedLatch.await(2, TimeUnit.SECONDS))

        assertArrayEquals(clientToServerData, serverReceived)
        assertArrayEquals(serverToClientData, clientReceived)
    }

    /**
     * Stress regression for the spawned-child read loop (upstream PR #75). Real-world Android
     * shared-instance soak (>30 min uptime) has been observed to wedge a long-lived spawned
     * child's read loop — inbound bytes stop draining though the socket stays ESTABLISHED and
     * outbound still flows. The redundant `withContext(Dispatchers.IO)` inside that loop
     * (already on ioScope's IO dispatcher) was removed to match python's direct
     * `socket.recv(4096)`; this guards the loop-body shape against regressions.
     *
     * The wedge is not deterministically reproducible on a desktop JVM, so this does not
     * assert "wedge fixed" — it asserts "a long-lived spawned child keeps draining inbound
     * bytes under aggressive sibling probe churn" (the watchdog-probe shape that
     * isSharedInstanceRunning produces on every shared-instance poll).
     */
    @Test
    fun `long-lived spawned child keeps draining inbound bytes under sibling probe churn`() {
        val numRounds = 50
        val probesPerRound = 5
        val packetData = "Long-lived client packet >>>".toByteArray()
        val receivedCount = AtomicInteger(0)

        server = LocalServerInterface(name = "TestServer", tcpPort = 0)
        server!!.onPacketReceived = { data, _ ->
            if (data.contentEquals(packetData)) receivedCount.incrementAndGet()
        }
        server!!.start()
        val tcpPort = server!!.boundPort

        // Issue #74 baseline: spawned-interface registrations in Transport before the
        // long-lived client connects. Relative so prior tests' state doesn't matter.
        val leakBaseline = Transport.localClientInterfaceCountForTest()

        val client = LocalClientInterface(name = "LongLivedClient", tcpPort = tcpPort)
        clients.add(client)
        client.start()
        Thread.sleep(200)
        assertEquals(1, server!!.clientCount())

        repeat(numRounds) { round ->
            // One packet from the long-lived client.
            client.processOutgoing(packetData)

            // Churn transient sibling probes (open + immediate close), mimicking the
            // watchdog-probe shape isSharedInstanceRunning produces on every poll.
            repeat(probesPerRound) {
                Socket().use { probe ->
                    probe.connect(InetSocketAddress("127.0.0.1", tcpPort), 1000)
                }
            }

            Thread.sleep(50)
            assertTrue(
                client.online.value,
                "long-lived client went offline at round $round under sibling churn",
            )
        }

        // Wait for the last packets to drain.
        val deadline = System.currentTimeMillis() + 2000
        while (System.currentTimeMillis() < deadline && receivedCount.get() < numRounds) {
            Thread.sleep(50)
        }

        assertEquals(
            numRounds,
            receivedCount.get(),
            "long-lived client sent $numRounds packets, server received ${receivedCount.get()} — " +
                "read loop may have wedged under sibling churn",
        )

        // Issue #74: the transient probes must not leave stale spawned interfaces registered
        // in Transport. Only the long-lived client's spawned child should remain — i.e. the
        // count settles back to baseline + 1, not baseline + 1 + (leaked probe children).
        val leakDeadline = System.currentTimeMillis() + 3000
        while (Transport.localClientInterfaceCountForTest() > leakBaseline + 1 &&
            System.currentTimeMillis() < leakDeadline
        ) {
            Thread.sleep(50)
        }
        assertEquals(
            leakBaseline + 1,
            Transport.localClientInterfaceCountForTest(),
            "transient probe connections leaked stale spawned interfaces in Transport (issue #74)",
        )
    }
}
