package network.reticulum.interfaces.backbone

import network.reticulum.interfaces.framing.HDLC
import network.reticulum.interfaces.framing.HdlcReceiveBuffer
import network.reticulum.interfaces.toRef
import network.reticulum.transport.Transport
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Timeout
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

class BackboneInterfaceRoundTripTest {

    private var backbone: BackboneInterface? = null
    private var client: Socket? = null

    @AfterEach
    fun cleanup() {
        try { client?.close() } catch (_: Exception) {}
        try { backbone?.detach() } catch (_: Exception) {}
    }

    @Test
    @Timeout(15, unit = TimeUnit.SECONDS)
    fun `a client frame is deframed and delivered upward`() {
        val received = CountDownLatch(1)
        val receivedData = AtomicReference<ByteArray>()

        val bb = BackboneInterface(name = "BB", bindIp = "127.0.0.1", bindPort = 0)
        bb.onPacketReceived = { data, _ -> receivedData.set(data); received.countDown() }
        backbone = bb
        bb.start()

        val sock = Socket()
        sock.connect(InetSocketAddress("127.0.0.1", bb.boundPort), 3000)
        client = sock

        // Payload must exceed HEADER_MIN_SIZE (19) to pass the deframer's min-length check.
        val payload = ByteArray(25) { (it + 1).toByte() }
        sock.getOutputStream().write(HDLC.frame(payload))
        sock.getOutputStream().flush()

        assertTrue(received.await(10, TimeUnit.SECONDS), "backbone should deframe and deliver the client's frame")
        assertArrayEquals(payload, receivedData.get())
    }

    @Test
    @Timeout(15, unit = TimeUnit.SECONDS)
    fun `an outbound packet is framed and reaches the client`() {
        val bb = BackboneInterface(name = "BB2", bindIp = "127.0.0.1", bindPort = 0)
        backbone = bb
        bb.start()

        val sock = Socket()
        sock.connect(InetSocketAddress("127.0.0.1", bb.boundPort), 3000)
        client = sock

        // Wait for the spawned client interface to appear.
        val deadline = System.currentTimeMillis() + 5000
        while (bb.spawnedInterfaces.isNullOrEmpty() && System.currentTimeMillis() < deadline) Thread.sleep(20)
        val spawned = bb.spawnedInterfaces?.firstOrNull()
        assertNotNull(spawned, "a client interface should be spawned on connect")

        val payload = ByteArray(30) { (it + 5).toByte() }
        spawned!!.processOutgoing(payload)

        // Read from the raw socket and deframe what the backbone sent.
        val frames = mutableListOf<ByteArray>()
        val rb = HdlcReceiveBuffer({ 262144 }, minFrameLen = 0, onFrame = { frames += it })
        val ins = sock.getInputStream()
        sock.soTimeout = 5000
        val buf = ByteArray(4096)
        val end = System.currentTimeMillis() + 6000
        while (frames.isEmpty() && System.currentTimeMillis() < end) {
            val n = try { ins.read(buf) } catch (e: Exception) { -1 }
            if (n <= 0) break
            rb.feed(buf.copyOfRange(0, n))
        }
        assertEquals(1, frames.size, "client should receive exactly one framed packet")
        assertArrayEquals(payload, frames[0])
    }

    @Test
    @Timeout(15, unit = TimeUnit.SECONDS)
    fun `detaching the listener deregisters and detaches its connected clients`() {
        val bb = BackboneInterface(name = "BB3", bindIp = "127.0.0.1", bindPort = 0)
        backbone = bb
        bb.start()

        val sock = Socket()
        sock.connect(InetSocketAddress("127.0.0.1", bb.boundPort), 3000)
        client = sock

        val deadline = System.currentTimeMillis() + 5000
        while (bb.spawnedInterfaces.isNullOrEmpty() && System.currentTimeMillis() < deadline) Thread.sleep(20)
        val spawned = bb.spawnedInterfaces?.firstOrNull()
        assertNotNull(spawned, "a client interface should be spawned on connect")
        val ref = spawned!!.toRef()

        // accept() registers every spawned client with Transport, so the path table can
        // name it as a next hop.
        assertTrue(
            Transport.getInterfaces().any { it === ref },
            "the spawned client should be registered with Transport while connected",
        )

        bb.detach()

        // Detaching the listener closes the clients' channels. Leaving them registered
        // would let a path-table entry keep resolving onto an interface whose writes are
        // never drained: findInterfaceByHash applies no online filter, so the send would
        // be accepted and silently discarded.
        assertFalse(
            Transport.getInterfaces().any { it === ref },
            "the spawned client should be deregistered from Transport when its listener detaches",
        )
        assertFalse(spawned.online.value, "the spawned client should be offline after the listener detaches")
        assertTrue(spawned.detached.get(), "the spawned client should be marked detached")
        assertTrue(bb.spawnedInterfaces.isNullOrEmpty(), "the listener should hold no spawned clients after detach")
    }
}
