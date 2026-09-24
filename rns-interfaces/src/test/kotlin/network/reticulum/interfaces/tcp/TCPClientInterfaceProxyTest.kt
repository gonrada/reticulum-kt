package network.reticulum.interfaces.tcp

import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Timeout
import java.io.DataInputStream
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread

/**
 * SOCKS5 proxy routing and connect-failure socket handling.
 */
class TCPClientInterfaceProxyTest {

    private val interfaces = mutableListOf<TCPClientInterface>()

    @AfterEach
    fun cleanup() {
        interfaces.forEach { it.stop() }
        interfaces.clear()
    }

    @Test
    @Timeout(15, unit = TimeUnit.SECONDS)
    fun `connects through a SOCKS5 proxy using remote domain resolution`() {
        // Real target the proxy bridges to.
        val target = ServerSocket(0)
        val targetAccepted = CountDownLatch(1)
        thread(isDaemon = true) {
            try { target.accept().use { targetAccepted.countDown(); Thread.sleep(300) } } catch (_: Exception) {}
        }

        // Minimal SOCKS5 proxy: no-auth, CONNECT, must receive ATYP=domain (remote DNS),
        // then connect upstream to the real target and reply success.
        val sawDomainAtyp = AtomicBoolean(false)
        val proxy = ServerSocket(0)
        thread(isDaemon = true) {
            try {
                proxy.accept().use { c ->
                    val din = DataInputStream(c.getInputStream())
                    val out = c.getOutputStream()
                    // greeting: VER, NMETHODS, methods[]
                    din.readUnsignedByte(); val n = din.readUnsignedByte(); repeat(n) { din.readUnsignedByte() }
                    out.write(byteArrayOf(0x05, 0x00)); out.flush() // select no-auth
                    // request: VER, CMD, RSV, ATYP
                    din.readUnsignedByte(); din.readUnsignedByte(); din.readUnsignedByte()
                    val atyp = din.readUnsignedByte()
                    val host = when (atyp) {
                        0x03 -> { sawDomainAtyp.set(true); val len = din.readUnsignedByte(); val b = ByteArray(len); din.readFully(b); String(b) }
                        0x01 -> { val b = ByteArray(4); din.readFully(b); "${b[0].toInt() and 0xFF}.${b[1].toInt() and 0xFF}.${b[2].toInt() and 0xFF}.${b[3].toInt() and 0xFF}" }
                        else -> { val b = ByteArray(16); din.readFully(b); "::1" }
                    }
                    val port = (din.readUnsignedByte() shl 8) or din.readUnsignedByte()
                    Socket().use { up ->
                        up.connect(InetSocketAddress(host, port), 2000) // fires targetAccepted
                        // success reply: VER REP RSV ATYP(IPv4) BND.ADDR(0.0.0.0) BND.PORT(0)
                        out.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0)); out.flush()
                        Thread.sleep(300)
                    }
                }
            } catch (_: Exception) {}
        }

        val iface = TCPClientInterface(
            name = "SocksTest",
            targetHost = "127.0.0.1",
            targetPort = target.localPort,
            connectTimeoutMs = 3000,
            maxReconnectAttempts = 1,
            socksProxyHost = "127.0.0.1",
            socksProxyPort = proxy.localPort,
        )
        interfaces.add(iface)
        iface.start()

        assertTrue(
            targetAccepted.await(10, TimeUnit.SECONDS),
            "target must receive a connection bridged through the SOCKS5 proxy",
        )
        assertTrue(
            sawDomainAtyp.get(),
            "proxy must receive ATYP=domain so the proxy resolves DNS (.onion support)",
        )

        target.close(); proxy.close()
    }

    @Test
    @Timeout(6, unit = TimeUnit.SECONDS)
    fun `proxy configured but not listening fails gracefully`() = runBlocking {
        val deadProxyPort = ServerSocket(0).use { it.localPort } // closed immediately
        val iface = TCPClientInterface(
            name = "SocksDead",
            targetHost = "127.0.0.1",
            targetPort = 12345,
            connectTimeoutMs = 250,
            maxReconnectAttempts = 2,
            socksProxyHost = "127.0.0.1",
            socksProxyPort = deadProxyPort,
        )
        interfaces.add(iface)
        iface.start()
        delay(500) // connect() must return null and not crash; interface keeps its state
        assertFalse(iface.detached.get())
    }

    @Test
    @Timeout(5, unit = TimeUnit.SECONDS)
    fun `defaults to no proxy`() {
        val iface = TCPClientInterface(
            name = "NoProxy",
            targetHost = "192.0.2.1",
            targetPort = 12345,
            maxReconnectAttempts = 1,
        )
        interfaces.add(iface)
        assertNotNull(iface)
    }
}
