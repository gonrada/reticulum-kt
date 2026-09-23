package network.reticulum.interfaces.util

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Timeout
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketOption
import java.net.StandardSocketOptions
import java.nio.channels.SocketChannel
import java.util.concurrent.TimeUnit

/**
 * Keepalive tuning mirror of python TCPInterface.py:183-197. The extended options are
 * platform-dependent, so their values are asserted only where the runtime reports them
 * as supported; SO_KEEPALIVE itself must always be set.
 */
class TcpKeepaliveTest {

    @Test
    fun `python probe constants are mirrored`() {
        assertEquals(5, TcpKeepalive.TCP_PROBE_AFTER)
        assertEquals(2, TcpKeepalive.TCP_PROBE_INTERVAL)
        assertEquals(12, TcpKeepalive.TCP_PROBES)
    }

    @Test
    @Timeout(15, unit = TimeUnit.SECONDS)
    fun `apply on a Socket enables keepalive and python probe timing where supported`() {
        ServerSocket(0, 1, java.net.InetAddress.getLoopbackAddress()).use { server ->
            Socket().use { sock ->
                sock.connect(InetSocketAddress(server.inetAddress, server.localPort), 3000)
                server.accept().use { accepted ->
                    val applied = TcpKeepalive.apply(accepted)
                    assertTrue(accepted.keepAlive, "SO_KEEPALIVE must be set on the accepted socket")

                    val supported = accepted.supportedOptions()
                    val expected = mapOf(
                        "TCP_KEEPIDLE" to TcpKeepalive.TCP_PROBE_AFTER,
                        "TCP_KEEPINTERVAL" to TcpKeepalive.TCP_PROBE_INTERVAL,
                        "TCP_KEEPCOUNT" to TcpKeepalive.TCP_PROBES,
                    )
                    var checked = 0
                    for (option in supported) {
                        val want = expected[option.name()] ?: continue
                        @Suppress("UNCHECKED_CAST")
                        val got = accepted.getOption(option as SocketOption<Int>)
                        assertEquals(want, got, "${option.name()} should carry python's constant")
                        checked++
                    }
                    // Every option the runtime supports must have been applied.
                    assertEquals(checked, applied, "applied count must match the supported extended options")
                }
            }
        }
    }

    @Test
    @Timeout(15, unit = TimeUnit.SECONDS)
    fun `apply on a SocketChannel enables keepalive`() {
        ServerSocket(0, 1, java.net.InetAddress.getLoopbackAddress()).use { server ->
            SocketChannel.open().use { ch ->
                ch.connect(InetSocketAddress(server.inetAddress, server.localPort))
                server.accept().use { _ ->
                    TcpKeepalive.apply(ch)
                    assertTrue(ch.getOption(StandardSocketOptions.SO_KEEPALIVE), "SO_KEEPALIVE must be set on the channel")
                }
            }
        }
    }
}
