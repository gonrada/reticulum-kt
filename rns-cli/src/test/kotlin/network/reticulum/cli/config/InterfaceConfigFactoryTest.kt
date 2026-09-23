package network.reticulum.cli.config

import network.reticulum.interfaces.tcp.TCPClientInterface
import network.reticulum.interfaces.tcp.TCPServerInterface
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Path
import kotlin.io.path.writeText

class InterfaceConfigFactoryTest {
    @TempDir
    lateinit var tempDir: Path

    @Test
    fun `TCP client forwards configured Python reconnect limit`() {
        val config = InterfaceConfig(
            name = "ConfiguredTcpClient",
            type = "TCPClientInterface",
            options = mapOf(
                "target_host" to "127.0.0.1",
                "target_port" to 4242,
                "max_reconnect_tries" to 7,
            ),
        )

        assertEquals(7, config.maxReconnectTries)

        val iface = InterfaceConfigFactory.createTcpClient(config) as TCPClientInterface
        assertEquals(7, iface.configuredMaxReconnectAttempts())
    }

    @Test
    fun `TCP client preserves Python unlimited reconnect default`() {
        val config = InterfaceConfig(
            name = "UnlimitedTcpClient",
            type = "TCPClientInterface",
            options = mapOf(
                "target_host" to "127.0.0.1",
                "target_port" to 4242,
            ),
        )

        assertEquals(null, config.maxReconnectTries)

        val iface = InterfaceConfigFactory.createTcpClient(config) as TCPClientInterface
        assertEquals(null, iface.configuredMaxReconnectAttempts())
    }

    @Test
    fun `TCP client accepts quoted integer reconnect limit like Python ConfigObj`() {
        val configFile = tempDir.resolve("config")
        configFile.writeText(
            """
            [interfaces]
              [[QuotedTcpClient]]
                type = TCPClientInterface
                enabled = yes
                target_host = 127.0.0.1
                target_port = 4242
                max_reconnect_tries = "7"
            """.trimIndent(),
        )

        val config = ConfigParser.parse(configFile.toFile()).interfaces.getValue("QuotedTcpClient")
        assertEquals(7, config.maxReconnectTries)
    }

    @Test
    fun `TCP client accepts supplementary Unicode decimal digits like Python int`() {
        val config = InterfaceConfig(
            name = "UnicodeTcpClient",
            type = "TCPClientInterface",
            options = mapOf("max_reconnect_tries" to "𑁦"),
        )

        assertEquals(0, config.maxReconnectTries)
    }

    @Test
    fun `TCP client rejects reconnect limits Python ConfigObj rejects`() {
        listOf(7.5, "malformed", "", Int.MAX_VALUE.toLong() + 1).forEach { invalidValue ->
            val config = InterfaceConfig(
                name = "InvalidTcpClient",
                type = "TCPClientInterface",
                options = mapOf("max_reconnect_tries" to invalidValue),
            )

            assertThrows(IllegalArgumentException::class.java) {
                config.maxReconnectTries
            }
        }
    }

    @Test
    fun `TCP client applies network_name and passphrase from config`() {
        val config = InterfaceConfig(
            name = "IfacTcpClient",
            type = "TCPClientInterface",
            options = mapOf(
                "target_host" to "127.0.0.1",
                "target_port" to 4242,
                "network_name" to "family",
                "passphrase" to "familypass123test",
            ),
        )
        assertEquals("family", config.ifacNetname)
        assertEquals("familypass123test", config.ifacNetkey)
        assertNull(config.ifacSizeBits)

        val iface = InterfaceConfigFactory.createTcpClient(config) as TCPClientInterface
        assertEquals("family", iface.ifacNetname)
        assertEquals(16, iface.ifacSize, "TCP default IFAC tag is 16 bytes once credentials exist")
        assertNotNull(iface.ifacIdentity)
        assertNotNull(iface.ifacKey)
    }

    @Test
    fun `TCP client honours ifac_size in bits and the legacy spellings`() {
        val config = InterfaceConfig(
            name = "IfacBitsTcpClient",
            type = "TCPClientInterface",
            options = mapOf(
                "target_host" to "127.0.0.1",
                "target_port" to 4242,
                "networkname" to "old",
                "network_name" to "new",   // underscored spelling wins (Reticulum.py:805-812)
                "pass_phrase" to "secret",
                "ifac_size" to "64",
            ),
        )
        assertEquals("new", config.ifacNetname)
        assertEquals("secret", config.ifacNetkey)
        assertEquals(64, config.ifacSizeBits)

        val iface = InterfaceConfigFactory.createTcpClient(config) as TCPClientInterface
        assertEquals(8, iface.ifacSize, "64 bits -> 8-byte tag")
    }

    @Test
    fun `TCP client without credentials has IFAC disabled`() {
        val config = InterfaceConfig(
            name = "PlainTcpClient",
            type = "TCPClientInterface",
            options = mapOf("target_host" to "127.0.0.1", "target_port" to 4242, "network_name" to ""),
        )
        assertNull(config.ifacNetname, "empty string means unset")
        val iface = InterfaceConfigFactory.createTcpClient(config) as TCPClientInterface
        assertEquals(0, iface.ifacSize)
        assertNull(iface.ifacIdentity)
    }

    @Test
    fun `TCP client IFAC credentials survive the config file parser`() {
        val configFile = tempDir.resolve("config")
        configFile.writeText(
            """
            [interfaces]
              [[IfacFromFile]]
                type = TCPClientInterface
                enabled = yes
                target_host = 127.0.0.1
                target_port = 4242
                network_name = family
                passphrase = familypass123test
                ifac_size = 128
            """.trimIndent(),
        )

        val config = ConfigParser.parse(configFile.toFile()).interfaces.getValue("IfacFromFile")
        assertEquals("family", config.ifacNetname)
        assertEquals("familypass123test", config.ifacNetkey)
        assertEquals(128, config.ifacSizeBits)

        val iface = InterfaceConfigFactory.createTcpClient(config) as TCPClientInterface
        assertEquals(16, iface.ifacSize)
    }

    @Test
    fun `TCP server receives IFAC credentials from config`() {
        val server = InterfaceConfig(
            name = "Srv",
            type = "TCPServerInterface",
            options = mapOf("listen_ip" to "127.0.0.1", "listen_port" to 0, "network_name" to "family", "passphrase" to "familypass123test"),
        )
        val tcp = InterfaceConfigFactory.createTcpServer(server) as TCPServerInterface
        assertEquals("family", tcp.ifacNetname)
        assertEquals(16, tcp.ifacSize)
        assertNotNull(tcp.ifacIdentity)
    }

    private fun TCPClientInterface.configuredMaxReconnectAttempts(): Int? {
        val field = TCPClientInterface::class.java.getDeclaredField("maxReconnectAttempts")
        field.isAccessible = true
        return field.get(this) as Int?
    }

    @Test
    fun `TCP client applies ingress-control knobs from config`() {
        val config = InterfaceConfig(
            name = "Knobs",
            type = "TCPClientInterface",
            options = mapOf(
                "target_host" to "127.0.0.1",
                "target_port" to 4242,
                "ingress_control" to true,
                "ic_new_time" to 900,
                "ic_burst_freq_new" to 2.5,
                "ic_burst_freq" to 7.5,
                "ic_burst_hold" to 30,
                "ic_burst_penalty" to 45,
                "ic_held_release_interval" to 20,
                "ic_max_held_announces" to 128,
            ),
        )

        val iface = InterfaceConfigFactory.createTcpClient(config) as TCPClientInterface

        // The reference reads these keys in seconds; the interface holds milliseconds.
        assertEquals(true, iface.ingressControlEnabled())
        assertEquals(900_000L, iface.icNewTimeMs)
        assertEquals(2.5, iface.icBurstFreqNew)
        assertEquals(7.5, iface.icBurstFreq)
        assertEquals(30_000L, iface.icBurstHoldMs)
        assertEquals(45_000L, iface.icBurstPenaltyMs)
        assertEquals(20_000L, iface.icHeldReleaseIntervalMs)
        assertEquals(128, iface.icMaxHeldAnnounces)
    }
}
