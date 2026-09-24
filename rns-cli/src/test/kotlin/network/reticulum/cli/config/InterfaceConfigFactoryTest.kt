package network.reticulum.cli.config

import network.reticulum.interfaces.backbone.BackboneInterface
import network.reticulum.interfaces.tcp.TCPClientInterface
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
    fun `Backbone interface is created from config`() {
        val config = InterfaceConfig(
            name = "TestBackbone",
            type = "BackboneInterface",
            options = mapOf(
                "listen_ip" to "127.0.0.1",
                "listen_port" to 0,
            ),
        )
        val iface = InterfaceConfigFactory.createBackbone(config) as BackboneInterface
        assertEquals("TestBackbone", iface.name)
    }

    @Test
    fun `Backbone type dispatches through createInterface`() {
        val config = InterfaceConfig(
            name = "DispatchBackbone",
            type = "BackboneInterface",
            options = mapOf("listen_ip" to "127.0.0.1", "listen_port" to 0),
        )
        assertNotNull(
            InterfaceConfigFactory.createInterface(config),
            "BackboneInterface config should produce an interface ref",
        )
    }

    @Test
    fun `Backbone requires listen_port`() {
        val config = InterfaceConfig(name = "NoPort", type = "BackboneInterface", options = emptyMap())
        assertNull(InterfaceConfigFactory.createBackbone(config))
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
    fun `SerialInterface is created from its python config keys without opening the port`() {
        val config = InterfaceConfig(
            name = "Wire",
            type = "SerialInterface",
            options = mapOf("port" to "/dev/ttyNONE0", "speed" to 115200, "databits" to 8, "parity" to "N", "stopbits" to 1),
        )
        assertEquals(InterfaceType.SERIAL, InterfaceType.fromConfigName(config.type))
        val iface = InterfaceConfigFactory.createSerial(config) as network.reticulum.interfaces.serial.SerialInterface
        assertEquals("Wire", iface.name)
        assertEquals(115200, iface.bitrate)
        assertEquals(564, iface.hwMtu)
        assertNull(InterfaceConfigFactory.createSerial(InterfaceConfig(name = "NoPort", type = "SerialInterface", options = emptyMap())))
    }

    @Test
    fun `KISS and AX25KISS interfaces are created from their python config keys`() {
        val kiss = InterfaceConfig(
            name = "Tnc",
            type = "KISSInterface",
            options = mapOf("port" to "/dev/ttyNONE1", "speed" to 9600, "preamble" to 150, "flow_control" to true, "id_interval" to 600, "id_callsign" to "N0CALL"),
        )
        val iface = InterfaceConfigFactory.createKiss(kiss, ax25 = false) as network.reticulum.interfaces.kiss.KissInterface
        assertEquals("Tnc", iface.name)
        assertEquals(9600, iface.bitrate)

        val ax25 = InterfaceConfig(
            name = "Packet",
            type = "AX25KISSInterface",
            options = mapOf("port" to "/dev/ttyNONE2", "callsign" to "N0CALL", "ssid" to 3),
        )
        assertNotNull(InterfaceConfigFactory.createKiss(ax25, ax25 = true))
        val noCall = InterfaceConfig(name = "NoCall", type = "AX25KISSInterface", options = mapOf("port" to "/dev/ttyNONE2"))
        assertNull(InterfaceConfigFactory.createKiss(noCall, ax25 = true), "python raises without a callsign")
    }

    @Test
    fun `TCP server and backbone receive IFAC credentials from config`() {
        val server = InterfaceConfig(
            name = "Srv",
            type = "TCPServerInterface",
            options = mapOf("listen_ip" to "127.0.0.1", "listen_port" to 0, "network_name" to "family", "passphrase" to "familypass123test"),
        )
        val tcp = InterfaceConfigFactory.createTcpServer(server) as network.reticulum.interfaces.tcp.TCPServerInterface
        assertEquals("family", tcp.ifacNetname)
        assertEquals(16, tcp.ifacSize)
        assertNotNull(tcp.ifacIdentity)
        val backbone = InterfaceConfig(
            name = "Bb",
            type = "BackboneInterface",
            options = mapOf("listen_ip" to "127.0.0.1", "listen_port" to 0, "network_name" to "family", "passphrase" to "familypass123test"),
        )
        val bb = InterfaceConfigFactory.createBackbone(backbone) as BackboneInterface
        assertEquals("family", bb.ifacNetname)
    }

    @Test
    fun `common knobs from config are applied to the interface`() {
        val config = InterfaceConfig(
            name = "Knobs",
            type = "TCPClientInterface",
            options = mapOf(
                "target_host" to "127.0.0.1", "target_port" to 4242,
                "interface_mode" to "roaming", "announce_cap" to 5,
                "announce_rate_target" to 600, "announce_rate_grace" to 2,
                "announces_to_internal" to true, "ingress_control" to false,
            ),
        )
        val iface = InterfaceConfigFactory.createTcpClient(config) as TCPClientInterface
        InterfaceConfigFactory.applyCommonKnobs(iface, config)
        val ref = network.reticulum.interfaces.InterfaceAdapter.getOrCreate(iface)
        assertEquals(network.reticulum.common.InterfaceMode.ROAMING, ref.mode)
        assertEquals(0.05, ref.announceCap, 1e-9)
        assertEquals(600, ref.announceRateTarget)
        assertEquals(2, ref.announceRateGrace)
        assertEquals(0, ref.announceRatePenalty, "penalty defaults to 0 once a target is set")
        assertEquals(true, ref.announcesToInternal)
        assertEquals(false, iface.ingressControlEnabled())

        val plain = InterfaceConfig(name = "Plain", type = "TCPClientInterface", options = mapOf("target_host" to "127.0.0.1", "target_port" to 4242))
        val untouched = InterfaceConfigFactory.createTcpClient(plain) as TCPClientInterface
        InterfaceConfigFactory.applyCommonKnobs(untouched, plain)
        val plainRef = network.reticulum.interfaces.InterfaceAdapter.getOrCreate(untouched)
        assertNull(plainRef.announceRateTarget)
        assertEquals(true, untouched.ingressControlEnabled())
    }

    private fun TCPClientInterface.configuredMaxReconnectAttempts(): Int? {
        val field = TCPClientInterface::class.java.getDeclaredField("maxReconnectAttempts")
        field.isAccessible = true
        return field.get(this) as Int?
    }
}
