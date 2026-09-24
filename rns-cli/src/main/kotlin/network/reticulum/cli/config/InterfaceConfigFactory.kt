package network.reticulum.cli.config

import network.reticulum.cli.logging.Logger
import network.reticulum.interfaces.Interface
import network.reticulum.interfaces.auto.AutoInterface
import network.reticulum.interfaces.backbone.BackboneInterface
import network.reticulum.interfaces.kiss.KissInterface
import network.reticulum.interfaces.kiss.KissSerialPort
import network.reticulum.interfaces.serial.SerialInterface
import network.reticulum.interfaces.tcp.TCPClientInterface
import network.reticulum.interfaces.tcp.TCPServerInterface
import network.reticulum.interfaces.toRef
import network.reticulum.transport.InterfaceRef
import network.reticulum.transport.Transport

/**
 * Factory for creating network interfaces from configuration.
 *
 * Creates Interface instances based on config type and options,
 * then wraps them as InterfaceRef for Transport registration.
 */
object InterfaceConfigFactory {

    /**
     * Create an interface from configuration.
     *
     * @param config Interface configuration
     * @return InterfaceRef for Transport, or null if type is unsupported or creation fails
     */
    fun createInterface(config: InterfaceConfig): InterfaceRef? {
        if (!config.enabled) {
            return null
        }

        val iface: Interface? = when (InterfaceType.fromConfigName(config.type)) {
            InterfaceType.TCP_CLIENT -> createTcpClient(config)
            InterfaceType.TCP_SERVER -> createTcpServer(config)
            InterfaceType.BACKBONE -> createBackbone(config)
            InterfaceType.UDP -> {
                Logger.warning("UDPInterface is not yet implemented")
                null
            }
            InterfaceType.AUTO -> createAutoInterface(config)
            InterfaceType.RNODE -> {
                Logger.warning("RNodeInterface is not yet implemented")
                null
            }
            InterfaceType.KISS -> createKiss(config, ax25 = false)
            InterfaceType.AX25_KISS -> createKiss(config, ax25 = true)
            InterfaceType.SERIAL -> createSerial(config)
            InterfaceType.I2P -> {
                Logger.warning("I2PInterface is not yet implemented")
                null
            }
            InterfaceType.BLE -> {
                Logger.warning("BLEInterface is not yet implemented")
                null
            }
            InterfaceType.UNKNOWN -> {
                Logger.warning("Unknown interface type: ${config.type}")
                null
            }
        }

        if (iface == null) {
            return null
        }
        applyCommonKnobs(iface, config)
        // Wire up packet callback to Transport
        val ifaceRef = iface.toRef()
        iface.onPacketReceived = { data, _ ->
            Transport.inbound(data, ifaceRef)
        }

        // Start the interface
        try {
            iface.start()
        } catch (e: Exception) {
            Logger.error("Failed to start interface ${config.name}: ${e.message}")
            return null
        }

        return ifaceRef
    }

    /**
     * Create a TCP client interface.
     */
    internal fun createTcpClient(config: InterfaceConfig): Interface? {
        val targetHost = config.targetHost
        val targetPort = config.targetPort

        if (targetHost == null || targetPort == null) {
            Logger.error("TCPClientInterface ${config.name} requires target_host and target_port")
            return null
        }

        Logger.debug("Creating TCPClientInterface ${config.name} -> $targetHost:$targetPort")

        return TCPClientInterface(
            name = config.name,
            targetHost = targetHost,
            targetPort = targetPort,
            maxReconnectAttempts = config.maxReconnectTries,
            // network_name / passphrase / ifac_size were parsed into the options map
            // but never handed to the interface, so the daemon ran "IFAC'd" TCP
            // clients in the clear (only the daemon's own factory was affected).
            ifacNetname = config.ifacNetname,
            ifacNetkey = config.ifacNetkey,
            ifacSizeBits = config.ifacSizeBits,
        )
    }

    /**
     * Create a TCP server interface.
     */
    internal fun createTcpServer(config: InterfaceConfig): Interface? {
        val listenIp = config.listenIp ?: "0.0.0.0"
        val listenPort = config.listenPort

        if (listenPort == null) {
            Logger.error("TCPServerInterface ${config.name} requires listen_port")
            return null
        }

        Logger.debug("Creating TCPServerInterface ${config.name} on $listenIp:$listenPort")

        return TCPServerInterface(
            name = config.name,
            bindAddress = listenIp,
            bindPort = listenPort,
            ifacNetname = config.ifacNetname,
            ifacNetkey = config.ifacNetkey,
            ifacSizeBits = config.ifacSizeBits,
        )
    }

    /**
     * Create a BackboneInterface (high-throughput NIO TCP backbone listener).
     */
    internal fun createBackbone(config: InterfaceConfig): Interface? {
        val listenIp = config.listenIp ?: "0.0.0.0"
        val listenPort = config.listenPort
        if (listenPort == null) {
            Logger.error("BackboneInterface ${config.name} requires listen_port")
            return null
        }
        Logger.debug("Creating BackboneInterface ${config.name} on $listenIp:$listenPort")
        return BackboneInterface(
            name = config.name,
            bindIp = listenIp,
            bindPort = listenPort,
            ifacNetname = config.ifacNetname,
            ifacNetkey = config.ifacNetkey,
            ifacSizeBits = config.ifacSizeBits,
        )
    }

    /**
     * Create an AutoInterface for local peer discovery.
     */
    private fun createAutoInterface(config: InterfaceConfig): Interface? {
        Logger.debug("Creating AutoInterface ${config.name}")

        return AutoInterface(
            name = config.name,
            groupId = config.groupId?.toByteArray(Charsets.UTF_8)
                ?: network.reticulum.interfaces.auto.AutoInterfaceConstants.DEFAULT_GROUP_ID,
            discoveryPort = config.discoveryPort
                ?: network.reticulum.interfaces.auto.AutoInterfaceConstants.DEFAULT_DISCOVERY_PORT,
            dataPort = config.dataPort
                ?: network.reticulum.interfaces.auto.AutoInterfaceConstants.DEFAULT_DATA_PORT,
            allowedDevices = config.devices,
            ignoredDevices = config.ignoredDevices ?: emptyList()
        )
    }

    /**
     * The per-interface knobs python applies to every interface type after construction
     * (Reticulum.py:758-900, 946-950): `interface_mode` / `mode`, `announce_cap`,
     * `announce_rate_target` / `_grace` / `_penalty`, `announces_from_internal` /
     * `announces_to_internal`, `ingress_control`. Absent keys keep the class values.
     * A mode the reference cannot resolve (`interface_mode = gateway` without `mode`)
     * is logged and the interface keeps its default, rather than failing the daemon.
     */
    internal fun applyCommonKnobs(iface: Interface, config: InterfaceConfig) {
        val section = config.options.mapValues { it.value.toString() } + mapOf("type" to config.type)
        val synthesized =
            try {
                network.reticulum.config.InterfaceConfig.synthesize(section, iface.bitrate)
            } catch (e: IllegalArgumentException) {
                Logger.error("${config.name}: ${e.message}")
                return
            }
        if ("interface_mode" in section || "mode" in section) iface.modeOverride = synthesized.mode
        if ("announce_cap" in section) iface.announceCapOverride = synthesized.announceCap
        if ("announces_from_internal" in section) iface.announcesFromInternalOverride = synthesized.announcesFromInternal
        synthesized.announcesToInternal?.let { iface.announcesToInternalOverride = it }
        // Reticulum.py:848-861: a target enables rate limiting; grace and penalty default to 0 with it.
        val target = section["announce_rate_target"]?.trim()?.toIntOrNull()?.takeIf { it > 0 }
        val grace = section["announce_rate_grace"]?.trim()?.toIntOrNull()?.takeIf { it >= 0 }
        val penalty = section["announce_rate_penalty"]?.trim()?.toIntOrNull()?.takeIf { it >= 0 }
        if (target != null) {
            iface.announceRateTargetOverride = target
            iface.announceRateGraceOverride = grace ?: 0
            iface.announceRatePenaltyOverride = penalty ?: 0
        }
        section["ingress_control"]?.let { iface.setIngressControl(it.trim().lowercase() in setOf("yes", "true", "on", "1")) }
        // python Interface.py:138-150 with the config overrides of Reticulum.py:840-860;
        // the synthesiser returns the class defaults for absent keys, and seconds -> ms.
        iface.icMaxHeldAnnounces = synthesized.icMaxHeldAnnounces
        iface.icBurstHoldMs = (synthesized.icBurstHold * 1000).toLong()
        iface.icBurstFreqNew = synthesized.icBurstFreqNew
        iface.icBurstFreq = synthesized.icBurstFreq
        iface.icNewTimeMs = (synthesized.icNewTime * 1000).toLong()
        iface.icBurstPenaltyMs = (synthesized.icBurstPenalty * 1000).toLong()
        iface.icHeldReleaseIntervalMs = (synthesized.icHeldReleaseInterval * 1000).toLong()
        section["egress_control"]?.let { iface.egressControl = it.trim().lowercase() in setOf("yes", "true", "on", "1") }
        section["ec_pr_freq"]?.trim()?.toDoubleOrNull()?.takeIf { it >= 0 }?.let { iface.ecPrFreq = it }
    }

    /** The serial device behind a SerialInterface / KISSInterface config, opened lazily by the interface. */
    internal fun serialPortFor(config: InterfaceConfig): KissSerialPort? {
        val portName = config.serialPort
        if (portName == null) {
            Logger.error("${config.type} ${config.name} requires a port")
            return null
        }
        return JSerialCommPort(portName, config.serialSpeed, config.serialDataBits, config.serialParity, config.serialStopBits)
    }

    /** python SerialInterface (Reticulum.py:1060-1062). */
    internal fun createSerial(config: InterfaceConfig): Interface? {
        val port = serialPortFor(config) ?: return null
        Logger.debug("Creating SerialInterface ${config.name} on ${config.serialPort} at ${config.serialSpeed} baud")
        return SerialInterface(
            name = config.name,
            port = port,
            speed = config.serialSpeed,
            ifacNetname = config.ifacNetname,
            ifacNetkey = config.ifacNetkey,
            ifacSizeBits = config.ifacSizeBits,
        )
    }

    /** python KISSInterface / AX25KISSInterface (Reticulum.py:1068-1075). */
    internal fun createKiss(config: InterfaceConfig, ax25: Boolean): Interface? {
        val port = serialPortFor(config) ?: return null
        if (ax25 && config.ax25Callsign.isEmpty()) {
            Logger.error("AX25KISSInterface ${config.name} requires a callsign")
            return null
        }
        val configureTnc = listOf(config.kissPreamble, config.kissTxTail, config.kissPersistence, config.kissSlotTime).any { it != null }
        Logger.debug("Creating ${if (ax25) "AX25KISSInterface" else "KISSInterface"} ${config.name} on ${config.serialPort}")
        return KissInterface(
            name = config.name,
            port = port,
            bitrateGuess = config.serialSpeed,
            flowControl = config.kissFlowControl,
            ax25 = ax25,
            ax25SrcCall = if (ax25) config.ax25Callsign else null,
            ax25SrcSsid = if (ax25 && config.ax25Ssid >= 0) config.ax25Ssid else 0,
            configureTnc = configureTnc,
            preambleMs = config.kissPreamble ?: 350,
            txTailMs = config.kissTxTail ?: 20,
            persistence = config.kissPersistence ?: 64,
            slotTimeMs = config.kissSlotTime ?: 20,
            beaconIntervalMs = config.kissIdInterval?.let { it * 1000L },
            beaconData = config.kissIdCallsign?.toByteArray(Charsets.UTF_8),
            ifacNetname = config.ifacNetname,
            ifacNetkey = config.ifacNetkey,
            ifacSizeBits = config.ifacSizeBits,
        )
    }
}
