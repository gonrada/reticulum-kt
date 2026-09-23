package network.reticulum.cli.config

import network.reticulum.cli.logging.Logger
import network.reticulum.interfaces.Interface
import network.reticulum.interfaces.auto.AutoInterface
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
            InterfaceType.UDP -> {
                Logger.warning("UDPInterface is not yet implemented")
                null
            }
            InterfaceType.AUTO -> createAutoInterface(config)
            InterfaceType.RNODE -> {
                Logger.warning("RNodeInterface is not yet implemented")
                null
            }
            InterfaceType.KISS -> {
                Logger.warning("KISSInterface is not yet implemented")
                null
            }
            InterfaceType.AX25_KISS -> {
                Logger.warning("AX25KISSInterface is not yet implemented")
                null
            }
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
            // network_name / passphrase / ifac_size were parsed into the options map but
            // never handed to the interface, so a configured IFAC ran in the clear.
            ifacNetname = config.ifacNetname,
            ifacNetkey = config.ifacNetkey,
            ifacSizeBits = config.ifacSizeBits,
        ).also { applyIngressControlKnobs(it, config) }
    }

    /**
     * Apply the announce ingress-control knobs of an interface section. They were parsed
     * into the options map but never reached the interface, so an operator's tuning had
     * no effect and the limiter ran on its defaults.
     */
    internal fun applyIngressControlKnobs(iface: Interface, config: InterfaceConfig) {
        config.ingressControl?.let { iface.setIngressControl(it) }
        config.icNewTimeSeconds?.let { iface.icNewTimeMs = (it * 1000).toLong() }
        config.icBurstFreqNew?.let { iface.icBurstFreqNew = it }
        config.icBurstFreq?.let { iface.icBurstFreq = it }
        config.icBurstHoldSeconds?.let { iface.icBurstHoldMs = (it * 1000).toLong() }
        config.icBurstPenaltySeconds?.let { iface.icBurstPenaltyMs = (it * 1000).toLong() }
        config.icHeldReleaseIntervalSeconds?.let { iface.icHeldReleaseIntervalMs = (it * 1000).toLong() }
        config.icMaxHeldAnnounces?.let { iface.icMaxHeldAnnounces = it }
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
        ).also { applyIngressControlKnobs(it, config) }
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
}
