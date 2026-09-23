package network.reticulum.cli.config

/**
 * Configuration data classes matching Python RNS config structure.
 *
 * Configuration is read from ~/.reticulum/config (ConfigObj/INI format).
 */

/**
 * Top-level configuration container.
 */
data class ReticulumConfig(
    val reticulum: ReticulumSection = ReticulumSection(),
    val logging: LoggingSection = LoggingSection(),
    val interfaces: Map<String, InterfaceConfig> = emptyMap()
)

/**
 * [reticulum] section configuration.
 */
data class ReticulumSection(
    val enableTransport: Boolean = false,
    val shareInstance: Boolean = true,
    val instanceName: String = "default",
    val sharedInstancePort: Int = 37428,
    val instanceControlPort: Int = 37429,
    val sharedInstanceType: String? = null,
    val panicOnInterfaceError: Boolean = false,
    val enableRemoteManagement: Boolean = false,
    val remoteManagementAllowed: List<String> = emptyList(),
    val respondToProbes: Boolean = false,
    val linkMtuDiscovery: Boolean = true
)

/**
 * [logging] section configuration.
 */
data class LoggingSection(
    val loglevel: Int = 4  // LOG_INFO is default
)

/**
 * Interface configuration from [[interface_name]] subsection.
 */
data class InterfaceConfig(
    val name: String,
    val type: String,
    val enabled: Boolean = true,
    val options: Map<String, Any> = emptyMap()
) {
    // Common interface options
    val targetHost: String? get() = options["target_host"] as? String
    val targetPort: Int? get() = (options["target_port"] as? Number)?.toInt()
    val listenIp: String? get() = options["listen_ip"] as? String
    val listenPort: Int? get() = (options["listen_port"] as? Number)?.toInt()
    val mode: Int? get() = (options["selected_interface_mode"] as? Number)?.toInt()
    val bitrate: Int? get() = (options["configured_bitrate"] as? Number)?.toInt()
    val maxReconnectTries: Int?
        get() {
            val value = options["max_reconnect_tries"] ?: return null
            return when (value) {
                is Byte -> value.toInt()
                is Short -> value.toInt()
                is Int -> value
                is Long -> value.takeIf { it in Int.MIN_VALUE..Int.MAX_VALUE }?.toInt()
                is String -> value.toPythonDecimalIntOrNull()
                else -> null
            } ?: throw IllegalArgumentException("max_reconnect_tries must be a 32-bit integer")
        }

    // IFAC. Both spellings feed one attribute and the underscored form wins when both
    // are present: python assigns from "networkname" then lets "network_name" overwrite
    // it (Reticulum.py:805-812). An empty string means unset, not an empty name.
    val ifacNetname: String? get() = ifacCredential("networkname", "network_name")
    val ifacNetkey: String? get() = ifacCredential("passphrase", "pass_phrase")

    /**
     * Configured `ifac_size` in BITS as the config expresses it, or null when unset.
     * The interface applies python's floor rule (below IFAC_MIN_SIZE*8 falls back to
     * the class default, Reticulum.py:802-803).
     */
    val ifacSizeBits: Int?
        get() = when (val v = options["ifac_size"]) {
            is Number -> v.toInt()
            is String -> v.trim().toIntOrNull()
            else -> null
        }

    private fun ifacCredential(vararg keys: String): String? =
        keys.mapNotNull { options[it]?.toString() }.lastOrNull { it.isNotEmpty() }

    // AutoInterface options
    // Announce ingress-control knobs (python Reticulum.py: ingress_control, ic_*). Times
    // are seconds in the file; the interface fields take milliseconds.
    val ingressControl: Boolean? get() = when (val v = options["ingress_control"]) {
        is Boolean -> v
        is String -> v.trim().lowercase() in setOf("yes", "true", "on", "1")
        else -> null
    }
    val icNewTimeSeconds: Double? get() = optDouble("ic_new_time")
    val icBurstFreqNew: Double? get() = optDouble("ic_burst_freq_new")
    val icBurstFreq: Double? get() = optDouble("ic_burst_freq")
    val icBurstHoldSeconds: Double? get() = optDouble("ic_burst_hold")
    val icBurstPenaltySeconds: Double? get() = optDouble("ic_burst_penalty")
    val icHeldReleaseIntervalSeconds: Double? get() = optDouble("ic_held_release_interval")
    val icMaxHeldAnnounces: Int? get() = optDouble("ic_max_held_announces")?.toInt()

    private fun optDouble(key: String): Double? = when (val v = options[key]) {
        is Number -> v.toDouble()
        is String -> v.trim().toDoubleOrNull()
        else -> null
    }

    val groupId: String? get() = options["group_id"] as? String
    val discoveryPort: Int? get() = (options["discovery_port"] as? Number)?.toInt()
    val dataPort: Int? get() = (options["data_port"] as? Number)?.toInt()
    val discoveryScope: String? get() = options["discovery_scope"] as? String

    @Suppress("UNCHECKED_CAST")
    val devices: List<String>? get() = when (val d = options["devices"]) {
        is List<*> -> d as? List<String>
        is String -> d.split(",").map { it.trim() }.filter { it.isNotEmpty() }
        else -> null
    }

    @Suppress("UNCHECKED_CAST")
    val ignoredDevices: List<String>? get() = when (val d = options["ignored_devices"]) {
        is List<*> -> d as? List<String>
        is String -> d.split(",").map { it.trim() }.filter { it.isNotEmpty() }
        else -> null
    }
}

private fun String.toPythonDecimalIntOrNull(): Int? {
    val value = trim()
    if (value.isEmpty()) return null

    val normalized = StringBuilder(value.length)
    var index = 0
    if (value.first() == '+' || value.first() == '-') {
        normalized.append(value.first())
        index++
        if (index == value.length) return null
    }

    var previousWasDigit = false
    while (index < value.length) {
        val codePoint = value.codePointAt(index)
        val nextIndex = index + Character.charCount(codePoint)
        if (codePoint == '_'.code) {
            if (
                !previousWasDigit ||
                nextIndex >= value.length ||
                !value.codePointAt(nextIndex).isPythonDecimalDigit()
            ) {
                return null
            }
            previousWasDigit = false
        } else {
            if (!codePoint.isPythonDecimalDigit()) return null
            normalized.append(Character.digit(codePoint, 10))
            previousWasDigit = true
        }
        index = nextIndex
    }

    return normalized.toString().toIntOrNull()
}

private fun Int.isPythonDecimalDigit(): Boolean =
    Character.getType(this) == Character.DECIMAL_DIGIT_NUMBER.toInt()

/**
 * Supported interface types.
 */
enum class InterfaceType(val configName: String) {
    TCP_CLIENT("TCPClientInterface"),
    TCP_SERVER("TCPServerInterface"),
    UDP("UDPInterface"),
    AUTO("AutoInterface"),
    RNODE("RNodeInterface"),
    KISS("KISSInterface"),
    AX25_KISS("AX25KISSInterface"),
    I2P("I2PInterface"),
    BLE("BLEInterface"),
    UNKNOWN("Unknown");

    companion object {
        fun fromConfigName(name: String): InterfaceType {
            return entries.find { it.configName.equals(name, ignoreCase = true) } ?: UNKNOWN
        }
    }
}
