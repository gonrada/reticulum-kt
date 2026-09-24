package network.reticulum.config

import network.reticulum.common.InterfaceMode

/**
 * Parsing of Reticulum's INI-style configuration and the config-derived decisions
 * `Reticulum._synthesize_interface` makes when it builds an interface.
 *
 * The port configures interfaces programmatically, so it never needed to read a config
 * file. The reference does (rnsd reads one), and the bounds it applies while reading are
 * protocol-relevant: an under-minimum IFAC size shrinks the authentication tag below the
 * protocol floor, a sub-minimum bitrate mis-sizes MTU and timeout maths, an out-of-range
 * announce cap lets a node monopolise a slow link, and a sub-floor discovery interval lets
 * a discoverable node flood the network. Those rules are the parity surface, independent of
 * whether a given consumer happens to load its configuration from a file.
 *
 * Rules mirrored from RNS 1.5.2 `Reticulum.py`:
 *  - interface mode selection and aliases (`:770-790`)
 *  - `bitrate >= MINIMUM_BITRATE` or the configured value is discarded (`:944-946`)
 *  - `announce_cap` accepted only in (0, 100], stored as a fraction (`:862-864`)
 *  - `ifac_size` in BITS, accepted only at or above `IFAC_MIN_SIZE*8`, stored as BYTES
 *    (`:802-803`)
 *  - `discoverable` forces a discovery-capable mode, and the announce interval has a
 *    5-minute floor and a 6-hour default (`:901-935`)
 */
/**
 * Raised when `interface_mode` names a mode the reference resolves through the legacy
 * `mode` key, and that key is absent.
 *
 * This reproduces an upstream defect rather than working around it. `Reticulum.py:776-779`
 * handles `gateway` and `internal` by consulting `c["mode"]` from inside the
 * `interface_mode` branch, so `interface_mode = gateway` alone raises KeyError out of
 * ConfigObj and the interface never configures. The behaviour is unchanged in RNS 1.5.2.
 *
 * A config file is a portable artifact — the same file is copied between a python node and
 * a Kotlin one — so a config the reference rejects must not silently come up here with a
 * mode the operator never saw applied. This is confined to config synthesis: interfaces
 * built programmatically never reach it, so the defect is not inflicted on the library's
 * own API.
 */
class MissingModeKeyException(interfaceMode: String) : IllegalArgumentException(
    "interface_mode = $interfaceMode requires a 'mode' key: the reference resolves this " +
        "mode through c[\"mode\"] (Reticulum.py:776-779) and raises KeyError without it"
)

object InterfaceConfig {

    /** `Reticulum.MINIMUM_BITRATE` — a configured bitrate below this is discarded. */
    const val MINIMUM_BITRATE = 5

    /** `Reticulum.IFAC_MIN_SIZE` (bytes). Config supplies BITS, so the floor is this * 8. */
    const val IFAC_MIN_SIZE = 1

    /** `Reticulum.ANNOUNCE_CAP` as a percentage; the stored default is this / 100. */
    const val ANNOUNCE_CAP_PERCENT = 2.0

    /** Interface default when the config does not override it (`Interface.DEFAULT_IFAC_SIZE`). */
    const val DEFAULT_IFAC_SIZE = 16

    const val DISCOVERY_INTERVAL_FLOOR_SECONDS = 5 * 60
    const val DISCOVERY_INTERVAL_DEFAULT_SECONDS = 6 * 60 * 60

    // Ingress-control defaults, in SECONDS as the config expresses them
    // (RNS 1.5.2 Interface.py:72-83). rns-interfaces holds the same values in
    // milliseconds for runtime use.
    const val IC_MAX_HELD_ANNOUNCES = 256
    const val IC_BURST_HOLD = 15.0
    const val IC_BURST_FREQ_NEW = 3.0
    const val IC_BURST_FREQ = 10.0
    const val IC_NEW_TIME = (2 * 60 * 60).toDouble()
    const val IC_BURST_PENALTY = 15.0
    const val IC_HELD_RELEASE_INTERVAL = 5.0

    /** Python's numeric `Interface.MODE_*` values; our enum is ordered to match. */
    fun modeValue(mode: InterfaceMode): Int = when (mode) {
        InterfaceMode.FULL -> 0x01
        InterfaceMode.POINT_TO_POINT -> 0x02
        InterfaceMode.ACCESS_POINT -> 0x03
        InterfaceMode.ROAMING -> 0x04
        InterfaceMode.BOUNDARY -> 0x05
        InterfaceMode.GATEWAY -> 0x06
        InterfaceMode.INTERNAL -> 0x07
    }

    fun modeName(mode: InterfaceMode): String = when (mode) {
        InterfaceMode.FULL -> "MODE_FULL"
        InterfaceMode.POINT_TO_POINT -> "MODE_POINT_TO_POINT"
        InterfaceMode.ACCESS_POINT -> "MODE_ACCESS_POINT"
        InterfaceMode.ROAMING -> "MODE_ROAMING"
        InterfaceMode.BOUNDARY -> "MODE_BOUNDARY"
        InterfaceMode.GATEWAY -> "MODE_GATEWAY"
        InterfaceMode.INTERNAL -> "MODE_INTERNAL"
    }

    /**
     * The config-derived attributes of one interface. `configuredBitrate` is deliberately
     * separate from `bitrate`: the reference records the accepted config value and leaves
     * the interface's own default in place when the configured one is out of bounds.
     */
    data class Synthesized(
        val mode: InterfaceMode,
        val selectedInterfaceMode: Int,
        val configuredBitrate: Int?,
        val bitrate: Int,
        val announceCap: Double,
        val ifacSize: Int,
        val defaultIfacSize: Int,
        val ifacNetname: String?,
        val ifacNetkey: String?,
        val discoverable: Boolean,
        val discoveryAnnounceInterval: Int?,
        /** Ingress-control knobs: config overrides, else the Interface class defaults. */
        val icMaxHeldAnnounces: Int,
        val icBurstHold: Double,
        val icBurstFreqNew: Double,
        val icBurstFreq: Double,
        val icNewTime: Double,
        val icBurstPenalty: Double,
        val icHeldReleaseInterval: Double,
        /**
         * Whether announces learned on an INTERNAL interface may leave via this one
         * (python `announces_from_internal`, default true).
         */
        val announcesFromInternal: Boolean,
        /**
         * Whether announces arriving here may be carried onto an INTERNAL interface
         * (python `announces_to_internal`). Null means no explicit policy, which is NOT
         * the same as false — the reference tests `== True`, so only an explicit true
         * overrides an internal interface's refusal of boundary-sourced announces.
         */
        val announcesToInternal: Boolean?,
    ) {
        val ifacActive: Boolean get() = ifacNetname != null || ifacNetkey != null
    }

    /** RNode types take ACCESS_POINT rather than GATEWAY when discovery forces a mode. */
    private val RNODE_TYPES = setOf("RNodeInterface", "RNodeMultiInterface")

    /**
     * Parse a ConfigObj-style INI document into nested sections.
     *
     * Supports `[section]`, `[[subsection]]` (any nesting depth by bracket count),
     * `key = value`, `#` comments and blank lines, which is the subset Reticulum's config
     * files use. Indentation is cosmetic in ConfigObj and is ignored here too.
     */
    fun parseIni(text: String): Map<String, Any> {
        val root = LinkedHashMap<String, Any>()
        // Stack of open sections by depth; index 0 is the document root.
        val stack = ArrayList<MutableMap<String, Any>>()
        stack.add(root)

        for (rawLine in text.lines()) {
            val line = stripInlineComment(rawLine).trim()
            if (line.isEmpty()) continue

            if (line.startsWith("[")) {
                val depth = line.takeWhile { it == '[' }.length
                val name = line.trim('[', ']').trim()
                // A section at depth N hangs off the section at depth N-1.
                while (stack.size > depth) stack.removeAt(stack.size - 1)
                if (stack.size < depth) {
                    // Malformed (skipped a level); treat the nearest open section as parent.
                    while (stack.size < depth) stack.add(stack[stack.size - 1])
                }
                val parent = stack[depth - 1]
                @Suppress("UNCHECKED_CAST")
                val section = parent.getOrPut(name) { LinkedHashMap<String, Any>() } as MutableMap<String, Any>
                stack.add(section)
            } else {
                val idx = line.indexOf('=')
                if (idx <= 0) continue
                val key = line.substring(0, idx).trim()
                val value = line.substring(idx + 1).trim().trim('"', '\'')
                stack[stack.size - 1][key] = value
            }
        }
        return root
    }

    /** Look up `[interfaces] -> [[name]]` in a parsed document, or null if absent. */
    @Suppress("UNCHECKED_CAST")
    fun interfaceSection(parsed: Map<String, Any>, name: String): Map<String, String>? {
        val interfaces = parsed["interfaces"] as? Map<String, Any> ?: return null
        val section = interfaces[name] as? Map<String, Any> ?: return null
        return section.entries
            .filter { it.value is String }
            .associate { it.key to it.value as String }
    }

    /** ConfigObj's `as_bool`: true/yes/on/1 and false/no/off/0, case-insensitive. */
    /**
     * Drop an inline `# comment`, but not a `#` inside a quoted value: python's ConfigObj
     * treats `#` inside single or double quotes as part of the value.
     */
    fun stripInlineComment(line: String): String {
        var quote: Char? = null
        for ((i, c) in line.withIndex()) {
            when {
                quote != null -> if (c == quote) quote = null
                c == '"' || c == '\'' -> quote = c
                c == '#' -> return line.substring(0, i)
            }
        }
        return line
    }

    private fun asBool(v: String): Boolean = when (v.trim().lowercase()) {
        "true", "yes", "on", "1" -> true
        else -> false
    }

    /**
     * Apply every config-derived bound the reference applies, and report the result.
     *
     * Out-of-range values are DISCARDED rather than clamped — matching the reference, which
     * simply leaves the interface default in place — except the discovery announce interval,
     * which is clamped UP to its floor.
     */
    fun synthesize(
        section: Map<String, String>,
        interfaceDefaultBitrate: Int = 0,
        defaultIfacSize: Int = DEFAULT_IFAC_SIZE,
    ): Synthesized {
        val type = section["type"] ?: ""

        // Mode. `interface_mode` is the modern key and `mode` the legacy one; the modern
        // key takes precedence, since the reference only reaches the `mode` branch when
        // `interface_mode` is absent (Reticulum.py:762-796).
        //
        // The two branches are NOT the same table. The `interface_mode` branch handles
        // full/ap/ptp/roaming/boundary from its own key and then — this is an upstream
        // defect, live in 1.5.2 at Reticulum.py:776,778 — falls through to `c["mode"]`
        // for gateway and internal. With `interface_mode = gateway` and no `mode` key,
        // ConfigObj raises KeyError and the interface fails to configure. See
        // gatewayFallthrough below; reproducing it is deliberate.
        var mode = InterfaceMode.FULL
        val interfaceModeText = section["interface_mode"]?.lowercase()
        if (interfaceModeText != null) {
            when (interfaceModeText) {
                "full" -> mode = InterfaceMode.FULL
                "access_point", "accesspoint", "ap" -> mode = InterfaceMode.ACCESS_POINT
                "pointtopoint", "ptp" -> mode = InterfaceMode.POINT_TO_POINT
                "roaming" -> mode = InterfaceMode.ROAMING
                "boundary" -> mode = InterfaceMode.BOUNDARY
                else -> {
                    // Reticulum.py:776-779 reads c["mode"] here, un-lowercased.
                    val legacy = section["mode"] ?: throw MissingModeKeyException(interfaceModeText)
                    if (legacy == "gateway" || legacy == "gw") mode = InterfaceMode.GATEWAY
                    else if (legacy == "internal") mode = InterfaceMode.INTERNAL
                }
            }
        } else {
            when (section["mode"]?.lowercase()) {
                "full" -> mode = InterfaceMode.FULL
                "access_point", "accesspoint", "ap" -> mode = InterfaceMode.ACCESS_POINT
                "pointtopoint", "ptp" -> mode = InterfaceMode.POINT_TO_POINT
                "roaming" -> mode = InterfaceMode.ROAMING
                "boundary" -> mode = InterfaceMode.BOUNDARY
                "gateway", "gw" -> mode = InterfaceMode.GATEWAY
                "internal" -> mode = InterfaceMode.INTERNAL
            }
        }

        // bitrate: accepted only at or above the minimum; otherwise the configured value is
        // discarded and the interface keeps its own default (Reticulum.py:944-946).
        val configuredBitrate = section["bitrate"]?.trim()?.toIntOrNull()
            ?.takeIf { it >= MINIMUM_BITRATE }

        // announce_cap: percent in (0, 100], stored as a fraction (Reticulum.py:862-864).
        val announceCap = section["announce_cap"]?.trim()?.toDoubleOrNull()
            ?.takeIf { it > 0.0 && it <= 100.0 }
            ?.let { it / 100.0 }
            ?: (ANNOUNCE_CAP_PERCENT / 100.0)

        // ifac_size: config is BITS, storage is BYTES, floor IFAC_MIN_SIZE*8
        // (Reticulum.py:802-803).
        val ifacSize = section["ifac_size"]?.trim()?.toIntOrNull()
            ?.takeIf { it >= IFAC_MIN_SIZE * 8 }
            ?.let { it / 8 }
            ?: defaultIfacSize

        // An empty-string value resolves to unset, and both spellings feed one attribute
        // (Reticulum.py:805-812).
        // Both spellings feed one attribute, and the underscored form WINS when both are
        // present: python assigns from "networkname" first and then lets "network_name"
        // overwrite it (Reticulum.py:806-812). An empty string means unset, not empty.
        val ifacNetname = listOfNotNull(section["networkname"], section["network_name"])
            .lastOrNull { it.isNotEmpty() }
        val ifacNetkey = listOfNotNull(section["passphrase"], section["pass_phrase"])
            .lastOrNull { it.isNotEmpty() }

        // discoverable: interval floor/default, then mode promotion (Reticulum.py:901-935).
        var discoverable = false
        var discoveryAnnounceInterval: Int? = null
        if (section.containsKey("discoverable")) {
            discoverable = asBool(section.getValue("discoverable"))
            if (discoverable) {
                section["announce_interval"]?.trim()?.toIntOrNull()?.let { minutes ->
                    discoveryAnnounceInterval =
                        (minutes * 60).coerceAtLeast(DISCOVERY_INTERVAL_FLOOR_SECONDS)
                }
                if (discoveryAnnounceInterval == null) {
                    discoveryAnnounceInterval = DISCOVERY_INTERVAL_DEFAULT_SECONDS
                }
                // A discoverable interface that is not already relay-capable is promoted, so
                // it does not advertise itself for discovery while refusing to relay.
                // INTERNAL counts as relay-capable and is left alone (python Reticulum.py:928
                // lists it alongside GATEWAY and ACCESS_POINT): promoting it would discard the
                // very mode the operator asked for and push the segment's announces onto the
                // public mesh — the opposite of what declaring it internal was for.
                if (mode != InterfaceMode.GATEWAY &&
                    mode != InterfaceMode.ACCESS_POINT &&
                    mode != InterfaceMode.INTERNAL
                ) {
                    mode = if (type in RNODE_TYPES) InterfaceMode.ACCESS_POINT else InterfaceMode.GATEWAY
                }
            }
        }

        // Ingress control: each knob is overridden by config when present, otherwise the
        // Interface class constant stands (Reticulum.py:840-860, Interface.py:138-150).
        fun icInt(key: String, dflt: Int) = section[key]?.trim()?.toIntOrNull() ?: dflt
        fun icNum(key: String, dflt: Double) = section[key]?.trim()?.toDoubleOrNull() ?: dflt

        return Synthesized(
            mode = mode,
            selectedInterfaceMode = modeValue(mode),
            configuredBitrate = configuredBitrate,
            bitrate = configuredBitrate ?: interfaceDefaultBitrate,
            announceCap = announceCap,
            ifacSize = ifacSize,
            defaultIfacSize = defaultIfacSize,
            ifacNetname = ifacNetname,
            ifacNetkey = ifacNetkey,
            discoverable = discoverable,
            discoveryAnnounceInterval = discoveryAnnounceInterval,
            icMaxHeldAnnounces = icInt("ic_max_held_announces", IC_MAX_HELD_ANNOUNCES),
            icBurstHold = icNum("ic_burst_hold", IC_BURST_HOLD),
            icBurstFreqNew = icNum("ic_burst_freq_new", IC_BURST_FREQ_NEW),
            icBurstFreq = icNum("ic_burst_freq", IC_BURST_FREQ),
            icNewTime = icNum("ic_new_time", IC_NEW_TIME),
            icBurstPenalty = icNum("ic_burst_penalty", IC_BURST_PENALTY),
            icHeldReleaseInterval = icNum("ic_held_release_interval", IC_HELD_RELEASE_INTERVAL),
            announcesFromInternal = section["announces_from_internal"]?.let { asBool(it) } ?: true,
            announcesToInternal = section["announces_to_internal"]?.let { asBool(it) },
        )
    }
}
