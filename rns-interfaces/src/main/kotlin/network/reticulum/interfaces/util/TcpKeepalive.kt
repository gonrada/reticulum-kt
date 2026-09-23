package network.reticulum.interfaces.util

import java.net.Socket
import java.net.SocketOption
import java.net.StandardSocketOptions
import java.nio.channels.SocketChannel

/**
 * TCP dead-peer detection, mirroring python `TCPClientInterface.set_timeouts_linux`
 * (RNS/Interfaces/TCPInterface.py:183-197): `SO_KEEPALIVE` on, first probe after
 * [TCP_PROBE_AFTER] s of idle, then every [TCP_PROBE_INTERVAL] s, giving up after
 * [TCP_PROBES] probes — a peer that vanishes without FIN is detected in ~30 s instead of
 * the OS default (~2 h on Linux), so it cannot hold a server slot forever.
 *
 * The idle/interval/count knobs live in `jdk.net.ExtendedSocketOptions` (JDK 11+), which
 * does not exist on Android and is unsupported on some platforms, so they are resolved by
 * reflection and every set is best-effort: unavailable means "leave the OS default", never
 * an error. Python's `TCP_USER_TIMEOUT` has no JDK equivalent and is not applied.
 */
internal object TcpKeepalive {
    /** Idle seconds before the first keepalive probe (python TCP_PROBE_AFTER). */
    const val TCP_PROBE_AFTER = 5

    /** Seconds between keepalive probes (python TCP_PROBE_INTERVAL). */
    const val TCP_PROBE_INTERVAL = 2

    /** Unanswered probes before the connection is dropped (python TCP_PROBES). */
    const val TCP_PROBES = 12

    private const val EXTENDED_OPTIONS_CLASS = "jdk.net.ExtendedSocketOptions"

    /**
     * `TCP_KEEPIDLE` / `TCP_KEEPINTERVAL` / `TCP_KEEPCOUNT` resolved reflectively, keyed by
     * name; empty where the class is absent (Android) or the fields are missing.
     */
    private val extendedOptions: Map<String, SocketOption<Int>> by lazy {
        try {
            val cls = Class.forName(EXTENDED_OPTIONS_CLASS)
            listOf("TCP_KEEPIDLE", "TCP_KEEPINTERVAL", "TCP_KEEPCOUNT").mapNotNull { fieldName ->
                try {
                    @Suppress("UNCHECKED_CAST")
                    val option = cls.getField(fieldName).get(null) as? SocketOption<Int>
                    option?.let { fieldName to it }
                } catch (_: Throwable) {
                    null
                }
            }.toMap()
        } catch (_: Throwable) {
            emptyMap()
        }
    }

    /** Whether this runtime exposes the extended keepalive options at all. */
    val extendedOptionsAvailable: Boolean
        get() = extendedOptions.isNotEmpty()

    /**
     * Enable keepalive with Python's probe timing on a connected [Socket].
     *
     * @return the number of extended options (idle/interval/count) actually applied; 0 when
     *   the runtime does not support them. `SO_KEEPALIVE` itself is set regardless.
     */
    fun apply(
        socket: Socket,
        probeAfter: Int = TCP_PROBE_AFTER,
        probeInterval: Int = TCP_PROBE_INTERVAL,
        probes: Int = TCP_PROBES,
    ): Int {
        try { socket.keepAlive = true } catch (_: Throwable) {}
        return applyExtended(probeAfter, probeInterval, probes) { option, value ->
            socket.setOption(option, value)
        }
    }

    /**
     * Enable keepalive with Python's probe timing on a connected [SocketChannel].
     *
     * @return the number of extended options (idle/interval/count) actually applied.
     */
    fun apply(
        channel: SocketChannel,
        probeAfter: Int = TCP_PROBE_AFTER,
        probeInterval: Int = TCP_PROBE_INTERVAL,
        probes: Int = TCP_PROBES,
    ): Int {
        try { channel.setOption(StandardSocketOptions.SO_KEEPALIVE, true) } catch (_: Throwable) {}
        return applyExtended(probeAfter, probeInterval, probes) { option, value ->
            channel.setOption(option, value)
        }
    }

    private inline fun applyExtended(
        probeAfter: Int,
        probeInterval: Int,
        probes: Int,
        set: (SocketOption<Int>, Int) -> Unit,
    ): Int {
        val options = extendedOptions
        if (options.isEmpty()) return 0
        var applied = 0
        val wanted = listOf(
            "TCP_KEEPIDLE" to probeAfter,
            "TCP_KEEPINTERVAL" to probeInterval,
            "TCP_KEEPCOUNT" to probes,
        )
        for ((name, value) in wanted) {
            val option = options[name] ?: continue
            try {
                set(option, value)
                applied++
            } catch (_: Throwable) {
                // UnsupportedOperationException / IOException on platforms or runtimes
                // without this option: keep the OS default.
            }
        }
        return applied
    }
}
