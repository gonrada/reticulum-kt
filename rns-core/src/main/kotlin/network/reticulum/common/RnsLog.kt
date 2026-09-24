package network.reticulum.common

import java.time.LocalDateTime
import java.time.format.DateTimeFormatter

/**
 * Central leveled logger.
 *
 * Replaces the per-file `println(LocalDateTime.now().format(DateTimeFormatter.ofPattern(...)))`
 * pattern, which on every call (a) re-parsed the formatter pattern, (b) built the interpolated
 * message eagerly even when nothing would consume it, and (c) wrote to the process-global
 * synchronized System.out — a fixed per-packet cost with no way to turn it down.
 *
 * Levels mirror Python RNS (RNS/__init__.py). The default level is [INFO], matching Python's
 * default: CRITICAL/ERROR/WARNING/NOTICE/INFO print, and the per-packet trace lines — logged at
 * [DEBUG]/[EXTREME] — are silent unless the level is raised. Override the default with the
 * `RNS_LOGLEVEL` environment variable (0..7) or by setting [level] at runtime.
 *
 * Use the lazy [log] overload (`RnsLog.log(DEBUG, tag) { "..." }`) on hot paths so the message
 * string is never built when the level is gated off. The eager overload exists for migrating
 * existing call sites that already hold a built string.
 */
object RnsLog {
    const val CRITICAL = 0
    const val ERROR = 1
    const val WARNING = 2
    const val NOTICE = 3
    const val INFO = 4
    const val VERBOSE = 5
    const val DEBUG = 6
    const val EXTREME = 7

    /** Active threshold; a message at `msgLevel <= level` is emitted. Defaults to [INFO]. */
    @Volatile
    var level: Int =
        System.getenv("RNS_LOGLEVEL")?.trim()?.toIntOrNull()?.coerceIn(CRITICAL, EXTREME) ?: INFO

    private val formatter: DateTimeFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS")

    /**
     * Optional file sink. When `RNS_LOG_FILE` is set, log lines go there (append, autoflush)
     * instead of stdout — useful on headless/embedded hosts, and where stdout is a data or
     * IPC stream (e.g. the conformance pipe-peer, whose stdout the harness discards).
     */
    private val fileSink: java.io.PrintStream? by lazy {
        System.getenv("RNS_LOG_FILE")?.trim()?.takeIf { it.isNotEmpty() }?.let { path ->
            try {
                java.io.PrintStream(java.io.FileOutputStream(path, true), true)
            } catch (e: Exception) {
                null
            }
        }
    }

    /** Whether a message at [msgLevel] would currently be emitted. */
    fun isEnabled(msgLevel: Int): Boolean = msgLevel <= level

    /** Lazy: [msg] is invoked only when [msgLevel] is enabled — no string built otherwise. */
    inline fun log(msgLevel: Int, tag: String, msg: () -> String) {
        if (msgLevel <= level) emit(tag, msg())
    }

    /** Eager overload for call sites that already hold a built message string. */
    fun log(msgLevel: Int, tag: String, message: String) {
        if (msgLevel <= level) emit(tag, message)
    }

    @PublishedApi
    internal fun emit(tag: String, message: String) {
        val ts = LocalDateTime.now().format(formatter)
        val line = "[$ts] [$tag] $message"
        val sink = fileSink
        if (sink != null) sink.println(line) else println(line)
    }
}
