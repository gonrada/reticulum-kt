package network.reticulum.bench

import network.reticulum.common.ByteArrayKey
import network.reticulum.common.DestinationDirection
import network.reticulum.common.DestinationType
import network.reticulum.common.InterfaceMode
import network.reticulum.common.RnsConstants
import network.reticulum.common.toKey
import network.reticulum.destination.Destination
import network.reticulum.identity.Identity
import network.reticulum.packet.Packet
import network.reticulum.transport.InterfaceRef
import network.reticulum.transport.Transport
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Test
import java.io.OutputStream
import java.io.PrintStream
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter
import java.util.concurrent.ConcurrentHashMap

/**
 * Baseline harness for the hot-path performance work. NOT a
 * correctness test and NOT part of normal CI — it self-skips unless run with -Dbench=on.
 * Measures ns/op and bytes-allocated/op for the real hot paths, and A/Bs the plan's
 * Tier-1 hypotheses inline (current code path vs the proposed alternative) so the numbers
 * are apples-to-apples in one JVM. No production code is touched.
 *
 *   run: :rns-core:test --tests network.reticulum.bench.HotPathBench -Dbench=on
 */
class HotPathBench {

    private val threadMx =
        java.lang.management.ManagementFactory.getThreadMXBean() as com.sun.management.ThreadMXBean

    private fun allocBytes(): Long = threadMx.getThreadAllocatedBytes(Thread.currentThread().threadId())

    private data class Result(val name: String, val nsPerOp: Double, val bytesPerOp: Long)

    private val results = mutableListOf<Result>()

    /** Warm up, then time [iters] iterations; record ns/op and bytes/op. Blackhole via sink. */
    private inline fun bench(name: String, warmup: Int, iters: Int, block: (Int) -> Any?) {
        var sink = 0
        for (i in 0 until warmup) sink = sink xor (block(i)?.hashCode() ?: 0)
        System.gc(); Thread.sleep(50)
        val a0 = allocBytes()
        val t0 = System.nanoTime()
        for (i in 0 until iters) sink = sink xor (block(i)?.hashCode() ?: 0)
        val t1 = System.nanoTime()
        val a1 = allocBytes()
        blackhole = sink
        results += Result(name, (t1 - t0).toDouble() / iters, (a1 - a0) / iters)
    }

    @Volatile private var blackhole: Int = 0

    private val nullOut = PrintStream(object : OutputStream() {
        override fun write(b: Int) {}
        override fun write(b: ByteArray, off: Int, len: Int) {}
    })

    // ---- a memoized-hash key, the item-4 proposal, for A/B against ByteArrayKey ----
    private class MemoKey(val bytes: ByteArray) {
        private val hash = bytes.contentHashCode()
        override fun hashCode() = hash
        override fun equals(other: Any?) = other is MemoKey && bytes.contentEquals(other.bytes)
    }

    @Test
    fun hotPaths() {
        assumeTrue(System.getProperty("bench") == "on", "perf harness; run with -Dbench=on")

        val realOut = System.out
        try {
            System.setOut(nullOut) // silence Transport's per-packet logging during timed regions

            benchLogging()
            benchByteArrayKey()
            benchDestinationLookup()
            benchPacket()
            benchInboundAndValidate()
        } finally {
            System.setOut(realOut)
        }
        report(realOut)
    }

    // 1 — logging fixed cost (item 1). current pattern vs cached formatter vs gated no-op.
    private fun benchLogging() {
        val destHash = ByteArray(RnsConstants.TRUNCATED_HASH_BYTES) { it.toByte() }
        val cachedFmt = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS")
        val level = 3 // pretend the gate sits above DEBUG

        // exactly what every private log() does today: re-parse pattern + now() + interpolate + write
        bench("log/current (ofPattern+now+interp+write)", 5_000, 50_000) {
            val ts = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS"))
            nullOut.println("[$ts] [Transport] Skipping announce for local destination ${hex(destHash)}")
            ts
        }
        // same, but the formatter is a constant (isolates the per-call ofPattern parse)
        bench("log/cached-formatter (now+interp+write)", 5_000, 50_000) {
            val ts = LocalDateTime.now().format(cachedFmt)
            nullOut.println("[$ts] [Transport] Skipping announce for local destination ${hex(destHash)}")
            ts
        }
        // the proposal: level gate with a lazy message that is never built when gated off
        bench("log/gated-lazy (no message built)", 5_000, 50_000) {
            if (level >= 6) { // DEBUG threshold, never true here
                val ts = LocalDateTime.now().format(cachedFmt)
                nullOut.println("[$ts] [Transport] Skipping announce for local destination ${hex(destHash)}")
            }
            it
        }
    }

    // 4 — ByteArrayKey put+get vs a hash-memoized key.
    private fun benchByteArrayKey() {
        val keys = Array(1024) { i -> ByteArray(16) { (i + it).toByte() } }
        val bak = ConcurrentHashMap<ByteArrayKey, Int>().apply { keys.forEachIndexed { i, k -> put(k.toKey(), i) } }
        val memo = ConcurrentHashMap<MemoKey, Int>().apply { keys.forEachIndexed { i, k -> put(MemoKey(k), i) } }

        bench("key/ByteArrayKey get (recompute hash)", 10_000, 200_000) { bak[keys[it and 1023].toKey()] }
        bench("key/MemoKey get (cached hash)", 10_000, 200_000) { memo[MemoKey(keys[it and 1023])] }
    }

    // 3 — isLocalDestination: linear scan over CopyOnWriteArrayList vs an index map.
    private fun benchDestinationLookup() {
        for (n in intArrayOf(1, 8, 64)) {
            val dests = (0 until n).map {
                Destination.create(Identity.create(), DestinationDirection.IN, DestinationType.SINGLE, "bench$it", "x")
            }
            val list = java.util.concurrent.CopyOnWriteArrayList(dests)
            val index = ConcurrentHashMap<ByteArrayKey, Destination>().apply { dests.forEach { put(it.hash.toKey(), it) } }
            val target = dests.last().hash // worst case for the scan: last element
            bench("dest/linear-scan n=$n", 20_000, 200_000) { list.any { d -> d.hash.contentEquals(target) } }
            bench("dest/index-lookup n=$n", 20_000, 200_000) { index.containsKey(target.toKey()) }
        }
    }

    // 5 — packet pack/hash allocation.
    private fun benchPacket() {
        val dest = Destination.create(Identity.create(), DestinationDirection.IN, DestinationType.SINGLE, "packbench", "x")
        val announce = Packet.createAnnounce(dest)!!
        announce.pack()
        bench("packet/getHashablePart", 10_000, 200_000) { announce.getHashablePart() }
        bench("packet/getHash (recompute fullHash)", 10_000, 100_000) { announce.getHash() }
        bench("packet/pack", 10_000, 100_000) { announce.pack() }
    }

    // end-to-end references: inbound dedup-hit path (framework overhead) + validateAnnounce (crypto floor).
    private fun benchInboundAndValidate() {
        try { Transport.stop() } catch (_: Exception) {}
        Transport.start(Identity.create(), enableTransport = false)
        val iface = BenchIface("bench-${System.nanoTime()}")
        Transport.registerInterface(iface)
        try {
            val dest = Destination.create(Identity.create(), DestinationDirection.IN, DestinationType.SINGLE, "inbench", "x")
            Transport.registerDestination(dest)
            val announce = Packet.createAnnounce(dest)!!
            val raw = announce.raw ?: announce.pack()

            // inbound() is a queue put by default (RNS 1.5.2 semantics). This measures the
            // processing path, so run it synchronously; queued, the loop would only time the
            // enqueue and then overflow the 1024-deep data queue.
            Transport.useInboundQueue = false
            try {
                Transport.inbound(raw, iface)      // first pass populates dedup; subsequent are hits
                bench("transport/inbound dedup-hit", 2_000, 30_000) { Transport.inbound(raw, iface); it }
            } finally {
                Transport.useInboundQueue = true
            }

            bench("identity/validateAnnounce (crypto)", 500, 5_000) { Identity.validateAnnounce(announce) }
        } finally {
            try { Transport.deregisterInterface(iface) } catch (_: Exception) {}
            try { Transport.stop() } catch (_: Exception) {}
        }
    }

    private fun hex(b: ByteArray): String {
        val sb = StringBuilder(b.size * 2)
        for (x in b) { val v = x.toInt() and 0xFF; sb.append("0123456789abcdef"[v ushr 4]); sb.append("0123456789abcdef"[v and 0xF]) }
        return sb.toString()
    }

    private fun report(out: PrintStream) {
        val sb = StringBuilder()
        sb.appendLine()
        sb.appendLine("==================== HotPathBench (Step-0 baseline) ====================")
        sb.appendLine(String.format("%-44s %14s %14s", "path", "ns/op", "bytes/op"))
        sb.appendLine("-".repeat(74))
        for (r in results) sb.appendLine(String.format("%-44s %14.1f %14d", r.name, r.nsPerOp, r.bytesPerOp))
        sb.appendLine("=".repeat(74))
        out.println(sb)
        // Also persist so Gradle's test-stdout capture can't hide it.
        val path = System.getProperty("bench.out") ?: "build/hotpath-bench.txt"
        runCatching { java.io.File(path).apply { parentFile?.mkdirs() }.writeText(sb.toString()) }
    }

    private class BenchIface(override val name: String) : InterfaceRef {
        override val hash = ByteArray(RnsConstants.TRUNCATED_HASH_BYTES) { 0xBB.toByte() }
        override val canSend = true
        override val canReceive = true
        override val online = true
        override val mode = InterfaceMode.FULL
        override val bitrate = 1_000_000
        override val hwMtu = RnsConstants.MTU
        override var tunnelId: ByteArray? = null
        override var wantsTunnel = false
        override fun send(data: ByteArray) = Unit
    }
}
