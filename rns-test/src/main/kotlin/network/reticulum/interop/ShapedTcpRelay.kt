package network.reticulum.interop

import java.io.Closeable
import java.io.IOException
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.LinkedBlockingQueue

/**
 * A slow link for the interop rig: one-way delay and a byte rate, both directions.
 *
 * Every test link in the rig is loopback with a millisecond RTT, so a timing defect
 * that needs seconds to appear never does. The one that motivated this (a request
 * budget applied to a response resource still in flight) took a Tor link and a
 * file download to surface. [oneWayDelayMs] sets the RTT (twice the delay plus
 * serialisation) and [bitrateBps] bounds the throughput, so a transfer takes a
 * predictable number of seconds on any host.
 */
data class LinkShaping(
    val oneWayDelayMs: Long,
    val bitrateBps: Long,
) {
    init {
        require(oneWayDelayMs >= 0) { "oneWayDelayMs must be >= 0" }
        require(bitrateBps > 0) { "bitrateBps must be > 0" }
    }

    /** Milliseconds to serialise [bytes] at [bitrateBps]. */
    fun txTimeMs(bytes: Int): Long = bytes * 8_000L / bitrateBps
}

/**
 * A loopback TCP relay that applies [LinkShaping] to every byte in both directions.
 * The Kotlin `TCPClientInterface` connects to [port]; the relay connects onward to
 * `targetHost:targetPort` (the Python peer) and pumps bytes through a delay line
 * with rate pacing. Chunks are held for the one-way delay, then released no faster
 * than the bitrate allows; ordering within a direction is preserved.
 */
class ShapedTcpRelay(
    private val targetHost: String,
    private val targetPort: Int,
    private val shaping: LinkShaping,
    private val chunkSize: Int = 4096,
) : Closeable {
    private val server = ServerSocket(0, 4, InetAddress.getLoopbackAddress())
    private val sockets = CopyOnWriteArrayList<Socket>()
    private val threads = CopyOnWriteArrayList<Thread>()

    @Volatile
    private var running = false

    /** The port the shaped side listens on; connect the interface under test here. */
    val port: Int get() = server.localPort

    fun start() {
        running = true
        spawn("shaped-relay-accept") {
            while (running) {
                val client =
                    try {
                        server.accept()
                    } catch (e: IOException) {
                        break
                    }
                val upstream =
                    try {
                        Socket(targetHost, targetPort)
                    } catch (e: IOException) {
                        client.close()
                        continue
                    }
                client.tcpNoDelay = true
                upstream.tcpNoDelay = true
                sockets.add(client)
                sockets.add(upstream)
                pump("shaped-relay-up", client, upstream)
                pump("shaped-relay-down", upstream, client)
            }
        }
    }

    /** One direction: reader thread stamps chunks with their release time, writer thread paces them out. */
    private fun pump(
        name: String,
        from: Socket,
        to: Socket,
    ) {
        val queue = LinkedBlockingQueue<Pair<Long, ByteArray>>()
        val eof = ByteArray(0)
        spawn("$name-read") {
            val input = from.getInputStream()
            val buf = ByteArray(chunkSize)
            try {
                while (running) {
                    val n = input.read(buf)
                    if (n < 0) break
                    if (n == 0) continue
                    queue.put(Pair(System.currentTimeMillis() + shaping.oneWayDelayMs, buf.copyOf(n)))
                }
            } catch (e: IOException) {
                // socket closed; fall through to EOF
            }
            queue.put(Pair(0L, eof))
        }
        spawn("$name-write") {
            val output = to.getOutputStream()
            var nextFree = 0L
            try {
                while (running) {
                    val (releaseAt, chunk) = queue.take()
                    if (chunk === eof) {
                        try {
                            to.shutdownOutput()
                        } catch (e: IOException) {
                            // already closed
                        }
                        break
                    }
                    val sendAt = maxOf(releaseAt, nextFree)
                    val wait = sendAt - System.currentTimeMillis()
                    if (wait > 0) Thread.sleep(wait)
                    output.write(chunk)
                    output.flush()
                    nextFree = maxOf(sendAt, System.currentTimeMillis()) + shaping.txTimeMs(chunk.size)
                }
            } catch (e: IOException) {
                // peer gone
            } catch (e: InterruptedException) {
                // closing
            }
        }
    }

    private fun spawn(
        name: String,
        body: () -> Unit,
    ) {
        val t = Thread(body, name)
        t.isDaemon = true
        threads.add(t)
        t.start()
    }

    override fun close() {
        running = false
        try {
            server.close()
        } catch (e: IOException) {
            // ignore
        }
        for (s in sockets) {
            try {
                s.close()
            } catch (e: IOException) {
                // ignore
            }
        }
        for (t in threads) {
            t.interrupt()
        }
        for (t in threads) {
            t.join(2_000)
        }
    }
}
