package network.reticulum.interfaces.kiss

import network.reticulum.common.RnsLog
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.util.concurrent.atomic.AtomicInteger
import kotlin.concurrent.thread

/**
 * A [KissSerialPort] backed by an [InputStream]/[OutputStream] pair — the adapter
 * the Bluetooth-Classic (RFCOMM) and USB-serial (CDC) KISS variants use to drive
 * [KissInterface] over their platform streams.
 *
 * [connect] is a factory the interface calls on each (re)connect: it opens the
 * transport and returns its streams, or null on failure. Keeping the streams
 * behind a factory lets the interface's reconnect loop re-establish the link, and
 * lets tests supply in-memory piped streams — so this adapter and the KISS core
 * are verifiable without radio hardware.
 *
 * ## Liveness
 *
 * Each open session runs its own reader thread that sits in a blocking
 * [InputStream.read]. That is the only call through which a stream reports that
 * the link behind it is gone: end-of-stream (-1) or an I/O error. Bytes it reads go
 * into a bounded buffer that the non-blocking [read] drains, so [KissInterface]'s
 * polling loop keeps its contract.
 *
 * The previous shape gated a read on [InputStream.available] and only inspected
 * liveness inside that branch. On a dead Android RFCOMM link `available()` returns
 * 0 forever and never throws, so the port stayed open, the interface stayed online,
 * and a radio that had been powered off for eight minutes was indistinguishable
 * from an idle one (observed on an Android phone paired with a KISS radio over SPP). The reference
 * never had this problem because pyserial's read blocks. Now it is the reader
 * thread, not the caller, that observes the link drop; [read] returning empty means
 * exactly "no data right now" and [isOpen] means exactly "the link is up".
 *
 * How soon a drop is observed is up to the OS: for RFCOMM it is the Bluetooth
 * stack's link-supervision timeout, typically several seconds, the same as any
 * blocking reader gets.
 */
class StreamKissSerialPort(
    // onClose first so `connect` stays the last parameter and trailing-lambda
    // construction (StreamKissSerialPort { ... }) still binds to it.
    private val onClose: (() -> Unit)? = null,
    private val connect: suspend () -> Pair<InputStream, OutputStream>?,
) : KissSerialPort {

    @Volatile private var input: InputStream? = null
    @Volatile private var output: OutputStream? = null
    @Volatile private var openFlag = false

    /** Bytes the reader thread has taken off the stream and [read] has not yet drained. */
    private val pending = ByteArrayOutputStream()
    private val pendingLock = Any()

    /**
     * Session counter. A reader thread belongs to the session it was started in and
     * may only mark that session closed: a thread from a previous session, still
     * unblocking after a reconnect, must not close the new one.
     */
    private val session = AtomicInteger(0)

    override val isOpen: Boolean
        get() = openFlag && input != null

    override suspend fun open(): Boolean {
        val streams = try {
            connect()
        } catch (e: Exception) {
            null
        } ?: return false
        val mySession = session.incrementAndGet()
        synchronized(pendingLock) { pending.reset() }
        input = streams.first
        output = streams.second
        openFlag = true
        thread(name = "KissSerialPort-reader-$mySession", isDaemon = true) {
            readerLoop(streams.first, mySession)
        }
        return true
    }

    private fun readerLoop(stream: InputStream, mySession: Int) {
        val buf = ByteArray(READ_CHUNK)
        try {
            while (session.get() == mySession) {
                val n = stream.read(buf) // blocks; -1 at end of stream; throws when the link is gone
                if (n < 0) break
                if (n == 0) continue
                synchronized(pendingLock) {
                    if (pending.size() + n > MAX_PENDING) {
                        // The consumer has not drained in a very long time (or a peer is
                        // flooding a link the interface is not reading). Drop what is
                        // buffered rather than grow; the deframer resyncs on the next FEND.
                        RnsLog.log(RnsLog.DEBUG, "StreamKissSerialPort") {
                            "dropping ${pending.size()} undrained bytes (buffer over $MAX_PENDING)"
                        }
                        pending.reset()
                    }
                    pending.write(buf, 0, n)
                }
            }
        } catch (e: Exception) {
            // End of the line for this session: the stream reported the link gone.
        }
        // Only the session this thread belongs to. After close() or a reconnect the
        // counter has moved on and this thread's verdict is stale.
        if (session.get() == mySession) openFlag = false
    }

    override fun read(): ByteArray {
        if (input == null) return ByteArray(0)
        return synchronized(pendingLock) {
            if (pending.size() == 0) {
                ByteArray(0)
            } else {
                val out = pending.toByteArray()
                pending.reset()
                out
            }
        }
    }

    override fun write(bytes: ByteArray): Int {
        val o = output ?: return -1
        return try {
            o.write(bytes)
            o.flush()
            bytes.size
        } catch (e: Exception) {
            openFlag = false
            -1
        }
    }

    override fun close() {
        // Retire the session first so the reader thread, once it unblocks, does not
        // touch state that may already belong to the next open().
        session.incrementAndGet()
        openFlag = false
        try {
            input?.close()
        } catch (_: Exception) {
        }
        try {
            output?.close()
        } catch (_: Exception) {
        }
        input = null
        output = null
        // Extra teardown for transports whose socket isn't closed by closing the
        // streams alone (e.g. an RFCOMM SppConnection's own close lambda). On
        // Android this is also what unblocks a reader parked in socket read().
        try {
            onClose?.invoke()
        } catch (_: Exception) {
        }
        synchronized(pendingLock) { pending.reset() }
    }

    private companion object {
        /** One blocking read's worth. KISS frames are small; this is about syscall count, not MTU. */
        const val READ_CHUNK = 4096
        /** Undrained-byte ceiling. KISS media run at kilobits per second; 64 KiB is many seconds of traffic. */
        const val MAX_PENDING = 64 * 1024
    }
}
