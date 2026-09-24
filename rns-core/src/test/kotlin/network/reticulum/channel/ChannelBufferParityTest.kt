package network.reticulum.channel

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.PrintStream
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Mirroring unit tests for the Channel / Buffer parity fixes made for the
 * conformance bridge phase 5e. Each pins a behavior change against the python
 * RNS contract it converges to, driving the real production code through a
 * lightweight in-memory [FakeOutlet] (no Link / wire required).
 */
class ChannelBufferParityTest {

    /** Minimal in-memory ChannelOutlet: every send produces an opaque packet
     *  reported as SENT, so Channel.send treats it as transmitted-with-receipt. */
    private class FakeOutlet(
        override val mdu: Int = 500,
        override val rtt: Long? = 0L,
    ) : ChannelOutlet {
        @Volatile var failSend = false

        /** Reports readiness the way the Link outlet does — always usable. */
        @Volatile var usable = true

        /** The transport is gone for good; no later send can succeed. */
        @Volatile var gone = false

        /** Raised by [send] instead of returning: the transmit path itself failed, which
         *  no ChannelException filter converts away. */
        @Volatile var sendError: Throwable? = null

        /** Every raw envelope the outlet actually transmitted, in order. */
        val sent = CopyOnWriteArrayList<ByteArray>()
        var notifyTimedOutCalls = 0
        override fun send(raw: ByteArray): Any? {
            sendError?.let { throw it }
            sent.add(raw)
            return if (failSend) null else Any()
        }
        override fun resend(packet: Any): Any? = packet
        override val isUsable: Boolean get() = usable
        override val isClosed: Boolean get() = gone || !usable
        override val timedOut: Boolean get() = false
        override fun getPacketState(packet: Any): Int = MessageState.SENT
        override fun setPacketTimeoutCallback(packet: Any, callback: ((Any) -> Unit)?, timeout: Long?) {}
        override fun setPacketDeliveredCallback(packet: Any, callback: ((Any) -> Unit)?) {}
        override fun getPacketId(packet: Any): Any = packet
        override fun notifyTimedOut() { notifyTimedOutCalls++ }
    }

    private class Probe(override val msgType: Int, var payload: ByteArray = ByteArray(0)) : MessageBase() {
        override fun pack(): ByteArray = payload
        override fun unpack(raw: ByteArray) { payload = raw }
    }

    private fun channel(mdu: Int = 500): Channel = Channel(FakeOutlet(mdu = mdu))

    // #D1: ME_TOO_BIG fires BEFORE the sequence advances / envelope is emplaced.
    @Test
    fun `send rejects oversize with ME_TOO_BIG without advancing sequence`() {
        val ch = channel(mdu = 20)
        ch.registerMessageType(0x0101, MessageFactory { Probe(0x0101) })
        // packed = 6-byte header + 20-byte payload = 26 > outlet.mdu(20).
        val ex = assertFailsWith<ChannelException> { ch.send(Probe(0x0101, ByteArray(20))) }
        assertEquals(ChannelExceptionType.ME_TOO_BIG, ex.type)
        val s = ch.stateForTest()
        assertEquals(0, s.nextSequence)
        assertEquals(0, s.txRing)
    }

    // #D2: a non-transmitting outlet restores the reserved sequence + raises
    // ME_LINK_NOT_READY; the next send reuses the freed sequence (no gap).
    @Test
    fun `send restores sequence and raises ME_LINK_NOT_READY when outlet does not transmit`() {
        val ch = channel()
        ch.registerMessageType(0x0101, MessageFactory { Probe(0x0101) })
        ch.failNextSendForTest = true
        val ex = assertFailsWith<ChannelException> { ch.send(Probe(0x0101, "hi".toByteArray())) }
        assertEquals(ChannelExceptionType.ME_LINK_NOT_READY, ex.type)
        assertEquals(0, ch.stateForTest().nextSequence)
        assertEquals(0, ch.stateForTest().txRing)

        val env = ch.send(Probe(0x0101, "ok".toByteArray()))
        assertEquals(0, env.sequence)
        assertEquals(1, ch.stateForTest().nextSequence)
    }

    // #D7: Envelope.unpack ignores the on-wire length field and delivers raw[6:].
    @Test
    fun `receive ignores envelope length field and delivers full payload`() {
        val ch = channel()
        val delivered = mutableListOf<ByteArray>()
        ch.registerMessageType(0x0101, MessageFactory { Probe(0x0101) })
        ch.addMessageHandler { m -> if (m is Probe) { delivered.add(m.payload); true } else false }
        val payload = "length-mismatch!".toByteArray() // 16 bytes
        // header: msgType=0x0101, sequence=0, length=1 (deliberately wrong).
        val raw = byteArrayOf(0x01, 0x01, 0x00, 0x00, 0x00, 0x01) + payload
        ch.receive(raw)
        assertEquals(1, delivered.size)
        assertEquals(payload.toList(), delivered[0].toList())
    }

    // Contiguous-delivery loop must NOT break on a non-matching ring head, so it
    // crosses the 0xFFFF->0 modulus boundary (the [0,0xFFFF] ring ordering).
    @Test
    fun `contiguous delivery crosses the sequence wrap boundary`() {
        val ch = channel()
        val delivered = mutableListOf<ByteArray>()
        ch.registerMessageType(0x0101, MessageFactory { Probe(0x0101) })
        ch.addMessageHandler { m -> if (m is Probe) { delivered.add(m.payload); true } else false }
        // Drive the receive counter up to 0xFFFF by delivering 0..0xFFFE in order.
        for (seq in 0 until 0xFFFF) {
            ch.receive(ch.packEnvelopeForTest(Probe(0x0101, ByteArray(0)), seq))
        }
        assertEquals(0xFFFF, ch.stateForTest().nextRxSequence)

        delivered.clear()
        // seq=0 arrives early -> in-window, buffered, not delivered.
        ch.receive(ch.packEnvelopeForTest(Probe(0x0101, "zero".toByteArray()), 0))
        assertTrue(delivered.isEmpty())
        assertEquals(1, ch.stateForTest().rxRing)
        // seq=0xFFFF completes the run -> delivers [0xFFFF, 0] across the wrap.
        ch.receive(ch.packEnvelopeForTest(Probe(0x0101, "last".toByteArray()), 0xFFFF))
        assertEquals(listOf("last", "zero"), delivered.map { String(it) })
        assertEquals(1, ch.stateForTest().nextRxSequence)
        assertEquals(0, ch.stateForTest().rxRing)
    }

    // A sequence too far ahead (> WINDOW_MAX) must be dropped, not buffered, so a
    // link peer cannot fill rxRing toward the 16-bit sequence space (Python
    // Channel._receive:367-369). A sequence within the window is still buffered.
    @Test
    fun `receive drops a sequence beyond the window`() {
        val ch = channel()
        ch.registerMessageType(0x0101, MessageFactory { Probe(0x0101) })
        ch.addMessageHandler { _ -> true }
        // nextRx = 0, WINDOW_MAX = 48. seq 1000 is far ahead -> dropped.
        ch.receive(ch.packEnvelopeForTest(Probe(0x0101, ByteArray(0)), 1000))
        assertEquals(0, ch.stateForTest().rxRing, "a far-ahead sequence must be dropped")
        // seq within the window is buffered (in-window future).
        ch.receive(ch.packEnvelopeForTest(Probe(0x0101, ByteArray(0)), 10))
        assertEquals(1, ch.stateForTest().rxRing, "an in-window future sequence must buffer")
    }

    // Channel.mdu = min(outlet.mdu - 6, 0xFFFF).
    @Test
    fun `channel mdu is capped at 0xFFFF`() {
        assertEquals(494, channel(mdu = 500).mdu)
        assertEquals(0xFFFF, channel(mdu = 70000).mdu)
    }

    // #D3: retransmission exhaustion shuts the channel down AND notifies the
    // outlet (which, for a LinkChannelOutlet, tears the Link down).
    @Test
    fun `retransmission exhaustion shuts down and notifies the outlet`() {
        val outlet = FakeOutlet()
        val ch = Channel(outlet)
        ch.registerMessageType(0x0101, MessageFactory { Probe(0x0101) })
        ch.addMessageHandler { _ -> true }
        val env = ch.send(Probe(0x0101, "x".toByteArray()))
        val pkt = env.packet!!
        // The packet never delivers (FakeOutlet keeps it SENT) -> fire timeouts.
        repeat(6) { ch.firePacketTimeoutForTest(pkt) }
        assertEquals(5, env.tries)
        assertEquals(1, outlet.notifyTimedOutCalls)
        assertEquals(0, ch.stateForTest().txRing)
        assertEquals(0, ch.stateForTest().messageHandlers) // _shutdown cleared handlers
    }

    // #D5: StreamDataMessage.unpack accepts a chunk inflating to exactly
    // MAX_CHUNK_LEN but aborts (IOException) one byte over.
    @Test
    fun `StreamDataMessage unpack enforces the 16384 decompression bound`() {
        val okRaw = packStream(StreamDataMessage.compressForTest(ByteArray(16384)))
        val ok = StreamDataMessage()
        ok.unpack(okRaw)
        assertEquals(16384, ok.data.size)

        val bombRaw = packStream(StreamDataMessage.compressForTest(ByteArray(16385)))
        assertFailsWith<IOException> { StreamDataMessage().unpack(bombRaw) }
    }

    // #D9: RawChannelReader registers SMT_STREAM_DATA as a SYSTEM type, so an
    // inbound StreamDataMessage unpacks and is reassembled (no ME_NOT_REGISTERED).
    @Test
    fun `RawChannelReader registers the system stream type and reassembles`() {
        val ch = channel()
        val reader = RawChannelReader(0, ch)
        val sdm = StreamDataMessage().apply { streamId = 0; data = "hello".toByteArray(); eof = true }
        ch.receive(ch.packEnvelopeForTest(sdm, 0))
        val buf = ByteArray(16)
        val n = reader.read(buf, 0, buf.size)
        assertEquals("hello", String(buf, 0, n))
    }

    // A write whose link has gone away must fail, not retry forever. The raw writer
    // returns 0 for every refused chunk (Buffer.py:264-267) and the reference leans on
    // io.BufferedWriter to re-drive it, which never terminates once the link is dead.
    @Test
    fun `write fails instead of blocking when the link is closed`() {
        val outlet = FakeOutlet()
        val ch = Channel(outlet)
        val writer = RawChannelWriter(1, ch)
        // Exactly the production shape: the Link outlet still reports itself usable
        // (Channel.py:579) but transmits nothing, so every send raises ME_LINK_NOT_READY.
        outlet.failSend = true
        outlet.gone = true

        val failure = AtomicReference<Throwable?>(null)
        val worker = thread(isDaemon = true) {
            try {
                writer.write("hello".toByteArray())
            } catch (e: Throwable) {
                failure.set(e)
            }
        }
        worker.join(5_000)

        assertTrue(!worker.isAlive, "write must not block on a closed link")
        assertTrue(failure.get() is IOException, "expected IOException, got ${failure.get()}")
    }

    // The same loop must NOT fail a link that can still recover: a full send window or a
    // link not yet ACTIVE refuses the chunk transiently, and the write has to drain once
    // the channel accepts again.
    @Test
    fun `write keeps retrying while the link can still recover`() {
        val outlet = FakeOutlet()
        val ch = Channel(outlet)
        val writer = RawChannelWriter(2, ch)
        outlet.failSend = true // refusing, but the outlet is alive

        val failure = AtomicReference<Throwable?>(null)
        val done = CountDownLatch(1)
        thread(isDaemon = true) {
            try {
                writer.write("hello".toByteArray())
            } catch (e: Throwable) {
                failure.set(e)
            } finally {
                done.countDown()
            }
        }

        assertTrue(!done.await(200, TimeUnit.MILLISECONDS), "a recoverable refusal must not fail the write")
        outlet.failSend = false // channel accepts again
        assertTrue(done.await(5, TimeUnit.SECONDS), "write must drain once the channel accepts")
        assertEquals(null, failure.get())
    }

    // close() waits for the channel to drain before its EOF marker, but that wait only
    // makes sense while the link can still become ready. On a closed outlet the channel
    // never reports ready again, so the wait runs to its full rtt*10 ceiling — 50s with a
    // null rtt (the 5000ms default). Callers close in a finally block, so the close must
    // return promptly and must not throw.
    @Test
    fun `close does not wait out the rtt ceiling on a closed link`() {
        val outlet = FakeOutlet(rtt = null) // rtt*10 would be 50s
        val ch = Channel(outlet)
        val writer = RawChannelWriter(3, ch)
        outlet.usable = false // never ready again; reports closed

        val failure = AtomicReference<Throwable?>(null)
        val done = CountDownLatch(1)
        thread(isDaemon = true) {
            try {
                writer.close()
            } catch (e: Throwable) {
                failure.set(e)
            } finally {
                done.countDown()
            }
        }

        assertTrue(done.await(5, TimeUnit.SECONDS), "close must not wait out rtt*10 on a closed link")
        assertEquals(null, failure.get(), "close on a dead link must complete quietly, got ${failure.get()}")
    }

    // The bounded wait still has to happen when the link is merely busy: a full send
    // window refuses transiently, and close() should give the channel its rtt*10 window
    // to drain before giving up on the EOF marker.
    @Test
    fun `close still waits the bounded window when the link is alive`() {
        val outlet = FakeOutlet(rtt = 30L) // rtt*10 = 300ms
        val ch = Channel(outlet)
        val writer = RawChannelWriter(4, ch)
        ch.padTxRingForTest(60) // window full -> not ready, but the outlet is alive

        val done = CountDownLatch(1)
        thread(isDaemon = true) {
            try {
                writer.close()
            } finally {
                done.countDown()
            }
        }

        assertTrue(!done.await(200, TimeUnit.MILLISECONDS), "a busy but live link must still get the wait")
        assertTrue(done.await(5, TimeUnit.SECONDS), "the wait must stay bounded")
    }

    // A reader blocks until the stream's EOF marker arrives, so a marker that fails to send
    // on a link that is otherwise fine leaves that reader with nothing to go on. close() is
    // called from finally blocks and still must not raise — but it must say so.
    @Test
    fun `close reports an EOF marker that failed to send on a live link`() {
        val outlet = FakeOutlet()
        val ch = Channel(outlet)
        val writer = RawChannelWriter(5, ch)
        // The link is healthy by every reading the outlet exposes; the transmit itself is
        // what failed, so this is a real loss of the marker and not a closed link.
        outlet.sendError = IllegalStateException("transmit path failed")

        val failure = AtomicReference<Throwable?>(null)
        val printed = captureStdout {
            try {
                writer.close()
            } catch (e: Throwable) {
                failure.set(e)
            }
        }

        assertEquals(null, failure.get(), "close must not raise, got ${failure.get()}")
        assertTrue(
            printed.contains("EOF"),
            "a lost EOF marker on a live link must be surfaced, printed=<$printed>",
        )
        assertTrue(
            printed.contains("transmit path failed"),
            "the report must carry the underlying failure, printed=<$printed>",
        )
    }

    // The quiet way a marker goes missing, and the likelier one: the link is alive but its
    // send window never drains inside the bounded wait. The send is then refused as
    // not-ready, writeInternal filters that to a zero return, and nothing is raised at all —
    // so the exception branch alone would never see it, while the reader waits forever.
    @Test
    fun `close reports an EOF marker the channel never became ready to send`() {
        val outlet = FakeOutlet(rtt = 30L) // rtt*10 = 300ms, so the wait ends quickly
        val ch = Channel(outlet)
        val writer = RawChannelWriter(8, ch)
        ch.padTxRingForTest(60) // window full -> never ready, but the outlet is alive

        val failure = AtomicReference<Throwable?>(null)
        val printed = captureStdout {
            try {
                writer.close()
            } catch (e: Throwable) {
                failure.set(e)
            }
        }

        assertEquals(null, failure.get(), "close must not raise, got ${failure.get()}")
        assertTrue(
            printed.contains("EOF"),
            "a marker refused by a live channel must be surfaced, printed=<$printed>",
        )
        assertTrue(outlet.sent.isEmpty(), "the marker really did not go out")
    }

    // The same failure on a link that has already closed is not worth reporting: a closed
    // link cannot carry the marker at all, every close on a dead link would print, and the
    // reader on the other side is gone with it.
    @Test
    fun `close stays quiet when a closed link cannot carry the EOF marker`() {
        val outlet = FakeOutlet()
        val ch = Channel(outlet)
        val writer = RawChannelWriter(6, ch)
        // The production outlet reports itself usable in every link state, so a closed link
        // shows up as isClosed alone.
        outlet.gone = true
        outlet.sendError = IllegalStateException("link is closed")

        val failure = AtomicReference<Throwable?>(null)
        val printed = captureStdout {
            try {
                writer.close()
            } catch (e: Throwable) {
                failure.set(e)
            }
        }

        assertEquals(null, failure.get(), "close must not raise, got ${failure.get()}")
        assertEquals("", printed.trim(), "a closed link has nothing to report, printed=<$printed>")
    }

    // The reporting must not have cost the marker itself: a healthy close still emits one
    // EOF-flagged, empty StreamDataMessage and says nothing.
    @Test
    fun `close still sends the EOF marker on a healthy link`() {
        val outlet = FakeOutlet()
        val ch = Channel(outlet)
        val writer = RawChannelWriter(7, ch)

        val printed = captureStdout { writer.close() }

        assertEquals(1, outlet.sent.size, "close must send exactly the EOF marker")
        val raw = outlet.sent[0]
        // Strip the 6-byte channel envelope header to reach the packed stream message.
        val marker = StreamDataMessage().apply { unpack(raw.copyOfRange(6, raw.size)) }
        assertEquals(7, marker.streamId)
        assertTrue(marker.eof, "the marker must carry the EOF flag")
        assertEquals(0, marker.data.size, "the marker carries no data")
        assertEquals("", printed.trim(), "a successful close must report nothing, printed=<$printed>")
    }

    /** Runs [body] with System.out swapped for a buffer, returning everything it printed. */
    private fun captureStdout(body: () -> Unit): String {
        val buffer = ByteArrayOutputStream()
        val original = System.out
        System.setOut(PrintStream(buffer, true, "UTF-8"))
        try {
            body()
        } finally {
            System.setOut(original)
        }
        return buffer.toString("UTF-8")
    }

    private fun packStream(compressedBody: ByteArray): ByteArray =
        StreamDataMessage().apply {
            streamId = 0
            data = compressedBody
            compressed = true
        }.pack()
}
