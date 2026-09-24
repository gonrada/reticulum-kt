package network.reticulum.interfaces.framing

/** Feeds [len] bytes of a reusable read buffer, starting at [off], into a stream deframer. */
internal typealias DeframerFeed = (buf: ByteArray, off: Int, len: Int) -> Unit

/**
 * Select, once at construction, the framer for a byte-stream interface that speaks
 * either KISS (CMD_DATA, port 0) or HDLC.
 */
internal fun streamFramer(kissFraming: Boolean): (ByteArray) -> ByteArray {
    if (kissFraming) return { data -> KISS.frame(data) }
    return { data -> HDLC.frame(data) }
}

/**
 * Select, once at construction, the deframer for a byte-stream interface and return
 * its feed function. Both bounds derive from [hwMtu]:
 *
 * - KISS: decoded frames are capped at [hwMtu], matching python's
 *   `len(data_buffer) < self.HW_MTU` read-loop gate (TCPInterface.py:370); the escaped
 *   accumulation buffer is bounded alongside (see [KISS.Deframer]).
 * - HDLC: a completed frame larger than `hwMtu + ifacSize` is DROPPED, matching python's
 *   `check_frame_len` (TCPInterface.py:337-340). Separately, the escaped accumulation
 *   buffer is bounded at `2*hwMtu+16` so a peer that never sends a closing FLAG cannot
 *   grow it without limit (memory-exhaustion DoS). That covers a fully escaped max frame,
 *   so no valid frame is truncated before the length check gets to judge it.
 */
internal fun streamDeframer(
    kissFraming: Boolean,
    hwMtu: Int,
    ifacSize: () -> Int = { 0 },
    onFrame: (ByteArray) -> Unit,
): DeframerFeed {
    if (kissFraming) {
        val deframer = KISS.createDeframer(hwMtu) { _, data -> onFrame(data) }
        return { buf, off, len -> deframer.process(buf, off, len) }
    }
    val deframer = HDLC.createDeframer(
        maxFrameBytes = 2 * hwMtu + 16,
        payloadLimit = { hwMtu + ifacSize() },
    ) { data -> onFrame(data) }
    return { buf, off, len -> deframer.process(buf, off, len) }
}
