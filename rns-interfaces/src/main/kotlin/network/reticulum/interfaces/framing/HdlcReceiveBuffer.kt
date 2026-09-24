package network.reticulum.interfaces.framing

/**
 * Bounded HDLC deframer — Kotlin port of Python RNS's `HDLC.ReceiveBuffer`
 * (RNS/Interfaces/util/HDLC.py). Assembles `FLAG`-delimited frames from a continuous
 * byte stream, unescapes them, length-validates, and hands each complete frame to
 * [onFrame]. A frame that fails the length check goes to [onInvalid].
 *
 * Memory is bounded: an unterminated frame is discarded once the unconsumed buffer
 * exceeds `2 * mtu`, and the buffer is compacted as frames are consumed. This is the
 * receive side for stream transports (BackboneInterface / LocalInterface), which see a
 * byte stream rather than discrete packets.
 *
 * Ported for the BackboneInterface; also usable by any stream KISS/HDLC path.
 *
 * @param mtu supplies the link MTU; the unterminated-frame buffer is bounded at `2*mtu`.
 *   Modelled as a supplier because an interface's MTU can change after MTU discovery.
 *   (Unlike the Python original, this is a non-null Int, so there is no `None*2` hazard.)
 * @param minFrameLen frames of this length or shorter are treated as invalid.
 * @param maxFrameLen optional upper bound (supplier); a frame longer than this is invalid.
 * @param onFrame invoked with each complete, length-valid, unescaped frame.
 * @param onInvalid invoked with the length of a frame that failed the length check.
 */
class HdlcReceiveBuffer(
    private val mtu: () -> Int,
    private val minFrameLen: Int,
    private val maxFrameLen: () -> Int? = { null },
    private val onFrame: ((ByteArray) -> Unit)? = null,
    private val onInvalid: ((Int) -> Unit)? = null,
) {
    private var buf = ByteArray(INITIAL_CAPACITY)
    private var size = 0 // valid bytes in buf
    private var off = 0  // consumed offset / next scan start

    /** Bytes currently buffered and unconsumed. */
    fun length(): Int = size - off

    /**
     * Drop any partial frame from the buffer and reset the assembly offset.
     *
     * Also gives the backing array back. reset() is only reached on garbage — no flag at
     * all, or an unterminated run past 2·MTU — and the growth that run caused is exactly
     * what a peer feeding one flag and two megabytes of filler was buying: with the
     * Backbone frame limit at 1 MiB, a 4 MiB array stayed pinned per idle connection for
     * the life of the socket, 4 GiB at the client cap, for no further bandwidth.
     * Python's `bytearray.clear()` releases the storage (util/HDLC.py:101-103).
     */
    fun reset() {
        size = 0
        off = 0
        if (buf.size > INITIAL_CAPACITY) buf = ByteArray(INITIAL_CAPACITY)
    }

    private companion object {
        const val INITIAL_CAPACITY = 256
    }

    fun feed(data: ByteArray) {
        if (data.isEmpty()) return
        ensureCapacity(data.size)
        System.arraycopy(data, 0, buf, size, data.size)
        size += data.size

        while (true) {
            val frameStart = indexOfFlag(off)
            if (frameStart == -1) {
                // No frame delimiter at all — nothing assemblable; drop the noise.
                reset()
                return
            }

            val frameEnd = indexOfFlag(frameStart + 1)
            if (frameEnd == -1) {
                // Opening flag but no closing flag yet. Wait for more, unless the
                // unterminated run has grown past twice the MTU — then discard it.
                if (size - off > mtu() * 2) reset()
                return
            }

            val frame = HDLC.unescape(buf.copyOfRange(frameStart + 1, frameEnd))
            val frameLen = frame.size
            if (frameLen > 0) {
                val maxLen = maxFrameLen()
                if (frameLen > minFrameLen && (maxLen == null || frameLen <= maxLen)) {
                    onFrame?.invoke(frame)
                } else {
                    onInvalid?.invoke(frameLen)
                }
            }

            // The closing flag doubles as the next frame's opening flag.
            off = frameEnd
            if (off > 0 && off >= size / 2) {
                System.arraycopy(buf, off, buf, 0, size - off)
                size -= off
                off = 0
            }
        }
    }

    private fun indexOfFlag(from: Int): Int {
        var i = from
        while (i < size) {
            if (buf[i] == HDLC.FLAG) return i
            i++
        }
        return -1
    }

    private fun ensureCapacity(extra: Int) {
        if (size + extra > buf.size) {
            var newCap = buf.size * 2
            while (newCap < size + extra) newCap *= 2
            buf = buf.copyOf(newCap)
        }
    }
}
