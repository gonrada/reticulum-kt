package network.reticulum.interfaces.framing

import java.io.ByteArrayOutputStream

/**
 * HDLC-like framing for Reticulum interfaces.
 *
 * Frame format: [FLAG][escaped data][FLAG]
 *
 * Escape sequences:
 * - FLAG (0x7E) in data → ESC (0x7D) + 0x5E (FLAG XOR ESC_MASK)
 * - ESC (0x7D) in data → ESC (0x7D) + 0x5D (ESC XOR ESC_MASK)
 */
object HDLC {
    /** Frame boundary flag. */
    const val FLAG: Byte = 0x7E

    /** Escape character. */
    const val ESC: Byte = 0x7D

    /** XOR mask for escaped bytes. */
    const val ESC_MASK: Byte = 0x20

    /**
     * Escape data for HDLC framing.
     *
     * @param data Raw data to escape
     * @return Escaped data (without frame flags)
     */
    fun escape(data: ByteArray): ByteArray {
        val output = ByteArrayOutputStream(data.size + data.size / 10)

        for (byte in data) {
            when (byte) {
                FLAG -> {
                    output.write(ESC.toInt())
                    output.write((FLAG.toInt() xor ESC_MASK.toInt()))
                }
                ESC -> {
                    output.write(ESC.toInt())
                    output.write((ESC.toInt() xor ESC_MASK.toInt()))
                }
                else -> output.write(byte.toInt())
            }
        }

        return output.toByteArray()
    }

    /**
     * Unescape HDLC-escaped data.
     *
     * @param data Escaped data (without frame flags)
     * @return Unescaped data
     */
    fun unescape(data: ByteArray): ByteArray {
        val output = ByteArrayOutputStream(data.size)
        var escape = false

        for (byte in data) {
            if (escape) {
                output.write(byte.toInt() xor ESC_MASK.toInt())
                escape = false
            } else if (byte == ESC) {
                escape = true
            } else {
                output.write(byte.toInt())
            }
        }

        return output.toByteArray()
    }

    /**
     * Frame data with HDLC framing.
     *
     * @param data Raw data to frame
     * @return Framed data: [FLAG][escaped data][FLAG]
     */
    fun frame(data: ByteArray): ByteArray {
        val escaped = escape(data)
        val output = ByteArray(escaped.size + 2)
        output[0] = FLAG
        System.arraycopy(escaped, 0, output, 1, escaped.size)
        output[output.size - 1] = FLAG
        return output
    }

    /**
     * Create a frame deframer for streaming data.
     *
     * @param maxFrameBytes caps the accumulated (escaped) frame. A peer that
     *   streams bytes without ever sending a closing FLAG would otherwise grow
     *   the buffer without limit; once the bound is hit the partial frame is
     *   discarded and the deframer resyncs on the next FLAG. Defaults to
     *   unbounded so existing callers are unchanged; stream interfaces should
     *   pass a bound derived from their HW_MTU.
     * @param payloadLimit the largest DEFRAMED frame that will be delivered, which the
     *   reference computes as `HW_MTU + ifac_size` (`TCPInterface.check_frame_len`,
     *   TCPInterface.py:337-340). Evaluated per frame because an interface's IFAC size is
     *   not known until its credentials are derived. This is a different rule from
     *   [maxFrameBytes]: that one bounds the still-escaped accumulation buffer so an
     *   unterminated frame cannot exhaust memory, while this one validates a frame that
     *   did arrive complete. Defaults to unbounded.
     * @param onFrame Callback invoked with each complete deframed packet
     * @return Deframer instance
     */
    fun createDeframer(
        maxFrameBytes: Int = Int.MAX_VALUE,
        payloadLimit: () -> Int = { Int.MAX_VALUE },
        onFrame: (ByteArray) -> Unit,
    ): Deframer {
        return Deframer(onFrame, maxFrameBytes, payloadLimit)
    }

    /**
     * Streaming HDLC deframer.
     *
     * Accumulates incoming bytes and emits complete frames via callback. The
     * escaped accumulation buffer is bounded by [maxFrameBytes]; a frame that
     * exceeds it is discarded (memory freed) and the deframer resyncs on the
     * next FLAG, so a peer that never closes a frame cannot exhaust memory.
     */
    class Deframer(
        private val onFrame: (ByteArray) -> Unit,
        private val maxFrameBytes: Int = Int.MAX_VALUE,
        private val payloadLimit: () -> Int = { Int.MAX_VALUE },
    ) {
        private var buffer = ByteArrayOutputStream()
        private var inFrame = false
        private var overflowed = false

        /**
         * Empty the accumulation buffer, giving its array back when it has grown large.
         * `ByteArrayOutputStream.reset()` keeps the capacity, so one oversized run would
         * otherwise leave a large array pinned per connection for its whole lifetime.
         * Python rebinds `data_buffer = b""` per frame, releasing the bytes.
         */
        private fun recycleBuffer() {
            if (buffer.size() > SHRINK_ABOVE) buffer = ByteArrayOutputStream() else buffer.reset()
        }

        /**
         * Process incoming bytes.
         *
         * @param data Incoming byte data
         */
        fun process(data: ByteArray) {
            for (byte in data) processByte(byte)
        }

        /**
         * Process [len] bytes of [data] starting at [off] — lets a read loop hand its
         * reusable read buffer straight to the deframer without a per-read copyOf().
         */
        fun process(data: ByteArray, off: Int, len: Int) {
            for (i in off until off + len) processByte(data[i])
        }

        private fun processByte(byte: Byte) {
            if (byte == FLAG) {
                if (inFrame && !overflowed && buffer.size() > 0) {
                    // End of frame
                    val frameData = buffer.toByteArray()
                    val unescaped = unescape(frameData)
                    // python TCPInterface.check_frame_len (TCPInterface.py:337-340): a frame
                    // at or below HEADER_MINSIZE cannot hold a valid packet, and one above
                    // HW_MTU + ifac_size is larger than this medium can legitimately carry.
                    // The upper bound arrived in RNS 1.5.2; without it we would accept and
                    // parse oversize frames that every conformant peer drops.
                    if (unescaped.size > network.reticulum.common.RnsConstants.HEADER_MIN_SIZE &&
                        unescaped.size <= payloadLimit()
                    ) {
                        onFrame(unescaped)
                    }
                }
                // Start of new frame (or just a flag)
                inFrame = true
                overflowed = false
                recycleBuffer()
            } else if (inFrame) {
                if (overflowed) return
                if (buffer.size() < maxFrameBytes) {
                    buffer.write(byte.toInt())
                } else {
                    // Bound hit without a closing FLAG: discard and resync.
                    overflowed = true
                    recycleBuffer()
                }
            }
        }

        /**
         * Reset the deframer state.
         */
        fun reset() {
            recycleBuffer()
            inFrame = false
            overflowed = false
        }

        private companion object {
            /** Accumulations above this are released rather than kept for reuse. */
            const val SHRINK_ABOVE = 64 * 1024
        }
    }
}
