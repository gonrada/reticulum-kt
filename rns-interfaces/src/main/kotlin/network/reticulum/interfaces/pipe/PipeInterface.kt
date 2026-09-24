package network.reticulum.interfaces.pipe

import network.reticulum.common.InterfaceMode
import network.reticulum.interfaces.Interface
import network.reticulum.interfaces.framing.HDLC
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream

/**
 * Interface that communicates over byte streams using HDLC framing.
 *
 * Matches Python's PipeInterface (Interface.py:54-205), which spawns a
 * subprocess and connects to it via stdin/stdout. This Kotlin version
 * takes raw streams directly, making it usable for:
 *
 * - Subprocess communication (like Python's PipeInterface)
 * - Named pipes (FIFOs)
 * - Testing (connecting two Transport instances without TCP)
 *
 * The framing is identical to Python's PipeInterface: simplified HDLC
 * with FLAG (0x7E) delimiters and ESC (0x7D) byte stuffing.
 *
 * @param name Human-readable interface name
 * @param inputStream Stream to read framed packets from
 * @param outputStream Stream to write framed packets to
 * @param bitrateEstimate Estimated bitrate in bits/sec (default 1 Mbps, matching Python)
 */

class PipeInterface(
    name: String,
    private val inputStream: InputStream,
    private val outputStream: OutputStream,
    bitrateEstimate: Int = BITRATE_GUESS,
    interfaceMode: InterfaceMode = InterfaceMode.FULL,
) : Interface(name) {

    override val mode: InterfaceMode = interfaceMode

    companion object {
        /** Maximum read chunk size (matches Python PipeInterface.MAX_CHUNK). */
        const val MAX_CHUNK = 32768

        /** Default bitrate estimate (matches Python PipeInterface.BITRATE_GUESS). */
        const val BITRATE_GUESS = 1_000_000

        /** Hardware MTU (matches Python PipeInterface.HW_MTU = 1064). */
        const val HW_MTU = 1064

        /** Default IFAC tag length in bytes for framed-serial media (python PipeInterface.py:57). */
        const val DEFAULT_IFAC_SIZE = 8
    }

    override val bitrate: Int = bitrateEstimate
    override val hwMtu: Int = HW_MTU

    // The tag is 8 bytes on this medium; see Interface.defaultIfacSize for why a
    // mismatch partitions rather than degrades.
    override val defaultIfacSize: Int
        get() = DEFAULT_IFAC_SIZE

    // Bound the deframer buffer so a peer that never sends a closing FLAG
    // cannot grow it without limit; 2*HW_MTU covers a fully-escaped max frame.
    private val hdlcDeframer = HDLC.createDeframer(
        maxFrameBytes = 2 * HW_MTU + 16,
        payloadLimit = { HW_MTU + ifacSize },
    ) { data ->
        processIncoming(data)
    }

    private var readThread: Thread? = null

    override fun processOutgoing(data: ByteArray) {
        if (!online.value || detached.get()) return

        val framed = HDLC.frame(data)
        synchronized(outputStream) {
            try {
                outputStream.write(framed)
                outputStream.flush()
            } catch (_: IOException) {
                setOnline(false)
                return
            }
        }
        txBytes.addAndGet(data.size.toLong())
    }

    override fun start() {
        setOnline(true)
        readThread = Thread(::readLoop).apply {
            isDaemon = true
            name = "PipeInterface[$name]-read"
            start()
        }
    }

    private fun readLoop() {
        val buffer = ByteArray(MAX_CHUNK)
        try {
            while (online.value && !detached.get()) {
                val bytesRead = inputStream.read(buffer)
                if (bytesRead == -1) break
                hdlcDeframer.process(buffer, 0, bytesRead)
            }
        } catch (_: IOException) {
            // Stream closed — expected on shutdown
        }
        setOnline(false)
    }

    override fun detach() {
        super.detach()
        try { inputStream.close() } catch (_: IOException) {}
        try { outputStream.close() } catch (_: IOException) {}
        readThread?.interrupt()
    }

    override fun toString(): String = "PipeInterface[$name]"
}
