package network.reticulum.interfaces.kiss

import java.io.ByteArrayOutputStream

/**
 * Minimal AX.25 UI-frame addressing for KISS TNC traffic, ported from the reference
 * (`RNS/Interfaces/AX25KISSInterface.py:60-64, 271-290`). Enough to prepend a valid AX.25
 * header on transmit and strip it on receive; not a full AX.25 stack.
 *
 * The 16-byte header is: a 7-byte destination address + a 7-byte source address
 * (each callsign character shifted left one bit, unused positions padded with a
 * shifted space, SSID in the trailing byte), then CTRL (UI) and PID (no layer 3).
 */
object Ax25 {
    const val PID_NOLAYER3 = 0xF0
    const val CTRL_UI = 0x03
    const val HEADER_SIZE = 16

    const val DEFAULT_DEST_CALLSIGN = "APZRNS"
    const val DEFAULT_DEST_SSID = 0

    /** Validate an operator/tocall callsign: [minLength]-6 chars, A-Z and 0-9 only. */
    fun validateCallsign(value: String?, role: String, interfaceName: String, minLength: Int = 3): String {
        val callsign = (value ?: "").trim().uppercase()
        if (callsign.length < minLength || callsign.length > 6) {
            throw IllegalArgumentException(
                "Invalid AX.25 $role callsign \"$callsign\" for $interfaceName. " +
                    "A $role callsign must be between $minLength and 6 characters. " +
                    "Correct it in the radio modem settings, or disable AX.25 framing."
            )
        }
        for (ch in callsign) {
            if (!((ch in 'A'..'Z') || (ch in '0'..'9'))) {
                throw IllegalArgumentException(
                    "Invalid AX.25 $role callsign \"$callsign\" for $interfaceName. " +
                        "Only A-Z and 0-9 are allowed. Correct it in the radio modem settings, " +
                        "or disable AX.25 framing."
                )
            }
        }
        return callsign
    }

    /** Validate an SSID: a whole number 0-15. */
    fun validateSsid(value: Int?, role: String, interfaceName: String): Int {
        val ssid = value ?: 0
        if (ssid < 0 || ssid > 15) {
            throw IllegalArgumentException(
                "Invalid AX.25 $role SSID \"$ssid\" for $interfaceName. " +
                    "An SSID must be a whole number between 0 and 15. Correct it in the radio " +
                    "modem settings, or disable AX.25 framing."
            )
        }
        return ssid
    }

    /** Build the 16-byte AX.25 UI header. Callsigns must already be validated/uppercased. */
    fun buildHeader(dstCall: String, dstSsid: Int, srcCall: String, srcSsid: Int): ByteArray {
        val out = ByteArrayOutputStream(HEADER_SIZE)
        val dst = dstCall.toByteArray(Charsets.US_ASCII)
        for (i in 0 until 6) {
            out.write(if (i < dst.size) (dst[i].toInt() and 0xFF) shl 1 else 0x20 shl 1)
        }
        out.write(0x60 or (dstSsid shl 1))

        val src = srcCall.toByteArray(Charsets.US_ASCII)
        for (i in 0 until 6) {
            out.write(if (i < src.size) (src[i].toInt() and 0xFF) shl 1 else 0x20 shl 1)
        }
        out.write(0x60 or (srcSsid shl 1) or 0x01)

        out.write(CTRL_UI)
        out.write(PID_NOLAYER3)
        return out.toByteArray()
    }
}
