package network.reticulum.interfaces.kiss

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test

class Ax25Test {

    /** Decode a 6-byte AX.25 address field back to a callsign (each char >> 1). */
    private fun decodeCall(header: ByteArray, offset: Int): String {
        val sb = StringBuilder()
        for (i in 0 until 6) {
            val c = ((header[offset + i].toInt() and 0xFF) shr 1).toChar()
            if (c != ' ') sb.append(c)
        }
        return sb.toString()
    }

    @Test
    fun `header encodes callsigns, ssids, ctrl and pid`() {
        val h = Ax25.buildHeader("APZRNS", 5, "NOCALL", 3)
        assertEquals(16, h.size)
        assertEquals("APZRNS", decodeCall(h, 0))
        assertEquals(0x60 or (5 shl 1), h[6].toInt() and 0xFF) // dest SSID byte
        assertEquals("NOCALL", decodeCall(h, 7))
        assertEquals(0x60 or (3 shl 1) or 0x01, h[13].toInt() and 0xFF) // src SSID byte, last-address bit set
        assertEquals(Ax25.CTRL_UI, h[14].toInt() and 0xFF)
        assertEquals(Ax25.PID_NOLAYER3, h[15].toInt() and 0xFF)
    }

    @Test
    fun `short callsigns are space-padded and decode back`() {
        val h = Ax25.buildHeader("CQ", 0, "AB1CD", 0)
        assertEquals("CQ", decodeCall(h, 0))
        assertEquals("AB1CD", decodeCall(h, 7))
    }

    @Test
    fun `callsign validation enforces length and charset`() {
        assertThrows(IllegalArgumentException::class.java) { Ax25.validateCallsign("X", "source", "i") }
        assertThrows(IllegalArgumentException::class.java) { Ax25.validateCallsign("TOOLONGX", "source", "i") }
        assertThrows(IllegalArgumentException::class.java) { Ax25.validateCallsign("N0-CL", "source", "i") }
        assertEquals("NOCALL", Ax25.validateCallsign(" nocall ", "source", "i")) // trim + upper
        assertEquals("CQ", Ax25.validateCallsign("cq", "destination", "i", minLength = 1))
    }

    @Test
    fun `ssid validation enforces range`() {
        assertThrows(IllegalArgumentException::class.java) { Ax25.validateSsid(-1, "source", "i") }
        assertThrows(IllegalArgumentException::class.java) { Ax25.validateSsid(16, "source", "i") }
        assertEquals(0, Ax25.validateSsid(null, "source", "i"))
        assertEquals(15, Ax25.validateSsid(15, "source", "i"))
    }
}
