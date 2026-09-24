package network.reticulum.interfaces.rnode

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class RNodeFrameDurationTest {

    @Test
    fun `fast links floor the ceiling at the minimum`() {
        // High bitrate -> tiny derived value -> floored at 30s.
        assertEquals(30_000L, RNodeInterface.deriveMaxFrameDurationMs(hwMtu = 508, bitrate = 1_000_000))
    }

    @Test
    fun `slow links scale the ceiling above the floor`() {
        // 300 baud, HW_MTU 508: 508*2*8 = 8128 bits, /300*1000*3 ~ 81s.
        val ms = RNodeInterface.deriveMaxFrameDurationMs(hwMtu = 508, bitrate = 300)
        assertTrue(ms > 30_000L, "a 300-baud link needs a ceiling well above the 30s floor")
        assertEquals(8128L * 1000 / 300 * 3, ms)
    }

    @Test
    fun `non-positive bitrate uses the floor`() {
        assertEquals(30_000L, RNodeInterface.deriveMaxFrameDurationMs(hwMtu = 508, bitrate = 0))
    }
}
