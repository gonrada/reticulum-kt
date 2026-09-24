package network.reticulum.common

import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.util.concurrent.atomic.AtomicInteger

class RnsLogTest {

    private val saved = RnsLog.level

    @AfterEach
    fun restore() {
        RnsLog.level = saved
    }

    @Test
    fun `lazy message is not built when the level is gated off`() {
        RnsLog.level = RnsLog.INFO
        val builds = AtomicInteger(0)

        RnsLog.log(RnsLog.DEBUG, "test") { builds.incrementAndGet(); "debug" }
        assertEquals(0, builds.get(), "a DEBUG message must not be built while level is INFO")

        RnsLog.log(RnsLog.INFO, "test") { builds.incrementAndGet(); "info" }
        assertEquals(1, builds.get(), "an INFO message must be built while level is INFO")
    }

    @Test
    fun `isEnabled reflects the threshold`() {
        RnsLog.level = RnsLog.NOTICE
        assertTrue(RnsLog.isEnabled(RnsLog.ERROR))
        assertTrue(RnsLog.isEnabled(RnsLog.NOTICE))
        assertFalse(RnsLog.isEnabled(RnsLog.INFO))
        assertFalse(RnsLog.isEnabled(RnsLog.DEBUG))
    }

    @Test
    fun `level constants follow the Python RNS ordering`() {
        assertEquals(4, RnsLog.INFO, "INFO must be 4 to match Python RNS default")
        assertTrue(RnsLog.CRITICAL < RnsLog.ERROR)
        assertTrue(RnsLog.ERROR < RnsLog.WARNING)
        assertTrue(RnsLog.WARNING < RnsLog.NOTICE)
        assertTrue(RnsLog.NOTICE < RnsLog.INFO)
        assertTrue(RnsLog.INFO < RnsLog.VERBOSE)
        assertTrue(RnsLog.VERBOSE < RnsLog.DEBUG)
        assertTrue(RnsLog.DEBUG < RnsLog.EXTREME)
    }
}
