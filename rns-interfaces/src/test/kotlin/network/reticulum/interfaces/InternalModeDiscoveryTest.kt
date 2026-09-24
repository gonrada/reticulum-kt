package network.reticulum.interfaces

import network.reticulum.common.InterfaceMode
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * `MODE_INTERNAL` belongs in `DISCOVER_PATHS_FOR` (python `Interface.py:55`).
 *
 * Internal mode contains ANNOUNCES, not path discovery. A private segment that could not
 * resolve a path would be unable to reach anything outside itself, which is a different
 * and much larger restriction than the one the mode is for. The announce-side semantics
 * are pinned in rns-core's InternalModeAnnounceTest.
 */
class InternalModeDiscoveryTest {
    @Test
    fun `internal mode still discovers paths`() {
        assertTrue(InterfaceMode.INTERNAL in Interface.DISCOVER_PATHS_FOR)
    }
}
