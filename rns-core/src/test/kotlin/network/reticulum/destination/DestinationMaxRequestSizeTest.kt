package network.reticulum.destination

import network.reticulum.common.DestinationDirection
import network.reticulum.common.DestinationType
import network.reticulum.identity.Identity
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test

/**
 * Pins the L1 config knob (docs/parity-security-analysis-rns-core.md):
 * Destination.setMaxRequestSize, which the Link layer consults to reject
 * oversized inbound request resources. Mirrors python
 * Destination.set_max_request_size / max_request_size.
 *
 * The gate's reject path itself lives in Link.processResourceAdv (reached only
 * over an ACTIVE encrypted link) and is opt-in: unset (null) it is a no-op, so
 * the default resource path is unchanged and covered by the existing Link/
 * Resource suites.
 */
class DestinationMaxRequestSizeTest {

    private fun destination(): Destination = Destination.create(
        identity = Identity.create(),
        direction = DestinationDirection.IN,
        type = DestinationType.SINGLE,
        appName = "test",
        aspects = arrayOf("maxreqsize"),
    )

    @Test
    fun `max request size defaults to unlimited (null)`() {
        assertNull(destination().maxRequestSize, "default must be null (unlimited), matching python")
    }

    @Test
    fun `setMaxRequestSize stores a non-negative limit`() {
        val d = destination()
        d.setMaxRequestSize(4096)
        assertEquals(4096, d.maxRequestSize)
        d.setMaxRequestSize(0)
        assertEquals(0, d.maxRequestSize)
    }

    @Test
    fun `setMaxRequestSize rejects a negative limit`() {
        assertThrows(IllegalArgumentException::class.java) {
            destination().setMaxRequestSize(-1)
        }
    }
}
