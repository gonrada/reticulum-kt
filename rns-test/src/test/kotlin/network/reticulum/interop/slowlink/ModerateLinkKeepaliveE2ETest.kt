package network.reticulum.interop.slowlink

import network.reticulum.interop.LinkShaping
import network.reticulum.interop.RnsLiveTestBase
import network.reticulum.link.Link
import network.reticulum.link.LinkConstants
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Timeout
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Keepalive over a link with a real RTT. At RTT ~100 ms the keepalive interval is
 * about 20 s (rtt scaled by KEEPALIVE_MAX / KEEPALIVE_MAX_RTT, floored at 5 s), so an
 * idle hold of three intervals exercises the keepalive exchange and the stale timer
 * on both sides at a timing no loopback test reaches. A keepalive-reply race that
 * closes an idle link is the kind of defect this is for.
 */
@DisplayName("Moderate link keepalive E2E (RTT ~100 ms, 200 kbit/s)")
class ModerateLinkKeepaliveE2ETest : RnsLiveTestBase() {
    override val aspects: Array<String> = arrayOf("moderatelink", "test")
    override val linkShaping: LinkShaping = LinkShaping(oneWayDelayMs = 50, bitrateBps = 200_000)

    @Test
    @DisplayName("An idle link holds through three keepalive intervals")
    @Timeout(180)
    fun `an idle link holds through three keepalive intervals`() {
        val destination = createPythonOutDestination()
        val establishedLatch = CountDownLatch(1)
        val linkRef = AtomicReference<Link>()
        val closed = AtomicBoolean(false)
        Link.create(
            destination,
            establishedCallback = { l ->
                linkRef.set(l)
                establishedLatch.countDown()
            },
            closedCallback = { _ -> closed.set(true) },
        )
        assertTrue(establishedLatch.await(30, TimeUnit.SECONDS), "Link should establish")
        assertNotNull(waitForPythonLink(15_000), "Python should see the link")
        val link = linkRef.get()
        assertEquals(LinkConstants.ACTIVE, link.status)

        val holdMs = (link.keepalive * 3 + 5_000).coerceIn(20_000, 120_000)
        println("  [Test] rtt=${link.rtt} ms keepalive=${link.keepalive} ms; holding idle for $holdMs ms")
        Thread.sleep(holdMs)

        assertFalse(closed.get(), "the link was closed during an idle hold of $holdMs ms")
        assertEquals(LinkConstants.ACTIVE, link.status, "Kotlin side must still be ACTIVE")
        assertNotNull(waitForPythonLink(5_000), "Python side must still hold the link")
        link.teardown()
    }
}
