package network.reticulum.interop.slowlink

import network.reticulum.interop.LinkShaping
import network.reticulum.interop.RnsLiveTestBase
import network.reticulum.interop.getBoolean
import network.reticulum.interop.getString
import network.reticulum.link.Link
import network.reticulum.link.LinkConstants
import network.reticulum.link.RequestReceipt
import network.reticulum.resource.Resource
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
 * The request/response and resource paths over a slow link: RTT about 1.5 s and
 * 200 kbit/s, shaped by [network.reticulum.interop.ShapedTcpRelay]. Every other
 * interop test runs on loopback at a millisecond RTT, where no transfer lasts long
 * enough for a timing defect to show.
 *
 * The first case is a field failure on a high-latency link made deterministic: with no
 * explicit timeout the request budget is rtt * 6 + 11.25 s, about 20 s here, and an
 * 800 KB response at 200 kbit/s takes over 30 s. The reference exempts a RECEIVING
 * receipt from that budget (Link.py:1416-1417); the port failed the request and tore
 * the resource down at the budget before the fix.
 */
@DisplayName("Slow link E2E (RTT ~1.5 s, 200 kbit/s)")
class SlowLinkE2ETest : RnsLiveTestBase() {
    override val aspects: Array<String> = arrayOf("slowlink", "test")
    override val linkShaping: LinkShaping = LinkShaping(oneWayDelayMs = 750, bitrateBps = 200_000)

    private fun establishLink(): Link {
        val destination = createPythonOutDestination()
        val establishedLatch = CountDownLatch(1)
        val linkRef = AtomicReference<Link>()
        Link.create(
            destination,
            establishedCallback = { l ->
                l.setResourceStrategy(Link.ACCEPT_ALL)
                linkRef.set(l)
                establishedLatch.countDown()
            },
        )
        assertTrue(establishedLatch.await(60, TimeUnit.SECONDS), "Link should establish over the slow link")
        assertNotNull(waitForPythonLink(30_000), "Python should see the link")
        val link = linkRef.get()
        assertEquals(LinkConstants.ACTIVE, link.status)
        println("  [Test] Link up: rtt=${link.rtt} ms, keepalive=${link.keepalive} ms")
        return link
    }

    @Test
    @DisplayName("A response resource that outlives the default request budget still completes")
    @Timeout(240)
    fun `a response resource that outlives the default request budget still completes`() {
        val link = establishLink()
        // Incompressible, so the bytes really cross the shaped link: 800 KB at 200 kbit/s
        // is 32 s of serialisation before the per-window round trips.
        val responseSize = 800_000
        val reg = python("rns_register_request_handler", "path" to "/slow/large", "random_response_size" to responseSize)
        assertTrue(reg.getBoolean("registered"))
        val expectedSha256 = reg.getString("response_sha256")

        val done = CountDownLatch(1)
        val failed = AtomicBoolean(false)
        val ready = AtomicReference<RequestReceipt>()
        val issuedAt = System.currentTimeMillis()
        val receipt =
            link.request(
                path = "/slow/large",
                data = "big".toByteArray(),
                responseCallback = { r ->
                    ready.set(r)
                    done.countDown()
                },
                failedCallback = { _ ->
                    failed.set(true)
                    done.countDown()
                },
            )
        assertNotNull(receipt, "request should be issued")
        val budgetMs = receipt.timeout
        println("  [Test] Request budget ${budgetMs} ms (rtt ${link.rtt} ms); expecting the transfer to take longer")

        assertTrue(done.await(210, TimeUnit.SECONDS), "the request must conclude one way or the other")
        val elapsedMs = System.currentTimeMillis() - issuedAt
        assertFalse(
            failed.get(),
            "request FAILED after $elapsedMs ms with a $budgetMs ms budget: the budget was applied to a " +
                "receiving response (python only times out a DELIVERED receipt, Link.py:1416-1417)",
        )
        assertEquals(RequestReceipt.READY, receipt.status)
        // Precondition, so a faster host cannot pass this vacuously.
        assertTrue(
            elapsedMs > budgetMs,
            "the transfer ($elapsedMs ms) did not outlive the request budget ($budgetMs ms); raise the response size",
        )
        val response = ready.get().response
        assertNotNull(response, "response bytes")
        assertEquals(responseSize, response.size, "response size")
        val digest = java.security.MessageDigest.getInstance("SHA-256").digest(response).joinToString("") { "%02x".format(it) }
        assertEquals(expectedSha256, digest, "response must be byte-exact")
        println("  [Test] ${response.size} bytes after $elapsedMs ms, budget was $budgetMs ms")
        link.teardown()
    }

    @Test
    @DisplayName("Kotlin sends a resource to Python over the slow link")
    @Timeout(180)
    fun `kotlin sends a resource to python over the slow link`() {
        val link = establishLink()
        // Random, so bz2 cannot shrink it: 120 KB is about 5 s on the wire at 200 kbit/s.
        val payload = ByteArray(120_000).also { java.util.Random(7).nextBytes(it) }
        val completed = CountDownLatch(1)
        val result = AtomicReference<Resource>()
        val startedAt = System.currentTimeMillis()
        Resource.create(
            data = payload,
            link = link,
            callback = { r ->
                result.set(r)
                completed.countDown()
            },
        )
        assertTrue(completed.await(150, TimeUnit.SECONDS), "resource should conclude")
        assertEquals(network.reticulum.resource.ResourceConstants.COMPLETE, result.get().status, "resource status")
        val deadline = System.currentTimeMillis() + 30_000
        var received = getPythonResources()
        while (received.isEmpty() && System.currentTimeMillis() < deadline) {
            Thread.sleep(500)
            received = getPythonResources()
        }
        assertTrue(received.isNotEmpty(), "Python should have received the resource")
        assertTrue(payload.contentEquals(received[0].data), "payload must round-trip byte-exact")
        println("  [Test] ${payload.size} bytes delivered in ${System.currentTimeMillis() - startedAt} ms")
        link.teardown()
    }
}
