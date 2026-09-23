package network.reticulum.link

import network.reticulum.common.DestinationDirection
import network.reticulum.common.DestinationType
import network.reticulum.common.PacketType
import network.reticulum.crypto.defaultCryptoProvider
import network.reticulum.destination.Destination
import network.reticulum.identity.Identity
import network.reticulum.packet.Packet
import network.reticulum.transport.Transport
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/**
 * python RequestReceipt.request_timed_out (Link.py:1416-1417) is a no-op unless the
 * receipt is DELIVERED. A response that is arriving as a resource puts the receipt in
 * RECEIVING, and from then on the transfer is governed by the resource's own watchdog,
 * not by the request budget of rtt * factor + grace.
 *
 * A watchdog pass that applies the budget to every pending receipt fails a file download
 * that has been live for the whole budget on a high-RTT link (RTT 1.4 s, budget 19.7 s),
 * and the resource is torn down as a consequence. Pinned here: a RECEIVING receipt is
 * left alone by the timeout pass however long it has been running; a receipt still
 * waiting for any response times out as before; and requestFailed still fails a RECEIVING
 * receipt, which is what responseResourceConcluded uses when the resource fails.
 */
class LinkRequestTimeoutTest {
    @BeforeEach
    fun setup() {
        try { Transport.stop() } catch (_: Exception) {}
        Transport.start(Identity.create(), enableTransport = false)
    }

    @AfterEach
    fun cleanup() {
        try { Transport.stop() } catch (_: Exception) {}
    }

    private fun makeLink(): Link {
        val receiverDestination = Destination.create(
            identity = Identity.create(),
            direction = DestinationDirection.IN,
            type = DestinationType.SINGLE,
            appName = "request",
            aspects = arrayOf("timeout"),
        )
        Transport.registerDestination(receiverDestination)
        val crypto = defaultCryptoProvider()
        val requestData = crypto.generateX25519KeyPair().publicKey + crypto.generateEd25519KeyPair().publicKey
        val packet = Packet.createRaw(
            destinationHash = receiverDestination.hash,
            data = requestData,
            packetType = PacketType.LINKREQUEST,
            destinationType = DestinationType.SINGLE,
        )
        packet.pack()
        return Link.validateRequest(receiverDestination, requestData, packet)!!
    }

    private fun receipt(link: Link, id: Int, failures: AtomicInteger, latch: CountDownLatch? = null): RequestReceipt =
        RequestReceipt(
            link = link,
            requestId = ByteArray(16) { id.toByte() },
            requestSize = 32,
            failedCallback = { failures.incrementAndGet(); latch?.countDown() },
            timeout = 1_000,
        )

    @Test
    fun `a receipt whose response is arriving as a resource is exempt from the request budget`() {
        val link = makeLink()
        val failures = AtomicInteger()
        val receiving = receipt(link, 1, failures)
        val now = System.currentTimeMillis()
        receiving.startedAt = now - 60_000 // sixty times over its 1 s budget
        link.addPendingRequestForTest(receiving)
        receiving.updateProgress(0.2f)
        assertEquals(RequestReceipt.RECEIVING, receiving.status)

        link.checkRequestTimeoutsForTest(now)

        assertEquals(RequestReceipt.RECEIVING, receiving.status, "the resource watchdog owns a live transfer")
        assertTrue(link.isPendingRequestForTest(receiving), "still pending, so the response can still land")
        assertEquals(0, failures.get())
    }

    @Test
    fun `a receipt still waiting for any response times out on its budget`() {
        val link = makeLink()
        val failures = AtomicInteger()
        val latch = CountDownLatch(1)
        val waiting = receipt(link, 2, failures, latch)
        val now = System.currentTimeMillis()
        waiting.startedAt = now - 5_000
        link.addPendingRequestForTest(waiting)

        link.checkRequestTimeoutsForTest(now)

        assertTrue(latch.await(5, TimeUnit.SECONDS), "failed callback must fire")
        assertEquals(RequestReceipt.FAILED, waiting.status)
        assertFalse(link.isPendingRequestForTest(waiting))
    }

    @Test
    fun `a receipt inside its budget is untouched`() {
        val link = makeLink()
        val failures = AtomicInteger()
        val fresh = receipt(link, 3, failures)
        val now = System.currentTimeMillis()
        fresh.startedAt = now - 100
        link.addPendingRequestForTest(fresh)

        link.checkRequestTimeoutsForTest(now)

        assertEquals(RequestReceipt.SENT, fresh.status)
        assertTrue(link.isPendingRequestForTest(fresh))
    }

    @Test
    fun `a failed response resource still fails a receiving receipt`() {
        val link = makeLink()
        val failures = AtomicInteger()
        val latch = CountDownLatch(1)
        val receiving = receipt(link, 4, failures, latch)
        link.addPendingRequestForTest(receiving)
        receiving.updateProgress(0.5f)
        assertEquals(RequestReceipt.RECEIVING, receiving.status)

        // What responseResourceConcluded calls when resource.status != COMPLETE.
        receiving.requestFailed()

        assertTrue(latch.await(5, TimeUnit.SECONDS))
        assertEquals(RequestReceipt.FAILED, receiving.status)
    }
}
