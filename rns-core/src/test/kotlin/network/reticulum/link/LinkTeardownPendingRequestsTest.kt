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
 * A request still pending when its link closes must conclude: the port fails it
 * (a deliberate deviation; the reference leaves it SENT forever, Link.py:704-730
 * and :1416-1417). Each receipt's failed callback fires exactly once, including one
 * already RECEIVING, and one already FAILED is not reported again.
 */
class LinkTeardownPendingRequestsTest {
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
            appName = "teardown",
            aspects = arrayOf("pending"),
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

    @Test
    fun `pending requests fail once when the link is torn down`() {
        val link = makeLink()
        val failures = AtomicInteger()
        val latch = CountDownLatch(2)
        fun receipt(id: Int) =
            RequestReceipt(
                link = link,
                requestId = ByteArray(16) { id.toByte() },
                requestSize = 16,
                failedCallback = { failures.incrementAndGet(); latch.countDown() },
                timeout = 60_000,
            )
        val sent = receipt(1).also { it.startedAt = System.currentTimeMillis() }
        val receiving = receipt(2).also { it.startedAt = System.currentTimeMillis(); it.updateProgress(0.3f) }
        val alreadyFailed = receipt(3).also { it.requestFailed() }
        link.addPendingRequestForTest(sent)
        link.addPendingRequestForTest(receiving)
        link.addPendingRequestForTest(alreadyFailed)
        assertEquals(RequestReceipt.RECEIVING, receiving.status)

        link.teardown()

        assertTrue(latch.await(5, TimeUnit.SECONDS), "both live requests must report failure")
        Thread.sleep(200) // give a stray second invocation time to show up
        assertEquals(RequestReceipt.FAILED, sent.status)
        assertEquals(RequestReceipt.FAILED, receiving.status)
        assertEquals(3, failures.get(), "one callback per request: two at teardown, one from the earlier failure")
        assertFalse(link.isPendingRequestForTest(sent))
        assertFalse(link.isPendingRequestForTest(receiving))
    }

    @Test
    fun `markDelivered starts the budget clock and is ignored on a concluded receipt`() {
        val link = makeLink()
        val fresh = RequestReceipt(link = link, requestId = ByteArray(16) { 7 }, requestSize = 16, timeout = 1_000)
        assertEquals(null, fresh.startedAt, "a resource-sized request has no clock until delivered")
        fresh.markDelivered()
        assertEquals(RequestReceipt.DELIVERED, fresh.status)
        assertTrue(fresh.startedAt != null)

        val failed = RequestReceipt(link = link, requestId = ByteArray(16) { 8 }, requestSize = 16, timeout = 1_000)
        failed.requestFailed()
        failed.markDelivered()
        assertEquals(RequestReceipt.FAILED, failed.status)
        link.teardown()
    }
}
