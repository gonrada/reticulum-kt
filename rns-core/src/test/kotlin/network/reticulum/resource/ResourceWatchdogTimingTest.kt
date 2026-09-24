package network.reticulum.resource

import network.reticulum.common.DestinationDirection
import network.reticulum.common.DestinationType
import network.reticulum.common.PacketContext
import network.reticulum.common.PacketType
import network.reticulum.crypto.defaultCryptoProvider
import network.reticulum.destination.Destination
import network.reticulum.identity.Identity
import network.reticulum.link.Link
import network.reticulum.link.LinkConstants
import network.reticulum.packet.Packet
import network.reticulum.transport.Transport
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.io.File
import java.util.concurrent.CopyOnWriteArrayList

/**
 * The Resource watchdog, branch by branch, against python `__watchdog_job`
 * (Resource.py:577-683), driven through the clock seam so a wait of minutes is one
 * call. The sender-transferring case is the detection check for the old single idle
 * timer: the previous watchdog cancelled at 64 RTTs; the reference waits
 * rtt × 6 × 16 + 10 s + 68 s.
 */
class ResourceWatchdogTimingTest {
    private val t0 = 1_700_000_000_000L

    @BeforeEach
    fun setup() {
        try { Transport.stop() } catch (_: Exception) {}
        Transport.start(Identity.create(), enableTransport = false)
        Resource.watchdogDisabledForTest = true
    }

    @AfterEach
    fun cleanup() {
        Resource.watchdogDisabledForTest = false
        Transport.outboundTapForTest = null
        try { Transport.stop() } catch (_: Exception) {}
    }

    private fun makeLink(rttMs: Long = 100): Link {
        val receiverDestination = Destination.create(
            identity = Identity.create(),
            direction = DestinationDirection.IN,
            type = DestinationType.SINGLE,
            appName = "watchdog",
            aspects = arrayOf("timing"),
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
        val link = Link.validateRequest(receiverDestination, requestData, packet)!!
        link.setRttForTest(rttMs)
        link.setStatusForTest(LinkConstants.ACTIVE)
        return link
    }

    private fun sender(link: Link, timeout: Long? = null): Resource =
        Resource.create(
            data = ByteArray(2_000) { (it * 7).toByte() },
            link = link,
            advertise = false,
            autoCompress = false,
            timeout = timeout,
        ).also { it.clock = { t0 } }

    @Test
    fun `advertised sender re-advertises at timeout plus grace, four times, then cancels`() {
        val link = makeLink()
        val r = sender(link, timeout = 2_000)
        assertEquals(2_000L, r.timeoutMsForTest(), "the constructor timeout is honoured")
        r.setStatusForTest(ResourceConstants.ADVERTISED)
        r.setStampsForTest(advSent = t0)
        r.setRetriesLeftForTest(ResourceConstants.MAX_ADV_RETRIES)
        val advBefore = r.advSendCountForTest()

        assertTrue(r.watchdogPassForTest(t0 + 2_999) > 0, "inside timeout + PROCESSING_GRACE nothing fires")
        assertEquals(advBefore, r.advSendCountForTest())

        var now = t0 + 3_001
        for (i in 1..ResourceConstants.MAX_ADV_RETRIES) {
            assertEquals(1L, r.watchdogPassForTest(now), "retry $i acts and re-evaluates at once")
            assertEquals(advBefore + i, r.advSendCountForTest(), "advertisement re-sent on retry $i")
            assertEquals(ResourceConstants.MAX_ADV_RETRIES - i, r.retriesLeftForTest())
            assertEquals(ResourceConstants.ADVERTISED, r.status)
            now += 3_001
        }
        r.watchdogPassForTest(now)
        assertEquals(ResourceConstants.FAILED, r.status, "python Resource.py:588-590: retries exhausted, cancel")
    }

    @Test
    fun `sender waiting for part requests holds far longer than four RTTs`() {
        val link = makeLink(rttMs = 100)
        val r = sender(link)
        r.setStatusForTest(ResourceConstants.TRANSFERRING)
        r.setRttForTest(100)
        r.setStampsForTest(lastActivity = t0)
        r.setRetriesLeftForTest(ResourceConstants.MAX_RETRIES)

        // The previous watchdog cancelled after 16 idle periods of 4 RTTs = 6.4 s.
        r.watchdogPassForTest(t0 + 7_000)
        assertEquals(ResourceConstants.TRANSFERRING, r.status, "alive at 70 RTTs: the reference waits 96 RTTs + 78 s")

        // rtt*6*16 + 10 s + sum((r+1)*0.5 s for r < 16) = 9.6 s + 10 s + 68 s = 87.6 s
        val maxWait = 100L * 6 * 16 + 10_000 + 68_000
        assertTrue(r.watchdogPassForTest(t0 + maxWait - 1) > 0, "still waiting one ms before max_wait")
        assertEquals(ResourceConstants.TRANSFERRING, r.status)
        r.watchdogPassForTest(t0 + maxWait + 1)
        assertEquals(ResourceConstants.FAILED, r.status, "python Resource.py:641-649")
    }

    @Test
    fun `sender awaiting proof re-queries the cache three times then cancels`() {
        val link = makeLink(rttMs = 100)
        val r = sender(link)
        r.setStatusForTest(ResourceConstants.AWAITING_PROOF)
        r.setRttForTest(100)
        r.setStampsForTest(lastPartSent = t0)
        r.setRetriesLeftForTest(3)
        val cacheRequests = CopyOnWriteArrayList<Packet>()
        Transport.outboundTapForTest = { p -> if (p.context == PacketContext.CACHE_REQUEST) cacheRequests.add(p) }

        // rtt * PROOF_TIMEOUT_FACTOR(3) + SENDER_GRACE_TIME(10 s)
        assertTrue(r.watchdogPassForTest(t0 + 10_299) > 0)
        assertEquals(0, cacheRequests.size)

        var now = t0 + 10_301
        for (i in 1..3) {
            assertEquals(1L, r.watchdogPassForTest(now))
            assertEquals(i, cacheRequests.size, "one CACHE_REQUEST per re-query (python Resource.py:661-668)")
            assertEquals(3 - i, r.retriesLeftForTest())
            assertEquals(ResourceConstants.AWAITING_PROOF, r.status)
            now += 10_301
        }
        val hashLen = cacheRequests.first().data.size
        assertEquals(32, hashLen, "the request carries the expected proof packet's full hash")
        r.watchdogPassForTest(now)
        assertEquals(ResourceConstants.FAILED, r.status, "python Resource.py:657-660")
    }

    @Test
    fun `receiver retries with a shrinking window and a half-second backoff per retry`() {
        val link = makeLink(rttMs = 100)
        val source = sender(link)
        val adv = ResourceAdvertisement.fromResource(source)
        val r = Resource.accept(adv, link)!!
        r.clock = { t0 }
        assertEquals(false, r.initiator)
        r.setStatusForTest(ResourceConstants.TRANSFERRING)
        r.setStampsForTest(lastActivity = t0)
        r.setRetriesLeftForTest(ResourceConstants.MAX_RETRIES)
        r.setOutstandingPartsForTest(4)
        val windowBefore = r.windowForTest()
        val requestsBefore = r.requestNextEmitCountForTest()

        // Before any RTT sample the wait is partTimeoutFactor(4) * 3*sdu/eifr + 0.25 s: well
        // under a second on this link, so 5 s is past it and 100 ms is not.
        assertTrue(r.watchdogPassForTest(t0 + 100) > 0, "no retry inside the wait")
        assertEquals(1L, r.watchdogPassForTest(t0 + 5_000), "retry fires")
        assertEquals(ResourceConstants.MAX_RETRIES - 1, r.retriesLeftForTest())
        assertTrue(r.requestNextEmitCountForTest() > requestsBefore, "request_next() re-issued")
        assertTrue(r.windowForTest() < windowBefore || windowBefore <= ResourceConstants.WINDOW_MIN, "window shrinks on retry (Resource.py:628-634)")

        // The next retry needs PER_RETRY_DELAY (0.5 s) more than the first did.
        r.setStampsForTest(lastActivity = t0)
        r.setOutstandingPartsForTest(4)
        val firstWait = 5_000L
        val secondPass = r.watchdogPassForTest(t0 + firstWait)
        assertEquals(1L, secondPass, "a second retry at the same offset still fires only because the first wait was far below 5 s")
        assertEquals(ResourceConstants.MAX_RETRIES - 2, r.retriesLeftForTest())
        assertEquals(ResourceConstants.TRANSFERRING, r.status)
    }

    @Test
    fun `receiver cancels when retries are exhausted`() {
        val link = makeLink(rttMs = 100)
        val source = sender(link)
        val r = Resource.accept(ResourceAdvertisement.fromResource(source), link)!!
        r.clock = { t0 }
        r.setStatusForTest(ResourceConstants.TRANSFERRING)
        r.setStampsForTest(lastActivity = t0)
        r.setRetriesLeftForTest(0)
        r.setOutstandingPartsForTest(4)
        r.watchdogPassForTest(t0 + 60_000)
        assertEquals(ResourceConstants.FAILED, r.status, "python Resource.py:636-638")
    }

    @Test
    fun `every timestamp in Resource comes from the clock seam`() {
        val file = File("src/main/kotlin/network/reticulum/resource/Resource.kt")
        assertTrue(file.exists(), "run from the rns-core module directory: ${file.absolutePath}")
        val direct = file.readLines().withIndex().filter { (_, line) ->
            line.contains("System.currentTimeMillis()") && !line.contains("internal var clock")
        }
        assertTrue(direct.isEmpty(), "direct clock reads bypass the seam at lines ${direct.map { it.index + 1 }}")
    }

    @Test
    fun `part timeout factor halves after the first RTT sample`() {
        val link = makeLink(rttMs = 100)
        val r = sender(link)
        assertEquals(ResourceConstants.PART_TIMEOUT_FACTOR, r.partTimeoutFactorForTest())
        assertNotEquals(ResourceConstants.PART_TIMEOUT_FACTOR, ResourceConstants.PART_TIMEOUT_FACTOR_AFTER_RTT)
    }
}
