package network.reticulum.transport

import network.reticulum.common.DestinationDirection
import network.reticulum.common.DestinationType
import network.reticulum.common.InterfaceMode
import network.reticulum.common.RnsConstants
import network.reticulum.destination.Destination
import network.reticulum.identity.Identity
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.security.SecureRandom

/**
 * An announce that answers a path request we are waiting on must never be held by
 * ingress limiting (python Transport.py:1819-1821 checks `path_requests` and
 * `discovery_path_requests` BEFORE `should_ingress_limit()`).
 *
 * Ingress limiting exists to shed *unsolicited* announce floods. A solicited response
 * is the one mechanism by which an unknown destination becomes a known one, so holding
 * it defeats path discovery: the requester learns nothing, waits out its budget, then
 * sends with no route. The symptom is a path request that times out under load on an
 * otherwise healthy interface — exactly what a shared KISS/LoRa segment produces.
 *
 * The two cases are deliberately identical apart from the pending path request, so the
 * only thing under test is the exemption. Removing `answersPendingPathRequest` from the
 * guard in `processAnnounce` must fail the second case.
 */
class AnnounceIngressLimitPathRequestTest {

    /** Interface that is always over its ingress allocation, and counts what it holds. */
    private class LimitingInterface(override val name: String) : InterfaceRef {
        override val hash: ByteArray = ByteArray(RnsConstants.TRUNCATED_HASH_BYTES) { 0xC4.toByte() }
        override val canSend = true
        override val canReceive = true
        override val online = true
        override val mode = InterfaceMode.FULL
        override val bitrate = 1_000_000
        override val hwMtu = 1064
        override var tunnelId: ByteArray? = null
        override var wantsTunnel = false
        override fun send(data: ByteArray) = Unit

        var held = 0
            private set

        override fun shouldIngressLimit(): Boolean = true

        override fun holdAnnounce(
            destinationHash: ByteArray,
            raw: ByteArray,
            hops: Int,
            receivingInterface: InterfaceRef,
        ) {
            held++
        }

        override fun heldAnnounceCount(): Int = held
    }

    private lateinit var iface: LimitingInterface

    @BeforeEach
    fun setup() {
        try { Transport.stop() } catch (_: Exception) {}
        Transport.start(Identity.create(), enableTransport = false)
        iface = LimitingInterface("limiting-${System.nanoTime()}")
        Transport.registerInterface(iface)
    }

    @AfterEach
    fun teardown() {
        try { Transport.deregisterInterface(iface) } catch (_: Exception) {}
        try { Transport.stop() } catch (_: Exception) {}
    }

    /** Correctly signed, ratchetless HEADER_1 announce — the hold must be the only reason it fails. */
    private fun signedAnnounceRaw(identity: Identity, dest: Destination): ByteArray {
        val publicKey = identity.getPublicKey()
        val nameHash = dest.nameHash
        val randomHash = ByteArray(10).also { SecureRandom().nextBytes(it) }
        val appData = ByteArray(16) { 0x2A }
        // python Identity.py:545 — signature covers dest_hash‖pub‖name_hash‖random_hash‖app_data
        val signedData = dest.hash + publicKey + nameHash + randomHash + appData
        val signature = identity.sign(signedData)
        val data = publicKey + nameHash + randomHash + signature + appData

        val flags = 0x01 // HEADER_1, ctx flag unset, BROADCAST, SINGLE, ANNOUNCE
        return byteArrayOf(flags.toByte(), 0x00) + dest.hash + byteArrayOf(0x00) + data
    }

    // Destination.create registers with Transport; a local destination is skipped before the
    // ingress branch is reached (python Transport.py:2175-2176), so deregister to model a peer.
    private fun foreignDestination(identity: Identity): Destination =
        Destination.create(
            identity = identity,
            direction = DestinationDirection.IN,
            type = DestinationType.SINGLE,
            appName = "ingress",
            aspects = arrayOf("pathreq", "exempt"),
        ).also { Transport.deregisterDestination(it) }

    @Test
    fun `an unsolicited announce is held while the interface is ingress limiting`() {
        val identity = Identity.create()
        val dest = foreignDestination(identity)

        Transport.inbound(signedAnnounceRaw(identity, dest), iface)
        Transport.awaitInboundIdle()

        assertEquals(1, iface.held, "an unsolicited announce must be held while over allocation")
        assertFalse(Transport.hasPath(dest.hash), "a held announce must not have created a path")
    }

    @Test
    fun `an announce answering a pending path request is exempt from ingress limiting`() {
        val identity = Identity.create()
        val dest = foreignDestination(identity)

        // Arms Transport.pathRequests for this destination. The request packet goes out on
        // the stub interface, whose send() is a no-op.
        Transport.requestPath(dest.hash)
        assertTrue(
            Transport.hasPendingPathRequestForTest(dest.hash),
            "precondition: requestPath must have armed the pending-request table",
        )

        Transport.inbound(signedAnnounceRaw(identity, dest), iface)
        Transport.awaitInboundIdle()

        assertEquals(
            0,
            iface.held,
            "an announce answering our own path request must not be held, even over allocation",
        )
        assertTrue(
            Transport.hasPath(dest.hash),
            "the solicited announce must be processed and the path learned",
        )
    }
}
