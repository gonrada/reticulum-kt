package network.reticulum.link

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import network.reticulum.Reticulum
import network.reticulum.channel.Channel
import network.reticulum.channel.ChannelOutlet
import network.reticulum.channel.MessageState
import network.reticulum.common.DestinationType
import network.reticulum.common.RnsLog
import network.reticulum.common.PacketContext
import network.reticulum.common.PacketType
import network.reticulum.common.RnsConstants
import network.reticulum.common.TransportType
import network.reticulum.common.toHexString
import network.reticulum.crypto.CryptoProvider
import network.reticulum.crypto.Hashes
import network.reticulum.crypto.Token
import network.reticulum.crypto.defaultCryptoProvider
import network.reticulum.destination.Destination
import network.reticulum.identity.Identity
import network.reticulum.packet.Packet
import network.reticulum.packet.PacketReceipt
import network.reticulum.transport.Transport
import org.jetbrains.annotations.TestOnly
import org.msgpack.core.MessagePack
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import kotlin.concurrent.thread

/**
 * Callbacks for link events.
 */
class LinkCallbacks {
    var linkEstablished: ((Link) -> Unit)? = null
    var linkClosed: ((Link) -> Unit)? = null
    var packet: ((ByteArray, Packet) -> Unit)? = null
    var resourceStarted: ((Any) -> Unit)? = null
    var resourceConcluded: ((Any) -> Unit)? = null
    var remoteIdentified: ((Link, Identity) -> Unit)? = null
}

/**
 * Represents an encrypted link to a remote peer.
 *
 * Links provide encrypted, authenticated communication channels between
 * two Reticulum peers. A link is established through a handshake protocol
 * that uses ECDH key exchange and Ed25519 signatures.
 *
 * Usage for initiator:
 * ```kotlin
 * val link = Link.create(destination) { link ->
 *     println("Link established!")
 * }
 * ```
 *
 * Usage for receiver (via Destination):
 * ```kotlin
 * destination.setLinkEstablishedCallback { link ->
 *     link.setPacketCallback { data, packet ->
 *         // Handle received data
 *     }
 * }
 * ```
 */
class Link private constructor(
    private val crypto: CryptoProvider,
    /** The destination this link connects to (null for incoming links). */
    val destination: Destination?,
    /** Whether this side initiated the link. */
    val initiator: Boolean,
    /** The owner destination for incoming links. */
    private val owner: Destination?,
    /** Encryption mode for this link. */
    val mode: Int = LinkConstants.MODE_DEFAULT,
) {
    companion object {
        private val linkCounter = AtomicInteger(0)

        // Shared coroutine scope for all link watchdogs (battery efficient on Android)
        private val watchdogScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        private val activeWatchdogs = ConcurrentHashMap<Int, Job>()

        /**
         * Test-only race inducer: when > 0, pauses for the configured number
         * of milliseconds at named seams in the link establishment path. Used
         * by reticulum-conformance to deterministically widen narrow race
         * windows so a regression at a specific seam fails reliably instead
         * of intermittently.
         *
         * Defaults to 0 (no-op). Production callers MUST NOT set this — it
         * only exists for test injection via the bridge's
         * `wire_set_race_inducer` command.
         *
         * Currently-instrumented seams:
         *  - "post-prove": sleeps in `validateRequest` immediately after
         *    `link.prove()` returns, before the function exits. Used to
         *    verify that all bookkeeping needed for inbound DATA is
         *    COMPLETE by the time prove() returns — the invariant fixed
         *    in PR #54.
         *
         * The sleep delegates to `Transport.raceInducerSleepReleasingJobsLock`
         * so it temporarily drops `jobsLock` for the sleep duration. Without
         * that, `validateRequest`'s caller (`Transport.ingest`) would still
         * be holding `jobsLock`, serializing concurrently-arriving DATA
         * packets behind the lock and defeating the test's intended race
         * window (per Greptile review on this PR).
         */
        @TestOnly
        @Volatile
        var raceInducerPostProveDelayMs: Long = 0L

        /**
         * Cancel all watchdog coroutines. Used during shutdown.
         */
        internal fun cancelAllWatchdogs() {
            activeWatchdogs.values.forEach { it.cancel() }
            activeWatchdogs.clear()
        }

        // Resource strategy constants
        const val ACCEPT_NONE = 0x00
        const val ACCEPT_APP = 0x01
        const val ACCEPT_ALL = 0x02

        // Keepalive payloads (Python Link.py: bytes([0xFF]) request, bytes([0xFE]) response).
        // Shared, never mutated — Packet stores data by reference and only reads it.
        private val KEEPALIVE_REQUEST = byteArrayOf(0xFF.toByte())
        private val KEEPALIVE_RESPONSE = byteArrayOf(0xFE.toByte())

        /**
         * Create an outgoing link to a destination.
         *
         * @param destination The destination to connect to (must be SINGLE type)
         * @param establishedCallback Optional callback when link is established
         * @param closedCallback Optional callback when link is closed
         * @param mode Encryption mode (default: AES-256-CBC)
         * @return The new Link instance
         */
        fun create(
            destination: Destination,
            establishedCallback: ((Link) -> Unit)? = null,
            closedCallback: ((Link) -> Unit)? = null,
            mode: Int = LinkConstants.MODE_DEFAULT,
        ): Link {
            require(destination.type == DestinationType.SINGLE) {
                "Links can only be established to SINGLE destination type"
            }

            val link =
                Link(
                    crypto = defaultCryptoProvider(),
                    destination = destination,
                    initiator = true,
                    owner = null,
                    mode = mode,
                )

            establishedCallback?.let { link.callbacks.linkEstablished = it }
            closedCallback?.let { link.callbacks.linkClosed = it }

            link.initializeAsInitiator()
            return link
        }

        /**
         * Validate an incoming link request and create a link if valid.
         *
         * @param owner The destination that received the link request
         * @param data The link request data
         * @param packet The link request packet
         * @return The new Link if valid, null otherwise
         */
        fun validateRequest(
            owner: Destination,
            data: ByteArray,
            packet: Packet,
        ): Link? {
            if (data.size != LinkConstants.ECPUBSIZE &&
                data.size != LinkConstants.ECPUBSIZE + LinkConstants.LINK_MTU_SIZE
            ) {
                log("Invalid link request payload size: ${data.size}")
                return null
            }

            // Bound concurrent half-open receiver links so a flood of link requests
            // cannot accumulate key-agreement state and watchdogs without limit.
            // validateRequest runs serialized under Transport's jobs lock, so the
            // count read is race-safe.
            if (Transport.pendingLinkCount() >= LinkConstants.MAX_PENDING_LINKS) {
                log("Half-open link limit (${LinkConstants.MAX_PENDING_LINKS}) reached; dropping link request")
                return null
            }

            return try {
                val peerPubBytes = data.copyOfRange(0, LinkConstants.KEYSIZE)
                val peerSigPubBytes = data.copyOfRange(LinkConstants.KEYSIZE, LinkConstants.ECPUBSIZE)

                val link =
                    Link(
                        crypto = defaultCryptoProvider(),
                        destination = null,
                        initiator = false,
                        owner = owner,
                        mode = modeFromLrPacket(packet),
                    )

                link.loadPeer(peerPubBytes, peerSigPubBytes)
                link.initializeAsReceiver()
                link.setLinkId(packet)

                // Handle MTU signalling if present. python: `mtu_from_lr_packet(packet)
                // or RNS.Reticulum.MTU` (Link.py:205) — a signalled MTU of 0 is falsy
                // there and normalises to the default; here it would make mdu (and
                // Resource.sdu) negative.
                if (data.size == LinkConstants.ECPUBSIZE + LinkConstants.LINK_MTU_SIZE) {
                    link.mtu = mtuFromLrPacket(packet)?.takeIf { it > 0 } ?: RnsConstants.MTU
                }

                link.mdu = LinkConstants.calculateMdu(link.mtu)
                link.attachedDestination = owner

                // Calculate establishment timeout
                link.establishmentTimeout = LinkConstants.ESTABLISHMENT_TIMEOUT_PER_HOP *
                    maxOf(1, packet.hops) + LinkConstants.KEEPALIVE
                link.establishmentCost += packet.raw?.size ?: 0

                log("Validating link request ${link.linkId.toHexString()}")

                // Set attached interface (Python: link.attached_interface = packet.receiving_interface).
                // Transport.outbound already confines LINK packets to this interface
                // (the broadcast branch filters on attachedInterfaceHash), so the
                // LRPROOF below does not need a pathTable entry to be routed; the
                // entry is registered only after prove() succeeds — see below.
                link.attachedInterfaceHash = packet.receivingInterfaceHash

                // Perform handshake (derives crypto state) BEFORE publishing
                // the link via Transport.registerLink. The order here is the
                // receiver-side mirror of the sender-side fix in #53: any
                // side-effect that makes the link visible to the peer must
                // happen AFTER all bookkeeping the receiver needs to dispatch
                // inbound traffic.
                //
                // Specifically: link.prove() sends the LRPROOF on the wire,
                // which the sender treats as "link is up" and begins sending
                // user DATA on. Transport.processData() looks up the receiver
                // link in activeLinks (Transport.kt:3752); if registerLink
                // hasn't run yet when DATA arrives, the lookup misses and
                // the packet is dropped silently. On a fast loopback
                // kotlin->reference->kotlin path, the sender's first DATA
                // can race ahead of Transport.registerLink; this manifested
                // as the residual #42 first-packet-of-burst loss surviving
                // the sender-side fix in #53.
                link.handshake()
                link.requestTime = System.currentTimeMillis()
                Transport.registerLink(link)
                link.lastInbound = System.currentTimeMillis()
                link.startWatchdog()

                // Now safe to send LRPROOF — receiver is fully wired to
                // accept inbound DATA on this link. If prove() throws after
                // registerLink/startWatchdog have run, we must roll the link
                // back out of activeLinks and stop the watchdog so it doesn't
                // sit in HANDSHAKE state until the establishment timeout
                // fires (zombie-link cleanup, per Greptile review on #54).
                try {
                    link.prove()
                } catch (proveError: Exception) {
                    // teardownInternal(..., sendClosePacket = false) sets status=CLOSED,
                    // calls stopWatchdog() and Transport.deregisterLink(link) — the full
                    // unwind for the partial registration we just did — and sends
                    // nothing. Python's validate_request sends nothing on this path
                    // either (Link.py:221-223): the peer has not authenticated, so it
                    // is never answered with an encrypted LINKCLOSE.
                    log("Link prove() failed after registration; rolling back: ${proveError.message}")
                    runCatching { link.teardownInternal(LinkConstants.TEARDOWN_REASON_DESTINATION_CLOSED, sendClosePacket = false) }
                    throw proveError
                }

                // python Link.py:227 stamps request_time AFTER prove(): the responder's
                // measured RTT (rtt_packet: now - request_time) runs from the proof going
                // out to the RTT packet coming back, and excludes the cost of signing and
                // sending the proof. The stamp above, before startWatchdog(), stays so the
                // HANDSHAKE timeout has a base; this one is the measurement basis. With the
                // early stamp alone, a cold JVM's first Ed25519 signature landed in the
                // responder's RTT, pushed it past the KEEPALIVE_MIN floor, and gave the
                // responder a longer keepalive than the initiator — whose on-time
                // keepalive the responder's reply throttle then skipped.
                link.requestTime = System.currentTimeMillis()

                // Register the link path only now that the request has fully
                // succeeded. Registering before handshake()/prove() let any
                // unauthenticated LINKREQUEST with a bad mode byte (handshake throws)
                // or mode 0 (prove throws) leave a long-lived pathTable row behind,
                // unbounded per distinct link id. python registers nothing before
                // prove() (Link.py:220-224) and never puts link ids in its path table.
                packet.receivingInterfaceHash?.let { interfaceHash ->
                    Transport.registerLinkPath(link.linkId, interfaceHash, packet.hops)
                }

                // Test-only race inducer (zero in production; settable via the
                // conformance bridge's wire_set_race_inducer command). Sleeps
                // here to widen the post-prove window so a test can verify
                // that any DATA arriving while we're "stuck" still gets
                // dispatched correctly — proving that registerLink + the
                // other bookkeeping above is sufficient for inbound DATA
                // handling.
                //
                // We delegate to Transport.raceInducerSleepReleasingJobsLock
                // because validateRequest is called transitively from
                // Transport.ingest under jobsLock.withLock; a plain
                // Thread.sleep here would serialize concurrent DATA packets
                // behind the lock, neutralizing the race window the test is
                // trying to expose (per Greptile review on this PR).
                val postProveDelay = raceInducerPostProveDelayMs
                if (postProveDelay > 0L) {
                    try {
                        Transport.raceInducerSleepReleasingJobsLock(postProveDelay)
                    } catch (ie: InterruptedException) {
                        // Mirror the proveError rollback above: registerLink +
                        // startWatchdog have already run, so an exception that
                        // escapes here would leave a zombie link in activeLinks
                        // with a running watchdog. Tear down before re-throwing
                        // so the outer `catch (e: Exception)` returns null on a
                        // clean state (per Greptile review on this PR).
                        log("Race inducer sleep interrupted; rolling back: ${ie.message}")
                        runCatching { link.teardown(LinkConstants.TEARDOWN_REASON_DESTINATION_CLOSED) }
                        Thread.currentThread().interrupt()
                        throw ie
                    }
                }

                log("Link request ${link.linkId.toHexString()} accepted")
                link
            } catch (e: Exception) {
                // If the exception is an InterruptedException, CLEAR the
                // thread's interrupt flag here. The inner
                // Transport.raceInducerSleepReleasingJobsLock catch
                // re-sets it before rethrow (standard Java pattern when
                // propagating cancellation), but at THIS layer we're
                // intentionally swallowing the interrupt — we've handled
                // it by aborting link establishment and returning null,
                // and the ingest thread caller will continue its receive
                // loop. Leaving the flag set would cause its next
                // interruptible operation (Thread.sleep, blocking I/O,
                // lockInterruptibly()) to throw spuriously, attributing
                // a cancellation that was intended only for this single
                // link-setup attempt to unrelated work in the loop.
                // Thread.interrupted() is the JDK's check-and-clear
                // primitive for exactly this case.
                if (e is InterruptedException) Thread.interrupted()
                log("Validating link request failed: ${e.message}")
                null
            }
        }

        /**
         * Compute link ID from link request packet.
         */
        fun linkIdFromLrPacket(packet: Packet): ByteArray {
            var hashable = packet.getHashablePart()
            if (packet.data.size > LinkConstants.ECPUBSIZE) {
                val diff = packet.data.size - LinkConstants.ECPUBSIZE
                hashable = hashable.copyOf(hashable.size - diff)
            }
            return Hashes.truncatedHash(hashable)
        }

        /**
         * Extract MTU from link request packet.
         */
        internal fun mtuFromLrPacket(packet: Packet): Int? {
            if (packet.data.size != LinkConstants.ECPUBSIZE + LinkConstants.LINK_MTU_SIZE) {
                return null
            }
            val offset = LinkConstants.ECPUBSIZE
            return ((packet.data[offset].toInt() and 0xFF) shl 16) or
                ((packet.data[offset + 1].toInt() and 0xFF) shl 8) or
                (packet.data[offset + 2].toInt() and 0xFF) and LinkConstants.MTU_BYTEMASK
        }

        /**
         * Extract mode from link request packet.
         */
        internal fun modeFromLrPacket(packet: Packet): Int {
            if (packet.data.size > LinkConstants.ECPUBSIZE) {
                return (packet.data[LinkConstants.ECPUBSIZE].toInt() and LinkConstants.MODE_BYTEMASK) shr 5
            }
            return LinkConstants.MODE_DEFAULT
        }

        /**
         * Create signalling bytes for MTU and mode.
         */
        fun signallingBytes(
            mtu: Int,
            mode: Int,
        ): ByteArray {
            require(mode in LinkConstants.ENABLED_MODES) {
                "Requested link mode ${LinkConstants.modeDescription(mode)} not enabled"
            }
            val value =
                (mtu and LinkConstants.MTU_BYTEMASK) +
                    (((mode shl 5) and LinkConstants.MODE_BYTEMASK) shl 16)
            return byteArrayOf(
                ((value shr 16) and 0xFF).toByte(),
                ((value shr 8) and 0xFF).toByte(),
                (value and 0xFF).toByte(),
            )
        }

        /**
         * Conformance test seam: build a genuine initiator LINKREQUEST payload
         * (pub_bytes || sig_pub_bytes || signalling_bytes) with freshly-generated
         * ephemeral X25519/Ed25519 keys, WITHOUT putting it on the wire. This is
         * the kotlin equivalent of the reference bridge patching Packet.send off
         * during _build_initiator_request_data (reticulum-conformance reference/
         * wire_tcp.py): initializeAsInitiator() bundles the genuine assembly with
         * the wire send, so this re-runs ONLY the assembly via the same crypto +
         * signallingBytes() the handshake uses, at the default MTU (Reticulum.MTU,
         * the value a no-MTU-discovery next hop yields). No port logic — pure
         * read-only assembly for the link-request adversarial commands.
         */
        /** Result holder for [buildInitiatorRequestDataForTest]. */
        class InitiatorRequestDataForTest(
            val requestData: ByteArray,
            val pubBytes: ByteArray,
            val sigPubBytes: ByteArray,
            val mtu: Int,
            val mode: Int,
        )

        fun buildInitiatorRequestDataForTest(
            mode: Int = LinkConstants.MODE_DEFAULT,
        ): InitiatorRequestDataForTest {
            val crypto = defaultCryptoProvider()
            val x = crypto.generateX25519KeyPair()
            val ed = crypto.generateEd25519KeyPair()
            val mtu = RnsConstants.MTU
            val signalling = signallingBytes(mtu, mode)
            val requestData = x.publicKey + ed.publicKey + signalling
            return InitiatorRequestDataForTest(requestData, x.publicKey, ed.publicKey, mtu, mode)
        }

        private fun log(message: String) {
            RnsLog.log(RnsLog.INFO, "Link", message)
        }

        /** Lazy per-packet variant: the message is only built when DEBUG is enabled. */
        private inline fun logDebug(message: () -> String) {
            RnsLog.log(RnsLog.DEBUG, "Link", message)
        }
    }

    // Unique per-instance ID (avoids watchdog collisions when two links share the same linkId)
    private val instanceId: Int = linkCounter.getAndIncrement()

    // Link identity
    var linkId: ByteArray = ByteArray(0)
        private set
    val hash: ByteArray get() = linkId

    // State
    @Volatile
    var status: Int = LinkConstants.PENDING
        private set

    /** Reason for link teardown. */
    var teardownReason: Int = LinkConstants.TEARDOWN_REASON_UNKNOWN
        private set

    // Timing
    var rtt: Long? = null
        private set

    /**
     * Conformance test seam: set the measured RTT (milliseconds). Python's
     * `RNS.Link.rtt` is a freely-mutable public attribute; kotlin keeps the
     * setter private, so the wire bridge's wire_link_set_rtt / wire_channel_
     * profile / wire_channel_timeout_formula commands use this to drive the
     * Channel rate-promotion bands (which read outlet.rtt == link.rtt live).
     * Mirrors the reference's `link.rtt = rtt`. No port logic beyond the assign.
     */
    fun setRttForTest(rttMs: Long?) {
        rtt = rttMs
    }

    /** Drive the watchdog's request-timeout pass at a chosen clock. */
    @TestOnly
    @network.reticulum.RnsTestSeam
    internal fun checkRequestTimeoutsForTest(now: Long) = checkRequestTimeouts(now)

    /** Register a receipt as if `request()` had sent it, without a link round trip. */
    @TestOnly
    @network.reticulum.RnsTestSeam
    internal fun addPendingRequestForTest(receipt: RequestReceipt) {
        synchronized(pendingRequests) { pendingRequests.add(receipt) }
    }

    @TestOnly
    @network.reticulum.RnsTestSeam
    internal fun isPendingRequestForTest(receipt: RequestReceipt): Boolean =
        synchronized(pendingRequests) { pendingRequests.contains(receipt) }

    /**
     * Conformance test seam: when true, every PacketReceipt validation on this
     * link's packets returns false (the proof never validates), even across
     * resends that build fresh receipts. Mirrors the reference neutering
     * `packet.receipt.validate_proof` for wire_channel_send(drop_acks=true) so
     * the Channel retransmits to _max_tries and tears the link down. Honored in
     * PacketReceipt.validateProof / validateLinkProof. Not used in production.
     */
    @Volatile
    @network.reticulum.RnsTestSeam
    var failProofValidationForTest: Boolean = false

    var mtu: Int = RnsConstants.MTU
        private set
    var mdu: Int = LinkConstants.calculateMdu()
        private set
    var establishmentCost: Int = 0
        private set
    var establishmentTimeout: Long = 0
        private set

    /** Expected hop count for LRPROOF validation (Python: self.expected_hops). */
    var expectedHops: Int = 0
        private set

    // Callbacks
    val callbacks = LinkCallbacks()

    /**
     * Get the peer's combined public key (X25519 + Ed25519).
     * This can be used to create an Identity from the link peer.
     * Returns null if peer keys are not yet loaded.
     */
    fun getPeerPublicKey(): ByteArray? {
        val x25519Key = peerPub ?: return null
        val ed25519Key = peerSigPub ?: return null
        return x25519Key + ed25519Key
    }

    // Timestamps
    private var requestTime: Long = 0

    /**
     * Wall-clock time the link was activated (status reached [LinkConstants.ACTIVE]),
     * or 0 if it never activated. Exposed read-only so LXMF-kt's direct-delivery
     * CLOSED-link handling can distinguish "was active, closed unexpectedly" from
     * "never activated" — Python LXMF reads `direct_link.activated_at != None`
     * (`LXMRouter.py` direct-delivery branch).
     */
    var activatedAt: Long = 0
        private set
    var lastInbound: Long = 0
        private set
    var lastOutbound: Long = 0
        private set
    var lastKeepalive: Long = 0
        private set
    var lastData: Long = 0
        private set

    /**
     * Backdate [lastOutbound] so the keepalive-response throttle opens. Exposed for the
     * conformance bridge, which has to drive the answering branch on a link that was just
     * established and therefore has a very recent outbound.
     */
    fun setLastOutboundForTest(value: Long) {
        lastOutbound = value
    }
    var lastProof: Long = 0
        private set

    /** When the link entered STALE, for the teardown grace window. */
    private var staleAt: Long = 0

    // Traffic counters
    val tx = AtomicLong(0)
    val rx = AtomicLong(0)
    val txBytes = AtomicLong(0)
    val rxBytes = AtomicLong(0)

    // Physical stats
    private var trackPhyStats: Boolean = false
    private var phyRssi: Int? = null
    private var phySnr: Float? = null
    private var phyQ: Float? = null

    // Timeout factors
    var trafficTimeoutFactor: Int = LinkConstants.TRAFFIC_TIMEOUT_FACTOR
    var keepaliveTimeoutFactor: Int = LinkConstants.KEEPALIVE_TIMEOUT_FACTOR
    var keepalive: Long = LinkConstants.KEEPALIVE
    var staleTime: Long = LinkConstants.STALE_TIME

    // Attached interface/destination (public to allow initiator links to attach a destination
    // for request handling — matches Python's Link.attached_interface which is also public)
    var attachedDestination: Destination? = null

    /**
     * The destination whose request handlers serve requests arriving on this link.
     *
     * python keeps one `self.destination` for both directions: the OUT destination the
     * initiator opened to, and, for an inbound link, the owning IN destination assigned at
     * `Link.py:214`. Ours splits those across three fields, so resolve them in that order.
     */
    val servingDestination: Destination?
        get() = owner ?: attachedDestination ?: destination

    /** Exposed for the conformance bridge. */
    fun destinationForTest(): Destination? = servingDestination

    // Hash of the interface this link is attached to (Python: link.attached_interface)
    var attachedInterfaceHash: ByteArray? = null
    private var remoteIdentity: Identity? = null

    // Cryptographic state
    private var prv: ByteArray? = null // X25519 private key
    private var pub: ByteArray? = null // X25519 public key
    private var sigPrv: ByteArray? = null // Ed25519 private key
    private var sigPub: ByteArray? = null // Ed25519 public key
    private var peerPub: ByteArray? = null // Peer's X25519 public key
    private var peerSigPub: ByteArray? = null // Peer's Ed25519 public key
    private var sharedKey: ByteArray? = null
    private var derivedKey: ByteArray? = null
    private var token: Token? = null

    // Watchdog uses shared coroutine scope (see companion object)

    // Resource tracking
    private val outgoingResources = mutableListOf<network.reticulum.resource.Resource>()
    private val incomingResources = mutableListOf<network.reticulum.resource.Resource>()

    /**
     * Partial reassembly of split transfers arriving on this link, keyed by the transfer's
     * original hash. Owned by the link so teardown releases it; see SegmentAccumulator.
     */
    internal val segmentAccumulators =
        java.util.concurrent.ConcurrentHashMap<network.reticulum.common.ByteArrayKey, network.reticulum.resource.SegmentAccumulator>()

    private var resourceStrategy: Int = ACCEPT_NONE
    private var resourceCallback: ((network.reticulum.resource.ResourceAdvertisement) -> Boolean)? = null

    // Resource performance tracking
    private var lastResourceWindow: Int? = null
    private var lastResourceEifr: Float? = null
    private var establishmentRate: Float? = null
    private var expectedRate: Float? = null

    // Request/response tracking
    internal val pendingRequests = mutableListOf<RequestReceipt>()

    // Channel support
    private var _channel: Channel? = null

    /**
     * Initialize as link initiator (outgoing link).
     */
    private fun initializeAsInitiator() {
        // Generate X25519 keypair
        val x25519KeyPair = crypto.generateX25519KeyPair()
        prv = x25519KeyPair.privateKey
        pub = x25519KeyPair.publicKey

        // Generate Ed25519 keypair for this link
        val ed25519KeyPair = crypto.generateEd25519KeyPair()
        sigPrv = ed25519KeyPair.privateKey
        sigPub = ed25519KeyPair.publicKey

        // Establishment timeout and expected hops (python Link.py:293-296): the
        // initiator waits first_hop_timeout(dest) + 6 s per hop, about 12 s at one
        // hop. The responder's formula (6 s per hop + KEEPALIVE, Link.py:215) was
        // used here before, so a link attempt on a dead path took 366 s to fail
        // and the path expiry behind it was delayed by as much. python's hops_to
        // reports PATHFINDER_M for an unknown path, which the timeout inherits.
        val hops = Transport.hopsTo(destination!!.hash) ?: network.reticulum.transport.TransportConstants.PATHFINDER_M
        expectedHops = hops
        establishmentTimeout = Transport.firstHopTimeout(destination.hash) +
            LinkConstants.ESTABLISHMENT_TIMEOUT_PER_HOP * maxOf(1, hops)

        // Query next-hop interface MTU for link MTU discovery (Python Link.py:308-314)
        val nhHwMtu = Transport.nextHopInterfaceHwMtu(destination.hash)
        val signalledMtu =
            if (Reticulum.LINK_MTU_DISCOVERY && nhHwMtu != null) {
                log("Signalling link MTU of $nhHwMtu for link")
                nhHwMtu
            } else {
                mtu // default RnsConstants.MTU (500)
            }
        val signallingBytes = signallingBytes(signalledMtu, mode)
        val requestData = pub!! + sigPub!! + signallingBytes

        // Create and send link request
        val packet =
            Packet.createRaw(
                destinationHash = destination.hash,
                data = requestData,
                packetType = PacketType.LINKREQUEST,
                destinationType = destination.type,
                transportType = TransportType.BROADCAST,
            )
        packet.pack()

        establishmentCost += packet.raw?.size ?: 0
        setLinkId(packet)

        Transport.registerLink(this)
        requestTime = System.currentTimeMillis()

        startWatchdog()
        // lastOutbound is stamped BEFORE every link send, as python's Packet.send() does
        // (Packet.py:302, before Transport.outbound). Stamping after the send put the
        // responder's keepalive-reply throttle (`now >= lastOutbound + keepalive`) at the
        // socket write plus however long the return through Transport took — lock
        // re-acquisition, log formatting — while the peer's watchdog fires its keepalive
        // exactly `keepalive` after it RECEIVED our packet. Under load the two crossed and
        // the reply was silently skipped. Same order at every site.
        hadOutbound()
        Transport.outbound(packet)

        log("Link request ${linkId.toHexString()} sent to ${destination.hexHash}")
    }

    /**
     * Load peer public keys.
     */
    private fun loadPeer(
        peerPubBytes: ByteArray,
        peerSigPubBytes: ByteArray,
    ) {
        this.peerPub = peerPubBytes.copyOf()
        this.peerSigPub = peerSigPubBytes.copyOf()
    }

    /**
     * Initialize as link receiver (incoming link).
     * Generates fresh X25519 keypair and uses owner's Ed25519 signing key.
     */
    private fun initializeAsReceiver() {
        // Generate fresh X25519 keypair for ECDH
        val x25519KeyPair = crypto.generateX25519KeyPair()
        prv = x25519KeyPair.privateKey
        pub = x25519KeyPair.publicKey

        // Use owner's Ed25519 signing key
        val ownerIdentity =
            owner?.identity
                ?: throw IllegalStateException("Cannot initialize receiver link: owner has no identity")
        sigPrv = ownerIdentity.sigPrv
        sigPub = ownerIdentity.sigPub
    }

    /**
     * Set link ID from packet.
     */
    private fun setLinkId(packet: Packet) {
        linkId = linkIdFromLrPacket(packet)
    }

    /**
     * Perform ECDH handshake and derive keys.
     */
    private fun handshake() {
        if (status != LinkConstants.PENDING || prv == null) {
            log("Handshake attempt with invalid state: $status")
            return
        }

        status = LinkConstants.HANDSHAKE

        // Perform ECDH
        sharedKey = crypto.x25519Exchange(prv!!, peerPub!!)

        // Derive encryption keys using HKDF
        val derivedKeyLength = LinkConstants.derivedKeyLength(mode)
        derivedKey =
            crypto.hkdf(
                length = derivedKeyLength,
                ikm = sharedKey!!,
                salt = getSalt(),
                info = getContext(),
            )
    }

    /**
     * Send link proof to complete handshake (receiver side).
     */
    private fun prove() {
        val signallingBytes = signallingBytes(mtu, mode)
        val signedData = linkId + pub!! + sigPub!! + signallingBytes

        // Sign with owner's identity
        val signature =
            owner!!.identity!!.sign(signedData)

        val proofData = signature + pub!! + signallingBytes

        val proof =
            Packet.createRaw(
                destinationHash = linkId,
                data = proofData,
                packetType = PacketType.PROOF,
                context = PacketContext.LRPROOF,
                destinationType = DestinationType.LINK,
            )
        proof.link = this

        hadOutbound() // before the send — see the comment in request()
        Transport.outbound(proof)
        establishmentCost += proof.raw?.size ?: 0
    }

    /**
     * Validate link proof and complete handshake (initiator side).
     *
     * @param packet The proof packet
     * @return true if proof is valid
     */
    fun validateProof(packet: Packet): Boolean {
        try {
            if (status != LinkConstants.PENDING) return false

            val sigLength = RnsConstants.SIGNATURE_SIZE
            val pubSize = LinkConstants.KEYSIZE

            // Check mode matches. python validate_proof RAISES on a mode
            // mismatch (Link.py:402) and the surrounding except sets
            // status=CLOSED (Link.py:452-453) — a mode-downgraded LRPROOF must
            // CLOSE the link, not leave it PENDING. Throw so the catch below
            // (which sets CLOSED, matching python) handles it.
            val receivedMode = modeFromLpPacket(packet)
            if (receivedMode != mode) {
                throw IllegalArgumentException(
                    "Invalid link mode $receivedMode in link request proof (expected $mode)",
                )
            }

            // Extract peer public key and signature. python accepts exactly
            // sig+pub (96) or sig+pub+signalling (99) bytes (Link.py:410, 416);
            // any other length is not a proof.
            if (packet.data.size != sigLength + pubSize &&
                packet.data.size != sigLength + pubSize + LinkConstants.LINK_MTU_SIZE
            ) {
                log("Invalid proof packet size: ${packet.data.size}")
                return false
            }

            val signature = packet.data.copyOfRange(0, sigLength)
            val peerPubBytes = packet.data.copyOfRange(sigLength, sigLength + pubSize)

            // Get peer's Ed25519 public key from destination's identity
            val peerSigPubBytes =
                destination!!
                    .identity!!
                    .getPublicKey()
                    .copyOfRange(LinkConstants.KEYSIZE, LinkConstants.ECPUBSIZE)

            // Verify the proof signature BEFORE mutating any link state.
            // loadPeer/handshake adopt the peer key and derive the session key,
            // moving the link PENDING -> HANDSHAKE. A forged LRPROOF — an on-path
            // attacker only needs the 16-byte linkId from the wire — must be
            // rejected with the link left PENDING, or it derives a bogus key and
            // pins the link out of PENDING so the genuine proof is dropped
            // (establishment DoS). signedData is built from the raw peer bytes,
            // which loadPeer would otherwise store verbatim.
            var signallingBytes = ByteArray(0)
            var confirmedMtu: Int? = null
            if (packet.data.size > sigLength + pubSize) {
                confirmedMtu = mtuFromLpPacket(packet)
                if (confirmedMtu != null) {
                    signallingBytes = signallingBytes(confirmedMtu, mode)
                }
            }

            val signedData = linkId + peerPubBytes + peerSigPubBytes + signallingBytes

            // Verify signature
            if (!destination.identity.validate(signature, signedData)) {
                log("Invalid link proof signature")
                return false
            }

            // Signature verified — now safe to adopt the peer key, derive the
            // session key, and record the confirmed MTU. A confirmed MTU of 0
            // normalises to the default (Link.py:441: `confirmed_mtu or MTU`).
            if (confirmedMtu != null) mtu = confirmedMtu.takeIf { it > 0 } ?: RnsConstants.MTU
            loadPeer(peerPubBytes, peerSigPubBytes)
            handshake()

            establishmentCost += packet.raw?.size ?: 0

            if (status != LinkConstants.HANDSHAKE) {
                log("Invalid state for proof validation: $status")
                return false
            }

            // Link is now active — but do NOT publish status=ACTIVE until every
            // piece of bookkeeping that an outbound send() depends on is in place.
            // `status` is @Volatile, so the final write at the end of this block
            // acts as a release fence: any thread that subsequently observes
            // status==ACTIVE is guaranteed to see the activeLinks membership,
            // attachedInterfaceHash, and pathTable entry written earlier.
            //
            // This ordering fixes the race behind #42: bridge callers that
            // `link_open(...)` and then immediately `link_send(first_payload)`
            // could previously observe status=ACTIVE during the ~16-line window
            // before registerLinkPath ran, causing Transport.outbound() to miss
            // the pathTable entry and drop the first DATA packet.
            rtt = System.currentTimeMillis() - requestTime
            remoteIdentity = destination.identity
            mdu = LinkConstants.calculateMdu(mtu)

            // Calculate establishment rate (bytes per ms)
            val linkRtt = rtt
            if (linkRtt != null && linkRtt > 0 && establishmentCost > 0) {
                establishmentRate = establishmentCost.toFloat() / linkRtt.toFloat()
            }

            Transport.activateLink(this)

            // Set attached interface (Python: self.attached_interface = packet.receiving_interface)
            attachedInterfaceHash = packet.receivingInterfaceHash

            // Register path for this link so outbound packets use correct interface
            packet.receivingInterfaceHash?.let { interfaceHash ->
                Transport.registerLinkPath(linkId, interfaceHash, packet.hops)
            }

            // Publish ACTIVE only after all the above is visible.
            activatedAt = System.currentTimeMillis()
            status = LinkConstants.ACTIVE

            log("Link ${linkId.toHexString()} established, RTT: ${rtt}ms")

            updateKeepalive()

            // Send RTT packet to server (Python expects this to activate the link on its side)
            sendRttPacket()

            // Notify callback
            callbacks.linkEstablished?.let { callback ->
                thread(isDaemon = true) {
                    callback(this)
                }
            }

            return true
        } catch (e: Exception) {
            log("Error validating proof: ${e.message}")
            status = LinkConstants.CLOSED
            return false
        }
    }

    private fun modeFromLpPacket(packet: Packet): Int {
        val sigLength = RnsConstants.SIGNATURE_SIZE
        val pubSize = LinkConstants.KEYSIZE
        if (packet.data.size > sigLength + pubSize) {
            return packet.data[sigLength + pubSize].toInt() shr 5
        }
        return LinkConstants.MODE_DEFAULT
    }

    private fun mtuFromLpPacket(packet: Packet): Int? {
        val sigLength = RnsConstants.SIGNATURE_SIZE
        val pubSize = LinkConstants.KEYSIZE
        val mtuOffset = sigLength + pubSize
        if (packet.data.size >= mtuOffset + LinkConstants.LINK_MTU_SIZE) {
            return ((packet.data[mtuOffset].toInt() and 0xFF) shl 16) or
                ((packet.data[mtuOffset + 1].toInt() and 0xFF) shl 8) or
                (packet.data[mtuOffset + 2].toInt() and 0xFF) and LinkConstants.MTU_BYTEMASK
        }
        return null
    }

    /**
     * Get the salt for key derivation.
     */
    fun getSalt(): ByteArray = linkId

    /**
     * Get the context for key derivation.
     */
    fun getContext(): ByteArray? = null

    /**
     * Encrypt data for transmission over the link.
     */
    fun encrypt(plaintext: ByteArray): ByteArray {
        if (token == null) {
            token = Token(derivedKey!!)
        }
        return token!!.encrypt(plaintext)
    }

    /**
     * Decrypt data received over the link.
     */
    fun decrypt(ciphertext: ByteArray): ByteArray? {
        // python Link.decrypt wraps the token decrypt in try/except and returns
        // None on failure (RNS 1.3.1 Link.py:decrypt; 1.1.x Link.py:1202-1209), so
        // a tampered/forged ciphertext (Token HMAC failure) is silently dropped
        // rather than propagating. All callers already treat a null return as "drop".
        return try {
            if (token == null) {
                token = Token(derivedKey!!)
            }
            token!!.decrypt(ciphertext)
        } catch (e: Exception) {
            log("Decryption failed on link ${linkId.toHexString()}: ${e.message}")
            null
        }
    }

    /**
     * Sign a message using this link's signing key.
     */
    fun sign(message: ByteArray): ByteArray = crypto.ed25519Sign(sigPrv!!, message)

    /**
     * Validate a signature from the peer.
     *
     * Returns the Ed25519 verification RESULT. Python's Link.validate
     * (Link.py:1211-1215) calls verify(), which raises on a bad signature, and
     * returns False; a pass requires the signature to actually verify. This
     * method previously discarded the boolean from ed25519Verify and returned a
     * hardcoded `true`, so any 64 bytes were accepted as a valid delivery-proof
     * signature and a third party who could see a link packet on the wire could
     * forge a DELIVERED confirmation for it. A missing peer key or any verifier
     * exception is a failed validation, never a pass.
     */
    fun validate(
        signature: ByteArray,
        message: ByteArray,
    ): Boolean =
        try {
            val key = peerSigPub ?: return false
            crypto.ed25519Verify(key, message, signature)
        } catch (e: Exception) {
            false
        }

    /**
     * Generate and send a proof for a packet over this link.
     *
     * @param packet The packet to prove
     */
    fun provePacket(packet: Packet) {
        // Conformance seam: notify any installed tap with the proved packet, the
        // kotlin equivalent of the reference wrapping link.prove_packet to record
        // each proved packet's context byte (wire_tcp.py:1299-1317). Mirrors the
        // existing inboundTapForTest seam. Null in normal operation; no port logic.
        runCatching { proveTapForTest?.invoke(packet) }

        // Sign the packet hash
        val signature = sign(packet.packetHash)

        // Always use explicit proofs for links (for now)
        val proofData = packet.packetHash + signature

        // Create proof packet addressed to this link
        val proof =
            Packet.createRaw(
                destinationHash = linkId,
                data = proofData,
                packetType = PacketType.PROOF,
                destinationType = DestinationType.LINK,
            )

        hadOutbound(isData = false) // before the send — see request()
        proof.send()
    }

    /**
     * Send data over the link.
     */
    fun send(data: ByteArray): Boolean = sendWithReceipt(data) != null

    /**
     * Send [data] on the link, optionally without a [PacketReceipt] (python
     * `RNS.Packet(link, data, create_receipt=False)`). Real-time streams such as
     * LXST audio frames send many packets per second and never wait for proofs;
     * a receipt per packet would only be tracked until it times out.
     */
    fun send(
        data: ByteArray,
        createReceipt: Boolean,
    ): Boolean {
        if (createReceipt) return send(data)
        if (status != LinkConstants.ACTIVE) return false
        val packet = linkPacket(encrypt(data), createReceipt = false)
        hadOutbound(isData = true)
        return Transport.outbound(packet)
    }

    /**
     * Build a DATA packet addressed to this link and associate it with the link.
     *
     * Every link packet carries the link's MTU (Python Packet.py: `self.MTU =
     * destination.mtu`, where the destination is the Link), so [Packet.mtu]
     * is always [mtu] here — never the global default.
     */
    private fun linkPacket(
        data: ByteArray,
        context: PacketContext = PacketContext.NONE,
        createReceipt: Boolean = true,
    ): Packet {
        val packet =
            Packet.createRaw(
                destinationHash = linkId,
                data = data,
                packetType = PacketType.DATA,
                destinationType = DestinationType.LINK,
                context = context,
                createReceipt = createReceipt,
                mtu = mtu,
            )
        packet.link = this
        return packet
    }

    /**
     * Send data over the link and return a receipt for delivery tracking.
     *
     * @param data The data to send
     * @return PacketReceipt if sent successfully, null otherwise
     */
    fun sendWithReceipt(data: ByteArray): PacketReceipt? {
        if (status != LinkConstants.ACTIVE) {
            return null
        }

        val encrypted = encrypt(data)
        val packet = linkPacket(encrypted, createReceipt = true)

        hadOutbound(isData = true) // before the send — see request()
        val receipt = packet.send()
        if (receipt != null) {
            receipt.setLink(this)
        }
        return receipt
    }

    /**
     * Conformance test seam: build (but do NOT send) a link DATA packet exactly
     * as [sendWithReceipt] would — genuine [encrypt] + createRaw with mtu=this.mtu
     * and packet.link=this — so a test can read the built packet's mtu/raw before
     * choosing to send, and can build a create_receipt=false packet (which
     * sendWithReceipt cannot express). packet.link is internal, so the
     * separate-module bridge cannot replicate this. No port logic.
     */
    fun buildDataPacketForTest(plaintext: ByteArray, createReceipt: Boolean = true): Packet {
        val encrypted = encrypt(plaintext)
        return linkPacket(encrypted, createReceipt = createReceipt)
    }

    /**
     * Send resource data over this link.
     * NOTE: Resource data is NOT link-encrypted! It's already encrypted at the
     * resource level. This matches Python RNS behavior.
     */
    fun sendResourceData(data: ByteArray) {
        if (status != LinkConstants.ACTIVE) {
            throw IllegalStateException("Link is not active")
        }

        logDebug { "sendResourceData: sending ${data.size} bytes (already resource-encrypted, no link encryption)" }
        // Send directly - already resource-level encrypted
        val packet = linkPacket(data, context = PacketContext.RESOURCE)

        hadOutbound(isData = true) // before the send — see request()
        packet.send()
    }

    /**
     * Get the Channel for this link.
     * Creates the channel lazily on first access.
     *
     * @return The Channel for this link
     */
    fun getChannel(): Channel {
        if (_channel == null) {
            _channel = Channel(LinkChannelOutlet(this))
        }
        return _channel!!
    }

    /**
     * Conformance test seam: build a fresh, NON-cached Channel over a real
     * LinkChannelOutlet on this link, mirroring the reference's
     * `Channel(LinkChannelOutlet(link))` throwaway used by wire_channel_profile /
     * wire_channel_timeout_formula / wire_channel_handler_chain. LinkChannelOutlet
     * is a private inner class, so this factory must live on Link. It does NOT
     * touch the cached `_channel` (the live channel is untouched).
     */
    fun newThrowawayChannelForTest(): Channel = Channel(LinkChannelOutlet(this))

    /**
     * ChannelOutlet implementation that wraps a Link.
     * Provides the transport layer for Channel message delivery.
     */
    private class LinkChannelOutlet(
        private val link: Link,
    ) : ChannelOutlet {
        override val mdu: Int
            get() = link.mdu

        override val rtt: Long?
            get() = link.rtt

        override val isUsable: Boolean
            // Mirror python RNS LinkChannelOutlet.is_usable (Channel.py:709-710),
            // which returns True unconditionally ("had issues looking at
            // Link.status"). Channel.is_ready_to_send therefore does NOT gate on
            // link status; readiness is governed solely by the tx-ring window, and
            // a send on a non-ACTIVE link instead fails via the no-receipt branch
            // (Channel.send -> ME_LINK_NOT_READY) because send() below only
            // actually transmits when ACTIVE.
            get() = true

        override val isClosed: Boolean
            // A CLOSED link never transmits again: send() below returns null for
            // every later call, so Channel.send can only ever raise
            // ME_LINK_NOT_READY. PENDING/HANDSHAKE/ACTIVE/STALE are not terminal —
            // a send refused in those states can still succeed once the link
            // settles, so they must keep their retry.
            get() = link.status == LinkConstants.CLOSED

        override val timedOut: Boolean
            get() =
                link.status == LinkConstants.CLOSED &&
                    link.teardownReason == LinkConstants.TEARDOWN_REASON_TIMEOUT

        override fun notifyTimedOut() {
            // Mirror python LinkChannelOutlet.timed_out (Channel.py:707-708):
            // tear the Link down when the Channel exhausts its retransmissions.
            link.teardown(LinkConstants.TEARDOWN_REASON_TIMEOUT)
        }

        override fun send(raw: ByteArray): Any? {
            // Mirror python LinkChannelOutlet.send (Channel.py:669-672): only
            // actually transmit when the link is ACTIVE; otherwise return null so
            // the packet has no receipt and Channel.send restores the reserved
            // sequence and raises ME_LINK_NOT_READY (the dead-channel send path).
            if (link.status != LinkConstants.ACTIVE) return null

            val encrypted = link.encrypt(raw)
            // linkPacket associates the packet with this Link so the receipt can
            // validate proofs using the Link's signing keys.
            // Without this, the receipt falls through to destination-based
            // validation which doesn't match Link proofs.
            val packet = link.linkPacket(encrypted, context = PacketContext.CHANNEL)

            // Use packet.send() so a PacketReceipt is created, enabling
            // delivery confirmation and timeout callbacks for Channel retry logic
            link.hadOutbound(isData = true) // before the send — see Link.request()
            val receipt = packet.send()
            return if (receipt != null) {
                packet
            } else {
                null
            }
        }

        override fun resend(packet: Any): Any? {
            if (packet !is Packet) return null
            val receipt = packet.resend()
            return if (receipt != null) packet else null
        }

        override fun getPacketState(packet: Any): Int {
            if (packet !is Packet) return MessageState.FAILED
            val receipt = packet.receipt ?: return MessageState.FAILED

            return when (receipt.status) {
                PacketReceipt.SENT -> MessageState.SENT
                PacketReceipt.DELIVERED -> MessageState.DELIVERED
                PacketReceipt.FAILED, PacketReceipt.CULLED -> MessageState.FAILED
                else -> MessageState.FAILED
            }
        }

        override fun setPacketTimeoutCallback(
            packet: Any,
            callback: ((Any) -> Unit)?,
            timeout: Long?,
        ) {
            if (packet !is Packet) return
            val receipt = packet.receipt ?: return

            if (timeout != null) {
                receipt.setTimeout(timeout / 1000.0) // Convert ms to seconds
            }

            if (callback != null) {
                receipt.setTimeoutCallback { callback(packet) }
            } else {
                receipt.callbacks.timeout = null
            }
        }

        override fun setPacketDeliveredCallback(
            packet: Any,
            callback: ((Any) -> Unit)?,
        ) {
            if (packet !is Packet) return
            val receipt = packet.receipt ?: return

            if (callback != null) {
                receipt.setDeliveryCallback { callback(packet) }
            } else {
                receipt.callbacks.delivery = null
            }
        }

        override fun getPacketId(packet: Any): Any = if (packet is Packet) packet.packetHash else packet
    }

    /**
     * Send a request to the remote peer.
     *
     * Requests allow querying the remote peer and receiving a response. The request
     * is sent over the encrypted link, and the response is delivered via callbacks.
     *
     * For small requests (<=MDU), the request is sent as a packet. For larger requests,
     * it's automatically sent as a resource.
     *
     * @param path The request path (identifies the handler on the remote side)
     * @param data The request data (will be serialized with msgpack)
     * @param responseCallback Optional callback when response is received
     * @param failedCallback Optional callback when request fails
     * @param progressCallback Optional callback for response progress
     * @param timeout Optional timeout in milliseconds (if null, calculated from RTT)
     * @return RequestReceipt to track the request, or null if link is not active
     */
    fun request(
        path: String,
        data: Any? = null,
        responseCallback: ((RequestReceipt) -> Unit)? = null,
        failedCallback: ((RequestReceipt) -> Unit)? = null,
        progressCallback: ((RequestReceipt) -> Unit)? = null,
        timeout: Long? = null,
    ): RequestReceipt? {
        if (status != LinkConstants.ACTIVE) {
            log("Cannot send request: link not active")
            return null
        }

        // Hash the path
        val pathHash = Hashes.truncatedHash(path.toByteArray(Charsets.UTF_8))

        // Pack the request: [timestamp, path_hash, data]
        val timestamp = System.currentTimeMillis()
        val packedRequest =
            try {
                packRequest(timestamp, pathHash, data)
            } catch (e: Exception) {
                log("Error packing request: ${e.message}")
                return null
            }

        // Calculate timeout if not provided
        val actualTimeout = timeout ?: calculateRequestTimeout()

        // Decide whether to send as packet or resource
        if (packedRequest.size <= mdu) {
            // Send as packet
            val encrypted = encrypt(packedRequest)
            val packet = linkPacket(encrypted, context = PacketContext.REQUEST)

            // Generate request ID from packet's truncated hash (like Python does)
            // This must be calculated AFTER creating the packet with encrypted data
            val requestId = packet.truncatedHash

            // Create the RequestReceipt
            val receipt =
                RequestReceipt(
                    link = this,
                    requestId = requestId,
                    requestSize = packedRequest.size,
                    responseCallback = responseCallback,
                    failedCallback = failedCallback,
                    progressCallback = progressCallback,
                    timeout = actualTimeout,
                )

            // Add to pending requests
            synchronized(pendingRequests) {
                pendingRequests.add(receipt)
            }

            hadOutbound(isData = true) // before the send — see request()
            if (!Transport.outbound(packet)) {
                log("Failed to send request packet")
                synchronized(pendingRequests) {
                    pendingRequests.remove(receipt)
                }
                return null
            }

            receipt.startedAt = System.currentTimeMillis()

            // Timeout monitoring handled by watchdog checkRequestTimeouts()
            return receipt
        } else {
            // Send as resource (Python: Link.py:514-527)
            val requestId = Hashes.truncatedHash(packedRequest)
            log("Sending request ${requestId.toHexString()} as resource")

            val receipt =
                RequestReceipt(
                    link = this,
                    requestId = requestId,
                    requestSize = packedRequest.size,
                    responseCallback = responseCallback,
                    failedCallback = failedCallback,
                    progressCallback = progressCallback,
                    timeout = actualTimeout,
                )

            synchronized(pendingRequests) {
                pendingRequests.add(receipt)
            }

            // python RequestReceipt.request_resource_concluded (Link.py:1386-1405): the
            // budget clock starts when the request resource has been delivered, and a
            // request resource that fails fails the request at once. `startedAt` stays
            // null until then, which keeps the watchdog's budget pass off this receipt
            // while the request itself is still uploading.
            network.reticulum.resource.Resource.create(
                data = packedRequest,
                link = this,
                requestId = requestId,
                isResponse = false,
                timeout = actualTimeout,
                callback = { res -> requestResourceSent(res, receipt) },
                failedCallback = { res -> requestResourceSent(res, receipt) },
            )
            return receipt
        }
    }

    /** The request resource of a resource-sized request concluded (python Link.py:1386-1405). */
    private fun requestResourceSent(
        resource: network.reticulum.resource.Resource,
        receipt: RequestReceipt,
    ) {
        if (resource.status == network.reticulum.resource.ResourceConstants.COMPLETE) {
            log("Request ${receipt.requestId.toHexString()} successfully sent as resource")
            receipt.markDelivered()
        } else {
            log("Sending request ${receipt.requestId.toHexString()} as resource failed with status: ${resource.status}")
            synchronized(pendingRequests) { pendingRequests.remove(receipt) }
            receipt.requestFailed()
        }
    }

    /**
     * Identify to the remote peer.
     *
     * This method allows the link initiator to reveal their identity to the remote peer
     * over the encrypted link. This preserves initiator anonymity while allowing authentication.
     *
     * Only works if:
     * - This is the initiator side
     * - Link is active
     *
     * @param identity The identity to identify as
     * @return true if identification was sent, false otherwise
     */
    fun identify(identity: Identity): Boolean {
        if (!initiator) {
            log("Cannot identify: only initiator can identify")
            return false
        }

        if (status != LinkConstants.ACTIVE) {
            log("Cannot identify: link not active")
            return false
        }

        // Build signed data: link_id + public_key
        val publicKey = identity.getPublicKey()
        val signedData = linkId + publicKey

        // Sign the data
        val signature =
            identity.sign(signedData)

        // Build proof data: public_key + signature
        val proofData = publicKey + signature

        // Encrypt and send
        val encrypted = encrypt(proofData)
        val packet = linkPacket(encrypted, context = PacketContext.LINKIDENTIFY)

        hadOutbound(isData = true) // before the send — see request()
        return Transport.outbound(packet).also { sent ->
            if (sent) {
                log("Sent identity to remote peer")
            }
        }
    }

    /**
     * Set the resource strategy for this link.
     *
     * @param strategy One of ACCEPT_NONE, ACCEPT_ALL, or ACCEPT_APP
     * @return true if strategy was set successfully, false otherwise
     */
    fun setResourceStrategy(strategy: Int): Boolean =
        when (strategy) {
            ACCEPT_NONE, ACCEPT_ALL, ACCEPT_APP -> {
                resourceStrategy = strategy
                true
            }
            else -> {
                log("Invalid resource strategy: $strategy")
                false
            }
        }

    /**
     * Get the current resource strategy for this link.
     *
     * @return The current resource strategy
     */
    fun getResourceStrategy(): Int = resourceStrategy

    /**
     * Set the resource callback for ACCEPT_APP strategy.
     *
     * @param callback Function that takes a ResourceAdvertisement and returns true to accept
     */
    fun setResourceCallback(callback: ((network.reticulum.resource.ResourceAdvertisement) -> Boolean)?) {
        resourceCallback = callback
    }

    /**
     * Pack a request using msgpack.
     *
     * Format: [timestamp, path_hash, data]
     */
    private fun packRequest(
        timestamp: Long,
        pathHash: ByteArray,
        data: Any?,
    ): ByteArray {
        val packer = MessagePack.newDefaultBufferPacker()

        packer.packArrayHeader(3)
        packer.packLong(timestamp)
        packer.packBinaryHeader(pathHash.size)
        packer.writePayload(pathHash)

        // Pack data (can be null)
        RequestWire.packValue(packer, data)
        val packed = packer.toByteArray()
        packer.close()
        return packed
    }

    /**
     * Calculate request timeout based on RTT.
     */
    private fun calculateRequestTimeout(): Long {
        val linkRtt = rtt ?: LinkConstants.KEEPALIVE_MAX
        // python Link.request: timeout = self.rtt * self.traffic_timeout_factor +
        // RNS.Resource.RESPONSE_MAX_GRACE_TIME*1.125 (Link.py:493-494). rtt is in
        // MILLIS here; RESPONSE_MAX_GRACE_TIME (10) is SECONDS, so 10*1.125 s =
        // 11250 ms. (The previous +5000 ms was an admitted approximation that
        // diverged from the reference.)
        val graceMs = (network.reticulum.resource.ResourceConstants.RESPONSE_MAX_GRACE_TIME * 1125L)
        return linkRtt * trafficTimeoutFactor + graceMs
    }

    /**
     * Close the link.
     *
     * @param reason The teardown reason (defaults based on initiator status)
     */
    fun teardown(reason: Int = LinkConstants.TEARDOWN_REASON_UNKNOWN) {
        teardownInternal(reason, sendClosePacket = true)
    }

    /**
     * Close the link.
     *
     * @param sendClosePacket false when the close was initiated by the peer's
     *   LINKCLOSE: python teardown_packet (Link.py:693-701) goes straight to
     *   link_closed() and never answers a close with a close.
     */
    private fun teardownInternal(
        reason: Int,
        sendClosePacket: Boolean,
    ) {
        if (status == LinkConstants.CLOSED) return

        val previousStatus = status

        // Send the close packet BEFORE the status flips to CLOSED, as python does
        // (Link.teardown sends, then sets CLOSED). Order matters: a CLOSED link is one
        // the transport treats as gone — python's outbound skips link packets whose
        // link is CLOSED (Transport.py:1451) — so closing first and sending second is a
        // packet that never leaves, and the peer learns of the close only when its
        // watchdog times out.
        // python sends the close packet from any state but PENDING (Link.py:668) —
        // HANDSHAKE included. That window is not theoretical: a non-initiator sits in
        // HANDSHAKE from the moment it sends LRPROOF until the initiator's RTT packet
        // arrives one round trip later, and a peer that shuts down inside it must still
        // say goodbye. Gating on ACTIVE meant a server closed right after the initiator
        // saw the link come up sent nothing, and the initiator waited out its watchdog
        // and reported TIMEOUT for a clean close. An initiator in HANDSHAKE has no
        // derived key yet; encryption fails inside sendTeardownPacket and is logged,
        // exactly as python's __teardown_packet swallows the same failure.
        if (sendClosePacket && previousStatus != LinkConstants.PENDING) {
            // Data must be encrypted like Python's __teardown_packet():
            // self.decrypt(packet.data) checks if plaintext == self.link_id
            sendTeardownPacket()
        }

        status = LinkConstants.CLOSED

        // Set teardown reason
        teardownReason =
            if (reason == LinkConstants.TEARDOWN_REASON_UNKNOWN) {
                if (initiator) {
                    LinkConstants.TEARDOWN_REASON_INITIATOR_CLOSED
                } else {
                    LinkConstants.TEARDOWN_REASON_DESTINATION_CLOSED
                }
            } else {
                reason
            }

        stopWatchdog()

        Transport.deregisterLink(this)

        // Fail any resources still in flight on this link immediately, rather than leaving
        // them to time out on their own watchdog (RTT * PART_TIMEOUT_FACTOR * MAX_RETRIES).
        // Mirrors python link_closed(), which cancels active resources when the link closes.
        // `status` is already CLOSED above, so each cancel() fails the resource locally and
        // skips the RESOURCE_ICL send (which is gated on link.status == ACTIVE) over the dead
        // link. Snapshot under the locks, then cancel outside them: cancel() ->
        // resourceConcluded() removes from these same lists, so iterating them live would fault.
        val resourcesToFail =
            synchronized(outgoingResources) { outgoingResources.toList() } +
                synchronized(incomingResources) { incomingResources.toList() }
        resourcesToFail.forEach { resource ->
            try {
                resource.cancel()
            } catch (e: Exception) {
                log("Error cancelling resource on link teardown: ${e.message}")
            }
        }

        // Fail every request still pending. python's link_closed leaves pending_requests
        // untouched (Link.py:704-730) and its request_timed_out never acts on a SENT
        // receipt, so a caller waiting on failed_callback waited forever; a deliberate
        // deviation, recorded in port-deviations.md.
        val requestsToFail = synchronized(pendingRequests) { pendingRequests.toList().also { pendingRequests.clear() } }
        for (pending in requestsToFail) {
            try {
                pending.requestFailed()
            } catch (e: Exception) {
                log("Error failing pending request on link teardown: ${e.message}")
            }
        }

        // Release every partial split-transfer accumulation this link owned. The segment
        // resources themselves have already concluded and left incomingResources, so the
        // cancel loop above cannot reach these bytes; without this a peer that opened a
        // link, sent segment 1 of a transfer it never finished, and closed the link left
        // its accumulation on the heap for the life of the process.
        segmentAccumulators.clear()

        // Shut the channel down with the link (python link_closed, Link.py:707:
        // `if self._channel: self._channel._shutdown()`). Otherwise tx-ring
        // receipts keep timing out and retryEnvelope resends on a CLOSED link
        // up to MAX_TRIES per envelope, and handlers/rings are retained.
        try {
            _channel?.shutdown()
        } catch (e: Exception) {
            log("Error shutting down channel on link teardown: ${e.message}")
        }

        // Purge the ephemeral key material, mirroring python link_closed()
        // (Link.py:728-733: prv/pub/pub_bytes/shared_key/derived_key = None).
        // This is the forward-secrecy guarantee — once a link closes, its
        // ephemeral private key and derived link key must not linger in memory
        // where a later compromise could recover past traffic.
        prv = null
        pub = null
        sharedKey = null
        derivedKey = null

        callbacks.linkClosed?.let { callback ->
            try {
                callback(this)
            } catch (e: Exception) {
                log("Error in link closed callback: ${e.message}")
            }
        }

        log("Link ${linkId.toHexString()} closed (reason: $teardownReason)")
    }

    /**
     * Record outbound activity.
     */
    fun hadOutbound(
        isKeepalive: Boolean = false,
        isData: Boolean = false,
    ) {
        lastOutbound = System.currentTimeMillis()
        if (isKeepalive) {
            lastKeepalive = lastOutbound
        }
        if (isData) {
            lastData = lastOutbound
        }
    }

    /**
     * Record inbound activity.
     */
    fun hadInbound(isData: Boolean = false) {
        lastInbound = System.currentTimeMillis()
        if (isData) {
            lastData = lastInbound
        }
    }

    /**
     * Get link age in milliseconds.
     */
    fun getAge(): Long? =
        if (activatedAt > 0) {
            System.currentTimeMillis() - activatedAt
        } else {
            null
        }

    /**
     * Time since last inbound packet.
     */
    fun noInboundFor(): Long {
        val activeAt = if (activatedAt > 0) activatedAt else 0
        val lastIn = maxOf(lastInbound, activeAt)
        return System.currentTimeMillis() - lastIn
    }

    /**
     * Time since last outbound packet.
     */
    fun noOutboundFor(): Long = System.currentTimeMillis() - lastOutbound

    /**
     * Time since last data packet (excludes keepalives).
     */
    fun noDataFor(): Long = System.currentTimeMillis() - lastData

    /**
     * Time since any activity.
     */
    fun inactiveFor(): Long = minOf(noInboundFor(), noOutboundFor())

    /**
     * Get the remote peer's identity if known.
     */
    fun getRemoteIdentity(): Identity? = remoteIdentity

    /**
     * Update keepalive interval based on RTT.
     */
    private fun updateKeepalive() {
        val linkRtt = rtt ?: return
        // Python: keepalive = max(min(rtt * (KEEPALIVE_MAX / KEEPALIVE_MAX_RTT), KEEPALIVE_MAX), KEEPALIVE_MIN)
        // Python uses seconds; Kotlin RTT is in ms, KEEPALIVE_MAX is in ms, KEEPALIVE_MAX_RTT is in seconds.
        // Scale factor: KEEPALIVE_MAX_ms / (KEEPALIVE_MAX_RTT_s * 1000) = 360000 / 1750 ≈ 205.7
        val rttKeepalive = (linkRtt * (LinkConstants.KEEPALIVE_MAX.toDouble() / (LinkConstants.KEEPALIVE_MAX_RTT * 1000.0))).toLong()
        keepalive = maxOf(LinkConstants.KEEPALIVE_MIN, minOf(rttKeepalive, LinkConstants.KEEPALIVE_MAX))
        staleTime = LinkConstants.STALE_FACTOR * keepalive
    }

    /**
     * Start the watchdog coroutine using shared scope.
     * This is more battery-efficient than per-link threads on Android.
     */
    private fun startWatchdog() {
        // Cancel existing watchdog for this instance if any
        activeWatchdogs[instanceId]?.cancel()

        // Start new watchdog coroutine in shared scope
        val job =
            watchdogScope.launch {
                while (isActive && status != LinkConstants.CLOSED) {
                    // python Link.py:713-777 — check first, then sleep exactly until the next
                    // thing is due, never longer than WATCHDOG_MAX_SLEEP. This loop used to
                    // sleep a fixed min(keepalive/4, 5 s) and then check, which made every
                    // watchdog action up to 5 s late. Keepalive scales with RTT, so on a
                    // loaded box a 21 s keepalive was emitted at 25 s, and the conformance
                    // suite's 3 s headroom caught it (test_initiator_keepalive_holds_active_link).
                    val sleepMs =
                        try {
                            checkTimeout()
                        } catch (e: Exception) {
                            log("Watchdog error: ${e.message}")
                            LinkConstants.WATCHDOG_MAX_SLEEP
                        }
                    try {
                        delay(sleepMs.coerceIn(1L, LinkConstants.WATCHDOG_MAX_SLEEP))
                    } catch (e: kotlinx.coroutines.CancellationException) {
                        // Normal cancellation, exit loop
                        break
                    }
                }
            }

        activeWatchdogs[instanceId] = job
    }

    /**
     * Stop the watchdog coroutine for this link.
     */
    private fun stopWatchdog() {
        activeWatchdogs.remove(instanceId)?.cancel()
    }

    /**
     * One watchdog tick: act on whatever is due, and return how long to sleep before the
     * next tick, in milliseconds (python Link.__watchdog_job, Link.py:713-777).
     *
     * The return value is the point. The reference computes, in every state, the time at
     * which the next action becomes due and sleeps exactly that long (capped at
     * WATCHDOG_MAX_SLEEP), so a keepalive goes out within a scheduler quantum of when the
     * protocol says it should. A fixed polling interval cannot do that: whatever the
     * interval, an action can be that late.
     */
    private fun checkTimeout(): Long {
        val now = System.currentTimeMillis()
        var sleepMs: Long = LinkConstants.WATCHDOG_MAX_SLEEP

        when (status) {
            LinkConstants.PENDING -> {
                // Link was initiated, but no response from destination yet
                sleepMs = (requestTime + establishmentTimeout) - now
                if (now >= requestTime + establishmentTimeout) {
                    log("Link establishment timed out")
                    teardown(LinkConstants.TEARDOWN_REASON_TIMEOUT)
                    sleepMs = 1
                }
            }

            LinkConstants.HANDSHAKE -> {
                // Waiting for link proof or RTT packet
                sleepMs = (requestTime + establishmentTimeout) - now
                if (now >= requestTime + establishmentTimeout) {
                    if (initiator) {
                        log("Timeout waiting for link request proof")
                    } else {
                        log("Timeout waiting for RTT packet from link initiator")
                    }
                    teardown(LinkConstants.TEARDOWN_REASON_TIMEOUT)
                    sleepMs = 1
                }
            }

            LinkConstants.ACTIVE -> {
                val activatedTime = activatedAt
                val lastInbound = maxOf(maxOf(this.lastInbound, lastProof), activatedTime)
                val inactivity = now - lastInbound
                // Also drive keepalive on OUTBOUND idle, matching python
                // `now >= last_inbound + keepalive or now >= last_outbound + keepalive`
                // (Link.py:749) — otherwise a link that only receives never emits a
                // keepalive to keep the reverse path / NAT warm.
                val outboundIdle = now - lastOutbound

                if (inactivity >= keepalive || outboundIdle >= keepalive) {
                    // Send keepalive if we're the initiator and haven't sent one recently
                    if (initiator && (now - lastKeepalive) >= keepalive) {
                        sendKeepalive()
                    }

                    // Transition to stale if no inbound for stale_time
                    if (inactivity >= staleTime) {
                        status = LinkConstants.STALE
                        staleAt = now
                        log("Link marked stale")
                        // python Link.py:754 — the stale grace, then the teardown tick.
                        sleepMs = (rtt ?: keepalive) * keepaliveTimeoutFactor + LinkConstants.STALE_GRACE
                    } else {
                        // python Link.py:757
                        sleepMs = keepalive
                    }
                } else {
                    // python Link.py:759 — sleep until the inbound-driven keepalive is due.
                    // The reference computes this from last_inbound alone even though the
                    // trigger above also fires on outbound idle; that asymmetry is kept.
                    sleepMs = (lastInbound + keepalive) - now
                }

                // Check for timed-out pending requests
                checkRequestTimeouts(now)
            }

            LinkConstants.STALE -> {
                // Give the link a grace window after going STALE before tearing
                // it down, matching python's watchdog which sleeps
                // `rtt*keepalive_timeout_factor + STALE_GRACE` between marking STALE
                // and the teardown tick (Link.py:753-766). Tearing down on the first
                // STALE tick (the previous behaviour) collapsed that grace, so links
                // on lossy / high-RTT paths were reaped sooner than the reference.
                val rttMs = rtt ?: keepalive
                val graceMs = rttMs * keepaliveTimeoutFactor + LinkConstants.STALE_GRACE
                val remaining = graceMs - (now - staleAt)
                if (remaining <= 0) {
                    // teardown() sends the close packet itself (previousStatus is STALE, not
                    // PENDING); an explicit send here produced two LINKCLOSEs.
                    teardown(LinkConstants.TEARDOWN_REASON_TIMEOUT)
                    sleepMs = 1
                } else {
                    sleepMs = remaining
                }
            }
        }
        return sleepMs
    }

    /**
     * Check pending requests for timeouts.
     * Called from the watchdog loop.
     */
    private fun checkRequestTimeouts(now: Long) {
        val timedOut = mutableListOf<RequestReceipt>()
        synchronized(pendingRequests) {
            val iter = pendingRequests.iterator()
            while (iter.hasNext()) {
                val receipt = iter.next()
                val started = receipt.startedAt ?: continue
                // python RequestReceipt.request_timed_out (Link.py:1416-1417) acts only
                // on a DELIVERED receipt. Once the response is arriving as a resource the
                // receipt is RECEIVING and the request budget (rtt * factor + grace) no
                // longer applies: the resource's own watchdog governs the transfer, and
                // responseResourceConcluded fails the request if that transfer fails.
                // Applying the budget here tore down live multi-second transfers on
                // high-RTT links (a 20 s budget against a file download over Tor).
                if (receipt.status == RequestReceipt.RECEIVING) continue
                if (now - started > receipt.timeout) {
                    timedOut.add(receipt)
                    iter.remove()
                }
            }
        }
        for (receipt in timedOut) {
            log("Request ${receipt.requestId.toHexString()} timed out after ${receipt.timeout}ms")
            receipt.requestFailed()
        }
    }

    /**
     * Send a teardown packet to the remote end.
     */
    private fun sendTeardownPacket() {
        try {
            val teardownData = linkId // Send link ID as teardown data
            val packet = linkPacket(encrypt(teardownData), context = PacketContext.LINKCLOSE)
            Transport.outbound(packet)
        } catch (e: Exception) {
            log("Error sending teardown packet: ${e.message}")
        }
    }

    /**
     * Send RTT packet to the remote side.
     * This is sent by the initiator after validating the link proof to
     * let the server know the link is ready and what the measured RTT is.
     */
    private fun sendRttPacket() {
        val linkRtt = rtt ?: return

        // Pack RTT as a double (seconds) like Python does
        val rttSeconds = linkRtt / 1000.0
        val packer = MessagePack.newDefaultBufferPacker()
        packer.packDouble(rttSeconds)
        val rttData = packer.toByteArray()
        packer.close()

        // Encrypt and send
        val encrypted = encrypt(rttData)
        val packet = linkPacket(encrypted, context = PacketContext.LRRTT)

        hadOutbound() // before the send — see request()
        Transport.outbound(packet)
        log("Sent RTT packet to server (${rttSeconds}s)")
    }

    /**
     * Send a keepalive packet.
     */
    private fun sendKeepalive() {
        if (status != LinkConstants.ACTIVE && status != LinkConstants.STALE) return

        val packet = linkPacket(KEEPALIVE_REQUEST, context = PacketContext.KEEPALIVE)

        hadOutbound(isKeepalive = true) // before the send — see request()
        Transport.outbound(packet)
    }

    /**
     * Receive and process an incoming packet on this link.
     *
     * This is the main packet processing method that handles all link traffic including:
     * - Regular data packets
     * - Keepalives
     * - Link identification
     * - RTT measurements
     * - Resource advertisements and transfers
     * - Requests and responses
     * - Channel data
     * - Link close packets
     *
     * @param packet The incoming packet to process
     */
    /**
     * Conformance test seam: a per-link tap invoked for every inbound packet at
     * the top of receive(), the kotlin equivalent of the reference bridge
     * monkey-patching link.receive to observe inbound RESPONSE / RESOURCE_ADV
     * packets (reference wire_capture_response_packet). Null in normal operation.
     */
    @Volatile
    @network.reticulum.RnsTestSeam
    var inboundTapForTest: ((Packet) -> Unit)? = null

    /**
     * Conformance test seam: a tap fired inside provePacket() with the proved
     * packet, the kotlin equivalent of the reference wrapping link.prove_packet
     * to record each proved packet's context byte for the receiver-proof log
     * (reference wire_listener_proof_log, wire_tcp.py:1299-1317). Null in normal
     * operation.
     */
    @Volatile
    @network.reticulum.RnsTestSeam
    var proveTapForTest: ((Packet) -> Unit)? = null

    fun receive(packet: Packet) {
        inboundTapForTest?.let { tap -> runCatching { tap(packet) } }
        // Skip closed links, and skip initiator keepalive responses
        if (status == LinkConstants.CLOSED) return

        // Defence in depth: only LINK-typed packets are link traffic.
        // python gates active_links delivery on destination_type == LINK
        // (Transport.py:2571). A captured link DATA packet with its type bits
        // flipped to PLAIN/GROUP bypasses the packet hashlist (replay), so it
        // must not reach the link even if Transport lets it through.
        if (packet.destinationType != DestinationType.LINK) {
            log("Dropping ${packet.destinationType} packet addressed to link ${linkId.toHexString()}")
            return
        }

        if (initiator &&
            packet.context == PacketContext.KEEPALIVE &&
            packet.data.contentEquals(KEEPALIVE_REQUEST)
        ) {
            return
        }

        // Verify packet arrived on expected interface (Python: Link.py:982-983).
        // Python compares `packet.receiving_interface != self.attached_interface`,
        // so a null receiving interface counts as a MISMATCH when one is expected —
        // a packet with no interface binding must not be treated as on-interface.
        val expectedIface = attachedInterfaceHash
        val receivedIface = packet.receivingInterfaceHash
        if (expectedIface != null &&
            (receivedIface == null || !expectedIface.contentEquals(receivedIface))
        ) {
            log("Link packet received on unexpected interface, ignoring")
            return
        }

        // Record inbound activity
        lastInbound = System.currentTimeMillis()
        if (packet.context != PacketContext.KEEPALIVE) {
            lastData = lastInbound
        }

        // Update counters
        rx.incrementAndGet()
        rxBytes.addAndGet(packet.data.size.toLong())

        // Revive stale link
        if (status == LinkConstants.STALE) {
            status = LinkConstants.ACTIVE
            log("Link ${linkId.toHexString()} revived from stale state")
        }

        // Process based on packet type. This is the boundary between the
        // interface reader thread and attacker-controlled decoding, so contain
        // Throwable, not just Exception: an OutOfMemoryError raised by a
        // declared msgpack length must not escape the reader thread.
        try {
            when (packet.packetType) {
                PacketType.DATA -> processDataPacket(packet)
                PacketType.PROOF -> processProofPacket(packet)
                else -> {
                    log("Ignoring packet with unexpected type: ${packet.packetType}")
                }
            }
        } catch (t: Throwable) {
            if (t is InterruptedException) Thread.currentThread().interrupt()
            log(
                "Unhandled ${t::class.java.name} while processing ${packet.packetType}/${packet.context} " +
                    "on link ${linkId.toHexString()}: ${t.message}",
            )
        }
    }

    /**
     * Process DATA type packets with various contexts.
     */
    private fun processDataPacket(packet: Packet) {
        logDebug { "Processing link DATA packet: context=${packet.context}, size=${packet.data.size}" }
        when (packet.context) {
            PacketContext.NONE -> processRegularData(packet)
            PacketContext.LINKIDENTIFY -> processLinkIdentify(packet)
            PacketContext.REQUEST -> processRequest(packet)
            PacketContext.RESPONSE -> processResponse(packet)
            PacketContext.LRRTT -> processLrrtt(packet)
            PacketContext.LINKCLOSE -> processLinkClose(packet)
            PacketContext.RESOURCE_ADV -> processResourceAdv(packet)
            PacketContext.RESOURCE_REQ -> processResourceReq(packet)
            PacketContext.RESOURCE_HMU -> processResourceHmu(packet)
            PacketContext.RESOURCE_ICL -> processResourceIcl(packet)
            PacketContext.RESOURCE_RCL -> processResourceRcl(packet)
            PacketContext.RESOURCE -> processResource(packet)
            PacketContext.KEEPALIVE -> processKeepalive(packet)
            PacketContext.CHANNEL -> processChannel(packet)
            PacketContext.COMMAND -> processCommand(packet)
            PacketContext.COMMAND_STATUS -> processCommandStatus(packet)
            else -> {
                log("Unhandled packet context: ${packet.context}")
            }
        }
    }

    /**
     * Process regular data packets (context = NONE).
     */
    private fun processRegularData(packet: Packet) {
        val plaintext = decrypt(packet.data) ?: return

        // Update physical layer stats
        updatePhyStats(packet.rssi, packet.snr, packet.q)

        // Associate the packet with this link so prove() can work
        packet.link = this

        // Invoke packet callback
        callbacks.packet?.let { callback ->
            thread(isDaemon = true) {
                try {
                    callback(plaintext, packet)
                } catch (e: Exception) {
                    log("Error in packet callback: ${e.message}")
                }
            }
        }

        // Enforce proof strategy (Python: Link.py:1003-1012). The destination whose
        // strategy applies is the one serving the link on either side; `destination` on
        // an initiator link was left out, so inbound DATA there was never auto-proved.
        val dest = servingDestination
        if (dest != null && dest.shouldProve(packet)) {
            packet.prove()
        }
    }

    /**
     * Process link identification packets.
     */
    private fun processLinkIdentify(packet: Packet) {
        val plaintext = decrypt(packet.data) ?: return

        log("Processing LINKIDENTIFY packet: ${plaintext.size} bytes (expected ${RnsConstants.IDENTITY_PUBLIC_KEY_SIZE + RnsConstants.SIGNATURE_SIZE})")

        // Only receivers process identity packets, and format is:
        // public_key (64 bytes: X25519 + Ed25519) + signature (64 bytes)
        if (!initiator && plaintext.size == RnsConstants.IDENTITY_PUBLIC_KEY_SIZE + RnsConstants.SIGNATURE_SIZE) {
            try {
                val publicKey = plaintext.copyOfRange(0, RnsConstants.IDENTITY_PUBLIC_KEY_SIZE)
                val signedData = linkId + publicKey
                val signature =
                    plaintext.copyOfRange(
                        RnsConstants.IDENTITY_PUBLIC_KEY_SIZE,
                        RnsConstants.IDENTITY_PUBLIC_KEY_SIZE + RnsConstants.SIGNATURE_SIZE,
                    )

                // Load and validate the identity
                val identity = Identity.fromPublicKey(publicKey)
                if (identity.validate(signature, signedData)) {
                    // python Link.py:999-1006: a blackholed identity ends the link;
                    // otherwise the remote identity is set once and never replaced,
                    // so a peer cannot swap the identity behind later ACL decisions
                    // or re-fire remoteIdentified.
                    if (Transport.isBlackholed(identity.hash)) {
                        log("Terminating incoming link from blackholed identity ${identity.hexHash}")
                        teardown()
                        return
                    }

                    if (remoteIdentity == null) {
                        remoteIdentity = identity
                        log("Remote peer identified: ${identity.hexHash}")

                        // Invoke callback
                        callbacks.remoteIdentified?.let { callback ->
                            thread(isDaemon = true) {
                                try {
                                    callback(this, identity)
                                } catch (e: Exception) {
                                    log("Error in remote identified callback: ${e.message}")
                                }
                            }
                        }
                    } else {
                        log("Ignoring LINKIDENTIFY from ${identity.hexHash}: remote identity already set")
                    }
                } else {
                    log("Invalid signature in link identify packet")
                }
            } catch (e: Exception) {
                log("Error processing link identify: ${e.message}")
            }
        } else {
            log("Ignoring LINKIDENTIFY: initiator=$initiator, size=${plaintext.size}")
        }
    }

    /**
     * Process request packets.
     */
    private fun processRequest(packet: Packet) {
        try {
            val requestId = packet.truncatedHash
            val packedRequest = decrypt(packet.data) ?: return

            // python Link.py:1018-1020: enforce the owning destination's
            // max_request_size on the packed request before decoding it. The
            // owning destination of a receiver link is `owner` (python
            // `self.destination`, Link.py:214); `destination` is null there.
            val maxReq = servingDestination?.maxRequestSize
            if (maxReq != null && packedRequest.size > maxReq) {
                log("Ignored request with excessive size ${packedRequest.size} (max $maxReq) on $this")
                return
            }

            val unpackedRequest = unpackRequest(packedRequest, "request") ?: return

            // Pass to handleRequest
            handleRequest(requestId, unpackedRequest)
        } catch (e: Exception) {
            log("Error processing request: ${e.message}")
        }
    }

    /**
     * Unpack a msgpack request: `[timestamp, path_hash, data]`.
     *
     * Returns `listOf(timestamp: Long, pathHash: ByteArray, data: ByteArray?)`
     * as consumed by [handleRequest], or null (after logging, naming the
     * request as [kind]) when the outer array is not 3 elements. Malformed
     * msgpack propagates as an exception, as before.
     *
     * The data element is whatever the requester packed: python
     * `Link.request(path, data)` msgpacks `data` as-is, and LXMF peers send
     * lists (`LXMPeer.sync` offers a list of transient ids, the client `/get`
     * sends `[wants, haves]`). It is decoded as [RequestWire.valueToBytes]
     * does for responses: bin and str as their raw bytes, nil as null, and any
     * other type re-serialised to msgpack bytes for the handler to decode.
     * Before this only bin or nil were accepted, so a list-carrying request
     * from a python peer was dropped as malformed.
     */
    private fun unpackRequest(
        packedRequest: ByteArray,
        kind: String,
    ): List<Any?>? {
        checkMsgpackStructure(packedRequest)
        val unpacker =
            org.msgpack.core.MessagePack
                .newDefaultUnpacker(packedRequest)
        val arraySize = unpacker.unpackArrayHeader()
        if (arraySize != 3) {
            log("Invalid $kind format: expected 3 elements, got $arraySize")
            return null
        }

        // Python sends time.time() which is a float; Kotlin uses millis (Long).
        // Accept both integer and float timestamps from msgpack.
        val nextFormat = unpacker.nextFormat
        val timestamp =
            if (nextFormat.valueType == org.msgpack.value.ValueType.FLOAT) {
                unpacker.unpackDouble().toLong()
            } else {
                unpacker.unpackLong()
            }
        // Request path hashes are truncated hashes (Destination.register_request_handler).
        val pathHash =
            unpackBoundedBinary(unpacker, packedRequest, "$kind path hash", RnsConstants.TRUNCATED_HASH_BYTES)

        // Every nested length was bounded by checkMsgpackStructure above, so
        // unpackValue cannot allocate more than the input size here.
        val requestData = RequestWire.valueToBytes(unpacker, packedRequest)
        unpacker.close()
        return listOf(timestamp, pathHash, requestData)
    }

    /**
     * Structural pre-pass over peer-supplied msgpack: `skipValue` walks the whole value
     * checking every declared bin/str/array/map length against the buffer WITHOUT
     * allocating payloads, so a length that overruns the input throws here before any
     * allocating read. python's umsgpack raises InsufficientDataException the same way.
     */
    private fun checkMsgpackStructure(input: ByteArray) {
        org.msgpack.core.MessagePack
            .newDefaultUnpacker(input)
            .use { it.skipValue() }
    }

    /**
     * Read a msgpack bin field whose declared length must fit in the remaining input,
     * and equal [expected] when the field has a fixed size. msgpack-core's `readPayload(n)`
     * allocates `n` bytes before reading, so a declared bin32 length inside a ~430-byte
     * packet would otherwise allocate up to 2 GiB (or raise OutOfMemoryError) before any
     * check.
     */
    private fun unpackBoundedBinary(
        unpacker: org.msgpack.core.MessageUnpacker,
        input: ByteArray,
        field: String,
        expected: Int? = null,
    ): ByteArray {
        val declared = unpacker.unpackBinaryHeader()
        val remaining = input.size - unpacker.totalReadBytes
        if (declared < 0 || declared.toLong() > remaining) {
            throw IllegalArgumentException("$field length $declared exceeds remaining input ($remaining bytes)")
        }
        if (expected != null && declared != expected) {
            throw IllegalArgumentException("$field length $declared, expected $expected")
        }
        return unpacker.readPayload(declared)
    }

    /**
     * Unpack a msgpack response: `[request_id, response_data]`.
     *
     * The response value can be any msgpack type. Like Python's
     * `umsgpack.unpackb(plaintext)[1]`, binary and string values are returned
     * as their raw bytes, nil as null, and complex types (arrays, maps) are
     * re-serialized to msgpack bytes. Returns null (after logging) when the
     * outer array is not 2 elements. Malformed msgpack propagates as an
     * exception, as before.
     */
    private fun unpackResponse(packedResponse: ByteArray): Pair<ByteArray, ByteArray?>? {
        checkMsgpackStructure(packedResponse)
        val unpacker =
            org.msgpack.core.MessagePack
                .newDefaultUnpacker(packedResponse)
        val arraySize = unpacker.unpackArrayHeader()
        if (arraySize != 2) {
            log("Invalid response format: expected 2 elements, got $arraySize")
            return null
        }

        // Request ids are truncated hashes of the packed request (Link.py:931-940).
        val requestId =
            unpackBoundedBinary(unpacker, packedResponse, "response request id", RnsConstants.TRUNCATED_HASH_BYTES)

        // Every nested length was bounded by checkMsgpackStructure above, so
        // unpackValue cannot allocate more than the input size here.
        val responseData = RequestWire.valueToBytes(unpacker, packedResponse)
        unpacker.close()
        return Pair(requestId, responseData)
    }

    /**
     * Process response packets.
     */
    private fun processResponse(packet: Packet) {
        try {
            logDebug { "processResponse: decrypting ${packet.data.size} bytes" }
            val packedResponse = decrypt(packet.data)
            if (packedResponse == null) {
                log("processResponse: decrypt returned null")
                return
            }

            val (requestId, responseData) = unpackResponse(packedResponse) ?: return

            // Calculate transfer size
            val responseDataSize = responseData?.size ?: 0
            val transferSize = responseDataSize

            // Pass to handleResponse
            logDebug { "processResponse: requestId=${requestId.toHexString()}, dataSize=$responseDataSize" }
            handleResponse(requestId, responseData, responseDataSize, transferSize)
        } catch (e: Exception) {
            log("Error processing response: ${e.message}\n${e.stackTraceToString()}")
        }
    }

    /**
     * Process LRRTT (Link RTT) packets.
     */
    private fun processLrrtt(packet: Packet) {
        // Only receivers process RTT packets
        if (!initiator) {
            rttPacket(packet)
        }
    }

    /**
     * Process RTT measurement packet.
     */
    private fun rttPacket(packet: Packet) {
        // Guard against duplicate/replayed LRRTT packets. Matches the peer-side
        // validateProof() check on HANDSHAKE and prevents double-firing the
        // link-established callbacks or re-measuring rtt/activatedAt.
        if (status != LinkConstants.HANDSHAKE) return
        try {
            val measuredRtt = System.currentTimeMillis() - requestTime
            val plaintext = decrypt(packet.data) ?: return

            // Unpack msgpack RTT value from plaintext
            // Python sends RTT as a float in seconds
            val remoteRtt =
                try {
                    val unpacker = MessagePack.newDefaultUnpacker(plaintext)
                    val rttSeconds = unpacker.unpackDouble()
                    unpacker.close()
                    (rttSeconds * 1000).toLong() // Convert seconds to ms
                } catch (e: Exception) {
                    // Fallback: try as float
                    try {
                        val unpacker = MessagePack.newDefaultUnpacker(plaintext)
                        val rttSeconds = unpacker.unpackFloat()
                        unpacker.close()
                        (rttSeconds * 1000).toLong()
                    } catch (e2: Exception) {
                        measuredRtt // Use measured if unpacking fails
                    }
                }

            // Use max of measured and remote RTT. The remote value is
            // peer-supplied: clamp it to a sane range first so +Inf / huge /
            // negative / NaN cannot saturate the Long and wrap every timeout
            // derived from rtt (calculateRequestTimeout, Channel packet timeout,
            // STALE grace) — python's float arithmetic never wraps (Link.py:541).
            rtt = maxOf(measuredRtt, remoteRtt.coerceIn(0L, LinkConstants.MAX_REMOTE_RTT_MS))
            // Set activatedAt BEFORE the volatile status write so any thread that
            // observes status==ACTIVE via the volatile read is also guaranteed to
            // see a non-zero activatedAt (getAge()/noInboundFor() correctness).
            // This mirrors the ordering applied to validateProof() for issue #42.
            activatedAt = System.currentTimeMillis()
            status = LinkConstants.ACTIVE

            // Calculate establishment rate (bytes per ms)
            val linkRtt = rtt
            if (linkRtt != null && linkRtt > 0 && establishmentCost > 0) {
                establishmentRate = establishmentCost.toFloat() / linkRtt.toFloat()
            }

            log("Link RTT measured: ${rtt}ms")
            updateKeepalive()

            // Fire both the link-level and destination-level "link established"
            // callbacks SYNCHRONOUSLY from rttPacket — matches Python RNS
            // (RNS/Link.py:550-551 fires both inline) and closes #56's
            // receiver-side first-packet-loss residual.
            //
            // The previous async-via-thread(isDaemon = true) approach raced
            // the read loop: rttPacket returned, the read loop immediately
            // processed the next packet (the sender's first user DATA, sent
            // as soon as the sender saw LRPROOF and went ACTIVE), and
            // link.processRegularData ran callbacks.packet?.let { ... } —
            // which was still null because the daemon thread that wires it
            // (via destination.linkEstablished -> link.setPacketCallback)
            // hadn't run yet. The DATA was silently dropped.
            //
            // Synchronous invocation guarantees that by the time the read
            // loop reads the next packet, every callback the user registered
            // in their linkEstablished handler is wired. Trade-off: a slow
            // user callback now blocks the receive loop for that link's
            // interface, same risk Python carries; documented as user
            // contract that callbacks should not block.
            callbacks.linkEstablished?.let { callback ->
                try {
                    callback(this)
                } catch (e: Exception) {
                    log("Error in link established callback:\n${e.stackTraceToString()}")
                }
            }

            owner?.let { ownerDest ->
                try {
                    ownerDest.invokeLinkEstablished(this)
                } catch (e: Exception) {
                    log("Error in destination link established callback:\n${e.stackTraceToString()}")
                }
            }
        } catch (e: Exception) {
            log("Error processing RTT packet: ${e.message}")
            teardown(LinkConstants.TEARDOWN_REASON_TIMEOUT)
        }
    }

    /**
     * Process link close packets.
     */
    private fun processLinkClose(packet: Packet) {
        try {
            val plaintext = decrypt(packet.data) ?: return

            // Verify the close is for this link
            if (plaintext.contentEquals(linkId)) {
                log("Received link close packet")
                val closeReason =
                    if (initiator) {
                        LinkConstants.TEARDOWN_REASON_DESTINATION_CLOSED
                    } else {
                        LinkConstants.TEARDOWN_REASON_INITIATOR_CLOSED
                    }
                // The peer already closed: do not echo a LINKCLOSE back
                // (python teardown_packet, Link.py:693-701, sends nothing).
                teardownInternal(closeReason, sendClosePacket = false)
            }
        } catch (e: Exception) {
            log("Error processing link close: ${e.message}")
        }
    }

    /**
     * Process resource advertisement packets.
     */
    private fun processResourceAdv(packet: Packet) {
        try {
            // Decrypt the advertisement data
            val plaintext = decrypt(packet.data) ?: return

            // Parse the advertisement
            val advertisement =
                network.reticulum.resource.ResourceAdvertisement
                    .unpack(plaintext)
            if (advertisement == null) {
                log("Failed to unpack resource advertisement")
                return
            }

            // Check if this is a request response
            if (network.reticulum.resource.ResourceAdvertisement
                    .isRequest(plaintext)
            ) {
                // python Link.py:1056-1062: a request resource is only accepted
                // when the owning destination has request handlers, and its
                // advertised (uncompressed) size is within max_request_size.
                // The owning destination of a receiver link is `owner` (python
                // `self.destination`, Link.py:214); `destination` is null on
                // receiver links, which made this gate a no-op. Without
                // handlers python silently ignores the advertisement (no reject).
                val target = servingDestination
                if (target == null || target.requestHandlerCount() == 0) {
                    log("Ignoring request resource on $this: no request handlers registered")
                    return
                }
                val maxReq = target.maxRequestSize
                if (maxReq != null) {
                    val advSize = network.reticulum.resource.ResourceAdvertisement
                        .readSize(plaintext) ?: 0
                    if (advSize > maxReq) {
                        log("Rejected request with excessive size $advSize (max $maxReq) on $this")
                        network.reticulum.resource.Resource.reject(advertisement, this)
                        return
                    }
                }
                // This is a request being sent as a resource
                val resource =
                    network.reticulum.resource.Resource.accept(
                        advertisement = advertisement,
                        link = this,
                        callback = { res -> requestResourceConcluded(res) },
                    )
                if (resource != null) {
                    registerIncomingResource(resource)
                }
                return
            }

            // Check if this is a response to a pending request
            if (network.reticulum.resource.ResourceAdvertisement
                    .isResponse(plaintext)
            ) {
                val requestId =
                    network.reticulum.resource.ResourceAdvertisement
                        .readRequestId(plaintext)
                if (requestId != null) {
                    // Find matching pending request
                    val pendingRequest =
                        synchronized(pendingRequests) {
                            pendingRequests.find { it.requestId.contentEquals(requestId) }
                        }

                    if (pendingRequest != null) {
                        // Enforce the request's max_response_size before accepting
                        // the response resource (python Link.py: reject an oversized
                        // response). No-op unless the caller set maxResponseSize.
                        val maxResp = pendingRequest.maxResponseSize
                        if (maxResp != null) {
                            val advSize = network.reticulum.resource.ResourceAdvertisement
                                .readSize(plaintext) ?: 0
                            if (advSize > maxResp) {
                                log("Rejected response with excessive size $advSize (max $maxResp) on $this")
                                network.reticulum.resource.Resource.reject(advertisement, this)
                                return
                            }
                        }
                        val resource =
                            network.reticulum.resource.Resource.accept(
                                advertisement = advertisement,
                                link = this,
                                callback = { res -> responseResourceConcluded(res) },
                                progressCallback = { res -> pendingRequest.updateProgress(res.overallProgress) },
                            )
                        if (resource != null) {
                            val responseSize =
                                network.reticulum.resource.ResourceAdvertisement
                                    .readSize(plaintext)
                            val transferSize =
                                network.reticulum.resource.ResourceAdvertisement
                                    .readTransferSize(plaintext)
                            if (responseSize != null) {
                                pendingRequest.responseSize = responseSize
                            }
                            if (transferSize != null) {
                                if (pendingRequest.responseTransferSize == null) {
                                    pendingRequest.responseTransferSize = 0
                                }
                                pendingRequest.responseTransferSize = (pendingRequest.responseTransferSize ?: 0) + transferSize
                            }
                            if (pendingRequest.startedAt == null) {
                                pendingRequest.startedAt = System.currentTimeMillis()
                            }
                            registerIncomingResource(resource)
                        }
                    }
                }
                return
            }

            // Note: dedup of duplicate advertisements lives inside
            // `Resource.accept` (mirroring python `Resource.py:223`), so
            // all four call sites below — request, response, ACCEPT_APP,
            // ACCEPT_ALL — are guarded uniformly. `Resource.accept`
            // returns null on a hash that is already in
            // `incomingResources`, and the `if (resource != null)`
            // checks below skip registration in that case.

            // General resource advertisement - check strategy
            when (resourceStrategy) {
                ACCEPT_NONE -> {
                    // python Link.py:1065 is silent under ACCEPT_NONE; answering with an
                    // encrypted RCL was a 1:1 reflection with no purpose.
                    log("Ignoring resource ${advertisement.hash.toHexString()} (strategy: ACCEPT_NONE)")
                }
                ACCEPT_ALL -> {
                    log("Accepting resource ${advertisement.hash.toHexString()} (strategy: ACCEPT_ALL)")
                    val resource =
                        network.reticulum.resource.Resource.accept(
                            advertisement = advertisement,
                            link = this,
                            // Do NOT pass `callback = { res -> resourceConcluded(res) }`
                            // here — Resource.assemble() already calls
                            // `link.resourceConcluded(this)` directly when the
                            // transfer completes, which fires `callbacks.resourceConcluded`
                            // on this link. Passing a per-resource callback that ALSO
                            // calls `resourceConcluded(res)` re-fires the user-level
                            // callback a second time, causing every received Resource
                            // (e.g. an LXMF message in RESOURCE representation) to be
                            // delivered twice on the receiver side. Mirrors Python
                            // RNS, where Link.py wires the user callback directly as
                            // the per-resource callback (Link.py:1097, 1102) and
                            // Link.resource_concluded() is pure bookkeeping.
                            callback = null,
                        )
                    if (resource != null) {
                        registerIncomingResource(resource)
                    }
                }
                ACCEPT_APP -> {
                    val callback = resourceCallback
                    if (callback != null) {
                        try {
                            if (callback(advertisement)) {
                                log("Accepting resource ${advertisement.hash.toHexString()} (strategy: ACCEPT_APP, callback returned true)")
                                val resource =
                                    network.reticulum.resource.Resource.accept(
                                        advertisement = advertisement,
                                        link = this,
                                        // See note above on the ACCEPT_ALL branch — the same
                                        // double-fire applies here. Resource.assemble() calls
                                        // link.resourceConcluded(this) directly when the
                                        // transfer completes; passing a per-resource callback
                                        // that re-calls resourceConcluded(res) here delivers
                                        // every received Resource twice.
                                        callback = null,
                                    )
                                if (resource != null) {
                                    registerIncomingResource(resource)
                                }
                            } else {
                                log("Rejecting resource ${advertisement.hash.toHexString()} (strategy: ACCEPT_APP, callback returned false)")
                                network.reticulum.resource.Resource
                                    .reject(advertisement, this)
                            }
                        } catch (e: Exception) {
                            log("Error in resource callback: ${e.message}")
                            network.reticulum.resource.Resource
                                .reject(advertisement, this)
                        }
                    } else {
                        log("Rejecting resource ${advertisement.hash.toHexString()} (strategy: ACCEPT_APP, no callback set)")
                        network.reticulum.resource.Resource
                            .reject(advertisement, this)
                    }
                }
            }
        } catch (e: Exception) {
            log("Error processing resource advertisement: ${e.message}")
        }
    }

    /**
     * Find the resource whose full hash starts with [truncatedHash]
     * (the first [RnsConstants.TRUNCATED_HASH_BYTES] bytes), without
     * allocating a per-candidate prefix copy. Callers hold the list's lock.
     */
    private fun findResourceByTruncatedHash(
        resources: List<network.reticulum.resource.Resource>,
        truncatedHash: ByteArray,
    ): network.reticulum.resource.Resource? {
        val n = RnsConstants.TRUNCATED_HASH_BYTES
        if (truncatedHash.size != n) return null
        return resources.find { resource ->
            val full = resource.hash
            if (full.size < n) return@find false
            var i = 0
            while (i < n) {
                if (full[i] != truncatedHash[i]) return@find false
                i++
            }
            true
        }
    }

    /**
     * Process resource request packets.
     */
    private fun processResourceReq(packet: Packet) {
        try {
            val plaintext = decrypt(packet.data) ?: return

            // Extract resource hash from request
            // Format is either:
            // - [flags][hash] for normal requests
            // - [HASHMAP_IS_EXHAUSTED][maphash][hash] for exhausted hashmap requests
            val resourceHash =
                if (plaintext.isNotEmpty() &&
                    plaintext[0].toInt() and 0xFF == network.reticulum.resource.ResourceConstants.HASHMAP_IS_EXHAUSTED
                ) {
                    // Exhausted hashmap format: skip first byte + MAPHASH_LEN
                    val offset = 1 + network.reticulum.resource.ResourceConstants.MAPHASH_LEN
                    if (plaintext.size >= offset + RnsConstants.TRUNCATED_HASH_BYTES) {
                        plaintext.copyOfRange(offset, offset + RnsConstants.TRUNCATED_HASH_BYTES)
                    } else {
                        log("Invalid exhausted hashmap request size: ${plaintext.size}")
                        return
                    }
                } else {
                    // Normal format: skip first byte (flags)
                    if (plaintext.size >= 1 + RnsConstants.TRUNCATED_HASH_BYTES) {
                        plaintext.copyOfRange(1, 1 + RnsConstants.TRUNCATED_HASH_BYTES)
                    } else {
                        log("Invalid resource request size: ${plaintext.size}")
                        return
                    }
                }

            // Find matching outgoing resource - compare truncated hash (first 16 bytes)
            val resource =
                synchronized(outgoingResources) {
                    findResourceByTruncatedHash(outgoingResources, resourceHash)
                }

            if (resource == null) {
                log("Received request for unknown resource: ${resourceHash.toHexString()}")
                return
            }

            // A re-delivered request packet must not be served twice. The peer asks for
            // parts by index, and serving the same request again re-sends parts the
            // receiver has already taken, desynchronising the window it uses to decide
            // what to ask for next — python calls the result a sequencing error and
            // guards it by packet hash (Link.py:1094-1095).
            if (!resource.admitRequestPacket(packet.getHash())) {
                log("Ignoring duplicate request for resource ${resourceHash.toHexString()}")
                return
            }

            // Process the request - send requested parts
            log("Processing request for resource ${resourceHash.toHexString()}")
            resource.handleRequest(plaintext)
        } catch (e: Exception) {
            log("Error processing resource request: ${e.message}")
        }
    }

    /**
     * Process resource hashmap update packets.
     */
    private fun processResourceHmu(packet: Packet) {
        try {
            val plaintext = decrypt(packet.data) ?: return

            // Extract resource hash (first 16 bytes)
            if (plaintext.size < RnsConstants.TRUNCATED_HASH_BYTES) {
                log("Invalid HMU packet size: ${plaintext.size}")
                return
            }

            val resourceHash = plaintext.copyOfRange(0, RnsConstants.TRUNCATED_HASH_BYTES)

            // Find matching incoming resource - compare truncated hash (first 16 bytes)
            val resource =
                synchronized(incomingResources) {
                    findResourceByTruncatedHash(incomingResources, resourceHash)
                }

            if (resource == null) {
                log("Received HMU for unknown resource: ${resourceHash.toHexString()}")
                return
            }

            // Process hashmap update - update received parts and request next
            log("Processing HMU for resource ${resourceHash.toHexString()}")
            resource.handleHashmapUpdate(plaintext)
        } catch (e: Exception) {
            log("Error processing resource HMU: ${e.message}")
        }
    }

    /**
     * Process resource initiator cancel packets.
     */
    private fun processResourceIcl(packet: Packet) {
        try {
            val plaintext = decrypt(packet.data) ?: return

            // Extract resource hash (first 16 bytes)
            if (plaintext.size < RnsConstants.TRUNCATED_HASH_BYTES) {
                log("Invalid ICL packet size: ${plaintext.size}")
                return
            }

            val resourceHash = plaintext.copyOfRange(0, RnsConstants.TRUNCATED_HASH_BYTES)

            // Find matching incoming resource (we're receiving, initiator is cancelling)
            // Compare truncated hash (first 16 bytes)
            val resource =
                synchronized(incomingResources) {
                    findResourceByTruncatedHash(incomingResources, resourceHash)
                }

            if (resource == null) {
                log("Received ICL for unknown resource: ${resourceHash.toHexString()}")
                return
            }

            log("Initiator cancelled resource ${resourceHash.toHexString()}")
            resource.cancel()
        } catch (e: Exception) {
            log("Error processing resource ICL: ${e.message}")
        }
    }

    /**
     * Process resource receiver cancel packets.
     */
    private fun processResourceRcl(packet: Packet) {
        try {
            val plaintext = decrypt(packet.data) ?: return

            // Extract resource hash (first 16 bytes)
            if (plaintext.size < RnsConstants.TRUNCATED_HASH_BYTES) {
                log("Invalid RCL packet size: ${plaintext.size}")
                return
            }

            val resourceHash = plaintext.copyOfRange(0, RnsConstants.TRUNCATED_HASH_BYTES)

            // Find matching outgoing resource (we're sending, receiver is rejecting)
            // Compare truncated hash (first 16 bytes)
            val resource =
                synchronized(outgoingResources) {
                    findResourceByTruncatedHash(outgoingResources, resourceHash)
                }

            if (resource == null) {
                log("Received RCL for unknown resource: ${resourceHash.toHexString()}")
                return
            }

            log("Receiver rejected resource ${resourceHash.toHexString()}")
            // REJECTED, not FAILED: the peer read the advertisement and refused it, which
            // is a different answer from a transfer that broke (python Resource._rejected,
            // Resource.py:1125-1136). cancel() here would report FAILED and invite a retry
            // into the same refusal.
            resource.rejected()
        } catch (e: Exception) {
            log("Error processing resource RCL: ${e.message}")
        }
    }

    /**
     * Process resource data packets.
     * NOTE: Resource data is NOT link-encrypted! It's already encrypted at the
     * resource level. We pass it directly to the Resource without decrypting.
     * This matches Python RNS behavior.
     */
    private fun processResource(packet: Packet) {
        try {
            logDebug { "processResource: packet.data.size=${packet.data.size} bytes (not decrypting - resource-level encrypted)" }

            // Route the part to the ONE incoming resource it belongs to. Parts
            // carry no explicit resource id — they are identified by a per-resource
            // map hash — so ask each resource whether the part is in its window.
            // Python feeds every incoming resource and lets each self-select
            // (Link.py:1143-1144); we select first (side-effect-free) so a part for
            // resource B never mutates resource A's state, and two concurrent
            // transfers on one link both progress instead of the first swallowing
            // every part.
            val resource =
                synchronized(incomingResources) {
                    incomingResources.toList()
                }.firstOrNull { res -> res.acceptsPart(packet.data) }

            if (resource == null) {
                log("Received resource part matching no incoming resource")
                return
            }

            // Pass the data directly - it's already resource-level encrypted, NOT link-encrypted
            resource.receivePart(packet.data)
        } catch (e: Exception) {
            log("Error processing resource data: ${e.message}")
        }
    }

    /**
     * Process keepalive packets.
     */
    private fun processKeepalive(packet: Packet) {
        // Receivers respond to keepalive requests, but throttle the 0xFE reply to
        // at most one per keepalive interval (python Link.py:1132 gates on
        // `time >= last_outbound + keepalive`). Without this, a flood of 0xFF
        // forces a 0xFE per packet — a reflection/amplification and CPU sink.
        if (!initiator && packet.data.contentEquals(KEEPALIVE_REQUEST)) {
            if (System.currentTimeMillis() >= lastOutbound + keepalive) {
                val keepaliveResponse = linkPacket(KEEPALIVE_RESPONSE, context = PacketContext.KEEPALIVE)
                hadOutbound(isKeepalive = true) // before the send — see request()
                Transport.outbound(keepaliveResponse)
            }
        }
        // Keepalives update last_inbound which is already handled in receive()
    }

    /**
     * Process channel packets.
     */
    private fun processChannel(packet: Packet) {
        if (_channel == null) {
            log("Channel data received without open channel")
            return
        }

        // Prove receipt of the channel packet (Python: Link.py:1173). The
        // proveTapForTest seam fires inside provePacket() (which packet.prove()
        // routes to for a link packet), so the channel-proof context is logged
        // there — no separate tap call here (it would double-count).
        packet.link = this
        packet.prove()

        // Decrypt and pass to the channel
        val plaintext = decrypt(packet.data)
        if (plaintext != null) {
            updatePhyStats(packet.rssi, packet.snr, packet.q)
            _channel!!.receive(plaintext)
        }
    }

    /**
     * Process command packets.
     */
    private fun processCommand(packet: Packet) {
        // TODO: Implement command handling
        log("Command handling not yet implemented")
    }

    /**
     * Process command status packets.
     */
    private fun processCommandStatus(packet: Packet) {
        // TODO: Implement command status handling
        log("Command status handling not yet implemented")
    }

    /**
     * Process PROOF type packets.
     */
    private fun processProofPacket(packet: Packet) {
        when (packet.context) {
            PacketContext.RESOURCE_PRF -> processResourceProof(packet)
            else -> {
                log("Unhandled proof context: ${packet.context}")
            }
        }
    }

    /**
     * Process resource proof packets.
     */
    private fun processResourceProof(packet: Packet) {
        try {
            val data = packet.data
            if (data.isEmpty()) {
                log("Invalid proof packet: no data")
                return
            }

            // Proof format: [resource_hash (32 bytes)][proof (32 bytes)]
            // Python sends full hash (32 bytes), not truncated (16 bytes)
            if (data.size != RnsConstants.FULL_HASH_BYTES * 2) {
                log("Invalid proof packet size: ${data.size}")
                return
            }

            // Extract resource hash (full 32 bytes, but we compare truncated for lookup)
            val resourceHashFull = data.copyOfRange(0, RnsConstants.FULL_HASH_BYTES)
            val resourceHash = resourceHashFull.copyOfRange(0, RnsConstants.TRUNCATED_HASH_BYTES)

            // Find matching outgoing resource - compare truncated hash (first 16 bytes)
            val resource =
                synchronized(outgoingResources) {
                    findResourceByTruncatedHash(outgoingResources, resourceHash)
                }

            if (resource == null) {
                log("Received proof for unknown resource: ${resourceHash.toHexString()}")
                return
            }

            // Validate the proof
            if (resource.validateProof(data)) {
                log("Proof validated for resource ${resourceHash.toHexString()}")
                lastProof = System.currentTimeMillis()
                // Resource validation handles completion logic
            } else {
                log("Proof validation failed for resource ${resourceHash.toHexString()}")
            }
        } catch (e: Exception) {
            log("Error processing resource proof: ${e.message}")
        }
    }

    /**
     * Register an outgoing resource with this link.
     */
    fun registerOutgoingResource(resource: network.reticulum.resource.Resource) {
        synchronized(outgoingResources) {
            if (!outgoingResources.contains(resource)) {
                outgoingResources.add(resource)
                log("Registered outgoing resource ${resource.hash.toHexString()}")
            }
        }
    }

    /**
     * Register an incoming resource with this link. Reference-dedup only —
     * callers are expected to consult [hasIncomingResource] first to avoid
     * registering a fresh Resource built from a duplicate RESOURCE_ADV. This
     * mirrors Python `RNS.Link.register_incoming_resource` (Link.py:1308),
     * which is also a plain append; the python `Resource.accept` does the
     * hash-based dedup check before registration.
     */
    fun registerIncomingResource(resource: network.reticulum.resource.Resource) {
        synchronized(incomingResources) {
            if (!incomingResources.contains(resource)) {
                incomingResources.add(resource)
                log("Registered incoming resource ${resource.hash.toHexString()}")
            }
        }
    }

    /**
     * Returns true if an incoming resource with the same advertisement hash
     * is already registered. Mirrors Python `RNS.Link.has_incoming_resource`
     * (Link.py:1311) — the hash equality check that prevents accepting the
     * same RESOURCE_ADV twice when the sender retransmits it.
     *
     * This check is load-bearing because Transport's packet hashlist
     * intentionally skips LINK-destined packets (see Transport.processInbound's
     * `rememberHash` calculation), so a sender retransmit reaches the link
     * layer in raw form. Without this check, two independent Resource state
     * machines would fill from the same parts, both `assemble()`, and the
     * user delivery callback would fire twice (observed as `Inbox sizes
     * [N, N]` in the cross-impl conformance suite when `jobsLock` was
     * released around blocking I/O — the timing change exposed the latent
     * race).
     */
    fun hasIncomingResource(advertisementHash: ByteArray): Boolean =
        synchronized(incomingResources) {
            incomingResources.any { it.hash.contentEquals(advertisementHash) }
        }

    /**
     * Invoke the inbound Resource start callback synchronously.
     *
     * Python calls this callback inside `Resource.accept`, after registration
     * and before requesting the first parts. Keep the same ordering so callback
     * configuration is guaranteed to apply before any payload can assemble.
     */
    internal fun resourceStarted(resource: network.reticulum.resource.Resource) {
        callbacks.resourceStarted?.let { callback ->
            try {
                callback(resource)
            } catch (e: Exception) {
                log("Error in resource started callback: ${e.message}")
            }
        }
    }

    /**
     * Test-only: snapshot of the current incoming resource hashes.
     * Used by `LinkResourceDedupTest` (in `rns-test`, a separate module —
     * Kotlin `internal` would not cross the module boundary, hence `public`)
     * to verify dedup behavior. Production code should NOT depend on this
     * surface.
     */
    @org.jetbrains.annotations.VisibleForTesting
    fun incomingResourceHashesForTest(): List<ByteArray> =
        synchronized(incomingResources) { incomingResources.map { it.hash } }

    /**
     * Called when a resource transfer concludes (successfully or with failure).
     * Updates link statistics and removes resource from tracking.
     *
     * @param resource The resource that concluded
     */
    fun resourceConcluded(
        resource: network.reticulum.resource.Resource,
        // false for the intermediate segments of a split transfer: the link's bookkeeping
        // runs, the app-visible callback does not (python fires it only on the last
        // segment, Resource.py:738-751; per-segment firing handed consumers a COMPLETE
        // resource with data == null).
        notifyCallback: Boolean = true,
    ) {
        val concludedAt = System.currentTimeMillis()
        val wasIncoming =
            synchronized(incomingResources) {
                incomingResources.contains(resource)
            }
        val wasOutgoing =
            synchronized(outgoingResources) {
                outgoingResources.contains(resource)
            }

        // Update statistics based on resource performance
        if (wasIncoming) {
            // Record this transfer's final window so the NEXT inbound Resource on
            // this link inherits it (Resource.accept reads getLastResourceWindow).
            // Mirrors python `Link.resource_concluded` (Link.py:1284):
            //   self.last_resource_window = resource.window
            // Without this, every inbound transfer restarts at WINDOW=4 and
            // multi-resource throughput silently degrades.
            lastResourceWindow = resource.currentWindow

            synchronized(incomingResources) {
                incomingResources.remove(resource)
            }
        }

        if (wasOutgoing) {
            // Calculate expected rate from resource transfer
            // TODO: Get resource.startedTransferring property when Resource is fully implemented
            // For now, we skip this calculation
            // val transferTime = (concludedAt - resource.startedTransferring) / 1000.0f
            // if (transferTime > 0.0001f) {
            //     expectedRate = (resource.size * 8) / transferTime
            // }

            synchronized(outgoingResources) {
                outgoingResources.remove(resource)
            }
        }

        // Invoke the resource concluded callback if set
        if (notifyCallback) callbacks.resourceConcluded?.let { callback ->
            thread(isDaemon = true) {
                try {
                    callback(resource)
                } catch (e: Exception) {
                    log("Error in resource concluded callback: ${e.message}")
                }
            }
        }

        log("Resource ${resource.hash.toHexString()} concluded")
    }

    /**
     * Handle an incoming request on this link.
     *
     * @param requestId The unique request identifier
     * @param unpackedRequest Array of [timestamp, pathHash, data]
     */
    fun handleRequest(
        requestId: ByteArray,
        unpackedRequest: List<Any?>,
    ) {
        if (status != LinkConstants.ACTIVE) return

        try {
            // Extract request components
            val requestedAt = (unpackedRequest[0] as? Number)?.toLong() ?: System.currentTimeMillis()
            val pathHash = unpackedRequest[1] as? ByteArray ?: return
            val requestData = unpackedRequest[2] as? ByteArray

            // The destination whose handlers serve this link; see [servingDestination].
            val targetDestination = servingDestination ?: return

            // Look up the request handler
            val handler =
                targetDestination.getRequestHandler(pathHash) ?: run {
                    log("No handler found for path hash ${pathHash.toHexString()}")
                    return
                }

            // Check access control
            val allowed =
                when (handler.allow) {
                    network.reticulum.destination.RequestPolicy.ALLOW_NONE -> false
                    network.reticulum.destination.RequestPolicy.ALLOW_ALL -> true
                    network.reticulum.destination.RequestPolicy.ALLOW_LIST -> {
                        val remoteId = remoteIdentity
                        remoteId != null && handler.allowedList?.any { it.contentEquals(remoteId.hash) } == true
                    }
                    else -> false
                }

            if (!allowed) {
                val identityStr = remoteIdentity?.hexHash ?: "<Unknown>"
                log("Request ${requestId.toHexString()} from $identityStr not allowed for path: ${handler.path}")
                return
            }

            log("Handling request ${requestId.toHexString()} for: ${handler.path}")

            // Generate response
            val response =
                try {
                    handler.responseGenerator(
                        handler.path,
                        requestData,
                        requestId,
                        linkId,
                        remoteIdentity,
                        requestedAt,
                    )
                } catch (e: Exception) {
                    log("Error in response generator: ${e.message}")
                    null
                }

            // Send response if not null
            when (response) {
                null -> Unit
                is network.reticulum.destination.RequestResponse.Bytes ->
                    sendResponse(requestId, response.data, handler.autoCompress)
                is network.reticulum.destination.RequestResponse.Value ->
                    sendResponse(requestId, response.value, handler.autoCompress)
                is network.reticulum.destination.RequestResponse.File ->
                    sendFileResponse(
                        requestId, response.content, response.metadata, handler.autoCompress,
                    )
            }
        } catch (e: Exception) {
            log("Error handling request: ${e.message}")
        }
    }

    /**
     * Send a file response: always a Resource, with the metadata in the resource's own
     * metadata block rather than wrapped into the content (python `Link.py:845-846`).
     *
     * Unlike [sendResponse] there is no packet form even for a small file. The requester
     * distinguishes the two branches by whether the response arrived with metadata, so
     * sending a short file as a RESPONSE packet would strip the metadata and silently turn
     * it into an ordinary response.
     */
    private fun sendFileResponse(
        requestId: ByteArray,
        content: ByteArray,
        metadata: ByteArray?,
        autoCompress: Boolean,
    ) {
        try {
            network.reticulum.resource.Resource.create(
                data = content,
                link = this,
                metadata = metadata,
                requestId = requestId,
                isResponse = true,
                autoCompress = autoCompress,
            )
        } catch (e: Exception) {
            log("Error sending file response: ${e.message}")
        }
    }

    /**
     * Send a response to a request.
     *
     * @param requestId The request ID this is responding to
     * @param response The response value: a ByteArray goes on the wire as a
     *   msgpack bin (the [RequestResponse.Bytes] form); anything else is
     *   packed as its msgpack type (the [RequestResponse.Value] form), which
     *   is what a python requester's `umsgpack.unpackb(...)[1]` hands back as
     *   a list, int or bool.
     * @param autoCompress Whether to auto-compress (if large enough)
     */
    private fun sendResponse(
        requestId: ByteArray,
        response: Any?,
        autoCompress: Boolean,
    ) {
        try {
            // Pack response as msgpack: [requestId, response]
            val packedResponse = RequestWire.packResponse(requestId, response)
            // Send as packet if small enough, otherwise as resource
            if (packedResponse.size <= mdu) {
                val packet = linkPacket(encrypt(packedResponse), context = PacketContext.RESPONSE)
                hadOutbound(isData = true) // before the send — see request()
                Transport.outbound(packet)
            } else {
                // Send as resource with is_response flag (Python: Link.py:903-905)
                network.reticulum.resource.Resource.create(
                    data = packedResponse,
                    link = this,
                    requestId = requestId,
                    isResponse = true,
                    autoCompress = autoCompress,
                )
            }
        } catch (e: Exception) {
            log("Error sending response: ${e.message}")
        }
    }

    /**
     * Handle an incoming response to a previous request.
     *
     * @param requestId The request ID this is responding to
     * @param responseData The response data
     * @param responseSize The total size of the response
     * @param transferSize The transfer size (may differ due to compression)
     * @param metadata Optional metadata for file responses
     */
    fun handleResponse(
        requestId: ByteArray,
        responseData: ByteArray?,
        responseSize: Int,
        transferSize: Int,
        metadata: ByteArray? = null,
    ) {
        if (status != LinkConstants.ACTIVE) return

        try {
            // Find matching pending request
            val receipt =
                synchronized(pendingRequests) {
                    pendingRequests.find { it.requestId.contentEquals(requestId) }
                }

            if (receipt == null) {
                log("Received response for unknown request: ${requestId.toHexString()}")
                return
            }

            // Update receipt
            receipt.responseSize = responseSize
            if (receipt.responseTransferSize == null) {
                receipt.responseTransferSize = 0
            }
            receipt.responseTransferSize = (receipt.responseTransferSize ?: 0) + transferSize

            // Mark as ready and invoke callback
            receipt.responseReceived(responseData, metadata)

            // Remove from pending list
            synchronized(pendingRequests) {
                pendingRequests.remove(receipt)
            }
        } catch (e: Exception) {
            log("Error handling response: ${e.message}")
        }
    }

    /**
     * Called when a request resource transfer completes.
     *
     * @param resource The completed resource
     */
    fun requestResourceConcluded(resource: network.reticulum.resource.Resource) {
        if (resource.status == network.reticulum.resource.ResourceConstants.COMPLETE) {
            val packedRequest =
                resource.data ?: run {
                    log("Request resource completed but has no data")
                    return
                }

            // Unpack the request and compute requestId from the packed data
            // (Python: Link.py:931-940)
            val requestId = Hashes.truncatedHash(packedRequest)
            val unpackedRequest = unpackRequest(packedRequest, "resource request") ?: return

            // Handle request on a separate thread (Python: Link.py:938-939)
            thread(isDaemon = true) {
                handleRequest(requestId, unpackedRequest)
            }
        } else {
            log("Incoming request resource failed with status: ${resource.status}")
        }
    }

    /**
     * Called when a response resource transfer completes.
     *
     * @param resource The completed resource
     */
    fun responseResourceConcluded(resource: network.reticulum.resource.Resource) {
        if (resource.status != network.reticulum.resource.ResourceConstants.COMPLETE) {
            log("Response resource failed with status: ${resource.status}")
            // Notify pending request of failure
            val requestId = resource.requestId
            if (requestId != null) {
                synchronized(pendingRequests) {
                    pendingRequests.find { it.requestId.contentEquals(requestId) }?.let { pending ->
                        pending.requestFailed()
                    }
                }
            }
            return
        }

        val responseData = resource.data
        if (responseData == null) {
            log("Response resource has no data")
            return
        }

        try {
            // Python special-case: file responses are sent as raw resource data with metadata,
            // not as msgpack [request_id, response_data].
            if (resource.hasMetadata) {
                val requestId = resource.requestId
                if (requestId == null) {
                    log("Response resource has metadata but no request ID")
                    return
                }

                handleResponse(
                    requestId,
                    responseData,
                    resource.totalSize,
                    resource.size,
                    metadata = resource.metadataBytes,
                )
                return
            }

            // Unpack response: [request_id, response_data]
            val (requestId, unpackedResponseData) = unpackResponse(responseData) ?: return

            // Pass to handleResponse
            handleResponse(requestId, unpackedResponseData, responseData.size, resource.totalSize)
        } catch (e: Exception) {
            log("Error processing response resource: ${e.message}")
        }
    }

    /**
     * Enable or disable physical layer statistics tracking.
     *
     * @param track Whether to track physical layer statistics
     */
    fun trackPhyStats(track: Boolean) {
        this.trackPhyStats = track
    }

    /**
     * Get the RSSI (Received Signal Strength Indication) value.
     *
     * @return RSSI value if tracking is enabled and available, null otherwise
     */
    fun getRssi(): Int? = if (trackPhyStats) phyRssi else null

    /**
     * Get the SNR (Signal-to-Noise Ratio) value.
     *
     * @return SNR value if tracking is enabled and available, null otherwise
     */
    fun getSnr(): Float? = if (trackPhyStats) phySnr else null

    /**
     * Get the Q (link quality) value.
     *
     * @return Q value if tracking is enabled and available, null otherwise
     */
    fun getQ(): Float? = if (trackPhyStats) phyQ else null

    /**
     * Update physical layer statistics from interface.
     * This is typically called by the interface when a packet is received.
     *
     * @param rssi RSSI value
     * @param snr SNR value
     * @param q Link quality value
     */
    fun updatePhyStats(
        rssi: Int? = null,
        snr: Float? = null,
        q: Float? = null,
    ) {
        if (trackPhyStats) {
            rssi?.let { phyRssi = it }
            snr?.let { phySnr = it }
            q?.let { phyQ = it }
        }
    }

    /**
     * Get the MTU for this link.
     *
     * @return MTU if link is active, null otherwise
     */
    // ===== Conformance test seams (separate-module bridge can't read private state) =====
    /** [prv, pub, sharedKey, derivedKey] presence — pins forward-secret
     *  ephemeral-key purge on close (reference wire_link_key_material). */
    fun keyMaterialPresenceForTest(): BooleanArray =
        booleanArrayOf(prv != null, pub != null, sharedKey != null, derivedKey != null)

    /** Plant sentinel physical-layer stats so the track_phy_stats gating in
     *  getRssi/getSnr/getQ is observable (reference wire_link_phy_stats_gate). */
    fun setPhyStatsForTest(rssiValue: Int?, snrValue: Float?, qValue: Float?) {
        phyRssi = rssiValue
        phySnr = snrValue
        phyQ = qValue
    }

    /** Force the link lifecycle status (status has a private setter). Mirrors
     *  the reference's `link.status = Link.PENDING` to deterministically hit
     *  identify()'s ACTIVE-only guard (reference wire_link_identify_pending). */
    fun setStatusForTest(newStatus: Int) {
        status = newStatus
    }

    /** This link's own ephemeral X25519 / Ed25519 public bytes (reference
     *  wire_capture_lrproof_frame reads link.pub_bytes / link.sig_pub_bytes). */
    fun pubBytesForTest(): ByteArray? = pub?.copyOf()
    fun sigPubBytesForTest(): ByteArray? = sigPub?.copyOf()

    /** Point the peer signing key at this link's OWN sig pub so a real
     *  link.sign() yields a signature real validation accepts — the reference's
     *  `link.peer_sig_pub = link.sig_pub` self-consistent-signing setup for
     *  wire_inject_crafted_link_proof (no cross-process key needed). */
    @network.reticulum.RnsTestSeam
    fun makeSelfConsistentSigningForTest() {
        peerSigPub = sigPub?.copyOf()
    }

    fun getMtu(): Int? = if (status == LinkConstants.ACTIVE) mtu else null

    /**
     * Test-only MTU override (the field has a private setter). Mirrors the
     * reference conformance harness temporarily shrinking `link.mtu` so a modest
     * Resource payload chunks into many small parts (wire_tcp.py
     * cmd_wire_resource_create force_sdu / _build_resource_receiver). Resource
     * derives its per-part SDU from this at construction; the caller restores the
     * negotiated MTU afterwards.
     */
    fun setMtuForTest(value: Int) {
        mtu = value
    }

    /**
     * Get the MDU (Maximum Data Unit) for this link.
     *
     * @return MDU if link is active, null otherwise
     */
    fun getMdu(): Int? = if (status == LinkConstants.ACTIVE) mdu else null

    /**
     * Check if a resource is in the incoming resources list.
     *
     * @param resource The resource to check
     * @return true if the resource is in the list, false otherwise
     */
    fun hasIncomingResource(resource: network.reticulum.resource.Resource): Boolean = hasIncomingResource(resource.hash)

    /**
     * Check if a resource is in the outgoing resources list.
     *
     * @param resource The resource to check
     * @return true if the resource is in the list, false otherwise
     */
    fun hasOutgoingResource(resource: network.reticulum.resource.Resource): Boolean {
        synchronized(outgoingResources) {
            return outgoingResources.any { it.hash.contentEquals(resource.hash) }
        }
    }

    /**
     * Check if the link is ready for a new outgoing resource.
     *
     * @return true if no outgoing resources are active, false otherwise
     */
    fun readyForNewResource(): Boolean {
        synchronized(outgoingResources) {
            return outgoingResources.isEmpty()
        }
    }

    /**
     * Cancel an outgoing resource transfer.
     *
     * @param resource The resource to cancel
     * @return true if removed, false if not found
     */
    fun cancelOutgoingResource(resource: network.reticulum.resource.Resource): Boolean {
        synchronized(outgoingResources) {
            val removed = outgoingResources.remove(resource)
            if (!removed) {
                log("Attempt to cancel a non-existing outgoing resource")
            }
            return removed
        }
    }

    /**
     * Cancel an incoming resource transfer.
     *
     * @param resource The resource to cancel
     * @return true if removed, false if not found
     */
    fun cancelIncomingResource(resource: network.reticulum.resource.Resource): Boolean {
        synchronized(incomingResources) {
            val removed = incomingResources.remove(resource)
            if (!removed) {
                log("Attempt to cancel a non-existing incoming resource")
            }
            return removed
        }
    }

    /**
     * Get the window size from the last concluded resource.
     *
     * @return Window size if available, null otherwise
     */
    fun getLastResourceWindow(): Int? = lastResourceWindow

    /**
     * Get the EIFR (Effective Information Flow Rate) from the last concluded resource.
     *
     * @return EIFR if available, null otherwise
     */
    fun getLastResourceEifr(): Float? = lastResourceEifr

    /**
     * Set the link established callback.
     *
     * @param callback Function to call when link is established
     */
    fun setLinkEstablishedCallback(callback: ((Link) -> Unit)?) {
        callbacks.linkEstablished = callback
    }

    /**
     * Set the link closed callback.
     *
     * @param callback Function to call when link is closed
     */
    fun setLinkClosedCallback(callback: ((Link) -> Unit)?) {
        callbacks.linkClosed = callback
    }

    /**
     * Set the packet callback.
     *
     * @param callback Function to call when a packet is received
     */
    fun setPacketCallback(callback: ((ByteArray, Packet) -> Unit)?) {
        callbacks.packet = callback
    }

    /**
     * Set the remote identified callback.
     *
     * @param callback Function to call when remote peer identifies
     */
    fun setRemoteIdentifiedCallback(callback: ((Link, Identity) -> Unit)?) {
        callbacks.remoteIdentified = callback
    }

    /**
     * Set the resource started callback.
     *
     * @param callback Function to call when a resource transfer starts
     */
    fun setResourceStartedCallback(callback: ((Any) -> Unit)?) {
        callbacks.resourceStarted = callback
    }

    /**
     * Set the resource concluded callback.
     *
     * @param callback Function to call when a resource transfer concludes
     */
    fun setResourceConcludedCallback(callback: ((Any) -> Unit)?) {
        callbacks.resourceConcluded = callback
    }

    /**
     * Get the establishment rate (data rate during link establishment).
     *
     * @return Establishment rate in bits per second if available, null otherwise
     */
    fun getEstablishmentRate(): Float? {
        return establishmentRate?.let { it * 8 } // Convert bytes/ms to bits/second
    }

    /**
     * Get the expected data rate for this link.
     *
     * @return Expected rate in bits per second if available, null otherwise
     */
    fun getExpectedRate(): Float? = if (status == LinkConstants.ACTIVE) expectedRate else null

    override fun toString(): String = "Link[${linkId.toHexString().take(12)}]"
}

/**
 * Receipt for a request sent over a link.
 * Tracks the status and response of the request.
 */
class RequestReceipt(
    internal val link: Link,
    internal val requestId: ByteArray,
    val requestSize: Int,
    private val responseCallback: ((RequestReceipt) -> Unit)? = null,
    private val failedCallback: ((RequestReceipt) -> Unit)? = null,
    private val progressCallback: ((RequestReceipt) -> Unit)? = null,
    val timeout: Long,
) {
    companion object {
        const val FAILED = 0x00
        const val SENT = 0x01
        const val DELIVERED = 0x02
        const val RECEIVING = 0x03
        const val READY = 0x04
    }

    var status: Int = SENT
        private set

    var progress: Float = 0.0f
        private set

    var response: ByteArray? = null
        private set

    var metadata: ByteArray? = null
        private set

    var responseSize: Int? = null
        internal set

    var responseTransferSize: Int? = null
        internal set

    /** Maximum accepted response size in bytes (python PendingRequest.max_response_size).
     *  null = unlimited; when set, the Link rejects an oversized response resource. */
    var maxResponseSize: Int? = null
        internal set

    private val sentAt = System.currentTimeMillis()
    private var concludedAt: Long? = null
    private var responseConcludedAt: Long? = null

    internal var startedAt: Long? = null

    /**
     * Called when the response is received.
     */
    internal fun responseReceived(
        responseData: ByteArray?,
        metadata: ByteArray? = null,
    ) {
        if (status == FAILED) return

        this.progress = 1.0f
        this.response = responseData
        this.metadata = metadata
        this.status = READY
        this.responseConcludedAt = System.currentTimeMillis()

        // Invoke callbacks
        progressCallback?.let { callback ->
            kotlin.concurrent.thread(isDaemon = true) {
                try {
                    callback(this)
                } catch (e: Exception) {
                    println("[RequestReceipt] Error in progress callback: ${e.message}")
                }
            }
        }

        responseCallback?.let { callback ->
            kotlin.concurrent.thread(isDaemon = true) {
                try {
                    callback(this)
                } catch (e: Exception) {
                    println("[RequestReceipt] Error in response callback: ${e.message}")
                }
            }
        }
    }

    /**
     * Called when the request times out or fails.
     */
    internal fun requestFailed() {
        if (status == READY || status == FAILED) return

        this.status = FAILED
        this.concludedAt = System.currentTimeMillis()

        failedCallback?.let { callback ->
            kotlin.concurrent.thread(isDaemon = true) {
                try {
                    callback(this)
                } catch (e: Exception) {
                    println("[RequestReceipt] Error in failed callback: ${e.message}")
                }
            }
        }
    }

    /**
     * The request itself has been delivered (python `request_resource_concluded`,
     * Link.py:1390-1392): status DELIVERED and the response budget starts now.
     */
    internal fun markDelivered() {
        if (status == FAILED || status == READY) return
        if (startedAt == null) startedAt = System.currentTimeMillis()
        if (status == SENT) status = DELIVERED
    }

    /**
     * Update progress for resource transfers.
     */
    internal fun updateProgress(newProgress: Float) {
        if (status == FAILED) return

        this.progress = newProgress
        if (status != RECEIVING) {
            status = RECEIVING
        }

        progressCallback?.let { callback ->
            kotlin.concurrent.thread(isDaemon = true) {
                try {
                    callback(this)
                } catch (e: Exception) {
                    println("[RequestReceipt] Error in progress callback: ${e.message}")
                }
            }
        }
    }

    /**
     * Get the request ID (copy).
     */
    fun getRequestIdCopy(): ByteArray = requestId.copyOf()

    /**
     * Get the response data if ready (copy).
     */
    fun getResponseCopy(): ByteArray? = response?.copyOf()

    /**
     * Get the response time in milliseconds.
     */
    fun getResponseTime(): Long? {
        val concluded = responseConcludedAt ?: return null
        val started = startedAt ?: sentAt
        return concluded - started
    }

    /**
     * Check if the request has concluded (success or failure).
     */
    fun concluded(): Boolean = status == READY || status == FAILED
}
