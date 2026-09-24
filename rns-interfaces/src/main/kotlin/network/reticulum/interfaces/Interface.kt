package network.reticulum.interfaces

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import network.reticulum.common.ByteArrayKey
import network.reticulum.common.InterfaceMode
import network.reticulum.common.RnsConstants
import network.reticulum.common.toKey
import network.reticulum.crypto.Hashes
import network.reticulum.transport.HeldAnnounce
import network.reticulum.transport.InterfaceRef
import network.reticulum.transport.Transport
import network.reticulum.transport.TransportConstants
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedDeque
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * Base interface contract for Reticulum network interfaces.
 *
 * Interfaces are responsible for sending and receiving raw packet data.
 * They handle framing, but not packet parsing or routing.
 */
abstract class Interface(
    /** Human-readable name for this interface. */
    val name: String
) {
    // IFAC (Interface Access Code) properties for network isolation

    /** IFAC network name for access control. */
    open val ifacNetname: String? = null

    /** IFAC network passphrase for access control. */
    open val ifacNetkey: String? = null

    /**
     * IFAC credentials derived once, lazily, from [ifacNetname]/[ifacNetkey]
     * (python Reticulum.py:994-1008: ifac_origin = full_hash(netname) + full_hash(netkey),
     * ifac_key = hkdf(64, full_hash(ifac_origin), IFAC_SALT), identity = from_bytes(key)).
     * Null when neither is set, i.e. IFAC disabled.
     */
    private val ifacCredentials: IfacCredentials? by lazy {
        IfacUtils.deriveIfacCredentials(ifacNetname, ifacNetkey)
    }

    /**
     * The class-level `DEFAULT_IFAC_SIZE`: the IFAC tag length in bytes this medium uses
     * when the config supplies none. 16 for packet/IP media (python `Interface.py:96`);
     * serial and framed media override it to 8 (`SerialInterface.py:53`,
     * `KISSInterface.py:63`, `AX25KISSInterface.py:70`, `RNodeInterface.py:110`,
     * `PipeInterface.py:57`).
     *
     * The peer derives its own tag length from ITS class constant, never from anything on
     * the wire, so a mismatch is not a degraded link — every packet fails IFAC validation
     * and the two nodes are silently partitioned.
     */
    protected open val defaultIfacSize: Int
        get() = 16

    /**
     * Configured `ifac_size` in BITS, as the config file expresses it, or null when the
     * config did not set one. Subclasses that accept the setting override this.
     */
    protected open val configuredIfacSizeBits: Int?
        get() = null

    /**
     * IFAC tag length in bytes while IFAC is enabled; [ifacSize] reports it only when
     * credentials exist.
     *
     * python `Reticulum.py:802-803`: a configured size at or above `IFAC_MIN_SIZE * 8`
     * bits converts to bytes, and anything below it is DISCARDED in favour of the class
     * default rather than clamped.
     */
    protected open val enabledIfacSize: Int
        get() = configuredIfacSizeBits
            ?.takeIf { it >= RnsConstants.IFAC_MIN_SIZE * 8 }
            ?.div(8)
            ?: defaultIfacSize

    /**
     * IFAC size in bytes. 0 = disabled.
     * When ifacNetname or ifacNetkey is set, defaults to [enabledIfacSize] (16 bytes).
     */
    open val ifacSize: Int
        get() = if (ifacCredentials != null) enabledIfacSize else 0

    /** IFAC key derived from network name/key. Null if IFAC disabled. */
    open val ifacKey: ByteArray?
        get() = ifacCredentials?.key

    /** IFAC identity for signing packets. Null if IFAC disabled. */
    open val ifacIdentity: network.reticulum.identity.Identity?
        get() = ifacCredentials?.identity

    /** Whether this interface can receive packets. */
    open val canReceive: Boolean = true

    /** Whether this interface can send packets. */
    open val canSend: Boolean = true

    /** Whether this interface forwards packets (for transport nodes). */
    open val forward: Boolean = false

    /** Whether this interface repeats packets (for radio repeaters). */
    open val repeat: Boolean = false

    /** Interface operational mode. */
    open val mode: InterfaceMode = InterfaceMode.FULL

    /**
     * Runtime override for [mode], settable after interface construction.
     *
     * When non-null, [InterfaceAdapter.mode] surfaces this value to Transport
     * instead of the declared [mode]. Introduced so the conformance bridge
     * can park a peer in any of the six modes without requiring a
     * per-subclass constructor parameter, mirroring Python RNS's post-init
     * `interface.mode = MODE_X` assignment used by `Reticulum._synthesize_interface`
     * (Reticulum.py:773) and by runtime tests.
     *
     * Production code paths should never set this — prefer declaring the
     * intended mode via the subclass's natural configuration surface.
     */
    @Volatile
    var modeOverride: InterfaceMode? = null

    // Per-instance config overrides. python sets these as attributes on the constructed
    // interface (Reticulum.py:862-900, 946-950); here the class values are `open val`s,
    // so a daemon's factory applies the config through these and the adapter reads
    // `override ?: class value`. Null keeps the class value.
    @Volatile var announceCapOverride: Double? = null
    @Volatile var announceRateTargetOverride: Int? = null
    @Volatile var announceRateGraceOverride: Int? = null
    @Volatile var announceRatePenaltyOverride: Int? = null
    @Volatile var announcesFromInternalOverride: Boolean? = null
    @Volatile var announcesToInternalOverride: Boolean? = null

    /** python `ingress_control = no` (Reticulum.py:819-820): disable announce and path-request ingress limiting. */
    fun setIngressControl(enabled: Boolean) {
        ingressControl.set(enabled)
    }

    fun ingressControlEnabled(): Boolean = ingressControl.get()
    /** Estimated bitrate in bits per second. */
    open val bitrate: Int = 62500

    /** Announce bandwidth cap as fraction of interface bitrate (default 2%). */
    open val announceCap: Double = 0.02

    /**
     * Minimum seconds between announces from one destination before this interface starts
     * counting rate violations, or null for no announce-rate limiting (python
     * `announce_rate_target`). The two knobs below only apply when this is set.
     */
    open val announceRateTarget: Int? = null

    /** Violations tolerated before a destination is blocked (python `announce_rate_grace`). */
    open val announceRateGrace: Int = 0

    /** Seconds added to the target when blocking (python `announce_rate_penalty`). */
    open val announceRatePenalty: Int = 0

    /**
     * Whether announces LEARNED on an INTERNAL interface may be forwarded out of this one
     * (python `announces_from_internal`, `Interface.py:122`).
     *
     * Defaults to true, matching the reference: an internal segment's announces propagate
     * outward unless an operator opts a specific interface out. Set false on an
     * outward-facing interface to stop internal topology leaking onto the public mesh.
     */
    open val announcesFromInternal: Boolean = true

    /**
     * Whether announces arriving on THIS interface may be carried onto an INTERNAL one
     * (python `announces_to_internal`, `Interface.py:123`).
     *
     * Three states, and null is not the same as false. Null (the default) means "no
     * explicit policy": an internal interface then applies its own rule, which refuses
     * only BOUNDARY-mode sources. True overrides that refusal. False is inert here — the
     * reference tests `== True` — and is kept distinct so config round-trips faithfully.
     */
    open val announcesToInternal: Boolean? = null

    /** Hardware MTU (if different from standard MTU). */
    open val hwMtu: Int? = null

    /** Whether this interface supports link MTU discovery (Python: AUTOCONFIGURE_MTU or FIXED_MTU). */
    open val supportsLinkMtuDiscovery: Boolean = false

    /** Whether this interface auto-configures its HW_MTU from bitrate
     *  (python Interface.AUTOCONFIGURE_MTU; Interfaces/Interface.py:93 default False). */
    open val autoconfigureMtu: Boolean = false

    /** Whether this interface has a fixed (pinned) HW_MTU
     *  (python Interface.FIXED_MTU; Interfaces/Interface.py:94 default False). */
    open val fixedMtu: Boolean = false

    /** Whether this is a local shared instance server (Python RNS compatibility). */
    open val isLocalSharedInstance: Boolean = false

    // Discovery properties
    /** Whether this interface type supports discovery. */
    open val supportsDiscovery: Boolean = false

    /** Whether discovery is enabled for this instance. */
    open val discoverable: Boolean = false

    /** Last time a discovery announce was sent (epoch seconds). */
    @Volatile var lastDiscoveryAnnounce: Long = 0L

    /** Interval between discovery announces (seconds). */
    open val discoveryAnnounceInterval: Long
        get() = network.reticulum.discovery.DiscoveryConstants.DEFAULT_ANNOUNCE_INTERVAL

    /** Human-readable name for discovery announces. */
    open val discoveryName: String? = null

    /** Whether to encrypt discovery announce payloads. */
    open val discoveryEncrypt: Boolean = false

    /** Required stamp value (null = use default). */
    open val discoveryStampValue: Int? = null

    /** Whether to include IFAC credentials in discovery announces. */
    open val discoveryPublishIfac: Boolean = false

    /** Geographic coordinates for discovery. */
    open val discoveryLatitude: Double? = null
    open val discoveryLongitude: Double? = null
    open val discoveryHeight: Double? = null

    /** Interface type name for discovery announces. */
    open val discoveryInterfaceType: String = "Interface"

    /** Whether this interface uses KISS framing (python: interface.kiss_framing,
     * read by the discovery announce builder's TCPClient/KISS rules). */
    open val kissFraming: Boolean = false

    /** Type-specific discovery data. */
    open fun getDiscoveryData(): Map<Int, Any>? = null

    /** Creation timestamp in milliseconds. */
    val createdAt: Long = System.currentTimeMillis()

    /** Total bytes received. */
    val rxBytes = AtomicLong(0)

    /** Total bytes transmitted. */
    val txBytes = AtomicLong(0)

    private val _online = MutableStateFlow(false)

    /**
     * Whether this interface is currently online, exposed as a [StateFlow]
     * so observers can react to transitions (e.g., UI state, handshake
     * completion in [network.reticulum.interfaces.rnode.RNodeInterface]
     * which flips to online several seconds after registration).
     *
     * Scalar reads use `online.value`; to observe, collect the flow.
     *
     * The exposed type is the read-only [StateFlow]; mutation happens
     * through [setOnline] (the backing [MutableStateFlow] stays private).
     */
    val online: StateFlow<Boolean> = _online.asStateFlow()

    /**
     * Update the online state. Public so subclasses (and parents managing
     * spawned peers) can flip the flag during their lifecycle.
     *
     * Public rather than protected because some subclass hierarchies —
     * [network.reticulum.interfaces.nearby.NearbyInterface] tearing down
     * its spawned [network.reticulum.interfaces.nearby.NearbyPeerInterface]
     * peers, and the conformance bridge's `MockInterface` in a separate
     * module — need cross-instance or cross-module write access that JVM
     * protected semantics won't allow. External Columba-side consumers
     * read via the [online] StateFlow; they have no incentive to call
     * this, and doing so would fight with the owning subclass.
     */
    fun setOnline(value: Boolean) {
        _online.value = value
    }

    /** Whether this interface has been detached (shutdown). */
    val detached = AtomicBoolean(false)

    /** Parent interface (for spawned interfaces). */
    var parentInterface: Interface? = null

    /** Spawned child interfaces. */
    var spawnedInterfaces: MutableList<Interface>? = null

    /** Tunnel ID if this is a tunneled interface. */
    var tunnelId: ByteArray? = null

    /** Whether this interface wants a tunnel synthesized. */
    @Volatile
    var wantsTunnel: Boolean = false

    /** Physical layer signal stats from the most recently received packet. */
    @Volatile var rStatRssi: Int? = null
    @Volatile var rStatSnr: Float? = null
    @Volatile var rStatQ: Float? = null

    /** Callback for received packets. */
    var onPacketReceived: ((data: ByteArray, fromInterface: Interface) -> Unit)? = null

    // Ingress control for announce rate limiting
    protected val ingressControl = AtomicBoolean(true)

    // python keeps the ingress-control tuning on the instance (Interface.py:138-150) so
    // config can override it per interface (`ic_*` keys, Reticulum.py:817-857); here the
    // class constants are the defaults and these are what the limiter reads. Times are
    // milliseconds.
    @Volatile var icNewTimeMs: Long = IC_NEW_TIME
    @Volatile var icBurstFreqNew: Double = IC_BURST_FREQ_NEW
    @Volatile var icBurstFreq: Double = IC_BURST_FREQ
    @Volatile var icBurstHoldMs: Long = IC_BURST_HOLD
    @Volatile var icBurstPenaltyMs: Long = IC_BURST_PENALTY
    @Volatile var icHeldReleaseIntervalMs: Long = IC_HELD_RELEASE_INTERVAL
    @Volatile var icMaxHeldAnnounces: Int = MAX_HELD_ANNOUNCES

    /** python `egress_control` / `ec_pr_freq` (Interface.py:148-149): off unless configured. */
    @Volatile var egressControl: Boolean = false
    @Volatile var ecPrFreq: Double = EC_PR_FREQ

    /** python `protocol_violations`: undecodable or out-of-spec frames seen on this interface. */
    val protocolViolationCount = java.util.concurrent.atomic.AtomicLong(0)

    fun protocolViolation(description: String) {
        protocolViolationCount.incrementAndGet()
        network.reticulum.common.RnsLog.log(network.reticulum.common.RnsLog.DEBUG, "Interface", "Protocol violation on $this: $description")
    }
    private val incomingAnnounceTimestamps = ConcurrentLinkedDeque<Long>()
    private val outgoingAnnounceTimestamps = ConcurrentLinkedDeque<Long>()
    private val burstActive = AtomicBoolean(false)
    @Volatile private var burstActivatedAt: Long = 0
    /** python `ic_burst_sustained`: the last time the rate was still at or over the threshold while bursting. */
    @Volatile private var burstSustainedAt: Long = 0
    private val outgoingPathRequestTimestamps = ConcurrentLinkedDeque<Long>()
    @Volatile private var heldReleaseAt: Long = 0

    // Ingress control for path-request rate limiting (python ip_freq_deque and the
    // ic_pr_burst_* fields, Interface.py:134-137, 155). Kept separate from the announce
    // limiter above: the two have different thresholds and the path-request one has a
    // cooldown the announce one does not.
    private val incomingPathRequestTimestamps = ConcurrentLinkedDeque<Long>()
    private val prBurstActive = AtomicBoolean(false)
    @Volatile private var prBurstActivatedAt: Long = 0
    @Volatile private var prBurstSustainedAt: Long = 0
    @Volatile private var prBurstCooldown: Int = 0

    /** Per-interface held announces for ingress control: dest_hash -> HeldAnnounce. */
    private val heldAnnounces = ConcurrentHashMap<ByteArrayKey, HeldAnnounce>()

    companion object {
        /** Announce-frequency deque length (python Interface.py:58-59 = 48). */
        const val IA_FREQ_SAMPLES = 48
        const val OA_FREQ_SAMPLES = 48

        /**
         * Minimum samples in the frequency deque before a burst may activate or
         * deactivate (python IC_BURST_MIN_SAMPLES, Interface.py:84). Without
         * this gate the ingress limiter trips on as few as 2 announces, holding
         * legitimate distinct announces that python would process.
         */

        /** python `EC_BURST_MIN_SAMPLES` / `EC_PR_FREQ` (Interface.py:85-86). */
        const val EC_BURST_MIN_SAMPLES = 2
        const val EC_PR_FREQ = 5.0
        /** python `AR_FREQ_DECAY = 1 / AR_MINFREQ_HZ` (Interface.py:65-67), in ms. */
        const val AR_FREQ_DECAY = 10 * 1000L
        /** Maximum held announces. */
        const val MAX_HELD_ANNOUNCES = 256

        /** Burst detection thresholds. */
        // Ingress-control tuning, matching RNS 1.5.2 Interface.py:76-83 exactly. These had
        // drifted: burst hold was 60s against the reference's 15, the penalty 300s against
        // 15, the release interval 30s against 5, and both frequency thresholds were higher
        // (3.5/12.0 against 3/10). Together those made us hold announces roughly four times
        // longer than the reference under the same burst, which the conformance suite's
        // ingress-control literals caught. Values are milliseconds here; python counts
        // seconds.
        const val IC_NEW_TIME = 2 * 60 * 60 * 1000L // python 2*60*60 s
        const val IC_BURST_FREQ_NEW = 3.0 // python 3
        const val IC_BURST_FREQ = 10.0 // python 10
        const val IC_BURST_HOLD = 15 * 1000L // python 15 s
        const val IC_BURST_PENALTY = 15 * 1000L // python 15 s
        const val IC_HELD_RELEASE_INTERVAL = 5 * 1000L // python 5 s

        // Path-request ingress control (python Interface.py:62-63, 79-80, 84, 66-69). The
        // path-request thresholds are lower than the announce ones — 8/s against 10/s once an
        // interface is older than IC_NEW_TIME — because a path request costs the node a
        // recursive forward on every other interface, where an announce costs one table write.
        const val IP_FREQ_SAMPLES = 48
        const val IC_PR_BURST_FREQ_NEW = 3.0 // python 3
        const val IC_PR_BURST_FREQ = 8.0 // python 8
        /** Samples required before a frequency reads as non-zero (python IC_DEQUE_MIN_SAMPLE). */
        const val IC_DEQUE_MIN_SAMPLE = 2
        /** Oldest-sample decay for the path-request window (python PR_FREQ_DECAY = 1/PR_MINFREQ_HZ = 10 s). */
        const val PR_FREQ_DECAY = 10 * 1000L

        /** Transport-node announce-rate defaults a node applies when none are
         *  configured (python Interface.DEFAULT_AR_TARGET/_PENALTY/_GRACE,
         *  Interfaces/Interface.py:89-91). */
        const val DEFAULT_AR_TARGET = 3600  // seconds
        const val DEFAULT_AR_PENALTY = 0
        const val DEFAULT_AR_GRACE = 5

        /** Interface modes that should actively discover paths. */
        val DISCOVER_PATHS_FOR = setOf(
            InterfaceMode.ACCESS_POINT,
            InterfaceMode.GATEWAY,
            InterfaceMode.ROAMING,
            // python Interface.py:55. Internal mode contains ANNOUNCES, not path
            // discovery: a private segment that could not resolve a path would be
            // unable to reach anything outside itself.
            InterfaceMode.INTERNAL,
        )

        /**
         * Python RNS's `Interface.optimise_mtu` bitrate-to-HW_MTU tier mapping
         * (`Interface.py:250-262` in 1.5.2). Returns the HW_MTU python assigns for
         * [bitrate] (bps), or null for the lowest tier (python sets `HW_MTU = None`).
         * Python gates the whole mapping on AUTOCONFIGURE_MTU; callers apply their
         * equivalent gate before calling, exactly as python's `if self.AUTOCONFIGURE_MTU`.
         *
         * Every comparison is `>=`. Through RNS 1.3.1 only the top tier was inclusive and
         * the rest were strict `>`, which put a bitrate sitting exactly on a boundary one
         * tier BELOW where 1.5.2 puts it. The boundaries are round numbers an operator
         * actually configures — 1 Mbps, 2 Mbps, 5 Mbps, 62500 bps — so at exactly those
         * rates the two ends of a link would size their hardware MTU differently.
         */
        fun optimiseMtu(bitrate: Long): Int? = when {
            bitrate >= 1_000_000_000L -> 524288
            bitrate >= 750_000_000L -> 262144
            bitrate >= 400_000_000L -> 131072
            bitrate >= 200_000_000L -> 65536
            bitrate >= 100_000_000L -> 32768
            bitrate >= 10_000_000L -> 16384
            bitrate >= 5_000_000L -> 8192
            bitrate >= 2_000_000L -> 4096
            bitrate >= 1_000_000L -> 2048
            bitrate >= 62_500L -> 1024
            else -> null
        }
    }

    /**
     * Get interface age in milliseconds.
     */
    fun age(): Long = System.currentTimeMillis() - createdAt

    /**
     * Get a hash identifier for this interface.
     */
    fun getHash(): ByteArray = Hashes.fullHash(toString().toByteArray())

    /**
     * Send raw packet data through this interface.
     *
     * Implementations should frame the data appropriately.
     *
     * @param data Raw packet bytes to send
     * @throws IllegalStateException if interface is not online or is detached
     */
    abstract fun processOutgoing(data: ByteArray)

    /**
     * Handle incoming data from the physical layer.
     *
     * Implementations should deframe the data and call [processIncoming].
     */
    protected fun processIncoming(data: ByteArray) {
        if (!online.value || detached.get()) return
        // Drop empty frames (e.g. empty keepalives) before counting or delivering them.
        // Python guards `if not data: return` per interface (TCPInterface.py:305,
        // UDPInterface.py:118); here it is guarded once at the shared entry point.
        if (data.isEmpty()) return

        rxBytes.addAndGet(data.size.toLong())
        parentInterface?.rxBytes?.addAndGet(data.size.toLong())

        onPacketReceived?.invoke(data, this)
    }

    /**
     * Start the interface.
     */
    abstract fun start()

    /**
     * Stop and detach the interface.
     */
    open fun detach() {
        setOnline(false)
        detached.set(true)
    }

    /**
     * Record that an announce was received.
     */
    fun recordIncomingAnnounce() {
        val now = System.currentTimeMillis()
        incomingAnnounceTimestamps.addLast(now)
        while (incomingAnnounceTimestamps.size > IA_FREQ_SAMPLES) {
            incomingAnnounceTimestamps.pollFirst()
        }
        parentInterface?.recordIncomingAnnounce()
    }

    /**
     * Record that an announce was sent.
     */
    fun recordOutgoingAnnounce() {
        val now = System.currentTimeMillis()
        outgoingAnnounceTimestamps.addLast(now)
        while (outgoingAnnounceTimestamps.size > OA_FREQ_SAMPLES) {
            outgoingAnnounceTimestamps.pollFirst()
        }
        parentInterface?.recordOutgoingAnnounce()
    }

    /**
     * python `incoming_announce_frequency` (Interface.py:346-355): zero until more than
     * `IC_DEQUE_MIN_SAMPLE` samples exist, the oldest sample dropped once the span exceeds
     * `AR_FREQ_DECAY`, otherwise samples per second over the span back to the oldest one.
     */
    fun incomingAnnounceFrequency(): Double {
        val n = incomingAnnounceTimestamps.size
        if (n <= IC_DEQUE_MIN_SAMPLE) return 0.0
        val oldest = incomingAnnounceTimestamps.peekFirst() ?: return 0.0
        val span = System.currentTimeMillis() - oldest
        if (span > AR_FREQ_DECAY) incomingAnnounceTimestamps.pollFirst()
        // Floored at one millisecond for the same reason as incomingPrFrequency.
        return n / (maxOf(1L, span) / 1000.0)
    }

    /**
     * Calculate outgoing announce frequency (announces per second).
     */
    fun outgoingAnnounceFrequency(): Double = frequencyOf(outgoingAnnounceTimestamps)

    /**
     * Announces per second over the sampled timestamps (epoch ms): the mean spacing
     * between samples, counting the gap from the last sample to now as one more delta.
     */
    private fun frequencyOf(deque: ConcurrentLinkedDeque<Long>): Double {
        val timestamps = deque.toList()
        if (timestamps.size <= 1) return 0.0

        var deltaSum = 0L
        for (i in 1 until timestamps.size) {
            deltaSum += timestamps[i] - timestamps[i - 1]
        }
        deltaSum += System.currentTimeMillis() - timestamps.last()

        return if (deltaSum == 0L) 0.0 else 1000.0 / (deltaSum.toDouble() / timestamps.size)
    }

    /**
     * Check if ingress should be limited due to announce burst.
     */
    /**
     * python `should_ingress_limit` (Interface.py:188-206). The frequency itself is zero
     * until three samples exist (`IC_DEQUE_MIN_SAMPLE`), which is what keeps two lone
     * announces from tripping the limiter; a separate six-sample gate here armed later
     * than the reference and cited a constant python does not have.
     */
    fun shouldIngressLimit(): Boolean {
        if (!ingressControl.get()) return false

        val freqThreshold = if (age() < icNewTimeMs) icBurstFreqNew else icBurstFreq
        val iaFreq = incomingAnnounceFrequency()
        val now = System.currentTimeMillis()

        if (burstActive.get()) {
            if (iaFreq < freqThreshold && now > burstActivatedAt + icBurstHoldMs && now > burstSustainedAt + icBurstHoldMs) {
                if (incomingAnnounceTimestamps.size >= IC_DEQUE_MIN_SAMPLE) burstActive.set(false)
            } else if (iaFreq >= freqThreshold) {
                burstSustainedAt = now
            }
            return true
        }
        if (iaFreq > freqThreshold) {
            burstActive.set(true)
            burstActivatedAt = now
            burstSustainedAt = now
            heldReleaseAt = now + icBurstPenaltyMs
            return true
        }
        return false
    }

    // ---- path-request ingress control (python Interface.py:213-236, 320-324, 366-374) ----

    /**
     * Record that a path request was received on this interface (python
     * `received_path_request`, Interface.py:320-324). Feeds [incomingPrFrequency] and
     * propagates to the parent interface the same way the announce counterpart does, so a
     * shared-instance server sees the aggregate rate across its spawned clients.
     */
    fun recordIncomingPathRequest() {
        val now = System.currentTimeMillis()
        incomingPathRequestTimestamps.addLast(now)
        while (incomingPathRequestTimestamps.size > IP_FREQ_SAMPLES) {
            incomingPathRequestTimestamps.pollFirst()
        }
        parentInterface?.recordIncomingPathRequest()
    }

    /**
     * Incoming path requests per second (python `incoming_pr_frequency`, Interface.py:366-374).
     *
     * This is the reference's own arithmetic — samples divided by the span back to the oldest
     * one — not the mean-spacing form [frequencyOf] uses for announces. It reads as zero until
     * more than IC_DEQUE_MIN_SAMPLE samples exist, and it evicts the oldest sample once the
     * span exceeds PR_FREQ_DECAY so a burst ten seconds ago stops anchoring the average.
     */
    fun incomingPrFrequency(): Double {
        val n = incomingPathRequestTimestamps.size
        if (n <= IC_DEQUE_MIN_SAMPLE) return 0.0
        val oldest = incomingPathRequestTimestamps.peekFirst() ?: return 0.0
        val elapsed = System.currentTimeMillis() - oldest
        if (elapsed > PR_FREQ_DECAY) incomingPathRequestTimestamps.pollFirst()
        // python returns 0 for a non-positive span, but its clock is sub-microsecond and
        // never produces one. Ours is milliseconds: a real burst of requests that all land
        // inside one tick would read as ZERO hertz and never trip the limiter. Floor the
        // span at one millisecond so such a burst reads as what it is — very fast.
        val spanMs = maxOf(1L, elapsed)
        return n / (spanMs / 1000.0)
    }

    /**
     * Whether inbound path requests on this interface should be ingress limited (python
     * `should_ingress_limit_pr`, Interface.py:213-236).
     *
     * The shape follows [shouldIngressLimit] with the one refinement the reference gave the
     * path-request limiter: leaving the active state runs down a three-call cooldown rather
     * than flipping off the first time the rate dips under threshold, and any re-trip during
     * the cooldown resets it. A limiter that turns off on the first quiet sample re-arms on
     * the next request and flaps; the cooldown makes it settle.
     *
     * Transport reads this at inbound preprocessing to classify the packet as
     * TC_INGRESS_LIMITED, and again in path_request to refuse recursive discovery.
     */
    /** python `sent_path_request` (Interface.py:320-324). */
    fun recordOutgoingPathRequest() {
        outgoingPathRequestTimestamps.addLast(System.currentTimeMillis())
        while (outgoingPathRequestTimestamps.size > IP_FREQ_SAMPLES) outgoingPathRequestTimestamps.pollFirst()
        parentInterface?.recordOutgoingPathRequest()
    }

    /** python `outgoing_pr_frequency` (Interface.py:380-389); [preemptive] counts the request about to be sent. */
    fun outgoingPrFrequency(preemptive: Boolean = false): Double {
        val size = outgoingPathRequestTimestamps.size
        val n = size + (if (preemptive) 1 else 0)
        if (size <= 1) return 0.0
        val oldest = outgoingPathRequestTimestamps.peekFirst() ?: return 0.0
        val span = System.currentTimeMillis() - oldest
        if (span > PR_FREQ_DECAY) outgoingPathRequestTimestamps.pollFirst()
        return n / (maxOf(1L, span) / 1000.0)
    }

    /** python `should_egress_limit_pr` (Interface.py:240-248): only when `egress_control` is on. */
    fun shouldEgressLimitPr(): Boolean {
        if (!egressControl) return false
        val opFreq = outgoingPrFrequency(preemptive = true)
        return opFreq > ecPrFreq && outgoingPathRequestTimestamps.size >= EC_BURST_MIN_SAMPLES
    }

    fun shouldIngressLimitPr(): Boolean {
        if (!ingressControl.get()) return false

        val freqThreshold = if (age() < icNewTimeMs) IC_PR_BURST_FREQ_NEW else IC_PR_BURST_FREQ
        val ipFreq = incomingPrFrequency()
        val now = System.currentTimeMillis()

        if (prBurstActive.get()) {
            if (ipFreq < freqThreshold &&
                now > prBurstActivatedAt + icBurstHoldMs &&
                now > prBurstSustainedAt + icBurstHoldMs
            ) {
                if (prBurstCooldown <= 0) prBurstActive.set(false) else prBurstCooldown--
            } else {
                prBurstCooldown = 3
                if (ipFreq >= freqThreshold) prBurstSustainedAt = now
            }
            // python returns True for the whole active arm, including the call that
            // deactivates — the caller that observed the burst is still limited.
            return true
        }

        if (ipFreq > freqThreshold) {
            prBurstActive.set(true)
            prBurstActivatedAt = now
            prBurstSustainedAt = now
            prBurstCooldown = 3
            return true
        }
        return false
    }

    /**
     * Hold an announce for later release when ingress burst subsides.
     * Matches Python Interface.hold_announce() (Interface.py:170-174).
     */
    fun holdAnnounce(destinationHash: ByteArray, raw: ByteArray, hops: Int, receivingInterface: InterfaceRef) {
        // python Interface.py:270-271 — an announce already at the hop ceiling would only be
        // dropped on release; holding it wastes one of the 256 slots.
        if (hops >= TransportConstants.PATHFINDER_M - 1) return
        val key = destinationHash.toKey()
        val held = HeldAnnounce(destinationHash.copyOf(), raw.copyOf(), hops, receivingInterface)
        heldAnnounces.compute(key) { _, existing ->
            if (existing != null) held                              // update existing
            else if (heldAnnounces.size < icMaxHeldAnnounces) held  // insert new
            else existing                                           // full — drop new (Python behavior)
        }
    }

    /**
     * Process held announces: release one (min-hops first) when burst has subsided.
     * Matches Python Interface.process_held_announces() (Interface.py:176-200).
     */
    fun processHeldAnnounces() {
        try {
            if (shouldIngressLimit() || heldAnnounces.isEmpty()) return

            val now = System.currentTimeMillis()
            if (now <= heldReleaseAt) return

            val freqThreshold = if (age() < icNewTimeMs) icBurstFreqNew else icBurstFreq
            val iaFreq = incomingAnnounceFrequency()
            if (iaFreq >= freqThreshold) return

            // Select announce with minimum hops (Python: PATHFINDER_M as initial max)
            var minHops = TransportConstants.PATHFINDER_M
            var selectedKey: ByteArrayKey? = null
            var selectedAnnounce: HeldAnnounce? = null
            for ((key, announce) in heldAnnounces) {
                if (announce.hops < minHops) {
                    minHops = announce.hops
                    selectedKey = key
                    selectedAnnounce = announce
                }
            }

            if (selectedAnnounce != null && selectedKey != null) {
                heldReleaseAt = now + icHeldReleaseIntervalMs
                heldAnnounces.remove(selectedKey)
                // Re-inject via daemon thread to avoid re-entrancy (matches Python)
                val raw = selectedAnnounce.raw
                val iface = selectedAnnounce.receivingInterface
                Thread {
                    // python Interface.py:295 — a released announce re-enters as
                    // TC_INGRESS_LIMITED, so it drains behind everything else, and with
                    // ifac_handled=True: the raw we stored is the *unmasked* frame, and
                    // running IFAC removal on it again would find no IFAC flag and drop
                    // it. Every held announce on an IFAC interface was lost that way
                    // before this flag existed here.
                    Transport.inbound(
                        raw,
                        iface,
                        tc = TransportConstants.TC_INGRESS_LIMITED,
                        ifacHandled = true,
                    )
                }.apply {
                    isDaemon = true
                    name = "HeldRelease-${this@Interface.name}"
                }.start()
            }
        } catch (e: Exception) {
            System.err.println("An error occurred while processing held announces for $this: ${e.message}")
        }
    }

    /**
     * Number of announces currently held on this interface.
     */
    fun heldAnnounceCount(): Int = heldAnnounces.size

    /** Destination hashes of the currently-held announces (conformance seam). */
    fun heldAnnounceDestinations(): List<ByteArray> =
        heldAnnounces.values.map { it.destinationHash.copyOf() }

    /**
     * Open the held-announce release gate deterministically (conformance seam) —
     * the kotlin analogue of the reference bridge backdating `ic_held_release`
     * to 0 so `process_held_announces()` can release without a real sleep.
     */
    fun openHeldReleaseGateForTest() {
        heldReleaseAt = 0
    }

    /**
     * Get the effective MTU for this interface.
     */
    fun getEffectiveMtu(): Int = hwMtu ?: RnsConstants.MTU

    override fun toString(): String = "Interface[$name]"
}
