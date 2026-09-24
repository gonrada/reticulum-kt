package network.reticulum.interfaces

import network.reticulum.common.InterfaceMode
import network.reticulum.common.RnsConstants
import network.reticulum.transport.InterfaceRef
import network.reticulum.transport.Transport

/**
 * Adapter to bridge Interface to InterfaceRef for Transport integration.
 * Also sets up the receive callback to deliver packets to Transport.
 */
class InterfaceAdapter private constructor(
    private val iface: Interface,
) : InterfaceRef {
    override val name: String = iface.name
    override val hash: ByteArray = iface.getHash()
    override val canSend: Boolean = iface.canSend
    override val canReceive: Boolean = iface.canReceive
    override val online: Boolean get() = iface.online.value
    override val rxBytes: Long get() = iface.rxBytes.get()
    override val txBytes: Long get() = iface.txBytes.get()
    override val mode: InterfaceMode get() = iface.modeOverride ?: iface.mode
    // Never forwarded before, so every adapted interface reported the InterfaceRef
    // default of 0. The announce-cap egress spacing is (len*8/bitrate)/announce_cap,
    // and a zero bitrate makes that wait zero: the 2% announce bandwidth cap was a
    // silent no-op on every real interface that goes through this adapter.
    override val bitrate: Int get() = iface.bitrate
    override val announceCap: Double get() = iface.announceCapOverride ?: iface.announceCap
    override val announceRateTarget: Int? get() = iface.announceRateTargetOverride ?: iface.announceRateTarget
    override val announceRateGrace: Int get() = iface.announceRateGraceOverride ?: iface.announceRateGrace
    override val announceRatePenalty: Int get() = iface.announceRatePenaltyOverride ?: iface.announceRatePenalty
    override val announcesFromInternal: Boolean get() = iface.announcesFromInternalOverride ?: iface.announcesFromInternal
    override val announcesToInternal: Boolean? get() = iface.announcesToInternalOverride ?: iface.announcesToInternal
    override val hwMtu: Int get() = iface.hwMtu ?: RnsConstants.MTU
    override val supportsLinkMtuDiscovery: Boolean get() = iface.supportsLinkMtuDiscovery

    // Tunnel properties - delegate to underlying interface
    override var tunnelId: ByteArray?
        get() = iface.tunnelId
        set(value) {
            iface.tunnelId = value
        }

    override var wantsTunnel: Boolean
        get() = iface.wantsTunnel
        set(value) {
            iface.wantsTunnel = value
        }

    // Shared instance properties (Python RNS compatibility)
    override val isLocalSharedInstance: Boolean
        get() = iface.isLocalSharedInstance

    override val isConnectedToSharedInstance: Boolean
        get() = (iface as? network.reticulum.interfaces.local.LocalClientInterface)?.isConnectedToSharedInstance() ?: false

    override val parentInterface: InterfaceRef?
        get() = iface.parentInterface?.toRef()

    // Physical layer stats
    override val rStatRssi: Int?
        get() = iface.rStatRssi
    override val rStatSnr: Float?
        get() = iface.rStatSnr
    override val rStatQ: Float?
        get() = iface.rStatQ

    // Discovery properties - delegate to underlying interface
    override val supportsDiscovery: Boolean get() = iface.supportsDiscovery
    override val discoverable: Boolean get() = iface.discoverable
    override var lastDiscoveryAnnounce: Long
        get() = iface.lastDiscoveryAnnounce
        set(value) {
            iface.lastDiscoveryAnnounce = value
        }
    override val discoveryAnnounceInterval: Long get() = iface.discoveryAnnounceInterval
    override val discoveryName: String? get() = iface.discoveryName
    override val discoveryEncrypt: Boolean get() = iface.discoveryEncrypt
    override val discoveryStampValue: Int? get() = iface.discoveryStampValue
    override val discoveryPublishIfac: Boolean get() = iface.discoveryPublishIfac
    override val discoveryLatitude: Double? get() = iface.discoveryLatitude
    override val discoveryLongitude: Double? get() = iface.discoveryLongitude
    override val discoveryHeight: Double? get() = iface.discoveryHeight
    override val discoveryInterfaceType: String get() = iface.discoveryInterfaceType
    override val kissFraming: Boolean get() = iface.kissFraming
    override val ifacNetname: String? get() = iface.ifacNetname
    override val ifacNetkey: String? get() = iface.ifacNetkey

    override fun getDiscoveryData(): Map<Int, Any>? = iface.getDiscoveryData()

    // IFAC properties - delegate to underlying interface
    override val ifacSize: Int
        get() = iface.ifacSize

    override val ifacKey: ByteArray?
        get() = iface.ifacKey

    override val ifacIdentity: network.reticulum.identity.Identity?
        get() = iface.ifacIdentity

    init {
        // Only set up the callback if one isn't already set
        // This prevents overwriting callbacks set by parent interfaces (e.g., TCPServerInterface)
        if (iface.onPacketReceived == null) {
            iface.onPacketReceived = { data, fromInterface ->
                // Get or create InterfaceRef for the source interface
                val sourceRef =
                    if (fromInterface === iface) {
                        this
                    } else {
                        fromInterface.toRef()
                    }
                Transport.inbound(data, sourceRef)
            }
        }
    }

    // Ingress control delegation
    override fun shouldIngressLimit(): Boolean = iface.shouldIngressLimit()

    override fun recordIncomingAnnounce() = iface.recordIncomingAnnounce()

    override fun shouldIngressLimitPr(): Boolean = iface.shouldIngressLimitPr()

    override fun recordIncomingPathRequest() = iface.recordIncomingPathRequest()

    override fun shouldEgressLimitPr(): Boolean = iface.shouldEgressLimitPr()

    override fun recordOutgoingPathRequest() = iface.recordOutgoingPathRequest()

    override fun protocolViolation(description: String) = iface.protocolViolation(description)

    override val protocolViolations: Long get() = iface.protocolViolationCount.get()
    // Held announce delegation
    override fun holdAnnounce(
        destinationHash: ByteArray,
        raw: ByteArray,
        hops: Int,
        receivingInterface: InterfaceRef,
    ) = iface.holdAnnounce(destinationHash, raw, hops, receivingInterface)

    override fun processHeldAnnounces() = iface.processHeldAnnounces()

    override fun heldAnnounceCount(): Int = iface.heldAnnounceCount()

    override fun send(data: ByteArray) {
        iface.processOutgoing(data)
    }

    override fun detach() {
        iface.detach()
    }

    companion object {
        /**
         * Return the interface's adapter, creating it once and caching it ON the
         * interface itself ([Interface.cachedAdapter]). Backing the cache with a
         * per-instance field — instead of the process-global map that never evicted —
         * lets a detached, dereferenced interface and its adapter be garbage-collected
         * together, while still returning a stable adapter identity for a live interface
         * (Transport register/deregister match by adapter identity, so this must be
         * stable). Double-checked locking on the interface guards concurrent creation.
         */
        fun getOrCreate(iface: Interface): InterfaceAdapter {
            iface.cachedAdapter?.let { return it }
            return synchronized(iface) {
                iface.cachedAdapter ?: InterfaceAdapter(iface).also { iface.cachedAdapter = it }
            }
        }
    }
}

/**
 * Extension function to create an InterfaceRef from an Interface.
 */
fun Interface.toRef(): InterfaceRef = InterfaceAdapter.getOrCreate(this)
