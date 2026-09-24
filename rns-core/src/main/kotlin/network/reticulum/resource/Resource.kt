package network.reticulum.resource

import network.reticulum.common.DestinationType
import network.reticulum.common.PacketContext
import network.reticulum.common.PacketType
import network.reticulum.common.ByteArrayKey
import network.reticulum.common.toKey
import network.reticulum.common.RnsConstants
import network.reticulum.common.toHexString
import network.reticulum.crypto.Hashes
import network.reticulum.link.Link
import network.reticulum.link.LinkConstants
import network.reticulum.packet.Packet
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.security.SecureRandom
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import org.apache.commons.compress.compressors.bzip2.BZip2CompressorInputStream
import org.apache.commons.compress.compressors.bzip2.BZip2CompressorOutputStream
import kotlin.concurrent.thread
import kotlin.math.ceil
import kotlin.math.max
import kotlin.math.min

/**
 * Callbacks for resource transfer events.
 */
class ResourceCallbacks {
    var completed: ((Resource) -> Unit)? = null
    var progress: ((Resource) -> Unit)? = null
    var failed: ((Resource) -> Unit)? = null
}

/**
 * Represents a large data transfer over a Link.
 *
 * Resources handle automatic chunking, sequencing, compression,
 * and retransmission for reliable transfer of arbitrary-sized data.
 *
 * Usage for sending:
 * ```kotlin
 * val resource = Resource.create(data, link) { resource ->
 *     println("Transfer complete!")
 * }
 * ```
 *
 * Usage for receiving (via Link callback):
 * ```kotlin
 * link.callbacks.resourceStarted = { resource ->
 *     resource.callbacks.completed = { r ->
 *         val data = r.data
 *         // Process received data
 *     }
 * }
 * ```
 */
/**
 * Receive-side accumulation of one split transfer's completed segments, owned by the
 * [Link] the transfer arrives on and released when that link tears down. Python keeps the
 * equivalent as a file under storagepath keyed by the original hash (Resource.py:200,
 * 721-723). Besides the bytes it records what a well-behaved sender is bound to — the
 * segment count advertised by the first segment and the next index expected — so a
 * sender that changes `l` mid-transfer or replays a segment is refused rather than
 * accumulated.
 */
internal class SegmentAccumulator(val expectedSegments: Int) {
    val buffer = ByteArrayOutputStream()
    var metadata: ByteArray? = null
    var nextIndex: Int = 1
    /** Stamped by the owning Resource from its clock when the accumulator is created and on every segment. */
    @Volatile var lastProgressAt: Long = 0L
}

class Resource private constructor(
    /** The link this resource is being transferred over. */
    val link: Link,
    /** Whether this side initiated the transfer. */
    val initiator: Boolean
) {
    /**
     * Every timestamp in this class is taken from here. Tests replace it so the
     * watchdog's waits of seconds to minutes are driven in milliseconds and to the
     * exact millisecond. Production never
     * sets it; `ResourceWatchdogTimingTest` greps this file so no direct clock read
     * can reappear.
     */
    @Volatile
    @network.reticulum.RnsTestSeam
    internal var clock: () -> Long = { System.currentTimeMillis() }

    companion object {
        /**
         * Bound on hashmap rebuild attempts after a map-hash collision. Each retry draws a
         * fresh random_hash, so repeats are vanishingly unlikely; the bound turns a
         * pathological case into an error rather than a hang.
         */
        private const val MAX_HASHMAP_REBUILDS = 16

        /**
         * Test-only hook over [getMapHash]. Receives the resource and the genuine map hash
         * and may substitute another value, which is how the conformance bridge forces a
         * map-hash collision without fabricating bytes: it returns one part's real hash a
         * second time. Null in normal operation.
         */
        @Volatile
        @network.reticulum.RnsTestSeam
        var mapHashInterceptorForTest: ((Resource, ByteArray) -> ByteArray?)? = null

        /**
         * Receive-side segment accumulator, keyed by `originalHash` — the one field that
         * is identical across every segment of a split transfer.
         *
         * Python accumulates on disk: `resource.storagepath = resourcepath + "/" +
         * original_hash.hex()` (Resource.py:200), each segment appends with
         * `open(storagepath, "ab")` (Resource.py:722-723), and the user callback fires
         * only once `segment_index == total_segments` (Resource.py:738). The metadata
         * block rides on segment 1 alone and is re-attached at the end.
         *
         * Without this, every segment was delivered as its own COMPLETE resource holding
         * only its own bytes, so a >1 MiB transfer from a python sender arrived as N
         * fragments instead of one payload — right total length, wrong content, no error,
         * because each segment passes its own hash check.
         */
        // The accumulations themselves live on the Link (`Link.segmentAccumulators`), not
        // here: a transfer is bound to the link it arrives on, so link teardown can release
        // every partial accumulation that link owned. A process-wide map keyed only by the
        // sender-supplied original hash could not be released by anything but completion,
        // and a peer that never completed retained heap for the life of the process.

        private val resourceCounter = AtomicInteger(0)
        private val random = SecureRandom()

        /**
         * Test-only watchdog suppression. Mirrors the reference conformance
         * harness monkeypatching `RNS.Resource.watchdog_job = lambda self: None`
         * around `_build_resource_receiver` (wire_tcp.py:6903) so an inbound
         * Resource can be built and driven synchronously without its watchdog
         * thread firing a part-request / timeout retry that would cancel the
         * transfer out from under inspection. Production code never sets this;
         * the conformance-bridge sets it true for the duration of a receiver
         * build and resets it in resetWireState().
         */
        @Volatile
        @network.reticulum.RnsTestSeam
        var watchdogDisabledForTest: Boolean = false

        /**
         * Create a new resource for outgoing transfer.
         *
         * @param data The data to transfer
         * @param link The link to transfer over
         * @param metadata Optional metadata to include with the resource
         * @param advertise Whether to automatically advertise (default: true)
         * @param autoCompress Whether to compress the data (default: true)
         * @param callback Callback when transfer completes
         * @param progressCallback Callback for progress updates
         * @return The new Resource instance
         */
        fun create(
            data: ByteArray,
            link: Link,
            metadata: ByteArray? = null,
            advertise: Boolean = true,
            autoCompress: Boolean = true,
            callback: ((Resource) -> Unit)? = null,
            progressCallback: ((Resource) -> Unit)? = null,
            failedCallback: ((Resource) -> Unit)? = null,
            requestId: ByteArray? = null,
            isResponse: Boolean = false,
            timeout: Long? = null
        ): Resource {
            val resource = Resource(link, initiator = true)

            callback?.let { resource.callbacks.completed = it }
            progressCallback?.let { resource.callbacks.progress = it }
            // Wire the failed callback BEFORE advertise() starts the watchdog. Setting it via
            // resource.callbacks.failed after create() returns leaves a window where a watchdog
            // timeout could fire against a null failed callback and drop the failure
            // notification (null-safe, no crash, but silent).
            failedCallback?.let { resource.callbacks.failed = it }

            resource.requestId = requestId
            resource.isResponse = isResponse
            timeout?.let { resource.timeoutMs = it }

            resource.initializeForSending(data, metadata, autoCompress)

            if (advertise) {
                resource.advertise()
            }

            return resource
        }

        /**
         * Accept an incoming resource advertisement.
         *
         * @param advertisement The received advertisement
         * @param link The link the advertisement came from
         * @param callback Callback when transfer completes
         * @param progressCallback Callback for progress updates
         * @return The new Resource instance, or null if invalid
         */
        fun accept(
            advertisement: ResourceAdvertisement,
            link: Link,
            callback: ((Resource) -> Unit)? = null,
            progressCallback: ((Resource) -> Unit)? = null
        ): Resource? {
            // Dedupe duplicate advertisements before doing any setup work.
            // Mirrors python `RNS.Resource.accept`'s
            // `if not resource.link.has_incoming_resource(resource)` guard
            // at Resource.py:223 — the check sits inside accept() so all
            // four `Link.processResourceAdv` call sites (isRequest,
            // isResponse, ACCEPT_APP, ACCEPT_ALL) automatically benefit.
            // Transport's packet hashlist intentionally skips LINK-destined
            // packets, so a sender retransmit of `RESOURCE_ADV` reaches the
            // link layer in raw form; without this check a fresh Resource
            // instance gets built per retransmit and assemble fires twice
            // (observed as `Inbox sizes [N, N]` in the cross-impl
            // conformance suite).
            if (link.hasIncomingResource(advertisement.hash)) {
                log(
                    "Ignoring RESOURCE_ADV ${advertisement.hash.toHexString()} — " +
                        "resource already transferring",
                )
                return null
            }
            // Track whether initialization registered the resource so that
            // a thrown `requestNext()` doesn't leave a zombie entry in
            // `link.incomingResources`. `initializeFromAdvertisement` calls
            // `link.registerIncomingResource(this)` and `startWatchdog()`
            // before we get a chance to call `requestNext()`; a throw from
            // there with the registration leaked would mean the dedup guard
            // above rejects every subsequent retransmit of the same
            // advertisement.hash for the lifetime of the link, removing the
            // recovery path entirely. Python's accept (Resource.py:223-244)
            // has the same shape but the failure modes there are caught by
            // its own watchdog cancellation; we mirror that recovery
            // explicitly via `resource.cancel()`.
            var resource: Resource? = null
            return try {
                resource = Resource(link, initiator = false)

                callback?.let { resource.callbacks.completed = it }
                progressCallback?.let { resource.callbacks.progress = it }

                resource.initializeFromAdvertisement(advertisement)
                // Python invokes resource_started synchronously after the
                // inbound Resource is registered and before hashmap_update()
                // requests the first parts (Resource.py:223-234). This ordering
                // is load-bearing: applications use the callback to configure
                // per-transfer limits such as max_decompressed_size. Deferring
                // it lets a small compressed Resource arrive and assemble with
                // the default limit before the callback applies its bound.
                link.resourceStarted(resource)
                resource.requestNext()
                // Python starts the watchdog only after resource_started and
                // the initial hashmap request (Resource.py:223-234). Starting
                // it during initialization allows a watchdog retry to bypass a
                // slow callback and request parts before configuration finishes.
                resource.startWatchdog()

                resource
            } catch (e: Exception) {
                log("Failed to accept resource: ${e.message}")
                resource?.cancel()
                null
            }
        }

        /**
         * Refuse an advertised resource, telling the sender so rather than letting it
         * discover the refusal by timing out (python `Resource.reject`, `Resource.py:156-165`).
         *
         * The packet is addressed to the LINK and its payload encrypted to it, exactly like
         * every other link packet. An earlier version addressed it to the resource hash and
         * sent the hash in clear: the sender's RCL handler decrypts the payload before
         * matching, so nothing matched, and every rejected transfer ran to its full watchdog
         * timeout and reported FAILED instead of REJECTED.
         */
        fun reject(advertisement: ResourceAdvertisement, link: Link) {
            try {
                val rejectPacket = Packet.createRaw(
                    destinationHash = link.linkId,
                    data = link.encrypt(advertisement.hash),
                    packetType = PacketType.DATA,
                    destinationType = DestinationType.LINK,
                    context = PacketContext.RESOURCE_RCL,
                    mtu = link.mtu,
                )
                rejectPacket.send()
            } catch (e: Exception) {
                log("Error rejecting resource: ${e.message}")
            }
        }

        // Off by default: resource-op logging includes hashes/sizes and fires on
        // every transfer step. Opt in with -Dreticulum.resource.debug=true.
        private val DEBUG = System.getProperty("reticulum.resource.debug", "false").toBoolean()

        private fun log(message: String) {
            if (!DEBUG) return
            val timestamp = java.time.LocalDateTime.now().format(
                java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS")
            )
            println("[$timestamp] [Resource] $message")
        }
    }

    // Resource identification
    var hash: ByteArray = ByteArray(0)
        private set
    var originalHash: ByteArray = ByteArray(0)
        private set
    var randomHash: ByteArray = ByteArray(0)
        private set

    // Size tracking
    var size: Int = 0           // Transfer size (possibly compressed)
        private set
    var totalSize: Int = 0      // Total uncompressed size
        private set
    var uncompressedSize: Int = 0
        private set

    // Status. @Volatile because it is read across threads: the daemon
    // advertise spin-wait (below) and the watchdog read it while cancel() /
    // conclude write it from another thread. Without it the JVM may cache a
    // stale value, so the daemon's `while (status == QUEUED ...)` loop could
    // spin until shutdown and its post-loop QUEUED guards (and doAdvertise's)
    // could see a stale QUEUED after a cancel. Python's GIL gives this
    // cross-thread visibility for free; @Volatile is the JVM equivalent, not a
    // behavior change. status is only ever ASSIGNED (never read-modify-written),
    // so @Volatile suffices — no atomic needed.
    @Volatile
    var status: Int = ResourceConstants.NONE
        private set

    // Parts management
    var parts: Array<ByteArray?> = arrayOf()
        private set
    var hashmapRaw: ByteArray = ByteArray(0)
        private set
    private var hashmap: Array<ByteArray?> = arrayOf()
    private var hashmapHeight: Int = 0
    private var receivedCount: Int = 0
    private var outstandingParts: Int = 0
    private var consecutiveCompletedHeight: Int = -1
    private var sentParts: Int = 0
    private val sentPartsSet = mutableSetOf<Int>()

    // Segmenting
    var segmentIndex: Int = 1
        private set
    var totalSegments: Int = 1
        private set
    var split: Boolean = false
        private set

    // Flags
    var compressed: Boolean = false
        private set
    var encrypted: Boolean = true  // Resources over links are always encrypted
        private set
    var hasMetadata: Boolean = false
        private set
    var isResponse: Boolean = false
        private set

    // Request tracking
    var requestId: ByteArray? = null
        private set

    // Callbacks
    val callbacks = ResourceCallbacks()

    // Window management
    private var window: Int = ResourceConstants.WINDOW

    /**
     * Current flow-control window, exposed module-internally so
     * `Link.resourceConcluded` can record it as the link's last-resource-window
     * (Link.py:1284). Not a test seam — this is production state used by the
     * window-inheritance path.
     */
    internal val currentWindow: Int get() = window
    private var windowMax: Int = ResourceConstants.WINDOW_MAX_SLOW
    private var windowMin: Int = ResourceConstants.WINDOW_MIN

    // Timing
    private var rtt: Long? = null
    private var lastActivity: Long = clock()
    private var lastPartSent: Long = 0
    private var startedTransferring: Long? = null
    // python Resource.py:345-350, 383-384. `retriesLeft` counts down and is refilled at
    // the sites the reference refills it; `timeoutFactor` drops to PROOF_TIMEOUT_FACTOR
    // in AWAITING_PROOF; `partTimeoutFactor` drops after the first RTT sample.
    private var retriesLeft: Int = ResourceConstants.MAX_RETRIES
    private var timeoutFactor: Int = link.trafficTimeoutFactor
    private var partTimeoutFactor: Int = ResourceConstants.PART_TIMEOUT_FACTOR
    /** python `self.timeout` (Resource.py:383-384): the constructor argument, else rtt × traffic_timeout_factor. */
    private var timeoutMs: Long = (link.rtt ?: 0L) * link.trafficTimeoutFactor

    // Request/response timing for RTT calculation
    private var reqSent: Long = 0
    private var reqResp: Long? = null
    private var reqSentBytes: Int = 0
    private var rttRxdBytes: Long = 0
    private var rttRxdBytesAtPartReq: Long = 0
    private var reqRespRttRate: Double = 0.0
    private var reqDataRttRate: Double = 0.0

    // Rate tracking
    private var fastRateRounds: Int = 0
    private var verySlowRateRounds: Int = 0
    private var windowFlexibility: Int = ResourceConstants.WINDOW_FLEXIBILITY
    private var eifr: Double = 0.0
    private var previousEifr: Double? = null

    // Hashmap update tracking
    private var waitingForHmu: Boolean = false
    private var receivingPart: Boolean = false
    private val receiveLock = java.util.concurrent.locks.ReentrantLock()
    private var assemblyLock: Boolean = false

    // Sender-side tracking
    private var receiverMinConsecutiveHeight: Int = 0
    private var advSent: Long = 0

    // Watchdog
    private var watchdogThread: Thread? = null
    @Volatile private var watchdogActive = false
    @Volatile private var cancelTransitionHookForTest: (() -> Unit)? = null

    // SDU for this resource — uses plain packet MDU (not link MDU) because
    // resource parts are already bulk-encrypted before splitting, and are sent
    // as raw packets that only add header + IFAC overhead (no Token encryption).
    // Python: self.sdu = self.link.mtu - RNS.Reticulum.HEADER_MAXSIZE - RNS.Reticulum.IFAC_MIN_SIZE
    private val sdu: Int = link.mtu - RnsConstants.HEADER_MAX_SIZE - RnsConstants.IFAC_MIN_SIZE

    // Raw data
    private var uncompressedData: ByteArray? = null
    private var compressedData: ByteArray? = null
    private var assembledData: ByteArray? = null
    private var metadata: ByteArray? = null

    // Multi-segment support. Python spools a >MAX_EFFICIENT_SIZE payload to a
    // tempfile and every segment re-reads its own range from it
    // (Resource.py:275-322, 779-792). The port keeps the full payload in
    // memory instead: [segmentSource] is the in-memory equivalent of python's
    // `input_file`, shared (not copied) between the segments of one transfer.
    // [inputFile] is retained for a file-backed source. Both flags are
    // @Volatile: the preparation thread writes them, validateProof (on the
    // Transport ingest thread) reads them.
    private var inputFile: java.io.RandomAccessFile? = null
    private var segmentSource: ByteArray? = null
    private var segmentMetadataSize: Int = 0
    private var autoCompressOption: Boolean = true
    @Volatile private var preparingNextSegment: Boolean = false
    @Volatile private var nextSegment: Resource? = null

    // Proof tracking
    private var expectedProof: ByteArray? = null

    // Decompression-bomb ceiling. Mirrors python Resource.__init__
    // (Resource.py:364-365): max_decompressed_size == auto_compress_limit ==
    // Resource.AUTO_COMPRESS_MAX_SIZE (64 MiB). This is the bound the receiver's
    // bounded bz2 decompression stops at before declaring a CORRUPT bomb
    // (Resource.py:686-689). A listener may lower it per-inbound-resource.
    @Volatile
    private var maxDecompressedSize: Int = ResourceConstants.AUTO_COMPRESS_MAX_SIZE
    private var autoCompressLimit: Int = ResourceConstants.AUTO_COMPRESS_MAX_SIZE

    // Conformance instrumentation counters (see *ForTest accessors). These count
    // genuine state-machine events the reference harness observes by wrapping the
    // python instance methods (which kotlin cannot monkeypatch per-instance).
    // AtomicInteger, not @Volatile Int: these are bumped with ++ from the
    // receiver's part-delivery path and the background watchdog. @Volatile only
    // guarantees visibility; ++ is a non-atomic read-modify-write that can lose
    // increments under concurrency. incrementAndGet() is atomic. (Kotlin-only
    // conformance instrumentation — no python equivalent.)
    private val proveCalls = AtomicInteger(0)
    @Volatile private var lastRequestData: ByteArray? = null
    private val requestNextEmitCount = AtomicInteger(0)
    private val hmuRequestsSent = AtomicInteger(0)
    private val hashmapUpdatesReceived = AtomicInteger(0)

    // Test-only: when false, receivePart() does NOT auto-issue its follow-up
    // requestNext() on a window drain. Mirrors the reference harness shadowing
    // `receiver.request_next = lambda: None` during a part-feed so the feed only
    // POSITIONS the consecutive pointer and the explicitly-driven requestNext()
    // afterwards is the one observed. Default true = production behaviour.
    @Volatile private var autoRequestNext: Boolean = true

    /**
     * Initialize resource for sending.
     * Matches Python RNS Resource.__init__() protocol.
     */
    private fun initializeForSending(data: ByteArray, metadata: ByteArray?, autoCompress: Boolean) {
        // Handle metadata. Mirrors python Resource.__init__ (Resource.py:260-268):
        //   packed_metadata = umsgpack.packb(metadata)
        //   self.metadata   = struct.pack(">I", len(packed_metadata))[1:] + packed_metadata
        //   data            = self.metadata + resource_data
        // i.e. the metadata is first msgpack-packed (a `bytes` value packs to bin
        // format: 0xC4 + len + body for <=255 bytes), THEN prefixed with a 3-byte
        // big-endian length of the PACKED block. total_size counts the whole
        // 3 + len(packed) metadata block. A previous build prepended the raw
        // metadata without the msgpack wrapper, growing total_size by only
        // 3 + len(metadata) instead of 3 + len(umsgpack.packb(metadata)).
        var metadataBlock = ByteArray(0)
        if (metadata != null) {
            // python Resource.py:264-265 raises; dropping the metadata silently sent a
            // transfer the receiver could not interpret.
            require(metadata.size <= ResourceConstants.METADATA_MAX_SIZE) {
                "Resource metadata size of ${metadata.size} bytes exceeds the maximum of ${ResourceConstants.METADATA_MAX_SIZE} bytes"
            }
            this.metadata = metadata
            this.hasMetadata = true
            val packedMetadata = msgpackPackBinary(metadata)
            val metaSize = packedMetadata.size
            val metaPrefix = byteArrayOf(
                ((metaSize shr 16) and 0xFF).toByte(),
                ((metaSize shr 8) and 0xFF).toByte(),
                (metaSize and 0xFF).toByte()
            )
            metadataBlock = metaPrefix + packedMetadata
        }
        autoCompressOption = autoCompress
        segmentMetadataSize = metadataBlock.size
        totalSize = data.size + segmentMetadataSize

        // Segmentation. Mirrors python Resource.__init__ (Resource.py:275-322):
        // a payload whose metadata_size + len(data) exceeds MAX_EFFICIENT_SIZE
        // is spooled and only the FIRST segment's range
        // (MAX_EFFICIENT_SIZE - metadata_size bytes) becomes this resource's
        // data; later segments are built by prepareNextSegment() from the
        // retained source. A previous build set split/totalSegments > 1 while
        // still packing the whole payload into this one resource and had no
        // segment source for prepareNextSegment(), so validateProof spun
        // forever waiting for a segment that could never be built.
        val segmentData: ByteArray
        if (totalSize > ResourceConstants.MAX_EFFICIENT_SIZE) {
            totalSegments = ((totalSize - 1) / ResourceConstants.MAX_EFFICIENT_SIZE) + 1
            segmentIndex = 1
            split = true
            segmentSource = data
            // The first segment's raw read is MAX_EFFICIENT_SIZE - metadata block
            // (python first_read_size, Resource.py:303). A metadata block that fills
            // the whole segment budget makes that read size zero or negative: the
            // reference then reads with a negative size and CPython raises
            // ValueError, so it does not complete this degenerate transfer either.
            // Fail fast with a clear error instead of advertising an empty segment.
            if (segmentMetadataSize >= ResourceConstants.MAX_EFFICIENT_SIZE) {
                throw IllegalArgumentException(
                    "metadata block ($segmentMetadataSize bytes) leaves no room " +
                        "for the first segment payload (budget ${ResourceConstants.MAX_EFFICIENT_SIZE} bytes)",
                )
            }
            val firstReadSize = ResourceConstants.MAX_EFFICIENT_SIZE - segmentMetadataSize
            segmentData = data.copyOfRange(0, min(firstReadSize, data.size))
        } else {
            totalSegments = 1
            segmentIndex = 1
            split = false
            segmentData = data
        }

        val dataWithMetadata = if (metadataBlock.isEmpty()) segmentData else metadataBlock + segmentData
        initializeSegmentPayload(dataWithMetadata, autoCompress)
    }

    /**
     * Build this resource's transfer payload (compress, encrypt, split into
     * parts, hashmap, hash and expected proof) from ONE segment's data —
     * [dataWithMetadata] is `self.metadata + resource_data` for the first
     * segment and the bare segment range for later ones (Resource.py:335-337).
     * Shared by [initializeForSending] (segment 1) and [buildNextSegment].
     * Does not touch totalSize / totalSegments / segmentIndex / split, which
     * the caller has already set for the whole transfer.
     */
    private fun initializeSegmentPayload(dataWithMetadata: ByteArray, autoCompress: Boolean) {
        // Python: self.uncompressed_data = data; self.uncompressed_size = len(...)
        // (Resource.py:402) — the segment payload including its metadata block.
        uncompressedData = dataWithMetadata
        uncompressedSize = dataWithMetadata.size

        // Compress if requested and within limits
        val compressedResult = if (autoCompress && dataWithMetadata.size <= ResourceConstants.AUTO_COMPRESS_MAX_SIZE) {
            compress(dataWithMetadata)
        } else {
            dataWithMetadata
        }

        compressed = compressedResult.size < dataWithMetadata.size
        compressedData = if (compressed) compressedResult else null

        // Use compressed data if it's smaller, otherwise uncompressed
        val contentData = if (compressed) compressedResult else dataWithMetadata

        // Generate random prefix for the data stream (different from randomHash!)
        // This provides uniqueness for the encrypted stream
        val dataRandomPrefix = ByteArray(ResourceConstants.RANDOM_HASH_SIZE).also { random.nextBytes(it) }

        // Build the transfer data: random_prefix + content
        val prefixedData = dataRandomPrefix + contentData

        // Encrypt the entire data stream using the link's encryption
        val encryptedData = link.encrypt(prefixedData)
        encrypted = true

        size = encryptedData.size
        log("initializeForSending: prefixedData=${prefixedData.size} bytes, encryptedData=${encryptedData.size} bytes")

        val totalParts = ceil(size.toDouble() / sdu).toInt()

        // Build the hashmap, rebuilding under a fresh random_hash if two parts inside the
        // receiver's COLLISION_GUARD window map to the same hash (python Resource.py:440-477).
        //
        // A map hash is what the receiver uses to ask for a specific part. Two parts sharing
        // one inside the window are indistinguishable to it: a request resolves to whichever
        // the receiver finds first, so one part is delivered twice and the other never, and
        // the transfer fails its final hash check after moving all the data. The map hash is
        // salted with random_hash, so drawing a new one re-rolls every part's hash at once.
        var attempts = 0
        while (true) {
            // Regenerating random_hash changes the resource hash, so it must be drawn
            // INSIDE the loop — the hashes below are derived from whichever draw wins.
            randomHash = ByteArray(ResourceConstants.RANDOM_HASH_SIZE).also { random.nextBytes(it) }

            val candidateParts = arrayOfNulls<ByteArray>(totalParts)
            val candidateHashes = arrayOfNulls<ByteArray>(totalParts)
            val hashmapBuilder = ByteArrayOutputStream()
            val collisionGuard = ArrayDeque<ByteArrayKey>()
            var collided = false

            for (i in 0 until totalParts) {
                val start = i * sdu
                val end = min(start + sdu, size)
                val part = encryptedData.copyOfRange(start, end)

                // Calculate part hash: full_hash(part + randomHash)[:MAPHASH_LEN]
                val partHash = getMapHash(part)
                val key = partHash.toKey()
                if (collisionGuard.contains(key)) {
                    log("Found hash collision in resource map, remapping...")
                    collided = true
                    break
                }
                collisionGuard.addLast(key)
                if (collisionGuard.size > ResourceAdvertisement.COLLISION_GUARD_SIZE) {
                    collisionGuard.removeFirst()
                }

                candidateParts[i] = part
                candidateHashes[i] = partHash
                hashmapBuilder.write(partHash)
            }

            if (!collided) {
                parts = candidateParts
                hashmap = candidateHashes
                hashmapRaw = hashmapBuilder.toByteArray()
                break
            }

            // Each retry is an independent draw over a 4-byte hash, so the chance of
            // repeated collisions falls off immediately. A bound still beats an unbounded
            // loop here: giving up leaves the caller with an error instead of a hang.
            attempts++
            if (attempts >= MAX_HASHMAP_REBUILDS) {
                throw IllegalStateException(
                    "Could not build a collision-free resource hashmap for $totalParts " +
                        "parts after $attempts attempts",
                )
            }
        }

        // Calculate resource hash from UNCOMPRESSED data (with metadata) + randomHash
        // This matches Python: self.hash = RNS.Identity.full_hash(data+self.random_hash)
        hash = Hashes.fullHash(dataWithMetadata + randomHash)
        originalHash = hash.copyOf()

        // Calculate expected proof: full_hash(uncompressed_data + hash)
        expectedProof = Hashes.fullHash(dataWithMetadata + hash)

        status = ResourceConstants.QUEUED
        log("Resource ${hash.toHexString()} created: $size bytes in ${parts.size} parts (compressed=$compressed, encrypted=$encrypted)")
    }

    /**
     * Initialize resource from received advertisement.
     */
    private fun initializeFromAdvertisement(adv: ResourceAdvertisement) {
        status = ResourceConstants.TRANSFERRING
        hash = adv.hash
        originalHash = adv.originalHash
        randomHash = adv.randomHash
        size = adv.transferSize
        totalSize = adv.dataSize
        uncompressedSize = adv.dataSize
        compressed = adv.compressed
        encrypted = adv.encrypted
        hasMetadata = adv.hasMetadata
        split = adv.split
        segmentIndex = adv.segmentIndex
        totalSegments = adv.totalSegments
        requestId = adv.requestId

        // Derive the part count from the advertised TRANSFER SIZE and this
        // receiver's OWN per-part SDU — NOT the advertised n field. Mirrors
        // python `Resource.accept` (Resource.py:187):
        //   resource.total_parts = int(math.ceil(resource.size/float(resource.sdu)))
        // The advertisement also carries n = len(parts) (Resource.py:301) but
        // accept never reads it; trusting a tampered n would build a mis-sized
        // parts list and desynchronise indexing.
        val totalParts = ceil(size.toDouble() / sdu).toInt()
        parts = arrayOfNulls(totalParts)
        hashmap = arrayOfNulls(totalParts)

        // Parse hashmap from advertisement
        hashmapRaw = adv.hashmap
        updateHashmap(0, hashmapRaw)

        // Inherit the previous transfer's final window on this link, mirroring
        // python `Resource.accept` (Resource.py:216-218):
        //   previous_window = resource.link.get_last_resource_window()
        //   if previous_window: resource.window = previous_window
        // Link.resourceConcluded records the window of each completed inbound
        // transfer; a second transfer starts at that grown window rather than
        // the WINDOW=4 default, preserving multi-resource throughput.
        link.getLastResourceWindow()?.let { window = it }

        lastActivity = clock()
        startedTransferring = lastActivity

        // Register with link
        link.registerIncomingResource(this)

        log("Resource ${hash.toHexString()} accepted: $size bytes in ${parts.size} parts")
    }

    /**
     * Advertise this resource to the receiver.
     */
    fun advertise() {
        if (status != ResourceConstants.QUEUED) return

        // One-outgoing-resource-at-a-time gate. Mirrors python
        // `Resource.__advertise_job` (Resource.py:520-524):
        //   while not self.link.ready_for_new_resource():
        //       self.status = Resource.QUEUED
        //       sleep(0.25)
        // If the link already has an outgoing resource in flight, spin in QUEUED
        // (on a daemon thread, like python's __advertise_job) until it is ready,
        // then advertise. The common idle case (ready immediately) advertises
        // synchronously, so this adds no thread/latency for the normal path.
        if (!link.readyForNewResource()) {
            thread(isDaemon = true, name = "resource-advertise-${hash.toHexString().take(8)}") {
                while (status == ResourceConstants.QUEUED && !link.readyForNewResource()) {
                    try {
                        Thread.sleep(250)
                    } catch (e: InterruptedException) {
                        return@thread
                    }
                }
                if (status == ResourceConstants.QUEUED) {
                    doAdvertise()
                }
            }
            return
        }

        doAdvertise()
    }

    private fun doAdvertise() {
        if (status != ResourceConstants.QUEUED) return

        // Register with link
        link.registerOutgoingResource(this)

        status = ResourceConstants.ADVERTISED
        rtt = null
        retriesLeft = ResourceConstants.MAX_ADV_RETRIES
        sendAdvertisementPacket()
        startWatchdog()
        log("Advertised resource ${hash.toHexString()}")

        // Start building the next segment in the background while this one
        // transfers, so validateProof normally finds it ready (Resource.py:525-527).
        if (segmentIndex < totalSegments) {
            prepareNextSegment()
        }
    }

    /** Count of RESOURCE_ADV packets this sender has emitted (initial + watchdog re-sends). */
    @Volatile
    private var advSendCount = 0

    /**
     * Build and send this resource's RESOURCE_ADV packet and refresh the advertisement clocks.
     * Extracted from [doAdvertise] so the sender watchdog can re-advertise when no part requests
     * arrive: a lost initial advertisement leaves the receiver unaware, and only the sender can
     * recover by re-advertising (Python watchdog ADVERTISED branch, Resource.py:585-598).
     */
    private fun sendAdvertisementPacket() {
        advSendCount++
        val advData = ResourceAdvertisement.fromResource(this).pack()
        val encrypted = link.encrypt(advData)
        val packet = Packet.createRaw(
            destinationHash = link.linkId,
            data = encrypted,
            packetType = PacketType.DATA,
            destinationType = DestinationType.LINK,
            context = PacketContext.RESOURCE_ADV,
            mtu = link.mtu,
        )
        packet.send()
        lastActivity = clock()
        advSent = lastActivity
    }

    /**
     * Send the next batch of parts.
     */
    private fun sendParts() {
        if (status != ResourceConstants.TRANSFERRING) return

        var sent = 0
        for (i in parts.indices) {
            if (sent >= window) break

            val part = parts[i]
            if (part != null) {
                sendPart(i, part)
                sent++
            }
        }
    }

    /**
     * Send a single part.
     * Matches Python: part is just the encrypted data chunk, no index prefix.
     * The receiver identifies parts by their map hash, not by index.
     */
    private fun sendPart(index: Int, data: ByteArray) {
        // Send just the data - no index prefix!
        // Python identifies parts by computing the map hash of the received data
        link.sendResourceData(data)
        lastActivity = clock()
        lastPartSent = lastActivity

        // Track sent parts
        if (sentPartsSet.add(index)) {
            sentParts++
            // Outgoing progress: fire on the sender as each new part is
            // transmitted, mirroring the receiver-side callback in receivePart().
            // Resends do not re-enter this block (sentPartsSet.add returns false), so
            // progress only advances on the first send of each part. Matches Python
            // get_progress(), which uses sent_parts/total_parts for the initiator.
            try {
                callbacks.progress?.invoke(this)
            } catch (e: Exception) {
                log("Error in progress callback: ${e.message}")
            }
        }
    }

    /**
     * Receive a part from the sender.
     * Parts are identified by their map hash, not by index.
     * Matches Python RNS receive_part() protocol.
     */
    /**
     * True if [data]'s map hash falls in this resource's current receive window,
     * i.e. this part belongs to this resource. Side-effect-free — the Link uses it
     * to route an inbound RESOURCE part to the ONE resource it belongs to, so two
     * concurrent transfers on a single link no longer send every part to the first
     * transferring resource. The map hash is resource-specific (it mixes the
     * resource's randomHash), so membership can only be decided per-resource; this
     * mirrors [receivePart]'s window search without mutating any state, and a
     * completed resource (searchStart == parts.size) correctly returns false.
     */
    fun acceptsPart(data: ByteArray): Boolean {
        receiveLock.lock()
        try {
            if (status == ResourceConstants.FAILED) return false
            val partHash = getMapHash(data)
            val searchStart = if (consecutiveCompletedHeight >= 0) consecutiveCompletedHeight else 0
            for (i in searchStart until minOf(searchStart + window, parts.size)) {
                val mapHash = hashmap[i]
                if (mapHash != null && mapHash.contentEquals(partHash)) return true
            }
            return false
        } finally {
            receiveLock.unlock()
        }
    }

    fun receivePart(data: ByteArray) {
        receiveLock.lock()
        try {
            receivingPart = true
            lastActivity = clock()
            retriesLeft = ResourceConstants.MAX_RETRIES

            // RTT calculation on first response
            if (reqResp == null) {
                reqResp = lastActivity
                val rttMs = reqResp!! - reqSent
                // python Resource.py:853: once an RTT sample exists the part timeout
                // factor halves.
                partTimeoutFactor = ResourceConstants.PART_TIMEOUT_FACTOR_AFTER_RTT

                if (rtt == null) {
                    rtt = link.rtt ?: rttMs
                } else if (rttMs < rtt!!) {
                    rtt = maxOf(rtt!! - (rtt!! * 0.05).toLong(), rttMs)
                } else if (rttMs > rtt!!) {
                    rtt = minOf(rtt!! + (rtt!! * 0.05).toLong(), rttMs)
                }

                // Calculate request-response RTT rate
                if (rttMs > 0) {
                    val reqRespCost = data.size + reqSentBytes
                    reqRespRttRate = reqRespCost.toDouble() / (rttMs.toDouble() / 1000.0)

                    if (reqRespRttRate > ResourceConstants.RATE_FAST && fastRateRounds < ResourceConstants.FAST_RATE_THRESHOLD) {
                        fastRateRounds++
                        if (fastRateRounds == ResourceConstants.FAST_RATE_THRESHOLD) {
                            windowMax = ResourceConstants.WINDOW_MAX_FAST
                        }
                    }
                }
            }

            if (status == ResourceConstants.FAILED) {
                receivingPart = false
                return
            }

            status = ResourceConstants.TRANSFERRING
            val partData = data
            val partHash = getMapHash(partData)

            log("receivePart: received ${partData.size} bytes, partHash=${partHash.toHexString()}")
            log("receivePart: randomHash=${randomHash.toHexString()}, hashmap size=${hashmap.size}")
            if (hashmap.isNotEmpty() && hashmap[0] != null) {
                log("receivePart: expected hashmap[0]=${hashmap[0]!!.toHexString()}")
            }

            // Search for matching hash in current window
            val searchStart = if (consecutiveCompletedHeight >= 0) consecutiveCompletedHeight else 0
            log("receivePart: searchStart=$searchStart, window=$window, parts.size=${parts.size}")
            for (i in searchStart until minOf(searchStart + window, parts.size)) {
                val mapHash = hashmap[i]
                if (mapHash != null && mapHash.contentEquals(partHash)) {
                    if (parts[i] == null) {
                        // Insert data into parts list
                        parts[i] = partData
                        rttRxdBytes += partData.size
                        receivedCount++
                        outstandingParts--

                        // Update consecutive completed pointer
                        if (i == consecutiveCompletedHeight + 1) {
                            consecutiveCompletedHeight = i
                        }

                        // Extend consecutive pointer if possible
                        var cp = consecutiveCompletedHeight + 1
                        while (cp < parts.size && parts[cp] != null) {
                            consecutiveCompletedHeight = cp
                            cp++
                        }

                        // Progress callback
                        try {
                            callbacks.progress?.invoke(this)
                        } catch (e: Exception) {
                            log("Error in progress callback: ${e.message}")
                        }
                    }
                    break
                }
            }

            receivingPart = false

            // Check if transfer complete
            if (receivedCount == parts.size && !assemblyLock) {
                assemblyLock = true
                assemble()
            } else if (outstandingParts == 0) {
                // All outstanding parts received, adjust window and request more
                if (window < windowMax) {
                    window++
                    if ((window - windowMin) > (windowFlexibility - 1)) {
                        windowMin++
                    }
                }

                // Calculate data rate
                if (reqSent != 0L) {
                    val rttMs = clock() - reqSent
                    val reqTransferred = rttRxdBytes - rttRxdBytesAtPartReq

                    if (rttMs != 0L) {
                        reqDataRttRate = reqTransferred.toDouble() / (rttMs.toDouble() / 1000.0)
                        updateEifr()
                        rttRxdBytesAtPartReq = rttRxdBytes

                        if (reqDataRttRate > ResourceConstants.RATE_FAST && fastRateRounds < ResourceConstants.FAST_RATE_THRESHOLD) {
                            fastRateRounds++
                            if (fastRateRounds == ResourceConstants.FAST_RATE_THRESHOLD) {
                                windowMax = ResourceConstants.WINDOW_MAX_FAST
                            }
                        }

                        if (fastRateRounds == 0 && reqDataRttRate < ResourceConstants.RATE_VERY_SLOW &&
                            verySlowRateRounds < ResourceConstants.VERY_SLOW_RATE_THRESHOLD) {
                            verySlowRateRounds++
                            if (verySlowRateRounds == ResourceConstants.VERY_SLOW_RATE_THRESHOLD) {
                                windowMax = ResourceConstants.WINDOW_MAX_VERY_SLOW
                            }
                        }
                    }
                }

                // Auto-follow-up request, suppressible under test (see autoRequestNext)
                // to mirror the reference shadowing request_next during a part-feed.
                if (autoRequestNext) requestNext()
            }
        } finally {
            receivingPart = false
            receiveLock.unlock()
        }
    }

    /**
     * Request the next batch of missing parts.
     * Matches Python RNS request_next() protocol.
     */
    private fun requestNext() {
        // Wait for any receiving operation to complete
        while (receivingPart) {
            Thread.sleep(1)
        }

        if (status == ResourceConstants.FAILED) return
        if (waitingForHmu) return

        outstandingParts = 0
        var hashmapExhausted = ResourceConstants.HASHMAP_IS_NOT_EXHAUSTED
        val requestedHashes = ByteArrayOutputStream()

        var i = 0
        var pn = consecutiveCompletedHeight + 1
        val searchStart = pn

        for (partIdx in searchStart until minOf(searchStart + window, parts.size)) {
            if (parts[partIdx] == null) {
                val partHash = hashmap[partIdx]
                if (partHash != null) {
                    requestedHashes.write(partHash)
                    outstandingParts++
                    i++
                } else {
                    hashmapExhausted = ResourceConstants.HASHMAP_IS_EXHAUSTED
                }
            }
            pn++
            if (i >= window || hashmapExhausted == ResourceConstants.HASHMAP_IS_EXHAUSTED) {
                break
            }
        }

        // Build HMU part
        val hmuPart = ByteArrayOutputStream()
        hmuPart.write(hashmapExhausted)
        if (hashmapExhausted == ResourceConstants.HASHMAP_IS_EXHAUSTED) {
            val lastMapHash = hashmap[hashmapHeight - 1]
            if (lastMapHash != null) {
                hmuPart.write(lastMapHash)
            }
            // Count the false->true transition of waiting_for_hmu — this is the
            // hashmap-update request the receiver issues over a >74-part transfer.
            // The reference harness counts the same event by wrapping the
            // instance request_next (wire_tcp.py on_resource_started). requestNext
            // early-returns while waitingForHmu, so reaching here always means a
            // false->true transition.
            hmuRequestsSent.incrementAndGet()
            waitingForHmu = true
        }

        // Build full request: hmu_part + resource_hash + requested_hashes
        val requestData = ByteArrayOutputStream()
        requestData.write(hmuPart.toByteArray())
        requestData.write(hash)
        requestData.write(requestedHashes.toByteArray())

        try {
            // Send encrypted via link
            val reqDataBytes = requestData.toByteArray()
            // Record the genuine request plaintext + count this emit. Mirrors the
            // reference harness capturing each outbound RESOURCE_REQ packet's
            // .data (wire_tcp.py cmd_wire_resource_request_next_content). Captured
            // only at the actual send block, so the waitingForHmu early-return
            // above does not bump the count.
            lastRequestData = reqDataBytes
            requestNextEmitCount.incrementAndGet()
            val encrypted = link.encrypt(reqDataBytes)
            val packet = Packet.createRaw(
                destinationHash = link.linkId,
                data = encrypted,
                packetType = PacketType.DATA,
                destinationType = DestinationType.LINK,
                context = PacketContext.RESOURCE_REQ,
                mtu = link.mtu
            )

            packet.send()
            lastActivity = clock()
            reqSent = lastActivity
            reqSentBytes = encrypted.size
            reqResp = null
        } catch (e: Exception) {
            log("Failed to send resource request: ${e.message}")
        }
    }

    /**
     * Handle a request for parts from the receiver.
     * Matches Python RNS request() protocol.
     */
    fun handleRequest(data: ByteArray) {
        if (status == ResourceConstants.FAILED) return

        // Calculate RTT
        val rttMs = clock() - advSent
        if (rtt == null) {
            rtt = rttMs
        }

        if (status != ResourceConstants.TRANSFERRING) {
            status = ResourceConstants.TRANSFERRING
            startedTransferring = clock()
        }

        retriesLeft = ResourceConstants.MAX_RETRIES

        // Parse request format: [hmu_flag] [last_map_hash?] [resource_hash] [requested_hashes...]
        val wantsMoreHashmap = data[0].toInt() and 0xFF == ResourceConstants.HASHMAP_IS_EXHAUSTED
        val pad = if (wantsMoreHashmap) 1 + ResourceConstants.MAPHASH_LEN else 1

        // Extract requested hashes (after pad + resource hash). Mirrors python
        // `Resource.request` (Resource.py:998): requested_hashes =
        // request_data[pad+HASHLENGTH//8:]. An exhausted HMU-only request carries
        // NO requested hashes (data.size == hashStart) but MUST still reach the
        // hashmap-update / sequencing-gate branch below — so only a strictly
        // SHORTER (malformed) request is dropped here, not the empty-hashes case.
        // (A previous `<=` guard dropped every HMU-only request, skipping the
        // 74-alignment sequencing gate entirely.)
        val hashStart = pad + ResourceConstants.RESOURCE_HASH_LEN
        if (data.size < hashStart) return

        val requestedHashesData = data.copyOfRange(hashStart, data.size)

        // Define search scope
        val searchStart = receiverMinConsecutiveHeight
        val searchEnd = receiverMinConsecutiveHeight + ResourceAdvertisement.COLLISION_GUARD_SIZE

        // Parse requested map hashes
        val mapHashes = mutableListOf<ByteArray>()
        for (i in 0 until requestedHashesData.size / ResourceConstants.MAPHASH_LEN) {
            val start = i * ResourceConstants.MAPHASH_LEN
            val end = start + ResourceConstants.MAPHASH_LEN
            mapHashes.add(requestedHashesData.copyOfRange(start, end))
        }

        // Find and send requested parts. Mirrors python `Resource.request`
        // (Resource.py:1009-1014):
        //   if not part.sent: part.send(); self.sent_parts += 1
        //   else: part.resend()
        // sendPart() already tracks first-send vs resend via sentPartsSet and
        // increments sentParts exactly once per unique part — so this loop must
        // NOT separately bump sentParts / sentPartsSet. A previous build did both
        // (sendPart AND an inline increment), double-counting sent_parts: an
        // 8-part serve reported sent_parts=16 and reached AWAITING_PROOF after
        // only half the parts were actually sent.
        // Use the map hashes computed once at construction (hashmap[i], the
        // sender-side equivalent of python's precomputed part.map_hash,
        // Resource.py:1021/1047) instead of re-hashing every candidate part per
        // request: a ~100-byte RESOURCE_REQ otherwise cost ~2 x COLLISION_GUARD_SIZE
        // SHA-256s on the ingest thread.
        for (actualIndex in searchStart until minOf(searchEnd, parts.size)) {
            val part = parts[actualIndex] ?: continue
            val partMapHash = hashmap[actualIndex] ?: continue
            if (mapHashes.any { it.contentEquals(partMapHash) }) {
                sendPart(actualIndex, part)
                lastActivity = clock()
            }
        }

        // Handle hashmap update request
        if (wantsMoreHashmap) {
            val lastMapHash = data.copyOfRange(1, 1 + ResourceConstants.MAPHASH_LEN)

            // Find the part that matches last_map_hash
            var partIndex = receiverMinConsecutiveHeight
            for (i in searchStart until minOf(searchEnd, parts.size)) {
                // Precomputed map hash (see the send loop above).
                val partMapHash = if (parts[i] != null) hashmap[i] else null
                partIndex++
                if (partMapHash != null && partMapHash.contentEquals(lastMapHash)) {
                    break
                }
            }

            receiverMinConsecutiveHeight = maxOf(partIndex - 1 - ResourceConstants.WINDOW_MAX, 0)

            if (partIndex % ResourceAdvertisement.HASHMAP_MAX_LEN != 0) {
                log("Resource sequencing error, cancelling transfer!")
                cancel()
                return
            }

            val segment = partIndex / ResourceAdvertisement.HASHMAP_MAX_LEN

            // Build hashmap update
            val hashmapStart = segment * ResourceAdvertisement.HASHMAP_MAX_LEN
            val hashmapEnd = minOf((segment + 1) * ResourceAdvertisement.HASHMAP_MAX_LEN, parts.size)

            val hashmapData = ByteArrayOutputStream()
            for (i in hashmapStart until hashmapEnd) {
                val start = i * ResourceConstants.MAPHASH_LEN
                val end = start + ResourceConstants.MAPHASH_LEN
                if (end <= hashmapRaw.size) {
                    hashmapData.write(hashmapRaw.copyOfRange(start, end))
                }
            }

            // Send hashmap update: resource_hash + msgpack([segment, hashmap])
            val hmuData = ByteArrayOutputStream()
            hmuData.write(hash)
            // Pack [segment, hashmap] using msgpack
            val packer = org.msgpack.core.MessagePack.newDefaultPacker(hmuData)
            packer.packArrayHeader(2)
            packer.packInt(segment)
            packer.packBinaryHeader(hashmapData.size())
            packer.writePayload(hashmapData.toByteArray())
            packer.close()

            try {
                // Send encrypted via link
                val hmuBytes = hmuData.toByteArray()
                val encrypted = link.encrypt(hmuBytes)
                val hmuPacket = Packet.createRaw(
                    destinationHash = link.linkId,
                    data = encrypted,
                    packetType = PacketType.DATA,
                    destinationType = DestinationType.LINK,
                    context = PacketContext.RESOURCE_HMU,
                    mtu = link.mtu
                )
                hmuPacket.send()
                lastActivity = clock()
            } catch (e: Exception) {
                log("Failed to send hashmap update: ${e.message}")
            }
        }

        // Check if all parts have been sent
        if (sentParts >= parts.size) {
            status = ResourceConstants.AWAITING_PROOF
            retriesLeft = 3 // python Resource.py:1083: three cache re-queries for the proof
            log("All parts sent, awaiting proof for ${hash.toHexString()}")
        }
    }

    /**
     * Handle a hashmap update packet from the sender.
     * Matches Python RNS hashmap_update_packet().
     */
    fun handleHashmapUpdate(plaintext: ByteArray) {
        if (status == ResourceConstants.FAILED) return
        // Only apply an HMU we asked for (`if self.waiting_for_hmu`,
        // Resource.py:489-490). An unsolicited one otherwise rewrote hashmap
        // slots and reflected one RESOURCE_REQ per packet.
        if (!waitingForHmu) return

        lastActivity = clock()
        retriesLeft = ResourceConstants.MAX_RETRIES

        // Parse: resource_hash (32 bytes) + msgpack([segment, hashmap])
        if (plaintext.size <= ResourceConstants.RESOURCE_HASH_LEN) return

        val msgpackData = plaintext.copyOfRange(ResourceConstants.RESOURCE_HASH_LEN, plaintext.size)

        try {
            val unpacker = org.msgpack.core.MessagePack.newDefaultUnpacker(msgpackData)
            val arraySize = unpacker.unpackArrayHeader()
            if (arraySize != 2) return

            val segment = unpacker.unpackInt()
            val hashmapLen = unpacker.unpackBinaryHeader()
            // Never allocate for a declared bin length the packet cannot back:
            // msgpack-core's readPayload(n) is `new byte[n]` before any read, so
            // an attacker-declared bin32 length near 2^31 forced a huge
            // allocation / OutOfMemoryError. A genuine HMU carries at most
            // HASHMAP_MAX_LEN map hashes (Resource.py:1057-1069).
            val remaining = msgpackData.size - unpacker.totalReadBytes
            if (hashmapLen < 0 || hashmapLen > remaining ||
                hashmapLen > ResourceAdvertisement.HASHMAP_MAX_LEN * ResourceConstants.MAPHASH_LEN
            ) {
                log("Invalid hashmap update length $hashmapLen, ignoring")
                return
            }
            val hashmapBytes = unpacker.readPayload(hashmapLen)
            unpacker.close()

            // Count each accepted hashmap-update segment. Mirrors the reference
            // harness wrapping the instance hashmap_update_packet
            // (wire_tcp.py on_resource_started). Counted in the packet handler,
            // NOT in the private hashmapUpdate(), so the inject_hashmap_update
            // injector (which drives hashmapUpdate directly) is unaffected.
            hashmapUpdatesReceived.incrementAndGet()
            hashmapUpdate(segment, hashmapBytes)
        } catch (e: Exception) {
            log("Failed to parse hashmap update: ${e.message}")
        }
    }

    /**
     * Apply a hashmap update.
     * Matches Python RNS hashmap_update().
     */
    private fun hashmapUpdate(segment: Int, hashmapBytes: ByteArray) {
        if (status == ResourceConstants.FAILED) return

        status = ResourceConstants.TRANSFERRING
        val segLen = ResourceAdvertisement.HASHMAP_MAX_LEN
        val hashes = hashmapBytes.size / ResourceConstants.MAPHASH_LEN

        // A negative segment has no meaning (python's negative list index
        // would silently write at the tail, Resource.py:503-504); treat it
        // like an empty HMU and cancel.
        if (segment < 0) {
            log("Invalid HMU segment $segment received, cancelling transfer")
            cancel()
            return
        }

        for (i in 0 until hashes) {
            // Long arithmetic: a huge segment must not overflow into a
            // negative index that passes the `< hashmap.size` check.
            val idxLong = i.toLong() + segment.toLong() * segLen
            if (idxLong >= hashmap.size) continue
            val idx = idxLong.toInt()
            if (hashmap[idx] == null) {
                hashmapHeight++
            }
            val start = i * ResourceConstants.MAPHASH_LEN
            val end = start + ResourceConstants.MAPHASH_LEN
            hashmap[idx] = hashmapBytes.copyOfRange(start, end)
        }

        // `if hashes < 1: cancel()` (Resource.py:506-508): an empty HMU is
        // invalid, not a reason to re-request.
        if (hashes < 1) {
            log("Invalid HMU received, cancelling transfer")
            cancel()
            return
        }

        waitingForHmu = false
        requestNext()
    }

    /**
     * Update expected in-flight rate.
     * Matches Python RNS update_eifr().
     */
    private fun updateEifr() {
        val currentRtt = rtt ?: link.rtt ?: return

        val expectedInflightRate = if (reqDataRttRate != 0.0) {
            reqDataRttRate * 8
        } else if (previousEifr != null) {
            previousEifr!!
        } else {
            // python Resource.py:568: link.establishment_cost * 8 / rtt. A link whose
            // cost was never recorded falls back to one MDU so the rate is never zero.
            val costBytes = if (link.establishmentCost > 0) link.establishmentCost else link.mdu
            (costBytes * 8).toDouble() / (currentRtt.toDouble() / 1000.0)
        }

        eifr = expectedInflightRate
        previousEifr = eifr
    }

    /**
     * Send proof of complete receipt to sender.
     * Called by receiver after successfully assembling all parts.
     * Matches Python: proof = full_hash(self.data + self.hash)
     * where self.data includes metadata (before stripping).
     */
    private fun prove() {
        // Count every prove() entry. The reference harness wraps the instance
        // prove (wire_tcp.py cmd_wire_resource_receiver_proof_count /
        // cmd_wire_inject_corrupt_assembled_resource) to assert exactly one
        // proof per completed transfer and zero on a CORRUPT one.
        proveCalls.incrementAndGet()
        if (status == ResourceConstants.FAILED) return

        try {
            // Use uncompressedData which contains data WITH metadata
            // This matches Python's prove() which uses self.data before metadata is stripped
            val proofData = uncompressedData
            if (proofData == null) {
                log("Cannot prove resource: no assembled data")
                return
            }

            val proof = Hashes.fullHash(proofData + hash)
            val proofPayload = hash + proof

            // Create proof packet - NOT encrypted (matches Python: resource proofs are not encrypted)
            val packet = Packet.createRaw(
                destinationHash = link.linkId,
                data = proofPayload,
                packetType = PacketType.PROOF,
                destinationType = DestinationType.LINK,
                context = PacketContext.RESOURCE_PRF,
                mtu = link.mtu
            )

            packet.send()
            log("Sent proof for resource ${hash.toHexString()}")

        } catch (e: Exception) {
            log("Could not send proof packet: ${e.message}")
            cancel()
        }
    }

    /**
     * Validate proof received from receiver.
     * Called by sender when proof packet arrives.
     */
    fun validateProof(proofData: ByteArray): Boolean {
        if (status == ResourceConstants.FAILED) return false

        try {
            // Proof format: [resource_hash (32 bytes)][proof (32 bytes)]
            // Python sends full hash (32 bytes), not truncated (16 bytes)
            if (proofData.size != RnsConstants.FULL_HASH_BYTES * 2) {
                log("Invalid proof length: ${proofData.size}")
                return false
            }

            val receivedHash = proofData.copyOfRange(0, RnsConstants.FULL_HASH_BYTES)
            val receivedProof = proofData.copyOfRange(RnsConstants.FULL_HASH_BYTES, proofData.size)

            // Verify the proof matches expected
            val expected = expectedProof
            if (expected == null) {
                log("No expected proof available")
                return false
            }

            if (!receivedProof.contentEquals(expected)) {
                log("Proof validation failed: mismatch")
                return false
            }

            // Multi-segment: resolve the next segment BEFORE concluding this
            // one. Python sets COMPLETE first and then blocks in
            // `while self.next_segment == None: time.sleep(0.05)`
            // (Resource.py:816-826) — safe there because __prepare_next_segment
            // always succeeds from the tempfile and validate_proof runs on its
            // own thread. Here validateProof runs on the Transport ingest thread
            // under jobsLock, so the wait is bounded (see awaitNextSegment) and a
            // segment that cannot be built cancels the transfer instead of
            // spinning; ordering the wait first keeps cancel()'s
            // `status < COMPLETE` guard effective.
            var next: Resource? = null
            if (segmentIndex < totalSegments) {
                next = awaitNextSegment()
                if (next == null) {
                    log("Could not prepare segment ${segmentIndex + 1}/$totalSegments, cancelling transfer")
                    cancel()
                    return false
                }
            }

            // Mark resource as complete
            status = ResourceConstants.COMPLETE
            stopWatchdog()
            link.resourceConcluded(this)
            log("Resource ${hash.toHexString()} proof validated successfully")

            if (next != null) {
                // Advertise the next segment (Resource.py:834)
                next.advertise()

                // Clean up this segment's data (Resource.py:827-832); the next
                // segment holds its own reference to the shared source.
                uncompressedData = null
                compressedData = null
                assembledData = null
                parts = arrayOf()
                segmentSource = null
            } else {
                // All segments complete, invoke callback (Resource.py:800-814)
                callbacks.completed?.invoke(this)

                // Close input file if present
                inputFile?.close()
                inputFile = null
                segmentSource = null
            }

            return true

        } catch (e: Exception) {
            log("Error validating proof: ${e.message}")
            return false
        }
    }

    /**
     * Prepare the next segment for a multi-segment transfer.
     * This creates a new Resource for the next segment of data.
     */
    private fun prepareNextSegment() {
        if (preparingNextSegment) return
        if (segmentIndex >= totalSegments) return
        if (segmentSource == null && inputFile == null) {
            log("Cannot prepare next segment: no segment source")
            return
        }

        preparingNextSegment = true
        log("Preparing segment ${segmentIndex + 1} of $totalSegments")

        thread(isDaemon = true, name = "segment-prep-${hash.toHexString().take(8)}") {
            try {
                nextSegment = buildNextSegment()
                log("Next segment prepared: ${nextSegment?.hash?.toHexString()}")
            } catch (e: Exception) {
                log("Error preparing next segment: ${e.message}")
                // Clearing the flag lets awaitNextSegment stop waiting at once.
                preparingNextSegment = false
            }
        }
    }

    /**
     * Upper bound on how long [validateProof] waits for a background
     * [prepareNextSegment] to finish. Preparation starts at advertise time and
     * is a bz2 + encrypt of at most MAX_EFFICIENT_SIZE bytes, so it is normally
     * long done when the proof arrives; the bound only matters if the
     * preparation thread is starved or dies, and then the transfer is
     * cancelled rather than the ingest thread stalled forever.
     */
    private val nextSegmentWaitMs: Long = 15_000

    /**
     * Return the next segment, building it synchronously if nobody has started
     * to (Resource.py:820-823 does the same), or waiting a bounded time for an
     * in-flight [prepareNextSegment]. Returns null if no segment could be built.
     */
    private fun awaitNextSegment(): Resource? {
        nextSegment?.let { return it }
        if (!preparingNextSegment) {
            log("Next segment preparation not started yet, preparing now")
            return try {
                buildNextSegment().also { nextSegment = it }
            } catch (e: Exception) {
                log("Error preparing next segment: ${e.message}")
                null
            }
        }
        val deadline = clock() + nextSegmentWaitMs
        while (nextSegment == null && preparingNextSegment && clock() < deadline) {
            try {
                Thread.sleep(50)
            } catch (e: InterruptedException) {
                Thread.currentThread().interrupt()
                break
            }
        }
        return nextSegment
    }

    /**
     * Read [maxLen] bytes of the shared transfer source starting at [start],
     * clamped to the source length — the port's equivalent of python's
     * `data.seek(seek_position); data.read(segment_read_size)` on the tempfile
     * (Resource.py:320-321).
     */
    private fun readSegmentRange(start: Long, maxLen: Int): ByteArray {
        segmentSource?.let { source ->
            val from = min(start, source.size.toLong()).toInt()
            val to = min(from.toLong() + maxLen, source.size.toLong()).toInt()
            return source.copyOfRange(from, to)
        }
        inputFile?.let { file ->
            val from = min(start, file.length())
            val readSize = min(maxLen.toLong(), file.length() - from).toInt()
            file.seek(from)
            return ByteArray(readSize).also { file.readFully(it) }
        }
        throw IllegalStateException("No segment source for multi-segment resource")
    }

    /**
     * Build the Resource for segment [segmentIndex]+1 from the shared source.
     * Mirrors python `Resource.__prepare_next_segment` + the segment branch of
     * `Resource.__init__` (Resource.py:306-322, 779-792): seek_index =
     * next_index - 1, first_read_size = MAX_EFFICIENT_SIZE - metadata_size,
     * seek_position = first_read_size + (seek_index - 1) * MAX_EFFICIENT_SIZE,
     * read MAX_EFFICIENT_SIZE bytes. Later segments carry no metadata block
     * but keep has_metadata set (sent_metadata_size > 0, Resource.py:270-271),
     * inherit original_hash, request_id, is_response and the auto-compress
     * option, and share the callbacks.
     */
    private fun buildNextSegment(): Resource {
        val nextIndex = segmentIndex + 1
        val firstReadSize = max(0, ResourceConstants.MAX_EFFICIENT_SIZE - segmentMetadataSize)
        val seekPosition = firstReadSize.toLong() +
            (nextIndex - 2).toLong() * ResourceConstants.MAX_EFFICIENT_SIZE
        val segmentData = readSegmentRange(seekPosition, ResourceConstants.MAX_EFFICIENT_SIZE)

        val parent = this
        return Resource(link, initiator = true).apply {
            callbacks.completed = parent.callbacks.completed
            callbacks.progress = parent.callbacks.progress
            callbacks.failed = parent.callbacks.failed

            requestId = parent.requestId
            isResponse = parent.isResponse
            hasMetadata = parent.hasMetadata
            segmentSource = parent.segmentSource
            inputFile = parent.inputFile
            segmentMetadataSize = parent.segmentMetadataSize
            autoCompressOption = parent.autoCompressOption

            totalSize = parent.totalSize
            totalSegments = parent.totalSegments
            segmentIndex = nextIndex
            split = true

            initializeSegmentPayload(segmentData, parent.autoCompressOption)

            // initializeSegmentPayload sets originalHash = hash; every segment
            // of one transfer advertises the FIRST segment's hash as `o`.
            originalHash = parent.originalHash
        }
    }

    /**
     * Assemble received parts into final data.
     * Matches Python RNS Resource.assemble() protocol.
     */
    private fun assemble() {
        if (status != ResourceConstants.TRANSFERRING) return

        status = ResourceConstants.ASSEMBLING
        log("Assembling resource ${hash.toHexString()}")

        try {
            // Combine all parts (encrypted stream)
            val output = ByteArrayOutputStream()
            for (part in parts) {
                if (part == null) {
                    // Mirrors python `Resource.assemble` (Resource.py:676): a None
                    // part makes `b"".join(self.parts)` raise, landing in the
                    // except branch that sets CORRUPT (Resource.py:721).
                    markCorrupt("Assembly failed: missing parts")
                    return
                }
                output.write(part)
            }

            val encryptedStream = output.toByteArray()

            // Decrypt the stream if encrypted. A failed Token authentication is an
            // integrity failure: mirrors python where link.decrypt raising lands
            // in assemble's except->CORRUPT branch (Resource.py:715/721), NOT a
            // clean FAILED. A corrupted-in-flight part typically breaks the
            // Token HMAC, so this is the path the corrupt-assembled injector hits.
            var decryptedData = if (encrypted) {
                link.decrypt(encryptedStream) ?: run {
                    markCorrupt("Assembly failed: decryption/authentication error")
                    return
                }
            } else {
                encryptedStream
            }

            // Strip off the random prefix (first RANDOM_HASH_SIZE bytes)
            if (decryptedData.size < ResourceConstants.RANDOM_HASH_SIZE) {
                markCorrupt("Assembly failed: data too short after decryption")
                return
            }
            decryptedData = decryptedData.copyOfRange(ResourceConstants.RANDOM_HASH_SIZE, decryptedData.size)

            // Decompress if needed, bounded by maxDecompressedSize. Mirrors python
            // `Resource.assemble` (Resource.py:685-690):
            //   self.data = decompressor.decompress(data, max_length=self.max_decompressed_size)
            //   if not decompressor.eof: self.status = CORRUPT; self.cancel(); return
            // A bz2 stream that inflates past the bound is a decompression bomb;
            // the receiver marks the transfer CORRUPT rather than exhausting memory.
            var assembled = if (compressed) {
                decompressBounded(decryptedData, maxDecompressedSize) ?: run {
                    markCorrupt("Decompressed resource exceeded maximum decompressed size")
                    // Python's cancel() on a CORRUPT resource rejects the
                    // advertisement (RESOURCE_RCL) and tears the link down
                    // (Resource.py:1096-1099). The port's cancel() is a no-op
                    // once status >= COMPLETE, so without this the peer could
                    // feed an unbounded sequence of 64 MiB inflations over one
                    // link; the hash-mismatch CORRUPT path below stays as it is
                    // because python does not tear down there.
                    rejectAndTeardownLink()
                    return
                }
            } else {
                decryptedData
            }

            // Verify hash matches
            val calculatedHash = Hashes.fullHash(assembled + randomHash)
            if (!calculatedHash.contentEquals(hash)) {
                markCorrupt("Assembly failed: hash mismatch")
                return
            }

            // Store the full assembled data (with metadata) for proof calculation
            // This matches Python where self.data in prove() includes metadata
            val dataForProof = assembled

            // Strip metadata if present, but ONLY for segment 1. Mirrors python
            // `Resource.assemble` (Resource.py:697):
            //   if self.has_metadata and self.segment_index == 1:
            // Continuation segments (segment_index > 1) carry no metadata block in
            // their content (python writes the metadata file once, from segment 1,
            // and each later segment's assembled stream is raw data), so stripping
            // on them would eat real payload bytes. The block is [3-byte BE
            // len(packed)] + umsgpack.packb(metadata) (Resource.py:266/696-704);
            // recover the raw metadata by msgpack-unpacking the packed slice.
            if (hasMetadata && segmentIndex == 1 && assembled.size > 3) {
                val metaSize = ((assembled[0].toInt() and 0xFF) shl 16) or
                              ((assembled[1].toInt() and 0xFF) shl 8) or
                              (assembled[2].toInt() and 0xFF)
                if (metaSize > 0 && metaSize + 3 <= assembled.size) {
                    val packedMetadata = assembled.copyOfRange(3, 3 + metaSize)
                    metadata = runCatching { msgpackUnpackBinary(packedMetadata) }.getOrNull() ?: packedMetadata
                    assembled = assembled.copyOfRange(3 + metaSize, assembled.size)
                }
            }

            // uncompressedData is THIS segment's data including its metadata block, which
            // is what prove() hashes — python proves per segment the same way.
            uncompressedData = dataForProof

            // Decide THIS segment's delivered payload before anything observes the
            // resource. resourceConcluded consumers read `data` synchronously (the
            // conformance bridge does exactly that), so assembledData must be final
            // before the conclusion fires.
            val isFinalSegment = !split || totalSegments <= 1 || segmentIndex >= totalSegments
            if (!split || totalSegments <= 1) {
                assembledData = assembled
            } else {
                // Split transfer: append to this LINK's accumulation keyed on originalHash,
                // which python keys its storagepath by (Resource.py:200, 722-723). Every
                // segment advertises the first segment's hash as `o` (Resource.py:450-453,
                // 1297). The accumulation is bounded three ways python's disk file is not
                // (see ResourceConstants.SEGMENT_ACCUMULATOR_*): it is released with the
                // link, it expires idle, and it may not exceed a per-transfer or per-link
                // ceiling — the alternative was heap retained until the process died.
                val accumulators = link.segmentAccumulators
                val now = clock()
                accumulators.entries.removeIf { now - it.value.lastProgressAt > ResourceConstants.SEGMENT_ACCUMULATOR_MAX_IDLE_MS }
                val accKey = ByteArrayKey(originalHash)
                val acc = accumulators.computeIfAbsent(accKey) { SegmentAccumulator(totalSegments).also { it.lastProgressAt = now } }
                synchronized(acc) {
                    // The reference sender advertises a monotonic `i` and a constant `l`
                    // per transfer (Resource.py:1297); anything else is not a transfer we
                    // can reassemble, and a sender doing it on purpose is paying 4 KB per
                    // 64 MiB of our heap. Refuse it as corrupt rather than append.
                    if (totalSegments != acc.expectedSegments || segmentIndex != acc.nextIndex) {
                        accumulators.remove(accKey)
                        markCorrupt(
                            "Split transfer segment out of sequence: got $segmentIndex/$totalSegments, " +
                                "expected ${acc.nextIndex}/${acc.expectedSegments}",
                        )
                        return
                    }
                    val transferTotal = acc.buffer.size().toLong() + assembled.size
                    val linkTotal = accumulators.values.sumOf { it.buffer.size().toLong() } + assembled.size
                    if (transferTotal > ResourceConstants.MAX_ACCUMULATED_TRANSFER_SIZE ||
                        linkTotal > ResourceConstants.MAX_ACCUMULATED_LINK_SIZE
                    ) {
                        // Same response as a decompression bomb (above): the peer is asking
                        // for more memory than this receiver will ever hold for it.
                        accumulators.remove(accKey)
                        markCorrupt("Split transfer exceeded the receive-side accumulation bound")
                        rejectAndTeardownLink()
                        return
                    }
                    if (segmentIndex == 1) acc.metadata = metadata
                    acc.buffer.write(assembled)
                    acc.nextIndex = segmentIndex + 1
                    acc.lastProgressAt = now
                    if (isFinalSegment) {
                        assembledData = acc.buffer.toByteArray()
                        metadata = acc.metadata
                        accumulators.remove(accKey)
                    } else {
                        // Not deliverable yet. Python simply has not written the caller's
                        // `self.data` at this point either (Resource.py:751).
                        assembledData = null
                    }
                }
            }

            status = ResourceConstants.COMPLETE
            stopWatchdog()
            // Link-level bookkeeping for every segment; the app-visible callback only for
            // the last one, as python (Resource.py:738-751). Firing it per segment handed
            // consumers a COMPLETE resource with `data == null`.
            link.resourceConcluded(this, notifyCallback = isFinalSegment)

            if (isFinalSegment) {
                val delivered = assembledData?.size ?: 0
                if (split && totalSegments > 1) {
                    log(
                        "Resource ${originalHash.toHexString()} reassembled from " +
                            "$totalSegments segments: $delivered bytes",
                    )
                } else {
                    log("Resource ${hash.toHexString()} assembled: $delivered bytes")
                }
                prove()
                callbacks.completed?.invoke(this)
            } else {
                // Python logs this and waits for the next segment's advertisement
                // (Resource.py:762). The proof still goes out per segment — it is what
                // makes the sender advertise the next one.
                log(
                    "Resource segment $segmentIndex of $totalSegments received " +
                        "(${assembled.size} bytes), waiting for the next segment",
                )
                prove()
            }

        } catch (e: Exception) {
            // Mirrors python `Resource.assemble`'s except branch (Resource.py:
            // 719-721): any error during reassembly marks the transfer CORRUPT,
            // not FAILED.
            markCorrupt("Assembly error: ${e.message}")
        }
    }

    /**
     * Mark this inbound transfer CORRUPT and conclude it on the link, mirroring
     * python `Resource.assemble`'s CORRUPT paths (Resource.py:689/715/721) which
     * set `status = CORRUPT` and fall through to `link.resource_concluded(self)`.
     * No proof is sent on a CORRUPT verdict.
     */
    private fun markCorrupt(reason: String) {
        // A corrupt segment poisons the whole split transfer: drop the partial
        // accumulation so a later, unrelated transfer cannot inherit these bytes.
        dropSegmentAccumulator()
        status = ResourceConstants.CORRUPT
        log(reason)
        stopWatchdog()
        link.resourceConcluded(this)
        callbacks.failed?.invoke(this)
    }

    /**
     * Mirror of python `Resource.cancel`'s CORRUPT branch (Resource.py:1096-1099):
     * `self.reject(self.advertisement_packet)` sends a RESOURCE_RCL carrying the
     * advertised resource hash (`reject`, Resource.py:156-162, packs `adv.h`
     * as a link packet), then `self.link.teardown()`. Used only on the
     * decompression-bomb verdict; markCorrupt has already concluded the
     * resource on the link.
     */
    private fun rejectAndTeardownLink() {
        try {
            val rejectPacket = Packet.createRaw(
                destinationHash = link.linkId,
                data = link.encrypt(hash),
                packetType = PacketType.DATA,
                destinationType = DestinationType.LINK,
                context = PacketContext.RESOURCE_RCL,
                mtu = link.mtu,
            )
            rejectPacket.send()
        } catch (e: Exception) {
            log("Could not send resource reject packet: ${e.message}")
        }
        try {
            link.teardown()
        } catch (e: Exception) {
            log("Error tearing down link after rejected resource: ${e.message}")
        }
    }

    /**
     * Cancel this resource transfer.
     *
     * Mirrors python `RNS.Resource.cancel` (Resource.py:1079-1108): set
     * `status = FAILED`, remove from the link's incoming/outgoing list
     * via `link.resourceConcluded`, and notify any registered failure
     * callback. Without the `callbacks.failed?.invoke` fire here, the
     * watchdog timeout path would silently drop the registration but
     * leave the message-level state stuck at SENDING/TRANSFERRING.
     * Without `link.resourceConcluded`, the hash would remain in
     * `incomingResources` for the lifetime of the link — every
     * subsequent retransmit of the same `RESOURCE_ADV` would be dropped
     * by the dedup guard inside `Resource.accept`, removing the
     * recovery path that existed pre-dedup.
     */
    /**
     * Packet hashes of the part requests already served for this resource (python
     * `Resource.req_hashlist`, `Resource.py:380`). Held for the life of the resource
     * object, as in the reference.
     */
    private val servedRequestHashes = java.util.Collections.newSetFromMap(
        java.util.concurrent.ConcurrentHashMap<ByteArrayKey, Boolean>(),
    )

    /**
     * Record a request packet as served, returning false if it was already seen.
     *
     * The duplicate is dropped rather than answered: the peer asks for parts by index, so
     * re-serving one request re-sends parts it has already taken and desynchronises the
     * window it uses to pick the next request.
     */
    fun admitRequestPacket(packetHash: ByteArray): Boolean =
        servedRequestHashes.add(packetHash.toKey())

    /** Number of distinct request packets served, for the conformance bridge. */
    fun servedRequestCountForTest(): Int = servedRequestHashes.size

    /**
     * The receiver refused this resource: mark it REJECTED (python `Resource._rejected`,
     * `Resource.py:1125-1136`).
     *
     * Distinct from [cancel], which reports FAILED. The difference is the whole point of
     * the RESOURCE_RCL packet: FAILED means the transfer broke — a timeout, a lost link, a
     * corrupt part — and is worth retrying, whereas REJECTED means the peer looked at the
     * advertisement and said no, and retrying will get the same answer. An application
     * that cannot tell them apart retries into a refusal forever.
     *
     * Only the initiator can be rejected, and only before the transfer concluded.
     */
    fun rejected() {
        val transitioned = synchronized(this) {
            if (status >= ResourceConstants.COMPLETE || !initiator) {
                false
            } else {
                status = ResourceConstants.REJECTED
                stopWatchdog()
                true
            }
        }
        if (!transitioned) return
        dropSegmentAccumulator()
        link.resourceConcluded(this)
        try {
            callbacks.failed?.invoke(this)
        } catch (e: Exception) {
            log("Error in resource reject callback: ${e.message}")
        }
    }

    /** Drop this transfer's partial accumulation — completion, corruption or cancellation. */
    private fun dropSegmentAccumulator() {
        if (originalHash.isNotEmpty()) link.segmentAccumulators.remove(ByteArrayKey(originalHash))
    }

    fun cancel() {
        // Abandoned split transfer: release any partially accumulated segments.
        dropSegmentAccumulator()
        // Idempotency guard. Mirrors python `Resource.py:1090`'s
        // `elif self.status < Resource.COMPLETE:` check — once a resource
        // has reached a terminal state (COMPLETE / FAILED / CORRUPT,
        // status >= COMPLETE = 0x06), a second cancel() is a no-op.
        // Necessary now that cancel() fires `callbacks.failed?.invoke`:
        // without this guard, a double-cancel from application code +
        // watchdog timeout would deliver the failed callback twice.
        val transitionedToFailed = synchronized(this) {
            if (status >= ResourceConstants.COMPLETE) {
                false
            } else {
                // Publish the terminal status while holding the same monitor used
                // by startWatchdog(). Python likewise sets FAILED before stopping
                // its watchdog. This closes the stop-then-status gap where another
                // thread could otherwise install a fresh watchdog on a canceled
                // Resource.
                status = ResourceConstants.FAILED
                cancelTransitionHookForTest?.invoke()
                stopWatchdog()
                true
            }
        }
        if (!transitionedToFailed) return
        // python Resource.py:1087-1094 — when the INITIATOR cancels a still-ACTIVE
        // transfer it sends a RESOURCE_ICL packet carrying the resource hash so the
        // receiver tears its inbound resource down too. Without this the receiver's
        // inbound Resource is never told and lingers in TRANSFERRING. The receiver
        // (processResourceIcl) decrypts the data and reads the first 16 bytes as the
        // resource hash, so encrypt the hash to the link exactly like advertise().
        if (initiator && link.status == LinkConstants.ACTIVE) {
            try {
                val cancelPacket =
                    Packet.createRaw(
                        destinationHash = link.linkId,
                        data = link.encrypt(hash),
                        packetType = PacketType.DATA,
                        destinationType = DestinationType.LINK,
                        context = PacketContext.RESOURCE_ICL,
                        mtu = link.mtu,
                    )
                cancelPacket.send()
            } catch (e: Exception) {
                log("Could not send resource cancel packet: ${e.message}")
            }
        }
        link.resourceConcluded(this)
        callbacks.failed?.invoke(this)
        log("Resource ${hash.toHexString()} cancelled")
    }

    /**
     * Get the received/assembled data (without metadata).
     */
    val data: ByteArray?
        get() = assembledData

    /**
     * Get extracted metadata bytes, if present.
     */
    val metadataBytes: ByteArray?
        get() = metadata

    /**
     * Get transfer progress (0.0 to 1.0).
     */
    val progress: Float
        get() = when {
            parts.isEmpty() -> 0f
            // Sender (initiator): fraction of parts transmitted — matches Python
            // get_progress(), which sets processed_parts = sent_parts for the initiator.
            initiator -> sentParts.toFloat() / parts.size
            // Receiver: fraction of parts received.
            else -> receivedCount.toFloat() / parts.size
        }

    /**
     * Transfer progress across ALL segments (0.0 to 1.0).
     *
     * [progress] is per-segment: it is `receivedCount / parts.size`, which runs
     * 0..1 once for EACH segment. A 37 MB payload arrives as 36 segments, so a
     * bar bound to [progress] sweeps full thirty-six times and tells the
     * operator nothing about the transfer. Segments are advertised with a
     * monotonic `i` and a constant `l` (Resource.py:1297), so the completed
     * fraction is exact rather than estimated.
     */
    val overallProgress: Float
        get() {
            val total = totalSegments
            if (total <= 1) return progress
            val done = (segmentIndex - 1).coerceAtLeast(0)
            return ((done + progress) / total).coerceIn(0f, 1f)
        }

    /**
     * Update hashmap from received data.
     */
    private fun updateHashmap(startIndex: Int, hashmapData: ByteArray) {
        val hashLen = ResourceConstants.MAPHASH_LEN
        var mapIndex = startIndex
        var offset = 0

        while (offset + hashLen <= hashmapData.size && mapIndex < hashmap.size) {
            hashmap[mapIndex] = hashmapData.copyOfRange(offset, offset + hashLen)
            mapIndex++
            offset += hashLen
        }

        hashmapHeight = mapIndex
    }

    /**
     * Calculate a short hash for a part.
     * Matches Python: RNS.Identity.full_hash(data+self.random_hash)[:MAPHASH_LEN]
     */
    private fun getMapHash(data: ByteArray): ByteArray {
        val real = Hashes.fullHash(data + randomHash).copyOf(ResourceConstants.MAPHASH_LEN)
        return mapHashInterceptorForTest?.invoke(this, real) ?: real
    }

    /**
     * Compress data using BZ2 (matches Python RNS).
     */
    private fun compress(data: ByteArray): ByteArray {
        val output = ByteArrayOutputStream()
        BZip2CompressorOutputStream(output).use { bz2 ->
            bz2.write(data)
        }
        return output.toByteArray()
    }

    /**
     * Decompress BZ2 data (matches Python RNS).
     */
    private fun decompress(data: ByteArray): ByteArray {
        val input = ByteArrayInputStream(data)
        val output = ByteArrayOutputStream()
        BZip2CompressorInputStream(input).use { bz2 ->
            val buffer = ByteArray(1024)
            var len: Int
            while (bz2.read(buffer).also { len = it } != -1) {
                output.write(buffer, 0, len)
            }
        }
        return output.toByteArray()
    }

    /**
     * Bounded BZ2 decompression. Returns null if the decompressed output would
     * exceed [maxLen] bytes — the decompression-bomb guard. Mirrors python
     * `BZ2Decompressor.decompress(data, max_length=self.max_decompressed_size)`
     * + the `if not decompressor.eof` over-bound check (Resource.py:687-690):
     * a stream that has not reached EOF by the bound is a bomb and is rejected.
     */
    private fun decompressBounded(data: ByteArray, maxLen: Int): ByteArray? {
        val input = ByteArrayInputStream(data)
        val output = ByteArrayOutputStream()
        BZip2CompressorInputStream(input).use { bz2 ->
            val buffer = ByteArray(8192)
            var total = 0L
            var len: Int
            while (bz2.read(buffer).also { len = it } != -1) {
                total += len
                if (total > maxLen) {
                    return null
                }
                output.write(buffer, 0, len)
            }
        }
        return output.toByteArray()
    }

    /**
     * MessagePack-pack a binary value (msgpack `bin` format), mirroring python
     * `umsgpack.packb(metadata)` for a `bytes` payload (Resource.py:261).
     */
    private fun msgpackPackBinary(data: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        val packer = org.msgpack.core.MessagePack.newDefaultPacker(out)
        packer.packBinaryHeader(data.size)
        packer.writePayload(data)
        packer.close()
        return out.toByteArray()
    }

    /**
     * MessagePack-unpack a single binary value, the inverse of
     * [msgpackPackBinary] — mirrors python `umsgpack.unpackb(packed_metadata)`.
     */
    private fun msgpackUnpackBinary(data: ByteArray): ByteArray {
        val unpacker = org.msgpack.core.MessagePack.newDefaultUnpacker(data)
        val len = unpacker.unpackBinaryHeader()
        // Same allocate-before-read hazard as the advertisement fields:
        // the metadata block is attacker-supplied, so refuse a declared length
        // the block cannot back instead of letting readPayload allocate it.
        if (len < 0 || len > data.size - unpacker.totalReadBytes) {
            throw IllegalArgumentException("Declared metadata length $len exceeds block of ${data.size} bytes")
        }
        val payload = unpacker.readPayload(len)
        unpacker.close()
        return payload
    }

    /**
     * Start watchdog thread for timeout detection.
     */
    @Synchronized
    private fun startWatchdog() {
        // Test-only suppression (see companion watchdogDisabledForTest): the
        // reference harness disables the watchdog around _build_resource_receiver
        // so an inbound Resource can be inspected synchronously without a
        // timeout-retry cancelling it.
        if (watchdogDisabledForTest) return
        if (watchdogActive) return
        if (status >= ResourceConstants.ASSEMBLING) return

        watchdogActive = true
        val newThread = thread(
            start = false,
            isDaemon = true,
            name = "resource-watchdog-${hash.toHexString().take(8)}",
        ) {
            watchdogJob()
        }
        watchdogThread = newThread
        newThread.start()
    }

    /**
     * Stop the watchdog thread.
     *
     * Skips the `interrupt()` call when invoked from the watchdog thread
     * itself (via `cancel()`'s call from `watchdogJob`'s retry-exhausted
     * branch). Setting the interrupt flag on the current thread would
     * propagate into any subsequent callback I/O — `callbacks.failed`
     * runs on this same thread, and a TCP send from inside the failed
     * callback uses `ReentrantLock.lockInterruptibly()` which checks
     * the flag on entry and immediately throws, silently aborting the
     * send. Python's watchdog uses a `__watchdog_job_id` flag check
     * rather than thread interruption (Resource.py:560-670), so the
     * equivalent self-targeting issue doesn't exist there.
     */
    @Synchronized
    private fun stopWatchdog() {
        watchdogActive = false
        val thread = watchdogThread
        if (thread != null && thread !== Thread.currentThread()) {
            thread.interrupt()
        }
        watchdogThread = null
    }

    /**
     * Watchdog job for timeout handling.
     */
    private fun watchdogJob() {
        try {
            while (watchdogActive && status < ResourceConstants.ASSEMBLING) {
                try {
                    val sleepMs = watchdogPass(clock())
                    if (!watchdogActive || status >= ResourceConstants.ASSEMBLING) break
                    Thread.sleep(minOf(sleepMs, ResourceConstants.WATCHDOG_MAX_SLEEP * 1000).coerceAtLeast(1))
                } catch (e: InterruptedException) {
                    break
                } catch (e: Exception) {
                    log("Watchdog error: ${e.message}")
                }
            }
        } finally {
            synchronized(this) {
                if (watchdogThread === Thread.currentThread()) {
                    watchdogActive = false
                    watchdogThread = null
                }
            }
        }
    }

    /** python `ensure_link` (Resource.py:529-535): a transfer on a link that is not ACTIVE is cancelled. */
    private fun ensureLink(): Boolean {
        if (link.status != network.reticulum.link.LinkConstants.ACTIVE) {
            log("Invalid link state for $this, aborting transfer")
            try {
                cancel()
            } catch (e: Exception) {
                log("Error while cancelling resource on link-state abort: ${e.message}")
            }
            return false
        }
        return true
    }

    /**
     * One watchdog evaluation at [now], python `__watchdog_job`'s loop body
     * (Resource.py:583-676). Returns the wait until the next evaluation in
     * milliseconds; every branch that acts returns 1 so the loop re-evaluates at once.
     *
     * Every wait is the reference's: ADVERTISED waits the resource timeout plus the
     * processing grace and re-advertises MAX_ADV_RETRIES times; a receiving transfer
     * waits a rate-derived time of flight for the outstanding parts plus the hashmap
     * allowance, the retry grace and a half second per retry used, shrinking its
     * window on each retry; a sender waiting for part requests holds for
     * rtt × factor × MAX_RETRIES plus the sender grace plus the summed retry delays;
     * a sender awaiting proof re-queries the network cache three times, rtt × 3 plus
     * the sender grace apart. Before this, all of it was one idle timer of
     * rtt × 4.
     */
    internal fun watchdogPass(now: Long): Long {
        var sleepMs: Long? = null
        val rttMs = rtt ?: link.rtt ?: 0L
        when {
            status == ResourceConstants.ADVERTISED -> {
                sleepMs = (advSent + timeoutMs + PROCESSING_GRACE_MS) - now
                if (sleepMs < 0) {
                    if (retriesLeft <= 0) {
                        log("Resource transfer timeout after sending advertisement")
                        cancel()
                        sleepMs = 1
                    } else {
                        try {
                            log("No part requests received, retrying resource advertisement...")
                            retriesLeft -= 1
                            if (!ensureLink()) return 1
                            sendAdvertisementPacket()
                            sleepMs = 1
                        } catch (e: Exception) {
                            log("Could not resend advertisement packet, cancelling resource. The contained exception was: ${e.message}")
                            cancel()
                            sleepMs = 1
                        }
                    }
                }
            }

            status == ResourceConstants.TRANSFERRING -> {
                if (!initiator) {
                    val retriesUsed = ResourceConstants.MAX_RETRIES - retriesLeft
                    val extraWaitMs = retriesUsed * PER_RETRY_DELAY_MS
                    updateEifr()
                    val rateBitsPerS = if (eifr > 0.0) eifr else 1.0
                    val expectedHmuWaitMs =
                        if (waitingForHmu || outstandingParts == 0) (sdu * 8 * ResourceConstants.HMU_WAIT_FACTOR) / rateBitsPerS * 1000.0 else 0.0
                    val expectedTofMs = (outstandingParts.toDouble() * sdu * 8) / rateBitsPerS * 1000.0
                    val waitMs =
                        if (reqRespRttRate != 0.0) {
                            partTimeoutFactor * expectedTofMs + expectedHmuWaitMs + RETRY_GRACE_MS + extraWaitMs
                        } else {
                            // python Resource.py:619 uses (3 * sdu) / eifr here, without the
                            // factor of eight; mirrored as written.
                            partTimeoutFactor * ((3.0 * sdu) / rateBitsPerS * 1000.0) + RETRY_GRACE_MS + extraWaitMs
                        }
                    sleepMs = (lastActivity + waitMs.toLong()) - now
                    if (sleepMs < 0) {
                        if (retriesLeft > 0) {
                            log("Timed out waiting for $outstandingParts part(s), requesting retry on $this")
                            if (window > windowMin) {
                                window -= 1
                                if (windowMax > windowMin) {
                                    windowMax -= 1
                                    if ((windowMax - window) > (windowFlexibility - 1)) windowMax -= 1
                                }
                            }
                            sleepMs = 1
                            retriesLeft -= 1
                            waitingForHmu = false
                            requestNext()
                        } else {
                            cancel()
                            sleepMs = 1
                        }
                    }
                } else {
                    var maxExtraWaitMs = 0L
                    for (r in 0 until ResourceConstants.MAX_RETRIES) maxExtraWaitMs += (r + 1) * PER_RETRY_DELAY_MS
                    val maxWaitMs = rttMs * timeoutFactor * ResourceConstants.MAX_RETRIES + SENDER_GRACE_MS + maxExtraWaitMs
                    sleepMs = (lastActivity + maxWaitMs) - now
                    if (sleepMs < 0) {
                        log("Resource timed out waiting for part requests")
                        cancel()
                        sleepMs = 1
                    }
                }
            }

            status == ResourceConstants.AWAITING_PROOF -> {
                // Proof packets are far smaller than a request/response round trip.
                timeoutFactor = ResourceConstants.PROOF_TIMEOUT_FACTOR
                sleepMs = (lastPartSent + (rttMs * timeoutFactor + SENDER_GRACE_MS)) - now
                if (sleepMs < 0) {
                    if (retriesLeft <= 0) {
                        log("Resource timed out waiting for proof")
                        cancel()
                        sleepMs = 1
                    } else {
                        log("All parts sent, but no resource proof received, querying network cache...")
                        retriesLeft -= 1
                        val proof = expectedProof
                        if (proof != null) {
                            val expectedProofPacket =
                                Packet.createRaw(
                                    destinationHash = link.linkId,
                                    data = hash + proof,
                                    packetType = PacketType.PROOF,
                                    destinationType = DestinationType.LINK,
                                    context = PacketContext.RESOURCE_PRF,
                                    mtu = link.mtu,
                                )
                            expectedProofPacket.pack()
                            network.reticulum.transport.Transport.requestFromCache(expectedProofPacket.packetHash, link)
                        }
                        lastPartSent = now
                        sleepMs = 1
                    }
                }
            }

            status >= ResourceConstants.ASSEMBLING -> sleepMs = 1

            // The reference never runs the watchdog before ADVERTISED / TRANSFERRING; the
            // port may start it earlier on the receive side, so wait a tick rather than
            // treat the state as a timing error.
            else -> sleepMs = ResourceConstants.WATCHDOG_MAX_SLEEP * 1000
        }

        if (sleepMs == 0L) log("Warning! Resource watchdog sleep time of 0!")
        if (sleepMs == null || sleepMs < 0) {
            log("Timing error ($sleepMs/$status), cancelling resource transfer.")
            cancel()
            return 1
        }
        return sleepMs
    }

    // ===== Conformance test seams =====
    // (watchdog time constants, python seconds -> ms)
    // Each is a thin public wrapper over a private member or method. The
    // conformance-bridge is a separate gradle module and cannot see private/
    // internal state; these exist solely so the bridge can read back or drive
    // the Resource state machine the way the reference harness reads/drives the
    // python instance attributes directly. None changes protocol behaviour.

    /** private expectedProof — full_hash(data+hash) (Resource.kt:expectedProof). */
    fun expectedProofForTest(): ByteArray? = expectedProof

    /**
     * Drive the private awaitNextSegment() — builds (or waits, bounded,
     * for) the next segment of a split transfer exactly as validateProof does.
     * Null means no segment could be produced (the cancel path), never a hang.
     */
    fun awaitNextSegmentForTest(): Resource? = awaitNextSegment()

    /** RESOURCE_ADV packets emitted by this sender (initial + watchdog re-sends). */
    fun advSendCountForTest(): Int = advSendCount

    /** Drive one re-advertise the way the watchdog's ADVERTISED branch does. */
    fun resendAdvertisementForTest() = sendAdvertisementPacket()

    /** private per-part SDU captured at construction (Resource.py:338). */
    fun sduForTest(): Int = sdu

    /** private window / windowMin / windowMax (flow-control state). */
    fun windowForTest(): Int = window
    fun windowMinForTest(): Int = windowMin
    fun windowMaxForTest(): Int = windowMax

    /** private hashmapHeight — number of loaded hashmap slots. */
    fun hashmapHeightForTest(): Int = hashmapHeight

    /** private receivedCount — number of stored parts. */
    fun receivedCountForTest(): Int = receivedCount

    /** private consecutiveCompletedHeight — the in-order pointer. */
    fun consecutiveCompletedHeightForTest(): Int = consecutiveCompletedHeight

    /** private waitingForHmu flag. */
    fun waitingForHmuForTest(): Boolean = waitingForHmu

    /** private sentParts (sender). */
    fun sentPartsForTest(): Int = sentParts

    /** sorted copy of the private sentPartsSet (sender). */
    fun sentPartIndicesForTest(): List<Int> = sentPartsSet.toList().sorted()

    /** private receiverMinConsecutiveHeight (sender search-scope anchor). */
    fun receiverMinConsecutiveHeightForTest(): Int = receiverMinConsecutiveHeight

    /** copy of the parsed private hashmap[] array (preserves nulls). */
    fun hashmapEntriesForTest(): List<ByteArray?> = hashmap.toList()

    /** private maxDecompressedSize / autoCompressLimit (bomb-guard ceiling). */
    fun maxDecompressedSizeForTest(): Int = maxDecompressedSize
    fun autoCompressLimitForTest(): Int = autoCompressLimit
    /** Lower the per-resource decompression bound (listener bomb-guard hook). */
    @network.reticulum.RnsTestSeam
    fun setMaxDecompressedSizeForTest(value: Int) { maxDecompressedSize = value }

    /** Instrumentation counters (see the fields for what each event is). */
    fun proveCallCountForTest(): Int = proveCalls.get()
    fun lastRequestDataForTest(): ByteArray? = lastRequestData
    fun requestNextEmitCountForTest(): Int = requestNextEmitCount.get()
    fun hmuRequestsSentForTest(): Int = hmuRequestsSent.get()
    fun hashmapUpdatesReceivedForTest(): Int = hashmapUpdatesReceived.get()
    fun watchdogActiveForTest(): Boolean = watchdogActive

    // Seams for ResourceWatchdogTimingTest: drive one evaluation and set the stamps it reads.
    @network.reticulum.RnsTestSeam
    internal fun watchdogPassForTest(now: Long): Long = watchdogPass(now)
    internal fun retriesLeftForTest(): Int = retriesLeft
    @network.reticulum.RnsTestSeam
    internal fun setRetriesLeftForTest(value: Int) { retriesLeft = value }
    @network.reticulum.RnsTestSeam
    internal fun setStampsForTest(advSent: Long? = null, lastActivity: Long? = null, lastPartSent: Long? = null) {
        advSent?.let { this.advSent = it }
        lastActivity?.let { this.lastActivity = it }
        lastPartSent?.let { this.lastPartSent = it }
    }
    @network.reticulum.RnsTestSeam
    internal fun setRttForTest(value: Long?) { rtt = value }
    @network.reticulum.RnsTestSeam
    internal fun setOutstandingPartsForTest(value: Int) { outstandingParts = value }
    internal fun timeoutMsForTest(): Long = timeoutMs
    internal fun partTimeoutFactorForTest(): Int = partTimeoutFactor
    fun startWatchdogForTest() = startWatchdog()
    fun setCancelTransitionHookForTest(hook: (() -> Unit)?) {
        cancelTransitionHookForTest = hook
    }

    /** Drive the private assemble(). */
    fun assembleForTest() = assemble()

    /** Set parts[index] directly (parts has a private setter). */
    fun setPartForTest(index: Int, data: ByteArray) {
        parts[index] = data
    }

    /** Drive the private hashmapUpdate(segment, bytes). */
    fun hashmapUpdateForTest(segment: Int, bytes: ByteArray) = hashmapUpdate(segment, bytes)

    /** Drive the private requestNext(). */
    fun requestNextForTest() = requestNext()

    /** Suppress/restore receivePart's auto-follow-up requestNext during a feed. */
    fun setAutoRequestNextForTest(enabled: Boolean) { autoRequestNext = enabled }

    /** Prime the sender as if it had just advertised (status TRANSFERRING,
     *  adv_sent set) — mirrors the reference priming a sender before request().*/
    fun primeTransferringForTest() {
        status = ResourceConstants.TRANSFERRING
        advSent = clock()
    }

    /** Force the status field (e.g. AWAITING_PROOF for the control proof case). */
    fun setStatusForTest(newStatus: Int) {
        status = newStatus
    }

    override fun toString(): String {
        return "<Resource ${hash.toHexString().take(16)}/${link.linkId.toHexString().take(16)}>"
    }
}

/** python Resource.PROCESSING_GRACE / RETRY_GRACE_TIME / SENDER_GRACE_TIME / PER_RETRY_DELAY (seconds) in milliseconds. */
private val PROCESSING_GRACE_MS: Long = (ResourceConstants.PROCESSING_GRACE * 1000).toLong()
private val RETRY_GRACE_MS: Long = (ResourceConstants.RETRY_GRACE_TIME * 1000).toLong()
private val SENDER_GRACE_MS: Long = (ResourceConstants.SENDER_GRACE_TIME * 1000).toLong()
private val PER_RETRY_DELAY_MS: Long = (ResourceConstants.PER_RETRY_DELAY * 1000).toLong()
