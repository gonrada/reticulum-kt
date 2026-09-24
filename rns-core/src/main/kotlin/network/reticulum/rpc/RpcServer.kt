package network.reticulum.rpc

import network.reticulum.common.RnsConstants
import network.reticulum.common.RnsLog
import network.reticulum.config.InterfaceConfig
import network.reticulum.identity.Identity
import network.reticulum.link.RequestWire
import network.reticulum.transport.InterfaceRef
import network.reticulum.transport.Transport
import network.reticulum.transport.TransportConstants
import org.msgpack.core.MessagePack
import org.msgpack.value.Value
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketException
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicBoolean
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.concurrent.thread

/**
 * The shared-instance RPC endpoint python clients (`rnstatus`, `rnpath`, `rnsd`,
 * `RNS.Reticulum` attached to a shared instance) talk to: python `Reticulum.rpc_loop`
 * (`Reticulum.py:1276-1336`) behind a `multiprocessing.connection.Listener`.
 *
 * Transport: TCP on the instance control port. Handshake: the
 * `multiprocessing.connection` HMAC challenge in both directions (`#CHALLENGE#`,
 * `{sha256}` digest tag, `#WELCOME#`/`#FAILURE#`), keyed with
 * `full_hash(transport_identity.private_key)` unless `rpc_key` is configured. Frames:
 * 4-byte big-endian length prefix. Payloads: msgpack, one request per connection, as
 * `rpc_loop` reads `mp.unpackb(conn.recv_bytes())` and answers `mp.packb(response)`.
 *
 * Every request of RNS 1.5.2 is served: the `get` paths, the `drop` paths,
 * `blackhole_identity`, `unblackhole_identity`, `destination_data` and
 * `identity_data`. Where the kotlin transport keeps no counterpart (per-packet RSSI
 * caches, the profiler, announce-traffic sub-counters) the response carries python's
 * "unknown" value — `None` or `0` — rather than an invented figure.
 */
class RpcServer(
    private val port: Int = DEFAULT_PORT,
    private val authKey: ByteArray,
    private val bindAddress: String = "127.0.0.1",
    private val log: (String) -> Unit = { RnsLog.log(RnsLog.DEBUG, "RpcServer", it) },
) {
    companion object {
        const val DEFAULT_PORT = 37429
        private val CHALLENGE = "#CHALLENGE#".toByteArray()
        private val WELCOME = "#WELCOME#".toByteArray()
        private val FAILURE = "#FAILURE#".toByteArray()
        private const val MESSAGE_LENGTH = 20
        private const val MAX_REQUEST_BYTES = 1024 * 1024
        private const val MAX_HANDSHAKE_BYTES = 256
        private const val CLIENT_TIMEOUT_MS = 30_000

        /** Python `Reticulum.rpc_key` default: `full_hash(Transport.identity.get_private_key())`. */
        fun defaultAuthKey(transportIdentity: Identity): ByteArray? {
            val privateKey = transportIdentity.getPrivateKey() ?: return null
            return java.security.MessageDigest.getInstance("SHA-256").digest(privateKey)
        }
    }

    private var serverSocket: ServerSocket? = null
    private var acceptThread: Thread? = null
    private val running = AtomicBoolean(false)

    /** The port actually bound, once [start] has run (0 in the constructor binds an ephemeral port). */
    val boundPort: Int get() = serverSocket?.localPort ?: port

    fun start() {
        val socket = ServerSocket()
        socket.reuseAddress = true
        socket.bind(java.net.InetSocketAddress(InetAddress.getByName(bindAddress), port))
        serverSocket = socket
        running.set(true)
        acceptThread = thread(name = "RpcServer-accept", isDaemon = true) { acceptLoop() }
        log("RPC server listening on $bindAddress:${socket.localPort}")
    }

    fun stop() {
        running.set(false)
        try {
            serverSocket?.close()
        } catch (_: Exception) {
        }
        serverSocket = null
    }

    private fun acceptLoop() {
        while (running.get()) {
            try {
                val client = serverSocket?.accept() ?: break
                thread(name = "RpcServer-client", isDaemon = true) { handleClient(client) }
            } catch (e: SocketException) {
                if (running.get()) log("RPC accept error: ${e.message}")
                break
            } catch (e: Exception) {
                log("RPC accept error: ${e.message}")
            }
        }
    }

    /** One request per connection, as python's `rpc_loop` closes after answering. */
    private fun handleClient(client: Socket) {
        try {
            client.soTimeout = CLIENT_TIMEOUT_MS
            val input = DataInputStream(client.getInputStream())
            val output = DataOutputStream(client.getOutputStream())
            if (!authenticate(input, output)) {
                log("RPC client authentication failed")
                return
            }
            val request =
                try {
                    receiveRequest(input) ?: return
                } catch (e: StackOverflowError) {
                    // msgpack-core builds a value tree recursively; a request nested deeper than
                    // the stack is malformed, not fatal to the daemon.
                    log("Rejected an RPC request nested beyond the stack")
                    return
                }
            val response =
                try {
                    handleRequest(request)
                } catch (e: Exception) {
                    log("An error occurred while handling RPC call from local client: ${e.message}")
                    null
                }
            sendBytes(output, packResponse(response))
        } catch (e: Exception) {
            log("RPC client error: ${e.message}")
        } finally {
            try {
                client.close()
            } catch (_: Exception) {
            }
        }
    }

    // ===== multiprocessing.connection handshake =====

    private fun authenticate(
        input: DataInputStream,
        output: DataOutputStream,
    ): Boolean {
        return try {
            // deliver_challenge: our challenge, the client's HMAC
            val challenge = ByteArray(MESSAGE_LENGTH).also { SecureRandom().nextBytes(it) }
            val digestPrefix = "{sha256}".toByteArray()
            sendBytes(output, CHALLENGE + digestPrefix + challenge)
            val response = receiveBytes(input, MAX_HANDSHAKE_BYTES)
            if (response == null) {
                sendBytes(output, FAILURE)
                return false
            }
            val (digestName, responseMac) = parseResponse(response)
            val message = digestPrefix + challenge
            // `_verify_challenge` (connection.py:953-954): an untagged response is legacy MD5.
            val verifyAlgorithm = macAlgorithm(digestName.ifEmpty { "md5" })
            val verified =
                verifyAlgorithm != null &&
                    java.security.MessageDigest.isEqual(responseMac, hmac(verifyAlgorithm, message))
            if (!verified) {
                sendBytes(output, FAILURE)
                return false
            }
            sendBytes(output, WELCOME)
            // answer_challenge: the client's challenge, our HMAC
            val clientChallenge = receiveBytes(input, MAX_HANDSHAKE_BYTES)
            if (clientChallenge == null || !clientChallenge.startsWith(CHALLENGE)) return false
            val clientMessage = clientChallenge.copyOfRange(CHALLENGE.size, clientChallenge.size)
            val (clientDigest, _) = parseResponse(clientMessage)
            // `_create_response` (connection.py:925-939): a challenge carrying no digest tag
            // comes from a python that only knows HMAC-MD5 and compares the reply against a
            // bare MAC (`deliver_challenge`, connection.py:739-745 before the digest tags),
            // so the tag has to be left off.
            // A tagged challenge is answered with that same digest, over the whole message.
            val answerAlgorithm = macAlgorithm(clientDigest.ifEmpty { "md5" }) ?: return false
            val ourMac = hmac(answerAlgorithm, clientMessage)
            val tag = if (clientDigest.isEmpty()) ByteArray(0) else "{$clientDigest}".toByteArray()
            sendBytes(output, tag + ourMac)
            val result = receiveBytes(input, MAX_HANDSHAKE_BYTES)
            result != null && result.contentEquals(WELCOME)
        } catch (e: Exception) {
            log("Authentication error: ${e.message}")
            false
        }
    }

    private fun ByteArray.startsWith(prefix: ByteArray): Boolean = size >= prefix.size && copyOfRange(0, prefix.size).contentEquals(prefix)

    /** `{digestname}payload`, or a bare legacy MD5 (16) / challenge (20) payload. */
    private fun parseResponse(response: ByteArray): Pair<String, ByteArray> {
        if (response.size == 16 || response.size == 20) return "" to response
        if (response.isNotEmpty() && response[0] == '{'.code.toByte()) {
            val close = response.indexOf('}'.code.toByte())
            if (close in 1..19) return String(response, 1, close - 1) to response.copyOfRange(close + 1, response.size)
        }
        return "" to response
    }

    /** `_ALLOWED_DIGESTS` (connection.py:875-876) mapped to JCA names; null for anything else. */
    private fun macAlgorithm(digestName: String): String? =
        when (digestName) {
            "md5" -> "HmacMD5"
            "sha256" -> "HmacSHA256"
            "sha384" -> "HmacSHA384"
            "sha3_256" -> "HmacSHA3-256"
            "sha3_384" -> "HmacSHA3-384"
            else -> null
        }

    private fun hmac(
        algorithm: String,
        message: ByteArray,
    ): ByteArray {
        val mac = Mac.getInstance(algorithm)
        mac.init(SecretKeySpec(authKey, algorithm))
        return mac.doFinal(message)
    }

    private fun sendBytes(
        output: DataOutputStream,
        data: ByteArray,
    ) {
        output.writeInt(data.size)
        output.write(data)
        output.flush()
    }

    private fun receiveBytes(
        input: DataInputStream,
        maxSize: Int,
    ): ByteArray? {
        val size = input.readInt()
        if (size < 0 || size > maxSize) return null
        val data = ByteArray(size)
        input.readFully(data)
        return data
    }

    // ===== msgpack payloads =====

    private fun receiveRequest(input: DataInputStream): Map<String, Any?>? {
        val data = receiveBytes(input, MAX_REQUEST_BYTES) ?: return null
        MessagePack.newDefaultUnpacker(data).use { it.skipValue() }
        val value = MessagePack.newDefaultUnpacker(data).use { it.unpackValue() }
        if (!value.isMapValue) return null
        val map = LinkedHashMap<String, Any?>()
        for ((k, v) in value.asMapValue().map()) {
            val key = if (k.isStringValue) k.asStringValue().asString() else continue
            map[key] = toKotlin(v)
        }
        return map
    }

    private fun toKotlin(v: Value): Any? =
        when {
            v.isNilValue -> null
            v.isBooleanValue -> v.asBooleanValue().boolean
            v.isIntegerValue -> v.asIntegerValue().toLong()
            v.isFloatValue -> v.asFloatValue().toDouble()
            v.isStringValue -> v.asStringValue().asString()
            v.isBinaryValue -> v.asBinaryValue().asByteArray()
            v.isArrayValue -> v.asArrayValue().list().map { toKotlin(it) }
            v.isMapValue -> v.asMapValue().map().entries.associate { (mk, mv) -> toKotlin(mk) to toKotlin(mv) }
            else -> null
        }

    private fun packResponse(response: Any?): ByteArray {
        val packer = MessagePack.newDefaultBufferPacker()
        RequestWire.packValue(packer, response)
        val out = packer.toByteArray()
        packer.close()
        return out
    }

    // ===== python Reticulum.rpc_loop =====

    internal fun handleRequest(call: Map<String, Any?>): Any? {
        val hash = { key: String -> call[key] as? ByteArray }
        if ("get" in call) {
            return when (call["get"] as? String) {
                "path_table" -> getPathTable((call["max_hops"] as? Number)?.toInt())
                "interface_stats" -> getInterfaceStats()
                "rate_table" -> getRateTable()
                "next_hop_if_name" -> hash("destination_hash")?.let { getNextHopIfName(it) }
                "next_hop" -> hash("destination_hash")?.let { Transport.nextHop(it) }
                "first_hop_timeout" -> hash("destination_hash")?.let { Transport.firstHopTimeout(it) / 1000.0 }
                "lowest_interface_bitrate" -> Transport.lowestInterfaceBitrate()
                "medium_path_timeout" -> Transport.mediumPathTimeout() / 1000.0
                "link_count" -> Transport.linkCount()
                "active_link_count" -> Transport.activeLinkCount()
                "packet_rssi", "packet_snr", "packet_q" -> null // no per-packet phy cache in the kotlin transport
                "profiling_results" -> null
                "blackholed_identities" -> getBlackholedIdentities()
                "is_blackholed" -> hash("identity_hash")?.let { Transport.isBlackholed(it) } ?: false
                else -> null
            }
        }
        if ("drop" in call) {
            return when (call["drop"] as? String) {
                "path" -> hash("destination_hash")?.let { Transport.expirePath(it); true } ?: false
                "all_via" -> hash("destination_hash")?.let { dropAllVia(it) } ?: 0
                "announce_queues" -> {
                    Transport.dropAnnounceQueues()
                    true
                }
                else -> null
            }
        }
        if ("blackhole_identity" in call) {
            val identityHash = hash("blackhole_identity") ?: return false
            if (identityHash.size != RnsConstants.TRUNCATED_HASH_BYTES) return false
            val until = (call["until"] as? Number)?.toDouble()?.let { untilFromPython(it) }
            return Transport.blackholeIdentity(identityHash, until = until, reason = call["reason"] as? String)
        }
        if ("unblackhole_identity" in call) {
            val identityHash = hash("unblackhole_identity") ?: return false
            if (identityHash.size != RnsConstants.TRUNCATED_HASH_BYTES) return false
            return Transport.unblackholeIdentity(identityHash)
        }
        if ("destination_data" in call) {
            val destinationHash = hash("destination_hash") ?: return false
            return when (call["destination_data"] as? String) {
                "used" -> Identity.usedDestinationData(destinationHash)
                "retain" -> Identity.retainDestinationData(destinationHash)
                "unretain" -> Identity.unretainDestinationData(destinationHash)
                else -> null
            }
        }
        if ("identity_data" in call) {
            val identityHash = hash("identity_hash") ?: return false
            return when (call["identity_data"] as? String) {
                "retain" -> Identity.retainIdentity(identityHash)
                else -> null
            }
        }
        return null
    }

    /** Python blackhole `until` is a unix timestamp in seconds; the transport keeps milliseconds. */
    private fun untilFromPython(seconds: Double): Long = (seconds * 1000).toLong()

    private fun interfaceName(ref: InterfaceRef): String = ref.qualifiedName

    /** Python `get_interface_stats` (Reticulum.py:1399-1630). */
    internal fun getInterfaceStats(): Map<String, Any?> {
        val interfaces = mutableListOf<Map<String, Any?>>()
        for (iface in Transport.getInterfaces()) {
            val stats = LinkedHashMap<String, Any?>()
            stats["clients"] = null
            iface.parentInterface?.let {
                stats["parent_interface_name"] = interfaceName(it)
                stats["parent_interface_hash"] = it.hash
            }
            stats["bitrate"] = iface.bitrate
            stats["rxs"] = 0
            stats["txs"] = 0
            stats["arxs"] = 0
            stats["atxs"] = 0
            stats["prxs"] = 0
            stats["ptxs"] = 0
            if (iface.ifacSize > 0) {
                stats["ifac_signature"] = iface.ifacKey
                stats["ifac_size"] = iface.ifacSize
                stats["ifac_netname"] = iface.ifacNetname
            } else {
                stats["ifac_signature"] = null
                stats["ifac_size"] = null
                stats["ifac_netname"] = null
            }
            stats["autoconnect_source"] = null
            stats["name"] = interfaceName(iface)
            stats["short_name"] = iface.name
            stats["hash"] = iface.hash
            stats["type"] = iface.discoveryInterfaceType
            stats["mtu"] = iface.hwMtu
            stats["rxb"] = iface.rxBytes
            stats["txb"] = iface.txBytes
            for (key in listOf("arxb", "atxb", "arxc", "atxc", "prxb", "ptxb", "prxc", "ptxc", "txdrp", "txdrb", "txstalled", "txbuffered")) stats[key] = 0
            stats["incoming_announce_frequency"] = 0.0
            stats["outgoing_announce_frequency"] = 0.0
            stats["incoming_pr_frequency"] = 0.0
            stats["outgoing_pr_frequency"] = 0.0
            stats["announce_rate_target"] = iface.announceRateTarget
            stats["announce_rate_penalty"] = iface.announceRatePenalty
            stats["announce_rate_grace"] = iface.announceRateGrace
            stats["held_announces"] = 0
            stats["burst_active"] = false
            stats["burst_activated"] = 0
            stats["burst_count"] = 0
            stats["pr_burst_active"] = false
            stats["pr_burst_activated"] = 0
            stats["pr_burst_count"] = 0
            stats["status"] = iface.online
            stats["mode"] = InterfaceConfig.modeValue(iface.mode)
            stats["gravity"] = 0
            stats["announces_to_internal"] = iface.announcesToInternal
            stats["protocol_violations"] = iface.protocolViolations
            stats["ifac_violations"] = 0
            stats["packet_filter_hits"] = 0
            interfaces.add(stats)
        }
        val stats = LinkedHashMap<String, Any?>()
        stats["interfaces"] = interfaces
        stats["rxb"] = Transport.trafficRxBytes
        stats["txb"] = Transport.trafficTxBytes
        stats["rxs"] = Transport.speedRx
        stats["txs"] = Transport.speedTx
        for (key in listOf("arxb", "atxb", "arxs", "atxs", "arxf", "atxf", "prxb", "ptxb", "prxs", "ptxs", "prxf", "ptxf", "rxpps", "txpps")) stats[key] = 0
        for (key in listOf("rxqt", "rxqd", "rxqa", "rxqp", "rxqil", "rxqtd", "rxqdd", "rxqad", "rxqpd", "rxqild")) stats[key] = 0
        for (key in listOf("tqpressure", "dqpressure", "aqpressure", "pqpressure", "ilqpressure")) stats[key] = 0
        stats["txq"] = null
        if (Transport.transportEnabled) {
            stats["transport_id"] = Transport.identity?.hash
            stats["network_id"] = Transport.networkIdentity?.hash
            stats["transport_uptime"] = Transport.uptimeMs() / 1000.0
            stats["probe_responder"] = Transport.probeDestination?.hash
        }
        val runtime = Runtime.getRuntime()
        stats["rss"] = runtime.totalMemory() - runtime.freeMemory()
        return stats
    }

    /** Python `get_path_table` (Reticulum.py:1632-1650): timestamps in seconds, interface as its `str()`. */
    internal fun getPathTable(maxHops: Int?): List<Map<String, Any?>> {
        val byHash = Transport.getInterfaces().associateBy { it.hash.toList() }
        return Transport.pathTableSnapshot()
            .filter { (_, entry) -> maxHops == null || entry.hops <= maxHops }
            .map { (destHash, entry) ->
                mapOf(
                    "hash" to destHash,
                    "timestamp" to entry.timestamp / 1000.0,
                    "via" to entry.nextHop,
                    "hops" to entry.hops,
                    "expires" to entry.expires / 1000.0,
                    "interface" to (byHash[entry.receivingInterfaceHash.toList()]?.let { interfaceName(it) } ?: "None"),
                )
            }
    }

    /** Python `get_rate_table` (Reticulum.py:1652-1671), seconds. */
    internal fun getRateTable(): List<Map<String, Any?>> =
        Transport.announceRateSnapshot().map { (destHash, entry) ->
            mapOf(
                "hash" to destHash,
                "last" to entry.last / 1000.0,
                "rate_violations" to entry.rateViolations,
                "blocked_until" to entry.blockedUntil / 1000.0,
                "timestamps" to entry.timestamps.map { it / 1000.0 },
            )
        }

    private fun getNextHopIfName(destinationHash: ByteArray): String = Transport.nextHopInterface(destinationHash)?.let { interfaceName(it) } ?: "None"

    private fun dropAllVia(transportHash: ByteArray): Int {
        var dropped = 0
        for ((destHash, entry) in Transport.pathTableSnapshot()) {
            if (entry.nextHop.contentEquals(transportHash)) {
                Transport.expirePath(destHash)
                dropped++
            }
        }
        return dropped
    }

    /** Python `Transport.blackholed_identities`: `{hash: {"source", "until", "reason"}}`, `until` in seconds. */
    private fun getBlackholedIdentities(): Map<ByteArray, Map<String, Any?>> =
        Transport.blackholeListHandler().entries.associate { (key, entry) ->
            key.bytes to mapOf("source" to entry.source, "until" to entry.until?.let { it / 1000.0 }, "reason" to entry.reason)
        }
}
