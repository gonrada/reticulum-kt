package network.reticulum.transport

import network.reticulum.common.toKey
import network.reticulum.destination.Destination
import network.reticulum.common.DestinationDirection
import network.reticulum.common.DestinationType
import network.reticulum.destination.RequestPolicy
import network.reticulum.identity.Identity
import org.msgpack.core.MessagePack
import org.msgpack.value.Value
import org.msgpack.value.ValueFactory

/**
 * The transport instance's management destinations: the probe responder and the remote
 * management endpoint.
 *
 * These are what make a transport node *addressable* by the reference tooling. `rnprobe`
 * sends a packet to `rnstransport.probe` and times the proof that comes back; `rnstatus -R`
 * and `rnpath -R` open a link to `rnstransport.remote.management` and issue `/status` and
 * `/path` requests. Neither existed here, so a Kotlin node was invisible to both — it is
 * not a degraded answer, there is simply no destination at that address to answer.
 *
 * Both are gated off by default and registered from [Transport.start], mirroring
 * `Transport.py:367-373` (remote management) and `Transport.py:511-518` (probe).
 */
internal object TransportManagement {

    /**
     * Build the probe-responder destination (python `Transport.py:511-516`).
     *
     * It carries no request handlers and no packet callback: the whole mechanism is
     * `PROVE_ALL`, which makes the destination return a proof for any packet addressed to
     * it, and the prober times the round trip. `accepts_links(False)` keeps it from being
     * used as a link target — a probe is a single packet, and an open link endpoint here
     * would be an unauthenticated resource an unknown peer could hold.
     */
    fun createProbeDestination(identity: Identity): Destination =
        Destination.create(
            identity = identity,
            direction = DestinationDirection.IN,
            type = DestinationType.SINGLE,
            appName = TransportConstants.APP_NAME,
            aspects = arrayOf("probe"),
        ).apply {
            acceptLinkRequests = false
            setProofStrategy(Destination.PROVE_ALL)
        }

    /**
     * Build the remote-management destination and register its two request handlers
     * (python `Transport.py:367-373`).
     *
     * Both handlers are bound to `ALLOW_LIST` against [Transport.remoteManagementAllowed]
     * **by reference**, not a copy. The reference does the same, and it matters: the ACL is
     * populated from config after this destination is built, and again whenever
     * `remote_management_allowed` gains an entry, so a handler holding a snapshot would
     * enforce an empty list forever and lock out every legitimate operator.
     */
    fun createRemoteManagementDestination(identity: Identity): Destination =
        Destination.create(
            identity = identity,
            direction = DestinationDirection.IN,
            type = DestinationType.SINGLE,
            appName = TransportConstants.APP_NAME,
            aspects = arrayOf("remote", "management"),
        ).apply {
            registerRequestHandler(
                path = "/status",
                responseGenerator = ::remoteStatusHandler,
                allow = RequestPolicy.ALLOW_LIST,
                allowedList = Transport.remoteManagementAllowed,
            )
            registerRequestHandler(
                path = "/path",
                responseGenerator = ::remotePathHandler,
                allow = RequestPolicy.ALLOW_LIST,
                allowedList = Transport.remoteManagementAllowed,
            )
        }

    // ------------------------------------------------------------------------
    // Request handlers
    //
    // The reference hands the response generator a decoded python object and msgpacks
    // whatever it returns; ours receives and returns raw bytes, so each handler decodes its
    // own request and encodes its own response. The wire shape is the msgpack the reference
    // produces, since `rnstatus`/`rnpath` are the clients on the other end.
    // ------------------------------------------------------------------------

    /**
     * `/status` — python `Transport.remote_status_handler` (`Transport.py:3325-3343`).
     *
     * Request is a msgpack list: `[include_link_count, include_profiling]`. The response is a
     * list whose first element is always the interface stats, with the link count and the
     * profiling results appended only when asked for.
     *
     * An unidentified requester gets nothing — the reference returns None before looking at
     * the request at all (`Transport.py:3326`), so an ACL hit alone is not authorisation.
     */
    @Suppress("UNUSED_PARAMETER")
    private fun remoteStatusHandler(
        path: String,
        data: ByteArray?,
        requestId: ByteArray,
        linkId: ByteArray,
        remoteIdentity: Identity?,
        requestedAt: Long,
    ): ByteArray? {
        if (remoteIdentity == null) return null
        return try {
            val request = data?.let { decodeList(it) } ?: return null
            if (request.isEmpty()) return null

            val response = ArrayList<Value>()
            response.add(interfaceStatsValue())
            if (request[0].isBooleanValue && request[0].asBooleanValue().boolean) {
                response.add(ValueFactory.newInteger(Transport.linkCount().toLong()))
            }
            // Profiling is not instrumented here, so the slot the reference fills with
            // profiling results is reported as nil rather than fabricated.
            if (request.size >= 2 && request[1].isBooleanValue && request[1].asBooleanValue().boolean) {
                response.add(ValueFactory.newNil())
            }
            encode(ValueFactory.newArray(response))
        } catch (e: Exception) {
            Transport.logManagement("Remote status request from ${remoteIdentity.hexHash} failed: ${e.message}")
            null
        }
    }

    /**
     * `/path` — python `Transport.remote_path_handler` (`Transport.py:3346-3376`).
     *
     * Request is a msgpack list `[command, destination_hash?, max_hops?]`. `command` is
     * `"table"` or `"rates"`; a destination hash filters the result to that one entry, and
     * `max_hops` caps the paths returned. An unrecognised command yields nil, as it does in
     * the reference (`response` is never assigned and falls through).
     */
    @Suppress("UNUSED_PARAMETER")
    private fun remotePathHandler(
        path: String,
        data: ByteArray?,
        requestId: ByteArray,
        linkId: ByteArray,
        remoteIdentity: Identity?,
        requestedAt: Long,
    ): ByteArray? {
        if (remoteIdentity == null) return null
        return try {
            val request = data?.let { decodeList(it) } ?: return null
            if (request.isEmpty()) return null

            val command = request[0].takeIf { it.isStringValue }?.asStringValue()?.asString()
            val filterHash = request.getOrNull(1)
                ?.takeIf { it.isBinaryValue }?.asBinaryValue()?.asByteArray()
            val maxHops = request.getOrNull(2)
                ?.takeIf { it.isIntegerValue }?.asIntegerValue()?.toInt()

            val rows = when (command) {
                "table" -> pathTableValues(maxHops)
                "rates" -> rateTableValues()
                else -> return encode(ValueFactory.newNil())
            }.filter { row ->
                filterHash == null || rowHash(row)?.contentEquals(filterHash) == true
            }
            encode(ValueFactory.newArray(rows))
        } catch (e: Exception) {
            Transport.logManagement("Remote path request from ${remoteIdentity.hexHash} failed: ${e.message}")
            null
        }
    }

    // ------------------------------------------------------------------------
    // Table snapshots, in the reference's msgpack shapes
    // ------------------------------------------------------------------------

    /**
     * python `Reticulum.get_path_table` (`Reticulum.py:1630-1648`).
     *
     * `timestamp` and `expires` go out in SECONDS: the reference stores python `time.time()`
     * floats and `rnpath` renders them as absolute times, so shipping our millisecond values
     * would put every path tens of thousands of years into the future.
     */
    private fun pathTableValues(maxHops: Int?): List<Value> =
        Transport.pathTableSnapshot().mapNotNull { (destHash, entry) ->
            if (maxHops != null && entry.hops > maxHops) return@mapNotNull null
            ValueFactory.newMap(
                linkedMapOf<Value, Value>(
                    ValueFactory.newString("hash") to ValueFactory.newBinary(destHash),
                    ValueFactory.newString("timestamp") to ValueFactory.newFloat(entry.timestamp / 1000.0),
                    ValueFactory.newString("via") to ValueFactory.newBinary(entry.nextHop),
                    ValueFactory.newString("hops") to ValueFactory.newInteger(entry.hops.toLong()),
                    ValueFactory.newString("expires") to ValueFactory.newFloat(entry.expires / 1000.0),
                    ValueFactory.newString("interface") to
                        ValueFactory.newString(Transport.interfaceNameForHash(entry.receivingInterfaceHash)),
                ),
            )
        }

    /** python `Reticulum.get_rate_table` (`Reticulum.py:1650-1668`). */
    private fun rateTableValues(): List<Value> =
        Transport.announceRateSnapshot().map { (destHash, entry) ->
            ValueFactory.newMap(
                linkedMapOf<Value, Value>(
                    ValueFactory.newString("hash") to ValueFactory.newBinary(destHash),
                    ValueFactory.newString("last") to ValueFactory.newFloat(entry.last / 1000.0),
                    ValueFactory.newString("rate_violations") to
                        ValueFactory.newInteger(entry.rateViolations.toLong()),
                    ValueFactory.newString("blocked_until") to
                        ValueFactory.newFloat(entry.blockedUntil / 1000.0),
                    ValueFactory.newString("timestamps") to ValueFactory.newArray(
                        entry.timestamps.map { ValueFactory.newFloat(it / 1000.0) },
                    ),
                ),
            )
        }

    /**
     * python `Reticulum.get_interface_stats` (`Reticulum.py:1397-1520`).
     *
     * The reference duck-types across every interface class and reports whatever attributes
     * happen to exist — radio airtime, channel load, noise floor, battery, I2P tunnel state
     * and so on. Reported here are the fields every interface genuinely has: identity, mode,
     * bitrate, online state and the traffic counters. The radio- and transport-specific
     * fields are absent rather than zero-filled, so a reader cannot mistake "we do not
     * measure this" for "this measured zero".
     */
    private fun interfaceStatsValue(): Value {
        val interfaces = Transport.interfaceStatsSnapshot().map { snap ->
            ValueFactory.newMap(
                linkedMapOf<Value, Value>(
                    ValueFactory.newString("name") to ValueFactory.newString(snap.name),
                    ValueFactory.newString("hash") to ValueFactory.newBinary(snap.hash),
                    ValueFactory.newString("mode") to ValueFactory.newInteger(snap.mode.toLong()),
                    ValueFactory.newString("bitrate") to ValueFactory.newInteger(snap.bitrate.toLong()),
                    ValueFactory.newString("status") to ValueFactory.newBoolean(snap.online),
                    ValueFactory.newString("txb") to ValueFactory.newInteger(snap.txBytes),
                    ValueFactory.newString("rxb") to ValueFactory.newInteger(snap.rxBytes),
                    ValueFactory.newString("clients") to ValueFactory.newNil(),
                ),
            )
        }
        return ValueFactory.newMap(
            linkedMapOf<Value, Value>(
                ValueFactory.newString("interfaces") to ValueFactory.newArray(interfaces),
                ValueFactory.newString("transport_id") to
                    (Transport.identity?.hash?.let { ValueFactory.newBinary(it) } ?: ValueFactory.newNil()),
                ValueFactory.newString("transport_enabled") to
                    ValueFactory.newBoolean(Transport.isTransportEnabled()),
                ValueFactory.newString("rxb") to ValueFactory.newInteger(Transport.trafficRxb()),
                ValueFactory.newString("txb") to ValueFactory.newInteger(Transport.trafficTxb()),
            ),
        )
    }

    // ------------------------------------------------------------------------
    // msgpack helpers
    // ------------------------------------------------------------------------

    private fun decodeList(data: ByteArray): List<Value>? {
        MessagePack.newDefaultUnpacker(data).use { unpacker ->
            if (!unpacker.hasNext()) return null
            // unpackValue builds the tree recursively; a request from an allowed
            // manager nested deeper than the stack is malformed, not fatal to the
            // transport thread this runs on.
            val value =
                try {
                    unpacker.unpackValue()
                } catch (e: StackOverflowError) {
                    return null
                }
            return if (value.isArrayValue) value.asArrayValue().list() else null
        }
    }

    private fun encode(value: Value): ByteArray =
        MessagePack.newDefaultBufferPacker().use { packer ->
            packer.packValue(value)
            packer.toByteArray()
        }

    private fun rowHash(row: Value): ByteArray? {
        if (!row.isMapValue) return null
        val entry = row.asMapValue().map()[ValueFactory.newString("hash")] ?: return null
        return entry.takeIf { it.isBinaryValue }?.asBinaryValue()?.asByteArray()
    }
}
