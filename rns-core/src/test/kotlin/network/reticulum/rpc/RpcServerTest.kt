package network.reticulum.rpc

import network.reticulum.identity.Identity
import network.reticulum.transport.Transport
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.msgpack.core.MessagePack
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.Socket
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * A python `multiprocessing.connection.Client` written in Kotlin: the two-way HMAC
 * handshake, a length-prefixed msgpack request, a msgpack reply. Exercises the
 * request set python's `rnstatus`/`rnpath` use.
 */
class RpcServerTest {
    private val key = ByteArray(32) { (it * 7).toByte() }
    private lateinit var server: RpcServer

    @BeforeEach
    fun setup() {
        try { Transport.stop() } catch (_: Exception) {}
        Transport.start(Identity.create(), enableTransport = true)
        server = RpcServer(port = 0, authKey = key, log = {})
        server.start()
    }

    @AfterEach
    fun teardown() {
        server.stop()
        try { Transport.stop() } catch (_: Exception) {}
    }

    private fun hmac(message: ByteArray): ByteArray = hmac("HmacSHA256", message)

    private fun hmac(algorithm: String, message: ByteArray): ByteArray {
        val mac = Mac.getInstance(algorithm)
        mac.init(SecretKeySpec(key, algorithm))
        return mac.doFinal(message)
    }

    private fun send(out: DataOutputStream, data: ByteArray) {
        out.writeInt(data.size); out.write(data); out.flush()
    }

    private fun recv(input: DataInputStream): ByteArray {
        val n = input.readInt()
        val data = ByteArray(n)
        input.readFully(data)
        return data
    }

    /** One call, as `Reticulum.get_rpc_client()` + `send_bytes(mp.packb(call))` + `mp.unpackb(recv_bytes())`. */
    private fun call(request: Map<String, Any?>): Any? {
        Socket("127.0.0.1", server.boundPort).use { socket ->
            val input = DataInputStream(socket.getInputStream())
            val out = DataOutputStream(socket.getOutputStream())
            // answer_challenge (client side of deliver_challenge)
            val challenge = recv(input)
            val prefix = "#CHALLENGE#".toByteArray()
            assertTrue(challenge.copyOfRange(0, prefix.size).contentEquals(prefix))
            val message = challenge.copyOfRange(prefix.size, challenge.size)
            assertEquals("{sha256}", String(message, 0, 8))
            send(out, "{sha256}".toByteArray() + hmac(message))
            assertEquals("#WELCOME#", String(recv(input)))
            // deliver_challenge (client side): our challenge, the server's HMAC
            val ours = "{sha256}".toByteArray() + ByteArray(20) { it.toByte() }
            send(out, prefix + ours)
            val answer = recv(input)
            assertEquals("{sha256}", String(answer, 0, 8))
            assertArrayEquals(hmac(ours), answer.copyOfRange(8, answer.size))
            send(out, "#WELCOME#".toByteArray())
            // the call
            val packer = MessagePack.newDefaultBufferPacker()
            packer.packMapHeader(request.size)
            for ((k, v) in request) {
                packer.packString(k)
                when (v) {
                    null -> packer.packNil()
                    is String -> packer.packString(v)
                    is Int -> packer.packInt(v)
                    is Double -> packer.packDouble(v)
                    is ByteArray -> { packer.packBinaryHeader(v.size); packer.writePayload(v) }
                    else -> packer.packString(v.toString())
                }
            }
            send(out, packer.toByteArray())
            val reply = recv(input)
            return decode(MessagePack.newDefaultUnpacker(reply).unpackValue())
        }
    }

    private fun decode(v: org.msgpack.value.Value): Any? =
        when {
            v.isNilValue -> null
            v.isBooleanValue -> v.asBooleanValue().boolean
            v.isIntegerValue -> v.asIntegerValue().toLong()
            v.isFloatValue -> v.asFloatValue().toDouble()
            v.isStringValue -> v.asStringValue().asString()
            v.isBinaryValue -> v.asBinaryValue().asByteArray()
            v.isArrayValue -> v.asArrayValue().list().map { decode(it) }
            v.isMapValue -> v.asMapValue().map().entries.associate { (k, mv) -> decode(k).let { if (it is ByteArray) it.toList() else it } to decode(mv) }
            else -> null
        }

    @Test
    fun `a wrong key fails the handshake`() {
        Socket("127.0.0.1", server.boundPort).use { socket ->
            val input = DataInputStream(socket.getInputStream())
            val out = DataOutputStream(socket.getOutputStream())
            val challenge = recv(input)
            send(out, "{sha256}".toByteArray() + ByteArray(32))
            assertEquals("#FAILURE#", String(recv(input)))
        }
    }

    /**
     * A python that predates the digest tags: `answer_challenge` hashes the whole challenge
     * with MD5 and sends a bare 16-byte MAC, `deliver_challenge` sends a bare 20-byte
     * challenge and compares the reply against a bare HMAC-MD5 (connection.py:732-759,
     * before the digest tags). A tagged reply there is `digest received was wrong`.
     */
    @Test
    fun `a legacy md5-only python client completes the handshake`() {
        Socket("127.0.0.1", server.boundPort).use { socket ->
            val input = DataInputStream(socket.getInputStream())
            val out = DataOutputStream(socket.getOutputStream())
            val prefix = "#CHALLENGE#".toByteArray()
            val challenge = recv(input)
            assertTrue(challenge.copyOfRange(0, prefix.size).contentEquals(prefix))
            val message = challenge.copyOfRange(prefix.size, challenge.size)
            // The MAC covers the entire message, digest tag included.
            send(out, hmac("HmacMD5", message))
            assertEquals("#WELCOME#", String(recv(input)))
            val ours = ByteArray(20) { (it * 5).toByte() }
            send(out, prefix + ours)
            val answer = recv(input)
            assertArrayEquals(hmac("HmacMD5", ours), answer, "a legacy client wants a bare MD5 MAC")
            send(out, "#WELCOME#".toByteArray())
        }
    }

    @Test
    fun `interface stats carry the python keys`() {
        val stats = call(mapOf("get" to "interface_stats")) as Map<*, *>
        assertTrue(stats["interfaces"] is List<*>)
        for (key in listOf("rxb", "txb", "rxs", "txs", "arxb", "rxqt", "tqpressure", "txq", "rss", "transport_id", "transport_uptime")) {
            assertTrue(stats.containsKey(key), "missing $key")
        }
        assertNotNull(stats["transport_id"])
        assertNull(stats["txq"])
    }

    @Test
    fun `counts, timeouts and tables answer as python types`() {
        assertEquals(0L, call(mapOf("get" to "link_count")))
        assertEquals(0L, call(mapOf("get" to "active_link_count")))
        val timeout = call(mapOf("get" to "first_hop_timeout", "destination_hash" to ByteArray(16)))
        assertTrue(timeout is Double && timeout > 0.0, "first_hop_timeout is seconds as a float: $timeout")
        assertTrue(call(mapOf("get" to "medium_path_timeout")) is Double)
        assertEquals(emptyList<Any?>(), call(mapOf("get" to "path_table", "max_hops" to 8)))
        assertEquals(emptyList<Any?>(), call(mapOf("get" to "rate_table")))
        assertEquals("None", call(mapOf("get" to "next_hop_if_name", "destination_hash" to ByteArray(16))))
        assertNull(call(mapOf("get" to "next_hop", "destination_hash" to ByteArray(16))))
        assertNull(call(mapOf("get" to "packet_rssi", "packet_hash" to ByteArray(32))))
        assertNull(call(mapOf("get" to "profiling_results")))
        assertNull(call(mapOf("get" to "lowest_interface_bitrate")), "no online interface: None")
    }

    @Test
    fun `drops and blackholes round-trip`() {
        assertEquals(true, call(mapOf("drop" to "announce_queues")))
        assertEquals(true, call(mapOf("drop" to "path", "destination_hash" to ByteArray(16))))
        assertEquals(0L, call(mapOf("drop" to "all_via", "destination_hash" to ByteArray(16))))
        val identityHash = ByteArray(16) { 3 }
        assertEquals(false, call(mapOf("get" to "is_blackholed", "identity_hash" to identityHash)))
        assertEquals(true, call(mapOf("blackhole_identity" to identityHash, "until" to null, "reason" to "test")))
        assertEquals(true, call(mapOf("get" to "is_blackholed", "identity_hash" to identityHash)))
        val listed = call(mapOf("get" to "blackholed_identities")) as Map<*, *>
        val entry = listed[identityHash.toList()] as Map<*, *>
        assertEquals("test", entry["reason"])
        assertNull(entry["until"])
        assertEquals(true, call(mapOf("unblackhole_identity" to identityHash)))
        assertFalse(call(mapOf("get" to "is_blackholed", "identity_hash" to identityHash)) as Boolean)
        assertEquals(false, call(mapOf("blackhole_identity" to ByteArray(3))), "python refuses a wrong-length hash")
    }

    @Test
    fun `an unknown call answers None`() {
        assertNull(call(mapOf("get" to "no_such_thing")))
        assertNull(call(mapOf("frobnicate" to 1)))
    }
}
