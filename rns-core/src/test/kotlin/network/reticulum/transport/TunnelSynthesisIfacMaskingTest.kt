package network.reticulum.transport

import network.reticulum.common.InterfaceMode
import network.reticulum.common.RnsConstants
import network.reticulum.crypto.Hashes
import network.reticulum.crypto.defaultCryptoProvider
import network.reticulum.destination.Destination
import network.reticulum.identity.Identity
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test

/**
 * Regression guard for the tunnel-synthesis frame leaving an IFAC'd interface in
 * plaintext (seen in a raw capture of two IFAC'd TCP client interfaces: first frame
 * len=195, byte0=0x08, bytes 2..18 equal to the plaintext
 * `rnstransport.tunnel.synthesize` hash).
 *
 * [Transport.synthesizeTunnel] used to hand `packet.pack()` straight to
 * `interface_.send()`, bypassing `transmit()` and therefore `applyIfacMasking()`.
 * python builds the packet with `attached_interface` and calls `packet.send()`
 * (Transport.py:2780), so the frame is masked like any other. An IFAC'd python
 * TCPServerInterface drops a flag-clear frame silently (Transport.py:1442-1473),
 * so the tunnel was never registered and reconnecting clients lost path
 * restoration.
 *
 * The frame is checked at the byte level, the way the reference's inbound side
 * would see it: the IFAC tag at bytes 2..18 is the only unmasked field, so the
 * test recomputes the HKDF mask from it, unmasks, and then requires (a) the
 * plaintext destination hash to reappear, (b) the tag to equal the last 16 bytes
 * of the interface identity's signature over the plaintext (Ed25519 is
 * deterministic), and (c) the masker applied to that plaintext to reproduce the
 * captured frame exactly.
 */
@DisplayName("Tunnel synthesis goes through IFAC masking")
class TunnelSynthesisIfacMaskingTest {

    /**
     * Minimal [InterfaceRef] carrying IFAC credentials, derived the way
     * `IfacUtils.deriveIfacCredentials` (rns-interfaces) and python
     * Reticulum.py:719-741 derive them, so the fixture is a real interface's
     * credential set and not an arbitrary key. Inline because rns-core's test
     * sourceset cannot see rns-interfaces.
     */
    private class IfacInterface(
        override val name: String,
        netname: String?,
        netkey: String?,
    ) : InterfaceRef {
        val sent = mutableListOf<ByteArray>()

        // Real interfaces register under fullHash(toString()) — 32 bytes — and
        // synthesizeTunnel folds this into the tunnel id, so use the real width.
        override val hash: ByteArray = Hashes.fullHash(name.toByteArray())
        override val canSend: Boolean = true
        override val canReceive: Boolean = true
        override val online: Boolean = true
        override val mode: InterfaceMode = InterfaceMode.FULL
        override val bitrate: Int = 1_000_000
        override val hwMtu: Int = RnsConstants.MTU

        override var tunnelId: ByteArray? = null
        override var wantsTunnel: Boolean = true

        override val ifacKey: ByteArray?
        override val ifacIdentity: Identity?
        override val ifacSize: Int

        init {
            if (netname == null && netkey == null) {
                ifacKey = null
                ifacIdentity = null
                ifacSize = 0
            } else {
                val origin =
                    listOfNotNull(
                        netname?.let { Hashes.fullHash(it.toByteArray()) },
                        netkey?.let { Hashes.fullHash(it.toByteArray()) },
                    ).fold(ByteArray(0)) { acc, b -> acc + b }
                val key = defaultCryptoProvider().hkdf(64, Hashes.fullHash(origin), IFAC_SALT, null)
                ifacKey = key
                ifacIdentity = Identity.fromBytes(key) ?: error("IFAC identity from derived key")
                ifacSize = 16
            }
        }

        override fun send(data: ByteArray) {
            sent.add(data.copyOf())
        }
    }

    private lateinit var iface: IfacInterface

    @BeforeEach
    fun setup() {
        try {
            Transport.stop()
        } catch (_: Exception) {
        }
        Transport.pathTable.clear()
        // synthesizeTunnel needs a transport identity; outbound() needs started.
        Transport.start(Identity.create(), enableTransport = false)
    }

    @AfterEach
    fun teardown() {
        try {
            Transport.deregisterInterface(iface)
        } catch (_: Exception) {
        }
        Transport.pathTable.clear()
        try {
            Transport.stop()
        } catch (_: Exception) {
        }
    }

    private fun register(netname: String?, netkey: String?): IfacInterface {
        iface = IfacInterface("ifac-tunnel-${System.nanoTime()}", netname, netkey)
        Transport.registerInterface(iface)
        return iface
    }

    /**
     * The reference's unmask (Transport.py:1449-1471): mask = HKDF(len, ifac, ifac_key);
     * byte 0 and byte 1 XOR mask, tag untouched, payload XOR mask; then clear the
     * IFAC flag on byte 0.
     */
    private fun unmask(frame: ByteArray, ifacKey: ByteArray, ifacSize: Int): ByteArray {
        val mask = defaultCryptoProvider().hkdf(frame.size, frame.copyOfRange(2, 2 + ifacSize), ifacKey, null)
        val unmasked = ByteArray(frame.size) { i ->
            if (i in 2 until 2 + ifacSize) frame[i] else (frame[i].toInt() xor mask[i].toInt()).toByte()
        }
        return byteArrayOf((unmasked[0].toInt() and 0x7F).toByte(), unmasked[1]) +
            unmasked.copyOfRange(2 + ifacSize, unmasked.size)
    }

    @Test
    @DisplayName("frame leaves an IFAC'd interface masked, flag set, tag valid")
    fun `tunnel synthesis frame is ifac masked`() {
        val ifc = register("family", "familypass123test")

        val tunnelId = Transport.synthesizeTunnel(ifc)

        assertNotNull(tunnelId, "synthesis should succeed")
        assertFalse(ifc.wantsTunnel, "wantsTunnel is cleared once the frame is out")
        assertEquals(1, ifc.sent.size, "exactly one frame on the wire")
        val frame = ifc.sent[0]

        // HEADER_1: flags(1)+hops(1)+dest(16)+context(1)+data(176) = 195, plus a 16-byte tag.
        assertEquals(PLAIN_FRAME_SIZE + 16, frame.size, "masked frame is plaintext + ifac tag")
        assertEquals(0x80, frame[0].toInt() and 0x80, "IFAC flag (bit 7 of byte 0) must be set")
        assertFalse(
            frame.copyOfRange(2, 18).contentEquals(TUNNEL_SYNTH_HASH),
            "bytes 2..18 must not be the plaintext tunnel.synthesize hash",
        )

        // Unmask the way the receiving reference does and require the plaintext back.
        val ifac = frame.copyOfRange(2, 18)
        val plain = unmask(frame, ifc.ifacKey!!, ifc.ifacSize)
        assertEquals(PLAIN_FRAME_SIZE, plain.size)
        assertEquals(0, plain[0].toInt() and 0x80, "plaintext flag byte has the IFAC bit clear")
        assertArrayEquals(TUNNEL_SYNTH_HASH, plain.copyOfRange(2, 18), "unmasked destination is tunnel.synthesize")

        // The tag is the last ifacSize bytes of the interface identity's signature over
        // the plaintext (Transport.py:1332-1335 handle_outgoing_ifac).
        val sig = ifc.ifacIdentity!!.sign(plain)
        assertArrayEquals(sig.copyOfRange(sig.size - 16, sig.size), ifac, "tag = tail of Ed25519(plaintext)")

        // And the masker, given that plaintext, reproduces the captured frame byte for byte.
        assertArrayEquals(Transport.applyIfacMaskingForTest(plain, ifc), frame, "frame == applyIfacMasking(plaintext)")

        // Routed through transmit(): tx accounting recorded once, not twice.
        val stats = Transport.getInterfaceStats(ifc)
        assertNotNull(stats)
        assertEquals(1L, stats!!.txPackets, "one tx packet recorded")
        assertEquals(frame.size.toLong(), stats.txBytes, "tx bytes = the masked frame, counted once")
    }

    @Test
    @DisplayName("frame on a non-IFAC interface is the plaintext packet")
    fun `tunnel synthesis frame is plain without ifac`() {
        val ifc = register(null, null)

        assertNotNull(Transport.synthesizeTunnel(ifc))
        assertEquals(1, ifc.sent.size)
        val frame = ifc.sent[0]

        assertEquals(PLAIN_FRAME_SIZE, frame.size)
        assertEquals(0, frame[0].toInt() and 0x80, "no IFAC flag without credentials")
        assertArrayEquals(TUNNEL_SYNTH_HASH, frame.copyOfRange(2, 18))
        assertTrue(!ifc.wantsTunnel)
    }

    private companion object {
        /** python Reticulum.IFAC_SALT — the HKDF salt for the derived IFAC key. */
        val IFAC_SALT: ByteArray =
            "adf54d882c9a9b80771eb4995d702d4a3e733391b2a0f53f416d9f907e55cff8"
                .chunked(2).map { it.toInt(16).toByte() }.toByteArray()

        val TUNNEL_SYNTH_HASH: ByteArray =
            Destination.computeHash("rnstransport", listOf("tunnel", "synthesize"), null)

        /** flags + hops + dest(16) + context + (pubkey 64 + iface hash 32 + random 16 + sig 64). */
        const val PLAIN_FRAME_SIZE = 2 + 16 + 1 + 176
    }
}
