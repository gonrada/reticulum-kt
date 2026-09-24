package network.reticulum.transport

import network.reticulum.common.DestinationDirection
import network.reticulum.common.DestinationType
import network.reticulum.common.InterfaceMode
import network.reticulum.common.RnsConstants
import network.reticulum.destination.Destination
import network.reticulum.identity.Identity
import network.reticulum.packet.Packet
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.util.concurrent.atomic.AtomicReference

/**
 * onForeignLocalAnnounce fires when an announce arrives for one of our own destinations
 * that we did NOT emit (a foreign node announcing our identity), but stays silent for our
 * own announce echoing back off a shared instance.
 */
class ForeignLocalAnnounceTest {

    private class CapturingInterface(override val name: String) : InterfaceRef {
        override val hash: ByteArray = ByteArray(RnsConstants.TRUNCATED_HASH_BYTES) { 0xAA.toByte() }
        override val canSend = true
        override val canReceive = true
        override val online = true
        override val mode = InterfaceMode.FULL
        override val bitrate = 1_000_000
        override val hwMtu = RnsConstants.MTU
        override var tunnelId: ByteArray? = null
        override var wantsTunnel = false
        override fun send(data: ByteArray) = Unit
    }

    private lateinit var iface: CapturingInterface

    @BeforeEach
    fun setup() {
        try { Transport.stop() } catch (_: Exception) {}
        Transport.start(Identity.create(), enableTransport = false)
        iface = CapturingInterface("capture-${System.nanoTime()}")
        Transport.registerInterface(iface)
    }

    @AfterEach
    fun teardown() {
        Transport.onForeignLocalAnnounce = null
        try { Transport.deregisterInterface(iface) } catch (_: Exception) {}
        try { Transport.stop() } catch (_: Exception) {}
    }

    @Test
    fun `foreign announce for a local destination is surfaced, our own echo is not`() {
        val dest = Destination.create(
            identity = Identity.create(),
            direction = DestinationDirection.IN,
            type = DestinationType.SINGLE,
            appName = "foreignannouncetest",
            aspects = arrayOf("delivery"),
        )
        Transport.registerDestination(dest)

        val captured = AtomicReference<ByteArray?>(null)
        Transport.onForeignLocalAnnounce = { destHash, _, _ -> captured.set(destHash) }

        // (a) Our own announce, emitted via outbound (records the self-hash), then echoed
        // back via inbound — must stay silent.
        val selfAnnounce = Packet.createAnnounce(dest)!!
        Transport.outbound(selfAnnounce)
        captured.set(null)
        Transport.inbound(selfAnnounce.raw ?: selfAnnounce.pack(), iface)
        Thread.sleep(200) // give any async processing a chance to (wrongly) fire
        assertNull(captured.get(), "our own announce echoing back must not be surfaced")

        // (b) A foreign announce for the SAME destination — a distinct packet we did not
        // emit — must be surfaced.
        val foreignAnnounce = Packet.createAnnounce(dest)!!
        assertFalse(
            foreignAnnounce.packetHash.contentEquals(selfAnnounce.packetHash),
            "two announces for the same destination must be distinct packets",
        )
        captured.set(null)
        Transport.inbound(foreignAnnounce.raw ?: foreignAnnounce.pack(), iface)
        val deadline = System.currentTimeMillis() + 2000
        while (captured.get() == null && System.currentTimeMillis() < deadline) Thread.sleep(10)
        assertNotNull(captured.get(), "a foreign announce of our own identity must be surfaced")
        assertArrayEquals(dest.hash, captured.get())
    }
}
