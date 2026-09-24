package network.reticulum.interfaces

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

/** Empty inbound frames (e.g. empty keepalives) are dropped. */
class InterfaceEmptyFrameGuardTest {

    private class TestIface : Interface("test-empty-guard") {
        override fun start() { setOnline(true) }
        override fun processOutgoing(data: ByteArray) {}
        fun deliver(data: ByteArray) = processIncoming(data)
    }

    @Test
    fun `empty frames are dropped and non-empty frames delivered`() {
        val iface = TestIface()
        iface.start()
        val received = mutableListOf<ByteArray>()
        iface.onPacketReceived = { data, _ -> received += data }

        iface.deliver(ByteArray(0))
        assertTrue(received.isEmpty(), "an empty frame must not be delivered")
        assertEquals(0L, iface.rxBytes.get(), "an empty frame must not count rx bytes")

        val payload = byteArrayOf(1, 2, 3)
        iface.deliver(payload)
        assertEquals(1, received.size)
        assertArrayEquals(payload, received[0])
        assertEquals(3L, iface.rxBytes.get())
    }
}
