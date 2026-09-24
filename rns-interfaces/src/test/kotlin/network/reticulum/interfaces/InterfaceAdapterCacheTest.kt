package network.reticulum.interfaces

import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.lang.ref.WeakReference

/**
 * The InterfaceRef adapter must (a) be stable for a live interface — Transport
 * register/deregister match by adapter identity — and (b) be released once the interface
 * is dropped. The previous global adapterCache kept every interface ever created alive
 * for the process lifetime; this asserts that regression is fixed.
 */
class InterfaceAdapterCacheTest {

    private class TestIface : Interface("adapter-cache-test") {
        override fun start() {}
        override fun processOutgoing(data: ByteArray) {}
    }

    @Test
    fun `toRef returns a stable adapter for a live interface`() {
        val iface = TestIface()
        assertSame(
            iface.toRef(),
            iface.toRef(),
            "a live interface must return the same adapter identity across calls",
        )
    }

    // Kept in a helper so the strong locals are gone when it returns.
    private fun makeAndDrop(): Pair<WeakReference<Interface>, WeakReference<Any>> {
        val iface = TestIface()
        val adapter = iface.toRef()
        return WeakReference<Interface>(iface) to WeakReference(adapter as Any)
    }

    @Test
    fun `interface and its adapter are collectable after being dropped`() {
        val (ifaceWeak, adapterWeak) = makeAndDrop()

        var cleared = false
        for (i in 0 until 50) {
            System.gc()
            System.runFinalization()
            Thread.sleep(20)
            if (ifaceWeak.get() == null) { cleared = true; break }
        }

        assertTrue(cleared, "interface must be GC-collectable after drop (no global adapter-cache retention)")
        assertNull(adapterWeak.get(), "adapter must be collected together with its interface")
    }
}
