package network.reticulum

import network.reticulum.identity.Identity
import network.reticulum.transport.Transport
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.net.InetAddress
import java.net.ServerSocket
import java.nio.file.Path
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

/**
 * Issue #71: tryConnectToSharedInstance must wire onPacketReceived (via the registrar)
 * BEFORE launching the interface read loop, otherwise a frame arriving in the gap is
 * silently dropped. Also verifies the deregister-on-failure guard added alongside the
 * reorder, so a start() failure after registration does not leak a registered interface.
 *
 * Driven through the real Reticulum.start(connectToSharedInstance = true) path: a plain
 * ServerSocket satisfies isSharedInstanceRunning's probe, and an injected fake client
 * interface records the ordering the registrar/start sequence actually produced.
 */
class SharedInstanceStartupRaceTest {

    @TempDir
    lateinit var tmp: Path

    /** Reflection target for tryConnectToSharedInstance's getMethod("start")/("detach"). */
    private class FakeClientIface(private val onStart: () -> Unit) {
        fun start() = onStart()
        fun detach() { /* no-op; shutdown() calls this reflectively */ }
    }

    @AfterEach
    fun cleanup() {
        try { Reticulum.stop() } catch (_: Exception) {}
        try { Transport.stop() } catch (_: Exception) {}
        Reticulum.clearPendingFactories()
    }

    @Test
    fun `registrar wires the callback before the interface read loop starts`() {
        val server = ServerSocket(0, 8, InetAddress.getLoopbackAddress())
        val port = server.localPort
        val registrarRan = AtomicBoolean(false)
        val startSawRegistrar = AtomicReference<Boolean?>(null)
        val fake = FakeClientIface(onStart = { startSawRegistrar.set(registrarRan.get()) })

        Reticulum.stop()
        Reticulum.clearPendingFactories()
        Reticulum.setLocalClientFactory { _, _ -> fake }
        Reticulum.setInterfaceRegistrar { iface -> if (iface === fake) registrarRan.set(true) }
        Reticulum.setInterfaceDeregistrar { /* not exercised in this test */ }

        try {
            Reticulum.start(
                configDir = tmp.toString(),
                connectToSharedInstance = true,
                sharedInstancePort = port,
                transportIdentity = Identity.create(),
            )
            assertEquals(
                true,
                startSawRegistrar.get(),
                "the registrar (which wires onPacketReceived) must run before the interface " +
                    "read loop starts — otherwise a frame in the gap is silently dropped (issue #71)",
            )
        } finally {
            server.close()
        }
    }

    @Test
    fun `a start failure after registration deregisters the interface`() {
        val server = ServerSocket(0, 8, InetAddress.getLoopbackAddress())
        val port = server.localPort
        val deregistered = AtomicBoolean(false)
        val fake = FakeClientIface(onStart = { throw RuntimeException("connect boom") })

        Reticulum.stop()
        Reticulum.clearPendingFactories()
        Reticulum.setLocalClientFactory { _, _ -> fake }
        Reticulum.setInterfaceRegistrar { /* registration succeeds; start() is what fails */ }
        Reticulum.setInterfaceDeregistrar { iface -> if (iface === fake) deregistered.set(true) }

        try {
            Reticulum.start(
                configDir = tmp.toString(),
                connectToSharedInstance = true,
                sharedInstancePort = port,
                transportIdentity = Identity.create(),
            )
            assertTrue(
                deregistered.get(),
                "a start() failure after the interface was registered must invoke the deregistrar " +
                    "so no dead interface is left registered in Transport",
            )
        } finally {
            server.close()
        }
    }
}
