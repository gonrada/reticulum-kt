package network.reticulum.transport

import network.reticulum.common.ByteArrayKey
import network.reticulum.common.InterfaceMode
import network.reticulum.common.RnsConstants
import network.reticulum.common.toKey
import network.reticulum.identity.Identity
import network.reticulum.storage.PathStore
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

/**
 * `Transport.stop()` clears roughly twenty-five tables and used to skip exactly one:
 * the registered-interface list. Detached interfaces stayed registered, so a later
 * `start()` added fresh ones alongside dead ones.
 *
 * That matters because the path table is reloaded from storage naming the interface
 * hash from the *previous* session, and `findInterfaceByHash` filters on nothing. The
 * first packet of the new session was handed to a dead interface, `processOutgoing`
 * refused it, and the send failed silently — a link request is not retried, so the
 * caller waited out the full establishment timeout.
 *
 * Reachable because a host application can stop and restart the stack inside one
 * process (calling `Reticulum.stop()` on shutdown and again during init-failure
 * cleanup). Not a parity question: Python's `exit_handler`
 * (Transport.py:3977) does not clear `Transport.interfaces` either, but Python has no
 * supported in-process restart, so there is nothing to port and nothing to diverge
 * from. This is ours because our lifecycle is richer.
 *
 * Removing `interfaces.clear()` from `stop()` must fail both cases.
 */
class TransportStopClearsInterfacesTest {

    private class StubInterface(
        override val name: String,
        fill: Byte,
    ) : InterfaceRef {
        override val hash: ByteArray = ByteArray(RnsConstants.TRUNCATED_HASH_BYTES) { fill }
        override val canSend = true
        override val canReceive = true
        override val online = true
        override val mode = InterfaceMode.FULL
        override val bitrate = 1_000_000
        override val hwMtu = 1064
        override var tunnelId: ByteArray? = null
        override var wantsTunnel = false
        override fun send(data: ByteArray) = Unit
    }

    /** Survives stop()/start() the way a Room-backed store does, so start() reloads from it. */
    private class InMemoryPathStore : PathStore {
        val rows = mutableMapOf<ByteArrayKey, PathEntry>()

        override fun upsertPath(destHash: ByteArray, entry: PathEntry) {
            rows[destHash.toKey()] = entry
        }

        override fun removePath(destHash: ByteArray) {
            rows.remove(destHash.toKey())
        }

        override fun loadAllPaths(): Map<ByteArrayKey, PathEntry> = rows.toMap()

        override fun removeExpiredBefore(timestampMs: Long) {
            rows.entries.removeIf { it.value.expires < timestampMs }
        }
    }

    @BeforeEach
    fun setup() {
        try { Transport.stop() } catch (_: Exception) {}
    }

    @AfterEach
    fun teardown() {
        try { Transport.stop() } catch (_: Exception) {}
        Transport.pathStore = null
    }

    @Test
    fun `stop clears the registered interface list`() {
        val old = StubInterface("session-1", 0xD1.toByte())

        Transport.start(Identity.create(), enableTransport = false)
        Transport.registerInterface(old)
        assertNotNull(
            Transport.findInterfaceByHashForTest(old.hash),
            "precondition: the interface resolves while its session is up",
        )

        Transport.stop()
        Transport.start(Identity.create(), enableTransport = false)

        assertNull(
            Transport.findInterfaceByHashForTest(old.hash),
            "an interface from the previous session must not resolve after a restart",
        )
    }

    @Test
    fun `a path reloaded from storage does not resolve to a dead interface`() {
        val store = InMemoryPathStore()
        Transport.pathStore = store

        val old = StubInterface("session-1", 0xD1.toByte())
        val destHash = ByteArray(RnsConstants.TRUNCATED_HASH_BYTES) { 0x7E }

        Transport.start(Identity.create(), enableTransport = false)
        Transport.registerInterface(old)

        // A path learned in the first session, persisted as a Room-backed store would.
        val now = System.currentTimeMillis()
        store.upsertPath(
            destHash,
            PathEntry(
                timestamp = now,
                nextHop = destHash.copyOf(),
                hops = 1,
                expires = now + 7 * 24 * 60 * 60 * 1000L,
                randomBlobs = mutableListOf(),
                receivingInterfaceHash = old.hash.copyOf(),
                announcePacketHash = ByteArray(RnsConstants.FULL_HASH_BYTES) { 0x11 },
            ),
        )

        Transport.stop()
        // The restart brings up a *different* interface, as a real one would: a fresh
        // socket, a fresh hash. The reloaded row still names the old session's hash.
        Transport.start(Identity.create(), enableTransport = false)
        val fresh = StubInterface("session-2", 0xD2.toByte())
        Transport.registerInterface(fresh)

        assertNull(
            Transport.findInterfaceByHashForTest(old.hash),
            "the reloaded path names a dead interface, which must not resolve",
        )
        assertFalse(
            Transport.hasPath(destHash),
            "a path whose interface is gone is dangling and must not be reported as usable",
        )

        Transport.deregisterInterface(fresh)
    }
}
