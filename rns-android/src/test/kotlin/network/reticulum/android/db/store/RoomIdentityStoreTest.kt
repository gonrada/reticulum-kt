package network.reticulum.android.db.store

import android.database.sqlite.SQLiteDatabaseLockedException
import network.reticulum.android.db.dao.IdentityRatchetDao
import network.reticulum.android.db.dao.KnownDestinationDao
import network.reticulum.android.db.entity.IdentityRatchetEntity
import network.reticulum.android.db.entity.KnownDestinationEntity
import network.reticulum.identity.Identity.IdentityData
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

/**
 * Regression tests for Sentry COLUMBA-D4 (issue via upstream PR #84).
 *
 * [RoomIdentityStore] persists security-critical material — identity public keys and per-peer
 * ratchets. Unlike the write-through caches, these are not cheaply reconstructable from the
 * live network, so a transient SQLite lock ([SQLiteDatabaseLockedException]) must be retried,
 * not dropped, and must never crash the write thread. The store previously issued bare
 * `writeExecutor.execute { … }`, so the lock exception escaped and crashed the
 * NativeReticulumDB write thread. It now routes through `submitWriteThroughDurable`.
 *
 * The real lock can't be reproduced through Robolectric's host SQLite, so the exact exception
 * is injected via fake DAOs and the task runs inline on a [DirectExecutorService].
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28])
class RoomIdentityStoreTest {

    private fun identityData() = IdentityData(
        timestamp = 1L,
        packetHash = byteArrayOf(9),
        publicKey = byteArrayOf(2, 3, 4),
        appData = null,
    )

    @Test
    fun `upsertKnownDestination retries a transient lock and eventually succeeds`() {
        val dao = FakeKnownDestinationDao(failFirst = 2) // fail twice, succeed on the 3rd
        val store = RoomIdentityStore(dao, FakeIdentityRatchetDao(), DirectExecutorService())

        store.upsertKnownDestination(byteArrayOf(1), identityData())

        assertEquals("must retry the transient lock through to success", 3, dao.upsertAttempts)
    }

    @Test
    fun `upsertKnownDestination gives up after the retry budget without crashing`() {
        val dao = FakeKnownDestinationDao(failFirst = Int.MAX_VALUE) // always locked
        val store = RoomIdentityStore(dao, FakeIdentityRatchetDao(), DirectExecutorService())

        // Pre-fix this SQLiteDatabaseLockedException escaped the bare executor task and, on the
        // NativeReticulumDB write thread, reached the uncaught handler — fatal (COLUMBA-D4).
        store.upsertKnownDestination(byteArrayOf(1), identityData())

        // Reaching here = no crash. Bounded to DURABLE_MAX_ATTEMPTS (3).
        assertEquals("attempts must be bounded", 3, dao.upsertAttempts)
    }

    @Test
    fun `upsertRatchet retries a transient lock`() {
        val ratchetDao = FakeIdentityRatchetDao(failFirst = 1)
        val store = RoomIdentityStore(FakeKnownDestinationDao(), ratchetDao, DirectExecutorService())

        store.upsertRatchet(byteArrayOf(1), byteArrayOf(5, 6), 123L)

        assertEquals("a dropped ratchet costs forward secrecy — must retry", 2, ratchetDao.upsertAttempts)
    }

    @Test
    fun `a healthy upsert writes exactly once`() {
        val dao = FakeKnownDestinationDao()
        val store = RoomIdentityStore(dao, FakeIdentityRatchetDao(), DirectExecutorService())

        store.upsertKnownDestination(byteArrayOf(1), identityData())

        assertEquals(1, dao.upsertAttempts)
    }

    @Test
    fun `a durable write rejected by a shut-down executor is flushed synchronously`() {
        val dao = FakeKnownDestinationDao()
        // StoreLifecycle.drain has shut the executor down (execute() -> RejectedExecutionException)
        // but has not yet closed the DB. A best-effort cache write drops here; a security-critical
        // identity write is instead flushed synchronously — the shutdown-race reconciliation.
        val executor = DirectExecutorService().apply { shutdown() }
        val store = RoomIdentityStore(dao, FakeIdentityRatchetDao(), executor)

        store.upsertKnownDestination(byteArrayOf(1), identityData())

        assertEquals("rejected durable write must be flushed synchronously, not dropped", 1, dao.upsertAttempts)
    }

    @Test
    fun `a durable write flushed on teardown retries a transient lock`() {
        // The teardown flush is the write most likely to meet a lock: it runs on the calling
        // thread while the executor may still be draining its queue. It must carry the same
        // retry budget as the executor path — dropping it on the first lock loses exactly the
        // write this path exists to preserve.
        val dao = FakeKnownDestinationDao(failFirst = 2) // fail twice, succeed on the 3rd
        val store = RoomIdentityStore(dao, FakeIdentityRatchetDao(), DirectExecutorService().apply { shutdown() })

        store.upsertKnownDestination(byteArrayOf(1), identityData())

        assertEquals("the teardown flush must retry the transient lock", 3, dao.upsertAttempts)
    }

    @Test
    fun `a teardown flush does not run beside a write still on the executor`() {
        // shutdown() refuses NEW submissions only — a queued or in-flight write keeps running
        // on the write thread. The rejected write is flushed on the calling thread, so without
        // serialization the two open concurrent transactions against the same database.
        val dao = BlockingKnownDestinationDao(holdMillis = 300L)
        val executor = Executors.newSingleThreadExecutor()
        try {
            val store = RoomIdentityStore(dao, FakeIdentityRatchetDao(), executor)

            store.upsertKnownDestination(byteArrayOf(1), identityData())
            assertTrue("first write must reach the DAO", dao.started.await(5, TimeUnit.SECONDS))

            executor.shutdown() // drain begins while the first write is still in flight
            store.upsertKnownDestination(byteArrayOf(2), identityData()) // rejected -> flushed here

            assertTrue("executor must terminate", executor.awaitTermination(5, TimeUnit.SECONDS))
            assertEquals("both writes must reach the DAO", 2, dao.attempts.get())
            assertFalse(
                "the teardown flush must not write beside the in-flight executor write",
                dao.overlapped,
            )
        } finally {
            executor.shutdownNow()
        }
    }

    // The gate wait exists so the flush does not open a transaction beside one already
    // running on the write thread. When that wait expires the write still has to land: an
    // identity or a ratchet cannot be rebuilt from the network, so a certain loss is worse
    // than an overlap the database serialises and the retry budget absorbs.
    @Test
    fun `a teardown flush still writes when the gate cannot be had in its budget`() {
        val dao = GateHoldingKnownDestinationDao()
        val executor = Executors.newSingleThreadExecutor()
        try {
            val store = RoomIdentityStore(dao, FakeIdentityRatchetDao(), executor)

            store.upsertKnownDestination(byteArrayOf(1), identityData())
            assertTrue("the gate holder must reach the DAO", dao.firstStarted.await(5, TimeUnit.SECONDS))

            executor.shutdown() // drain begins; the first write keeps the gate
            store.upsertKnownDestination(byteArrayOf(2), identityData()) // rejected -> flushed here

            assertEquals("the flush must write even without the gate", 2, dao.attempts.get())
            assertTrue(
                "the gate must genuinely still have been held when the flush wrote",
                dao.laterWriteSawOneInFlight,
            )
        } finally {
            dao.release.countDown()
            executor.shutdownNow()
            executor.awaitTermination(5, TimeUnit.SECONDS)
        }
    }

    // Proceeding without the gate means the flush reaches its own cleanup holding nothing.
    // An unconditional release there throws IllegalMonitorStateException on the calling
    // thread, turning a degraded write into a crash during teardown.
    @Test
    fun `a teardown flush without the gate does not release a gate it never took`() {
        val dao = GateHoldingKnownDestinationDao()
        val executor = Executors.newSingleThreadExecutor()
        try {
            val store = RoomIdentityStore(dao, FakeIdentityRatchetDao(), executor)

            store.upsertKnownDestination(byteArrayOf(1), identityData())
            assertTrue("the gate holder must reach the DAO", dao.firstStarted.await(5, TimeUnit.SECONDS))
            executor.shutdown()

            val thrown = runCatching {
                store.upsertKnownDestination(byteArrayOf(2), identityData())
            }.exceptionOrNull()

            assertFalse(
                "the flush must not release a gate it never acquired: $thrown",
                thrown is IllegalMonitorStateException,
            )
            assertNull("a degraded teardown flush must not throw: $thrown", thrown)
        } finally {
            dao.release.countDown()
            executor.shutdownNow()
            executor.awaitTermination(5, TimeUnit.SECONDS)
        }
    }

    // And when the gate is free the flush must still take it and give it back, or the next
    // write pays the whole wait budget before proceeding ungated.
    @Test
    fun `a teardown flush that takes the gate hands it back`() {
        val dao = FakeKnownDestinationDao()
        val store = RoomIdentityStore(dao, FakeIdentityRatchetDao(), DirectExecutorService().apply { shutdown() })

        store.upsertKnownDestination(byteArrayOf(1), identityData())
        assertEquals("the flush must write once", 1, dao.upsertAttempts)

        // On another thread: the gate is reentrant, so a leak is invisible to the thread
        // that leaked it. A second flush that had to wait the budget out takes >1.5s.
        val failure = AtomicReference<Throwable?>(null)
        val done = CountDownLatch(1)
        val worker = Thread {
            try {
                store.upsertKnownDestination(byteArrayOf(2), identityData())
            } catch (e: Throwable) {
                failure.set(e)
            } finally {
                done.countDown()
            }
        }
        worker.start()

        assertTrue("a following write must not wait out the gate budget", done.await(1, TimeUnit.SECONDS))
        worker.join(5_000)
        assertNull("the following write must not throw", failure.get())
        assertEquals("the following write must also land", 2, dao.upsertAttempts)
    }

    /**
     * Holds the write gate until the test releases it, so a teardown flush runs out its
     * whole wait budget. Only the first write blocks; later ones return at once.
     */
    private class GateHoldingKnownDestinationDao : KnownDestinationDao {
        val attempts = AtomicInteger()
        val firstStarted = CountDownLatch(1)
        val release = CountDownLatch(1)
        private val inFlight = AtomicInteger()

        /** A write after the first found the first one still inside [upsert]. */
        @Volatile var laterWriteSawOneInFlight = false

        override fun upsert(entity: KnownDestinationEntity) {
            val n = attempts.incrementAndGet()
            val concurrent = inFlight.incrementAndGet() > 1
            if (n > 1 && concurrent) laterWriteSawOneInFlight = true
            try {
                if (n == 1) {
                    firstStarted.countDown()
                    try {
                        release.await(10, TimeUnit.SECONDS)
                    } catch (ie: InterruptedException) {
                        Thread.currentThread().interrupt()
                    }
                }
            } finally {
                inFlight.decrementAndGet()
            }
        }

        override fun getByHash(destHash: ByteArray): KnownDestinationEntity? = null
        override fun getAll(): List<KnownDestinationEntity> = emptyList()
        override fun count(): Int = 0
        override fun deleteByHash(destHash: ByteArray) = Unit
    }

    private class FakeKnownDestinationDao(
        private val failFirst: Int = 0,
    ) : KnownDestinationDao {
        var upsertAttempts = 0
        override fun upsert(entity: KnownDestinationEntity) {
            upsertAttempts++
            if (upsertAttempts <= failFirst) throw SQLiteDatabaseLockedException("database is locked")
        }
        override fun getByHash(destHash: ByteArray): KnownDestinationEntity? = null
        override fun getAll(): List<KnownDestinationEntity> = emptyList()
        override fun count(): Int = 0
        override fun deleteByHash(destHash: ByteArray) = Unit
    }

    /** Records whether two writes were ever inside [upsert] at the same time. */
    private class BlockingKnownDestinationDao(
        private val holdMillis: Long,
    ) : KnownDestinationDao {
        val attempts = AtomicInteger()
        val started = CountDownLatch(1)
        private val inFlight = AtomicInteger()

        @Volatile var overlapped = false

        override fun upsert(entity: KnownDestinationEntity) {
            attempts.incrementAndGet()
            if (inFlight.incrementAndGet() > 1) overlapped = true
            started.countDown()
            try {
                Thread.sleep(holdMillis)
            } finally {
                inFlight.decrementAndGet()
            }
        }

        override fun getByHash(destHash: ByteArray): KnownDestinationEntity? = null
        override fun getAll(): List<KnownDestinationEntity> = emptyList()
        override fun count(): Int = 0
        override fun deleteByHash(destHash: ByteArray) = Unit
    }

    private class FakeIdentityRatchetDao(
        private val failFirst: Int = 0,
    ) : IdentityRatchetDao {
        var upsertAttempts = 0
        override fun upsert(entity: IdentityRatchetEntity) {
            upsertAttempts++
            if (upsertAttempts <= failFirst) throw SQLiteDatabaseLockedException("database is locked")
        }
        override fun getByHash(destHash: ByteArray): IdentityRatchetEntity? = null
        override fun deleteExpiredBefore(thresholdMs: Long) = Unit
    }
}
