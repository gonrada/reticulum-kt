package network.reticulum.android.db.store

import android.database.SQLException
import android.util.Log
import java.util.concurrent.ExecutorService
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.TimeUnit
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

private const val TAG = "RoomStore"

/** Durable-write retry budget for a transient SQLite lock. */
private const val DURABLE_MAX_ATTEMPTS = 3
private const val DURABLE_BACKOFF_MS = 25L

/**
 * Serializes every write submitted through this file.
 *
 * The write executor is single-threaded, so ordinary writes never contend for
 * this gate. It exists for the one write that does not run on that thread: the
 * teardown fallback in [submitWriteThroughDurable], which runs [block] on the
 * calling thread after the executor has refused it. `ExecutorService.shutdown()`
 * only refuses *new* submissions — queued and in-flight tasks keep running on
 * the write thread — so without the gate that fallback can open a second
 * concurrent transaction against the same database.
 */
private val writeGate = ReentrantLock()

/**
 * Bound on how long the teardown fallback waits for [writeGate]. The fallback
 * runs on a caller thread (an RNS thread), and a Room/SQLite write does not
 * observe thread interruption, so an unbounded wait could pin that thread
 * behind a write that never finishes.
 *
 * The gate's current holder may be part-way through a durable retry cycle, so the budget
 * has to cover one: [DURABLE_MAX_ATTEMPTS] writes plus the linear backoff between them.
 * [DURABLE_ATTEMPT_BUDGET_MS] is an allowance for a single write rather than a measured
 * figure, and nothing enforces it; it is here so the relationship holds when the retry
 * constants change, instead of a flat number that silently stops covering a cycle.
 *
 * This bounds the wait, not the whole path: when it expires the flush proceeds ungated and
 * then runs its own retry cycle, so the worst case on the teardown thread is this wait plus
 * a full cycle — [DURABLE_MAX_ATTEMPTS] writes and the backoff between them — not this
 * figure alone. The total stays inside the teardown force window.
 */
private const val DURABLE_ATTEMPT_BUDGET_MS = 500L
private const val FALLBACK_GATE_WAIT_MS =
    DURABLE_MAX_ATTEMPTS * DURABLE_ATTEMPT_BUDGET_MS +
        DURABLE_BACKOFF_MS * (DURABLE_MAX_ATTEMPTS * (DURABLE_MAX_ATTEMPTS - 1) / 2)

/**
 * Submit a best-effort, write-through persistence task to this executor.
 *
 * Reticulum's Room stores (paths, packet hashes, cached announces) are
 * write-through caches whose contents are reconstructable from the live
 * network — losing a single write is acceptable; crashing the process is
 * not.
 *
 * [network.reticulum.android.lifecycle.StoreLifecycle.drain] quiesces this
 * executor before the `RoomDatabase` is closed on service teardown, but by
 * design it closes the DB even when a write is still in flight (its
 * `Forced`/`Stuck`/`Interrupted` outcomes — the drain budget is bounded so
 * a foreground-service `onDestroy` can't ANR, and Room/SQLite writes don't
 * observe thread interruption). A write caught in that residual window
 * throws from deep inside Room:
 *
 *  - [IllegalStateException] — "Cannot perform this operation because there
 *    is no current transaction" (Sentry COLUMBA-B7, close landed between
 *    `beginTransaction` and `endTransaction`), "...the connection pool has
 *    been closed" (COLUMBA-8X, close before the write's transaction began),
 *    or "attempt to re-open an already-closed object" (COLUMBA-8R, close
 *    mid-transaction).
 *  - [SQLException] — a transient SQLite failure (e.g. `SQLITE_FULL` on a
 *    device low on storage, or a lock timeout) unrelated to teardown.
 *
 * and if the executor was already `shutdown()` by the drain,
 * [ExecutorService.execute] itself throws [RejectedExecutionException] on
 * the calling (RNS) thread. On the dedicated write thread an unhandled
 * exception reaches the thread's uncaught handler and is **fatal** — these
 * are the crashes above. Swallow + log at WARN instead; the dropped write
 * is rebuilt from the next announce.
 *
 * [IllegalStateException] is caught broadly on purpose. The close race
 * surfaces as several different framework messages — "no current
 * transaction" / "connection pool has been closed" / "already-closed
 * object", and (COLUMBA-B7 was itself a late-discovered variant of 8X/8R)
 * plausibly others — so matching on message text would risk missing a
 * variant and reintroducing the crash. The trade-off is that an
 * [IllegalStateException] from a genuine logic error would also be
 * swallowed, so each [block] is kept to plain DAO calls with no
 * `check`/`error`/`require` and no main-thread DB access — there is no such
 * error here to mask. Keep them that way.
 *
 * @param op short operation label for the dropped-write log line.
 */
internal fun ExecutorService.submitWriteThrough(op: String, block: () -> Unit) {
    try {
        execute {
            try {
                writeGate.withLock { block() }
            } catch (e: IllegalStateException) {
                Log.w(TAG, "Dropped DB write '$op'; database closed mid-write: ${e.message}")
            } catch (e: SQLException) {
                Log.w(TAG, "Dropped DB write '$op'; transient SQLite error: ${e.message}")
            }
        }
    } catch (e: RejectedExecutionException) {
        // Executor already shutdown() by StoreLifecycle during service teardown.
        Log.w(TAG, "DB write '$op' rejected; executor already shut down")
    }
}

/**
 * Like [submitWriteThrough], but for **security-critical** writes that must not be silently
 * dropped on a transient lock — identity public keys and per-peer ratchets. Unlike the
 * write-through caches (paths, packet hashes, cached announces), these are not cheaply
 * reconstructable from the live network: a dropped ratchet write costs forward secrecy /
 * decryption of subsequent traffic until re-negotiation.
 *
 * A transient [SQLException] (e.g. `SQLITE_BUSY` / `SQLiteDatabaseLockedException` under
 * write contention) is **retried** up to [DURABLE_MAX_ATTEMPTS] with a
 * small linear backoff, rather than dropped. Teardown-close [IllegalStateException] (the DB
 * was closed mid-write) is swallowed as in [submitWriteThrough]; retry exhaustion is logged at
 * ERROR, never a crash. An executor-shutdown [RejectedExecutionException] is flushed on the
 * calling thread instead — under [writeGate] and with the same retry budget, so that flush
 * neither runs beside a write still in flight on the write thread nor loses the write to a
 * single transient lock. Keep [block] to plain DAO calls (see [submitWriteThrough]).
 *
 * @param op short operation label for the log lines.
 */
internal fun ExecutorService.submitWriteThroughDurable(op: String, block: () -> Unit) {
    try {
        execute {
            writeGate.withLock { runDurable(op, block) }
        }
    } catch (e: RejectedExecutionException) {
        // StoreLifecycle.drain shuts the executor down BEFORE closing the DB, so a
        // security-critical write rejected here can still be flushed synchronously on the
        // calling thread while the DB is (briefly) open — rather than silently dropped as a
        // best-effort cache write would be. This is the bounded reconciliation for the
        // shutdown race; full persist-and-replay across process death is a separate follow-up.
        Log.w(TAG, "Durable DB write '$op' rejected by executor; flushing synchronously on teardown")

        // Take the same gate the executor's writes take: shutdown() only refuses new
        // submissions, so a queued or in-flight write may still be running on the write
        // thread, and this flush should not run a transaction beside it. The wait is
        // bounded (see FALLBACK_GATE_WAIT_MS), because this runs on a stack thread during
        // teardown.
        //
        // If the wait expires the write still goes through. The content here is an
        // identity or a ratchet, which is not reconstructable from the network, so losing
        // it is worse than overlapping a transaction: the database serialises writes
        // itself, and an overlap surfaces as a transient lock, which the retry below is
        // there to absorb. Giving up would trade a certain loss for an avoidable one.
        val gated = try {
            writeGate.tryLock(FALLBACK_GATE_WAIT_MS, TimeUnit.MILLISECONDS)
        } catch (ie: InterruptedException) {
            Thread.currentThread().interrupt()
            false
        }
        if (!gated) {
            Log.w(
                TAG,
                "Durable DB write '$op' proceeding without the write gate; another write " +
                    "held it for ${FALLBACK_GATE_WAIT_MS}ms",
            )
        }
        try {
            // Same retry budget as the executor path: this flush is the one most likely to
            // meet a transient lock, because it runs while the executor may still be
            // draining. Dropping it on the first lock would lose the write this path exists
            // to preserve.
            runDurable(op, block)
        } finally {
            // Only if it was actually acquired: unlocking a gate this thread does not hold
            // throws, which would turn a degraded flush into a crash during teardown.
            if (gated) writeGate.unlock()
        }
    }
}

/**
 * Run [block] with the durable retry budget, swallowing the teardown-close
 * [IllegalStateException] and retrying a transient [SQLException] up to
 * [DURABLE_MAX_ATTEMPTS] times. Callers normally hold [writeGate] across this call, so a
 * retry cycle is serialized against every other write in this file; the teardown flush
 * proceeds without it if the gate cannot be had in its budget, and relies on the
 * database's own serialisation plus these retries instead.
 */
private fun runDurable(op: String, block: () -> Unit) {
    var attempt = 0
    while (true) {
        try {
            block()
            return
        } catch (e: IllegalStateException) {
            Log.w(TAG, "Dropped durable DB write '$op'; database closed mid-write: ${e.message}")
            return
        } catch (e: SQLException) {
            attempt++
            if (attempt >= DURABLE_MAX_ATTEMPTS) {
                Log.e(TAG, "Durable DB write '$op' failed after $attempt attempts; giving up: ${e.message}")
                return
            }
            Log.w(TAG, "Durable DB write '$op' transient SQLite error (attempt $attempt), retrying: ${e.message}")
            try {
                Thread.sleep(DURABLE_BACKOFF_MS * attempt)
            } catch (ie: InterruptedException) {
                Thread.currentThread().interrupt()
                return
            }
        }
    }
}
