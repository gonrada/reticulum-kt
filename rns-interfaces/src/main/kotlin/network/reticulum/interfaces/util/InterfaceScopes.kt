package network.reticulum.interfaces.util

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.launch
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Build the coroutine scope an interface runs its I/O in.
 *
 * - With a [parent] (Android service lifecycle): a child scope whose [SupervisorJob] is
 *   parented to the parent's [Job], so it is cancelled when the parent is cancelled but
 *   can also be cancelled independently and does not propagate failures upward. With
 *   [ioDispatcher] the scope is pinned to [Dispatchers.IO]; otherwise it inherits the
 *   parent's dispatcher.
 * - Without a parent (JVM / tests): a standalone [SupervisorJob] + [Dispatchers.IO]
 *   scope that lives until explicitly cancelled.
 */
internal fun createInterfaceScope(parent: CoroutineScope?, ioDispatcher: Boolean = true): CoroutineScope {
    if (parent == null) return CoroutineScope(SupervisorJob() + Dispatchers.IO)
    val context = parent.coroutineContext + SupervisorJob(parent.coroutineContext[Job])
    return CoroutineScope(if (ioDispatcher) context + Dispatchers.IO else context)
}

/**
 * Run [action] exactly once when this scope ends. Two triggers are registered — a
 * coroutine whose `finally` runs as soon as the scope's cancellation starts (the fast
 * path), and a completion handler on the scope's [Job] (fires once the job and its
 * children have completed, or immediately if it already has) — and a guard ensures
 * [action] runs on the first of them only. Interfaces use this to detach when the
 * parent lifecycle scope they were handed goes away.
 */
internal fun CoroutineScope.onCancellationOnce(action: () -> Unit) {
    val fired = AtomicBoolean(false)
    val fire = { if (fired.compareAndSet(false, true)) action() }
    launch {
        try {
            awaitCancellation()
        } finally {
            fire()
        }
    }
    coroutineContext[Job]?.invokeOnCompletion { fire() }
}
