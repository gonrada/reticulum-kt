package network.reticulum.crypto

import network.reticulum.identity.Identity
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread

/**
 * Exercises every primitive a link handshake uses — Ed25519 keygen/sign/verify, X25519
 * agreement, HKDF, AES-CBC, HMAC, SHA-256 — once, on a background thread, so the first
 * real link on a fresh JVM does not pay class loading and JIT compilation inside its
 * round-trip measurement.
 *
 * Why this exists. Both ends of a link derive their keepalive interval from their own
 * RTT measurement, floored at KEEPALIVE_MIN below an RTT of ~24 ms. The responder's
 * measurement is the larger by construction (it is `max(measured, remote)`), so an
 * initiator that measures just under the floor and a responder just over it end up
 * with different keepalives, and the responder's reply throttle then skips the
 * initiator's first, on-time keepalive — by design, and identically in the reference.
 * Two cold JVMs measure ~23 ms for their first handshake on loopback and sit exactly
 * on that boundary; a warmed JVM measures a few milliseconds and is nowhere near it.
 * The reference never needs this: CPython has no warm-up cost. Kotlin-only; changes
 * no protocol behaviour.
 *
 * Cost: one keypair and a handful of operations, ~50-150 ms once, off the caller's thread.
 */
object CryptoWarmup {
    private val started = AtomicBoolean(false)

    @Volatile
    var completed: Boolean = false
        private set

    /** Run the warm-up on a daemon thread. Idempotent: later calls are no-ops. */
    fun runAsync() {
        if (!started.compareAndSet(false, true)) return
        thread(name = "Transport-cryptowarm", isDaemon = true) { run() }
    }

    /** Run the warm-up on the calling thread. Never throws; a failure is logged and ignored. */
    fun run() {
        try {
            val a = Identity.create()
            val b = Identity.create()
            val message = ByteArray(64) { it.toByte() }
            // Ed25519 sign + verify (link proofs, announces)
            val signature = a.sign(message)
            check(a.validate(signature, message))
            // X25519 + HKDF + AES-CBC + HMAC (identity encryption uses the same Token path a link does)
            val peer = Identity.fromPublicKey(b.getPublicKey())
            val ciphertext = peer.encrypt(message)
            check(b.decrypt(ciphertext).contentEquals(message))
            // SHA-256 (packet hashes, link ids)
            Hashes.fullHash(message)
            completed = true
        } catch (t: Throwable) {
            // Warm-up is best-effort; a real handshake will simply pay the cost instead.
            println("[CryptoWarmup] crypto warm-up failed: ${t.javaClass.simpleName}: ${t.message}")
        }
    }
}
