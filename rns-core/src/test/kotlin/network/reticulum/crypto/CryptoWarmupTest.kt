package network.reticulum.crypto

import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * The warm-up must exercise the primitives without failing on a working provider, and be
 * safe to call any number of times. What it buys — a first-link RTT that is not inflated
 * by JIT — is a timing property pinned by the conformance keepalive test, not here.
 */
class CryptoWarmupTest {
    @Test
    fun `warm-up completes on a working provider and is idempotent`() {
        CryptoWarmup.run()
        assertTrue(CryptoWarmup.completed, "every primitive must succeed on the default provider")
        CryptoWarmup.run() // second pass must not throw either
        CryptoWarmup.runAsync() // and the async entry must be a no-op after the first
        assertTrue(CryptoWarmup.completed)
    }
}
