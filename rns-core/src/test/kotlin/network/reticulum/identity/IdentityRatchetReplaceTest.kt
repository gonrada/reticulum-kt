package network.reticulum.identity

import network.reticulum.common.RnsConstants
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.io.File
import java.nio.file.Files

/**
 * [Identity.rememberRatchet] keeps exactly one ratchet per destination and a
 * newer ratchet replaces the older one, as the reference does. Before the fix
 * every distinct ratchet was prepended and retained for RATCHET_EXPIRY, one
 * entry per announce, so any announcer could grow the table without bound.
 */
class IdentityRatchetReplaceTest {

    private lateinit var tempDir: File
    private lateinit var previousStoragePath: String
    private val used = mutableListOf<ByteArray>()

    private fun dest(b: Int) = ByteArray(RnsConstants.TRUNCATED_HASH_BYTES) { b.toByte() }.also { used += it }
    private fun ratchet(b: Int) = ByteArray(RnsConstants.KEY_SIZE) { b.toByte() }

    @BeforeEach
    fun setup() {
        tempDir = Files.createTempDirectory("rns-ratchet-replace").toFile()
        previousStoragePath = Identity.storagePath
        Identity.setStoragePath(tempDir.absolutePath)
        Identity.identityStore = null
    }

    @AfterEach
    fun teardown() {
        used.forEach { Identity.dropRatchetCacheForTest(it) }
        Identity.setStoragePath(previousStoragePath)
        tempDir.deleteRecursively()
    }

    @Test
    fun `a newer ratchet replaces the previous one for the same destination`() {
        val d = dest(0x51)
        Identity.rememberRatchet(d, ratchet(1))
        Identity.rememberRatchet(d, ratchet(2))

        val stored = Identity.getRatchets(d)
        assertEquals(1, stored.size, "exactly one ratchet must be retained per destination")
        assertArrayEquals(ratchet(2), stored[0], "the latest ratchet wins")
        assertArrayEquals(ratchet(2), Identity.getRatchet(d))
    }

    @Test
    fun `re-remembering the current ratchet is a no-op`() {
        val d = dest(0x52)
        Identity.rememberRatchet(d, ratchet(3))
        Identity.rememberRatchet(d, ratchet(3))

        assertEquals(1, Identity.getRatchets(d).size)
        assertArrayEquals(ratchet(3), Identity.getRatchet(d))
    }

    @Test
    fun `destinations keep independent ratchets`() {
        val a = dest(0x53)
        val b = dest(0x54)
        Identity.rememberRatchet(a, ratchet(4))
        Identity.rememberRatchet(b, ratchet(5))
        Identity.rememberRatchet(a, ratchet(6))

        assertArrayEquals(ratchet(6), Identity.getRatchet(a), "a's replacement must not touch b")
        assertArrayEquals(ratchet(5), Identity.getRatchet(b))
        assertEquals(1, Identity.getRatchets(a).size)
        assertEquals(1, Identity.getRatchets(b).size)
    }
}
