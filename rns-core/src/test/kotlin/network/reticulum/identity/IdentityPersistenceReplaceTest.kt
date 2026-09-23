package network.reticulum.identity

import network.reticulum.common.RnsConstants
import network.reticulum.common.toHexString
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.io.File
import java.nio.file.Files

/**
 * The temp -> final renames in [Identity.saveKnownDestinations]
 * (`known_destinations.tmp`) and the ratchet persist job (`<hex>.out`) must
 * replace an existing target. `File.renameTo` fails when the target exists on
 * Windows and its result was discarded, so neither file was ever updated after
 * the first write.
 */
class IdentityPersistenceReplaceTest {

    private lateinit var tempDir: File
    private lateinit var previousStoragePath: String
    private val used = mutableListOf<ByteArray>()

    private fun dest(b: Int) = ByteArray(RnsConstants.TRUNCATED_HASH_BYTES) { b.toByte() }.also { used += it }
    private fun pubKey(b: Int) = ByteArray(RnsConstants.FULL_KEY_SIZE) { b.toByte() }
    private fun ratchet(b: Int) = ByteArray(RnsConstants.KEY_SIZE) { b.toByte() }
    private val packetHash = ByteArray(RnsConstants.TRUNCATED_HASH_BYTES) { 9 }

    @BeforeEach
    fun setup() {
        tempDir = Files.createTempDirectory("rns-persist-replace").toFile()
        previousStoragePath = Identity.storagePath
        Identity.setStoragePath(tempDir.absolutePath)
        Identity.identityStore = null
        Identity.clearKnownDestinations()
    }

    @AfterEach
    fun teardown() {
        used.forEach { Identity.dropRatchetCacheForTest(it) }
        Identity.clearKnownDestinations()
        Identity.setStoragePath(previousStoragePath)
        tempDir.deleteRecursively()
    }

    @Test
    fun `saving known destinations twice leaves the second content in the final file`() {
        val a = dest(0x61)
        val b = dest(0x62)
        val finalFile = File(tempDir, "known_destinations")
        val tempFile = File(tempDir, "known_destinations.tmp")

        Identity.remember(packetHash, a, pubKey(1))
        Identity.saveKnownDestinations()
        assertTrue(finalFile.exists(), "first save must create the file")
        val first = finalFile.readBytes()

        Identity.remember(packetHash, b, pubKey(2))
        Identity.saveKnownDestinations()
        val second = finalFile.readBytes()

        assertFalse(first.contentEquals(second), "second save must replace the existing file")
        assertFalse(tempFile.exists(), "temp file must be moved, not left behind")

        // Round-trip: the replaced file holds both entries.
        Identity.clearKnownDestinations()
        Identity.loadKnownDestinations()
        assertTrue(Identity.isKnown(a))
        assertTrue(Identity.isKnown(b), "entry added before the second save must be on disk")
    }

    @Test
    fun `persisting a second ratchet replaces the on-disk ratchet file`() {
        val d = dest(0x63)
        val outFile = File(tempDir, "ratchets/${d.toHexString()}.out")

        Identity.rememberRatchet(d, ratchet(1))
        Identity.dropRatchetCacheForTest(d)
        assertArrayEquals(ratchet(1), Identity.getRatchet(d), "first ratchet must load from disk")

        Identity.rememberRatchet(d, ratchet(2))
        Identity.dropRatchetCacheForTest(d)
        assertArrayEquals(ratchet(2), Identity.getRatchet(d), "second ratchet must replace the file")
        assertFalse(outFile.exists(), ".out file must be moved, not left behind")
    }
}
