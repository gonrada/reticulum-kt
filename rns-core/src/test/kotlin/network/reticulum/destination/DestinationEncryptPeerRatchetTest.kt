package network.reticulum.destination

import network.reticulum.common.DestinationDirection
import network.reticulum.common.DestinationType
import network.reticulum.common.RnsConstants
import network.reticulum.crypto.defaultCryptoProvider
import network.reticulum.identity.Identity
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.io.File
import java.nio.file.Files

/**
 * [Destination.encrypt] must consult the persisted peer-ratchet store when the
 * in-process announce cache has nothing for the destination. Without the
 * fallback, every send after a restart used the peer's static identity key
 * until its next announce was heard: forward secrecy lost, and a blackout
 * against a peer that enforces ratchets.
 */
class DestinationEncryptPeerRatchetTest {

    private lateinit var tempDir: File
    private lateinit var previousStoragePath: String
    private val touched = mutableListOf<ByteArray>()

    @BeforeEach
    fun setup() {
        tempDir = Files.createTempDirectory("rns-encrypt-peer-ratchet").toFile()
        previousStoragePath = Identity.storagePath
        Identity.setStoragePath(tempDir.absolutePath)
        Identity.identityStore = null
    }

    @AfterEach
    fun teardown() {
        touched.forEach {
            Identity.dropRatchetCacheForTest(it)
            Destination.clearRatchetForDestination(it)
        }
        Identity.setStoragePath(previousStoragePath)
        tempDir.deleteRecursively()
    }

    @Test
    fun `encrypt falls back to the persisted peer ratchet when the announce cache is empty`() {
        val crypto = defaultCryptoProvider()
        val peerIdentity = Identity.create()
        val receiver = Destination.create(
            identity = peerIdentity,
            direction = DestinationDirection.IN,
            type = DestinationType.SINGLE,
            appName = "ratchettest",
            aspects = arrayOf("encrypt-fallback"),
        )
        val ratchetPrivate = crypto.randomBytes(RnsConstants.KEY_SIZE)
        val ratchetPublic = crypto.x25519PublicFromPrivate(ratchetPrivate)
        receiver.addRatchet(ratchetPrivate)
        receiver.enforceRatchets = true

        // The sender knows the peer's identity and holds its ratchet only in the
        // persisted store: the announce cache and the in-memory ratchet cache are
        // both empty, as they are after a restart.
        val sender = Destination.create(
            identity = Identity.fromPublicKey(peerIdentity.getPublicKey()),
            direction = DestinationDirection.OUT,
            type = DestinationType.SINGLE,
            appName = "ratchettest",
            aspects = arrayOf("encrypt-fallback"),
        )
        touched += sender.hash
        Identity.rememberRatchet(sender.hash, ratchetPublic)
        Identity.dropRatchetCacheForTest(sender.hash)
        Destination.clearRatchetForDestination(sender.hash)
        assertNull(Destination.getRatchetForDestination(sender.hash))

        val ciphertext = sender.encrypt("ratchet-probe".toByteArray())

        assertArrayEquals(
            Identity.ratchetIdFor(ratchetPublic),
            sender.latestRatchetId,
            "the persisted ratchet's id must be recorded as the one used",
        )
        val plaintext = receiver.decrypt(ciphertext)
        assertNotNull(plaintext, "a receiver that enforces ratchets must be able to decrypt")
        assertArrayEquals("ratchet-probe".toByteArray(), plaintext)
    }
}
