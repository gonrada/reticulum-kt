package network.reticulum.destination

import network.reticulum.common.DestinationDirection
import network.reticulum.common.DestinationType
import network.reticulum.identity.Identity
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.msgpack.core.MessagePack
import java.io.File
import java.io.IOException
import java.nio.file.Files

/**
 * The ratchet-file loader reads declared lengths before the file's signature is
 * checked, so every declared length must be bounded by the bytes it is read
 * from. Unbounded, a corrupt header claiming gigabytes was allocated before it
 * was found to be short, and the allocation failure is an error no caller
 * catches.
 */
class DestinationRatchetFileBoundsTest {

    private val tempDirs = mutableListOf<File>()

    @AfterEach
    fun cleanup() {
        tempDirs.forEach { runCatching { it.deleteRecursively() } }
        tempDirs.clear()
    }

    private fun destinationWithFile(bytes: ByteArray, identity: Identity): Pair<Destination, String> {
        val dir = Files.createTempDirectory("ratchet_file_bounds_").toFile()
        tempDirs += dir
        val file = File(dir, "ratchets.bin")
        file.writeBytes(bytes)
        val dest = Destination.create(
            identity = identity,
            direction = DestinationDirection.IN,
            type = DestinationType.SINGLE,
            appName = "ratchettest",
            aspects = arrayOf("file-bounds"),
        )
        return dest to file.absolutePath
    }

    @Test
    fun `an outer length larger than the file is rejected before allocation`() {
        val packer = MessagePack.newDefaultBufferPacker()
        packer.packMapHeader(1)
        packer.packString("signature")
        packer.packBinaryHeader(Int.MAX_VALUE)
        packer.close()
        val (dest, path) = destinationWithFile(packer.toByteArray(), Identity.create())

        val error = assertThrows(IOException::class.java) { dest.enableRatchets(path) }
        assertTrue(error.message!!.contains("exceeds the file"), error.message)
    }

    @Test
    fun `an entry length larger than the signed payload is rejected before allocation`() {
        val identity = Identity.create()
        val inner = MessagePack.newDefaultBufferPacker()
        inner.packArrayHeader(1)
        inner.packBinaryHeader(Int.MAX_VALUE)
        inner.close()
        val packed = inner.toByteArray()
        val signature = identity.sign(packed)

        val outer = MessagePack.newDefaultBufferPacker()
        outer.packMapHeader(2)
        outer.packString("signature")
        outer.packBinaryHeader(signature.size)
        outer.writePayload(signature)
        outer.packString("ratchets")
        outer.packBinaryHeader(packed.size)
        outer.writePayload(packed)
        outer.close()
        val (dest, path) = destinationWithFile(outer.toByteArray(), identity)

        val error = assertThrows(IOException::class.java) { dest.enableRatchets(path) }
        assertTrue(error.message!!.contains("exceeds the payload"), error.message)
    }
}
