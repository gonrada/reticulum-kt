package network.reticulum.crypto

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test

/**
 * Pins HKDF behaviour against the python reference.
 *
 * python HKDF.py:44-45 reads `if derive_from == None or derive_from == "": raise
 * ValueError(...)`, and in python `b"" == ""` is False, so that guard fires only for
 * None — empty *bytes* derive a real key. Verified by running the reference on 1.3.1 and
 * 1.5.2: hkdf(derive_from=b"") returns a key; hkdf(derive_from=None) raises. A literal
 * transcription of the guard rejected empty bytes and diverged from the reference; the
 * conformance suite's `test_hkdf_accepts_empty_bytes_ikm` pins the same rule.
 */
class HkdfGuardTest {
    private val crypto = BouncyCastleProvider()

    @Test
    fun `accepts empty input keying material, as python does`() {
        val out = crypto.hkdf(length = 32, ikm = ByteArray(0), salt = ByteArray(16) { 1 }, info = null)
        assertEquals(32, out.size, "empty-bytes IKM must derive a key, not throw")
    }

    @Test
    fun `still rejects a non-positive output length`() {
        assertThrows(IllegalArgumentException::class.java) {
            crypto.hkdf(length = 0, ikm = ByteArray(32) { 1 }, salt = null, info = null)
        }
    }

    @Test
    fun `a non-null empty salt derives identically to a null salt`() {
        val ikm = ByteArray(32) { it.toByte() }
        val nullSalt = crypto.hkdf(length = 32, ikm = ikm, salt = null, info = null)
        val emptySalt = crypto.hkdf(length = 32, ikm = ikm, salt = ByteArray(0), info = null)
        assertArrayEquals(nullSalt, emptySalt, "empty salt must be zero-substituted like null")
    }

    @Test
    fun `derives the requested output length`() {
        val out = crypto.hkdf(length = 48, ikm = ByteArray(32) { 7 }, salt = ByteArray(16) { 2 }, info = ByteArray(4) { 3 })
        assertEquals(48, out.size)
    }
}
