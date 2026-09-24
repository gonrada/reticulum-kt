package network.reticulum.crypto

import network.reticulum.common.AesMode
import network.reticulum.common.CryptoException
import network.reticulum.common.RnsConstants

/**
 * Modified Fernet token implementation for Reticulum.
 *
 * Based on the Fernet spec (https://github.com/fernet/spec/blob/master/Spec.md)
 * but without VERSION and TIMESTAMP fields to reduce overhead and metadata leakage.
 *
 * Token format: IV (16 bytes) || ciphertext || HMAC (32 bytes)
 *
 * Key structure:
 * - AES-128-CBC: 32-byte key (16 signing + 16 encryption)
 * - AES-256-CBC: 64-byte key (32 signing + 32 encryption)
 */
class Token(
    private val key: ByteArray,
    private val crypto: CryptoProvider = defaultCryptoProvider()
) {
    private val mode: AesMode
    private val signingKey: ByteArray
    private val encryptionKey: ByteArray

    // The offset/length forms are internal to BouncyCastleProvider, not on the
    // CryptoProvider interface; any other provider gets the sliced-copy path.
    private val bcCrypto: BouncyCastleProvider? = crypto as? BouncyCastleProvider

    init {
        when (key.size) {
            32 -> {
                mode = AesMode.AES_128_CBC
                signingKey = key.copyOfRange(0, 16)
                encryptionKey = key.copyOfRange(16, 32)
            }
            64 -> {
                mode = AesMode.AES_256_CBC
                signingKey = key.copyOfRange(0, 32)
                encryptionKey = key.copyOfRange(32, 64)
            }
            else -> throw IllegalArgumentException(
                "Token key must be 32 bytes (AES-128) or 64 bytes (AES-256), got ${key.size}"
            )
        }
    }

    /**
     * Encrypt plaintext and return token.
     *
     * @param plaintext Data to encrypt
     * @return Token: IV (16) || ciphertext || HMAC (32)
     */
    fun encrypt(plaintext: ByteArray): ByteArray {
        val iv = crypto.randomBytes(16)
        return encryptWithIv(plaintext, iv)
    }

    /**
     * Encrypt plaintext with a specific IV (for testing reproducibility).
     *
     * @param plaintext Data to encrypt
     * @param iv 16-byte initialization vector
     * @return Token: IV (16) || ciphertext || HMAC (32)
     */
    fun encryptWithIv(plaintext: ByteArray, iv: ByteArray): ByteArray {
        require(iv.size == 16) { "IV must be 16 bytes" }

        // python Token.encrypt: ciphertext = mode.encrypt(PKCS7.pad(data), ...)
        // — padding belongs to the Token layer, the AES layer is the bare
        // block cipher (Token.py:86-95). Byte-identical to a padded cipher on
        // encrypt; split out so decrypt can use python's LAX unpad.
        val ciphertext = crypto.aesEncryptNoPadding(PKCS7.pad(plaintext), encryptionKey, iv, mode)

        // token = IV || ciphertext || HMAC(IV || ciphertext), assembled in
        // place: the signed parts are the token's first 16 + ciphertext bytes.
        val signedLength = 16 + ciphertext.size
        val token = ByteArray(signedLength + 32)
        iv.copyInto(token, 0)
        ciphertext.copyInto(token, 16)
        hmacOver(token, 0, signedLength).copyInto(token, signedLength)
        return token
    }

    /** HMAC-SHA256(signingKey) over data[offset, offset + length). */
    private fun hmacOver(data: ByteArray, offset: Int, length: Int): ByteArray =
        bcCrypto?.hmacSha256(signingKey, data, offset, length)
            ?: crypto.hmacSha256(signingKey, data.copyOfRange(offset, offset + length))

    /** Bare AES-CBC decrypt of data[offset, offset + length) under encryptionKey. */
    private fun aesDecryptOver(data: ByteArray, offset: Int, length: Int, iv: ByteArray): ByteArray =
        bcCrypto?.aesDecryptNoPadding(data, offset, length, encryptionKey, iv, mode)
            ?: crypto.aesDecryptNoPadding(data.copyOfRange(offset, offset + length), encryptionKey, iv, mode)

    /**
     * Constant-time comparison of data[offset, offset + expected.size) with
     * expected: the same XOR-accumulate loop as ByteArray.constantTimeEquals,
     * without copying the range out first.
     */
    private fun constantTimeEqualsAt(data: ByteArray, offset: Int, expected: ByteArray): Boolean {
        if (data.size - offset != expected.size) return false
        var result = 0
        for (i in expected.indices) {
            result = result or (data[offset + i].toInt() xor expected[i].toInt())
        }
        return result == 0
    }

    /**
     * Verify the HMAC of a token.
     *
     * python Token.verify_hmac (Token.py:76-83): a token of 32 bytes or
     * fewer cannot carry both an HMAC and a body and is REJECTED by raise,
     * not by returning false.
     *
     * @param token The token to verify
     * @return true if HMAC is valid
     * @throws CryptoException if the token is 32 bytes or fewer
     */
    fun verifyHmac(token: ByteArray): Boolean {
        if (token.size <= 32) {
            throw CryptoException("Cannot verify HMAC on token of only ${token.size} bytes")
        }

        // HMAC over token[0, size-32); the received tag is the trailing 32 bytes.
        val signedLength = token.size - 32
        val expectedHmac = hmacOver(token, 0, signedLength)

        return constantTimeEqualsAt(token, signedLength, expectedHmac)
    }

    /**
     * Decrypt a token, mirroring python Token.decrypt (Token.py:98-114):
     * authenticate FIRST (verifyHmac, which raises on a <=32-byte token),
     * then bare-AES decrypt and python's LAX PKCS7 unpad; any failure in
     * that stage raises "Could not decrypt token".
     *
     * @param token Token: IV (16) || ciphertext || HMAC (32)
     * @return Decrypted plaintext
     * @throws CryptoException if HMAC verification fails or decryption fails
     */
    fun decrypt(token: ByteArray): ByteArray {
        if (!verifyHmac(token)) {
            throw CryptoException("Token HMAC was invalid")
        }

        val iv = token.copyOfRange(0, 16)
        // ciphertext = token[16, size-32), decrypted in place. An authenticated
        // token shorter than 48 bytes has no such range; reject it before the
        // try, as the former copyOfRange(16, size - 32) did.
        val ciphertextLength = token.size - 48
        require(ciphertextLength >= 0) { "Token of ${token.size} bytes carries no ciphertext" }

        return try {
            PKCS7.unpad(aesDecryptOver(token, 16, ciphertextLength, iv))
        } catch (e: Exception) {
            throw CryptoException("Could not decrypt token: ${e.message}", e)
        }
    }

    companion object {
        const val TOKEN_OVERHEAD = RnsConstants.TOKEN_OVERHEAD  // 48 bytes

        /**
         * Generate a new random token key.
         *
         * @param mode AES mode (determines key size)
         * @param crypto CryptoProvider to use
         * @return Random key suitable for Token
         */
        fun generateKey(
            mode: AesMode = AesMode.AES_256_CBC,
            crypto: CryptoProvider = defaultCryptoProvider()
        ): ByteArray {
            return when (mode) {
                AesMode.AES_128_CBC -> crypto.randomBytes(32)
                AesMode.AES_256_CBC -> crypto.randomBytes(64)
            }
        }
    }
}
