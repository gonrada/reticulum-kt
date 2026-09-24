@file:Suppress("NOTHING_TO_INLINE")

package network.reticulum.common

/**
 * Extension functions for byte array manipulation.
 * These are critical for wire format compatibility.
 */

private val HEX_DIGITS = "0123456789abcdef".toCharArray()

/**
 * Convert a ByteArray to a lowercase hex string.
 *
 * Direct nibble lookup rather than `"%02x".format(it)` per byte — the former allocated a
 * java.util.Formatter (and, parsing the "%02x" spec, a regex Matcher) plus buffers on every
 * byte. Hex conversion is on hot paths (every log line, hexHash, dedup keys), and JFR put the
 * old form at the top of the announce-path allocation profile. Output is byte-identical.
 */
fun ByteArray.toHexString(): String {
    val out = CharArray(size * 2)
    var i = 0
    for (b in this) {
        val v = b.toInt() and 0xFF
        out[i++] = HEX_DIGITS[v ushr 4]
        out[i++] = HEX_DIGITS[v and 0x0F]
    }
    return String(out)
}

/**
 * Convert a hex string to ByteArray.
 *
 * Index loop with [Character.digit] rather than `chunked(2).map { .. }.toByteArray()`,
 * which built a List<String> of 2-char substrings and a boxed List<Byte> per call.
 *
 * @throws IllegalArgumentException on odd length or a non-hex character.
 */
fun String.hexToByteArray(): ByteArray {
    require(length % 2 == 0) { "Hex string must have even length" }
    val out = ByteArray(length / 2)
    var i = 0
    while (i < length) {
        val hi = Character.digit(this[i], 16)
        val lo = Character.digit(this[i + 1], 16)
        require(hi >= 0 && lo >= 0) { "Invalid hex digit at index $i" }
        out[i shr 1] = ((hi shl 4) or lo).toByte()
        i += 2
    }
    return out
}

/**
 * Compare two byte arrays for equality in constant time.
 * This prevents timing attacks when comparing sensitive data.
 */
fun ByteArray.constantTimeEquals(other: ByteArray): Boolean {
    if (this.size != other.size) return false
    var result = 0
    for (i in indices) {
        result = result or (this[i].toInt() xor other[i].toInt())
    }
    return result == 0
}

/**
 * XOR two byte arrays. Arrays must be the same length.
 */
fun ByteArray.xor(other: ByteArray): ByteArray {
    require(this.size == other.size) { "Arrays must be same length for XOR" }
    return ByteArray(size) { i -> (this[i].toInt() xor other[i].toInt()).toByte() }
}

/**
 * Concatenate multiple byte arrays.
 */
fun concatBytes(vararg arrays: ByteArray): ByteArray {
    val totalLength = arrays.sumOf { it.size }
    val result = ByteArray(totalLength)
    var offset = 0
    for (array in arrays) {
        array.copyInto(result, offset)
        offset += array.size
    }
    return result
}

/**
 * Slice a byte array (like Python's array[start:end]).
 */
fun ByteArray.slice(start: Int, end: Int = size): ByteArray {
    require(start >= 0 && end <= size && start <= end) {
        "Invalid slice: start=$start, end=$end, size=$size"
    }
    return copyOfRange(start, end)
}

/**
 * Read a 16-bit unsigned integer from big-endian bytes at offset.
 */
fun ByteArray.readUInt16BE(offset: Int = 0): Int {
    return ((this[offset].toInt() and 0xFF) shl 8) or
            (this[offset + 1].toInt() and 0xFF)
}

/**
 * Read a 32-bit unsigned integer from big-endian bytes at offset.
 */
fun ByteArray.readUInt32BE(offset: Int = 0): Long {
    return ((this[offset].toInt() and 0xFF).toLong() shl 24) or
            ((this[offset + 1].toInt() and 0xFF).toLong() shl 16) or
            ((this[offset + 2].toInt() and 0xFF).toLong() shl 8) or
            (this[offset + 3].toInt() and 0xFF).toLong()
}

/**
 * Write a 16-bit unsigned integer as big-endian bytes.
 */
fun Int.toBytesBE16(): ByteArray {
    return byteArrayOf(
        ((this shr 8) and 0xFF).toByte(),
        (this and 0xFF).toByte()
    )
}

/**
 * Write a 32-bit unsigned integer as big-endian bytes.
 */
fun Long.toBytesBE32(): ByteArray {
    return byteArrayOf(
        ((this shr 24) and 0xFF).toByte(),
        ((this shr 16) and 0xFF).toByte(),
        ((this shr 8) and 0xFF).toByte(),
        (this and 0xFF).toByte()
    )
}

/**
 * Convert a Long to little-endian bytes (32 bytes, for X25519).
 * This is critical for X25519 compatibility with Python.
 */
fun Long.toLittleEndianBytes32(): ByteArray {
    val result = ByteArray(32)
    var value = this
    for (i in 0 until 8) {
        result[i] = (value and 0xFF).toByte()
        value = value shr 8
    }
    return result
}

/**
 * Read bytes as a little-endian BigInteger.
 * Used for X25519 key operations.
 */
fun ByteArray.toLittleEndianBigInteger(): java.math.BigInteger {
    // Reverse and add leading zero to ensure positive
    val reversed = this.reversedArray()
    val positive = ByteArray(reversed.size + 1)
    reversed.copyInto(positive, 1)
    return java.math.BigInteger(positive)
}

/**
 * Convert BigInteger to little-endian bytes with specified length.
 * Used for X25519 key operations.
 */
fun java.math.BigInteger.toLittleEndianBytes(length: Int): ByteArray {
    val bytes = this.toByteArray()
    val result = ByteArray(length)

    // BigInteger uses big-endian and may have leading zero
    val start = if (bytes.size > length && bytes[0] == 0.toByte()) 1 else 0
    val toCopy = minOf(bytes.size - start, length)

    // Copy in reverse order for little-endian
    for (i in 0 until toCopy) {
        result[i] = bytes[bytes.size - 1 - i]
    }

    return result
}

/**
 * Wrapper for ByteArray to use as Map key with proper equality.
 */
class ByteArrayKey(val bytes: ByteArray) {
    // Computed once at construction. These keys live in many ConcurrentHashMaps / key-sets
    // (path/link/reverse/announce tables, dedup hashlists, receipts, tunnels, the destination
    // index...), so hashCode() is called on every put/get/contains; recomputing
    // contentHashCode() each time was pure waste. Safe because a map key's backing array must
    // not be mutated after use (contentEquals would break too) — the same immutability this
    // class already assumes.
    private val hash: Int = bytes.contentHashCode()

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is ByteArrayKey) return false
        return bytes.contentEquals(other.bytes)
    }

    override fun hashCode(): Int = hash

    override fun toString(): String = bytes.toHexString()
}

/**
 * Convert ByteArray to ByteArrayKey for use as Map key.
 */
fun ByteArray.toKey(): ByteArrayKey = ByteArrayKey(this)
