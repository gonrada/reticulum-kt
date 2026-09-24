package network.reticulum.link

import org.msgpack.core.MessagePack
import org.msgpack.core.MessagePacker
import org.msgpack.core.MessageUnpacker
import org.msgpack.value.ValueType
/**
 * The msgpack value conventions shared by link requests and responses.
 *
 * python packs a request as `[time, path_hash, data]` and a response as
 * `[request_id, response]` with `data` and `response` being whatever value the
 * caller supplied (`Link.py:481`, `Link.py:864`). Kotlin represents a received
 * value as `ByteArray?` on both sides, so one decoding rule serves both:
 *
 * - nil → null
 * - bin, str → the raw bytes
 * - anything else (array, map, int, bool, float) → the msgpack encoding of the
 *   value, for the receiver to decode with its own schema
 *
 * Sending goes through [packValue], which maps Kotlin types to their msgpack
 * types so the python side receives native lists, ints and bools.
 */
internal object RequestWire {
    /** Pack a Kotlin value as its msgpack type; ByteArray is a bin, unknown types are `toString()`ed. */
    fun packValue(
        packer: MessagePacker,
        value: Any?,
    ) {
        when (value) {
            null -> packer.packNil()
            is ByteArray -> {
                packer.packBinaryHeader(value.size)
                packer.writePayload(value)
            }
            is String -> packer.packString(value)
            is Int -> packer.packInt(value)
            is Long -> packer.packLong(value)
            is Boolean -> packer.packBoolean(value)
            is Float -> packer.packFloat(value)
            is Double -> packer.packDouble(value)
            is Map<*, *> -> {
                packer.packMapHeader(value.size)
                for ((k, v) in value) {
                    packValue(packer, k)
                    packValue(packer, v)
                }
            }
            is List<*> -> {
                packer.packArrayHeader(value.size)
                for (item in value) packValue(packer, item)
            }
            else -> packer.packString(value.toString())
        }
    }

    /** Pack `[requestId, response]` as python `Link.handle_request` does (`Link.py:864`). */
    fun packResponse(
        requestId: ByteArray,
        response: Any?,
    ): ByteArray {
        val packer = MessagePack.newDefaultBufferPacker()
        packer.packArrayHeader(2)
        packer.packBinaryHeader(requestId.size)
        packer.writePayload(requestId)
        packValue(packer, response)
        val packed = packer.toByteArray()
        packer.close()
        return packed
    }

    /**
     * Read the next value of [unpacker] (positioned inside [input]) into the
     * `ByteArray?` form handlers and receipts carry: nil as null, bin and str as
     * their payload, anything else as the value's own bytes, sliced out of [input]
     * by span. Nothing is ever built into a tree: `skipValue` walks nested arrays
     * and maps iteratively, so a request nested a hundred thousand levels deep
     * costs a loop, not a stack. The caller must already have bounded the declared
     * lengths against the input (the `Link` unpackers do this with the same
     * non-allocating skip).
     */
    fun valueToBytes(
        unpacker: MessageUnpacker,
        input: ByteArray,
    ): ByteArray? {
        val format = unpacker.nextFormat
        return when (format.valueType) {
            ValueType.NIL -> {
                unpacker.unpackNil()
                null
            }
            ValueType.BINARY, ValueType.STRING -> {
                val declared = if (format.valueType == ValueType.BINARY) unpacker.unpackBinaryHeader() else unpacker.unpackRawStringHeader()
                val remaining = input.size - unpacker.totalReadBytes
                require(declared in 0..remaining) { "value length $declared exceeds remaining input ($remaining bytes)" }
                unpacker.readPayload(declared)
            }
            else -> {
                val start = unpacker.totalReadBytes.toInt()
                unpacker.skipValue()
                val end = unpacker.totalReadBytes.toInt()
                require(start in 0..end && end <= input.size) { "value span $start..$end outside input" }
                input.copyOfRange(start, end)
            }
        }
    }
}
