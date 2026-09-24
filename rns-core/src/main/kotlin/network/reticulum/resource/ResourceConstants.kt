package network.reticulum.resource

import network.reticulum.common.RnsConstants

/**
 * Constants for Resource operations, matching Python RNS Resource.py.
 */
object ResourceConstants {
    // Window sizes for flow control
    const val WINDOW = 4
    const val WINDOW_MIN = 2
    const val WINDOW_MAX_SLOW = 10
    const val WINDOW_MAX_VERY_SLOW = 4
    const val WINDOW_MAX_FAST = 75
    const val WINDOW_MAX = WINDOW_MAX_FAST
    const val FAST_RATE_THRESHOLD = WINDOW_MAX_SLOW - WINDOW - 2
    const val VERY_SLOW_RATE_THRESHOLD = 2

    // Rate thresholds (bytes per second)
    const val RATE_FAST = (50 * 1000) / 8  // 50 Kbps
    const val RATE_VERY_SLOW = (2 * 1000) / 8  // 2 Kbps

    const val WINDOW_FLEXIBILITY = 4

    // Hash and segment constants
    const val MAPHASH_LEN = 4
    const val RANDOM_HASH_SIZE = 4
    const val RESOURCE_HASH_LEN = 32  // Full hash (256 bits / 8)

    // Size limits
    const val MAX_EFFICIENT_SIZE = 1 * 1024 * 1024 - 1  // ~1MB
    const val RESPONSE_MAX_GRACE_TIME = 10
    const val METADATA_MAX_SIZE = 16 * 1024 * 1024 - 1  // ~16MB
    const val AUTO_COMPRESS_MAX_SIZE = 64 * 1024 * 1024  // 64MB

    // Receive-side bounds on split transfers. Python appends each completed segment to a
    // file under storagepath and sweeps it after RESOURCE_CACHE = 24 h (Resource.py:200,
    // 721-757; Reticulum.py:157, 1239-1245): the leak from an unfinished transfer is disk,
    // bounded by free space. This port accumulates on the heap, so the same construction
    // — a peer that keeps sending segment 1 of a transfer it never finishes, each one a
    // ~4 KB bz2 stream that inflates to exactly AUTO_COMPRESS_MAX_SIZE — retained 64 MiB
    // per ~15 packets with no ceiling. These are the
    // ceiling. They are generous for LXMF traffic and small next to the OOM they replace;
    // python has no equivalent because disk does not need one.
    /** Idle time after which a partial accumulation is discarded (python RESOURCE_CACHE). */
    const val SEGMENT_ACCUMULATOR_MAX_IDLE_MS = 24L * 60 * 60 * 1000
    /** Largest reassembled payload one split transfer may grow to on this receiver. */
    const val MAX_ACCUMULATED_TRANSFER_SIZE = 128L * 1024 * 1024
    /** Largest total held across all partial accumulations on one link. */
    const val MAX_ACCUMULATED_LINK_SIZE = 256L * 1024 * 1024

    // Timeout factors
    const val PART_TIMEOUT_FACTOR = 4
    const val PART_TIMEOUT_FACTOR_AFTER_RTT = 2
    const val PROOF_TIMEOUT_FACTOR = 3
    const val MAX_RETRIES = 16
    const val MAX_ADV_RETRIES = 4
    const val SENDER_GRACE_TIME = 10.0
    const val PROCESSING_GRACE = 1.0
    const val RETRY_GRACE_TIME = 0.25
    const val PER_RETRY_DELAY = 0.5
    /** python `HMU_WAIT_FACTOR` (Resource.py:130): hashmap-update allowance in the receiver's part timeout. */
    const val HMU_WAIT_FACTOR = 3.5

    const val WATCHDOG_MAX_SLEEP = 1L

    // Hashmap status flags
    const val HASHMAP_IS_NOT_EXHAUSTED = 0x00
    const val HASHMAP_IS_EXHAUSTED = 0xFF

    // Resource status constants
    const val NONE = 0x00
    const val QUEUED = 0x01
    const val ADVERTISED = 0x02
    const val TRANSFERRING = 0x03
    const val AWAITING_PROOF = 0x04
    const val ASSEMBLING = 0x05
    const val COMPLETE = 0x06
    const val FAILED = 0x07
    const val CORRUPT = 0x08

    /**
     * A resource the receiver refused (python `Resource.REJECTED`, `Resource.py:153`).
     *
     * Through RNS 1.3.1 this was 0x00, the same value as [NONE]. That collision made a
     * rejected resource indistinguishable from one that had never started: a caller
     * testing `status == REJECTED` saw true on a freshly constructed resource, and one
     * testing `status == NONE` read a refusal as "not begun". RNS 1.5.2 moved it to 0x09.
     */
    const val REJECTED = 0x09

    // Resource flags
    const val FLAG_ENCRYPTED = 0x01
    const val FLAG_COMPRESSED = 0x02

    /**
     * Calculate the SDU (Service Data Unit) size for resources.
     * This is the maximum amount of data that can fit in one resource part.
     * Resource parts are sent as raw packets (already bulk-encrypted), so
     * only packet header + IFAC overhead applies — not Token encryption overhead.
     * Python: Resource.SDU = RNS.Packet.MDU = RNS.Reticulum.MDU
     */
    fun calculateSdu(mtu: Int = RnsConstants.MTU): Int {
        return mtu - RnsConstants.HEADER_MAX_SIZE - RnsConstants.IFAC_MIN_SIZE
    }

    /**
     * Get status description string.
     */
    fun statusDescription(status: Int): String {
        return when (status) {
            NONE -> "NONE"
            QUEUED -> "QUEUED"
            ADVERTISED -> "ADVERTISED"
            TRANSFERRING -> "TRANSFERRING"
            AWAITING_PROOF -> "AWAITING_PROOF"
            ASSEMBLING -> "ASSEMBLING"
            COMPLETE -> "COMPLETE"
            FAILED -> "FAILED"
            CORRUPT -> "CORRUPT"
            REJECTED -> "REJECTED"
            else -> "UNKNOWN_STATUS_$status"
        }
    }
}
