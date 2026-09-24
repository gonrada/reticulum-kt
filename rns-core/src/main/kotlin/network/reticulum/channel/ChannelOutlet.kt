package network.reticulum.channel

/**
 * Interface for the underlying transport used by a Channel.
 * Typically implemented by Link to provide encrypted delivery.
 */
interface ChannelOutlet {
    /**
     * Send raw bytes over the outlet.
     * @param raw The data to send
     * @return An opaque packet identifier for tracking
     */
    fun send(raw: ByteArray): Any?

    /**
     * Resend a previously sent packet.
     * @param packet The packet to resend
     * @return The new packet identifier
     */
    fun resend(packet: Any): Any?

    /**
     * Maximum data unit size for this outlet.
     */
    val mdu: Int

    /**
     * Current round-trip time estimate in milliseconds.
     */
    val rtt: Long?

    /**
     * Whether the outlet is currently usable.
     */
    val isUsable: Boolean

    /**
     * Whether the underlying transport has gone away for good, so no later send
     * can succeed. A full send window or a transport that is still coming up is
     * NOT closed — those recover.
     *
     * Separate from [isUsable] because the Link outlet reports itself usable
     * unconditionally, mirroring python `LinkChannelOutlet.is_usable`
     * (Channel.py:579), so readiness alone cannot tell a transient refusal from
     * a terminal one. Defaults to the inverse of [isUsable] for outlets that do
     * report readiness honestly.
     */
    val isClosed: Boolean get() = !isUsable

    /**
     * Whether the outlet has timed out.
     */
    val timedOut: Boolean

    /**
     * Get the current state of a packet.
     * @param packet The packet to check
     * @return The message state
     */
    fun getPacketState(packet: Any): Int

    /**
     * Set a callback for when a packet times out.
     */
    fun setPacketTimeoutCallback(packet: Any, callback: ((Any) -> Unit)?, timeout: Long? = null)

    /**
     * Set a callback for when a packet is delivered.
     */
    fun setPacketDeliveredCallback(packet: Any, callback: ((Any) -> Unit)?)

    /**
     * Get an identifier for a packet.
     */
    fun getPacketId(packet: Any): Any

    /**
     * Notify the outlet that the channel has exhausted its retransmission
     * budget for an envelope. Mirrors python RNS LinkChannelOutlet.timed_out()
     * (Channel.py:707-708), which tears the underlying Link down. The default
     * is a no-op so non-Link outlets (test stubs) need not implement it.
     */
    fun notifyTimedOut() {}
}
