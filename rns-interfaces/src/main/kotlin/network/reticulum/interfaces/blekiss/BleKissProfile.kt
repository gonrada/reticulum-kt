package network.reticulum.interfaces.blekiss

/**
 * A BLE GATT profile that carries a transparent, KISS-framed byte stream: one
 * service, one write characteristic (app → TNC) and one notify characteristic
 * (TNC → app). The known profiles are structurally identical and differ only in
 * their UUIDs, so the BLE transport is parameterised over them and the peripheral's
 * profile is auto-detected at connect time — rather than forking the transport.
 *
 * - [NUS] Nordic UART Service: R1 / RNode-class BLE TNCs.
 * - [KTS] KISS TNC Service: the published BLE-KISS profile (e.g. Mobilinkd TNC4).
 *
 * The KTS spec directs implementers to buffer "as if the buffer was being filled
 * from a serial line", which is exactly what [BleKissInterface] does above this seam,
 * so no profile-specific deframing is required.
 */
enum class BleKissProfile(
    val serviceUuid: String,
    /** Write TO the peripheral (app → TNC). */
    val rxCharUuid: String,
    /** Notify FROM the peripheral (TNC → app). */
    val txCharUuid: String,
) {
    NUS(
        NusLink.NUS_SERVICE_UUID,
        NusLink.NUS_RX_CHAR_UUID,
        NusLink.NUS_TX_CHAR_UUID,
    ),
    KTS(
        "00000001-ba2a-46c9-ae49-01b0961f68bb",
        "00000002-ba2a-46c9-ae49-01b0961f68bb",
        "00000003-ba2a-46c9-ae49-01b0961f68bb",
    );

    companion object {
        /**
         * Auto-detection order. NUS is tried first so the existing default is
         * unchanged; KTS is tried next for TNC4-class peripherals.
         */
        val DETECTION_ORDER: List<BleKissProfile> = listOf(NUS, KTS)

        /** The profile whose service UUID matches [uuid] (case-insensitive), or null. */
        fun byServiceUuid(uuid: String): BleKissProfile? =
            DETECTION_ORDER.firstOrNull { it.serviceUuid.equals(uuid, ignoreCase = true) }
    }
}
