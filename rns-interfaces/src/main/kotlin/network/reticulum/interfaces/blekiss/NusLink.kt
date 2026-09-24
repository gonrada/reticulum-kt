package network.reticulum.interfaces.blekiss

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.StateFlow

/**
 * Transport seam for a Nordic UART Service (NUS) BLE link to a KISS TNC.
 *
 * Mirrors a Python `BLEConnection` transport (not part of the reference): it hides the GATT/central details
 * (connect to a peripheral's NUS, write to the RX characteristic
 * `6e400002-…`, receive notifications from the TX characteristic `6e400003-…`,
 * negotiate MTU) behind a small message-oriented contract, so the KISS logic in
 * [BleKissInterface] stays pure and unit-testable without a radio.
 *
 * The Android implementation wraps `BluetoothGatt`; tests use an in-memory fake.
 * BLE GATT is message-oriented — each notification and each write is a discrete
 * chunk — so this contract is message-based, not stream-based.
 */
interface NusLink {
    /** Standard Nordic UART Service UUIDs. */
    companion object {
        const val NUS_SERVICE_UUID = "6e400001-b5a3-f393-e0a9-e50e24dcca9e"
        const val NUS_RX_CHAR_UUID = "6e400002-b5a3-f393-e0a9-e50e24dcca9e" // write TO peripheral
        const val NUS_TX_CHAR_UUID = "6e400003-b5a3-f393-e0a9-e50e24dcca9e" // notify FROM peripheral
    }

    /** Notifications received from the peripheral's NUS TX characteristic. */
    val incoming: Flow<ByteArray>

    /** Whether the GATT link is currently connected. */
    val connected: StateFlow<Boolean>

    /**
     * Connect to the peripheral and enable NUS TX notifications.
     * @return true once connected and ready, false on timeout/failure.
     */
    suspend fun connect(timeoutMs: Long): Boolean

    /**
     * Write one already-KISS-framed payload to the NUS RX characteristic.
     * Implementations chunk to the negotiated ATT MTU internally.
     * @return true if the write completed, false on failure (which triggers a
     *   reconnect in [BleKissInterface]).
     */
    suspend fun write(frame: ByteArray): Boolean

    /** Tear down the GATT link. Must be idempotent and must not throw. */
    suspend fun close()
}
