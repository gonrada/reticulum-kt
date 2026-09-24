package network.reticulum.interfaces.blekiss

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class BleKissProfileTest {

    @Test
    fun `resolves NUS by service uuid`() {
        assertEquals(BleKissProfile.NUS, BleKissProfile.byServiceUuid(NusLink.NUS_SERVICE_UUID))
    }

    @Test
    fun `resolves KTS by service uuid, case-insensitively`() {
        assertEquals(BleKissProfile.KTS, BleKissProfile.byServiceUuid("00000001-ba2a-46c9-ae49-01b0961f68bb"))
        assertEquals(BleKissProfile.KTS, BleKissProfile.byServiceUuid("00000001-BA2A-46C9-AE49-01B0961F68BB"))
    }

    @Test
    fun `unknown service uuid resolves to null`() {
        assertNull(BleKissProfile.byServiceUuid("0000abcd-0000-1000-8000-00805f9b34fb"))
    }

    @Test
    fun `NUS is detected before KTS`() {
        assertEquals(listOf(BleKissProfile.NUS, BleKissProfile.KTS), BleKissProfile.DETECTION_ORDER)
    }

    @Test
    fun `KTS uuids match the published KISS TNC Service triple`() {
        assertEquals("00000001-ba2a-46c9-ae49-01b0961f68bb", BleKissProfile.KTS.serviceUuid)
        assertEquals("00000002-ba2a-46c9-ae49-01b0961f68bb", BleKissProfile.KTS.rxCharUuid)
        assertEquals("00000003-ba2a-46c9-ae49-01b0961f68bb", BleKissProfile.KTS.txCharUuid)
    }

    @Test
    fun `each profile has three distinct uuids`() {
        for (p in BleKissProfile.entries) {
            assertEquals(3, setOf(p.serviceUuid, p.rxCharUuid, p.txCharUuid).size, "$p uuids must be distinct")
        }
    }
}
