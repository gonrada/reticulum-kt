package network.reticulum.interfaces.kiss

import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import network.reticulum.interfaces.framing.KISS
import network.reticulum.interfaces.spp.SppConnection
import network.reticulum.interfaces.spp.SppDevice
import network.reticulum.interfaces.spp.SppDriver
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Assertions.fail
import org.junit.jupiter.api.Test
import java.io.PipedInputStream
import java.io.PipedOutputStream
import java.util.UUID
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicInteger

/** A fake SppDriver that hands back one prebuilt connection (piped streams). */
private class FakeSppDriver(private val conn: SppConnection) : SppDriver {
    private val _connectCalls = AtomicInteger(0)
    val connectCalls: Int get() = _connectCalls.get()

    override suspend fun connect(address: String, secure: Boolean): SppConnection {
        _connectCalls.incrementAndGet()
        return conn
    }

    override suspend fun accept(serviceName: String, uuid: UUID, secure: Boolean): SppConnection =
        throw UnsupportedOperationException("not used in this test")

    override fun cancelAccept() {}
    override fun listPairedDevices(): List<SppDevice> = emptyList()
    override fun shutdown() {}
}

class SppKissSerialPortTest {

    private val live = mutableListOf<KissInterface>()

    @AfterEach
    fun tearDown() {
        live.forEach { it.detach() }
        live.clear()
    }

    private suspend fun waitUntil(description: String, condition: () -> Boolean) {
        try {
            withTimeout(3_000) { while (!condition()) delay(5) }
        } catch (e: TimeoutCancellationException) {
            fail<Unit>("timed out waiting for: $description")
        }
    }

    @Test
    fun `KissInterface round-trips over an SppDriver and closes the socket on detach`() = runBlocking {
        // TNC -> interface (reads) and interface -> TNC (writes) via piped streams.
        val tncOut = PipedOutputStream()
        val adapterIn = PipedInputStream(tncOut, 8192)
        val adapterOut = PipedOutputStream()
        val tncIn = PipedInputStream(adapterOut, 8192)

        val closeCount = AtomicInteger(0)
        val conn = SppConnection(
            inputStream = adapterIn,
            outputStream = adapterOut,
            remoteAddress = "AA:BB:CC:DD:EE:FF",
            remoteName = "TestTNC",
            close = { closeCount.incrementAndGet() },
        )
        val driver = FakeSppDriver(conn)
        val port = SppKissSerialPort.create(driver, "AA:BB:CC:DD:EE:FF")

        val received = CopyOnWriteArrayList<ByteArray>()
        val iface = KissInterface(name = "spp-kiss-test", port = port, reconnectIntervalMs = 50L)
        live += iface
        iface.onPacketReceived = { data, _ -> received.add(data) }
        iface.start()
        waitUntil("online") { iface.online.value }
        assertTrue(driver.connectCalls >= 1)

        // RX: the TNC sends a KISS frame over RFCOMM; the interface delivers the payload.
        val rx = "hello".toByteArray()
        tncOut.write(KISS.frame(rx, KISS.CMD_DATA)); tncOut.flush()
        waitUntil("frame received") { received.isNotEmpty() }
        assertArrayEquals(rx, received[0])

        // TX: the interface sends; the raw KISS frame appears on the TNC side.
        val tx = "hi".toByteArray()
        val expected = KISS.frame(tx, KISS.CMD_DATA)
        iface.processOutgoing(tx)
        waitUntil("frame on the TNC side") { tncIn.available() >= expected.size }
        val buf = ByteArray(expected.size)
        var read = 0
        while (read < expected.size) {
            val n = tncIn.read(buf, read, expected.size - read)
            if (n <= 0) break
            read += n
        }
        assertArrayEquals(expected, buf)

        // Detach must close the RFCOMM socket via the connection's own close lambda.
        iface.detach()
        waitUntil("socket closed") { closeCount.get() >= 1 }
    }
}
