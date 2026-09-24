package network.reticulum.transport

import network.reticulum.common.DestinationDirection
import network.reticulum.common.DestinationType
import network.reticulum.destination.Destination
import network.reticulum.identity.Identity
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

/**
 * registerDestination must only add IN (local) destinations to the local-destination
 * table, matching Python register_destination (Transport.py:2898). An OUT destination —
 * created whenever we send to a remote peer — must NOT land there: if it does, the peer
 * is mis-classified as a local destination and its subsequent announces are skipped
 * (isLocalDestination), so its path/identity are never refreshed.
 */
class RegisterDestinationDirectionTest {

    @BeforeEach
    fun setup() {
        try { Transport.stop() } catch (_: Exception) {}
        Transport.start(Identity.create(), enableTransport = false)
    }

    @AfterEach
    fun teardown() {
        try { Transport.stop() } catch (_: Exception) {}
    }

    @Test
    fun `an OUT destination is not registered as local`() {
        val out = Destination.create(
            identity = Identity.create(),
            direction = DestinationDirection.OUT,
            type = DestinationType.SINGLE,
            appName = "registerdirtest",
            aspects = arrayOf("peer"),
        )

        Transport.registerDestination(out)

        // Root cause of the announce-suppression bug: the OUT peer must not be treated
        // as a local destination. findDestination reads the same list that
        // isLocalDestination (the announce skip) checks, so a null result here means the
        // peer's announces are no longer skipped.
        assertNull(
            Transport.findDestination(out.hash),
            "an OUT destination must not enter the local-destination table",
        )
    }

    @Test
    fun `an IN destination is registered as local`() {
        val inDest = Destination.create(
            identity = Identity.create(),
            direction = DestinationDirection.IN,
            type = DestinationType.SINGLE,
            appName = "registerdirtest",
            aspects = arrayOf("local"),
        )

        Transport.registerDestination(inDest)

        assertNotNull(
            Transport.findDestination(inDest.hash),
            "an IN destination must be registered as local",
        )
    }
}
