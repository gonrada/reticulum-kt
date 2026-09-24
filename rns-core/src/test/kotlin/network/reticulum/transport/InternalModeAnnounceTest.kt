package network.reticulum.transport

import network.reticulum.common.InterfaceMode
import network.reticulum.config.InterfaceConfig
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * `MODE_INTERNAL` (python `Interface.py:51`, new in RNS 1.5.2) and the two knobs that do
 * its actual work.
 *
 * The mode is easy to over-read as a sealed boundary around a private segment. It is not,
 * and these tests pin the weaker behaviour the reference actually implements
 * (`Transport.py:1471`, `:1479-1489`):
 *
 *  - Announces learned on an internal interface DO leave by default. Containment is
 *    opt-in per outgoing interface via `announces_from_internal = false`.
 *  - An internal interface DOES carry announces for non-local destinations. It refuses
 *    only BOUNDARY-sourced ones, and an explicit `announces_to_internal = true` on the
 *    source overrides even that.
 *
 * Getting this backwards would make an operator believe a segment was contained when it
 * was not, which is worse than not having the mode at all.
 */
class InternalModeAnnounceTest {

    // --- egress: announces learned on an internal segment leaving the node ---

    @Test
    fun `internal-sourced announces leave by default`() {
        assertTrue(
            AnnounceFilter.shouldForward(
                outgoingMode = InterfaceMode.FULL,
                isLocalDestination = false,
                sourceMode = InterfaceMode.INTERNAL,
            ),
            "announces_from_internal defaults to true, so the reference forwards these",
        )
    }

    @Test
    fun `an outgoing interface can opt out of carrying internal-sourced announces`() {
        assertFalse(
            AnnounceFilter.shouldForward(
                outgoingMode = InterfaceMode.FULL,
                isLocalDestination = false,
                sourceMode = InterfaceMode.INTERNAL,
                outgoingAnnouncesFromInternal = false,
            ),
        )
    }

    @Test
    fun `the opt-out does not suppress our own destinations`() {
        // A local destination is ours to advertise; the knob is about not leaking the
        // internal segment's topology, not about going silent.
        assertTrue(
            AnnounceFilter.shouldForward(
                outgoingMode = InterfaceMode.FULL,
                isLocalDestination = true,
                sourceMode = InterfaceMode.INTERNAL,
                outgoingAnnouncesFromInternal = false,
            ),
        )
    }

    // --- ingress: announces being carried onto an internal interface ---

    @Test
    fun `an internal interface carries ordinary announces`() {
        assertTrue(
            AnnounceFilter.shouldForward(
                outgoingMode = InterfaceMode.INTERNAL,
                isLocalDestination = false,
                sourceMode = InterfaceMode.FULL,
            ),
            "internal mode is not a sealed membrane; only boundary sources are refused",
        )
    }

    @Test
    fun `an internal interface refuses boundary-sourced announces`() {
        assertFalse(
            AnnounceFilter.shouldForward(
                outgoingMode = InterfaceMode.INTERNAL,
                isLocalDestination = false,
                sourceMode = InterfaceMode.BOUNDARY,
            ),
        )
    }

    @Test
    fun `an explicit announces_to_internal overrides the boundary refusal`() {
        assertTrue(
            AnnounceFilter.shouldForward(
                outgoingMode = InterfaceMode.INTERNAL,
                isLocalDestination = false,
                sourceMode = InterfaceMode.BOUNDARY,
                sourceAnnouncesToInternal = true,
            ),
        )
    }

    @Test
    fun `null announces_to_internal is not false`() {
        // The reference tests `== True`, so null leaves the boundary rule in charge rather
        // than acting as a refusal of its own. Distinct states, deliberately.
        assertTrue(
            AnnounceFilter.shouldForward(
                outgoingMode = InterfaceMode.INTERNAL,
                isLocalDestination = false,
                sourceMode = InterfaceMode.FULL,
                sourceAnnouncesToInternal = null,
            ),
        )
    }

    @Test
    fun `an internal interface drops announces with no known source`() {
        assertFalse(
            AnnounceFilter.shouldForward(
                outgoingMode = InterfaceMode.INTERNAL,
                isLocalDestination = false,
                sourceMode = null,
            ),
        )
    }

    // --- mode plumbing ---

    @Test
    fun `internal carries python's wire value 0x07`() {
        assertEquals(0x07, InterfaceConfig.modeValue(InterfaceMode.INTERNAL))
        // The wire value is derived from the enum ordinal elsewhere in Transport, so a
        // reordering that put INTERNAL anywhere but last would silently renumber modes.
        assertEquals(0x07, InterfaceMode.INTERNAL.ordinal + 1)
    }

    @Test
    fun `config selects internal mode from either key`() {
        val viaMode = InterfaceConfig.synthesize(mapOf("type" to "TCPClientInterface", "mode" to "internal"))
        assertEquals(InterfaceMode.INTERNAL, viaMode.mode)

        // interface_mode resolves internal through c["mode"], the same upstream quirk that
        // applies to gateway (python Reticulum.py:776-779).
        val viaInterfaceMode = InterfaceConfig.synthesize(
            mapOf("type" to "TCPClientInterface", "interface_mode" to "internal", "mode" to "internal"),
        )
        assertEquals(InterfaceMode.INTERNAL, viaInterfaceMode.mode)
    }

    @Test
    fun `a discoverable internal interface is not promoted to gateway`() {
        // python Reticulum.py:928 lists INTERNAL alongside GATEWAY and ACCESS_POINT as
        // already relay-capable. Promoting it would discard the operator's mode and push
        // the segment's announces onto the public mesh.
        val syn = InterfaceConfig.synthesize(
            mapOf("type" to "TCPClientInterface", "mode" to "internal", "discoverable" to "true"),
        )
        assertEquals(InterfaceMode.INTERNAL, syn.mode)
        assertTrue(syn.discoverable)
    }

    @Test
    fun `config round-trips both announce knobs`() {
        val dflt = InterfaceConfig.synthesize(mapOf("type" to "TCPClientInterface"))
        assertTrue(dflt.announcesFromInternal, "python defaults announces_from_internal to true")
        assertEquals(null, dflt.announcesToInternal, "and announces_to_internal to null, not false")

        val set = InterfaceConfig.synthesize(
            mapOf(
                "type" to "TCPClientInterface",
                "announces_from_internal" to "no",
                "announces_to_internal" to "yes",
            ),
        )
        assertFalse(set.announcesFromInternal)
        assertEquals(true, set.announcesToInternal)
    }
}
