# Python Reference Implementation Deviations

This document summarises intentional behavioral differences between the
Kotlin (reticulum-kt) implementation and the Python reference (RNS).
Each entry explains **what** differs, **why**, and the **risk**.

Python is always the ground truth. The **authoritative, complete list** of
deviations, one entry per divergence with the reference line it departs
from, is [`port-deviations.md`](port-deviations.md); the three entries below
are the original ones and are kept for their longer rationale. Deviations
are temporary workarounds or conscious trade-offs, not design choices.

---

## Transport: Stale Path Entry Removal on Outbound

**Python behavior** (`Transport.py:load_path_table`):
When loading persisted paths on startup, Python resolves the stored
interface hash to a live interface object. If `find_interface_from_hash()`
returns `None`, the path entry is simply not loaded (line 105:
"The interface is no longer available").

**Kotlin behavior** (`Transport.kt:processOutbound`):
Kotlin loads all persisted paths regardless of interface availability.
During outbound routing, if `findInterfaceByHash()` returns null for
a path entry, Kotlin removes the stale entry from the path table at
that point and falls through to broadcast.

**Why**: Kotlin's path persistence loads paths before all interfaces
are registered (AutoInterface/discovered interfaces register later).
Filtering at load time would discard valid paths for interfaces that
haven't connected yet.

**Risk**: Low. The end result is the same — stale paths are eventually
removed. The timing differs (Python: at load; Kotlin: at first use).

**Resolution**: Add a deferred path validation pass after all interfaces
are registered, matching Python's load-time filtering.

**Status (2026-09)**: the read APIs (`hasPath`, `hopsTo`, `nextHop`) now treat a
restored entry whose interface is not registered as absent once at least one
interface has registered, so the reference's invariant ("a usable path
references a live interface") holds at the point of use without racing
asynchronous interface registration. See `port-deviations.md`.

---

## LXMRouter: Ratchet Self-Storage Removed from generateAnnounceData

**Python behavior** (`Destination.py:announce()`):
Python does NOT store the ratchet public key under the local
destination's hash during announce generation. The ratchet public
key is only stored by REMOTE nodes that receive the announce.

**Kotlin behavior (before fix)**:
`generateAnnounceData()` called `setRatchetForDestination(hash, ratchetPub)`
and `Identity.rememberRatchet(hash, ratchetPub)`, storing the ratchet
public key under the local destination hash. This confused the
`Destination.encrypt()` path because `Identity.get_ratchet(destHash)`
would find a public key for a LOCAL destination and use it instead
of the identity's base key.

**Kotlin behavior (after fix)**: Matches Python — removed self-storage.

**Risk**: None. This was a bug fix, not a deviation.

---

## AutoInterface: Adaptive Announce Interval

**Python behavior** (`AutoInterface.py:announce_handler`):
Sends multicast discovery announcements every 1.6 seconds continuously
with no adaptation. This interval is hardcoded and never changes.

**Kotlin behavior** (`AutoInterface.kt:startAnnouncementLoop`):
The announce interval adapts based on peer activity and device state:

| State | Announce Interval | vs Python (1.6s) |
|-------|------------------|------------------|
| Startup / peer change | 1.6s (+ immediate reply) | Same |
| Stable, 30s | ~60s | 37x less |
| Stable, 60s+ | 2 minutes | 75x less |
| Doze, stable | 10 minutes | 375x less |
| New peer during Doze | Immediate reply → 1.6s | Same responsiveness |

The interval linearly ramps from 1.6s to `maxAnnounceIntervalMs *
throttleMultiplier` over 60 seconds after the last peer topology
change. Any peer add/remove resets to fast mode AND triggers an
immediate announce so the new peer discovers us within ~1 second.

Doze awareness: `NativeReticulumProtocol` observes `DozeStateObserver`
and sets `AutoInterface.throttleMultiplier` to 5.0 during Doze,
scaling the max interval from 2 minutes to 10 minutes.

**Why**: Continuous 1.6s multicast is the single biggest battery drain
on the native stack. Receiving other nodes' multicast is free (blocking
`socket.receive()`), but sending wakes the WiFi radio every 1.6s
indefinitely. Since peer discovery is symmetric, other nodes sending
at their rate still discover us via receiving — we only need to send
often enough that they discover us within a reasonable time.

**Multicast socket cleanup**: Kotlin explicitly calls `leaveGroup()`
before closing multicast sockets on detach, preventing OS-level
multicast group membership from lingering after the interface is
stopped. Python relies on `socket.close()` for implicit cleanup.

**Risk**: Low. A node running Kotlin at 2-minute intervals next to a
node running Python at 1.6s will still discover each other: the Python
node's multicast arrives within 1.6s, and the Kotlin node's immediate
reply fires within ~1 second. After discovery, unicast data flow is
unaffected.

**Resolution**: This is an intentional improvement, not a workaround.
`throttleMultiplier` can be set to 1.0 and `maxAnnounceIntervalMs`
can be set to `ANNOUNCE_INTERVAL_MS` to match exact Python behavior
if needed.

---

## Conformance Test Status

Against the [reticulum-conformance](https://github.com/torlando-tech/reticulum-conformance)
suite with RNS 1.5.2 as the reference, the full run on this port is
1308 passed, 0 failed, 12 skipped, 1 expected failure, with the
Kotlin bridge in every arm (reference-to-kotlin, kotlin-to-reference,
kotlin-to-kotlin). The one expected failure is `bz2_compress`: the compression
library produces different but equally valid output.
