package network.reticulum

/**
 * Marks a member of the published API that exists only so the conformance bridge and the
 * unit tests can reach into the library's state — forge a path-table entry, disable proof
 * validation on a link, lift the decompression bound, inject a ratchet, tap the inbound
 * path, and so on.
 *
 * None of these is reachable from the network. Every one of them weakens a security
 * property when called by application code in the same process, and they are public only
 * because the bridge is a separate Gradle module that cannot see `internal` members.
 * Opt-in makes the choice explicit: a consumer of the published artifact gets a compile
 * error at the call site unless it says, in its own source, that it means to use a test
 * seam. This build opts in module-wide.
 */
@RequiresOptIn(
    level = RequiresOptIn.Level.ERROR,
    message = "Test seam: forges or bypasses library state. Not for application code. " +
        "Opt in with @OptIn(RnsTestSeam::class) only in test or conformance-bridge code.",
)
@Retention(AnnotationRetention.BINARY)
@Target(
    AnnotationTarget.FUNCTION,
    AnnotationTarget.PROPERTY,
    AnnotationTarget.PROPERTY_GETTER,
    AnnotationTarget.PROPERTY_SETTER,
    AnnotationTarget.CLASS,
)
annotation class RnsTestSeam
