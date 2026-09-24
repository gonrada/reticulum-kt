plugins {
    kotlin("jvm") version "2.3.0" apply false
    kotlin("plugin.serialization") version "2.3.0" apply false
    id("com.android.library") version "9.1.0" apply false
    id("com.google.devtools.ksp") version "2.3.6" apply false
    id("org.jetbrains.kotlinx.kover") version "0.7.6"
}

allprojects {
    group = "com.github.torlando-tech.reticulum-kt"
    version = System.getenv("VERSION")?.removePrefix("v") ?: "0.1.0-SNAPSHOT"
}

dependencies {
    kover(project(":rns-core"))
    kover(project(":rns-interfaces"))
    // Aggregate rns-test execution data so coverage of rns-core classes that
    // can only be reached via two-node / interop tests (e.g. Link.rttPacket
    // owner-callback flow) is counted in the root koverXmlReport.
    kover(project(":rns-test"))
}

subprojects {
    // Apply JVM 21 target only to non-Android modules
    // Android modules use Java 17 for compatibility
    afterEvaluate {
        if (!plugins.hasPlugin("com.android.library") && !plugins.hasPlugin("com.android.application")) {
            tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile> {
                compilerOptions {
                    jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_21)
                    freeCompilerArgs.add("-Xjsr305=strict")
                    // Members annotated @RnsTestSeam (rns-core) require opt-in. Every module in
                    // THIS build opts in — the library uses a few of them internally and the
                    // conformance bridge and tests use all of them — so the requirement only
                    // bites a consumer of the published artifacts, which is the point.
                    freeCompilerArgs.add("-opt-in=network.reticulum.RnsTestSeam")
                }
            }

            tasks.withType<JavaCompile> {
                sourceCompatibility = "21"
                targetCompatibility = "21"
            }
        }
    }

    tasks.withType<Test> {
        useJUnitPlatform()
        // Forward the opt-in flag for the hot-path perf harness (HotPathBench) to the
        // forked test worker. No effect on normal runs; the harness self-skips unless set.
        System.getProperty("bench")?.let { systemProperty("bench", it) }
        // Allocation profiling: when -Dbench.jfr=<path> is set, arm JFR allocation
        // sampling on the test worker (AnnounceAllocProfile self-skips otherwise). JFR is
        // built into the JDK; the `profile` preset samples allocations at ~1-2% overhead.
        System.getProperty("bench.jfr")?.let { jfrPath ->
            systemProperty("bench.jfr", jfrPath)
            jvmArgs("-XX:StartFlightRecording=filename=$jfrPath,settings=profile,dumponexit=true")
            jvmArgs("-XX:FlightRecorderOptions=stackdepth=64")
        }
    }
}
