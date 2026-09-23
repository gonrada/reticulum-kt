plugins {
    kotlin("jvm")
    id("org.jetbrains.kotlinx.kover")
    `maven-publish`
}

java { withSourcesJar() }

publishing {
    publications {
        create<MavenPublication>("maven") { from(components["java"]) }
    }
}

val coroutinesVersion: String by project
val bouncycastleVersion: String by project
val junitVersion: String by project
val kotestVersion: String by project

dependencies {
    // Coroutines
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:$coroutinesVersion")

    // Cryptography - BouncyCastle for JVM
    implementation("org.bouncycastle:bcprov-jdk18on:$bouncycastleVersion")

    // MessagePack for serialization (api: exposed via Transport/Identity persistence methods)
    // 0.9.12: releases before 0.9.11 allocate an attacker-declared EXT payload length before
    // reading it (CVE-2026-21452), a remote DoS reachable at every unpack of peer bytes.
    api("org.msgpack:msgpack-core:0.9.12")

    // Compression - Apache Commons Compress for BZ2
    implementation("org.apache.commons:commons-compress:1.26.0")

    // Logging — SLF4J API only; consumers supply their own binding (Logback, Log4j2, etc.)
    implementation("io.github.microutils:kotlin-logging-jvm:3.0.5")

    // Testing
    testImplementation(kotlin("test"))
    testImplementation("org.junit.jupiter:junit-jupiter:$junitVersion")
    testImplementation("io.kotest:kotest-runner-junit5:$kotestVersion")
    testImplementation("io.kotest:kotest-assertions-core:$kotestVersion")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:$coroutinesVersion")
    testRuntimeOnly("org.slf4j:slf4j-simple:2.0.9")
}
