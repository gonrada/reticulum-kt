pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.PREFER_PROJECT)
    repositories {
        google()
        mavenCentral()
        // usb-serial-for-android (USB KISS TNC chip drivers) is published on JitPack.
        maven { url = uri("https://jitpack.io") }
    }
}

rootProject.name = "reticulum-kt"

include(":rns-core")
include(":rns-interfaces")
include(":rns-test")
include(":rns-cli")

// Android module for battery-optimized mobile deployment
include(":rns-android")

// Conformance test bridge
include(":conformance-bridge")
