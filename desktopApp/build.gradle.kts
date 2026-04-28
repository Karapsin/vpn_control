import org.gradle.internal.os.OperatingSystem
import org.jetbrains.compose.desktop.application.dsl.TargetFormat
import java.util.concurrent.TimeUnit

val hostOs = OperatingSystem.current()
val desktopPackageTargets = when {
    hostOs.isWindows -> arrayOf(TargetFormat.Exe, TargetFormat.Msi)
    hostOs.isLinux -> arrayOf(TargetFormat.Deb, TargetFormat.Rpm)
    hostOs.isMacOsX -> arrayOf(TargetFormat.Dmg)
    else -> emptyArray()
}
fun gitCommitCountOrFallback(): Int {
    return runCatching {
        val process = ProcessBuilder("git", "rev-list", "--count", "HEAD")
            .redirectErrorStream(true)
            .start()
        val finished = process.waitFor(5, TimeUnit.SECONDS)
        if (!finished) {
            process.destroyForcibly()
            return@runCatching 1
        }
        if (process.exitValue() != 0) {
            return@runCatching 1
        }
        process.inputStream.bufferedReader().use { it.readText() }
            .trim()
            .toIntOrNull()
            ?.coerceAtLeast(1)
            ?: 1
    }.getOrDefault(1)
}

val gitCommitCount = providers.provider { gitCommitCountOrFallback() }
val desktopPackageVersion = providers.gradleProperty("vpnControlDesktopVersion")
    .orElse(providers.environmentVariable("VPN_CONTROL_DESKTOP_VERSION"))
    .orElse(gitCommitCount.map { count -> "0.1.$count" })
val macosPackageVersion = providers.gradleProperty("vpnControlMacosDesktopVersion")
    .orElse(providers.environmentVariable("VPN_CONTROL_MACOS_DESKTOP_VERSION"))
    .orElse(gitCommitCount.map { count -> "1.0.$count" })

plugins {
    id("org.jetbrains.compose")
    id("org.jetbrains.kotlin.jvm")
    id("org.jetbrains.kotlin.plugin.compose")
}

kotlin {
    jvmToolchain(17)
}

dependencies {
    implementation(project(":shared:model"))
    implementation(project(":shared:core"))
    implementation(project(":shared:storage-api"))
    implementation(project(":shared:ui"))
    implementation(compose.desktop.currentOs)
    implementation(compose.material3)
    implementation(compose.materialIconsExtended)
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.7.3")

    testImplementation(kotlin("test"))
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.8.1")
}

sourceSets {
    main {
        resources.srcDir(project.file("../app/src/main/res/drawable-nodpi"))
    }
}

compose.desktop {
    application {
        mainClass = "com.kardinal.vpncontrol.desktop.MainKt"

        nativeDistributions {
            targetFormats(*desktopPackageTargets)
            packageName = "vpn-control"
            packageVersion = desktopPackageVersion.get()
            vendor = "Kardinal"
            description = "Desktop VPN Control client"

            linux {
                iconFile.set(project.file("../app/src/main/res/drawable-nodpi/gen_icon.png"))
                menuGroup = "Network"
                appCategory = "Network"
                debMaintainer = "kardinal"
                rpmLicenseType = "MIT"
            }

            windows {
                iconFile.set(project.file("src/main/resources/icons/vpn-control.ico"))
                menu = true
                menuGroup = "VPN Control"
                shortcut = true
                dirChooser = true
                perUserInstall = true
                upgradeUuid = "7a5e0a8e-2a7a-4baf-9f2a-5fb2c3529af2"
            }

            macOS {
                val version = macosPackageVersion.get()
                packageVersion = version
                packageBuildVersion = version
                dmgPackageVersion = version
                dmgPackageBuildVersion = version
            }
        }
    }
}
