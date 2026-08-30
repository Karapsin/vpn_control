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
val macosSigningIdentity = providers.gradleProperty("vpnControlMacosSigningIdentity")
    .orElse(providers.environmentVariable("VPN_CONTROL_MACOS_SIGNING_IDENTITY"))
val macosSigningKeychain = providers.gradleProperty("vpnControlMacosSigningKeychain")
    .orElse(providers.environmentVariable("VPN_CONTROL_MACOS_SIGNING_KEYCHAIN"))
val macosNotarizationAppleId = providers.gradleProperty("vpnControlMacosNotarizationAppleId")
    .orElse(providers.environmentVariable("VPN_CONTROL_MACOS_NOTARIZATION_APPLE_ID"))
val macosNotarizationPassword = providers.gradleProperty("vpnControlMacosNotarizationPassword")
    .orElse(providers.environmentVariable("VPN_CONTROL_MACOS_NOTARIZATION_PASSWORD"))
val macosNotarizationTeamId = providers.gradleProperty("vpnControlMacosNotarizationTeamId")
    .orElse(providers.environmentVariable("VPN_CONTROL_MACOS_NOTARIZATION_TEAM_ID"))
val desktopRuntimeDisplayVersion = if (hostOs.isMacOsX) macosPackageVersion else desktopPackageVersion
val generatedVersionResources = layout.buildDirectory.dir("generated/resources/version/main")

val generateDesktopVersionResource by tasks.registering {
    val outputDir = generatedVersionResources
    inputs.property("buildNumber", gitCommitCount)
    inputs.property("displayVersion", desktopRuntimeDisplayVersion)
    outputs.dir(outputDir)
    doLast {
        val target = outputDir.get().file("vpn-control-version.properties").asFile
        target.parentFile.mkdirs()
        target.writeText(
            "buildNumber=${gitCommitCount.get()}\n" +
                "displayVersion=${desktopRuntimeDisplayVersion.get()}\n",
        )
    }
}

fun Provider<String>.nonBlankOrNull(): String? = orNull?.trim()?.takeIf(String::isNotEmpty)

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
    implementation("com.dorkbox:SystemTray:4.4")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.7.3")

    testImplementation(kotlin("test"))
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.8.1")
}

sourceSets {
    main {
        resources.srcDir(project.file("../app/src/main/res/drawable-nodpi"))
        resources.srcDir(generatedVersionResources)
    }
}

tasks.named("processResources") {
    dependsOn(generateDesktopVersionResource)
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

                macosSigningIdentity.nonBlankOrNull()?.let { identityValue ->
                    signing {
                        sign.set(true)
                        identity.set(identityValue)
                        macosSigningKeychain.nonBlankOrNull()?.let(keychain::set)
                    }
                }

                val notarizationAppleId = macosNotarizationAppleId.nonBlankOrNull()
                val notarizationPassword = macosNotarizationPassword.nonBlankOrNull()
                val notarizationTeamId = macosNotarizationTeamId.nonBlankOrNull()
                if (notarizationAppleId != null && notarizationPassword != null && notarizationTeamId != null) {
                    notarization {
                        appleID.set(notarizationAppleId)
                        password.set(notarizationPassword)
                        teamID.set(notarizationTeamId)
                    }
                }
            }
        }
    }
}
