@file:OptIn(org.jetbrains.compose.ExperimentalComposeLibrary::class)

import org.gradle.internal.os.OperatingSystem
import org.jetbrains.compose.desktop.application.dsl.TargetFormat
import org.jetbrains.compose.desktop.application.tasks.AbstractJPackageTask

val hostOs = OperatingSystem.current()
val desktopPackageTargets = when {
    hostOs.isWindows -> arrayOf(TargetFormat.Exe, TargetFormat.Msi)
    hostOs.isLinux -> arrayOf(TargetFormat.Deb, TargetFormat.Rpm)
    hostOs.isMacOsX -> arrayOf(TargetFormat.Dmg)
    else -> emptyArray()
}
fun parseCanonicalVersion(value: String): List<Int> {
    val parts = value.trim().split('.').map { it.toIntOrNull() }
    require(parts.size == 3 && parts.all { it != null && it in 0..19 } && requireNotNull(parts[0]) > 0) {
        "vpnControlVersion must have three components; major is 1..19 and others are 0..19"
    }
    return parts.map { requireNotNull(it) }
}

val canonicalVersion = providers.gradleProperty("vpnControlVersion")
val canonicalVersionParts = canonicalVersion.map(::parseCanonicalVersion)
val canonicalBuildNumber = canonicalVersionParts.map { parts ->
    parts.fold(0) { value, component -> value * 20 + component }
        .times(20)
        .also { require(it > 0) { "vpnControlVersion must produce a positive build number" } }
}
val runtimeDisplayVersion = canonicalVersion
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
val generatedVersionResources = layout.buildDirectory.dir("generated/resources/version/main")

val generateDesktopVersionResource by tasks.registering {
    val outputDir = generatedVersionResources
    inputs.property("buildNumber", canonicalBuildNumber)
    inputs.property("displayVersion", runtimeDisplayVersion)
    outputs.dir(outputDir)
    doLast {
        val target = outputDir.get().file("vpn-control-version.properties").asFile
        target.parentFile.mkdirs()
        target.writeText(
            "buildNumber=${canonicalBuildNumber.get()}\n" +
                "displayVersion=${runtimeDisplayVersion.get()}\n",
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
    // Align with SystemTray's existing JPMS dependencies; protected Windows IPC uses native handles.
    implementation("net.java.dev.jna:jna-jpms:5.13.0")
    implementation("net.java.dev.jna:jna-platform-jpms:5.13.0")
    implementation("com.google.zxing:core:3.5.4")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.7.3")

    testImplementation(kotlin("test"))
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.8.1")
    testImplementation(compose.desktop.uiTestJUnit4)
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

tasks.withType<AbstractJPackageTask>().configureEach {
    if (hostOs.isLinux && targetFormat == TargetFormat.Deb) {
        // Compose 1.7.3 appends its own resource directory after freeArgs.
        // Package the prepared image explicitly, then inspect the emitted hook.
        val debResources = project.file("packaging/linux")
        val debPackager = rootProject.file("scripts/package_linux_deb.py")
        val preparedImage = tasks.named<AbstractJPackageTask>("createDistributable")
        dependsOn(preparedImage)
        appImage.set(preparedImage.flatMap { image ->
            image.destinationDir.map { directory -> directory.dir(image.packageName.get()) }
        })
        inputs.dir(debResources)
        inputs.file(debPackager)
        val packageTask = this
        actions.clear()
        doLast {
            val command = mutableListOf(
                "python3", debPackager.absolutePath,
                "--java-home", packageTask.javaHome.get(),
                "--app-image", packageTask.appImage.get().asFile.absolutePath,
                "--destination", packageTask.destinationDir.get().asFile.absolutePath,
                "--resources", debResources.absolutePath,
                "--name", packageTask.packageName.get(),
                "--package-name", packageTask.linuxPackageName.getOrElse(packageTask.packageName.get()),
                "--version", packageTask.packageVersion.get(),
            )
            fun value(option: String, value: String?) {
                if (!value.isNullOrEmpty()) command.addAll(listOf(option, value))
            }
            value("--vendor", packageTask.packageVendor.orNull)
            value("--description", packageTask.packageDescription.orNull)
            value("--copyright", packageTask.packageCopyright.orNull)
            value("--license-file", packageTask.licenseFile.orNull?.asFile?.absolutePath)
            value("--icon", packageTask.iconFile.orNull?.asFile?.absolutePath)
            value("--maintainer", packageTask.linuxDebMaintainer.orNull)
            value("--category", packageTask.linuxAppCategory.orNull)
            value("--menu-group", packageTask.linuxMenuGroup.orNull)
            value("--install-dir", packageTask.installationPath.orNull)
            value("--release", packageTask.linuxAppRelease.orNull)
            if (packageTask.linuxShortcut.orNull == true) command.add("--shortcut")
            project.exec { commandLine(command) }
        }
    }
    if (hostOs.isLinux && targetFormat == TargetFormat.Rpm) {
        // Preserve desktop registration through old-package removal, including
        // upgrades from published RPMs with unconditional uninstall scripts.
        val rpmPackager = rootProject.file("scripts/package_linux_rpm.py")
        val preparedImage = tasks.named<AbstractJPackageTask>("createDistributable")
        dependsOn(preparedImage)
        appImage.set(preparedImage.flatMap { image ->
            image.destinationDir.map { directory -> directory.dir(image.packageName.get()) }
        })
        inputs.files(rpmPackager, rootProject.file("scripts/package_linux_deb.py"))
        val packageTask = this
        actions.clear()
        doLast {
            val command = mutableListOf(
                "python3", rpmPackager.absolutePath,
                "--java-home", packageTask.javaHome.get(),
                "--app-image", packageTask.appImage.get().asFile.absolutePath,
                "--destination", packageTask.destinationDir.get().asFile.absolutePath,
                "--name", packageTask.packageName.get(),
                "--package-name", packageTask.linuxPackageName.getOrElse(packageTask.packageName.get()),
                "--version", packageTask.packageVersion.get(),
            )
            fun value(option: String, value: String?) {
                if (!value.isNullOrEmpty()) command.addAll(listOf(option, value))
            }
            value("--vendor", packageTask.packageVendor.orNull)
            value("--description", packageTask.packageDescription.orNull)
            value("--copyright", packageTask.packageCopyright.orNull)
            value("--license-file", packageTask.licenseFile.orNull?.asFile?.absolutePath)
            value("--icon", packageTask.iconFile.orNull?.asFile?.absolutePath)
            value("--license-type", packageTask.linuxRpmLicenseType.orNull)
            value("--category", packageTask.linuxAppCategory.orNull)
            value("--menu-group", packageTask.linuxMenuGroup.orNull)
            value("--install-dir", packageTask.installationPath.orNull)
            value("--release", packageTask.linuxAppRelease.orNull)
            if (packageTask.linuxShortcut.orNull == true) command.add("--shortcut")
            project.exec { commandLine(command) }
        }
    }
    if (hostOs.isWindows && targetFormat in setOf(TargetFormat.Exe, TargetFormat.Msi)) {
        // Installer tasks otherwise build a fresh image, bypassing --add-launcher and
        // the UTF-8 manifest post-processing attached to createDistributable below.
        val preparedImage = tasks.named<AbstractJPackageTask>("createDistributable")
        dependsOn(preparedImage)
        appImage.set(preparedImage.flatMap { image ->
            image.destinationDir.map { directory -> directory.dir(image.packageName.get()) }
        })
    }
    if (hostOs.isWindows && targetFormat == TargetFormat.AppImage) {
        val cliLauncher = project.file("src/main/packaging/windows-cli.properties")
        inputs.file(cliLauncher)
        freeArgs.addAll("--add-launcher", "vpn-control-cli=${cliLauncher.absolutePath}")
        val utf8LauncherPatch = rootProject.file("scripts/windows_launcher_utf8.py")
        inputs.file(utf8LauncherPatch)
        doLast {
            project.exec {
                commandLine("python3", utf8LauncherPatch.absolutePath, "--app-image",
                    destinationDir.get().dir(packageName.get()).asFile.absolutePath)
            }
        }
    }
}

tasks.withType<Test>().configureEach {
    testLogging.exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
    doFirst {
        systemProperty("vpnControl.test.mainClasspath", sourceSets.main.get().runtimeClasspath.asPath)
    }
}

val visualCapture by tasks.registering(Test::class) {
    description = "Captures deterministic desktop visual-regression scenes."
    group = "verification"
    dependsOn(tasks.named("testClasses"))
    testClassesDirs = sourceSets.test.get().output.classesDirs
    classpath = sourceSets.test.get().runtimeClasspath
    outputs.upToDateWhen { false }
    filter {
        includeTestsMatching("com.kardinal.vpncontrol.desktop.VisualCaptureTest")
    }
}

val nativeVisualCapture by tasks.registering(Test::class) {
    description = "Captures real desktop OS visual-regression scenes in an isolated session."
    group = "verification"
    dependsOn(tasks.named("testClasses"))
    testClassesDirs = sourceSets.test.get().output.classesDirs
    classpath = sourceSets.test.get().runtimeClasspath
    outputs.upToDateWhen { false }
    filter {
        includeTestsMatching("com.kardinal.vpncontrol.desktop.DesktopNativeVisualCaptureTest")
    }
}

compose.desktop {
    application {
        mainClass = "com.kardinal.vpncontrol.desktop.MainKt"

        nativeDistributions {
            modules("java.net.http")
            targetFormats(*desktopPackageTargets)
            packageName = "vpn-control"
            packageVersion = canonicalVersion.get()
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
                val version = canonicalVersion.get()
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
