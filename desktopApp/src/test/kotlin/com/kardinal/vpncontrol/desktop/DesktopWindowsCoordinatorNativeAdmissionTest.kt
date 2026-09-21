package com.kardinal.vpncontrol.desktop

import java.nio.file.Files
import java.nio.file.Path
import java.util.UUID
import java.util.concurrent.TimeUnit
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assume.assumeTrue
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.fail

class DesktopWindowsCoordinatorNativeAdmissionTest {
    @Test fun actualAdmitWorkerBoundaryAdmitsOnlyBoundPrivateUserImage() {
        runFixture(includeProgramData = false)
    }

    @Test fun actualCoordinatorConstructorAdmitsOnlyPinnedSameImageWorkerAndSafeProgramDataChild() {
        assumeTrue(System.getenv("VPN_CONTROL_NATIVE_COORDINATOR_ADMISSION") == "1")
        runFixture(includeProgramData = true)
    }

    private fun runFixture(includeProgramData: Boolean) {
        assumeTrue(System.getProperty("os.name").startsWith("Windows", true))
        val directory = Files.createTempDirectory("vpn-coordinator-native-admission-")
        var retainEvidence = false
        var privateImageStage: Path? = null
        try {
            listOf(
                "windows-install-native.cs", "windows-install-helper-inventory.cs", "windows-install-helper-protocol.cs",
                "windows-install-helper-roles.cs", "windows-install-helper-msi.cs", "windows-install-helper-sessions.cs",
                "windows-install-original-user-launch.cs",
                "windows-install-helper-coordinator-native-admission-fixture.cs",
            ).forEach { name -> javaClass.getResourceAsStream("/$name")!!.use { Files.copy(it, directory.resolve(name)) } }
            val pin = Files.readAllBytes(Path.of(System.getProperty("vpnControl.test.nativeGlobalJson", "native/windows/global.json")))
            val sdk = Json.parseToJsonElement(pin.decodeToString()).jsonObject["sdk"]!!.jsonObject
            assertEquals("disable", sdk["rollForward"]!!.jsonPrimitive.content)
            Files.write(directory.resolve("global.json"), pin)
            Files.writeString(directory.resolve("NuGet.Config"), "<configuration><packageSources><clear /></packageSources></configuration>")
            Files.writeString(directory.resolve("CoordinatorNativeAdmissionProbe.csproj"), """
                <Project Sdk="Microsoft.NET.Sdk"><PropertyGroup>
                  <TargetFramework>net10.0-windows</TargetFramework><OutputType>Exe</OutputType>
                  <AssemblyName>vpn-control</AssemblyName><StartupObject>CoordinatorNativeAdmissionFixtures</StartupObject><UseAppHost>true</UseAppHost>
                  <InvariantGlobalization>true</InvariantGlobalization><Nullable>disable</Nullable>
                  <ImplicitUsings>disable</ImplicitUsings><TreatWarningsAsErrors>true</TreatWarningsAsErrors>
                </PropertyGroup></Project>
            """.trimIndent())
            val dotnet = System.getenv("VPN_CONTROL_TEST_DOTNET") ?: "dotnet.exe"
            fun run(phase: String, command: List<String>): String {
                val stdout = directory.resolve("$phase-stdout.txt")
                val stderr = directory.resolve("$phase-stderr.txt")
                val process = ProcessBuilder(command).directory(directory.toFile()).redirectOutput(stdout.toFile()).redirectError(stderr.toFile()).also {
                    it.environment().putAll(mapOf(
                        "DOTNET_CLI_HOME" to directory.resolve("dotnet-home").toString(), "DOTNET_SKIP_FIRST_TIME_EXPERIENCE" to "1",
                        "DOTNET_CLI_TELEMETRY_OPTOUT" to "1", "DOTNET_MULTILEVEL_LOOKUP" to "0", "DOTNET_NOLOGO" to "1",
                        "DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE" to "1", "MSBUILDDISABLENODEREUSE" to "1",
                    ))
                    System.getenv("VPN_CONTROL_TEST_DOTNET_ROOT")?.let { root ->
                        it.environment()["DOTNET_ROOT"] = root
                        it.environment()["DOTNET_ROOT_X64"] = root
                    }
                }.start()
                process.outputStream.close()
                if (!process.waitFor(90, TimeUnit.SECONDS)) {
                    retainEvidence = true
                    fail("Coordinator native admission $phase did not finish; evidence retained: $directory")
                }
                val output = Files.readString(stdout); val error = Files.readString(stderr)
                assertEquals(0, process.exitValue(), "Coordinator native admission $phase failed; evidence: $directory\n$output\n$error")
                return output
            }
            assertEquals(sdk["version"]!!.jsonPrimitive.content, run("sdk", listOf(dotnet, "--version")).trim())
            run("build", listOf(dotnet, "build", "CoordinatorNativeAdmissionProbe.csproj", "--configuration", "Release", "--disable-build-servers", "-p:UseSharedCompilation=false"))
            // Routine Windows CI has no ProgramData mutation authority. Stage the
            // actual apphost beneath a private current-user ACL and call the
            // production admission helper used by AdmitWorker before the
            // separately authorized full coordinator scenario.
            val imageNative = JnaWindowsInstallNative()
            val currentSid = JnaWindowsInstallAdmission().currentSid()
            val currentUserImageStage = directory.resolve("current-user-coordinator-image")
            privateImageStage = currentUserImageStage
            imageNative.createDirectory(currentUserImageStage.toString(),
                "O:${currentSid}G:${currentSid}D:P(A;OICI;FA;;;${currentSid})(A;OICI;FA;;;SY)", false)
            val privateOutput = directory.resolve("bin/Release/net10.0-windows")
            Files.list(privateOutput).use { entries -> entries.forEach { source ->
                Files.copy(source, currentUserImageStage.resolve(source.fileName.toString()))
            } }
            assertTrue(run("private-image-admission", listOf(
                currentUserImageStage.resolve("vpn-control.exe").toString(), "--private-image-admission",
            )).contains("COORDINATOR_PRIVATE_ORIGINAL_USER_IMAGE_ADMISSION_OK"))
            // The real ProgramData ACL/process-authority execution is opt-in.
            // The routine assertion above is retained as its own non-skipped test.
            if (!includeProgramData) return
            val token = UUID.randomUUID().toString().replace("-", "")
            val outputRoot = directory.resolve("bin/Release/net10.0-windows")
            val programData = Path.of(System.getenv("ProgramData") ?: "C:\\ProgramData")
            val helper = programData.resolve("VpnCoordinatorNativeAdmission-$token")
            Files.createDirectory(helper)
            try {
                val acl = ProcessBuilder(
                    "icacls", helper.toString(), "/inheritance:r", "/grant:r",
                    "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F", "*S-1-5-32-545:(OI)(CI)RX",
                ).redirectErrorStream(true).start()
                assertEquals(0, acl.waitFor(), acl.inputStream.readBytes().decodeToString())
                listOf("vpn-control.exe", "vpn-control.dll", "vpn-control.deps.json", "vpn-control.runtimeconfig.json").forEach {
                    Files.copy(outputRoot.resolve(it), helper.resolve(it))
                }
                Files.copy(helper.resolve("vpn-control.exe"), helper.resolve("vpn-control-cli.exe"))
                val output = run("probe", listOf(helper.resolve("vpn-control.exe").toString(), "--completion-token", token))
                assertTrue(output.contains("COORDINATOR_NATIVE_ADMISSION_OK token=$token"), output)
            } finally {
                helper.toFile().deleteRecursively()
            }
        } finally {
            if (!retainEvidence) {
                privateImageStage?.toFile()?.deleteRecursively()
                directory.toFile().deleteRecursively()
            }
        }
    }
}
