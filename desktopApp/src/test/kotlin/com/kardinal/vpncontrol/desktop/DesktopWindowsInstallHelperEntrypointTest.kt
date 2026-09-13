package com.kardinal.vpncontrol.desktop

import java.nio.file.Files
import java.nio.file.Path
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.util.concurrent.TimeUnit
import org.junit.Assume.assumeTrue
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.fail

class DesktopWindowsInstallHelperEntrypointTest {
    @Test
    fun canonicalRoleDispatchUsesOnlySameAssemblyFactoryAndRejectsInvalidInputsBeforeIt() {
        assumeTrue(System.getProperty("os.name").startsWith("Windows", true))
        val directory = Files.createTempDirectory("vpn-install-helper-entrypoint-")
        listOf(
            "windows-install-native.cs",
            "windows-install-helper.cs",
            "windows-install-helper-protocol.cs",
            "windows-install-helper-roles.cs",
            "windows-install-helper-msi.cs",
            "windows-install-helper-sessions.cs", "windows-install-original-user-launch.cs", "windows-install-helper-inventory.cs",
            "windows-install-helper-entrypoint-fixture.cs",
            "windows-install-helper-session-fixture.cs",
        ).map { name ->
            directory.resolve(name).also { path ->
                javaClass.getResourceAsStream("/$name")!!.use { Files.copy(it, path) }
            }
        }
        val dotnet = System.getenv("VPN_CONTROL_TEST_DOTNET") ?: "dotnet.exe"
        val pin = Files.readAllBytes(Path.of(System.getProperty("vpnControl.test.nativeGlobalJson", "native/windows/global.json")))
        val sdk = Json.parseToJsonElement(pin.decodeToString()).jsonObject["sdk"]!!.jsonObject
        assertEquals("disable", sdk["rollForward"]!!.jsonPrimitive.content)
        Files.write(directory.resolve("global.json"), pin)
        Files.writeString(directory.resolve("NuGet.Config"), "<configuration><packageSources><clear /></packageSources></configuration>")
        Files.writeString(directory.resolve("EntrypointProbe.csproj"), """
            <Project Sdk="Microsoft.NET.Sdk"><PropertyGroup>
              <TargetFramework>net10.0-windows</TargetFramework><OutputType>Exe</OutputType>
              <StartupObject>InstallerEntrypointProbe</StartupObject><UseAppHost>false</UseAppHost>
              <InvariantGlobalization>true</InvariantGlobalization><Nullable>disable</Nullable>
              <ImplicitUsings>disable</ImplicitUsings><TreatWarningsAsErrors>true</TreatWarningsAsErrors>
            </PropertyGroup></Project>
        """.trimIndent())
        Files.writeString(directory.resolve("ProbeMain.cs"), """
            using System;
            internal static class InstallerEntrypointProbe {
              public static void Main() {
                Console.WriteLine(InstallerEntrypointFixtures.Run());
                Console.WriteLine(InstallerSessionAdmissionFixtures.FailedOwnerCloseRetainsExactHandleForRetry());
                Console.WriteLine(InstallerSessionAdmissionFixtures.WrongOwnerGenerationIsRejectedBeforeAnyInputLookup());
                Console.WriteLine(InstallerSessionAdmissionFixtures.ConstructionFailureKeepsOriginalFailureAndRecordsUncertainCleanup());
                Console.WriteLine(InstallerSessionAdmissionFixtures.MissingJobInputReleasesPinnedAncestor());
              }
            }
        """.trimIndent())
        fun run(phase: String, arguments: List<String>): String {
            val output = directory.resolve("$phase-stdout.txt")
            val error = directory.resolve("$phase-stderr.txt")
            val process = ProcessBuilder(listOf(dotnet) + arguments).directory(directory.toFile())
                .redirectOutput(output.toFile()).redirectError(error.toFile()).also {
                    it.environment().putAll(mapOf(
                        "DOTNET_CLI_HOME" to directory.resolve("dotnet-home").toString(),
                        "DOTNET_SKIP_FIRST_TIME_EXPERIENCE" to "1", "DOTNET_CLI_TELEMETRY_OPTOUT" to "1",
                        "DOTNET_MULTILEVEL_LOOKUP" to "0", "DOTNET_NOLOGO" to "1",
                        "DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE" to "1", "MSBUILDDISABLENODEREUSE" to "1",
                    ))
                }.start()
            process.outputStream.close()
            Files.writeString(directory.resolve("$phase-process.txt"), "pid=${process.pid()}\nstarted=${process.toHandle().info().startInstant().orElse(null)}\n")
            if (!process.waitFor(90, TimeUnit.SECONDS)) {
                synchronized(retainedProcesses) { retainedProcesses.add(process) }
                fail("Fixed entrypoint $phase still owns PID ${process.pid()}; evidence: $directory")
            }
            val stdout = Files.newInputStream(output).use { it.readNBytes(8192).decodeToString() }
            val stderr = Files.newInputStream(error).use { it.readNBytes(8192).decodeToString() }
            assertEquals(0, process.exitValue(), "Fixed entrypoint $phase failed; evidence: $directory\n$stdout\n$stderr")
            return stdout
        }
        assertEquals(sdk["version"]!!.jsonPrimitive.content, run("sdk", listOf("--version")).trim())
        run("build", listOf("build", "EntrypointProbe.csproj", "--configuration", "Release", "--disable-build-servers", "-p:UseSharedCompilation=false"))
        val text = run("probe", listOf(directory.resolve("bin/Release/net10.0-windows/EntrypointProbe.dll").toString()))
        for (marker in listOf("FIXED_INSTALL_ENTRYPOINT_OK", "OWNER_CLOSE_RETRIED", "OWNER_GENERATION_REJECTED",
            "CONSTRUCTION_FAILURE_RETAINED", "MISSING_INPUT_ANCESTOR_RELEASED")) assertTrue(text.contains(marker), text)
        println("NATIVE_INSTALL_ENTRYPOINT_OK evidence=$directory")
    }

    companion object {
        private val retainedProcesses = mutableListOf<Process>()
    }
}
