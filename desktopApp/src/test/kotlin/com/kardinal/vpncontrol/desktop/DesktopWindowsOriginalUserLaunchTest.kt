package com.kardinal.vpncontrol.desktop

import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.security.MessageDigest
import java.util.UUID
import java.util.concurrent.TimeUnit
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.junit.Assume.assumeTrue

class DesktopWindowsOriginalUserLaunchTest {
    @Test fun fixtureInvocationMatchesCompiledAssembly() {
        val project = javax.xml.parsers.DocumentBuilderFactory.newInstance().newDocumentBuilder()
            .parse(fixtureProject().byteInputStream())
        val assembly = project.getElementsByTagName("AssemblyName").item(0).textContent
        assertEquals("$assembly.dll", fixtureAssemblyFile())
        assertEquals("$assembly.exe", fixtureExecutableFile())
    }

    private val fixtureAssemblyName = "vpn-control-install-helper"
    private fun fixtureAssemblyFile() = "$fixtureAssemblyName.dll"
    private fun fixtureExecutableFile() = "$fixtureAssemblyName.exe"
    private fun fixtureProject() = """
                <Project Sdk="Microsoft.NET.Sdk"><PropertyGroup>
                  <TargetFramework>net10.0-windows</TargetFramework><OutputType>Exe</OutputType>
                  <AssemblyName>$fixtureAssemblyName</AssemblyName><StartupObject>OriginalUserLaunchProbe</StartupObject>
                  <UseAppHost>true</UseAppHost><InvariantGlobalization>true</InvariantGlobalization><Nullable>disable</Nullable>
                  <ImplicitUsings>disable</ImplicitUsings><TreatWarningsAsErrors>true</TreatWarningsAsErrors>
                  <EnableAotAnalyzer>true</EnableAotAnalyzer>
                </PropertyGroup></Project>
            """.trimIndent()

    @Test fun originalUserLauncherUsesAotSafeStartupInfoSize() {
        val source = javaClass.getResource("/windows-install-original-user-launch.cs")!!.readText()

        assertFalse(
            Regex("""Marshal\.SizeOf\s*\(\s*typeof\s*\(""").containsMatchIn(source),
            "Original-user launcher must not use the NativeAOT-incompatible Marshal.SizeOf(Type) overload",
        )
    }

    @Test fun nativeShellHandleLaunchRetainsOriginalInteractiveTokenAndRejectsUnfixedArguments() {
        assumeTrue(System.getProperty("os.name").startsWith("Windows", true))
        val directory = Files.createTempDirectory("vpn-install-original-user-launch-")
        var protectedStage: Path? = null
        var interactiveCompleted = false
        val sources = listOf(
            "windows-install-native.cs", "windows-install-helper-protocol.cs", "windows-install-helper-roles.cs",
            "windows-install-helper-msi.cs", "windows-install-helper-sessions.cs", "windows-install-helper-inventory.cs",
            "windows-install-original-user-launch.cs", "windows-install-original-user-launch-fixture.cs",
        ).map { name ->
            directory.resolve(name).also { destination -> javaClass.getResourceAsStream("/$name")!!.use { Files.copy(it, destination) } }
        }
        try {
            val pin = Files.readAllBytes(Path.of(System.getProperty("vpnControl.test.nativeGlobalJson", "native/windows/global.json")))
            val sdk = Json.parseToJsonElement(pin.decodeToString()).jsonObject["sdk"]!!.jsonObject
            assertEquals("disable", sdk["rollForward"]!!.jsonPrimitive.content)
            Files.write(directory.resolve("global.json"), pin)
            Files.writeString(directory.resolve("NuGet.Config"), """
                <configuration><packageSources><clear />
                  <add key="nuget.org" value="https://api.nuget.org/v3/index.json" protocolVersion="3" />
                </packageSources></configuration>
            """.trimIndent())
            Files.writeString(directory.resolve("OriginalUserLaunchProbe.csproj"), fixtureProject())
            Files.writeString(directory.resolve("ProbeMain.cs"), """
                using System; using System.Threading;
                internal static class OriginalUserLaunchProbe {
                  public static void Main(string[] arguments) {
                    if (arguments.Length==4) {
                      if (arguments[1]=="00000000-0000-0000-0000-00000000000b") Thread.Sleep(Timeout.Infinite);
                      else Thread.Sleep(1000);
                      return;
                    }
                    if (arguments.Length==1 && arguments[0]=="--current-token") {
                      Console.WriteLine(InstallerOriginalUserLaunchFixtures.ProbeCurrentTokenScalars()); return;
                    }
                    if (arguments.Length==1 && arguments[0]=="--image-pin") {
                      Console.WriteLine(InstallerOriginalUserLaunchFixtures.ProbeCurrentImagePin()); return;
                    }
                    Console.WriteLine(InstallerOriginalUserLaunchFixtures.Run());
                  }
                }
            """.trimIndent())
            val dotnet = System.getenv("VPN_CONTROL_TEST_DOTNET") ?: "dotnet.exe"
            fun run(command: List<String>, timeout: Long): String {
                val process = ProcessBuilder(command).directory(directory.toFile()).redirectErrorStream(true).also { launcher ->
                    launcher.environment().putAll(mapOf("DOTNET_CLI_HOME" to directory.resolve("dotnet-home").toString(),
                        "DOTNET_SKIP_FIRST_TIME_EXPERIENCE" to "1", "DOTNET_CLI_TELEMETRY_OPTOUT" to "1", "DOTNET_MULTILEVEL_LOOKUP" to "0", "DOTNET_NOLOGO" to "1"))
                    System.getenv("VPN_CONTROL_TEST_DOTNET_ROOT")?.takeIf(String::isNotBlank)?.let { runtimeRoot ->
                        launcher.environment()["DOTNET_ROOT"] = runtimeRoot
                        launcher.environment()["DOTNET_ROOT_X64"] = runtimeRoot
                    }
                }.start()
                try {
                    assertTrue(process.waitFor(timeout, TimeUnit.SECONDS), "Original-user launch probe timed out")
                    val output = process.inputStream.bufferedReader().readText()
                    assertEquals(0, process.exitValue(), output)
                    return output
                } finally { if (process.isAlive) process.destroyForcibly() }
            }
            assertEquals(sdk["version"]!!.jsonPrimitive.content, run(listOf(dotnet, "--version"), 30).trim())
            run(listOf(dotnet, "build", "OriginalUserLaunchProbe.csproj", "--configuration", "Release", "--disable-build-servers", "-p:UseSharedCompilation=false"), 90)
            // This ordinary current-token probe runs on every Windows compiler
            // runner and must precede the separately authorized interactive VM.
            assertTrue(run(listOf(dotnet, directory.resolve("bin/Release/net10.0-windows").resolve(fixtureAssemblyFile()).toString(), "--current-token"), 30)
                .contains("ORIGINAL_USER_CURRENT_TOKEN_SCALARS_OK"))
            // A per-user installation is a supported production layout. Exercise
            // actual image/ancestry admission before the interactive-only gate.
            val imageNative = JnaWindowsInstallNative()
            val currentSid = JnaWindowsInstallAdmission().currentSid()
            val privateStage = directory.resolve("current-user-image")
            imageNative.createDirectory(privateStage.toString(),
                "O:${currentSid}G:${currentSid}D:P(A;OICI;FA;;;${currentSid})(A;OICI;FA;;;SY)", false)
            copyFixtureImage(directory.resolve("bin/Release/net10.0-windows"), privateStage)
            assertTrue(run(listOf(privateStage.resolve(fixtureExecutableFile()).toString(), "--image-pin"), 30)
                .contains("ORIGINAL_USER_IMAGE_PIN_OK"))
            // Hosted Windows runners have no interactive shell token. They still compile the
            // actual source; only an owned interactive fixture opts into token/process proof.
            assumeTrue("Requires an explicit interactive Windows fixture",
                System.getenv("VPN_CONTROL_NATIVE_ORIGINAL_USER_LAUNCH") == "1" ||
                    System.getProperty("vpn.control.native.interactiveOriginalUser") == "true")
            val outputDirectory = directory.resolve("bin/Release/net10.0-windows")
            val native = JnaWindowsInstallNative()
            val stage = Path.of(native.programData()).resolve("VpnOriginalUserLaunch-${UUID.randomUUID()}")
            protectedStage = stage
            native.createDirectory(stage.toString(), "O:BAG:BAD:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;GRGX;;;BU)", false)
            copyFixtureImage(outputDirectory, stage)
            val executable = stage.resolve(fixtureExecutableFile())
            require(Files.isRegularFile(executable, LinkOption.NOFOLLOW_LINKS))
            val output = run(listOf(executable.toString()), 30)
            assertTrue(output.contains("ORIGINAL_INTERACTIVE_USER_LAUNCH_OK"), output)
            interactiveCompleted = true
        } finally {
            if (protectedStage == null || interactiveCompleted) protectedStage?.toFile()?.deleteRecursively()
            if (protectedStage == null || interactiveCompleted) directory.toFile().deleteRecursively()
        }
    }

    private fun copyFixtureImage(source: Path, stage: Path) {
        require(Files.isDirectory(source, LinkOption.NOFOLLOW_LINKS))
        Files.list(source).use { entries ->
            entries.forEach { input ->
                require(Files.isRegularFile(input, LinkOption.NOFOLLOW_LINKS))
                val target = stage.resolve(input.fileName.toString())
                require(!Files.exists(target, LinkOption.NOFOLLOW_LINKS))
                Files.copy(input, target, LinkOption.NOFOLLOW_LINKS)
                require(Files.isRegularFile(target, LinkOption.NOFOLLOW_LINKS))
                require(Files.size(target) == Files.size(input) && sha256(target) == sha256(input))
            }
        }
    }

    private fun sha256(file: Path): String = Files.newInputStream(file).use { stream ->
        val digest = MessageDigest.getInstance("SHA-256")
        val buffer = ByteArray(8192)
        while (true) {
            val count = stream.read(buffer)
            if (count < 0) break
            digest.update(buffer, 0, count)
        }
        digest.digest().joinToString("") { "%02x".format(it) }
    }
}
