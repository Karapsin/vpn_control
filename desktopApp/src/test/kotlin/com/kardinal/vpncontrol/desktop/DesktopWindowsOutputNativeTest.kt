package com.kardinal.vpncontrol.desktop

import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import java.util.concurrent.TimeUnit
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assume.assumeTrue
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.fail

/** Modern .NET and Win32 file semantics; ordinary inert IO, no runtime, installer or authorization. */
class DesktopWindowsOutputNativeTest {
    @Test fun productionOutputParserAndOriginalTokenPublicationPreserveAuthority() {
        assumeTrue(System.getProperty("os.name").startsWith("Windows", true))
        val dotnet = System.getenv("VPN_CONTROL_TEST_DOTNET") ?: "dotnet.exe"
        // The standalone native harness supplies the same captured repository pin explicitly.
        val pin = Path.of(System.getProperty("vpnControl.test.nativeGlobalJson", "native/windows/global.json"))
        val pinBytes = Files.readAllBytes(pin)
        val sdk = Json.parseToJsonElement(pinBytes.decodeToString()).jsonObject["sdk"]!!.jsonObject
        val expectedVersion = sdk["version"]!!.jsonPrimitive.content
        assertEquals("disable", sdk["rollForward"]!!.jsonPrimitive.content)
        val root = Files.createTempDirectory("vpn-output-native-").toRealPath()
        val inputs = listOf("windows-vpn-broker.cs", "windows-vpn-user-files.cs", "windows-vpn-cache-resources.cs", "windows-vpn-config.cs", "windows-vpn-output-probe.cs")
        for (name in inputs) {
            val bytes = requireNotNull(javaClass.getResourceAsStream("/$name")).use { it.readBytes() }
            Files.write(root.resolve(name), bytes)
            val hash = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
            println("NATIVE_OUTPUT_INPUT $name $hash")
        }
        Files.write(root.resolve("global.json"), pinBytes)
        Files.writeString(root.resolve("NuGet.Config"), "<configuration><packageSources><clear /></packageSources></configuration>")
        Files.writeString(root.resolve("OutputProbe.csproj"), """
            <Project Sdk="Microsoft.NET.Sdk"><PropertyGroup>
              <TargetFramework>net10.0-windows</TargetFramework><OutputType>Exe</OutputType>
              <UseAppHost>false</UseAppHost><InvariantGlobalization>true</InvariantGlobalization><EnableDefaultCompileItems>false</EnableDefaultCompileItems>
              <Nullable>disable</Nullable><ImplicitUsings>disable</ImplicitUsings>
              <TreatWarningsAsErrors>true</TreatWarningsAsErrors>
            </PropertyGroup><ItemGroup><Compile Include="*.cs" /></ItemGroup></Project>
        """.trimIndent())
        fun run(phase: String, arguments: List<String>, seconds: Long = 60): String {
            val stdout = root.resolve("$phase-stdout.txt")
            val stderr = root.resolve("$phase-stderr.txt")
            val process = ProcessBuilder(listOf(dotnet) + arguments).directory(root.toFile())
                .redirectOutput(stdout.toFile()).redirectError(stderr.toFile()).also {
                    it.environment().putAll(mapOf(
                        "DOTNET_CLI_HOME" to root.resolve("dotnet-home").toString(),
                        "DOTNET_SKIP_FIRST_TIME_EXPERIENCE" to "1", "DOTNET_CLI_TELEMETRY_OPTOUT" to "1",
                        "DOTNET_MULTILEVEL_LOOKUP" to "0", "DOTNET_NOLOGO" to "1",
                        "DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE" to "1", "MSBUILDDISABLENODEREUSE" to "1",
                    ))
                }.start()
            process.outputStream.close()
            Files.writeString(root.resolve("$phase-process.txt"), "pid=${process.pid()}\ncommand=${listOf(dotnet) + arguments}\n")
            if (!process.waitFor(seconds, TimeUnit.SECONDS)) {
                // Preserve this exact compiler/probe and its evidence; never infer terminal state.
                synchronized(retainedProcesses) { retainedProcesses.add(process) }
                fail("Native OUTPUT $phase still owns PID ${process.pid()}; evidence: $root")
            }
            val output = Files.newInputStream(stdout).use { it.readNBytes(8192).decodeToString() }
            val error = Files.newInputStream(stderr).use { it.readNBytes(8192).decodeToString() }
            assertEquals(0, process.exitValue(), "Native OUTPUT $phase failed; evidence: $root\n$output\n$error")
            return output
        }
        assertEquals(expectedVersion, run("sdk", listOf("--version")).trim())
        run("restore", listOf("restore", "OutputProbe.csproj", "--configfile", "NuGet.Config"))
        run("build", listOf("build", "OutputProbe.csproj", "--configuration", "Release", "--no-restore", "--disable-build-servers"))
        val cases = Files.createDirectory(root.resolve("cases"))
        val output = run("probe", listOf(root.resolve("bin/Release/net10.0-windows/OutputProbe.dll").toString(), cases.toString()))
        assertTrue(output.trimEnd().endsWith("OUTPUT_PROBE selected=17 failed=0"), output)
        Files.list(cases).use { assertEquals(0L, it.count(), "Successful native cases left mutable fixture data") }
        Files.delete(cases)
        println("NATIVE_OUTPUT_OK:17 SDK=$expectedVersion evidence=$root")
    }

    companion object {
        private val retainedProcesses = mutableListOf<Process>()
    }
}
