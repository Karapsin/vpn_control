package com.kardinal.vpncontrol.desktop

import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assume.assumeTrue
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class DesktopWindowsInstallHelperInventoryTest {
    @Test fun nativeInventoryBlocksLiveRetainedInstallationImagesAndOnlyExcludesExactWorker() {
        assumeTrue(System.getProperty("os.name").startsWith("Windows", true))
        val directory = Files.createTempDirectory("vpn-install-inventory-")
        listOf(
            "windows-install-native.cs", "windows-install-helper-inventory.cs",
            "windows-install-helper-inventory-fixture.cs",
        ).map { name -> directory.resolve(name).also { path ->
            javaClass.getResourceAsStream("/$name")!!.use { Files.copy(it, path) }
        } }
        try {
            val pin = Files.readAllBytes(Path.of(System.getProperty("vpnControl.test.nativeGlobalJson", "native/windows/global.json")))
            val sdk = Json.parseToJsonElement(pin.decodeToString()).jsonObject["sdk"]!!.jsonObject
            assertEquals("disable", sdk["rollForward"]!!.jsonPrimitive.content)
            Files.write(directory.resolve("global.json"), pin)
            Files.writeString(directory.resolve("NuGet.Config"), "<configuration><packageSources><clear /></packageSources></configuration>")
            Files.writeString(directory.resolve("InventoryProbe.csproj"), """
                <Project Sdk="Microsoft.NET.Sdk"><PropertyGroup>
                  <TargetFramework>net10.0-windows</TargetFramework><OutputType>Exe</OutputType>
                  <StartupObject>InventoryProbe</StartupObject><UseAppHost>false</UseAppHost>
                  <InvariantGlobalization>true</InvariantGlobalization><Nullable>disable</Nullable>
                  <ImplicitUsings>disable</ImplicitUsings><TreatWarningsAsErrors>true</TreatWarningsAsErrors>
                </PropertyGroup></Project>
            """.trimIndent())
            Files.writeString(directory.resolve("ProbeMain.cs"), """
                using System;
                internal static class InventoryProbe {
                  public static void Main() {
                    foreach (string value in InstallerInventoryFixtures.Run()) Console.WriteLine("CASE:"+value);
                    Console.WriteLine("FIXED_INSTALL_INVENTORY_OK");
                  }
                }
            """.trimIndent())
            val dotnet = System.getenv("VPN_CONTROL_TEST_DOTNET") ?: "dotnet.exe"
            fun run(phase: String, args: List<String>): String {
                val stdout = directory.resolve("$phase-stdout.txt")
                val stderr = directory.resolve("$phase-stderr.txt")
                val process = ProcessBuilder(listOf(dotnet) + args).directory(directory.toFile())
                    .redirectOutput(stdout.toFile()).redirectError(stderr.toFile()).also {
                        it.environment().putAll(mapOf(
                            "DOTNET_CLI_HOME" to directory.resolve("dotnet-home").toString(),
                            "DOTNET_SKIP_FIRST_TIME_EXPERIENCE" to "1", "DOTNET_CLI_TELEMETRY_OPTOUT" to "1",
                            "DOTNET_MULTILEVEL_LOOKUP" to "0", "DOTNET_NOLOGO" to "1",
                            "DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE" to "1", "MSBUILDDISABLENODEREUSE" to "1",
                        ))
                    }.start()
                process.outputStream.close()
                assertTrue(process.waitFor(90, TimeUnit.SECONDS), "Native inventory $phase timed out; evidence: $directory")
                val text = Files.readString(stdout) + Files.readString(stderr)
                assertEquals(0, process.exitValue(), "Native inventory $phase failed; evidence: $directory\n$text")
                return text
            }
            assertEquals(sdk["version"]!!.jsonPrimitive.content, run("sdk", listOf("--version")).trim())
            run("build", listOf("build", "InventoryProbe.csproj", "--configuration", "Release", "--disable-build-servers", "-p:UseSharedCompilation=false"))
            val text = run("probe", listOf(directory.resolve("bin/Release/net10.0-windows/InventoryProbe.dll").toString()))
            assertEquals(4, text.lineSequence().count { it.startsWith("CASE:") }, text)
            assertTrue(text.contains("FIXED_INSTALL_INVENTORY_OK"), text)
        } finally {
            directory.toFile().deleteRecursively()
        }
    }
}
