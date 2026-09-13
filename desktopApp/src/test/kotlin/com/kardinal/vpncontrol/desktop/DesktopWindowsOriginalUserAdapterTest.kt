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
import kotlin.test.fail

class DesktopWindowsOriginalUserAdapterTest {
    @Test fun acknowledgementLossRetainsTheAttemptAndNeverReplaysMsi() = runFixture("AcknowledgementLossDoesNotReplayMsi", "ACK_LOSS_NO_REPLAY")

    @Test fun wrongReceiptCorrelationIsRejectedBeforeAnyMsiInvocation() = runFixture("WrongCorrelationIsRejectedBeforeMsi", "FOREIGN_RECEIPT_REJECTED")

    @Test fun stalledInstallingReceiptReachesTheFiniteReconciliationDeadline() = runFixture("StalledInstallingReceiptReachesDeadline", "INSTALLING_DEADLINE_REACHED")

    @Test fun advancedInstallingReceiptWaitsForItsCorrelatedTerminalReceipt() = runFixture("AdvancedInstallingReceiptWaitsForTerminal", "ADVANCED_INSTALLING_ACCEPTED")

    private fun runFixture(operation: String, expected: String) {
        assumeTrue(System.getProperty("os.name").startsWith("Windows", true))
        val directory = Files.createTempDirectory("vpn-install-original-user-")
        listOf(
            "windows-install-native.cs", "windows-install-helper-protocol.cs",
            "windows-install-helper-roles.cs", "windows-install-helper-msi.cs",
            "windows-install-helper-sessions.cs", "windows-install-helper-original-user-fixture.cs",
        ).forEach { name -> javaClass.getResourceAsStream("/$name")!!.use { Files.copy(it, directory.resolve(name)) } }
        try {
            val pin = Files.readAllBytes(Path.of(System.getProperty("vpnControl.test.nativeGlobalJson", "native/windows/global.json")))
            val sdk = Json.parseToJsonElement(pin.decodeToString()).jsonObject["sdk"]!!.jsonObject
            assertEquals("disable", sdk["rollForward"]!!.jsonPrimitive.content)
            Files.write(directory.resolve("global.json"), pin)
            Files.writeString(directory.resolve("NuGet.Config"), "<configuration><packageSources><clear /></packageSources></configuration>")
            Files.writeString(directory.resolve("OriginalUserAdapterProbe.csproj"), """
                <Project Sdk="Microsoft.NET.Sdk"><PropertyGroup>
                  <TargetFramework>net10.0-windows</TargetFramework><OutputType>Exe</OutputType>
                  <StartupObject>OriginalUserAdapterProbe</StartupObject><UseAppHost>false</UseAppHost>
                  <InvariantGlobalization>true</InvariantGlobalization><Nullable>disable</Nullable>
                  <ImplicitUsings>disable</ImplicitUsings><TreatWarningsAsErrors>true</TreatWarningsAsErrors>
                </PropertyGroup></Project>
            """.trimIndent())
            Files.writeString(directory.resolve("ProbeMain.cs"), """
                using System;
                internal static class OriginalUserAdapterProbe {
                  public static void Main() { Console.WriteLine(OriginalUserAdapterFixtures.$operation()); }
                }
            """.trimIndent())
            val dotnet = System.getenv("VPN_CONTROL_TEST_DOTNET") ?: "dotnet.exe"
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
                if (!process.waitFor(90, TimeUnit.SECONDS)) {
                    synchronized(retainedProcesses) { retainedProcesses.add(process) }
                    fail("Original-user $phase still owns PID ${process.pid()}; evidence: $directory")
                }
                val stdout = Files.readString(output)
                val stderr = Files.readString(error)
                assertEquals(0, process.exitValue(), "Original-user $phase failed; evidence: $directory\n$stdout\n$stderr")
                return stdout
            }
            assertEquals(sdk["version"]!!.jsonPrimitive.content, run("sdk", listOf("--version")).trim())
            run("build", listOf("build", "OriginalUserAdapterProbe.csproj", "--configuration", "Release", "--disable-build-servers", "-p:UseSharedCompilation=false"))
            val text = run("probe", listOf(directory.resolve("bin/Release/net10.0-windows/OriginalUserAdapterProbe.dll").toString()))
            assertTrue(text.contains(expected), text)
            println("NATIVE_ORIGINAL_USER_ADAPTER_OK evidence=$directory")
        } finally {
            if (!retainedProcesses.any { it.isAlive }) directory.toFile().deleteRecursively()
        }
    }

    companion object { private val retainedProcesses = mutableListOf<Process>() }
}
