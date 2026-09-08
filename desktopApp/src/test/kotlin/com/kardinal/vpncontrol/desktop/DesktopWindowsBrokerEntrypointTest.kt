package com.kardinal.vpncontrol.desktop

import java.nio.file.Files
import java.util.Base64
import java.util.concurrent.TimeUnit
import org.junit.Assume.assumeTrue
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.fail

class DesktopWindowsBrokerEntrypointTest {
    @Test fun missingCompiledRuntimeAuthorityNeverReachesNativeRunner() = probe("missing")
    @Test fun mismatchedCompiledRuntimeAuthorityNeverReachesNativeRunner() = probe("mismatch")
    @Test fun matchingCompiledRuntimeAuthorityReachesOnlyTheFixedRunner() = probe("match")

    private fun probe(mode: String) {
        assumeTrue(System.getProperty("os.name").startsWith("Windows", true))
        val root = Files.createTempDirectory("vpn-broker-entry-")
        val names = listOf("windows-vpn-broker-main.cs", "windows-vpn-broker.cs", "windows-vpn-user-files.cs",
            "windows-vpn-cache-resources.cs", "windows-vpn-broker-entry-probe.cs")
        names.forEach { name ->
            requireNotNull(javaClass.getResourceAsStream("/$name")).use { input ->
                Files.newOutputStream(root.resolve(name)).use { output -> input.copyTo(output) }
            }
        }
        Files.writeString(root.resolve("authority.cs"),
            "internal static class VpnBrokerRuntimeAuthority { internal const string Sha256 = \"${"a".repeat(64)}\"; }")
        val script = """
            ${'$'}ErrorActionPreference='Stop'; ${'$'}ProgressPreference='SilentlyContinue'
            ${'$'}root=${'$'}env:VPN_CONTROL_BROKER_ENTRY_FIXTURE
            ${'$'}names=@('windows-vpn-broker-main.cs','windows-vpn-broker.cs','windows-vpn-user-files.cs','windows-vpn-cache-resources.cs','windows-vpn-broker-entry-probe.cs','authority.cs')
            ${'$'}sources=${'$'}names | ForEach-Object { Join-Path ${'$'}root ${'$'}_ }
            ${'$'}parameters=New-Object CodeDom.Compiler.CompilerParameters
            ${'$'}parameters.GenerateInMemory=${'$'}true
            ${'$'}parameters.ReferencedAssemblies.AddRange(@('System.dll','System.Core.dll','System.Web.Extensions.dll'))
            ${if (mode != "missing") "${'$'}parameters.CompilerOptions='/define:VPN_RUNTIME_AUTHORITY'" else ""}
            Add-Type -Path ${'$'}sources -CompilerParameters ${'$'}parameters
            [Console]::Write([BrokerEntryAuthorityProbe]::Run('$mode'))
        """.trimIndent()
        val process = ProcessBuilder("powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand",
            Base64.getEncoder().encodeToString(script.toByteArray(Charsets.UTF_16LE)))
            .redirectErrorStream(true).also { it.environment()["VPN_CONTROL_BROKER_ENTRY_FIXTURE"] = root.toString() }.start()
        if (!process.waitFor(30, TimeUnit.SECONDS)) {
            process.destroyForcibly() // The injected runner never opens a process or invokes a runtime.
            fail("Broker entry authority compiler fixture timed out; evidence retained at $root")
        }
        val output = process.inputStream.use { it.readNBytes(8193).decodeToString().take(8192) }
        assertEquals(0, process.exitValue(), output)
        assertTrue(output.endsWith("BROKER_AUTHORITY_OK:$mode:2"), output)
        (names + "authority.cs").forEach { Files.delete(root.resolve(it)) }
        Files.delete(root)
    }
}
