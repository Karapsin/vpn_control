package com.kardinal.vpncontrol.desktop

import java.nio.file.Files
import java.util.Base64
import java.util.concurrent.TimeUnit
import org.junit.Assume.assumeTrue
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.fail

class DesktopWindowsVpnAdmissionNativeTest {
    @Test fun protectedAncestorsRequireARealRetainedWitnessAndHandleMetadata() {
        assumeTrue(System.getProperty("os.name").startsWith("Windows", true))
        assumeTrue(System.getenv("VPN_CONTROL_TEST_WINDOWS_PROTECTED_ANCESTORS") == "1")
        // Explicit privileged fixture opt-in; this probe never launches a runtime or installer.
        val root = Files.createTempDirectory("vpn-protected-ancestor-")
        val report = root.resolve("probe.log")
        val source = listOf("/windows-vpn-broker.cs", "/windows-vpn-user-files.cs", "/windows-vpn-cache-resources.cs",
            "/windows-vpn-broker-admission-probe.cs").joinToString("\n") { resource ->
            requireNotNull(javaClass.getResourceAsStream(resource)).use { it.readBytes().decodeToString() }
        }
        val script = """
            ${'$'}ErrorActionPreference='Stop';${'$'}ProgressPreference='SilentlyContinue'
            ${'$'}principal=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
            if(-not ${'$'}principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Privileged fixture token required'}
            Add-Type -TypeDefinition ([Console]::In.ReadToEnd()) -ReferencedAssemblies @('System.dll','System.Core.dll','System.Web.Extensions.dll')
            [Console]::Write([VpnBrokerFixtures.AncestorProbe]::Run(${'$'}env:VPN_CONTROL_ANCESTOR_FIXTURE))
        """.trimIndent()
        val process = ProcessBuilder("powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand",
            Base64.getEncoder().encodeToString(script.toByteArray(Charsets.UTF_16LE)))
            .redirectErrorStream(true).redirectOutput(report.toFile()).also {
                it.environment()["VPN_CONTROL_ANCESTOR_FIXTURE"] = root.toString()
            }.start()
        process.outputStream.use { it.write(source.encodeToByteArray()) }
        if (!process.waitFor(30, TimeUnit.SECONDS)) {
            process.destroyForcibly() // Only this compiler and private admission fixture are owned.
            fail("Native ancestor admission probe timed out; private evidence was retained")
        }
        val output = Files.newInputStream(report).use { it.readNBytes(8193).decodeToString().take(8192) }
        assertEquals(0, process.exitValue(), output)
        assertTrue(output.endsWith("BROKER_ANCESTOR_OK:5"), output)
        Files.delete(report)
        Files.delete(root) // Never erase an unexpected entry or a failed fixture recursively.
    }
}
