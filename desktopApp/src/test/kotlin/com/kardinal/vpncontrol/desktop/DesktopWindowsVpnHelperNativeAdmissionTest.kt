package com.kardinal.vpncontrol.desktop

import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import org.junit.Assume.assumeTrue
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.fail

/** Inert typed-native contracts; this does not launch a packaged owner, request UAC or run a VPN. */
class DesktopWindowsVpnHelperNativeAdmissionTest {
    @Test fun fixedNativeEntrypointKeepsItsOwnAdmissionAroundTheRunner() {
        assumeTrue(System.getProperty("os.name").startsWith("Windows", true))
        val compiler = Path.of(requireNotNull(System.getenv("SystemRoot")),
            "Microsoft.NET", "Framework64", "v4.0.30319", "csc.exe")
        assertTrue(Files.isRegularFile(compiler), "The Windows Framework compiler fixture prerequisite is missing")
        val root = Files.createTempDirectory("vpn-helper-admission-")
        val names = listOf("windows-install-native.cs", "windows-vpn-helper-admission.cs",
            "windows-vpn-broker-main.cs", "windows-vpn-broker.cs", "windows-vpn-user-files.cs",
            "windows-vpn-cache-resources.cs", "windows-vpn-helper-admission-probe.cs")
        names.forEach { name ->
            requireNotNull(javaClass.getResourceAsStream("/$name")).use { input ->
                Files.newOutputStream(root.resolve(name)).use(input::copyTo)
            }
        }
        Files.writeString(root.resolve("authority.cs"),
            "internal static class VpnBrokerRuntimeAuthority { internal const string Sha256 = \"${"a".repeat(64)}\"; }")
        fun run(arguments: List<String>, logName: String): String {
            val log = root.resolve(logName)
            val process = ProcessBuilder(arguments).redirectErrorStream(true).redirectOutput(log.toFile()).start()
            if (!process.waitFor(60, TimeUnit.SECONDS)) {
                process.destroyForcibly() // Exact inert compiler/test process, never a product process.
                fail("Native admission fixture timed out; evidence retained at $root")
            }
            val output = Files.newInputStream(log).use { it.readNBytes(8193).decodeToString().take(8192) }
            assertEquals(0, process.exitValue(), output)
            return output
        }
        val executable = root.resolve("fixture.exe")
        run(listOf(compiler.toString(), "/nologo", "/target:exe", "/platform:x64", "/define:VPN_RUNTIME_AUTHORITY",
            "/main:PackagedBrokerAdmissionProbe", "/r:System.dll", "/r:System.Core.dll", "/r:System.Web.Extensions.dll",
            "/out:$executable") + (names + "authority.cs").map { root.resolve(it).toString() }, "compile.log")
        val output = run(listOf(executable.toString()), "run.log")
        assertTrue(output.lineSequence().any { it.trim() == "PACKAGED_BROKER_ADMISSION_OK:16" }, output)
        assertTrue(output.lineSequence().any { it.trim() == "PACKAGED_BROKER_ENTRY_FENCE_OK:6" }, output)
        (names + listOf("authority.cs", "fixture.exe", "compile.log", "run.log")).forEach { Files.delete(root.resolve(it)) }
        Files.delete(root)
    }
}
