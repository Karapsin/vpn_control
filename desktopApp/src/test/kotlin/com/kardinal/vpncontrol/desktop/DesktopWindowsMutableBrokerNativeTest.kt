package com.kardinal.vpncontrol.desktop

import java.nio.file.Files
import java.util.Base64
import java.util.concurrent.TimeUnit
import org.junit.Assume.assumeTrue
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.fail

class DesktopWindowsMutableBrokerNativeTest {
    @Test fun metadataFramesCannotConsumeConfigurationOrAllocateUnboundedIdentityArrays() =
        probe("MutableBrokerStateProbe", "MetadataFrames", "MUTABLE_METADATA_OK:7")

    @Test fun capturedCachePathsPreserveOptionsAndRejectUnadmittedReferences() =
        probe("MutableBrokerStateProbe", "ConfigurationMapping", "MUTABLE_CONFIGURATION_OK:5")

    @Test fun gateAndCommitOrderingPreservesUncertainPublicationAndCloseOwnership() =
        probe("MutableBrokerStateProbe", "Ordering", "MUTABLE_ORDERING_OK:6")

    @Test fun nativeMutableHandshakePublishesOnlyAfterExitAndRejectsRepeatedAdmission() =
        probe("MutableBrokerProbe", "Ready", "MUTABLE_BROKER_OK:1:", nativeChild = true)

    @Test fun nativeConfigurationLargerThanMetadataFrameKeepsItsChunkedTransport() =
        probe("MutableBrokerProbe", "LargeConfiguration", "MUTABLE_BROKER_OK:1:", nativeChild = true)

    private fun probe(type: String, method: String, expected: String, nativeChild: Boolean = false) {
        assumeTrue(System.getProperty("os.name").startsWith("Windows", true))
        if (nativeChild) assumeTrue(System.getenv("VPN_CONTROL_TEST_SCOPED_BROKER_MUTABLE") == "1")
        val root = Files.createTempDirectory("vpn-mutable-broker-")
        val names = listOf("windows-vpn-broker.cs", "windows-vpn-user-files.cs", "windows-vpn-cache-resources.cs",
            "windows-vpn-mutable-broker-probe.cs", "windows-vpn-mutable-child.cs")
        names.forEach { name ->
            requireNotNull(javaClass.getResourceAsStream("/$name")).use { input ->
                Files.newOutputStream(root.resolve(name)).use { output -> input.copyTo(output) }
            }
        }
        val script = """
            ${'$'}ErrorActionPreference='Stop'; ${'$'}ProgressPreference='SilentlyContinue'
            ${'$'}root=${'$'}env:VPN_CONTROL_MUTABLE_BROKER_FIXTURE
            ${'$'}references=@('System.dll','System.Core.dll','System.Web.Extensions.dll')
            ${'$'}sources=@('windows-vpn-broker.cs','windows-vpn-user-files.cs','windows-vpn-cache-resources.cs','windows-vpn-mutable-broker-probe.cs') | ForEach-Object { Join-Path ${'$'}root ${'$'}_ }
            Add-Type -Path ${'$'}sources -ReferencedAssemblies ${'$'}references
            ${if (nativeChild) """
                ${'$'}child=Join-Path ${'$'}root 'inert-child.exe'
                Add-Type -Path (Join-Path ${'$'}root 'windows-vpn-mutable-child.cs') -ReferencedAssemblies ${'$'}references -OutputAssembly ${'$'}child -OutputType ConsoleApplication
                [Console]::Write([$type]::$method(${'$'}root,${'$'}child))
            """.trimIndent() else "[Console]::Write([$type]::$method(${'$'}root))"}
        """.trimIndent()
        val process = ProcessBuilder("powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand",
            Base64.getEncoder().encodeToString(script.toByteArray(Charsets.UTF_16LE)))
            .redirectErrorStream(true).also { it.environment()["VPN_CONTROL_MUTABLE_BROKER_FIXTURE"] = root.toString() }.start()
        if (!process.waitFor(if (nativeChild) 120L else 30L, TimeUnit.SECONDS)) {
            process.destroyForcibly() // This exact fixture owns only its captured inert child; no VPN or installer.
            fail("Native mutable broker fixture timed out; evidence retained at $root")
        }
        val output = process.inputStream.use { it.readNBytes(8193).decodeToString().take(8192) }
        assertEquals(0, process.exitValue(), output)
        assertTrue(if (nativeChild) output.contains(expected) else output.endsWith(expected), output)
        if (nativeChild) System.err.println("Native mutable broker fixture retained at $root")
        else { names.forEach { Files.delete(root.resolve(it)) }; Files.delete(root) }
    }
}
