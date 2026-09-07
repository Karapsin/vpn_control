package com.kardinal.vpncontrol.desktop

import java.nio.file.Files
import java.util.Base64
import java.util.concurrent.TimeUnit
import org.junit.Assume.assumeTrue
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.fail

class DesktopWindowsUserFilesNativeTest {
    @Test fun retainedOriginalTokenPublishesWithoutOverwritingReplacedFilesOrParents() {
        runProbe("UserFilesProbe", "USER_FILES_OK:13")
    }

    @Test fun durableJournalRecoversReadOnlyAfterReplyLossAndPreservesEstablishedSuccess() {
        runProbe("PublicationJournalProbe", "JOURNAL_OK:13")
    }

    @Test fun ordinaryOwnerAndRetainedTokenAgreeOnTheAdmittedDestinationIdentity() {
        runProbe("UserFilesProbe", "AdmittedParent") { root ->
            DesktopWindowsResourceAdmission.capture(root.resolve("cache.db")).parentIdentity
        }
    }

    @Test fun privateScopeAdmissionRejectsWrongScopeReplacementsAndPublicReaders() {
        runProbe("ScopeRecordProbe", "SCOPE_OK:5")
    }

    @Test fun cacheLeasePreservesLatestBytesAndSeparatesPublicationFailureFromKnownCommit() {
        runProbe("CacheLeaseProbe", "CACHE_LEASE_OK:3")
    }

    @Test fun resourceGateRequiresOriginalExitAndExclusiveAdmissionBeforeClosing() {
        runProbe("ResourceGateProbe", "RESOURCE_GATE_OK:7")
    }

    @Test fun cacheBatchClosesRuntimeInputsAndKeepsPublicationOutsideTheStatusLock() {
        runProbe("CacheBatchProbe", "CACHE_BATCH_OK:4")
    }

    @Test fun resourcePreparationBindsKotlinAndNativeIdentityWithoutOpeningDestinations() {
        runProbe("ResourceWireProbe", "Run") { root ->
            val (job, resources) = DesktopWindowsRuntimeResourceProtocolTest.fixture()
            val bytes = java.io.ByteArrayOutputStream().also { output ->
                DesktopWindowsRuntimeResourceProtocol.writePreparation(job, resources.reversed()) { part, offset, count ->
                    output.write(part, offset, count)
                }
            }.toByteArray()
            Files.write(root.resolve("preparation.bin"), bytes)
            val digest = java.security.MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
            "RESOURCE_WIRE_OK:6:$digest"
        }
    }

    private fun runProbe(probe: String, expected: String) = runProbe(probe, "Run") { expected }

    private fun runProbe(probe: String, method: String, expectedValue: (java.nio.file.Path) -> String) {
        assumeTrue(System.getProperty("os.name").startsWith("Windows", true))
        assumeTrue(System.getenv("VPN_CONTROL_TEST_WINDOWS_USER_FILES") == "1")
        val root = Files.createTempDirectory("vpn-user-file-authority-")
        val expected = expectedValue(root)
        val source = listOf("/windows-vpn-user-files.cs", "/windows-vpn-cache-resources.cs", "/windows-vpn-user-files-probe.cs").joinToString("\n") {
            requireNotNull(javaClass.getResourceAsStream(it)).use { input -> input.readBytes().decodeToString() }
        }
        val script = """
            ${'$'}ErrorActionPreference='Stop'; ${'$'}ProgressPreference='SilentlyContinue'
            Add-Type -TypeDefinition ([Console]::In.ReadToEnd()) -ReferencedAssemblies @('System.dll','System.Core.dll')
            [Console]::Write([VpnScopedStorage.$probe]::$method(${'$'}env:VPN_CONTROL_USER_FILES_FIXTURE))
        """.trimIndent()
        val process = ProcessBuilder("powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand",
            Base64.getEncoder().encodeToString(script.toByteArray(Charsets.UTF_16LE)))
            .redirectErrorStream(true).also { it.environment()["VPN_CONTROL_USER_FILES_FIXTURE"] = root.toString() }.start()
        process.outputStream.use { it.write(source.encodeToByteArray()) }
        if (!process.waitFor(30, TimeUnit.SECONDS)) {
            process.destroyForcibly() // This exact ordinary compiler/probe never owns a VPN or installer.
            fail("Native resource authority probe timed out; its private evidence was retained")
        }
        val output = process.inputStream.use { it.readNBytes(8193).decodeToString().take(8192) }
        assertEquals(0, process.exitValue(), output)
        assertTrue(output.endsWith(expected), output)
        Files.delete(root) // Nonrecursive; a failed or partial publication keeps its evidence.
    }
}
