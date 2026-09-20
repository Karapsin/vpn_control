package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.UpdateAsset
import com.kardinal.vpncontrol.UpdatePackageType
import com.kardinal.vpncontrol.UpdatePlatform
import com.kardinal.vpncontrol.model.ControlCode
import com.sun.jna.Platform
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlinx.coroutines.runBlocking
import kotlin.test.*

class DesktopMacInstallerTest {
    @Test fun exactPublishedCleanupWorkerAt0600RetriesItsInterruptedChmod() {
        val directory = Files.createTempDirectory("vpn-mac-cleanup-worker")
        val worker = directory.resolve("vpn-control-install-cleanup-worker")
        val bytes = "current packaged worker".encodeToByteArray()
        try {
            org.junit.Assume.assumeTrue("macOS descriptor behavior", Platform.isMac() && "posix" in directory.fileSystem.supportedFileAttributeViews())
            Files.write(worker, bytes)
            Files.setPosixFilePermissions(worker, PosixFilePermissions.fromString("rw-------"))
            materializeMacNotStartedCleanupWorker(worker, bytes)
            assertEquals(PosixFilePermissions.fromString("rwx------"), Files.getPosixFilePermissions(worker))
        } finally { directory.toFile().deleteRecursively() }
    }

    @Test fun cleanupWorkerRetryRejectsModifiedModesContentAndLinks() {
        val directory = Files.createTempDirectory("vpn-mac-cleanup-worker-reject")
        val worker = directory.resolve("vpn-control-install-cleanup-worker")
        val bytes = "current packaged worker".encodeToByteArray()
        try {
            org.junit.Assume.assumeTrue("macOS descriptor behavior", Platform.isMac() && "posix" in directory.fileSystem.supportedFileAttributeViews())
            Files.write(worker, bytes)
            Files.setPosixFilePermissions(worker, PosixFilePermissions.fromString("rw-r-----"))
            assertFails { materializeMacNotStartedCleanupWorker(worker, bytes) }
            Files.delete(worker)
            Files.write(worker, "modified worker".encodeToByteArray())
            Files.setPosixFilePermissions(worker, PosixFilePermissions.fromString("rwx------"))
            assertFails { materializeMacNotStartedCleanupWorker(worker, bytes) }
            Files.delete(worker)
            Files.createSymbolicLink(worker, directory.resolve("replacement"))
            assertFails { materializeMacNotStartedCleanupWorker(worker, bytes) }
        } finally { directory.toFile().deleteRecursively() }
    }

    @Test fun freshOwnerDoesNotRunCleanupAgainAfterInputsWereReleased() {
        val input = Files.createTempDirectory("vpn-mac-cleanup-owner")
        var calls = 0
        try {
            releaseMacNotStartedInput(input) {
                calls++
                Files.delete(input)
            }
            releaseMacNotStartedInput(input) { error("No worker may be staged for an already released input") }
            assertEquals(1, calls)
        } finally { input.toFile().deleteRecursively() }
    }

    @Test fun onlyAnExactMissingNoStartInputIsAnIdempotentCleanupSuccess() {
        val directory = Files.createTempDirectory("vpn-mac-not-started-input")
        val input = directory.resolve("input")
        try {
            assertTrue(macInstallInputMissing(input))
            Files.createDirectory(input)
            assertFalse(macInstallInputMissing(input))
            Files.writeString(input.resolve("unexpected"), "retain")
            assertFalse(macInstallInputMissing(input))
        } finally { directory.toFile().deleteRecursively() }
    }

    @Test fun danglingPosixLinkIsNotAnAlreadyReleasedInput() {
        val directory = Files.createTempDirectory("vpn-mac-input-link")
        try {
            org.junit.Assume.assumeTrue("POSIX symbolic-link semantics", "posix" in directory.fileSystem.supportedFileAttributeViews())
            val input = directory.resolve("input")
            Files.createSymbolicLink(input, directory.resolve("replacement-target"))
            assertFalse(macInstallInputMissing(input))
        } finally { directory.toFile().deleteRecursively() }
    }

    @Test fun unsupportedPlatformAndPackageCannotStageOrLaunchNativeWorker() = runBlocking {
        val asset = UpdateAsset(UpdatePlatform.MACOS, "arm64", UpdatePackageType.DMG, "1.0.0", "update.dmg",
            "https://example.invalid/update.dmg", "a".repeat(64), 1)
        val correlation = DesktopInstallCorrelation("controller", "request", "operation")
        val absent = Path.of("/does-not-exist/vpn-control-test-package.dmg")
        val workspace = Path.of(System.getProperty("java.io.tmpdir")).resolve("vpn-mac-unsupported-${java.util.UUID.randomUUID()}")
        assertEquals("UNSUPPORTED", DesktopMacInstaller(workspace, isMac = { false })
            .prepare(absent, asset, correlation).exceptionOrNull()?.message)
        assertEquals("UNSUPPORTED", DesktopMacInstaller(workspace, isMac = { true })
            .prepare(absent, asset.copy(packageType = UpdatePackageType.DEB), correlation).exceptionOrNull()?.message)
        assertFalse(java.nio.file.Files.exists(workspace))
    }

    @Test fun provenUnstartedCancellationIsIdempotentButUnconfirmedExternalWorkerStaysUnknown() = runBlocking {
        var recorded = 0
        var confirmed = 0
        var delegated = 0
        val delegate = object : DesktopPreparedInstall {
            override val jobId = "05dc777a-9bb2-4a73-8d20-b42f45f64a32"
            override suspend fun commit() = Result.success(Unit)
            override fun cancel(): Result<Unit> { delegated++; return Result.failure(IllegalStateException("OUTCOME_UNKNOWN")) }
            override fun close() {}
        }
        val unstarted = DesktopMacUnstartedCancellation(delegate, { true }, { recorded++ }, { confirmed++ })
        unstarted.cancel().getOrThrow(); unstarted.cancel().getOrThrow()
        assertEquals(1, recorded); assertEquals(1, confirmed); assertEquals(0, delegated)
        assertEquals("CANCELLED", unstarted.commit().exceptionOrNull()?.message)
        val external = DesktopMacUnstartedCancellation(delegate, { false }, { error("No local proof") }, { error("Unconfirmed") })
        assertEquals("OUTCOME_UNKNOWN", external.cancel().exceptionOrNull()?.message)
        assertEquals("OUTCOME_UNKNOWN", external.cancel().exceptionOrNull()?.message)
        assertEquals(2, delegated)
    }

    @Test fun closeFailureLeavesPreparedCancellationRetryable() {
        var closes = 0
        val delegate = object : DesktopPreparedInstall {
            override val jobId = "05dc777a-9bb2-4a73-8d20-b42f45f64a32"
            override suspend fun commit() = Result.success(Unit)
            override fun cancel() = Result.success(Unit)
            override fun close() {
                closes++
                if (closes == 1) error("close failed")
            }
        }
        val prepared = DesktopMacUnstartedCancellation(delegate, { true }, {}, {})

        assertFails { prepared.close() }
        prepared.close()
        assertEquals(2, closes)
    }

    @Test fun exitedCoordinatorAfterAuthoritativePreparingReceiptChecksOnceAndPreservesTheJob() = runBlocking {
        val job = "00000000-0000-0000-0000-000000000051"
        var reads = 0
        var commits = 0
        var cancellations = 0
        var releases = 0
        var coordinatorChecks = 0
        val prepared = DesktopReceiptPreparedInstall(
            jobId = job,
            readReceipt = {
                reads++
                DesktopInstallJobReceipt(job, 0, DesktopInstallJobPhase.PREPARING, ControlCode.OK)
            },
            publishCommit = { commits++ },
            requestCancellation = { cancellations++ },
            release = { releases++ },
            timeoutMillis = 0,
            nonterminalReceiptFailure = {
                coordinatorChecks++
                IllegalStateException(ControlCode.OUTCOME_UNKNOWN.name)
            },
        )

        assertEquals(ControlCode.OUTCOME_UNKNOWN.name, prepared.awaitAuthorization().exceptionOrNull()?.message)
        assertEquals(1, reads)
        assertEquals(1, coordinatorChecks)
        assertEquals(0, commits)
        assertEquals(0, cancellations)
        assertEquals(0, releases)
    }
}
