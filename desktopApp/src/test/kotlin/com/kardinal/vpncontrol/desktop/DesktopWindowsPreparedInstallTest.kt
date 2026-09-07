package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.ControlCode
import com.kardinal.vpncontrol.model.ControlValue
import kotlinx.coroutines.runBlocking
import java.nio.file.Files
import kotlin.test.*

class DesktopWindowsPreparedInstallTest {
    @Test fun externallyExitedWorkerBeforeReadinessRemainsFailureInOperationAndRecovery() = runBlocking {
        val workspace = Files.createTempDirectory("windows-preauthorization-worker-exit-")
        val correlation = DesktopInstallCorrelation("live-owner", "original-request", "original-operation")
        val journal = DesktopInstallCorrelationJournal(workspace,
            readProtectedReceipt = { throw WindowsInstallNativeFailure(2) })
        journal.record(correlation, job)
        var launches = 0
        var releases = 0
        val receipt = object : DesktopPreparedInstall {
            override val jobId = job
            override suspend fun commit(): Result<Unit> = error("No readiness or authorization was published")
            override fun cancel(): Result<Unit> = Result.failure(WindowsInstallNativeFailure(2))
            override fun close() { releases++ }
        }
        val prepared = DesktopWindowsUnstartedCancellation(receipt,
            canProveNotStarted = { windowsInstallDefinitelyNotStarted(false, false, false) },
            recordNotStarted = { journal.markNotStarted(correlation, job, ControlCode.RUNTIME_FAILED) },
            onCancellationConfirmed = {})
        val handoff = DesktopInstallHandoff(
            prepare = {
                launches++
                Result.failure(DesktopInstallPreparationFailure(prepared,
                    IllegalStateException(ControlCode.RUNTIME_FAILED.name)))
            },
            stopRuntime = { fail("Unexpected worker exit must preserve the active owner") },
            requestExit = { fail("No installer handoff was authorized") })
        try {
            assertEquals(DesktopInstallHandoffResult(ControlCode.RUNTIME_FAILED), handoff.prepare(correlation.requestId))
            val recovery = journal.recover(correlation)
            assertTrue(recovery.notStarted)
            assertFalse(recovery.blocksInstallation)
            assertNull(recovery.receipt)
            assertEquals(ControlCode.RUNTIME_FAILED, recovery.code)
            val visible = DesktopRecoveredInstallPresentation.values(listOf(recovery)).values.single() as ControlValue.ObjectValue
            assertEquals(ControlValue.Text("failed"), visible.values["phase"])
            assertEquals(ControlValue.Text("RUNTIME_FAILED"), visible.values["code"])
            assertEquals(ControlValue.BooleanValue(false), visible.values["installed"])
            assertEquals(ControlValue.BooleanValue(true), visible.values["final"])
            assertEquals(1, launches)
            assertEquals(1, releases)
            assertEquals(ControlCode.NOT_FOUND, handoff.retryCancellation().code)
        } finally {
            handoff.close()
            Files.walk(workspace).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::delete) }
        }
    }

    @Test fun unpublishedTemporaryReceiptAfterWorkerExitCannotAdmitReplacementOrStopTheOwner() = runBlocking {
        val root = Files.createTempDirectory("windows-unpublished-receipt-")
        val workspace = Files.createDirectory(root.resolve("workspace"))
        val jobDirectory = Files.createDirectory(root.resolve("job"))
        val temporary = jobDirectory.resolve("status-00000000-0000-0000-0000-000000000002.tmp")
        val bytes = """{"version":1,"jobId":"$job","sequence":0,"phase":"PREPARING","code":"OK"}""".encodeToByteArray()
        Files.write(temporary, bytes)
        val identity = DesktopInstallCorrelation("observed-owner", "original-request", "original-operation")
        val readReceipt: () -> DesktopInstallJobReceipt = {
            assertFalse(Files.exists(jobDirectory.resolve("status.json")))
            throw WindowsInstallNativeFailure(2)
        }
        val journal = DesktopInstallCorrelationJournal(workspace, readProtectedReceipt = { readReceipt() })
        journal.record(identity, job)
        var launches = 0
        var commits = 0
        var cancellationWrites = 0
        var notStarted = 0
        var releases = 0
        val receipt = DesktopWindowsPreparedInstall(job, readReceipt, { commits++ }, { cancellationWrites++ },
            { releases++ }, timeoutMillis = 0)
        val prepared = DesktopWindowsUnstartedCancellation(receipt,
            canProveNotStarted = { windowsInstallDefinitelyNotStarted(true, false, false) },
            recordNotStarted = { notStarted++; journal.markNotStarted(identity, job) },
            onCancellationConfirmed = { fail("No authoritative cancellation receipt exists") })
        val handoff = DesktopInstallHandoff(
            prepare = {
                launches++
                receipt.awaitAuthorization().fold(
                    onSuccess = { Result.success(prepared) },
                    onFailure = { Result.failure(DesktopInstallPreparationFailure(prepared, it)) })
            },
            stopRuntime = { fail("Unpublished authorization must preserve the running owner") },
            requestExit = { fail("Unpublished authorization must not request owner exit") })
        try {
            val unknown = DesktopInstallHandoffResult(ControlCode.OUTCOME_UNKNOWN, job)
            assertEquals(unknown, handoff.prepare(identity.requestId))
            assertEquals(ControlCode.BUSY, handoff.prepare("explicit-new-request").code)
            assertEquals(unknown, handoff.retryCancellation())
            val recovery = journal.recover(identity)
            assertTrue(recovery.blocksInstallation)
            assertFalse(recovery.notStarted)
            assertNull(recovery.receipt)
            assertEquals(ControlCode.OUTCOME_UNKNOWN, recovery.code)
            val visible = DesktopRecoveredInstallPresentation.values(listOf(recovery)).values.single() as ControlValue.ObjectValue
            assertEquals(ControlValue.Null, visible.values["installed"])
            assertEquals(ControlValue.BooleanValue(false), visible.values["final"])
            assertFailsWith<IllegalStateException> {
                journal.requireNew(DesktopInstallCorrelation("replacement-owner", "new-request", "new-operation"))
            }
            assertEquals(1, launches)
            assertEquals(0, commits)
            assertEquals(0, notStarted)
            assertEquals(0, releases)
            assertEquals(2, cancellationWrites)
            assertContentEquals(bytes, Files.readAllBytes(temporary))
        } finally {
            handoff.close()
            Files.walk(root).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::delete) }
        }
    }

    @Test fun delayedWorkerExitAllowsCancellationRetryWithoutSyntheticProtectedReceipt() = runBlocking {
        var alive = true
        var reads = 0
        var marks = 0
        var confirmed = 0
        val receipt = object : DesktopPreparedInstall {
            override val jobId = job
            override suspend fun commit() = Result.success(Unit)
            override fun cancel(): Result<Unit> { reads++; return Result.failure(IllegalStateException("OUTCOME_UNKNOWN")) }
            override fun close() = Unit
        }
        val prepared = DesktopWindowsUnstartedCancellation(receipt,
            canProveNotStarted = { windowsInstallDefinitelyNotStarted(true, true, alive) },
            recordNotStarted = { marks++ }, onCancellationConfirmed = { confirmed++ })
        assertTrue(prepared.cancel().isFailure)
        assertEquals(0, marks)
        alive = false
        assertTrue(prepared.cancel().isSuccess)
        assertTrue(prepared.cancel().isSuccess)
        assertEquals(1, marks)
        assertEquals(1, confirmed)
        assertEquals(1, reads)
        assertEquals("CANCELLED", prepared.commit().exceptionOrNull()?.message)
    }
    @Test fun localCancellationProofRequiresNoCoordinatorAndConfirmedWorkerAbsence() {
        assertTrue(windowsInstallDefinitelyNotStarted(false, false, null))
        assertTrue(windowsInstallDefinitelyNotStarted(false, false, false))
        assertTrue(windowsInstallDefinitelyNotStarted(true, true, false))
        assertFalse(windowsInstallDefinitelyNotStarted(false, false, true))
        assertFalse(windowsInstallDefinitelyNotStarted(true, true, true))
        assertFalse(windowsInstallDefinitelyNotStarted(true, false, false))
        assertFalse(windowsInstallDefinitelyNotStarted(true, false, null))
    }
    @Test fun capturedWorkerArgumentsPreserveQuotesAndTrailingBackslashes() {
        assertEquals("\"plain\"", windowsInstallArgument("plain"))
        assertEquals("\"a\\\"b\"", windowsInstallArgument("a\"b"))
        assertEquals("\"C:\\path with spaces\\\\\"", windowsInstallArgument("C:\\path with spaces\\"))
    }
    private val job = "00000000-0000-0000-0000-000000000001"
    private fun receipt(phase: DesktopInstallJobPhase, sequence: Long = phase.ordinal.toLong()) =
        DesktopInstallJobReceipt(job, sequence, phase,
            if (phase == DesktopInstallJobPhase.CANCELLED) ControlCode.CANCELLED else ControlCode.OK)

    @Test fun protectedAuthorizationAndCommitAcknowledgmentPrecedeStopAndExit() = runBlocking {
        val events = mutableListOf<String>()
        var current = receipt(DesktopInstallJobPhase.AUTHORIZED)
        val prepared = DesktopWindowsPreparedInstall(job,
            readReceipt = { events += "read:${current.phase}"; current },
            publishCommit = { events += "publish"; current = receipt(DesktopInstallJobPhase.WAITING_FOR_EXIT) },
            requestCancellation = { fail("Unexpected cancel") }, release = {})
        val handoff = DesktopInstallHandoff(
            prepare = { prepared.awaitAuthorization().map { prepared } },
            stopRuntime = { events += "stop"; Result.success(Unit) }, requestExit = { events += "exit" })
        assertEquals(ControlCode.OK, handoff.prepare("request").code)
        assertEquals(listOf("read:AUTHORIZED", "stop", "publish", "read:WAITING_FOR_EXIT", "exit"), events)
    }

    @Test fun commitPublicationWithoutProtectedAcknowledgmentNeverReportsSuccess() = runBlocking {
        var publications = 0
        val prepared = DesktopWindowsPreparedInstall(job, { receipt(DesktopInstallJobPhase.AUTHORIZED) },
            { publications++ }, {}, {}, timeoutMillis = 0)
        assertEquals("OUTCOME_UNKNOWN", prepared.commit().exceptionOrNull()?.message)
        assertEquals("OUTCOME_UNKNOWN", prepared.commit().exceptionOrNull()?.message)
        assertEquals(1, publications)
    }

    @Test fun cancellationWriteAloneIsNotCancellationAcknowledgment() {
        var current = receipt(DesktopInstallJobPhase.AUTHORIZED)
        var writes = 0
        val prepared = DesktopWindowsPreparedInstall(job, { current }, {}, { writes++ }, {}, timeoutMillis = 0)
        assertTrue(prepared.cancel().isFailure)
        current = receipt(DesktopInstallJobPhase.CANCELLED)
        assertTrue(prepared.cancel().isSuccess)
        assertEquals(2, writes)
    }

    @Test fun resetRunsOnceOnlyAfterProtectedCancellationAndUnknownCloseDoesNotReset() {
        var resets = 0
        var current = receipt(DesktopInstallJobPhase.AUTHORIZED)
        val first = DesktopWindowsPreparedInstall(job, { current }, {}, {}, {}, timeoutMillis = 0,
            onCancellationConfirmed = { resets++ })
        assertTrue(first.cancel().isFailure)
        first.close()
        assertEquals(0, resets)
        val second = DesktopWindowsPreparedInstall(job, { current }, {}, {}, {}, timeoutMillis = 0,
            onCancellationConfirmed = { resets++ })
        current = receipt(DesktopInstallJobPhase.CANCELLED)
        assertTrue(second.cancel().isSuccess)
        assertTrue(second.cancel().isSuccess)
        second.close()
        assertEquals(1, resets)
    }

    @Test fun substitutedJobCannotAcknowledgeReadiness() = runBlocking {
        val prepared = DesktopWindowsPreparedInstall(job,
            { receipt(DesktopInstallJobPhase.AUTHORIZED).copy(jobId = "00000000-0000-0000-0000-000000000002") }, {}, {}, {})
        assertTrue(prepared.awaitAuthorization().isFailure)
    }

    @Test fun newProtectedDirectoryDoesNotMeanItsFirstReceiptIsAlreadyPublished() = runBlocking {
        var reads = 0
        val prepared = DesktopWindowsPreparedInstall(job,
            { if (++reads == 1) throw WindowsInstallNativeFailure(2) else receipt(DesktopInstallJobPhase.AUTHORIZED) }, {}, {}, {})
        assertTrue(prepared.awaitAuthorization().isSuccess)
        assertEquals(2, reads)
    }

    @Test fun earlierPreparingReceiptDoesNotAuthorizeAnUnpublishedNewSequence() = runBlocking {
        var commits = 0
        val prepared = DesktopWindowsPreparedInstall(job,
            { receipt(DesktopInstallJobPhase.PREPARING) }, { commits++ }, {}, {}, timeoutMillis = 0)
        assertEquals("OUTCOME_UNKNOWN", prepared.awaitAuthorization().exceptionOrNull()?.message)
        assertEquals(0, commits)
        prepared.close()
    }
}
