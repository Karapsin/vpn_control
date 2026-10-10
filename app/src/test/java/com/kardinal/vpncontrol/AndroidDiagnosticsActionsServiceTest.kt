package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.model.*
import kotlinx.coroutines.*
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.*
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class AndroidDiagnosticsActionsServiceTest {
    @Test fun diagnosticsGuiExportHasQueryableOwnerOperation() = AndroidGuiOwnerActionFixture().use { f ->
        f.diagnosticsService().exportDiagnostics()
        assertEquals(1, f.reports) // The genuine GUI callback collected its report.
        assertEquals(listOf(f.report), f.shares)
        assertEquals("GUI diagnostics must enter the real owner ledger", 1, f.operations().size)
        val result = f.results.single()
        assertEquals(ControlCode.OK, result.code)
        assertFalse(f.status(requireNotNull(result.operationId)).data.containsKey("content"))
        assertEquals(f.report, (f.status(requireNotNull(result.operationId), wait = true).data.getValue("content") as ControlValue.Text).value)
        assertEquals(listOf(DiagnosticsStatusMessages.diagnosticsExportOpened()), f.statuses)
        assertFalse(f.busy)
    }

    @Test fun sharingFailureKeepsSameReportForExplicitRetryWithoutRecollection() = AndroidGuiOwnerActionFixture().use { f ->
        val service = f.diagnosticsService()
        f.shareFailure = true
        service.exportDiagnostics()
        assertEquals(listOf(DiagnosticsStatusMessages.diagnosticsDestinationOpenFailed()), f.statuses)
        assertFalse(f.busy)
        f.shareFailure = false
        service.exportDiagnostics()
        assertEquals(1, f.reports)
        assertEquals(1, f.operations().size)
        assertEquals(f.requests.first(), f.requests.last())
        assertEquals(listOf(f.report, f.report), f.shares)
        assertEquals(DiagnosticsStatusMessages.diagnosticsExportOpened(), f.statuses.last())
        assertFalse(f.busy)
    }

    @Test fun failedReportNeverSharesOrLeaksPrivateExceptionTextAndAlwaysClearsBusy() = AndroidGuiOwnerActionFixture().use { f ->
        f.reportFailure = true
        f.diagnosticsService().exportDiagnostics()
        assertEquals(listOf(DiagnosticsStatusMessages.diagnosticsExportFailed()), f.statuses)
        assertEquals(ControlCode.RUNTIME_FAILED, f.results.single().code)
        assertEquals(1, f.operations().size)
        assertTrue(f.shares.isEmpty())
        assertFalse(f.statuses.joinToString().contains("PRIVATE"))
        assertFalse(f.busy)
    }

    @Test fun thrownShareFailureClearsBusyAndRetriesRetainedOwnerReport() = AndroidGuiOwnerActionFixture().use { f ->
        val service = f.diagnosticsService()
        f.shareThrows = true
        service.exportDiagnostics()
        assertFalse(f.busy)
        assertEquals(listOf(DiagnosticsStatusMessages.diagnosticsExportFailed()), f.statuses)
        assertFalse(f.statuses.joinToString().contains("PRIVATE"))
        f.shareThrows = false
        service.exportDiagnostics()
        assertEquals(1, f.reports)
        assertEquals(f.requests.first(), f.requests.last())
        assertEquals(DiagnosticsStatusMessages.diagnosticsExportOpened(), f.statuses.last())
    }

    @Test fun lostReportResponseIsRecoveredWithoutDuplicateCollectionOrShare() = AndroidGuiOwnerActionFixture().use { f ->
        val service = f.diagnosticsService()
        f.loseResponse = true
        service.exportDiagnostics()
        assertEquals(1, f.reports)
        assertTrue(f.shares.isEmpty())
        assertFalse(f.busy)
        service.exportDiagnostics()
        assertEquals(f.requests.first(), f.requests.last())
        assertEquals(1, f.operations().size)
        assertEquals(1, f.reports)
        assertEquals(listOf(f.report), f.shares)
        assertEquals(DiagnosticsStatusMessages.diagnosticsExportOpened(), f.statuses.last())
    }

    @Test fun cancelledReportWaitAlwaysClearsBusyWithoutPublishingSuccess() = runTest {
        AndroidGuiOwnerActionFixture().use { f ->
            f.frontendLaunch = { block -> f.frontendJobs += launch { block() } }
            val release = CompletableDeferred<Unit>()
            f.reportGate = release
            f.diagnosticsService().exportDiagnostics()
            runCurrent()
            assertTrue(f.busy)
            assertEquals(1, f.reports)
            f.frontendJobs.single().cancelAndJoin()
            assertFalse("Cancelled frontend wait must clear its busy flag", f.busy)
            assertTrue(f.shares.isEmpty())
            assertTrue(f.statuses.isEmpty())
            release.complete(Unit)
        }
    }

    @Test fun cancelledFrontendWaitLeavesQueryableOwnerAndRetainedExactReport() = runTest {
        AndroidGuiOwnerActionFixture().use { f ->
            f.frontendLaunch = { block -> f.frontendJobs += launch { block() } }
            val release = CompletableDeferred<Unit>()
            f.reportGate = release
            val service = f.diagnosticsService()
            service.exportDiagnostics()
            runCurrent()
            val request = f.requests.single()
            val id = requireNotNull(f.owner.operationIdForRequest(request.requestId))
            assertEquals(1, f.reports)
            assertFalse(f.status(id).final)
            assertTrue(f.busy)
            service.exportDiagnostics()
            assertEquals(1, f.requests.size)
            f.frontendJobs.single().cancelAndJoin()
            assertFalse(f.busy)
            assertTrue(f.shares.isEmpty())
            release.complete(Unit)
            assertEquals(ControlCode.OK, f.status(id, wait = true).code)
            service.exportDiagnostics()
            runCurrent()
            f.frontendJobs.last().join()
            assertEquals(request, f.requests.last())
            assertEquals(1, f.reports)
            assertEquals(1, f.operations().size)
            assertEquals(listOf(f.report), f.shares)
            assertFalse(f.busy)
        }
    }

    @Test fun diagnosticsReadDoesNotTakeNestedMutationLeaseOrChangeConnection() = AndroidGuiOwnerActionFixture(running = true).use { f ->
        val runtime = f.observer.state.value
        val lease = requireNotNull(f.jobs.tryAcquireMutation())
        try {
            f.diagnosticsService().exportDiagnostics()
            assertEquals(ControlCode.OK, f.results.single().code)
            assertEquals(1, f.reports)
            assertEquals(listOf(f.report), f.shares)
            assertTrue(f.jobs.busy.value)
            assertEquals(runtime, f.observer.state.value)
            assertEquals(0, f.starts)
            assertEquals(0, f.stops)
            assertEquals(0, f.persists)
        } finally { f.jobs.releaseMutation(lease) }
    }
}
