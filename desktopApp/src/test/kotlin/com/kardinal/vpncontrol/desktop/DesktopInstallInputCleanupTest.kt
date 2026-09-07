package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.ControlCode
import kotlin.test.*

class DesktopInstallInputCleanupTest {
    @Test fun inconsistentNoStartFlagsNeverAuthorizeInputRemoval() {
        var records = listOf(DesktopInstallCorrelationRecovery(binding, null,
            ControlCode.OUTCOME_UNKNOWN, notStarted = true))
        val cleanup = DesktopInstallInputCleanup({ Result.success(records) },
            release = { _, _ -> error("No terminal proof") },
            releaseNotStarted = { error("Unknown code is not no-start proof") })
        assertTrue(cleanup.reconcile("new").isSuccess)
        assertNull(cleanup.decorate(records).single().cleanupCode)
        records = listOf(DesktopInstallCorrelationRecovery(binding,
            receipt.copy(phase = DesktopInstallJobPhase.INSTALLING), ControlCode.CANCELLED, notStarted = true))
        assertTrue(cleanup.reconcile("new").isSuccess)
        assertNull(cleanup.decorate(records).single().cleanupCode)
    }

    @Test fun provenNoStartCleanupRetainsDistinctOutcomeAndNeverRunsForUnknownJobs() {
        var records = listOf(DesktopInstallCorrelationRecovery(binding, null,
            ControlCode.INTERACTION_REQUIRED, notStarted = true))
        var calls = 0
        val cleanup = DesktopInstallInputCleanup({ Result.success(records) },
            release = { _, _ -> error("No protected receipt exists") },
            releaseNotStarted = { actual ->
                assertEquals(records.single(), actual); calls++; Result.success(Unit)
            })
        assertTrue(cleanup.reconcile("new").isSuccess)
        assertTrue(cleanup.reconcile("new").isSuccess)
        assertEquals(1, calls)
        val decorated = cleanup.decorate(records).single()
        assertEquals(ControlCode.OK, decorated.cleanupCode)
        assertEquals(ControlCode.INTERACTION_REQUIRED, decorated.code)
        assertTrue(decorated.notStarted)
        records = listOf(DesktopInstallCorrelationRecovery(binding, null, ControlCode.OUTCOME_UNKNOWN))
        assertNull(cleanup.decorate(records).single().cleanupCode)
        assertTrue(cleanup.reconcile("new").isSuccess)
        assertEquals(1, calls)
    }

    private val binding = DesktopInstallCorrelationRecord(DesktopInstallCorrelation("old", "request", "operation"),
        "00000000-0000-0000-0000-000000000081", "a".repeat(64))
    private val receipt = DesktopInstallJobReceipt(binding.jobId, 4, DesktopInstallJobPhase.SUCCEEDED, ControlCode.OK)
    @Test fun nextOwnerReleasesExactTerminalInputsOnceWithoutErasingReceipt() {
        val records = listOf(DesktopInstallCorrelationRecovery(binding, receipt, ControlCode.OK))
        var calls = 0
        val cleanup = DesktopInstallInputCleanup({ Result.success(records) }, release = { correlation, actual ->
            assertEquals(binding.correlation, correlation); assertEquals(receipt, actual); calls++; Result.success(Unit)
        })
        assertNull(cleanup.decorate(records).single().cleanupCode)
        assertTrue(cleanup.reconcile("new").isSuccess)
        assertTrue(cleanup.reconcile("new").isSuccess)
        assertEquals(1, calls)
        assertEquals(receipt, cleanup.decorate(records).single().receipt)
        assertEquals(ControlCode.OK, cleanup.decorate(records).single().cleanupCode)
    }
    @Test fun failedCleanupPreservesKnownInstallationAndRetriesOnlyCleanup() {
        val records = listOf(DesktopInstallCorrelationRecovery(binding, receipt, ControlCode.OK))
        var calls = 0
        val cleanup = DesktopInstallInputCleanup({ Result.success(records) }, release = { _, _ ->
            calls++; if (calls == 1) Result.failure(IllegalStateException("private detail")) else Result.success(Unit)
        })
        assertTrue(cleanup.reconcile("new").isFailure)
        val failed = cleanup.decorate(records).single()
        assertEquals(ControlCode.PERSISTENCE_FAILED, failed.cleanupCode)
        assertEquals(ControlCode.OK, failed.code)
        assertEquals(receipt, failed.receipt)
        val data = (DesktopRecoveredInstallPresentation.values(listOf(failed)).values.single()
            as com.kardinal.vpncontrol.model.ControlValue.ObjectValue).values
        assertEquals(com.kardinal.vpncontrol.model.ControlValue.BooleanValue(true), data["installed"])
        assertEquals(com.kardinal.vpncontrol.model.ControlValue.Text("PERSISTENCE_FAILED"), data["cleanupCode"])
        assertTrue(cleanup.reconcile("new").isSuccess)
        assertEquals(2, calls)
        assertEquals(ControlCode.OK, cleanup.decorate(records).single().cleanupCode)
    }
    @Test fun inspectionAndUncertainOrCurrentOwnerJobsNeverRunCleanup() {
        var records = listOf(DesktopInstallCorrelationRecovery(binding, null, ControlCode.OUTCOME_UNKNOWN))
        val cleanup = DesktopInstallInputCleanup({ Result.success(records) }, release = { _, _ -> error("Must retain active inputs") })
        assertTrue(cleanup.reconcile("new").isSuccess)
        records = listOf(DesktopInstallCorrelationRecovery(binding, receipt, ControlCode.OK))
        assertEquals(records, cleanup.decorate(records))
        assertTrue(cleanup.reconcile("old").isSuccess)
    }
}
