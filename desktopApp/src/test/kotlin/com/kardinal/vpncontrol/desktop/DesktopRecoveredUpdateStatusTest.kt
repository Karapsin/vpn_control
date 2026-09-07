package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.*
import com.kardinal.vpncontrol.model.ControlCode
import com.kardinal.vpncontrol.model.ControlValue
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.*

class DesktopRecoveredUpdateStatusTest {
    @Test fun provenAuthorizationFailureIsFailedAndNotInstalledInGuiAndCli() {
        val binding = DesktopInstallCorrelationRecord(DesktopInstallCorrelation("old", "request", "operation"),
            "00000000-0000-0000-0000-000000000092", "b".repeat(64))
        val recovery = listOf(DesktopInstallCorrelationRecovery(binding, null,
            ControlCode.INTERACTION_REQUIRED, notStarted = true))
        val state = DesktopRecoveredInstallPresentation.project(AppUpdateState(), recovery)
        assertEquals(AppInstallSessionPhase.FAILED, state.installSession?.phase)
        assertEquals("INTERACTION_REQUIRED", state.message)
        val value = DesktopRecoveredInstallPresentation.values(recovery).values.single() as ControlValue.ObjectValue
        assertEquals(ControlValue.Text("failed"), value.values["phase"])
        assertEquals(ControlValue.Text("INTERACTION_REQUIRED"), value.values["code"])
        assertEquals(ControlValue.BooleanValue(false), value.values["installed"])
        assertEquals(ControlValue.BooleanValue(true), value.values["final"])
    }

    @Test fun ownerMaintenanceReconcilesTerminalInputsWithoutChangingRecoveredInstallation() = kotlinx.coroutines.test.runTest {
        val directory = Files.createTempDirectory("vpn-cleanup-update")
        val binding = DesktopInstallCorrelationRecord(DesktopInstallCorrelation("old", "request", "operation"),
            "00000000-0000-0000-0000-000000000082", "b".repeat(64))
        val receipt = DesktopInstallJobReceipt(binding.jobId, 4, DesktopInstallJobPhase.SUCCEEDED, ControlCode.OK)
        var recovery = listOf(DesktopInstallCorrelationRecovery(binding, null, ControlCode.OUTCOME_UNKNOWN))
        var state = MainUiState()
        var released = 0
        val adapter = object : DesktopLinuxInstallAdapter {
            override suspend fun prepare(packageFile: Path, asset: UpdateAsset, correlation: DesktopInstallCorrelation,
                frontend: DesktopFrontendProcessIdentity?, onCancellationConfirmed: () -> Unit): Result<DesktopPreparedInstall> =
                error("Cleanup must never start installation")
            override fun recoverCorrelations() = Result.success(recovery)
            override fun releaseCompleted(correlation: DesktopInstallCorrelation, actual: DesktopInstallJobReceipt): Result<Unit> {
                assertEquals(binding.correlation, correlation); assertEquals(receipt, actual)
                released++; return Result.success(Unit)
            }
        }
        val service = DesktopUpdateService({ state }, { state = it(state) }, directory,
            osName = "Linux", workspaceDirectory = directory, linuxInstallerFactory = { adapter })
        try {
            service.recoverInstallCorrelations().getOrThrow()
            assertEquals(AppUpdatePhase.INSTALLING, state.appUpdate.phase)
            service.reconcileTerminalInstallInputs("new").getOrThrow()
            assertEquals(0, released)
            recovery = listOf(DesktopInstallCorrelationRecovery(binding, receipt, ControlCode.OK))
            // A receipt may become terminal after initial recovery projected INSTALLING.
            service.reconcileTerminalInstallInputs("new").getOrThrow()
            assertEquals(1, released)
            val result = service.recoverInstallCorrelations().getOrThrow().single()
            assertEquals(ControlCode.OK, result.cleanupCode)
            assertEquals(AppInstallSessionPhase.INSTALLED, state.appUpdate.installSession?.phase)
            assertEquals(receipt, result.receipt)
        } finally { directory.toFile().deleteRecursively() }
    }

    @Test fun oldTerminalHistoryCannotReplaceANewPreparingAttempt() {
        val binding = DesktopInstallCorrelationRecord(DesktopInstallCorrelation("old", "request", "operation"),
            "00000000-0000-0000-0000-000000000062", "b".repeat(64))
        val receipt = DesktopInstallJobReceipt(binding.jobId, 3, DesktopInstallJobPhase.CANCELLED, ControlCode.CANCELLED)
        val preparing = AppUpdateState(phase = AppUpdatePhase.INSTALLING)
        assertEquals(preparing, DesktopRecoveredInstallPresentation.project(preparing,
            listOf(DesktopInstallCorrelationRecovery(binding, receipt, ControlCode.CANCELLED))))
    }

    @Test fun previousOwnerUnknownInstallIsVisibleAndOnlyAuthoritativeReceiptCompletesIt() {
        val directory = Files.createTempDirectory("vpn-recovered-update")
        val binding = DesktopInstallCorrelationRecord(DesktopInstallCorrelation("old-owner", "request", "operation"),
            "00000000-0000-0000-0000-000000000061", "a".repeat(64))
        var recovery = listOf(DesktopInstallCorrelationRecovery(binding, null, ControlCode.OUTCOME_UNKNOWN))
        var state = MainUiState()
        var publications = 0
        val adapter = object : DesktopLinuxInstallAdapter {
            override suspend fun prepare(packageFile: Path, asset: UpdateAsset, correlation: DesktopInstallCorrelation,
                frontend: DesktopFrontendProcessIdentity?, onCancellationConfirmed: () -> Unit): Result<DesktopPreparedInstall> =
                error("Inspection must never prepare an installer")
            override fun recoverCorrelations() = Result.success(recovery)
            override fun releaseCompleted(correlation: DesktopInstallCorrelation, receipt: DesktopInstallJobReceipt): Result<Unit> =
                error("Inspection must preserve correlation and failure evidence")
        }
        val service = DesktopUpdateService({ state }, { next -> state = next(state); publications++ }, directory,
            osName = "Linux", workspaceDirectory = directory, linuxInstallerFactory = { adapter })
        try {
            assertEquals(recovery, service.recoverInstallCorrelations().getOrThrow())
            assertEquals(AppUpdatePhase.INSTALLING, state.appUpdate.phase)
            assertEquals(AppInstallSessionPhase.UNKNOWN, state.appUpdate.installSession?.phase)
            assertEquals(binding.jobId, state.appUpdate.installSession?.receiptId)
            assertFalse(requireNotNull(state.appUpdate.installSession).resumable)
            val unknown = (DesktopRecoveredInstallPresentation.values(recovery).values.single() as ControlValue.ObjectValue).values
            assertEquals(ControlValue.Null, unknown["installed"])
            assertEquals(ControlValue.BooleanValue(false), unknown["final"])
            assertEquals(ControlValue.Text(binding.correlation.operationId), unknown["operationId"])
            val previousPublications = publications
            service.recoverInstallCorrelations().getOrThrow()
            assertEquals(previousPublications, publications, "Repeated inspection must not publish unchanged state")
            val receipt = DesktopInstallJobReceipt(binding.jobId, 4, DesktopInstallJobPhase.SUCCEEDED, ControlCode.OK)
            recovery = listOf(DesktopInstallCorrelationRecovery(binding, receipt, ControlCode.OK))
            service.recoverInstallCorrelations().getOrThrow()
            assertEquals(AppInstallSessionPhase.INSTALLED, state.appUpdate.installSession?.phase)
            assertEquals(AppUpdatePhase.IDLE, state.appUpdate.phase)
            val installed = (DesktopRecoveredInstallPresentation.values(recovery).values.single() as ControlValue.ObjectValue).values
            assertEquals(ControlValue.BooleanValue(true), installed["installed"])
            assertEquals(ControlValue.BooleanValue(true), installed["final"])
        } finally { directory.toFile().deleteRecursively() }
    }
}
