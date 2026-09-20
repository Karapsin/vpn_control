package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.*
import com.kardinal.vpncontrol.model.ControlCode
import com.kardinal.vpncontrol.model.ControlValue
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.*

class DesktopRecoveredUpdateStatusTest {
    @Test fun firstLateHistoricalFailureCannotReplaceInProgressUpdate() {
        val directory = Files.createTempDirectory("vpn-late-recovered-retry")
        val binding = DesktopInstallCorrelationRecord(DesktopInstallCorrelation("old", "request", "operation"),
            "00000000-0000-0000-0000-000000000086", "b".repeat(64))
        val receipt = DesktopInstallJobReceipt(binding.jobId, 4, DesktopInstallJobPhase.FAILED, ControlCode.RUNTIME_FAILED)
        val history = listOf(DesktopInstallCorrelationRecovery(binding, receipt, ControlCode.RUNTIME_FAILED))
        val adapter = object : DesktopLinuxInstallAdapter {
            override suspend fun prepare(packageFile: Path, asset: UpdateAsset, correlation: DesktopInstallCorrelation,
                frontend: DesktopFrontendProcessIdentity?, onCancellationConfirmed: () -> Unit): Result<DesktopPreparedInstall> = error("No install")
            override fun recoverCorrelations() = Result.success(history)
            override fun releaseCompleted(correlation: DesktopInstallCorrelation, receipt: DesktopInstallJobReceipt): Result<Unit> = error("No cleanup")
        }
        try {
            for (phase in listOf(AppUpdatePhase.CHECKING, AppUpdatePhase.DOWNLOADING, AppUpdatePhase.VERIFYING, AppUpdatePhase.READY)) {
                var state = MainUiState(appUpdate = AppUpdateState(phase = phase))
                val service = DesktopUpdateService({ state }, { state = it(state) }, directory,
                    osName = "Linux", workspaceDirectory = directory, linuxInstallerFactory = { adapter })
                assertEquals(history, service.recoverInstallCorrelations().getOrThrow())
                assertEquals(phase, state.appUpdate.phase, "First late history replaced $phase")
            }
            var state = MainUiState()
            val service = DesktopUpdateService({ state }, { transform ->
                state = state.copy(appUpdate = AppUpdateState(phase = AppUpdatePhase.CHECKING))
                state = transform(state)
            }, directory, osName = "Linux", workspaceDirectory = directory, linuxInstallerFactory = { adapter })
            service.recoverInstallCorrelations().getOrThrow()
            assertEquals(AppUpdatePhase.CHECKING, state.appUpdate.phase, "Check started between snapshot and publication")
            val server = com.sun.net.httpserver.HttpServer.create(java.net.InetSocketAddress("127.0.0.1", 0), 0)
            val base = "http://127.0.0.1:${server.address.port}"
            server.createContext("/manifest") { exchange ->
                val body = """{"schemaVersion":1,"buildNumber":2,"releaseTag":"v1.0.2",
                    "releaseNotesUrl":"$base/notes","assets":[{"platform":"linux","architecture":"x86_64",
                    "packageType":"rpm","displayVersion":"1.0.2","fileName":"test.rpm",
                    "downloadUrl":"$base/package","sha256":"${"0".repeat(64)}","sizeBytes":1}]}""".toByteArray()
                exchange.sendResponseHeaders(200, body.size.toLong())
                exchange.responseBody.use { it.write(body) }
            }
            server.start()
            try {
                state = MainUiState()
                val checkedService = DesktopUpdateService({ state }, { state = it(state) }, directory,
                    buildInfo = DesktopBuildInfo(1, "1.0.1"), osName = "Linux", osArchitecture = "x86_64",
                    manifestUrl = "$base/manifest", trustUrl = { it.startsWith("$base/") },
                    workspaceDirectory = directory, linuxInstallerFactory = { adapter },
                    linuxOsReleaseReader = { "ID=fedora" }, linuxCommandExists = { true })
                kotlinx.coroutines.runBlocking { checkedService.check().getOrThrow() }
                assertEquals(AppUpdatePhase.IDLE, state.appUpdate.phase)
                checkedService.recoverInstallCorrelations().getOrThrow()
                assertEquals(AppUpdatePhase.IDLE, state.appUpdate.phase, "Late history replaced completed check")
                assertEquals("1.0.2", state.appUpdate.availableVersion)
            } finally { server.stop(0) }
        } finally { directory.toFile().deleteRecursively() }
    }

    @Test fun historicalFailureRemainsInspectableWithoutReplacingRetryOrDismissedState() {
        val directory = Files.createTempDirectory("vpn-recovered-retry")
        val binding = DesktopInstallCorrelationRecord(DesktopInstallCorrelation("old", "request", "operation"),
            "00000000-0000-0000-0000-000000000084", "b".repeat(64))
        val receipt = DesktopInstallJobReceipt(binding.jobId, 4, DesktopInstallJobPhase.FAILED, ControlCode.RUNTIME_FAILED)
        var history = listOf(DesktopInstallCorrelationRecovery(binding, receipt, ControlCode.RUNTIME_FAILED))
        var state = MainUiState()
        val adapter = object : DesktopLinuxInstallAdapter {
            override suspend fun prepare(packageFile: Path, asset: UpdateAsset, correlation: DesktopInstallCorrelation,
                frontend: DesktopFrontendProcessIdentity?, onCancellationConfirmed: () -> Unit): Result<DesktopPreparedInstall> =
                error("Status must not launch an installer")
            override fun recoverCorrelations() = Result.success(history)
            override fun releaseCompleted(correlation: DesktopInstallCorrelation, receipt: DesktopInstallJobReceipt): Result<Unit> =
                error("Status must not delete failure evidence")
        }
        val service = DesktopUpdateService({ state }, { state = it(state) }, directory,
            osName = "Linux", workspaceDirectory = directory, linuxInstallerFactory = { adapter })
        try {
            service.recoverInstallCorrelations().getOrThrow()
            assertEquals(AppUpdatePhase.FAILED, state.appUpdate.phase)
            // Native RPM retry: new check/download completed, then updates status read old receipts.
            for (phase in listOf(AppUpdatePhase.CHECKING, AppUpdatePhase.DOWNLOADING, AppUpdatePhase.READY)) {
                state = state.copy(appUpdate = AppUpdateState(phase = phase, availableVersion = "2.1.13"))
                val expected = state.appUpdate
                assertEquals(history, service.recoverInstallCorrelations().getOrThrow())
                assertEquals(expected, state.appUpdate, "Historical failure replaced $phase")
            }
            service.dismiss().getOrThrow()
            val dismissed = state.appUpdate
            assertEquals(history, service.recoverInstallCorrelations().getOrThrow())
            assertEquals(dismissed, state.appUpdate)
            history = history.map { it.copy(cleanupCode = ControlCode.OK) }
            service.recoverInstallCorrelations().getOrThrow()
            assertEquals(dismissed, state.appUpdate, "Cleanup completion must not revive dismissed failure")
            val retryBinding = binding.copy(jobId = "00000000-0000-0000-0000-000000000085",
                correlation = DesktopInstallCorrelation("new", "retry", "retry-operation"))
            history = history + DesktopInstallCorrelationRecovery(retryBinding, null, ControlCode.OUTCOME_UNKNOWN)
            service.recoverInstallCorrelations().getOrThrow()
            assertEquals(AppInstallSessionPhase.UNKNOWN, state.appUpdate.installSession?.phase)
            assertEquals(retryBinding.jobId, state.appUpdate.installSession?.receiptId)
            history = history.dropLast(1) + DesktopInstallCorrelationRecovery(retryBinding,
                DesktopInstallJobReceipt(retryBinding.jobId, 4, DesktopInstallJobPhase.SUCCEEDED, ControlCode.OK), ControlCode.OK)
            service.recoverInstallCorrelations().getOrThrow()
            assertEquals(AppInstallSessionPhase.INSTALLED, state.appUpdate.installSession?.phase)
            assertEquals(retryBinding.jobId, state.appUpdate.installSession?.receiptId)
        } finally { directory.toFile().deleteRecursively() }
    }

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
