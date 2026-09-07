package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.control.ControlDocumentCodec
import com.kardinal.vpncontrol.model.*
import kotlinx.coroutines.test.*
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlin.test.*

@OptIn(ExperimentalCoroutinesApi::class)
class DesktopControlInstallSessionTest {
    @Test fun unixAdmissionNeverLoadsWindowsTokenApisAndUnsupportedPlatformsHaveNoSideEffects() {
        assertEquals(null, desktopControlInstallPlatform("Linux") { error("Windows token API on Linux") })
        assertEquals(null, desktopControlInstallPlatform("Mac OS X") { error("Windows token API on macOS") })
        assertEquals(null, desktopControlInstallPlatform("Windows 11") { true })
        assertEquals(ControlCode.INTERACTION_REQUIRED, desktopControlInstallPlatform("Windows 11") { false })
        assertEquals(ControlCode.UNSUPPORTED, desktopControlInstallPlatform("Other OS") { error("Unknown platform") })
    }

    @Test fun protectedFailureRemainsFailureAndSettlementIsRequiredBeforeReleasingBusy() = runTest {
        val job = "00000000-0000-0000-0000-000000000001"
        var correlation: DesktopInstallCorrelation? = null
        var settle = false
        val session = DesktopHeadlessSession(backgroundScope, { MainUiState() }, { DesktopCliResponse.success("") }, {},
            controllerId = "owner", install = DesktopControlInstallActions({ value, _ ->
                correlation = value; DesktopInstallHandoffResult(ControlCode.OUTCOME_UNKNOWN, job)
            }, { Result.success(correlation?.let { listOf(DesktopInstallCorrelationRecovery(
                DesktopInstallCorrelationRecord(it, job, "0".repeat(64)),
                DesktopInstallJobReceipt(job, 2, DesktopInstallJobPhase.FAILED, ControlCode.RUNTIME_FAILED), ControlCode.RUNTIME_FAILED)) }.orEmpty()) },
                { error("Terminal failure is not cancellation") }, settle = { _, _ ->
                    if (settle) Result.success(Unit) else Result.failure(IllegalStateException("PERSISTENCE_FAILED"))
                }))
        session.execute(DesktopCliCommand.ControlSubmit(ControlRequest("install", ControlCommand(ControlOperationId.UPDATES_INSTALL), controllerId = "owner")))
        assertFalse(session.operationSnapshot().single().phase.terminal)
        settle = true
        advanceTimeBy(300); runCurrent()
        val result = session.operationSnapshot().single().result!!
        assertEquals(ControlCode.RUNTIME_FAILED, result.code)
        assertTrue(result.final)
    }

    @Test fun publicCliRoutesInstallToTypedOwnerWithRevisionAndAsyncOptions() {
        var captured: ControlRequest? = null
        val code = DesktopCli.handleArgs(arrayOf("--json", "--async", "--controller-id", "owner", "--if-revision", "7", "updates", "install"),
            printLine = {}, requestCommand = { command ->
                val request = (command as DesktopCliCommand.ControlSubmit).request
                captured = request
                DesktopCliResponse.success(ControlDocumentCodec.encodeResult(ControlResult("owner", request.requestId,
                    ControlCode.ACCEPTED, 7, final = false, operationId = "operation")))
            }, startHeadlessController = { error("No new controller for explicit owner") })
        assertEquals(0, code)
        assertEquals(ControlOperationId.UPDATES_INSTALL, captured?.command?.operation)
        assertEquals(7L, captured?.ifRevision)
        assertEquals(true, captured?.asynchronous)
    }

    @Test fun protectedTerminalReceiptCompletesExactJobAndPreviousOwnerStatusDoesNotReplay() = runTest {
        val job = "00000000-0000-0000-0000-000000000001"
        var binding: DesktopInstallCorrelationRecord? = null
        var terminal = false
        val actions = DesktopControlInstallActions({ correlation, _ ->
            binding = DesktopInstallCorrelationRecord(correlation, job, "0".repeat(64))
            DesktopInstallHandoffResult(ControlCode.OUTCOME_UNKNOWN, job)
        }, { Result.success(binding?.let { listOf(DesktopInstallCorrelationRecovery(it,
            DesktopInstallJobReceipt(job, if (terminal) 2 else 1,
                if (terminal) DesktopInstallJobPhase.SUCCEEDED else DesktopInstallJobPhase.AUTHORIZED, ControlCode.OK),
            if (terminal) ControlCode.OK else ControlCode.ACCEPTED)) }.orEmpty()) },
            { DesktopInstallHandoffResult(ControlCode.OUTCOME_UNKNOWN, job) })
        val session = DesktopHeadlessSession(backgroundScope, { MainUiState() }, { DesktopCliResponse.success("") }, {},
            controllerId = "owner", install = actions)
        val result = ControlDocumentCodec.decodeResult(session.execute(DesktopCliCommand.ControlSubmit(ControlRequest("install",
            ControlCommand(ControlOperationId.UPDATES_INSTALL), controllerId = "owner"))).message)
        terminal = true
        advanceTimeBy(300); runCurrent()
        val completed = session.operationSnapshot().single()
        assertEquals(ControlOperationPhase.SUCCEEDED, completed.phase)
        assertEquals(ControlValue.Text(job), completed.result?.data?.get("jobId"))
        val replacement = DesktopHeadlessSession(backgroundScope, { MainUiState() }, { error("No replay") }, {},
            controllerId = "replacement", install = actions.copy(prepare = { _, _ -> error("No replay") }))
        val inspected = ControlDocumentCodec.decodeResult(replacement.execute(DesktopCliCommand.ControlSubmit(ControlRequest("inspect",
            ControlCommand(ControlOperationId.OPERATIONS_STATUS, mapOf("id" to ControlValue.Text(result.operationId!!))),
            controllerId = "replacement"))).message)
        assertEquals(ControlCode.OK, inspected.code)
        assertTrue(inspected.final)
        assertEquals(ControlValue.Text("owner"), inspected.data["originControllerId"])
        assertEquals(ControlValue.Text(job), inspected.data["jobId"])
    }

    @Test fun staleRevisionAndOwnerCannotPrepareAndAuthorizationPrecedesStopAndCommit() = runTest {
        val events = mutableListOf<String>()
        val job = "00000000-0000-0000-0000-000000000001"
        val prepared = object : DesktopPreparedInstall {
            override val jobId = job
            override suspend fun commit(): Result<Unit> { events += "protected-waiting"; return Result.success(Unit) }
            override fun cancel() = Result.success(Unit)
            override fun close() {}
        }
        val handoff = DesktopInstallHandoff({ events += "protected-authorized"; Result.success(prepared) },
            { events += "stop"; Result.success(Unit) }, { events += "request-exit" })
        val session = DesktopHeadlessSession(backgroundScope, { MainUiState() }, { DesktopCliResponse.success("") }, {},
            controllerId = "owner", metadataProvider = { DesktopControlMetadata(7, false) },
            install = DesktopControlInstallActions({ correlation, _ -> handoff.prepare(correlation.requestId) },
                { Result.success(emptyList()) }, handoff::retryCancellation))
        val request = ControlRequest("install", ControlCommand(ControlOperationId.UPDATES_INSTALL), controllerId = "owner", ifRevision = 6)
        suspend fun submit(request: ControlRequest) = ControlDocumentCodec.decodeResult(session.execute(DesktopCliCommand.ControlSubmit(request)).message)
        assertEquals(ControlCode.CONFLICT, submit(request.copy(controllerId = "other")).code)
        assertEquals(ControlCode.CONFLICT, submit(request).code)
        assertTrue(events.isEmpty())
        assertEquals(ControlCode.ACCEPTED, submit(request.copy(requestId = "fresh", ifRevision = 7)).code)
        assertEquals(listOf("protected-authorized", "stop", "protected-waiting", "request-exit"), events)
    }

    @Test fun protectedHandoffIsNonterminalDeduplicatedAndKeepsExactJob() = runTest {
        var calls = 0
        var identity: DesktopInstallCorrelation? = null
        val job = "00000000-0000-0000-0000-000000000001"
        val session = DesktopHeadlessSession(backgroundScope, { MainUiState() }, { DesktopCliResponse.success("") }, {},
            controllerId = "owner", metadataProvider = { DesktopControlMetadata(7, false) },
            install = DesktopControlInstallActions(
                prepare = { correlation, _ -> calls++; identity = correlation; DesktopInstallHandoffResult(ControlCode.OK, job) },
                recover = { Result.success(emptyList()) }, cancel = { DesktopInstallHandoffResult(ControlCode.OUTCOME_UNKNOWN, job) }))
        val request = ControlRequest("install", ControlCommand(ControlOperationId.UPDATES_INSTALL),
            controllerId = "owner", ifRevision = 7)
        suspend fun submit(request: ControlRequest) = ControlDocumentCodec.decodeResult(session.execute(DesktopCliCommand.ControlSubmit(request)).message)
        val result = submit(request)
        assertEquals(ControlCode.ACCEPTED, result.code)
        assertFalse(result.final)
        assertEquals(ControlValue.Text(job), result.data["jobId"])
        assertEquals(DesktopInstallCorrelation("owner", "install", result.operationId!!), identity)
        assertEquals(result, submit(request))
        assertEquals(1, calls)
        assertEquals(ControlCode.BUSY, submit(request.copy(requestId = "other")).code)
        assertFalse(session.operationSnapshot().single().phase.terminal)
    }

    @Test fun unknownCancellationDoesNotBecomeTerminalOrPermitNewInstall() = runTest {
        val job = "00000000-0000-0000-0000-000000000001"
        var cancellations = 0
        val session = DesktopHeadlessSession(backgroundScope, { MainUiState() }, { DesktopCliResponse.success("") }, {},
            controllerId = "owner", install = DesktopControlInstallActions(
                prepare = { _, _ -> DesktopInstallHandoffResult(ControlCode.OUTCOME_UNKNOWN, job) },
                recover = { Result.success(emptyList()) }, cancel = { cancellations++; DesktopInstallHandoffResult(ControlCode.OUTCOME_UNKNOWN, job) }))
        val request = ControlRequest("install", ControlCommand(ControlOperationId.UPDATES_INSTALL), controllerId = "owner")
        val result = ControlDocumentCodec.decodeResult(session.execute(DesktopCliCommand.ControlSubmit(request)).message)
        assertEquals(ControlCode.OUTCOME_UNKNOWN, result.code)
        assertFalse(result.final)
        session.execute(DesktopCliCommand.OperationCancel(result.operationId!!))
        advanceTimeBy(300); runCurrent()
        assertTrue(cancellations > 0)
        assertFalse(session.operationSnapshot().single().phase.terminal)
        assertTrue(session.hasBackgroundWork())
    }

    @Test fun previousOwnerUnknownBlocksMutationsAndResumeButKeepsInspectionResponsive() = runTest {
        var effects = 0
        val binding = DesktopInstallCorrelationRecord(DesktopInstallCorrelation("old", "old-request", "old-operation"),
            "00000000-0000-0000-0000-000000000001", "0".repeat(64))
        val session = DesktopHeadlessSession(backgroundScope, { MainUiState() }, { effects++; DesktopCliResponse.success("") }, {},
            controllerId = "owner", install = DesktopControlInstallActions({ _, _ -> error("No replay") },
                { Result.success(listOf(DesktopInstallCorrelationRecovery(binding, null, ControlCode.OUTCOME_UNKNOWN))) },
                { error("No cancellation without retained handle") }))
        session.initialize { effects++ }
        val response = session.execute(DesktopCliCommand.On)
        assertEquals("BUSY", response.message)
        assertEquals(0, effects)
        val status = ControlDocumentCodec.decodeResult(session.execute(DesktopCliCommand.ControlSubmit(ControlRequest("inspect",
            ControlCommand(ControlOperationId.OPERATIONS_STATUS, mapOf("id" to ControlValue.Text("old-operation"))), controllerId = "owner"))).message)
        assertEquals(ControlCode.OUTCOME_UNKNOWN, status.code)
        assertFalse(status.final)
    }
}
