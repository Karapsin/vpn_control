package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.control.ControlDocumentCodec
import com.kardinal.vpncontrol.model.*
import kotlinx.coroutines.async
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.test.*
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlin.test.*

@OptIn(ExperimentalCoroutinesApi::class)
class DesktopControlInstallSessionTest {
    @Test fun exactInstallJournalNameUsesCanonicalProtocolEncoding() {
        val canonical = com.kardinal.vpncontrol.control.ControlProtocolCodec.encodeValues(linkedMapOf(
            "controllerId" to ControlValue.Text("11111111-1111-4111-8111-111111111111"),
            "operationId" to ControlValue.Text("33333333-3333-4333-8333-333333333333")))
        assertEquals("{\"controllerId\":\"11111111-1111-4111-8111-111111111111\",\"operationId\":\"33333333-3333-4333-8333-333333333333\"}", canonical)
        val digest = java.security.MessageDigest.getInstance("SHA-256").digest(canonical.toByteArray())
            .joinToString("") { "%02x".format(it) }
        assertEquals("06fe77cd6eab31fd692a3648fed2ed8b7436dc65542efd79f652a340c6950429", digest)
    }

    @Test fun publicOperationStatusBindsDelayedAndRecoveredInstallJob() = runTest {
        val job = "00000000-0000-0000-0000-000000000001"
        val release = CompletableDeferred<Unit>()
        val owner = DesktopHeadlessSession(backgroundScope, { MainUiState() }, { DesktopCliResponse.success("") }, {},
            controllerId = "owner", install = DesktopControlInstallActions(
                prepare = { _, _ -> release.await(); DesktopInstallHandoffResult(ControlCode.OK, job) },
                recover = { Result.success(emptyList()) },
                cancel = { DesktopInstallHandoffResult(ControlCode.OUTCOME_UNKNOWN, job) }))
        suspend fun inspect(session: DesktopHeadlessSession, operation: String): ControlResult =
            ControlDocumentCodec.decodeResult(session.execute(DesktopCliCommand.ControlSubmit(ControlRequest(
                "inspect", ControlCommand(ControlOperationId.OPERATIONS_STATUS,
                    mapOf("id" to ControlValue.Text(operation))), controllerId = session.controllerId))).message)
        val initial = ControlDocumentCodec.decodeResult(owner.execute(DesktopCliCommand.ControlSubmit(ControlRequest(
            "install", ControlCommand(ControlOperationId.UPDATES_INSTALL), controllerId = "owner", asynchronous = true))).message)
        val operation = assertNotNull(initial.operationId)
        val before = inspect(owner, operation)
        assertEquals(operation, before.operationId)
        assertNull(before.data["jobId"])
        release.complete(Unit); runCurrent()
        val after = inspect(owner, operation)
        assertEquals(operation, after.operationId)
        assertEquals(ControlValue.Text(job), after.data["jobId"])

        val recovered = DesktopInstallCorrelationRecord(DesktopInstallCorrelation("owner", "install", operation), job, "0".repeat(64))
        val replacement = DesktopHeadlessSession(backgroundScope, { MainUiState() }, { DesktopCliResponse.success("") }, {},
            controllerId = "replacement-owner", install = DesktopControlInstallActions(
                prepare = { _, _ -> error("Recovery must not replay install") },
                recover = { Result.success(listOf(DesktopInstallCorrelationRecovery(recovered, null, ControlCode.OUTCOME_UNKNOWN))) },
                cancel = { DesktopInstallHandoffResult(ControlCode.OUTCOME_UNKNOWN, job) }))
        val afterExit = inspect(replacement, operation)
        assertEquals(operation, afterExit.operationId)
        assertEquals(ControlValue.Text(job), afterExit.data["jobId"])
        assertEquals(ControlValue.Text("owner"), afterExit.data["originControllerId"])
    }

    @Test fun cancellationCannotBeAcceptedAfterLateAuthorizationReservesTheIrreversibleHandoff() = runTest {
        val job = "00000000-0000-0000-0000-000000000001"
        lateinit var correlation: DesktopInstallCorrelation
        var recovered = emptyList<DesktopInstallCorrelationRecovery>()
        val enteredResume = CompletableDeferred<Unit>()
        val releaseResume = CompletableDeferred<Unit>()
        var ready = 0
        val session = DesktopHeadlessSession(backgroundScope, { MainUiState() }, { DesktopCliResponse.success("") }, {}, controllerId = "owner",
            install = DesktopControlInstallActions(
                prepare = { value, _ -> correlation = value; DesktopInstallHandoffResult(ControlCode.OUTCOME_UNKNOWN, job) },
                recover = { Result.success(recovered) }, cancel = { DesktopInstallHandoffResult(ControlCode.CANCELLED, job) },
                resumeLateAuthorization = { _, _ ->
                    enteredResume.complete(Unit)
                    releaseResume.await()
                    DesktopInstallHandoffResult(ControlCode.OK, job)
                },
                onInstallReady = { _, _ -> ready++ },
            ))
        val install = ControlDocumentCodec.decodeResult(session.execute(DesktopCliCommand.ControlSubmit(ControlRequest(
            "install", ControlCommand(ControlOperationId.UPDATES_INSTALL), controllerId = "owner"))).message)
        recovered = listOf(DesktopInstallCorrelationRecovery(
            DesktopInstallCorrelationRecord(correlation, job, "0".repeat(64)),
            DesktopInstallJobReceipt(job, 1, DesktopInstallJobPhase.AUTHORIZED, ControlCode.OK), ControlCode.ACCEPTED))
        advanceTimeBy(300); runCurrent()
        assertTrue(enteredResume.isCompleted)
        val cancellation = session.execute(DesktopCliCommand.OperationCancel(requireNotNull(install.operationId)))
        assertFalse(cancellation.success)
        assertEquals("CONFLICT", cancellation.message)
        releaseResume.complete(Unit)
        runCurrent()
        assertEquals(1, ready)
    }

    @Test fun cancelBeforeLateAuthorizationReservationNeverResumesWorker() = runTest {
        val job = "00000000-0000-0000-0000-000000000001"
        var resumes = 0
        lateinit var correlation: DesktopInstallCorrelation
        var recovered = emptyList<DesktopInstallCorrelationRecovery>()
        val session = DesktopHeadlessSession(backgroundScope, { MainUiState() }, { DesktopCliResponse.success("") }, {}, controllerId = "owner",
            install = DesktopControlInstallActions(
                prepare = { value, _ -> correlation = value; DesktopInstallHandoffResult(ControlCode.OUTCOME_UNKNOWN, job) },
                recover = { Result.success(recovered) }, cancel = { DesktopInstallHandoffResult(ControlCode.OUTCOME_UNKNOWN, job) },
                resumeLateAuthorization = { _, _ -> resumes++; DesktopInstallHandoffResult(ControlCode.OK, job) }))
        val install = ControlDocumentCodec.decodeResult(session.execute(DesktopCliCommand.ControlSubmit(ControlRequest("install", ControlCommand(ControlOperationId.UPDATES_INSTALL), controllerId = "owner"))).message)
        session.execute(DesktopCliCommand.OperationCancel(requireNotNull(install.operationId)))
        recovered = listOf(DesktopInstallCorrelationRecovery(DesktopInstallCorrelationRecord(correlation, job, "0".repeat(64)), DesktopInstallJobReceipt(job, 1, DesktopInstallJobPhase.AUTHORIZED, ControlCode.OK), ControlCode.ACCEPTED))
        advanceTimeBy(300); runCurrent()
        assertEquals(0, resumes)
    }

    @Test fun precommitLateAuthorizationFailureSurvivesCancelledWorkerSettlement() = runTest {
        val job = "00000000-0000-0000-0000-000000000001"
        lateinit var correlation: DesktopInstallCorrelation
        var recovered = emptyList<DesktopInstallCorrelationRecovery>()
        var settles = 0
        val session = DesktopHeadlessSession(backgroundScope, { MainUiState() }, { DesktopCliResponse.success("") }, {},
            controllerId = "owner", install = DesktopControlInstallActions(
                prepare = { value, _ -> correlation = value; DesktopInstallHandoffResult(ControlCode.OUTCOME_UNKNOWN, job) },
                recover = { Result.success(recovered) },
                cancel = { error("The runner must not issue a second cancellation") },
                resumeLateAuthorization = { _, _ ->
                    recovered = listOf(DesktopInstallCorrelationRecovery(
                        DesktopInstallCorrelationRecord(correlation, job, "0".repeat(64)),
                        DesktopInstallJobReceipt(job, 2, DesktopInstallJobPhase.CANCELLED, ControlCode.CANCELLED),
                        ControlCode.CANCELLED))
                    DesktopInstallHandoffResult(ControlCode.RUNTIME_FAILED,
                        primaryFailureCode = ControlCode.RUNTIME_FAILED)
                },
                settle = { _, _ -> settles++; Result.success(Unit) },
            ))
        session.execute(DesktopCliCommand.ControlSubmit(ControlRequest(
            "install", ControlCommand(ControlOperationId.UPDATES_INSTALL), controllerId = "owner")))
        recovered = listOf(DesktopInstallCorrelationRecovery(
            DesktopInstallCorrelationRecord(correlation, job, "0".repeat(64)),
            DesktopInstallJobReceipt(job, 1, DesktopInstallJobPhase.AUTHORIZED, ControlCode.OK), ControlCode.ACCEPTED))

        advanceTimeBy(600); runCurrent()

        val operation = session.operationSnapshot().single()
        assertEquals(ControlOperationPhase.FAILED, operation.phase)
        assertEquals(ControlCode.RUNTIME_FAILED, operation.result?.code)
        assertEquals(1, settles)
    }

    @Test fun authoritativeNoncancelledTerminalReceiptOverridesPrecommitFailure() = runTest {
        for ((phase, code, expectedPhase) in listOf(
            Triple(DesktopInstallJobPhase.SUCCEEDED, ControlCode.OK, ControlOperationPhase.SUCCEEDED),
            Triple(DesktopInstallJobPhase.FAILED, ControlCode.PERSISTENCE_FAILED, ControlOperationPhase.FAILED),
        )) {
            val job = "00000000-0000-0000-0000-000000000001"
            lateinit var correlation: DesktopInstallCorrelation
            var recovered = emptyList<DesktopInstallCorrelationRecovery>()
            val session = DesktopHeadlessSession(backgroundScope, { MainUiState() }, { DesktopCliResponse.success("") }, {},
                controllerId = "owner-$phase", install = DesktopControlInstallActions(
                    prepare = { value, _ -> correlation = value; DesktopInstallHandoffResult(ControlCode.OUTCOME_UNKNOWN, job) },
                    recover = { Result.success(recovered) },
                    cancel = { error("The runner must not cancel an acknowledged receipt") },
                    resumeLateAuthorization = { _, _ ->
                        recovered = listOf(DesktopInstallCorrelationRecovery(
                            DesktopInstallCorrelationRecord(correlation, job, "0".repeat(64)),
                            DesktopInstallJobReceipt(job, 2, phase, code), code))
                        DesktopInstallHandoffResult(ControlCode.RUNTIME_FAILED,
                            primaryFailureCode = ControlCode.RUNTIME_FAILED)
                    },
                    settle = { _, _ -> Result.success(Unit) },
                ))
            session.execute(DesktopCliCommand.ControlSubmit(ControlRequest(
                "install-$phase", ControlCommand(ControlOperationId.UPDATES_INSTALL), controllerId = "owner-$phase")))
            recovered = listOf(DesktopInstallCorrelationRecovery(
                DesktopInstallCorrelationRecord(correlation, job, "0".repeat(64)),
                DesktopInstallJobReceipt(job, 1, DesktopInstallJobPhase.AUTHORIZED, ControlCode.OK), ControlCode.ACCEPTED))

            advanceTimeBy(600); runCurrent()

            val operation = session.operationSnapshot().single()
            assertEquals(expectedPhase, operation.phase)
            assertEquals(code, operation.result?.code)
        }
    }

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

    @Test fun lateAuthorizedExactJobResumesOnceAndStatusReportsAcknowledgedHandoff() = runTest {
        val job = "00000000-0000-0000-0000-000000000001"
        lateinit var correlation: DesktopInstallCorrelation
        var recovered = emptyList<DesktopInstallCorrelationRecovery>()
        var resumes = 0
        var ready = 0
        val session = DesktopHeadlessSession(backgroundScope, { MainUiState() }, { DesktopCliResponse.success("") }, {},
            controllerId = "owner", install = DesktopControlInstallActions(
                prepare = { value, _ -> correlation = value; DesktopInstallHandoffResult(ControlCode.OUTCOME_UNKNOWN, job) },
                recover = { Result.success(recovered) },
                cancel = { DesktopInstallHandoffResult(ControlCode.OUTCOME_UNKNOWN, job) },
                resumeLateAuthorization = { value, exact ->
                    assertEquals(correlation, value); assertEquals(job, exact); resumes++
                    DesktopInstallHandoffResult(ControlCode.OK, job)
                },
                onInstallReady = { value, exact -> assertEquals(correlation, value); assertEquals(job, exact); ready++ },
            ))
        val install = ControlDocumentCodec.decodeResult(session.execute(DesktopCliCommand.ControlSubmit(ControlRequest(
            "install", ControlCommand(ControlOperationId.UPDATES_INSTALL), controllerId = "owner"))).message)
        recovered = listOf(DesktopInstallCorrelationRecovery(
            DesktopInstallCorrelationRecord(correlation, job, "0".repeat(64)),
            DesktopInstallJobReceipt(job, 1, DesktopInstallJobPhase.AUTHORIZED, ControlCode.OK), ControlCode.ACCEPTED))
        advanceTimeBy(300); runCurrent()
        assertEquals(1, resumes); assertEquals(1, ready)
        val status = ControlDocumentCodec.decodeResult(session.execute(DesktopCliCommand.ControlSubmit(ControlRequest(
            "status", ControlCommand(ControlOperationId.OPERATIONS_STATUS, mapOf("id" to ControlValue.Text(requireNotNull(install.operationId)))),
            controllerId = "owner"))).message)
        assertEquals(ControlCode.ACCEPTED, status.code)
        assertEquals(ControlValue.BooleanValue(true), status.data["handoffReady"])
        assertFalse(status.final)
    }

    @Test fun lateAuthorizedHandoffRetriesExitArmingWithoutReplayingItsExactWorker() = runTest {
        val job = "00000000-0000-0000-0000-000000000001"
        lateinit var correlation: DesktopInstallCorrelation
        var recovered = emptyList<DesktopInstallCorrelationRecovery>()
        var resumes = 0
        var arms = 0
        val session = DesktopHeadlessSession(backgroundScope, { MainUiState() }, { DesktopCliResponse.success("") }, {}, controllerId = "owner",
            install = DesktopControlInstallActions(
                prepare = { value, _ -> correlation = value; DesktopInstallHandoffResult(ControlCode.OUTCOME_UNKNOWN, job) },
                recover = { Result.success(recovered) }, cancel = { error("Committed handoff cannot be cancelled") },
                resumeLateAuthorization = { _, _ -> resumes++; DesktopInstallHandoffResult(ControlCode.OK, job) },
                onInstallReady = { _, _ -> arms++; if (arms == 1) error("response acknowledgement unavailable") },
            ))
        session.execute(DesktopCliCommand.ControlSubmit(ControlRequest(
            "install", ControlCommand(ControlOperationId.UPDATES_INSTALL), controllerId = "owner")))
        recovered = listOf(DesktopInstallCorrelationRecovery(
            DesktopInstallCorrelationRecord(correlation, job, "0".repeat(64)),
            DesktopInstallJobReceipt(job, 1, DesktopInstallJobPhase.AUTHORIZED, ControlCode.OK), ControlCode.ACCEPTED))
        advanceTimeBy(300); runCurrent()
        assertEquals(1, resumes); assertEquals(1, arms)
        advanceTimeBy(300); runCurrent()
        assertEquals(1, resumes); assertEquals(2, arms)
    }

    @Test fun lateAuthorizationNeverReplacesTheReservedJobWithAnUncorrelatedResumeResult() = runTest {
        val job = "00000000-0000-0000-0000-000000000001"
        val other = "00000000-0000-0000-0000-000000000002"
        lateinit var correlation: DesktopInstallCorrelation
        var recovered = emptyList<DesktopInstallCorrelationRecovery>()
        val session = DesktopHeadlessSession(backgroundScope, { MainUiState() }, { DesktopCliResponse.success("") }, {}, controllerId = "owner",
            install = DesktopControlInstallActions(
                prepare = { value, _ -> correlation = value; DesktopInstallHandoffResult(ControlCode.OUTCOME_UNKNOWN, job) },
                recover = { Result.success(recovered) }, cancel = { DesktopInstallHandoffResult(ControlCode.OUTCOME_UNKNOWN, job) },
                resumeLateAuthorization = { _, _ -> DesktopInstallHandoffResult(ControlCode.OUTCOME_UNKNOWN, other) },
            ))
        val install = ControlDocumentCodec.decodeResult(session.execute(DesktopCliCommand.ControlSubmit(ControlRequest(
            "install", ControlCommand(ControlOperationId.UPDATES_INSTALL), controllerId = "owner"))).message)
        recovered = listOf(DesktopInstallCorrelationRecovery(
            DesktopInstallCorrelationRecord(correlation, job, "0".repeat(64)),
            DesktopInstallJobReceipt(job, 1, DesktopInstallJobPhase.AUTHORIZED, ControlCode.OK), ControlCode.ACCEPTED))
        advanceTimeBy(300); runCurrent()
        val status = ControlDocumentCodec.decodeResult(session.execute(DesktopCliCommand.ControlSubmit(ControlRequest(
            "status", ControlCommand(ControlOperationId.OPERATIONS_STATUS, mapOf("id" to ControlValue.Text(requireNotNull(install.operationId)))),
            controllerId = "owner"))).message)
        assertEquals(ControlValue.Text(job), status.data["jobId"])
    }

    @Test fun unconfirmedPrecommitCancellationReopensOnlyTheOwnedCancellationRetry() = runTest {
        val job = "00000000-0000-0000-0000-000000000001"
        lateinit var correlation: DesktopInstallCorrelation
        var recovered = emptyList<DesktopInstallCorrelationRecovery>()
        var resumes = 0
        var cancellations = 0
        val session = DesktopHeadlessSession(backgroundScope, { MainUiState() }, { DesktopCliResponse.success("") }, {}, controllerId = "owner",
            install = DesktopControlInstallActions(
                prepare = { value, _ -> correlation = value; DesktopInstallHandoffResult(ControlCode.OUTCOME_UNKNOWN, job) },
                recover = { Result.success(recovered) },
                cancel = { cancellations++; DesktopInstallHandoffResult(ControlCode.CANCELLED, job) },
                resumeLateAuthorization = { _, _ ->
                    resumes++
                    DesktopInstallHandoffResult(ControlCode.OUTCOME_UNKNOWN, job, cancellationRetryAllowed = true,
                        primaryFailureCode = ControlCode.RUNTIME_FAILED)
                },
            ))
        val install = ControlDocumentCodec.decodeResult(session.execute(DesktopCliCommand.ControlSubmit(ControlRequest(
            "install", ControlCommand(ControlOperationId.UPDATES_INSTALL), controllerId = "owner"))).message)
        recovered = listOf(DesktopInstallCorrelationRecovery(
            DesktopInstallCorrelationRecord(correlation, job, "0".repeat(64)),
            DesktopInstallJobReceipt(job, 1, DesktopInstallJobPhase.AUTHORIZED, ControlCode.OK), ControlCode.ACCEPTED))
        advanceTimeBy(300); runCurrent()
        assertEquals(1, resumes)
        assertTrue(session.operationSnapshot().single().cancellable)
        assertTrue(session.execute(DesktopCliCommand.OperationCancel(requireNotNull(install.operationId))).success)
        advanceTimeBy(300); runCurrent()
        assertEquals(1, resumes); assertEquals(1, cancellations)
        assertEquals(ControlOperationPhase.FAILED, session.operationSnapshot().single().phase)
        assertEquals(ControlCode.RUNTIME_FAILED, session.operationSnapshot().single().result?.code)
    }

    @Test fun ambiguousLateCommitDoesNotReopenCancellationOrReplayTheExactWorker() = runTest {
        val job = "00000000-0000-0000-0000-000000000001"
        lateinit var correlation: DesktopInstallCorrelation
        var recovered = emptyList<DesktopInstallCorrelationRecovery>()
        var resumes = 0
        val session = DesktopHeadlessSession(backgroundScope, { MainUiState() }, { DesktopCliResponse.success("") }, {}, controllerId = "owner",
            install = DesktopControlInstallActions(
                prepare = { value, _ -> correlation = value; DesktopInstallHandoffResult(ControlCode.OUTCOME_UNKNOWN, job) },
                recover = { Result.success(recovered) }, cancel = { error("Ambiguous commit must not cancel") },
                resumeLateAuthorization = { _, _ -> resumes++; DesktopInstallHandoffResult(ControlCode.OUTCOME_UNKNOWN, job) },
            ))
        val install = ControlDocumentCodec.decodeResult(session.execute(DesktopCliCommand.ControlSubmit(ControlRequest(
            "install", ControlCommand(ControlOperationId.UPDATES_INSTALL), controllerId = "owner"))).message)
        recovered = listOf(DesktopInstallCorrelationRecovery(
            DesktopInstallCorrelationRecord(correlation, job, "0".repeat(64)),
            DesktopInstallJobReceipt(job, 1, DesktopInstallJobPhase.AUTHORIZED, ControlCode.OK), ControlCode.ACCEPTED))
        advanceTimeBy(300); runCurrent()
        assertEquals(1, resumes)
        assertFalse(session.operationSnapshot().single().cancellable)
        assertFalse(session.execute(DesktopCliCommand.OperationCancel(requireNotNull(install.operationId))).success)
        advanceTimeBy(300); runCurrent()
        assertEquals(1, resumes)
    }

    @Test fun updatesCancelTargetsTheExactPendingInstallBeforeDismissal() = runTest {
        val job = "00000000-0000-0000-0000-000000000001"
        var prepared = 0
        var cancellations = 0
        var dismissals = 0
        var cancellationCode = ControlCode.OUTCOME_UNKNOWN
        val session = DesktopHeadlessSession(backgroundScope, { MainUiState() }, { command ->
            assertEquals(DesktopCliCommand.UpdatesDismiss, command)
            dismissals++
            DesktopCliResponse.success("")
        }, {}, controllerId = "owner", install = DesktopControlInstallActions(
            prepare = { _, _ ->
                prepared++
                DesktopInstallHandoffResult(ControlCode.OUTCOME_UNKNOWN, job)
            },
            recover = { Result.success(emptyList()) },
            cancel = {
                cancellations++
                DesktopInstallHandoffResult(cancellationCode, job)
            },
        ))
        val install = ControlDocumentCodec.decodeResult(session.execute(DesktopCliCommand.ControlSubmit(ControlRequest(
            "install", ControlCommand(ControlOperationId.UPDATES_INSTALL), controllerId = "owner"))).message)
        val cancellation = async {
            session.execute(DesktopCliCommand.ControlSubmit(ControlRequest(
                "cancel", ControlCommand(ControlOperationId.UPDATES_CANCEL), controllerId = "owner")))
        }

        advanceTimeBy(300)
        runCurrent()

        assertNotNull(install.operationId)
        assertEquals(1, cancellations, "Cancellation must target the one retained install")
        assertEquals(1, prepared, "Cancellation must reuse the retained install identity")
        assertEquals(0, dismissals, "Dismissal waits for the exact install cancellation")
        cancellationCode = ControlCode.CANCELLED
        advanceTimeBy(300)
        runCurrent()
        assertTrue(cancellation.await().success)
        assertEquals(1, dismissals)
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
