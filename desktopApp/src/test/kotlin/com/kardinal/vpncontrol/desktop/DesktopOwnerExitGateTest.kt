package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.control.ControlProtocolCodec
import com.kardinal.vpncontrol.model.*
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.runBlocking
import kotlin.test.*

class DesktopOwnerExitGateTest {
    @Test fun normalQuitWaitsForItsExactFlushedOwnerResponseBeforeFrontendCallback() {
        val owner = java.util.UUID.randomUUID().toString()
        val frontend = DesktopFrontendProcessIdentity(java.util.UUID.randomUUID().toString(), 42, 99)
        val correlation = DesktopFrontendQuitCorrelation(owner, "supported public request", frontend)
        var callbacks = 0
        var release: (() -> Unit)? = null
        val gate = DesktopOwnerExitGate(releaseQuit = { actual, ready ->
            assertEquals(correlation, actual)
            callbacks++
            release = ready
        })
        gate.requestFrontendQuitAfterResponse(correlation)
        fun response(requestId: String = correlation.publicRequestId, responseOwner: String = owner,
            code: ControlCode = ControlCode.OK) = DesktopCliResponse(code == ControlCode.OK,
            ControlProtocolCodec.encodeResult(ControlResult(responseOwner, requestId, code, 0,
                operationId = java.util.UUID.randomUUID().toString())), code.exitCode)
        val command = DesktopCliCommand.ControlSubmit(ControlRequest(correlation.publicRequestId,
            ControlCommand(ControlOperationId.QUIT), controllerId = owner))
        gate.responseFlushed(command.copy(request = command.request.copy(requestId = "other")), response("other"))
        gate.responseFlushed(command, response(responseOwner = java.util.UUID.randomUUID().toString()))
        gate.responseFlushed(command, response(code = ControlCode.BUSY))
        assertEquals(0, callbacks)
        gate.responseFlushed(command, response())
        assertEquals(1, callbacks)
        assertFalse(gate.exitRequested)
        assertNotNull(release).invoke()
        assertTrue(gate.exitRequested)
    }

    @Test fun flushedInstallerResponseWaitsForCapturedFrontendAndRevocationInvalidatesLateRelease() {
        var callbacks = 0
        var release: (() -> Unit)? = null
        val gate = DesktopOwnerExitGate(releaseInstall = { _, _, ready -> callbacks++; release = ready })
        val job = "00000000-0000-0000-0000-000000000001"
        val correlation = DesktopInstallCorrelation("owner", "install", "operation")
        val request = ControlRequest("inspect", ControlCommand(ControlOperationId.OPERATIONS_STATUS,
            mapOf("id" to ControlValue.Text("operation"))), controllerId = "owner")
        val result = ControlResult("owner", "inspect", ControlCode.ACCEPTED, 0, final = false, operationId = "operation",
            data = mapOf("jobId" to ControlValue.Text(job), "handoffReady" to ControlValue.BooleanValue(true)))
        fun flush(ready: Boolean = true) = gate.responseFlushed(DesktopCliCommand.ControlSubmit(request),
            DesktopCliResponse.success(ControlProtocolCodec.encodeResult(result.copy(
                data = result.data + ("handoffReady" to ControlValue.BooleanValue(ready))))))
        gate.requestInstallExitAfterResponse(correlation, job)
        flush(false)
        assertEquals(0, callbacks)
        flush(); flush()
        assertEquals(1, callbacks)
        assertFalse(gate.exitRequested)
        gate.revokeInstallExit(correlation, job)
        assertNotNull(release).invoke()
        assertFalse(gate.exitRequested)
    }

    @Test fun exactFrontendCompletionReleasesOnlyAfterPublicResponseWasFlushed() {
        var release: (() -> Unit)? = null
        val gate = DesktopOwnerExitGate(releaseInstall = { _, _, ready -> release = ready })
        val job = "00000000-0000-0000-0000-000000000001"
        gate.requestInstallExitAfterResponse(DesktopInstallCorrelation("owner", "install", "operation"), job)
        assertNull(release)
        val request = ControlRequest("install", ControlCommand(ControlOperationId.UPDATES_INSTALL), controllerId = "owner")
        gate.responseFlushed(DesktopCliCommand.ControlSubmit(request), DesktopCliResponse.success(ControlProtocolCodec.encodeResult(
            ControlResult("owner", "install", ControlCode.ACCEPTED, 0, final = false, operationId = "operation",
                data = mapOf("jobId" to ControlValue.Text(job), "handoffReady" to ControlValue.BooleanValue(true))))))
        assertFalse(gate.exitRequested)
        assertNotNull(release).invoke()
        assertTrue(gate.exitRequested)
    }

    @Test fun flushedPublicUpdateStatusAcknowledgesTheExactWaitingInstallerExit() = runBlocking {
        var release: (() -> Unit)? = null
        val gate = DesktopOwnerExitGate(releaseInstall = { _, _, ready -> release = ready })
        val job = "00000000-0000-0000-0000-000000000001"
        val correlation = DesktopInstallCorrelation("owner", "install", "operation")
        gate.requestInstallExitAfterResponse(correlation, job)
        val request = ControlRequest("status", ControlCommand(ControlOperationId.UPDATES_STATUS), controllerId = "owner")
        val response = updateStatusResponse(request, correlation, job)
        val actual = ControlProtocolCodec.decodeResult(response.message)
        assertEquals(ControlCode.OK, actual.code)
        assertTrue(actual.final, "updates status is a completed inspection envelope")

        gate.responseFlushed(DesktopCliCommand.ControlSubmit(request), response)

        assertNotNull(release).invoke()
        assertTrue(gate.exitRequested)
    }

    @Test fun publicUpdateStatusRejectsEveryNonExactCorrelationAndNonReadyState() = runBlocking {
        val job = "00000000-0000-0000-0000-000000000001"
        val correlation = DesktopInstallCorrelation("owner", "install", "operation")
        val request = ControlRequest("status", ControlCommand(ControlOperationId.UPDATES_STATUS), controllerId = "owner")
        val actual = ControlProtocolCodec.decodeResult(updateStatusResponse(request, correlation, job).message)
        val base = ((actual.data.getValue("installations") as ControlValue.ArrayValue).values.single() as ControlValue.ObjectValue).values
        val mismatches = listOf(
            "job" to (base + ("jobId" to ControlValue.Text("00000000-0000-0000-0000-000000000002"))),
            "owner" to (base + ("originControllerId" to ControlValue.Text("other-owner"))),
            "request" to (base + ("originRequestId" to ControlValue.Text("other-request"))),
            "operation" to (base + ("operationId" to ControlValue.Text("other-operation"))),
            "code" to (base + ("code" to ControlValue.Text(ControlCode.OUTCOME_UNKNOWN.wireName))),
            "final" to (base + ("final" to ControlValue.BooleanValue(true))),
            "installed" to (base + ("installed" to ControlValue.BooleanValue(false))),
            "installed-true" to (base + ("installed" to ControlValue.BooleanValue(true))),
        )
        val phaseMismatches = (DesktopInstallJobPhase.entries - DesktopInstallJobPhase.WAITING_FOR_EXIT).map { phase ->
            "phase-${phase.name.lowercase()}" to (base + ("phase" to ControlValue.Text(phase.name.lowercase())))
        }
        (mismatches + phaseMismatches).forEach { (name, values) ->
            var released = false
            val gate = DesktopOwnerExitGate(releaseInstall = { _, _, ready -> released = true; ready() })
            gate.requestInstallExitAfterResponse(correlation, job)
            val response = actual.copy(data = mapOf("installations" to ControlValue.ArrayValue(
                listOf(ControlValue.ObjectValue(values))))).let { result ->
                DesktopCliResponse.success(ControlProtocolCodec.encodeResult(result))
            }
            gate.responseFlushed(DesktopCliCommand.ControlSubmit(request), response)
            assertFalse(released, name)
            assertFalse(gate.exitRequested, name)
        }
        for (outer in listOf(actual.copy(requestId = "other-status"), actual.copy(controllerId = "other-owner"),
            actual.copy(final = false), actual.copy(code = ControlCode.OUTCOME_UNKNOWN))) {
            var released = false
            val gate = DesktopOwnerExitGate(releaseInstall = { _, _, ready -> released = true; ready() })
            gate.requestInstallExitAfterResponse(correlation, job)
            gate.responseFlushed(DesktopCliCommand.ControlSubmit(request),
                DesktopCliResponse.success(ControlProtocolCodec.encodeResult(outer)))
            assertFalse(released)
            assertFalse(gate.exitRequested)
        }
        var released = false
        val gate = DesktopOwnerExitGate(releaseInstall = { _, _, ready -> released = true; ready() })
        gate.requestInstallExitAfterResponse(correlation, job)
        gate.responseFlushed(DesktopCliCommand.ControlSubmit(request),
            DesktopCliResponse(false, ControlProtocolCodec.encodeResult(actual), 0))
        assertFalse(released)
        assertFalse(gate.exitRequested)
    }

    private suspend fun updateStatusResponse(request: ControlRequest, correlation: DesktopInstallCorrelation,
        job: String): DesktopCliResponse {
        val receipt = DesktopInstallJobReceipt(job, 1, DesktopInstallJobPhase.WAITING_FOR_EXIT, ControlCode.OK)
        val recovery = DesktopInstallCorrelationRecovery(DesktopInstallCorrelationRecord(correlation, job, "0".repeat(64)),
            receipt, ControlCode.ACCEPTED)
        val session = DesktopHeadlessSession(CoroutineScope(SupervisorJob() + Dispatchers.Unconfined), { MainUiState() },
            { error("updates status must remain an inspection") }, {}, controllerId = correlation.controllerId,
            inspectRead = { command ->
                assertEquals(ControlOperationId.UPDATES_STATUS, command.operation)
                DesktopControlReadSnapshot(DesktopControlMetadata(0, false), Result.success(mapOf(
                    "installations" to DesktopRecoveredInstallPresentation.values(listOf(recovery)),
                )))
            })
        return try { session.execute(DesktopCliCommand.ControlSubmit(request)) } finally { session.close() }
    }

    @Test fun terminalFailureRevokesOnlyItsOwnUnflushedInstallExitPermit() {
        val gate = DesktopOwnerExitGate()
        val job = "00000000-0000-0000-0000-000000000001"
        val identity = DesktopInstallCorrelation("owner", "install", "operation")
        gate.requestInstallExitAfterResponse(identity, job)
        gate.revokeInstallExit(identity, job)
        val request = ControlRequest("install", ControlCommand(ControlOperationId.UPDATES_INSTALL), controllerId = "owner")
        val result = ControlResult("owner", "install", ControlCode.ACCEPTED, 0, final = false, operationId = "operation",
            data = mapOf("jobId" to ControlValue.Text(job), "handoffReady" to ControlValue.BooleanValue(true)))
        gate.responseFlushed(DesktopCliCommand.ControlSubmit(request), DesktopCliResponse.success(ControlProtocolCodec.encodeResult(result)))
        assertFalse(gate.exitRequested)
    }

    @Test fun installerExitRequiresExactReadyJobAndOperationAcknowledgement() {
        val gate = DesktopOwnerExitGate()
        val job = "00000000-0000-0000-0000-000000000001"
        val correlation = DesktopInstallCorrelation("owner", "install", "operation")
        val request = ControlRequest("install", ControlCommand(ControlOperationId.UPDATES_INSTALL), controllerId = "owner")
        val result = ControlResult("owner", "install", ControlCode.ACCEPTED, 0, final = false, operationId = "operation",
            data = mapOf("jobId" to ControlValue.Text(job), "handoffReady" to ControlValue.BooleanValue(true)))
        fun flush(result: ControlResult) = gate.responseFlushed(DesktopCliCommand.ControlSubmit(request),
            DesktopCliResponse.success(ControlProtocolCodec.encodeResult(result)))
        flush(result)
        assertFalse(gate.exitRequested)
        gate.requestInstallExitAfterResponse(correlation, job)
        flush(result.copy(operationId = "unrelated"))
        flush(result.copy(data = result.data + ("handoffReady" to ControlValue.BooleanValue(false))))
        flush(result.copy(data = result.data + ("jobId" to ControlValue.Text("other"))))
        assertFalse(gate.exitRequested)
        flush(result)
        assertTrue(gate.exitRequested)
    }

    @Test fun authenticatedServerReleasesExitGateOnlyAfterWritingSuccessfulQuitEnvelope() {
        val directory = java.nio.file.Files.createTempDirectory("owner-exit-response")
        val endpoint = directory.resolve("activation.port")
        val gate = DesktopOwnerExitGate()
        val flushed = java.util.concurrent.CountDownLatch(1)
        val owner = java.util.UUID.randomUUID().toString()
        val server = assertNotNull(DesktopActivationServer.start(
            onShowWindow = { DesktopActivationShowResult.HEADLESS }, controllerId = owner, portFile = endpoint,
            onCliCommand = { command ->
                val request = (command as DesktopCliCommand.ControlSubmit).request
                gate.requestExitAfterResponse(request.requestId)
                assertFalse(gate.exitRequested)
                DesktopCliResponse.success(ControlProtocolCodec.encodeResult(ControlResult(owner, request.requestId, ControlCode.OK, 0)))
            }, onCliResponseFlushed = { command, response -> gate.responseFlushed(command, response); flushed.countDown() }))
        try {
            val response = DesktopActivationServer.requestCliCommand(DesktopCliCommand.ControlSubmit(
                ControlRequest("quit", ControlCommand(ControlOperationId.QUIT), controllerId = owner)), endpoint)
            assertTrue(response.success)
            assertTrue(flushed.await(3, java.util.concurrent.TimeUnit.SECONDS))
            assertTrue(gate.exitRequested)
        } finally { server.close(); directory.toFile().deleteRecursively() }
    }

    @Test fun exitRequiresExactSuccessfulTerminalResponseNotAnotherReadOrAcceptedJob() {
        val gate = DesktopOwnerExitGate()
        val command = DesktopCliCommand.ControlSubmit(ControlRequest("quit", ControlCommand(ControlOperationId.QUIT), controllerId = "owner"))
        fun response(id: String = "quit", owner: String = "owner", code: ControlCode = ControlCode.OK) =
            DesktopCliResponse(code == ControlCode.OK || code == ControlCode.ACCEPTED, ControlProtocolCodec.encodeResult(
                ControlResult(owner, id, code, 0, final = code != ControlCode.ACCEPTED,
                    operationId = if (code == ControlCode.ACCEPTED) "operation" else null)), code.exitCode)
        gate.requestExitAfterResponse("quit")
        assertFalse(gate.exitRequested)
        gate.responseFlushed(DesktopCliCommand.ControlSnapshotRead("owner"), response())
        gate.responseFlushed(command.copy(request = command.request.copy(requestId = "read")), response("read"))
        gate.responseFlushed(command, response(code = ControlCode.BUSY))
        gate.responseFlushed(command, response(code = ControlCode.ACCEPTED))
        gate.responseFlushed(command, response(owner = "replacement"))
        assertFalse(gate.exitRequested)
        gate.responseFlushed(command, response())
        assertTrue(gate.exitRequested)
    }
}
