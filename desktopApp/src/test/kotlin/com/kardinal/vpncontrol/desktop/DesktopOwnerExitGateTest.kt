package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.ControlProtocolCodec
import com.kardinal.vpncontrol.model.*
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
