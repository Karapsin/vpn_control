package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.ControlProtocolCodec
import com.kardinal.vpncontrol.model.*
import kotlin.test.*

class DesktopOwnerExitGateTest {
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
