package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.ControlProtocolCodec
import com.kardinal.vpncontrol.model.*
import java.nio.file.Files
import kotlinx.coroutines.test.runTest
import kotlin.test.*

class DesktopQuitControlTest {
    @Test fun quitUsesOwnerAdmissionAndOnlyExitsAfterItsTerminalResponseIsFlushed() = runTest {
        val directory = Files.createTempDirectory("owner-quit-control")
        val service = DesktopAppServiceFactory.createForTesting(DesktopStateStore(directory))
        val owner = DesktopControllerOwner(service, scope = backgroundScope)
        try {
            val request = ControlRequest("quit", ControlCommand(ControlOperationId.QUIT), controllerId = owner.controllerId,
                ifRevision = service.configurationRevision)
            assertEquals(ControlCode.CONFLICT, owner.submit(request.copy(controllerId = "old-owner")).code)
            assertFalse(owner.exitRequested)
            val result = owner.submit(request)
            assertEquals(ControlCode.OK, result.code)
            assertFalse(owner.exitRequested)
            assertEquals(result, owner.submit(request))
            val response = DesktopCliResponse.success(ControlProtocolCodec.encodeResult(result))
            owner.responseFlushed(DesktopCliCommand.ControlSubmit(request.copy(requestId = "other")), response)
            assertFalse(owner.exitRequested)
            owner.responseFlushed(DesktopCliCommand.ControlSubmit(request), response)
            assertTrue(owner.exitRequested)
        } finally { owner.close(); directory.toFile().deleteRecursively() }
    }

    @Test fun quitPersistenceFailureCannotReleaseOwnerExitGate() = runTest {
        val directory = Files.createTempDirectory("owner-quit-failure")
        val service = DesktopAppServiceFactory.createForTesting(DesktopStateStore(directory))
        val owner = DesktopControllerOwner(service, scope = backgroundScope)
        try {
            service.applyControlSettings(mapOf("validation.batch-size" to ControlValue.IntegerValue(7))).getOrThrow()
            Files.move(directory.resolve("workspace.json"), directory.resolve("previous.json"))
            Files.createDirectory(directory.resolve("workspace.json"))
            Files.createDirectory(directory.resolve("workspace-recovery.json"))
            val request = ControlRequest("failed-quit", ControlCommand(ControlOperationId.QUIT), controllerId = owner.controllerId)
            val result = owner.submit(request)
            assertFalse(result.ok)
            owner.responseFlushed(DesktopCliCommand.ControlSubmit(request),
                DesktopCliResponse(result.ok, ControlProtocolCodec.encodeResult(result), result.exitCode))
            assertFalse(owner.exitRequested)
        } finally { owner.close(); directory.toFile().deleteRecursively() }
    }
}
