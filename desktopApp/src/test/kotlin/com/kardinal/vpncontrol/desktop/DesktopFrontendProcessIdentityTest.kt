package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.*
import com.kardinal.vpncontrol.model.*
import java.nio.file.Files
import java.util.UUID
import kotlin.test.*

class DesktopFrontendProcessIdentityTest {
    @Test fun fixedAuthenticatedEndpointProvesActualSelfProcessWithoutCallerPid() {
        val directory = Files.createTempDirectory("frontend-process-proof")
        val instance = assertNotNull(DesktopFrontendInstance.start(directory, DesktopFrontendVisibility()))
        try {
            val identity = DesktopFrontendProcessIdentity.read(directory, instance.identity).getOrThrow()
            assertEquals(ProcessHandle.current().pid(), identity.pid)
            assertEquals(ProcessHandle.current().info().startInstant().orElseThrow().toEpochMilli(), identity.startedAtEpochMillis)
            assertTrue(identity.isStillSameProcess())
            assertFalse(identity.copy(startedAtEpochMillis = identity.startedAtEpochMillis + 1).isStillSameProcess())
            assertTrue(DesktopFrontendProcessIdentity.read(directory, UUID.randomUUID().toString()).isFailure)
            // The endpoint still cannot execute product actions.
            assertFalse(DesktopActivationServer.requestCliCommand(DesktopCliCommand.On, DesktopFrontendInstance.endpoint(directory)).success)
        } finally { instance.close(); directory.toFile().deleteRecursively() }
    }

    @Test fun decoderRejectsStaleOwnerCorrelationMalformedFieldsAndUnverifiedProcess() {
        val directory = java.nio.file.Path.of("unused-fixture-directory")
        val registration = UUID.randomUUID().toString()
        val validData = mapOf("pid" to ControlValue.IntegerValue(123), "startedAtEpochMillis" to ControlValue.IntegerValue(456))
        fun read(transform: (ControlResult) -> ControlResult = { it }, verify: Boolean = true) =
            DesktopFrontendProcessIdentity.read(directory, registration, request = { command, endpoint ->
                assertEquals(directory.resolve("frontend.port"), endpoint)
                val request = command as DesktopCliCommand.ControlFrontendIdentityRead
                DesktopCliResponse.success(ControlProtocolCodec.encodeResult(transform(ControlResult(registration,
                    request.requestId, ControlCode.OK, 0, data = validData))))
            }, verifyProcess = { verify })
        assertTrue(read().isSuccess)
        assertTrue(read({ it.copy(controllerId = UUID.randomUUID().toString()) }).isFailure)
        assertTrue(read({ it.copy(requestId = "wrong") }).isFailure)
        assertTrue(read({ it.copy(data = validData - "pid") }).isFailure)
        assertTrue(read({ it.copy(data = validData + ("privatePath" to ControlValue.Text("PRIVATE"))) }).isFailure)
        assertTrue(read({ it.copy(data = validData + ("pid" to ControlValue.IntegerValue(-1))) }).isFailure)
        assertTrue(read({ it.copy(data = validData + ("startedAtEpochMillis" to ControlValue.Text("456"))) }).isFailure)
        assertTrue(read(verify = false).isFailure)
    }

    @Test fun internalProtocolHasOnlyRequestAndRegistrationIdentity() {
        val command = DesktopCliCommand.ControlFrontendIdentityRead(UUID.randomUUID().toString(), UUID.randomUUID().toString())
        assertEquals(command, DesktopCliProtocol.decodeCommand(DesktopCliProtocol.encodeCommand(command)).getOrThrow())
        assertTrue(command.bypassesMutationAdmission)
        assertTrue(DesktopCliProtocol.decodeCommand(DesktopCliProtocol.encodeCommand(command.copy(frontendId = "123"))).isFailure)
        assertTrue(DesktopCliProtocol.decodeCommand(DesktopCliProtocol.encodeCommand(command) + "\t123").isFailure)
    }
}
