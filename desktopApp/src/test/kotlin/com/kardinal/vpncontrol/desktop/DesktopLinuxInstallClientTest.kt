package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.ControlDocumentCodec
import com.kardinal.vpncontrol.model.*
import kotlin.test.*

class DesktopLinuxInstallClientTest {
    private val operation = "11111111-1111-4111-8111-111111111111"
    private val job = "22222222-2222-4222-8222-222222222222"
    private val owner = DesktopLinuxAuthorizationOwner(123, 456, 1000)
    private val endpoint = DesktopControlEndpoint(3210, "owner", "private-token", linuxAuthorizationOwner = owner)
    private fun command(timeout: Long = 10) = DesktopCliCommand.ControlSubmit(ControlRequest("install",
        ControlCommand(ControlOperationId.UPDATES_INSTALL), controllerId = "owner", asynchronous = true), timeout)
    private fun reply(request: ControlRequest, code: ControlCode = ControlCode.ACCEPTED, ready: Boolean = false,
        final: Boolean = false, controller: String = "owner", id: String = operation): DesktopCliResponse {
        val result = ControlResult(controller, request.requestId, code, 7, final = final, operationId = id,
            data = if (ready) mapOf("handoffReady" to ControlValue.BooleanValue(true), "jobId" to ControlValue.Text(job)) else emptyMap())
        return DesktopCliResponse(result.ok, ControlDocumentCodec.encodeResult(result), result.exitCode)
    }

    @Test fun asyncAcceptanceRetainsTerminalUntilExactProtectedHandoffAndNeverRereadsEndpoint() {
        var reads = 0; var closes = 0; var leased = false; var polls = 0
        val seen = mutableListOf<ControlOperationId>()
        val client = DesktopLinuxInstallClient(endpoint = { reads++; endpoint }, terminalAvailable = { true },
            verify = { captured, id -> assertSame(endpoint, captured); assertEquals("owner", id); owner },
            authorize = { leased = true; AutoCloseable { leased = false; closes++ } }, pause = {},
            exchange = { command, captured, _ ->
                assertSame(endpoint, captured)
                val request = (command as DesktopCliCommand.ControlSubmit).request
                seen += request.command.operation
                assertEquals("owner", request.controllerId)
                when (request.command.operation) {
                    ControlOperationId.STATUS -> { assertFalse(leased); reply(request, ControlCode.OK, final = true) }
                    ControlOperationId.UPDATES_INSTALL -> { assertTrue(leased); assertTrue(request.asynchronous); reply(request) }
                    ControlOperationId.OPERATIONS_STATUS -> {
                        assertTrue(leased); assertEquals(ControlValue.Text(operation), request.command.arguments["id"])
                        reply(request, ready = ++polls == 2)
                    }
                    else -> error("Unexpected request")
                }
            })
        val result = ControlDocumentCodec.decodeResult(client.execute(command()).message)
        assertEquals(ControlCode.ACCEPTED, result.code); assertFalse(result.final)
        assertEquals("install", result.requestId); assertEquals(operation, result.operationId)
        assertEquals(ControlValue.BooleanValue(true), result.data["handoffReady"])
        assertEquals(1, reads); assertEquals(1, closes); assertFalse(leased)
        assertFalse(ControlOperationId.OPERATIONS_WAIT in seen)
    }

    @Test fun absentTerminalOrUnverifiedOwnerNeverSubmitsInstall() {
        for (verified in listOf(true, false)) {
            var requests = 0; var starts = 0
            val client = DesktopLinuxInstallClient(endpoint = { endpoint }, terminalAvailable = { false },
                verify = { _, _ -> check(verified) { "CONFLICT" }; owner }, authorize = { starts++; AutoCloseable {} },
                exchange = { command, _, _ -> requests++; reply((command as DesktopCliCommand.ControlSubmit).request, ControlCode.OK, final = true) })
            val result = ControlDocumentCodec.decodeResult(client.execute(command()).message)
            assertEquals(if (verified) ControlCode.INTERACTION_REQUIRED else ControlCode.CONFLICT, result.code)
            assertEquals(1, requests); assertEquals(0, starts)
        }
    }

    @Test fun terminalFailureAndUnknownCloseOnlyAgentAndPreserveOriginalCorrelation() {
        for (code in listOf(ControlCode.PERMISSION_DENIED, ControlCode.OUTCOME_UNKNOWN)) {
            var closes = 0; var calls = 0
            val client = DesktopLinuxInstallClient(endpoint = { endpoint }, terminalAvailable = { true },
                verify = { _, _ -> owner }, authorize = { AutoCloseable { closes++ } }, pause = {},
                exchange = { command, _, _ ->
                    val request = (command as DesktopCliCommand.ControlSubmit).request
                    when (++calls) {
                        1 -> reply(request, ControlCode.OK, final = true)
                        2 -> reply(request)
                        else -> reply(request, code, final = code != ControlCode.OUTCOME_UNKNOWN)
                    }
                })
            val result = ControlDocumentCodec.decodeResult(client.execute(command()).message)
            assertEquals(code, result.code); assertEquals("install", result.requestId)
            assertEquals(operation, result.operationId); assertEquals(1, closes); assertEquals(3, calls)
        }
    }

    @Test fun timeoutBudgetIncludesHandshakeAndAuthorizationAndDoesNotDispatchAfterExpiry() {
        var time = 0L; var calls = 0; var closes = 0
        val client = DesktopLinuxInstallClient(endpoint = { endpoint }, terminalAvailable = { true },
            verify = { _, _ -> owner }, clockMillis = { time }, authorize = {
                time += 600; AutoCloseable { closes++ }
            }, exchange = { command, _, timeout ->
                calls++; assertEquals(1000L, timeout); time += 500
                reply((command as DesktopCliCommand.ControlSubmit).request, ControlCode.OK, final = true)
            })
        val result = ControlDocumentCodec.decodeResult(client.execute(command(1)).message)
        assertEquals(ControlCode.TIMEOUT, result.code); assertFalse(result.final)
        assertEquals(1, calls); assertEquals(1, closes)
    }

    @Test fun replacementControllerOrOperationCannotReleaseLeaseAsSuccessfulHandoff() {
        for (replacement in listOf("owner", "operation", "terminal-operation", "request")) {
            var calls = 0; var closes = 0
            val client = DesktopLinuxInstallClient(endpoint = { endpoint }, terminalAvailable = { true },
                verify = { _, _ -> owner }, authorize = { AutoCloseable { closes++ } }, pause = {},
                exchange = { command, _, _ ->
                    val request = (command as DesktopCliCommand.ControlSubmit).request
                    when (++calls) {
                        1 -> reply(request, ControlCode.OK, final = true)
                        2 -> reply(request)
                        else -> reply(if (replacement == "request") request.copy(requestId = "wrong") else request,
                            code = if (replacement == "terminal-operation") ControlCode.PERMISSION_DENIED else ControlCode.ACCEPTED,
                            final = replacement == "terminal-operation", ready = true,
                            controller = if (replacement == "owner") "replacement" else "owner",
                            id = if (replacement in setOf("operation", "terminal-operation")) job else operation)
                    }
                })
            val result = ControlDocumentCodec.decodeResult(client.execute(command()).message)
            assertFalse(result.ok); assertEquals(ControlCode.INCOMPATIBLE_PROTOCOL, result.code)
            assertEquals(1, closes)
        }
    }

    @Test fun unavailableAfterSubmissionIsUnknownWithKnownOperationNotDefinitiveFailure() {
        var calls = 0; var closes = 0
        val client = DesktopLinuxInstallClient(endpoint = { endpoint }, terminalAvailable = { true },
            verify = { _, _ -> owner }, authorize = { AutoCloseable { closes++ } }, pause = {},
            exchange = { command, _, _ ->
                val request = (command as DesktopCliCommand.ControlSubmit).request
                when (++calls) {
                    1 -> reply(request, ControlCode.OK, final = true)
                    2 -> reply(request)
                    else -> DesktopCliResponse.notRunning()
                }
            })
        val result = ControlDocumentCodec.decodeResult(client.execute(command()).message)
        assertEquals(ControlCode.OUTCOME_UNKNOWN, result.code)
        assertFalse(result.final); assertEquals(operation, result.operationId)
        assertEquals(1, closes)
    }
}
