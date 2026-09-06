package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.ControlProtocolCodec
import com.kardinal.vpncontrol.model.ControlCode
import com.kardinal.vpncontrol.model.ControlCommand
import com.kardinal.vpncontrol.model.ControlOperationId
import com.kardinal.vpncontrol.model.ControlRequest
import com.kardinal.vpncontrol.model.ControlResult
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse

class DesktopCliJsonTest {
    @Test
    fun timeoutIsLocalAndNotPartOfTheTransferredRequest() {
        for (timeout in listOf(0L, 1L, Int.MAX_VALUE.toLong(), Long.MAX_VALUE / 1000)) {
            val output = mutableListOf<String>()
            assertEquals(0, DesktopCli.handleArgs(arrayOf("--json", "--timeout-seconds", timeout.toString(),
                "settings", "show"), output::add, requestCommand = { command ->
                val submission = command as DesktopCliCommand.ControlSubmit
                assertEquals(timeout, submission.clientTimeoutSeconds)
                val decoded = DesktopCliProtocol.decodeCommand(DesktopCliProtocol.encodeCommand(submission)).getOrThrow()
                    as DesktopCliCommand.ControlSubmit
                assertEquals(submission.request, decoded.request)
                assertEquals(600L, decoded.clientTimeoutSeconds)
                DesktopCliResponse.success(ControlProtocolCodec.encodeResult(ControlResult("owner",
                    submission.request.requestId, ControlCode.OK, 0)))
            }))
        }
    }

    @Test
    fun jsonOperationInspectionNeverStartsAReplacementOwner() {
        for (arguments in listOf(arrayOf("list"), arrayOf("status", "missing"),
            arrayOf("wait", "missing"), arrayOf("cancel", "missing"))) {
            val output = mutableListOf<String>()
            assertEquals(2, DesktopCli.handleArgs(arrayOf("--json", "operations", *arguments), output::add,
                requestCommand = { DesktopCliResponse.notRunning() },
                startHeadlessController = { error("Never replace history") }))
            assertEquals(ControlCode.UNAVAILABLE, ControlProtocolCodec.decodeResult(output.single()).code)
        }
    }

    @Test
    fun invalidJsonInvocationsNeverStartOwnerOrPrintUsageOrPrivateInput() {
        for (args in listOf(arrayOf("--json", "settings", "set", "validation.batch-size", "private-invalid"),
            arrayOf("--json", "settings", "show", "--typo"),
            arrayOf("--json", "settings", "apply", "--input", "private-path"),
            arrayOf("--json", "settings", "set", "validation.batch-size", "3", "--if-revision", "1"))) {
            val output = mutableListOf<String>()
            assertEquals(1, DesktopCli.handleArgs(args, output::add,
                requestCommand = { error("Invalid request dispatched") },
                startHeadlessController = { error("Invalid request started owner") },
                readInput = { Result.failure(IllegalStateException("private-path")) }))
            val result = ControlProtocolCodec.decodeResult(output.single())
            assertEquals(ControlCode.INVALID_ARGUMENT, result.code)
            assertEquals(null, result.controllerId)
            assertEquals(listOf("OWNER_METADATA_UNAVAILABLE"), result.warnings)
            assertFalse(output.single().contains("private"))
        }
    }

    @Test
    fun jsonTransportFailuresAreSanitizedAndMismatchedRepliesAreRejected() {
        val request = ControlRequest("request", ControlCommand(ControlOperationId.SETTINGS_SHOW))
        val missing = desktopCliJsonResponse(request, DesktopCliResponse.notRunning())
        assertEquals(ControlCode.UNAVAILABLE, ControlProtocolCodec.decodeResult(missing.message).code)
        val unknown = desktopCliJsonResponse(request, DesktopCliResponse.failure("private transport details", 2))
        assertEquals(ControlCode.OUTCOME_UNKNOWN, ControlProtocolCodec.decodeResult(unknown.message).code)
        assertFalse(unknown.message.contains("private"))
        val mismatch = desktopCliJsonResponse(request, DesktopCliResponse.success(ControlProtocolCodec.encodeResult(
            ControlResult("owner", "wrong-request", ControlCode.OK, 3))))
        assertEquals(ControlCode.INCOMPATIBLE_PROTOCOL, ControlProtocolCodec.decodeResult(mismatch.message).code)
    }
}
