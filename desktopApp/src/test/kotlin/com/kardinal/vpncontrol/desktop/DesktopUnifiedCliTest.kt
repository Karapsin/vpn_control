package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.*
import com.kardinal.vpncontrol.model.*
import kotlin.test.*

class DesktopUnifiedCliTest {
    private fun response(request: ControlRequest, code: ControlCode = ControlCode.OK,
                         final: Boolean = true, operationId: String? = null): DesktopCliResponse {
        val result = ControlResult("owner", request.requestId, code, 4, final = final, operationId = operationId)
        return DesktopCliResponse(result.ok, ControlDocumentCodec.encodeResult(result), result.exitCode)
    }

    @Test fun humanAndJsonUseIdenticalTypedCommandsAndTimeoutMetadata() {
        for (arguments in listOf(listOf("on"), listOf("settings", "show"), listOf("select", "New", "York"),
            listOf("routing", "set", "ignore-rules", "true"), listOf("operations", "wait", "known-job"))) {
            val requests = mutableListOf<ControlRequest>()
            for (json in listOf(false, true)) {
                assertEquals(0, DesktopCli.handleArgs((arguments + listOf("--timeout-seconds", "7") +
                    if (json) listOf("--json") else emptyList()).toTypedArray(), printLine = {}, printProgress = {},
                    requestCommand = { command ->
                        val submit = assertIs<DesktopCliCommand.ControlSubmit>(command)
                        assertEquals(7L, submit.clientTimeoutSeconds)
                        requests += submit.request
                        response(submit.request)
                    }))
            }
            assertEquals(2, requests.size)
            assertEquals(requests[0].copy(requestId = "same"), requests[1].copy(requestId = "same"))
        }
    }

    @Test fun humanFailuresAndPendingOperationIdentityUseStderr() {
        for (android in listOf(false, true)) for ((code, final) in listOf(ControlCode.INVALID_ARGUMENT to true,
            ControlCode.TIMEOUT to false, ControlCode.ACCEPTED to false)) {
            val output = mutableListOf<String>()
            val errors = mutableListOf<String>()
            val argv = listOf("find-best") + if (android) listOf("--android") else emptyList()
            assertEquals(code.exitCode, DesktopCli.handleArgs(argv.toTypedArray(), printLine = output::add,
                printProgress = errors::add, requestCommand = { response(assertIs<DesktopCliCommand.ControlSubmit>(it).request,
                    code, final, "retained-job") }, androidRequest = { request, _, _ -> response(request, code, final, "retained-job") }))
            assertTrue(output.isEmpty())
            assertTrue(errors.single().contains(code.wireName))
            assertTrue(errors.single().contains("retained-job"))
        }
    }

    @Test fun unknownFlagsNeverReadInputStartOwnerOrLeakRawArguments() {
        val errors = mutableListOf<String>()
        assertEquals(1, DesktopCli.handleArgs(arrayOf("settings", "apply", "--input", "PRIVATE_PATH", "--unknown"),
            printLine = { error("Human error on stdout") }, printProgress = errors::add,
            requestCommand = { error("No request") }, startHeadlessController = { error("No startup") },
            readInput = { error("No file read") }))
        assertTrue(errors.isNotEmpty())
        assertFalse(errors.joinToString().contains("PRIVATE_PATH"))
    }

    @Test fun helpCoversEveryRegistryOperationAndAliasWithoutStartup() {
        val output = mutableListOf<String>()
        assertEquals(0, DesktopCli.handleArgs(arrayOf("--help"), printLine = output::add,
            requestCommand = { error("No request") }, startHeadlessController = { error("No startup") }))
        val help = output.single()
        for (descriptor in ControlOperationRegistry.operations) {
            assertTrue(help.contains(descriptor.grammar), descriptor.id.wireName)
            descriptor.aliases.forEach { assertTrue(help.contains(it)) }
        }
        assertTrue(help.contains("--timeout-seconds"))
    }
}
