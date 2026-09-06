package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.MainUiState
import java.nio.file.Files
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class DesktopOperationCliTest {
    @Test
    fun asyncGrammarUsesTypedRequestsAndRejectsUnwiredOptionsBeforeDispatch() {
        val requests = mutableSetOf<String>()
        for (arguments in listOf(arrayOf("--async", "find-best"), arrayOf("locations", "benchmark", "1", "--async"),
            arrayOf("subscriptions", "refresh", "all", "--async"), arrayOf("updates", "check", "--async"),
            arrayOf("updates", "download", "--async"))) {
            assertEquals(0, DesktopCli.handleArgs(arguments, {}, requestCommand = {
                val submission = it as DesktopCliCommand.ControlSubmit
                assertTrue(submission.request.asynchronous)
                assertTrue(requests.add(submission.request.requestId))
                assertEquals(submission, DesktopCliProtocol.decodeCommand(DesktopCliProtocol.encodeCommand(submission)).getOrThrow())
                DesktopCliResponse.success("accepted")
            }))
        }
        for (arguments in listOf(arrayOf("--async", "status"), arrayOf("--async", "--json", "settings", "show"),
            arrayOf("updates", "check", "--async", "--if-revision", "1"))) {
            assertEquals(1, DesktopCli.handleArgs(arguments, {}, requestCommand = { error("Unsupported options dispatched") }))
        }
    }

    @Test
    fun operationQueriesNeverCreateAnOwnerAndRejectMalformedInput() {
        for (arguments in listOf(arrayOf("operations", "list"), arrayOf("operations", "status", "unknown"), arrayOf("operations", "wait", "unknown"), arrayOf("operations", "cancel", "unknown"))) {
            assertEquals(2, DesktopCli.handleArgs(arguments, {}, requestCommand = {
                assertTrue(it.bypassesMutationAdmission)
                assertEquals(it, DesktopCliProtocol.decodeCommand(DesktopCliProtocol.encodeCommand(it)).getOrThrow())
                DesktopCliResponse.notRunning()
            }, startHeadlessController = { error("Never replace missing operation history") }))
        }
        for (arguments in listOf(arrayOf("operations", "list", "extra"), arrayOf("operations", "status"))) {
            assertEquals(1, DesktopCli.handleArgs(arguments, {}, requestCommand = { error("Invalid request dispatched") }))
        }
        val frame = DesktopCliProtocol.encodeCommand(DesktopCliCommand.OperationsList)
        assertTrue(DesktopCliProtocol.decodeCommand("$frame\textra").isFailure)
    }

    @Test
    fun authenticatedCliObservesRunningAndRetainedOperationsWithoutPrivateInput() = runBlocking {
        val directory = Files.createTempDirectory("vpn-control-operation-cli")
        val owner = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        val started = CompletableDeferred<Unit>()
        val finish = CompletableDeferred<Unit>()
        val updateStarted = CompletableDeferred<Unit>()
        val session = DesktopHeadlessSession(owner, { MainUiState() }, executeCommand = {
            if (it == DesktopCliCommand.UpdatesCheck) {
                updateStarted.complete(Unit)
                kotlinx.coroutines.awaitCancellation()
            }
            check(it is DesktopCliCommand.LocationBenchmark)
            started.complete(Unit)
            finish.await()
            DesktopCliResponse.success("private-result")
        }, refresh = {})
        val endpoint = directory.resolve("activation.port")
        val server = assertNotNull(DesktopActivationServer.start(
            onShowWindow = { DesktopActivationShowResult.HEADLESS },
            onCliCommand = { runBlocking { session.execute(it) } }, portFile = endpoint, controllerId = session.controllerId))
        try {
            fun invoke(vararg arguments: String): Pair<Int?, String> {
                val output = mutableListOf<String>()
                val code = DesktopCli.handleArgs(arrayOf("operations", *arguments), output::add,
                    requestCommand = { DesktopActivationServer.requestCliCommand(it, endpoint) },
                    startHeadlessController = { error("Must reuse owner") })
                return code to output.joinToString("\n")
            }
            assertEquals(0 to "[]", invoke("list"))
            val action = async(Dispatchers.IO) {
                DesktopActivationServer.requestCliCommand(DesktopCliCommand.LocationBenchmark("private-input"), endpoint)
            }
            kotlinx.coroutines.withTimeout(5_000) { started.await() }
            val running = invoke("list")
            assertEquals(0, running.first)
            val operation = Json.parseToJsonElement(running.second).jsonArray.single().jsonObject
            val id = operation.getValue("id").jsonPrimitive.content
            assertEquals(DesktopControlEndpoint.read(endpoint).controllerId, operation.getValue("controllerId").jsonPrimitive.content)
            assertEquals("running", operation.getValue("phase").jsonPrimitive.content)
            assertEquals(0, invoke("status", id).first)
            assertEquals(1 to "NOT_FOUND", invoke("status", "missing"))
            finish.complete(Unit)
            assertTrue(action.await().success)
            val completed = invoke("status", id)
            assertEquals(0, completed.first)
            assertEquals("succeeded", Json.parseToJsonElement(completed.second).jsonObject.getValue("phase").jsonPrimitive.content)
            assertFalse(completed.second.contains("private"))
            assertEquals("0", Json.parseToJsonElement(completed.second).jsonObject.getValue("configurationRevision").jsonPrimitive.content)
            assertEquals(0, invoke("wait", id).first)
            val acceptedOutput = mutableListOf<String>()
            lateinit var submitted: DesktopCliCommand.ControlSubmit
            assertEquals(0, DesktopCli.handleArgs(arrayOf("--async", "--json", "updates", "check"), acceptedOutput::add,
                requestCommand = {
                    submitted = it as DesktopCliCommand.ControlSubmit
                    DesktopActivationServer.requestCliCommand(it, endpoint)
                }, startHeadlessController = { error("Reuse owner") }))
            val accepted = Json.parseToJsonElement(acceptedOutput.single()).jsonObject
            assertEquals("ACCEPTED", accepted.getValue("code").jsonPrimitive.content)
            assertEquals("false", accepted.getValue("final").jsonPrimitive.content)
            assertEquals(session.controllerId, accepted.getValue("controllerId").jsonPrimitive.content)
            kotlinx.coroutines.withTimeout(5_000) { updateStarted.await() }
            val updateId = Json.parseToJsonElement(invoke("list").second).jsonArray.last().jsonObject.getValue("id").jsonPrimitive.content
            assertEquals(updateId, accepted.getValue("operationId").jsonPrimitive.content)
            val retry = submitted.copy(request = submitted.request.copy(controllerId = session.controllerId))
            val repeated = DesktopActivationServer.requestCliCommand(retry, endpoint)
            assertTrue(repeated.success)
            assertEquals(updateId, Json.parseToJsonElement(repeated.message).jsonObject.getValue("operationId").jsonPrimitive.content)
            assertEquals(com.kardinal.vpncontrol.model.ControlCode.CONFLICT,
                com.kardinal.vpncontrol.control.ControlProtocolCodec.decodeResult(DesktopActivationServer.requestCliCommand(
                    submitted.copy(request = submitted.request.copy(controllerId = "wrong-owner")), endpoint).message).code)
            assertEquals(2, session.operationSnapshot().size)
            fun invokeJson(vararg arguments: String): Pair<Int?, com.kardinal.vpncontrol.model.ControlResult> {
                val output = mutableListOf<String>()
                val exitCode = DesktopCli.handleArgs(arrayOf("--json", "operations", *arguments), output::add,
                    requestCommand = { DesktopActivationServer.requestCliCommand(it, endpoint) },
                    startHeadlessController = { error("Never replace operation history") })
                return exitCode to com.kardinal.vpncontrol.control.ControlProtocolCodec.decodeResult(output.single())
            }
            val jsonList = invokeJson("list")
            assertEquals(0, jsonList.first)
            assertEquals(2, (jsonList.second.data["operations"] as com.kardinal.vpncontrol.model.ControlValue.ArrayValue).values.size)
            assertEquals(0, invokeJson("status", updateId).first)
            assertEquals(com.kardinal.vpncontrol.model.ControlCode.NOT_FOUND, invokeJson("status", "missing").second.code)
            val timedOut = invokeJson("wait", updateId, "--timeout-seconds", "1")
            assertEquals(2, timedOut.first)
            assertEquals(com.kardinal.vpncontrol.model.ControlCode.TIMEOUT, timedOut.second.code)
            assertEquals(updateId, timedOut.second.operationId)
            assertFalse(timedOut.second.final)
            assertEquals(com.kardinal.vpncontrol.model.ControlValue.Text("running"),
                invokeJson("status", updateId).second.data["phase"])
            assertEquals(0, invokeJson("cancel", updateId).first)
            val jsonWait = invokeJson("wait", updateId)
            assertEquals(130, jsonWait.first)
            assertEquals(com.kardinal.vpncontrol.model.ControlCode.CANCELLED, jsonWait.second.code)
        } finally {
            finish.complete(Unit)
            server.close()
            session.close()
            owner.cancel()
            directory.toFile().deleteRecursively()
        }
    }
}
