package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.ControlDocumentCodec
import com.kardinal.vpncontrol.model.*
import java.nio.file.Files
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.runBlocking
import kotlin.test.*

class DesktopSynchronousOperationClientTest {
    private val captured = DesktopControlEndpoint(1234, "owner", "private-token")
    private val operation = "11111111-1111-4111-8111-111111111111"
    private fun command(timeout: Long = 1) = DesktopCliCommand.ControlSubmit(ControlRequest("original",
        ControlCommand(ControlOperationId.LOCATIONS_DELETE, mapOf("id" to ControlValue.Text("location"))),
        controllerId = "owner", ifRevision = 7), timeout)
    private fun reply(request: ControlRequest, code: ControlCode = ControlCode.OK, final: Boolean = true,
                      id: String? = null, controller: String = "owner",
                      data: Map<String, ControlValue> = emptyMap()): DesktopCliResponse {
        val result = ControlResult(controller, request.requestId, code, 7, final = final, operationId = id,
            restartRequired = true, data = data)
        return DesktopCliResponse(result.ok, ControlDocumentCodec.encodeResult(result), result.exitCode)
    }
    private fun result(response: DesktopCliResponse) = ControlDocumentCodec.decodeResult(response.message)

    @Test fun deadlineAndEndpointStayBoundThroughAcceptanceAndObservation() {
        var time = 0L
        var reads = 0
        var descriptor = captured
        val seen = mutableListOf<ControlRequest>()
        val allowances = mutableListOf<Long>()
        val original = command()
        val client = DesktopSynchronousOperationClient(endpoint = { reads++; descriptor }, clockMillis = { time },
            pause = { time += it }, exchange = { incoming, pinned, allowance ->
                assertSame(captured, pinned)
                allowances += allowance
                val request = assertIs<DesktopCliCommand.ControlSubmit>(incoming).request
                seen += request
                when (request.command.operation) {
                    ControlOperationId.STATUS -> { time += 100; reply(request) }
                    ControlOperationId.LOCATIONS_DELETE -> {
                        assertEquals(original.request.copy(asynchronous = true), request)
                        descriptor = DesktopControlEndpoint(9876, "replacement", "other-token")
                        time += 100
                        reply(request, ControlCode.ACCEPTED, final = false, id = operation)
                    }
                    ControlOperationId.OPERATIONS_STATUS -> {
                        assertEquals("owner", request.controllerId)
                        assertEquals(mapOf("id" to ControlValue.Text(operation)), request.command.arguments)
                        reply(request, id = operation, data = mapOf("committed" to ControlValue.BooleanValue(true)))
                    }
                    else -> error("Unexpected operation")
                }
            })
        val completed = result(client.execute(original))
        assertEquals(ControlCode.OK, completed.code)
        assertEquals("original", completed.requestId)
        assertEquals(operation, completed.operationId)
        assertEquals(ControlValue.BooleanValue(true), completed.data["committed"])
        assertEquals(1, reads)
        assertEquals(listOf(1000L, 900L, 700L), allowances)
        assertEquals(1, seen.count { it.command.operation == ControlOperationId.LOCATIONS_DELETE })
    }

    @Test fun exhaustedHandshakeBudgetNeverDispatchesMutation() {
        var time = 0L
        var calls = 0
        val client = DesktopSynchronousOperationClient(endpoint = { captured }, clockMillis = { time },
            exchange = { incoming, _, _ ->
                calls++
                val request = assertIs<DesktopCliCommand.ControlSubmit>(incoming).request
                assertEquals(ControlOperationId.STATUS, request.command.operation)
                time = 1000
                reply(request)
            })
        val timed = result(client.execute(command()))
        assertEquals(ControlCode.TIMEOUT, timed.code)
        assertFalse(timed.final)
        assertEquals("owner", timed.controllerId)
        assertNull(timed.operationId)
        assertEquals(1, calls)
    }

    @Test fun lostAdmissionResponseIsNeverReplayedOrGivenAnInventedOperation() {
        var calls = 0
        val client = DesktopSynchronousOperationClient(endpoint = { captured }, exchange = { incoming, _, _ ->
            val request = assertIs<DesktopCliCommand.ControlSubmit>(incoming).request
            if (++calls == 1) reply(request) else DesktopCliResponse.failure("TIMEOUT", 2)
        })
        val timed = result(client.execute(command()))
        assertEquals(ControlCode.TIMEOUT, timed.code)
        assertFalse(timed.final)
        assertEquals("owner", timed.controllerId)
        assertEquals("original", timed.requestId)
        assertNull(timed.operationId)
        assertEquals(2, calls)
    }

    @Test fun lostObservationRetainsAcceptedIdentityWithoutCancellation() {
        for (failure in listOf(DesktopCliResponse.notRunning(), DesktopCliResponse.failure("TIMEOUT", 2),
            DesktopCliResponse.failure("PERMISSION_DENIED"), DesktopCliResponse.failure("OUTCOME_UNKNOWN", 2))) {
            var calls = 0
            val client = DesktopSynchronousOperationClient(endpoint = { captured }, pause = {}, exchange = { incoming, _, _ ->
                val request = assertIs<DesktopCliCommand.ControlSubmit>(incoming).request
                when (++calls) {
                    1 -> reply(request)
                    2 -> reply(request, ControlCode.ACCEPTED, final = false, id = operation)
                    else -> { assertEquals(ControlOperationId.OPERATIONS_STATUS, request.command.operation); failure }
                }
            })
            val observed = result(client.execute(command()))
            assertFalse(observed.ok)
            assertFalse(observed.final, "Observation failure is not operation completion")
            assertEquals("owner", observed.controllerId)
            assertEquals("original", observed.requestId)
            assertEquals(operation, observed.operationId)
            assertEquals(7L, observed.configurationRevision)
            assertTrue(observed.restartRequired)
            assertTrue(observed.data.isEmpty())
            assertEquals(3, calls)
        }
    }

    @Test fun foreignOrMalformedObservationCannotReplaceAcceptedResult() {
        for (fault in listOf("owner", "request", "operation", "missing-operation")) {
            var calls = 0
            val client = DesktopSynchronousOperationClient(endpoint = { captured }, pause = {}, exchange = { incoming, _, _ ->
                val request = assertIs<DesktopCliCommand.ControlSubmit>(incoming).request
                when (++calls) {
                    1 -> reply(request)
                    2 -> reply(request, ControlCode.ACCEPTED, final = false, id = operation)
                    else -> reply(if (fault == "request") request.copy(requestId = "foreign") else request,
                        controller = if (fault == "owner") "replacement" else "owner",
                        id = when (fault) { "operation" -> "other"; "missing-operation" -> null; else -> operation })
                }
            })
            val rejected = result(client.execute(command()))
            assertFalse(rejected.ok)
            assertFalse(rejected.final)
            assertEquals("owner", rejected.controllerId)
            assertEquals(operation, rejected.operationId)
            assertEquals(3, calls)
        }
    }

    @Test fun unboundedWaitReturnsPendingNativeUncertaintyWithoutPollingAgain() {
        var time = 0L
        var calls = 0
        val client = DesktopSynchronousOperationClient(endpoint = { captured }, clockMillis = { time },
            pause = { time += 1_000_000 }, exchange = { incoming, _, allowance ->
                assertEquals(0L, allowance)
                val request = assertIs<DesktopCliCommand.ControlSubmit>(incoming).request
                when (++calls) {
                    1 -> reply(request)
                    2 -> reply(request, ControlCode.ACCEPTED, final = false, id = operation)
                    else -> reply(request, ControlCode.OUTCOME_UNKNOWN, final = false, id = operation,
                        data = mapOf("runtimeOutcome" to ControlValue.Text("unknown")))
                }
            })
        val pending = result(client.execute(command(0)))
        assertEquals(ControlCode.OUTCOME_UNKNOWN, pending.code)
        assertFalse(pending.final)
        assertEquals(operation, pending.operationId)
        assertEquals(ControlValue.Text("unknown"), pending.data["runtimeOutcome"])
        assertEquals(3, calls)
    }

    @Test fun authoritativeTerminalResultSurvivesElapsedBudgetAndKeepsFailureDetails() {
        for (code in listOf(ControlCode.OK, ControlCode.PERSISTENCE_FAILED, ControlCode.CANCELLED,
            ControlCode.UNAVAILABLE, ControlCode.INCOMPATIBLE_PROTOCOL)) {
            var time = 0L
            var calls = 0
            val client = DesktopSynchronousOperationClient(endpoint = { captured }, clockMillis = { time },
                exchange = { incoming, _, _ ->
                    val request = assertIs<DesktopCliCommand.ControlSubmit>(incoming).request
                    if (++calls == 1) reply(request) else {
                        time = 5000
                        reply(request, code, id = operation, data = mapOf("committed" to ControlValue.BooleanValue(code == ControlCode.OK)))
                    }
                })
            val terminal = result(client.execute(command()))
            assertEquals(code, terminal.code)
            assertTrue(terminal.final)
            assertEquals(operation, terminal.operationId)
            assertEquals(ControlValue.BooleanValue(code == ControlCode.OK), terminal.data["committed"])
            assertEquals(2, calls)
        }
    }

    @Test fun explicitAsyncAndInstallRetainTheirExistingAdapters() {
        assertFalse(DesktopSynchronousOperationClient.supports(command().copy(request = command().request.copy(asynchronous = true))))
        assertFalse(DesktopSynchronousOperationClient.supports(DesktopCliCommand.ControlSubmit(ControlRequest("install",
            ControlCommand(ControlOperationId.UPDATES_INSTALL)))))
        assertFalse(DesktopSynchronousOperationClient.supports(DesktopCliCommand.ControlSubmit(ControlRequest("read",
            ControlCommand(ControlOperationId.STATUS)))))
        assertTrue(DesktopSynchronousOperationClient.supports(command()))
    }

    @Test fun malformedNonterminalSuccessCannotEstablishAnOperation() {
        var calls = 0
        val client = DesktopSynchronousOperationClient(endpoint = { captured }, exchange = { incoming, _, _ ->
            val request = assertIs<DesktopCliCommand.ControlSubmit>(incoming).request
            if (++calls == 1) reply(request) else reply(request, ControlCode.OK, final = false, id = operation)
        })
        val rejected = result(client.execute(command()))
        assertEquals(ControlCode.INCOMPATIBLE_PROTOCOL, rejected.code)
        assertFalse(rejected.final)
        assertNull(rejected.operationId, "Invalid acceptance must not establish an operation")
        assertEquals(2, calls)
    }

    @Test fun observationModeDoesNotChangeRetainedCommandFingerprint() = runBlocking {
        val scope = CoroutineScope(Dispatchers.Default + SupervisorJob())
        val effects = AtomicInteger()
        val runner = DesktopOperationRunner(scope, "owner", metadataProvider = { DesktopControlMetadata(7, true) })
        val original = ControlRequest("delete", ControlCommand(ControlOperationId.LOCATIONS_DELETE,
            mapOf("id" to ControlValue.Text("location"))), controllerId = "owner", ifRevision = 7)
        suspend fun submit(request: ControlRequest, timeout: Long) = runner.execute(
            request.command.operation, DesktopCliCommand.ControlSubmit(request, timeout),
            requestId = request.requestId, asynchronous = request.asynchronous,
            expectedControllerId = request.controllerId, expectedRevision = request.ifRevision,
            resultEnvelope = true,
        ) { effects.incrementAndGet(); DesktopCliResponse.success("OK") }
        try {
            val accepted = ControlDocumentCodec.decodeResult(submit(original.copy(asynchronous = true), 1).message)
            val operation = assertNotNull(accepted.operationId)
            assertEquals(ControlCode.OK, runner.inspectResult(operation, "wait", wait = true)?.code)
            val retried = submit(original, 0)
            assertEquals(0, retried.exitCode, retried.message)
            assertEquals(operation, ControlDocumentCodec.decodeResult(retried.message).operationId)
            assertEquals(1, effects.get())
            for (different in listOf(original.copy(ifRevision = 8), original.copy(interactive = true),
                original.copy(command = original.command.copy(arguments = mapOf("id" to ControlValue.Text("other")))))) {
                assertEquals("CONFLICT", submit(different, 20).message)
            }
            assertEquals(1, effects.get())
        } finally { scope.cancel() }
    }

    @Test fun publicHumanAndJsonTimeoutsRetainAcceptedIdentityAndOwnerWork() = runBlocking {
        val directory = Files.createTempDirectory("vpn-cli-sync-timeout")
        val previous = DesktopWorkspacePaths.overrideDirectory()
        var release = CompletableDeferred<Unit>()
        val completed = AtomicInteger()
        val service = DesktopAppServiceFactory.createForTesting(DesktopStateStore(directory),
            locationBenchmarker = { profile, _, _, _ ->
                release.await()
                completed.incrementAndGet()
                Result.success(ProfileBenchmark(profile, "ok", "ok", 1.0, 2.0, 2.0, "test=ok"))
            })
        service.setSourceMode(ProfileSourceMode.CURRENT_LOCATIONS).getOrThrow()
        service.saveLocation("socks://127.0.0.1:1080#Slow").getOrThrow()
        val owner = DesktopControllerOwner(service)
        val server = assertNotNull(DesktopActivationServer.start(
            onShowWindow = { DesktopActivationShowResult.HEADLESS },
            onCliCommand = { runBlocking { owner.execute(it) } },
            portFile = directory.resolve("activation.port"), controllerId = owner.controllerId,
        ))
        DesktopWorkspacePaths.configure(DesktopWorkspaceInvocation(emptyList(), directory))
        try {
            for (json in listOf(true, false)) {
                release = CompletableDeferred()
                val output = mutableListOf<String>()
                val errors = mutableListOf<String>()
                val before = completed.get()
                val arguments = listOf("--timeout-seconds", "1", "locations", "benchmark", "Slow") +
                    if (json) listOf("--json") else emptyList()
                assertEquals(2, DesktopCli.handleArgs(arguments.toTypedArray(), output::add,
                    printProgress = errors::add, startHeadlessController = { error("Existing owner") }))
                val operation = owner.session.operationSnapshot().single { !it.phase.terminal }
                assertEquals(before, completed.get(), "Waiting timeout must leave owner work running")
                if (json) {
                    val timed = ControlDocumentCodec.decodeResult(output.single())
                    assertEquals(ControlCode.TIMEOUT, timed.code)
                    assertFalse(timed.final)
                    assertEquals(owner.controllerId, timed.controllerId)
                    assertEquals(operation.id, timed.operationId)
                    assertEquals(operation.requestId, timed.requestId)
                    assertTrue(errors.isEmpty())
                } else {
                    assertTrue(output.isEmpty(), "Human progress belongs on stderr")
                    assertTrue(errors.single().contains("TIMEOUT"))
                    assertTrue(errors.single().contains(operation.id), "Human timeout must retain operation identity")
                }
                release.complete(Unit)
                val terminal = owner.submit(ControlRequest("wait-${operation.id}",
                    ControlCommand(ControlOperationId.OPERATIONS_WAIT, mapOf("id" to ControlValue.Text(operation.id))),
                    controllerId = owner.controllerId))
                assertEquals(ControlCode.OK, terminal.code)
                assertEquals(operation.id, terminal.operationId)
                assertEquals(ControlValue.DecimalValue(2.0), terminal.data["secondaryTotalMs"])
                assertEquals(before + 1, completed.get())
            }
        } finally {
            release.complete(Unit)
            DesktopWorkspacePaths.configure(DesktopWorkspaceInvocation(emptyList(), previous))
            server.close()
            owner.close()
            directory.toFile().deleteRecursively()
        }
    }
}
