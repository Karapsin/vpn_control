package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.model.ProfileSourceMode
import com.kardinal.vpncontrol.model.SubscriptionRefreshPolicy
import com.kardinal.vpncontrol.model.SubscriptionSource
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.launch
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

@OptIn(ExperimentalCoroutinesApi::class)
class DesktopHeadlessSessionTest {
    @Test
    fun typedResponsesKeepIdentityAndMetadataOnRejectionBusyAndCompletion() = runTest {
        val session = DesktopHeadlessSession(backgroundScope, { MainUiState() },
            executeCommand = { kotlinx.coroutines.awaitCancellation() }, refresh = {}, controllerId = "owner",
            metadataProvider = { DesktopControlMetadata(9, true) })
        val request = com.kardinal.vpncontrol.model.ControlRequest("request",
            com.kardinal.vpncontrol.model.ControlCommand(com.kardinal.vpncontrol.model.ControlOperationId.UPDATES_CHECK),
            controllerId = "owner", asynchronous = true)
        suspend fun submit(value: com.kardinal.vpncontrol.model.ControlRequest) =
            com.kardinal.vpncontrol.control.ControlProtocolCodec.decodeResult(
                session.execute(DesktopCliCommand.ControlSubmit(value)).message)
        val invalid = submit(request.copy(command = request.command.copy(arguments =
            mapOf("private-unknown" to com.kardinal.vpncontrol.model.ControlValue.Text("private-input")))))
        assertEquals(com.kardinal.vpncontrol.model.ControlCode.INVALID_ARGUMENT, invalid.code)
        assertEquals("request", invalid.requestId)
        assertEquals("owner", invalid.controllerId)
        assertEquals(9L, invalid.configurationRevision)
        assertEquals(true, invalid.restartRequired)
        assertEquals(null, invalid.operationId)
        assertEquals("INVALID_ARGUMENT", invalid.message)
        assertEquals(com.kardinal.vpncontrol.model.ControlCode.UNSUPPORTED, submit(request.copy(interactive = true)).code)
        assertTrue(session.operationSnapshot().isEmpty())
        val accepted = submit(request)
        runCurrent()
        val busy = submit(request.copy(requestId = "competing"))
        assertEquals(com.kardinal.vpncontrol.model.ControlCode.BUSY, busy.code)
        assertEquals("competing", busy.requestId)
        assertEquals(null, busy.operationId)
        session.execute(DesktopCliCommand.OperationCancel(requireNotNull(accepted.operationId)))
        runCurrent()
        val completed = submit(request.copy(asynchronous = false))
        assertEquals(com.kardinal.vpncontrol.model.ControlCode.CANCELLED, completed.code)
        assertEquals(true, completed.final)
        assertEquals(accepted.operationId, completed.operationId)
    }

    @Test
    fun actionReturningTransportFailureCannotCompleteAsWaiterTimeoutOrCancellation() = runTest {
        for (code in listOf(com.kardinal.vpncontrol.model.ControlCode.UNAVAILABLE,
            com.kardinal.vpncontrol.model.ControlCode.TIMEOUT)) {
            val runner = DesktopOperationRunner(backgroundScope)
            suspend fun submit() = runner.execute(com.kardinal.vpncontrol.model.ControlOperationId.UPDATES_CHECK,
                DesktopCliCommand.UpdatesCheck, requestId = "request", asynchronous = true) {
                DesktopCliResponse.failure(code.wireName, code.exitCode)
            }
            submit()
            runCurrent()
            val retained = submit()
            assertEquals(com.kardinal.vpncontrol.model.ControlCode.RUNTIME_FAILED,
                com.kardinal.vpncontrol.control.ControlProtocolCodec.decodeResult(retained.message).code)
            assertEquals(1, retained.exitCode)
            assertEquals(1, runner.waitResponse(runner.snapshot().single().id).exitCode)
        }
    }

    @Test
    fun asyncResultsCaptureOwnerRevisionAndRetainCompletionMetadata() = runTest {
        var metadata = DesktopControlMetadata(3, false)
        val runner = DesktopOperationRunner(backgroundScope, controllerId = "owner", metadataProvider = { metadata })
        val finish = CompletableDeferred<Unit>()
        suspend fun submit() = runner.execute(com.kardinal.vpncontrol.model.ControlOperationId.UPDATES_CHECK,
            DesktopCliCommand.UpdatesCheck, requestId = "request", asynchronous = true) {
            finish.await()
            DesktopCliResponse.success("done")
        }
        val accepted = com.kardinal.vpncontrol.control.ControlProtocolCodec.decodeResult(submit().message)
        assertEquals(3L, accepted.configurationRevision)
        assertEquals(false, accepted.restartRequired)
        assertEquals(false, accepted.final)
        runCurrent()
        metadata = DesktopControlMetadata(7, true)
        finish.complete(Unit)
        runCurrent()
        metadata = DesktopControlMetadata(9, false)
        val retained = com.kardinal.vpncontrol.control.ControlProtocolCodec.decodeResult(submit().message)
        assertEquals(7L, retained.configurationRevision)
        assertEquals(true, retained.restartRequired)
        assertEquals(true, retained.final)
        assertEquals(accepted.operationId, retained.operationId)
    }

    @Test
    fun asyncAdmissionDeduplicatesRequestIdentityAndRejectsChangedRequestsOrOwners() = runTest {
        val runner = DesktopOperationRunner(backgroundScope, controllerId = "owner-a")
        val finish = CompletableDeferred<Unit>()
        var effects = 0
        suspend fun submit(request: String = "request-a", command: DesktopCliCommand = DesktopCliCommand.UpdatesCheck,
            owner: String = "owner-a") = runner.execute(
            com.kardinal.vpncontrol.model.ControlOperationId.UPDATES_CHECK, command,
            requestId = request, asynchronous = true, expectedControllerId = owner,
        ) {
            finish.await()
            effects++
            DesktopCliResponse.success("private-result")
        }
        val accepted = submit()
        assertTrue(accepted.success)
        assertTrue(accepted.message.contains("ACCEPTED"))
        assertTrue(accepted.message.contains("\"final\":false"))
        assertEquals(0, effects)
        assertEquals(accepted, submit())
        assertEquals("CONFLICT", submit(command = DesktopCliCommand.LocationBenchmark("private-input")).message)
        assertEquals("CONFLICT", submit(owner = "replacement-owner").message)
        assertEquals("BUSY", submit(request = "request-b").message)
        assertEquals(1, runner.snapshot().size)
        runCurrent()
        finish.complete(Unit)
        runCurrent()
        assertEquals(1, effects)
        val retained = submit()
        assertTrue(retained.success)
        assertEquals(com.kardinal.vpncontrol.model.ControlCode.OK,
            com.kardinal.vpncontrol.control.ControlProtocolCodec.decodeResult(retained.message).code)
        kotlin.test.assertFalse(retained.message.contains("private"))
        assertEquals(1, effects)
        assertEquals(1, runner.snapshot().size)
    }

    @Test
    fun explicitCancellationDoesNotReportTerminalUntilCleanupFinishes() = runTest {
        val cleanup = CompletableDeferred<Unit>()
        val runner = DesktopOperationRunner(backgroundScope)
        val action = launch {
            val result = runner.execute(com.kardinal.vpncontrol.model.ControlOperationId.UPDATES_DOWNLOAD,
                DesktopCliCommand.UpdatesDownload) {
                try { kotlinx.coroutines.awaitCancellation() }
                finally { kotlinx.coroutines.withContext(kotlinx.coroutines.NonCancellable) { cleanup.await() } }
            }
            assertEquals(130, result.exitCode)
        }
        runCurrent()
        val id = runner.snapshot().single().id
        assertTrue(runner.snapshot().single().cancellable)
        assertTrue(runner.cancelResponse(id).success)
        runCurrent()
        assertEquals(com.kardinal.vpncontrol.model.ControlOperationPhase.CANCELLING, runner.snapshot().single().phase)
        assertTrue(action.isActive)
        cleanup.complete(Unit)
        runCurrent()
        assertEquals(130, runner.waitResponse(id).exitCode)
        assertTrue(runner.cancelResponse(id).success)
        assertEquals("NOT_FOUND", runner.cancelResponse("missing").message)
    }

    @Test
    fun operationWaitReturnsFailureOutcomeAndObserverCancellationDoesNotCancelWork() = runTest {
        val finish = CompletableDeferred<Unit>()
        val runner = DesktopOperationRunner(backgroundScope)
        val action = launch {
            runner.execute(com.kardinal.vpncontrol.model.ControlOperationId.UPDATES_CHECK, DesktopCliCommand.UpdatesCheck) {
                finish.await()
                DesktopCliResponse.failure("PERSISTENCE_FAILED")
            }
        }
        runCurrent()
        val id = runner.snapshot().single().id
        val observer = launch { runner.waitResponse(id) }
        runCurrent()
        assertTrue(observer.isActive)
        observer.cancel()
        observer.join()
        assertTrue(action.isActive)
        finish.complete(Unit)
        runCurrent()
        val result = runner.waitResponse(id)
        assertEquals(1, result.exitCode)
        kotlin.test.assertFalse(result.success)
        assertTrue(result.message.contains("PERSISTENCE_FAILED"))
        assertEquals("NOT_FOUND", runner.waitResponse("missing").message)
    }

    @Test
    fun cancelledOwnerCompletesQueuedActionWithoutHangingCaller() = runTest {
        val ownerJob = kotlinx.coroutines.SupervisorJob().apply { cancel() }
        val runner = DesktopOperationRunner(kotlinx.coroutines.CoroutineScope(coroutineContext + ownerJob))
        val result = runner.execute(com.kardinal.vpncontrol.model.ControlOperationId.UPDATES_CHECK,
            DesktopCliCommand.UpdatesCheck) { error("Cancelled owner must not execute effects") }
        assertEquals(130, result.exitCode)
        assertEquals(com.kardinal.vpncontrol.model.ControlOperationPhase.CANCELLED, runner.snapshot().single().phase)
    }

    @Test
    fun longCommandBelongsToOwnerAndSurvivesCancelledWaiter() = runTest {
        val started = CompletableDeferred<Unit>()
        val finish = CompletableDeferred<Unit>()
        var effects = 0
        val session = DesktopHeadlessSession(backgroundScope, { MainUiState() },
            executeCommand = {
                if (it is DesktopCliCommand.LocationBenchmark) {
                    started.complete(Unit)
                    finish.await()
                    effects++
                    DesktopCliResponse.success("private-result-text")
                } else DesktopCliResponse.success("read")
            }, refresh = {})
        val waiter = launch { session.execute(DesktopCliCommand.LocationBenchmark("secret-input")) }
        started.await()
        assertTrue(session.hasBackgroundWork())
        assertEquals(com.kardinal.vpncontrol.model.ControlOperationPhase.RUNNING, session.operationSnapshot().single().phase)
        assertEquals("CONFLICT", session.execute(DesktopCliCommand.OperationCancel(session.operationSnapshot().single().id)).message)
        waiter.cancel()
        waiter.join()
        assertTrue(session.execute(DesktopCliCommand.Status).success)
        assertEquals("BUSY", session.execute(DesktopCliCommand.UpdatesCheck).message)
        assertEquals(0, effects)
        finish.complete(Unit)
        runCurrent()
        assertEquals(1, effects)
        val completed = session.operationSnapshot().single()
        assertEquals(com.kardinal.vpncontrol.model.ControlOperationPhase.SUCCEEDED, completed.phase)
        assertEquals("OK", completed.result?.message)
        assertEquals(emptyMap(), completed.result?.data)
        session.close()
    }

    @Test
    fun observesSettingsWithoutGuiAndKeepsReadsResponsiveDuringRefresh() = runTest {
        var state = MainUiState(
            profileSourceMode = ProfileSourceMode.SUBSCRIPTION,
            subscriptions = listOf(SubscriptionSource(id = "test", url = "https://example.test/sub")),
            activeSubscriptionId = "test",
            subscriptionRefreshPolicy = SubscriptionRefreshPolicy.OFF,
        )
        var refreshes = 0
        val finishRefresh = CompletableDeferred<Unit>()
        val session = DesktopHeadlessSession(backgroundScope, { state },
            executeCommand = { DesktopCliResponse.success("readable") },
            refresh = { refreshes++; finishRefresh.await() },
            nowMillis = { testScheduler.currentTime })
        try {
            session.start()
            runCurrent()
            assertEquals(0, refreshes)
            kotlin.test.assertFalse(session.hasBackgroundWork())
            state = state.copy(subscriptionRefreshPolicy = SubscriptionRefreshPolicy.EVERY_HOUR)
            advanceTimeBy(1_000)
            runCurrent()
            assertEquals(1, refreshes)
            assertTrue(session.hasBackgroundWork())
            assertTrue(session.execute(DesktopCliCommand.Status).success)
            assertEquals("BUSY", session.execute(DesktopCliCommand.Off).message)
            finishRefresh.complete(Unit)
            runCurrent()
            assertTrue(session.execute(DesktopCliCommand.Off).success)
            session.close()
            advanceTimeBy(2 * 60 * 60 * 1_000L)
            runCurrent()
            assertEquals(1, refreshes)
        } finally { session.close() }
    }
}
