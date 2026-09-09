package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.ControlDocumentCodec
import com.kardinal.vpncontrol.model.ControlCode
import com.kardinal.vpncontrol.model.ControlOperationId
import com.kardinal.vpncontrol.model.ControlOperationPhase
import kotlinx.coroutines.*
import kotlin.test.*

class DesktopOperationProgressTest {
    @Test fun returnedUncertainResponseCannotSealOrReleaseTheOriginalInputs() = runBlocking {
        for (code in listOf(ControlCode.OUTCOME_UNKNOWN, ControlCode.TIMEOUT, ControlCode.UNAVAILABLE, ControlCode.INCOMPATIBLE_PROTOCOL)) {
            val owner = CoroutineScope(SupervisorJob() + Dispatchers.Default)
            val runner = DesktopOperationRunner(owner, "owner")
            var releases = 0
            try {
                runner.execute(ControlOperationId.ON, DesktopCliCommand.On, requestId = "request", resultEnvelope = true) {
                    currentCoroutineContext()[DesktopOperationProgress]!!.retainInputs(AutoCloseable { releases++ })
                    DesktopCliResponse.failure(code.wireName, code.exitCode)
                }
                val operation = runner.snapshot().single()
                val observed = assertNotNull(runner.inspectResult(operation.id, "inspect", false))
                assertFalse(observed.final, "Returned $code is not terminal native evidence")
                assertEquals(code, observed.code)
                assertTrue(runner.hasRetainedRuntimeInputs(operation.id))
                assertEquals(0, releases)
            } finally { owner.cancel() }
        }
    }

    @Test fun publicAuthenticatedCliKeepsUnknownOutcomeAndWaitTimeoutNonterminal() = runBlocking {
        val directory = java.nio.file.Files.createTempDirectory("vpn-operation-progress-cli-")
        val owner = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        val finish = CompletableDeferred<Unit>()
        var effects = 0
        val session = DesktopHeadlessSession(owner, { com.kardinal.vpncontrol.MainUiState() }, executeCommand = {
            check(it == DesktopCliCommand.On)
            effects++
            desktopControlReportPendingOutcome()
            finish.await()
            desktopControlConfirmOutcome()
            DesktopCliResponse.success("OK")
        }, refresh = {})
        val endpoint = directory.resolve("activation.port")
        val server = assertNotNull(DesktopActivationServer.start(
            onShowWindow = { DesktopActivationShowResult.HEADLESS },
            onCliCommand = { runBlocking { session.execute(it) } }, portFile = endpoint, controllerId = session.controllerId))
        try {
            fun invoke(vararg args: String): Pair<Int?, com.kardinal.vpncontrol.model.ControlResult> {
                val output = mutableListOf<String>()
                val code = DesktopCli.handleArgs(arrayOf("--json", *args), output::add,
                    requestCommand = { DesktopActivationServer.requestCliCommand(it, endpoint) },
                    startHeadlessController = { error("Never replace this owner") })
                return code to ControlDocumentCodec.decodeResult(output.single())
            }
            val initial = withContext(Dispatchers.IO) { invoke("on", "--timeout-seconds", "5") }
            assertEquals(2, initial.first)
            assertEquals(ControlCode.OUTCOME_UNKNOWN, initial.second.code)
            assertFalse(initial.second.final)
            val id = assertNotNull(initial.second.operationId)
            val status = invoke("operations", "status", id)
            assertEquals(2, status.first)
            assertEquals(ControlCode.OUTCOME_UNKNOWN, status.second.code)
            assertEquals(session.controllerId, status.second.controllerId)
            val timeout = withContext(Dispatchers.IO) { invoke("operations", "wait", id, "--timeout-seconds", "1") }
            assertEquals(2, timeout.first)
            assertEquals(ControlCode.TIMEOUT, timeout.second.code)
            assertFalse(timeout.second.final)
            assertEquals(id, timeout.second.operationId)
            assertEquals(1, effects)
            finish.complete(Unit)
            val terminal = withContext(Dispatchers.IO) { invoke("operations", "wait", id, "--timeout-seconds", "5") }
            assertEquals(0, terminal.first)
            assertEquals(ControlCode.OK, terminal.second.code)
            assertTrue(terminal.second.final)
            assertEquals(id, terminal.second.operationId)
        } finally {
            finish.complete(Unit); server.close(); session.close(); owner.cancel()
            directory.toFile().deleteRecursively()
        }
    }

    @Test fun uncertaintyReturnsIdentityAndKeepsTheOriginalActionUntilAuthoritativeCompletion() = runBlocking {
        val owner = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        val runner = DesktopOperationRunner(owner, "owner")
        val reported = CompletableDeferred<Unit>()
        val finish = CompletableDeferred<Unit>()
        var effects = 0
        val releases = java.util.concurrent.atomic.AtomicInteger()
        try {
            val original = async {
                runner.execute(ControlOperationId.ON, DesktopCliCommand.On, requestId = "request",
                    expectedControllerId = "owner", resultEnvelope = true) {
                    effects++
                    currentCoroutineContext()[DesktopOperationProgress]!!.retainInputs(AutoCloseable { releases.incrementAndGet() })
                    desktopControlReportPendingOutcome()
                    reported.complete(Unit)
                    finish.await()
                    desktopControlConfirmOutcome()
                    DesktopCliResponse.success("private native detail must not escape")
                }
            }
            withTimeout(5_000) { reported.await() }
            val operation = runner.snapshot().single()
            val pending = assertNotNull(runner.inspectResult(operation.id, "inspect", false))
            assertEquals(ControlCode.OUTCOME_UNKNOWN, pending.code)
            assertFalse(pending.final)
            val initial = ControlDocumentCodec.decodeResult(withTimeout(5_000) { original.await() }.message)
            assertEquals(operation.id, initial.operationId)
            assertEquals("request", initial.requestId)
            assertEquals(2, initial.exitCode)
            val repeated = runner.execute(ControlOperationId.ON, DesktopCliCommand.On, requestId = "request",
                expectedControllerId = "owner", asynchronous = true, resultEnvelope = true) { error("Repeated native effect") }
            assertEquals(operation.id, ControlDocumentCodec.decodeResult(repeated.message).operationId)
            assertEquals(1, effects)
            assertEquals(0, releases.get(), "Unknown native work still owns its captured inputs")
            assertTrue(runner.hasRetainedRuntimeInputs(operation.id))
            val refused = runner.execute(ControlOperationId.ON, DesktopCliCommand.On, requestId = "other",
                asynchronous = true) { error("Uncertain native operation must retain mutation admission") }
            assertEquals("BUSY", refused.message)
            finish.complete(Unit)
            val terminal = assertNotNull(withTimeout(5_000) { runner.inspectResult(operation.id, "wait", true) })
            assertEquals(ControlCode.OK, terminal.code)
            assertTrue(terminal.final)
            assertEquals(1, releases.get(), "The exact operation must release inputs after native confirmation and terminal completion")
            assertFalse(runner.hasRetainedRuntimeInputs(operation.id))
            assertEquals(operation.id, terminal.operationId)
            assertFalse(ControlDocumentCodec.encodeResult(terminal).contains("private native"))
        } finally { finish.complete(Unit); owner.cancel() }
    }

    @Test fun cancellationWaitsForNativeConfirmationWithoutLosingThePendingIdentity() = runBlocking {
        val owner = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        val runner = DesktopOperationRunner(owner, "owner")
        val reported = CompletableDeferred<Unit>()
        val cancellationObserved = CompletableDeferred<Unit>()
        val nativeStopped = CompletableDeferred<Unit>()
        try {
            val accepted = runner.execute(ControlOperationId.UPDATES_CHECK, DesktopCliCommand.UpdatesCheck,
                requestId = "request", asynchronous = true, resultEnvelope = true) {
                desktopControlReportPendingOutcome()
                reported.complete(Unit)
                try { awaitCancellation() } catch (cancelled: CancellationException) {
                    withContext(NonCancellable) {
                        cancellationObserved.complete(Unit)
                        nativeStopped.await()
                        desktopControlConfirmOutcome()
                    }
                    throw cancelled
                }
            }
            val id = assertNotNull(ControlDocumentCodec.decodeResult(accepted.message).operationId)
            withTimeout(5_000) { reported.await() }
            assertTrue(runner.cancelResponse(id).success)
            withTimeout(5_000) { cancellationObserved.await() }
            val pending = assertNotNull(runner.inspectResult(id, "inspect", false))
            assertEquals(ControlCode.OUTCOME_UNKNOWN, pending.code)
            assertFalse(pending.final)
            assertEquals(ControlOperationPhase.CANCELLING, runner.snapshot().single().phase)
            nativeStopped.complete(Unit)
            val terminal = assertNotNull(withTimeout(5_000) { runner.inspectResult(id, "wait", true) })
            assertEquals(ControlCode.CANCELLED, terminal.code)
            assertEquals(130, terminal.exitCode)
            assertTrue(terminal.final)
        } finally { nativeStopped.complete(Unit); owner.cancel() }
    }

    @Test fun unconfirmedActionFailureDoesNotEraseAnUncertainNativeOutcome() = runBlocking {
        val owner = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        val runner = DesktopOperationRunner(owner, "owner")
        var releases = 0
        try {
            runner.execute(ControlOperationId.ON, DesktopCliCommand.On, requestId = "request", resultEnvelope = true) {
                currentCoroutineContext()[DesktopOperationProgress]!!.retainInputs(AutoCloseable { releases++ })
                desktopControlReportPendingOutcome()
                error("Unexpected observer failure")
            }
            val operation = runner.snapshot().single()
            val result = assertNotNull(runner.inspectResult(operation.id, "inspect", false))
            assertEquals(ControlCode.OUTCOME_UNKNOWN, result.code)
            assertFalse(result.final)
            assertTrue(runner.hasRetainedRuntimeInputs(operation.id))
            assertEquals(0, releases)
        } finally { owner.cancel() }
    }

    @Test fun cleanupFailurePreservesCommittedSuccessAndRetriesOnlyTerminalInputs() = runBlocking {
        val owner = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        val runner = DesktopOperationRunner(owner, "owner")
        val releases = java.util.concurrent.atomic.AtomicInteger()
        var effects = 0
        try {
            runner.execute(ControlOperationId.ON, DesktopCliCommand.On, requestId = "first") {
                effects++
                currentCoroutineContext()[DesktopOperationProgress]!!.retainInputs(AutoCloseable {
                    if (releases.incrementAndGet() == 1) throw java.io.IOException("private cleanup error")
                })
                DesktopCliResponse.success("OK")
            }
            val first = runner.snapshot().single()
            assertEquals(ControlCode.OK, first.result?.code)
            assertTrue(runner.hasRetainedRuntimeInputs(first.id))
            runner.execute(ControlOperationId.OFF, DesktopCliCommand.Off, requestId = "second") {
                effects++
                DesktopCliResponse.success("OK")
            }
            assertEquals(2, releases.get())
            assertEquals(2, effects)
            assertFalse(runner.hasRetainedRuntimeInputs(first.id))
            assertEquals(ControlCode.OK, runner.snapshot().single { it.id == first.id }.result?.code)
        } finally { owner.cancel() }
    }
}
