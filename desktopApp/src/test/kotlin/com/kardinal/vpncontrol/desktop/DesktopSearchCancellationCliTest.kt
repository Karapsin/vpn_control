package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.control.ControlDocumentCodec
import com.kardinal.vpncontrol.model.*
import java.nio.file.Files
import kotlinx.coroutines.*
import kotlin.test.*

/** Public cancellation must reach the real search cleanup, not merely change ledger flags. */
class DesktopSearchCancellationCliTest {
    @Test fun benchmarkCancellationReleasesProbeWithoutChangingSelection() = runBlocking {
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        val probing = CompletableDeferred<Unit>()
        val cleaned = CompletableDeferred<Unit>()
        val raw = "socks://127.0.0.1:1080#Pending-B"
        val location = DesktopLocationRecord(0, "", raw, "Pending B", "127.0.0.1", "SOCKS", "Imported", true)
        var state = MainUiState(selectedProfileRawLink = raw, isVpnRunning = true)
        val service = DesktopLocationBenchmarkService({ state }, { listOf(location) },
            benchmarkLocation = { _, _, _, _ ->
                probing.complete(Unit)
                try { awaitCancellation() } finally { cleaned.complete(Unit) }
            }, commitState = { _, _ -> error("Cancelled measurements must not commit") },
            updateState = { state = it(state) })
        val session = DesktopHeadlessSession(scope, { state }, executeCommand = {
            check(it is DesktopCliCommand.LocationBenchmark)
            service.benchmark(0).fold({ DesktopCliResponse.success("") }, { it.toConnectionFailureResponse() })
        }, refresh = {})
        try {
            fun invoke(vararg arguments: String): ControlResult {
                val output = mutableListOf<String>()
                DesktopCli.handleArgs(arrayOf("--json", *arguments), printLine = output::add,
                    requestCommand = {
                        val submit = assertIs<DesktopCliCommand.ControlSubmit>(it)
                        runBlocking { session.execute(submit.copy(request = submit.request.copy(controllerId = session.controllerId))) }
                    }, startHeadlessController = { error("Must reuse owner") })
                return ControlDocumentCodec.decodeResult(output.single())
            }
            val accepted = invoke("--async", "locations", "benchmark", "1")
            val id = assertNotNull(accepted.operationId)
            withTimeout(5_000) { probing.await() }
            assertEquals(ControlCode.OK, invoke("operations", "cancel", id).code)
            withTimeout(5_000) { cleaned.await() }
            val result = invoke("operations", "wait", id, "--timeout-seconds", "2")
            assertEquals(ControlCode.CANCELLED, result.code)
            assertTrue(result.final)
            assertEquals(raw, state.selectedProfileRawLink)
            assertTrue(state.isVpnRunning)
            assertFalse(state.isBusy)
        } finally {
            session.close()
            scope.cancel()
        }
    }

    @Test fun findBestCancellationWaitsForActualRuntimeRecovery() = runBlocking {
        for (recoveryFailure in listOf(null, "ROLLBACK_FAILED", "OUTCOME_UNKNOWN")) {
            val directory = Files.createTempDirectory("vpn-search-cancel")
            val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
            val probing = CompletableDeferred<Unit>()
            val restoring = CompletableDeferred<Unit>()
            val allowRestore = CompletableDeferred<Unit>()
            val restored = CompletableDeferred<Unit>()
            val raw = "socks://127.0.0.1:1080#Pending-B"
            val location = DesktopLocationRecord(0, "", raw, "Pending B", "127.0.0.1", "SOCKS", "Imported", true)
            var state = MainUiState(profileSourceMode = ProfileSourceMode.SUBSCRIPTION,
                activeSubscriptionId = "sub", subscriptions = listOf(SubscriptionSource("sub", "https://example.com/sub")),
                selectedProfileRawLink = raw, selectedProfileName = "Pending B", isVpnRunning = true)
            var actual = "Actual A"
            var restoreCount = 0
            val service = DesktopFindBestService(
                stateProvider = { state }, visibleLocationsProvider = { listOf(location) }, locationsProvider = { listOf(location) },
                captureRuntimeRestore = {
                    val captured = actual
                    suspend {
                        restoreCount++
                        restoring.complete(Unit)
                        allowRestore.await()
                        if (recoveryFailure == null) actual = captured
                        restored.complete(Unit)
                        if (recoveryFailure == null) Result.success(Unit)
                        else Result.failure(IllegalStateException(recoveryFailure))
                    }
                },
                refreshSubscriptions = { _, _ -> actual = "Temporary refresh runtime"; Result.success(1) },
                startConnection = { _, _, _ -> error("Cancellation must not start pending B") },
                verifyCandidate = { _, _, _, _ -> error("Probe has not completed") },
                commitState = { _, _ -> error("Cancelled probe must not commit") },
                updateState = { state = it(state) },
                evaluateProfiles = { _, _, _, _, _ -> probing.complete(Unit); awaitCancellation() },
            )
            val session = DesktopHeadlessSession(scope, { state }, executeCommand = {
                check(it == DesktopCliCommand.FindBest)
                service.findBestLocation().fold({ DesktopCliResponse.success("") }, { it.toConnectionFailureResponse() })
            }, refresh = {})
            val endpoint = directory.resolve("activation.port")
            val server = assertNotNull(DesktopActivationServer.start(
                onShowWindow = { DesktopActivationShowResult.HEADLESS },
                onCliCommand = { runBlocking { session.execute(it) } }, portFile = endpoint, controllerId = session.controllerId))
            try {
                fun invoke(vararg arguments: String): ControlResult {
                    val output = mutableListOf<String>()
                    val exit = DesktopCli.handleArgs(arrayOf("--json", *arguments), printLine = output::add,
                        requestCommand = { DesktopActivationServer.requestCliCommand(it, endpoint) },
                        startHeadlessController = { error("Must reuse owner") })
                    return ControlDocumentCodec.decodeResult(output.single()).also { assertEquals(it.exitCode, exit) }
                }
                val accepted = invoke("--async", "find-best")
                val id = assertNotNull(accepted.operationId)
                assertEquals(ControlCode.ACCEPTED, accepted.code)
                withTimeout(5_000) { probing.await() }
                val cancelled = invoke("operations", "cancel", id)
                assertEquals(ControlCode.OK, cancelled.code)
                withTimeout(5_000) { restoring.await() }
                val pending = invoke("operations", "status", id)
                assertFalse(pending.final, "Cancellation is not terminal while recovery is running")
                assertEquals(id, pending.operationId)
                assertEquals("Temporary refresh runtime", actual)
                allowRestore.complete(Unit)
                withTimeout(5_000) { restored.await() }
                val result = withTimeout(5_000) {
                    var result: ControlResult
                    do {
                        delay(10)
                        result = invoke("operations", "status", id)
                    } while (!result.final && result.code != ControlCode.OUTCOME_UNKNOWN)
                    result
                }
                assertEquals(when (recoveryFailure) {
                    null -> ControlCode.CANCELLED
                    "ROLLBACK_FAILED" -> ControlCode.RUNTIME_FAILED
                    else -> ControlCode.OUTCOME_UNKNOWN
                }, result.code)
                assertEquals(recoveryFailure != "OUTCOME_UNKNOWN", result.final)
                if (recoveryFailure == "ROLLBACK_FAILED") {
                    assertEquals(ControlValue.Text("ROLLBACK_FAILED"), result.data["recoveryCode"])
                }
                assertEquals(1, restoreCount)
                assertEquals(raw, state.selectedProfileRawLink)
                if (recoveryFailure == null) assertEquals("Actual A", actual)
                assertEquals(recoveryFailure == "OUTCOME_UNKNOWN", state.isBusy)
            } finally {
                allowRestore.complete(Unit)
                server.close()
                session.close()
                scope.cancel()
                directory.toFile().deleteRecursively()
            }
        }
    }
}
