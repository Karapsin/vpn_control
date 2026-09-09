package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.DnsSettings
import com.kardinal.vpncontrol.model.ConnectionStatusMessages
import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.ProxyProfile
import com.kardinal.vpncontrol.model.RoutingRules
import java.nio.file.Paths
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest

class DesktopConnectionLifecycleServiceTest {
    @Test fun unknownRestoreKeepsItsCodeAndExactInputsUntilNativeConfirmation() = runTest {
        val runtime = FakeDesktopRuntimeController()
        val service = DesktopConnectionLifecycleService(runtime)
        var state = MainUiState(appMode = AppMode.PROXY_ONLY)
        val location = desktopLifecycleLocation(0)
        service.startConnection(state, listOf(location), location, null, { state }, {},
            { _, next -> state = next; Result.success(Unit) }, { state = it(state) }).getOrThrow()
        var confirmed = false
        var closes = 0
        var restores = 0
        runtime.restoreLease = object : DesktopRuntimeRestoreLease {
            override suspend fun restore(): Result<DesktopRuntimeSession> {
                restores++
                return if (confirmed) runtime.startResult.also { runtime.running = true }
                else Result.failure(IllegalStateException("OUTCOME_UNKNOWN"))
            }
            override fun close() { closes++ }
        }
        val restore = service.captureRuntimeRestore()
        runtime.running = false
        val progress = DesktopOperationProgress {}
        kotlinx.coroutines.withContext(progress) {
            retainDesktopRuntimeInputs(restore as AutoCloseable)
            assertEquals("OUTCOME_UNKNOWN", restore().exceptionOrNull()?.message)
            releaseDesktopRuntimeRestore(restore)
            assertTrue(progress.hasPendingOutcome)
            assertTrue(progress.hasRetainedInputs)
            assertEquals(0, closes)
            assertEquals(1, restores)
            confirmed = true // The fixture now establishes the original native outcome.
            desktopControlConfirmOutcome()
            restore().getOrThrow()
            releaseDesktopRuntimeRestore(restore)
            assertEquals(1, closes)
            assertFalse(progress.hasRetainedInputs)
        }
    }

    @Test fun uncertainCandidateKeepsPreviousLeaseOwnedWithoutRollbackOrRelease() = runTest {
        val runtime = FakeDesktopRuntimeController()
        val service = DesktopConnectionLifecycleService(runtime)
        var state = MainUiState(appMode = AppMode.PROXY_ONLY)
        val location = desktopLifecycleLocation(0)
        service.startConnection(state, listOf(location), location, null, { state }, {},
            { _, next -> state = next; Result.success(Unit) }, { state = it(state) }).getOrThrow()
        var closes = 0
        runtime.restoreLease = object : DesktopRuntimeRestoreLease {
            override suspend fun restore(): Result<DesktopRuntimeSession> = error("Unknown work cannot be rolled back")
            override fun close() { closes++ }
        }
        runtime.startResult = Result.failure(IllegalStateException("OUTCOME_UNKNOWN"))
        val progress = DesktopOperationProgress {}
        kotlinx.coroutines.withContext(progress) {
            val result = service.startConnection(state, listOf(location), location, null, { state }, {},
                { _, next -> state = next; Result.success(Unit) }, { state = it(state) })
            assertEquals("OUTCOME_UNKNOWN", result.exceptionOrNull()?.message)
            assertEquals(0, closes)
            assertTrue(progress.hasPendingOutcome)
            assertTrue(progress.hasRetainedInputs)
            desktopControlConfirmOutcome()
            progress.releaseAllTerminal().getOrThrow()
            assertEquals(1, closes)
            assertEquals(2, runtime.startedProfiles.size)
        }
    }

    @Test fun capturedDisconnectedRestoreStopsLaterCandidateInsteadOfFailingOrApplyingSelection() = runTest {
        val runtime = FakeDesktopRuntimeController()
        val service = DesktopConnectionLifecycleService(runtime)
        val restore = service.captureRuntimeRestore()
        var state = MainUiState(appMode = AppMode.PROXY_ONLY)
        val location = desktopLifecycleLocation(0)
        assertTrue(service.startConnection(state, listOf(location), location, null, { state }, {},
            commitState = { _, next -> state = next; Result.success(Unit) },
            updateState = { state = it(state) }).isSuccess)
        assertTrue(restore().isSuccess)
        assertFalse(runtime.running)
        kotlin.test.assertNull(service.activeConnection)
        assertTrue(restore().isSuccess)
        assertEquals(1, runtime.startedProfiles.size)
    }

    @Test fun uncapturedRunningIdentityIsNotTreatedAsAnOriginallyDisconnectedRuntime() = runTest {
        val runtime = FakeDesktopRuntimeController(running = true, mode = AppMode.PROXY_ONLY)
        val service = DesktopConnectionLifecycleService(runtime)
        assertEquals("ROLLBACK_FAILED", service.captureRuntimeRestore()().exceptionOrNull()?.message)
        assertTrue(runtime.running)
    }

    @Test fun confirmedNativeStopWithResourceFailureClearsActiveIdentityAndPreservesFailure() = runTest {
        for (appExit in listOf(false, true)) {
            val failure = DesktopRuntimeResourcePublicationFailure(listOf(DesktopRuntimeResourceWarning(
                com.kardinal.vpncontrol.model.ControlCode.PERSISTENCE_FAILED,
                "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", DesktopRuntimeResourceDisposition.PENDING_PUBLICATION)))
            val runtime = FakeDesktopRuntimeController(stopResult = Result.failure(failure))
            val service = DesktopConnectionLifecycleService(runtime) { 900L }
            var state = MainUiState(appMode = AppMode.PROXY_ONLY)
            var resume = false
            val locations = listOf(desktopLifecycleLocation(0))
            val commit: (List<DesktopLocationRecord>, MainUiState) -> Result<Unit> = { _, next ->
                state = next; Result.success(Unit)
            }
            assertTrue(service.startConnection(state, locations, locations.single(), null, { state }, { resume = it },
                commitState = commit, updateState = { state = it(state) }).isSuccess)
            val result = if (appExit) service.stopRuntimeForAppExit(state, locations, { state }, { resume = it },
                commitState = commit, updateState = { state = it(state) })
            else service.stopConnection(state, locations, null, { state }, { resume = it },
                commitState = commit, updateState = { state = it(state) })
            kotlin.test.assertSame(failure, result.exceptionOrNull())
            assertFalse(runtime.running)
            assertFalse(state.isVpnRunning, "A stopped native process must not remain active in the GUI")
            kotlin.test.assertNull(service.activeConnection)
            assertFalse(state.isBusy)
            assertEquals(900L, state.sessionStoppedAtEpochMillis)
            assertEquals(appExit, resume)
        }
    }

    @Test fun rejectedPreparationPreservesActiveRuntimeTelemetryAndPendingSettings() = runTest {
        val runtime = FakeDesktopRuntimeController()
        val service = DesktopConnectionLifecycleService(runtime)
        var state = MainUiState(appMode = AppMode.PROXY_ONLY)
        var resume = false
        val first = desktopLifecycleLocation(0)
        val second = first.copy(index = 1, rawLink = "socks://127.0.0.2:1080#Pending", name = "Pending")
        suspend fun start(location: DesktopLocationRecord) = service.startConnection(state, listOf(first, second),
            location, null, { state }, { resume = it },
            commitState = { _, next -> state = next; Result.success(Unit) }, updateState = { state = it(state) })
        assertTrue(start(first).isSuccess)
        val active = service.activeConnection
        val startedAt = state.sessionStartedAtEpochMillis
        runtime.startResult = Result.failure(DesktopWindowsRuntimeFailure("CANCELLED"))
        state = state.copy(appMode = AppMode.VPN)
        assertEquals("CANCELLED", start(second).exceptionOrNull()?.message)
        assertTrue(runtime.running)
        assertTrue(state.isVpnRunning)
        assertFalse(state.isBusy)
        assertTrue(resume)
        assertEquals(active, service.activeConnection)
        assertEquals(startedAt, state.sessionStartedAtEpochMillis)
        assertEquals(1, state.successfulStarts)
        assertEquals(second.rawLink, state.selectedProfileRawLink)
        assertEquals(AppMode.VPN, state.appMode)
    }

    @Test fun deniedFindBestCandidatePreservesActualAAndPendingBWithoutPersistingCandidateC() = runTest {
        val runtime = FakeDesktopRuntimeController()
        val service = DesktopConnectionLifecycleService(runtime)
        var state = MainUiState(appMode = AppMode.PROXY_ONLY)
        var resume = false
        var commits = 0
        val actual = desktopLifecycleLocation(0)
        val pending = actual.copy(index = 1, rawLink = "socks://127.0.0.2:1080#PendingB", name = "PendingB")
        val candidate = actual.copy(index = 2, rawLink = "socks://127.0.0.3:1080#CandidateC", name = "CandidateC")
        val rows = listOf(actual, pending, candidate)
        val commit: (List<DesktopLocationRecord>, MainUiState) -> Result<Unit> = { _, next ->
            commits++; state = next; Result.success(Unit)
        }
        assertTrue(service.startConnection(state, rows, actual, null, { state }, { resume = it },
            commit, { state = it(state) }).isSuccess)
        val active = service.activeConnection
        state = state.copy(selectedProfileRawLink = pending.rawLink, selectedProfileName = pending.name,
            selectedProfileSourceUrl = pending.sourceUrl, appMode = AppMode.VPN)
        commits = 0
        runtime.startResult = Result.failure(DesktopWindowsRuntimeFailure("CANCELLED"))
        val result = service.startConnection(state, rows, candidate, null, { state }, { resume = it },
            commit, { state = it(state) }, commitSelectionOnSuccessOnly = true)
        assertEquals("CANCELLED", result.exceptionOrNull()?.message)
        assertEquals(pending.rawLink, state.selectedProfileRawLink)
        assertEquals(0, commits, "Denied preparation must not persist the automatic candidate")
        assertEquals(active, service.activeConnection)
        assertTrue(runtime.running)
        assertTrue(resume)
        assertEquals(AppMode.VPN, state.appMode)
        assertFalse(state.isBusy)
    }

    @Test fun successfulAutomaticCandidateCommitsItsSelectionOnlyAfterRuntimeStart() = runTest {
        val runtime = FakeDesktopRuntimeController()
        val service = DesktopConnectionLifecycleService(runtime)
        val pending = desktopLifecycleLocation(0)
        val candidate = pending.copy(index = 1, rawLink = "socks://127.0.0.2:1080#Candidate", name = "Candidate")
        var state = MainUiState(appMode = AppMode.PROXY_ONLY, selectedProfileRawLink = pending.rawLink)
        var commits = 0
        val result = service.startConnection(state, listOf(pending, candidate), candidate, null, { state }, {},
            commitState = { rows, next ->
                assertTrue(runtime.running)
                assertEquals(candidate.rawLink, rows.single { it.isSelected }.rawLink)
                commits++; state = next; Result.success(Unit)
            }, updateState = { state = it(state) }, commitSelectionOnSuccessOnly = true)
        assertTrue(result.isSuccess)
        assertEquals(1, commits)
        assertEquals(candidate.rawLink, state.selectedProfileRawLink)
        assertEquals(candidate.rawLink, service.activeConfiguration?.locationReference)
    }

    @Test fun failedAutomaticSelectionCommitRestoresActualAAndRetainsPendingBWithNewTelemetry() = runTest {
        val runtime = FakeDesktopRuntimeController()
        var now = 100L
        val service = DesktopConnectionLifecycleService(runtime) { now }
        var state = MainUiState(appMode = AppMode.PROXY_ONLY)
        val actual = desktopLifecycleLocation(0)
        val pending = actual.copy(index = 1, rawLink = "socks://127.0.0.2:1080#PendingB", name = "PendingB")
        val candidate = actual.copy(index = 2, rawLink = "socks://127.0.0.3:1080#CandidateC", name = "CandidateC")
        val rows = listOf(actual, pending, candidate)
        assertTrue(service.startConnection(state, rows, actual, null, { state }, {},
            { _, next -> state = next; Result.success(Unit) }, { state = it(state) }).isSuccess)
        val original = kotlin.test.assertNotNull(service.activeConnection)
        state = state.copy(selectedProfileRawLink = pending.rawLink, selectedProfileName = pending.name)
        now = 200L
        val failure = DesktopPersistenceException()
        val result = service.startConnection(state, rows, candidate, null, { state }, {},
            { _, _ -> Result.failure(failure) }, { state = it(state) }, commitSelectionOnSuccessOnly = true)
        kotlin.test.assertSame(failure, result.exceptionOrNull())
        assertEquals(pending.rawLink, state.selectedProfileRawLink)
        assertEquals(original.configuration, service.activeConfiguration)
        assertTrue(original.runtimeId != service.activeConnection?.runtimeId)
        assertEquals(200L, state.sessionStartedAtEpochMillis)
        assertEquals(1, state.successfulStarts)
        assertTrue(runtime.running)
        assertFalse(state.isBusy)
    }

    @Test fun recoveredPriorRuntimeGetsNewIdentityWithoutApplyingPendingSettings() = runTest {
        val runtime = FakeDesktopRuntimeController()
        var now = 100L
        val service = DesktopConnectionLifecycleService(runtime) { now }
        var state = MainUiState(appMode = AppMode.PROXY_ONLY)
        var resume = false
        val first = desktopLifecycleLocation(0)
        val second = first.copy(index = 1, rawLink = "socks://127.0.0.2:1080#Pending", name = "Pending")
        suspend fun start(location: DesktopLocationRecord) = service.startConnection(state, listOf(first, second),
            location, null, { state }, { resume = it },
            commitState = { _, next -> state = next; Result.success(Unit) }, updateState = { state = it(state) })
        assertTrue(start(first).isSuccess)
        val original = kotlin.test.assertNotNull(service.activeConnection)
        val recovered = runtime.startResult.getOrThrow().copy(processId = 42L)
        runtime.startResult = Result.failure(DesktopRuntimeTransitionFailure(
            com.kardinal.vpncontrol.model.ControlCode.RUNTIME_FAILED, recoveredSession = recovered))
        state = state.copy(appMode = AppMode.VPN)
        now = 200L
        assertEquals("RUNTIME_FAILED", start(second).exceptionOrNull()?.message)
        val actual = kotlin.test.assertNotNull(service.activeConnection)
        assertTrue(actual.runtimeId != original.runtimeId, "Recovered A is a new child, so old telemetry identity must end")
        assertEquals(200L, actual.startedAt)
        assertEquals(200L, state.sessionStartedAtEpochMillis)
        assertEquals(original.configuration, actual.configuration)
        assertEquals(first, actual.location)
        assertEquals(second.rawLink, state.selectedProfileRawLink)
        assertEquals(AppMode.VPN, state.appMode)
        assertTrue(state.isVpnRunning)
        assertFalse(state.isBusy)
        assertTrue(resume)
        assertEquals(1, state.successfulStarts, "Failed B must not count as a successful user start")
    }

    @Test
    fun capturedRuntimeRestoreDoesNotApplyPendingSelectionOrSettings() = runTest {
        val runtime = FakeDesktopRuntimeController()
        val service = DesktopConnectionLifecycleService(runtime)
        var state = MainUiState(appMode = AppMode.PROXY_ONLY)
        val first = desktopLifecycleLocation(0)
        assertTrue(service.startConnection(state, listOf(first), first, null, { state }, {},
            commitState = { _, next -> state = next; Result.success(Unit) },
            updateState = { state = it(state) }).isSuccess)
        val original = service.activeConfiguration
        val originalRuntime = kotlin.test.assertNotNull(service.activeConnection).runtimeId
        state = state.copy(selectedProfileRawLink = "socks://127.0.0.2:1080#Pending", appMode = AppMode.VPN)
        val restore = service.captureRuntimeRestore()
        assertTrue(service.stopConnection(state, listOf(first), null, { state }, {},
            commitState = { _, next -> state = next; Result.success(Unit) },
            updateState = { state = it(state) }).isSuccess)
        assertTrue(restore().isSuccess)
        val restoredRuntime = kotlin.test.assertNotNull(service.activeConnection).runtimeId
        assertTrue(originalRuntime != restoredRuntime)
        assertTrue(restore().isSuccess)
        assertEquals(restoredRuntime, service.activeConnection?.runtimeId)
        assertEquals(original, service.activeConfiguration)
        assertEquals(first.rawLink, service.activeLocation?.rawLink)
        assertEquals(listOf("Selected", "Selected"), runtime.startedProfiles.map { it.remarks })
        assertEquals("socks://127.0.0.2:1080#Pending", state.selectedProfileRawLink)
        assertEquals(AppMode.VPN, state.appMode)
    }

    @Test
    fun failedStartPersistenceNeverReportsSuccessOrLeavesNewRuntimeRunning() = runTest {
        for (failureAt in listOf(1, 2)) {
            val runtime = FakeDesktopRuntimeController()
            val service = DesktopConnectionLifecycleService(runtime)
            var state = MainUiState(appMode = AppMode.PROXY_ONLY)
            val locations = listOf(desktopLifecycleLocation(0))
            var writes = 0
            var resume = false
            val result = service.startConnection(state, locations, locations.single(), null, { state },
                { resume = it }, commitState = { _, next ->
                    writes++
                    if (writes == failureAt) Result.failure(DesktopPersistenceException())
                    else { state = next; Result.success(Unit) }
                }, updateState = { state = it(state) })
            assertEquals("PERSISTENCE_FAILED", result.exceptionOrNull()?.message)
            assertEquals(failureAt - 1, runtime.startedProfiles.size)
            assertFalse(runtime.running)
            assertFalse(state.isVpnRunning)
            assertFalse(state.isBusy)
            assertFalse(resume)
        }
    }

    @Test
    fun failedRestartCommitRestoresActualPriorRuntimeNotPendingSelection() = runTest {
        val runtime = FakeDesktopRuntimeController()
        val service = DesktopConnectionLifecycleService(runtime)
        var state = MainUiState(appMode = AppMode.PROXY_ONLY)
        val first = desktopLifecycleLocation(0)
        val second = first.copy(index = 1, rawLink = "socks://127.0.0.2:1080#Second", name = "Second")
        val locations = listOf(first, second)
        var failCommit = false
        suspend fun start(location: DesktopLocationRecord) = service.startConnection(
            state, locations, location, null, { state }, {}, commitState = { _, next ->
                if (failCommit && !next.isBusy) Result.failure(DesktopPersistenceException())
                else { state = next; Result.success(Unit) }
            }, updateState = { state = it(state) })
        assertTrue(start(first).isSuccess)
        failCommit = true
        assertEquals("PERSISTENCE_FAILED", start(second).exceptionOrNull()?.message)
        assertEquals(listOf("Selected", "Second", "Selected"), runtime.startedProfiles.map { it.remarks })
        assertEquals(first.rawLink, service.activeLocation?.rawLink)
        assertEquals(second.rawLink, state.selectedProfileRawLink)
        assertTrue(state.isVpnRunning)
        assertFalse(state.isBusy)
    }

    @Test
    fun failedStopSaveStillPublishesActualStoppedStateAndReturnsFailure() = runTest {
        val runtime = FakeDesktopRuntimeController(running = true)
        val service = DesktopConnectionLifecycleService(runtime)
        var state = MainUiState(isVpnRunning = true)
        val result = service.stopConnection(state, emptyList(), null, { state }, {},
            commitState = { _, _ -> Result.failure(DesktopPersistenceException()) },
            updateState = { state = it(state) })
        assertEquals("PERSISTENCE_FAILED", result.exceptionOrNull()?.message)
        assertFalse(runtime.running)
        assertFalse(state.isVpnRunning)
        assertFalse(state.isBusy)
    }

    @Test
    fun startConnectionSelectsLocationStartsRuntimeAndEnablesResume() = runTest {
        val runtime = FakeDesktopRuntimeController(
            startResult = Result.success(
                DesktopRuntimeSession(
                    appMode = AppMode.VPN,
                    listenPort = null,
                    interfaceName = "tun-test",
                    configJson = "{}",
                    logFile = Paths.get("runtime.log"),
                    processId = 42L,
                ),
            ),
        )
        val service = DesktopConnectionLifecycleService(
            runtime = runtime,
            clockMillis = { 1234L },
        )
        val committedRules = RoutingRules(directDomainSuffixes = listOf("committed.example"))
        var state = MainUiState(appMode = AppMode.VPN, routingRules = committedRules,
            routingDirectDomainsDraft = "unsaved.example")
        var locations = listOf(desktopLifecycleLocation(index = 0))
        var resume = false

        val result = service.startConnection(
            state = state,
            locations = locations,
            location = locations.single(),
            benchmarkSummary = "Best: Test",
            currentState = { state },
            setResumeConnectionOnLaunch = { resume = it },
            commitState = { nextLocations, nextState ->
                locations = nextLocations
                state = nextState
                Result.success(Unit)
            },
            updateState = { transform ->
                state = transform(state)
            },
        )

        assertTrue(result.isSuccess)
        assertEquals(committedRules, runtime.startedRules.single())
        val active = kotlin.test.assertNotNull(service.activeConfiguration)
        assertFalse(active.hasPendingChanges(state))
        assertTrue(active.hasPendingChanges(state.copy(appMode = AppMode.PROXY_ONLY)))
        assertFalse(active.hasPendingChanges(state.copy(routingDirectDomainsDraft = "another-unsaved.example")))
        assertEquals(locations.single().rawLink, service.activeLocation?.rawLink)
        assertTrue(resume)
        assertEquals("Selected", runtime.startedProfiles.single().remarks)
        assertTrue(locations.single().isSelected)
        assertTrue(state.isVpnRunning)
        assertFalse(state.isBusy)
        assertEquals("Selected", state.selectedProfileName)
        assertEquals(1234L, state.sessionStartedAtEpochMillis)
        assertEquals(1, state.successfulStarts)
        assertEquals("Best: Test", state.lastBenchmarkSummary)
        assertEquals(ConnectionStatusMessages.connectionStartedOnTarget(AppMode.VPN, "tun-test"), state.statusMessage)
    }

    @Test
    fun manualStopClearsResumeAndCountsSuccessfulStop() = runTest {
        val runtime = FakeDesktopRuntimeController(running = true, mode = AppMode.VPN)
        val service = DesktopConnectionLifecycleService(
            runtime = runtime,
            clockMillis = { 5678L },
        )
        var state = MainUiState(appMode = AppMode.VPN, isVpnRunning = true)
        val locations = listOf(desktopLifecycleLocation(index = 0))
        var resume = true

        val result = service.stopConnection(
            state = state,
            locations = locations,
            message = null,
            currentState = { state },
            setResumeConnectionOnLaunch = { resume = it },
            commitState = { _, nextState ->
                state = nextState
                Result.success(Unit)
            },
            updateState = { transform ->
                state = transform(state)
            },
        )

        assertTrue(result.isSuccess)
        assertFalse(resume)
        assertFalse(runtime.running)
        assertFalse(state.isVpnRunning)
        assertFalse(state.isBusy)
        assertEquals(5678L, state.sessionStoppedAtEpochMillis)
        assertEquals(1, state.successfulStops)
        assertEquals(ConnectionStatusMessages.connectionStopped(AppMode.VPN), state.statusMessage)
    }

    @Test
    fun exitStopKeepsResumeWhenRuntimeWasRunningWithoutCountingManualStop() = runTest {
        val runtime = FakeDesktopRuntimeController(running = true, mode = AppMode.PROXY_ONLY)
        val service = DesktopConnectionLifecycleService(
            runtime = runtime,
            clockMillis = { 9012L },
        )
        var state = MainUiState(appMode = AppMode.PROXY_ONLY, isVpnRunning = true)
        val locations = listOf(desktopLifecycleLocation(index = 0))
        var resume = false

        val result = service.stopRuntimeForAppExit(
            state = state,
            locations = locations,
            currentState = { state },
            setResumeConnectionOnLaunch = { resume = it },
            commitState = { _, nextState ->
                state = nextState
                Result.success(Unit)
            },
            updateState = { transform ->
                state = transform(state)
            },
        )

        assertTrue(result.isSuccess)
        assertTrue(resume)
        assertFalse(runtime.running)
        assertFalse(state.isVpnRunning)
        assertEquals(9012L, state.sessionStoppedAtEpochMillis)
        assertEquals(0, state.successfulStops)
        assertEquals(ConnectionStatusMessages.connectionStoppedReconnectOnNextLaunch(AppMode.PROXY_ONLY), state.statusMessage)
    }
}

private fun desktopLifecycleLocation(index: Int): DesktopLocationRecord {
    return DesktopLocationRecord(
        index = index,
        sourceUrl = "",
        rawLink = "socks://user:pass@127.0.0.1:1080#Selected",
        name = "Selected",
        server = "127.0.0.1",
        details = "SOCKS",
        benchmarkDetail = "Imported - not checked yet",
        isValid = true,
    )
}

private class FakeDesktopRuntimeController(
    var running: Boolean = false,
    private var mode: AppMode? = null,
    var startResult: Result<DesktopRuntimeSession> = Result.success(
        DesktopRuntimeSession(
            appMode = AppMode.PROXY_ONLY,
            listenPort = 1080,
            interfaceName = null,
            configJson = "{}",
            logFile = Paths.get("runtime.log"),
            processId = 1L,
        ),
    ),
    private val stopResult: Result<Unit> = Result.success(Unit),
) : DesktopRuntimeController {
    val startedProfiles = mutableListOf<ProxyProfile>()
    val startedRules = mutableListOf<RoutingRules>()
    var restoreLease: DesktopRuntimeRestoreLease? = null
    override fun captureRuntimeRestoreLease(): DesktopRuntimeRestoreLease? = restoreLease

    override suspend fun start(
        profile: ProxyProfile,
        routingRules: RoutingRules,
        dnsSettings: DnsSettings,
        appMode: AppMode,
        activeVerificationPort: Int?,
        homeSshRouteSettings: com.kardinal.vpncontrol.model.HomeSshRouteSettings,
    ): Result<DesktopRuntimeSession> {
        startedProfiles += profile
        startedRules += routingRules
        if (startResult.isSuccess) {
            running = true
            mode = appMode
        }
        return startResult
    }

    override suspend fun stop(): Result<Unit> {
        if (stopResult.isSuccess || stopResult.exceptionOrNull() is DesktopRuntimeResourcePublicationFailure) {
            running = false
            mode = null
        }
        return stopResult
    }

    override fun isRunning(): Boolean = running

    override fun currentMode(): AppMode? = mode.takeIf { running }

    override fun currentPort(): Int? = 1080.takeIf { running }
}
