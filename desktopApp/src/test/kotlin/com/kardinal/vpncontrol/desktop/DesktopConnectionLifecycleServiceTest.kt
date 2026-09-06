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
    private val startResult: Result<DesktopRuntimeSession> = Result.success(
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
        if (stopResult.isSuccess) {
            running = false
            mode = null
        }
        return stopResult
    }

    override fun isRunning(): Boolean = running

    override fun currentMode(): AppMode? = mode.takeIf { running }

    override fun currentPort(): Int? = 1080.takeIf { running }
}
