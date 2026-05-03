package com.kardinal.vpncontrol.desktop

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
        var state = MainUiState(appMode = AppMode.VPN)
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
            },
            updateState = { transform ->
                state = transform(state)
            },
        )

        assertTrue(result.isSuccess)
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

    override suspend fun start(
        profile: ProxyProfile,
        routingRules: RoutingRules,
        dnsSettings: DesktopDnsSettings,
        appMode: AppMode,
    ): Result<DesktopRuntimeSession> {
        startedProfiles += profile
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
}
