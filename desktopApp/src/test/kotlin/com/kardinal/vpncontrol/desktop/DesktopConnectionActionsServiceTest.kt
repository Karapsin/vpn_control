package com.kardinal.vpncontrol.desktop

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

class DesktopConnectionActionsServiceTest {
    @Test
    fun resumeReportsMissingPreviousLocation() = runTest {
        var state = MainUiState(
            selectedProfileRawLink = "socks://127.0.0.1:1080#Missing",
        )
        val actions = service(
            stateProvider = { state },
            locationsProvider = { emptyList() },
            updateState = { transform -> state = transform(state) },
            commitState = { _, nextState -> state = nextState },
        )

        actions.resumePreviousConnectionIfNeeded()

        assertFalse(state.isVpnRunning)
        assertEquals("Previous VPN location is no longer available", state.statusMessage)
    }

    @Test
    fun resumeStartsSelectedLocationOnlyOnce() = runTest {
        val location = desktopConnectionLocation()
        val runtime = FakeConnectionActionsRuntime()
        val lifecycle = DesktopConnectionLifecycleService(runtime)
        var state = MainUiState(
            appMode = AppMode.PROXY_ONLY,
            currentLocations = listOf(location.rawLink),
            selectedProfileRawLink = location.rawLink,
        )
        var locations = listOf(location)
        var resume = true
        var attempted = false
        val actions = service(
            lifecycle = lifecycle,
            stateProvider = { state },
            locationsProvider = { locations },
            getResume = { resume },
            setResume = { resume = it },
            getAttempted = { attempted },
            setAttempted = { attempted = it },
            updateState = { transform -> state = transform(state) },
            commitState = { nextLocations, nextState ->
                locations = nextLocations
                state = nextState
            },
        )

        actions.resumePreviousConnectionIfNeeded()
        actions.resumePreviousConnectionIfNeeded()

        assertTrue(attempted)
        assertTrue(resume)
        assertEquals(1, runtime.startCalls)
        assertTrue(state.isVpnRunning)
        assertEquals("Selected", state.selectedProfileName)
    }

    private fun service(
        lifecycle: DesktopConnectionLifecycleService = DesktopConnectionLifecycleService(FakeConnectionActionsRuntime()),
        stateProvider: () -> MainUiState,
        locationsProvider: () -> List<DesktopLocationRecord>,
        getResume: () -> Boolean = { true },
        setResume: (Boolean) -> Unit = {},
        getAttempted: () -> Boolean = { false },
        setAttempted: (Boolean) -> Unit = {},
        updateState: ((MainUiState) -> MainUiState) -> Unit,
        commitState: (List<DesktopLocationRecord>, MainUiState) -> Unit,
    ): DesktopConnectionActionsService {
        return DesktopConnectionActionsService(
            stateProvider = stateProvider,
            locationsProvider = locationsProvider,
            connectionLifecycle = lifecycle,
            getResumeConnectionOnLaunch = getResume,
            setResumeConnectionOnLaunch = setResume,
            getLaunchResumeAttempted = getAttempted,
            setLaunchResumeAttempted = setAttempted,
            commitState = commitState,
            updateState = updateState,
        )
    }

    private fun desktopConnectionLocation(): DesktopLocationRecord {
        return DesktopLocationRecord(
            index = 0,
            sourceUrl = "",
            rawLink = "socks://user:pass@127.0.0.1:1080#Selected",
            name = "Selected",
            server = "127.0.0.1",
            details = "SOCKS",
            benchmarkDetail = "Imported - not checked yet",
            isValid = true,
        )
    }
}

private class FakeConnectionActionsRuntime : DesktopRuntimeController {
    var startCalls = 0
    private var running = false
    private var mode: AppMode? = null

    override suspend fun start(
        profile: ProxyProfile,
        routingRules: RoutingRules,
        dnsSettings: DesktopDnsSettings,
        appMode: AppMode,
    ): Result<DesktopRuntimeSession> {
        startCalls += 1
        running = true
        mode = appMode
        return Result.success(
            DesktopRuntimeSession(
                appMode = appMode,
                listenPort = 1080,
                interfaceName = null,
                configJson = "{}",
                logFile = Paths.get("runtime.log"),
                processId = 1L,
            ),
        )
    }

    override suspend fun stop(): Result<Unit> {
        running = false
        mode = null
        return Result.success(Unit)
    }

    override fun isRunning(): Boolean = running

    override fun currentMode(): AppMode? = mode.takeIf { running }
}
