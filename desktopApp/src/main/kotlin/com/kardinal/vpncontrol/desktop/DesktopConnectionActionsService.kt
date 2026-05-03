package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.ConnectionStatusMessages
import com.kardinal.vpncontrol.model.LocationStatusMessages
import com.kardinal.vpncontrol.LocationStatusLogic
import com.kardinal.vpncontrol.MainUiState

internal class DesktopConnectionActionsService(
    private val stateProvider: () -> MainUiState,
    private val locationsProvider: () -> List<DesktopLocationRecord>,
    private val connectionLifecycle: DesktopConnectionLifecycleService,
    private val getResumeConnectionOnLaunch: () -> Boolean,
    private val setResumeConnectionOnLaunch: (Boolean) -> Unit,
    private val getLaunchResumeAttempted: () -> Boolean,
    private val setLaunchResumeAttempted: (Boolean) -> Unit,
    private val commitState: (nextLocations: List<DesktopLocationRecord>, nextState: MainUiState) -> Unit,
    private val updateState: ((MainUiState) -> MainUiState) -> Unit,
) {
    fun shouldResumeConnectionOnLaunch(): Boolean = getResumeConnectionOnLaunch()

    suspend fun resumePreviousConnectionIfNeeded() {
        val state = stateProvider()
        if (
            getLaunchResumeAttempted() ||
            !getResumeConnectionOnLaunch() ||
            state.isVpnRunning ||
            state.isBusy
        ) {
            return
        }
        setLaunchResumeAttempted(true)
        val location = selectedDesktopLocation()
        if (location == null) {
            updateState {
                it.copy(isBusy = false, isVpnRunning = false)
                    .withStatus(ConnectionStatusMessages.previousLocationUnavailable())
            }
            return
        }
        updateState {
            it.withStatus(ConnectionStatusMessages.restoringPreviousConnection(location.name))
        }
        start(
            location = location,
            benchmarkSummary = stateProvider().lastBenchmarkSummary,
        )
    }

    suspend fun shutdownForExit() {
        stopRuntimeForAppExit()
    }

    suspend fun toggleSelectedLocationProxy(): Result<Unit> {
        if (stateProvider().isVpnRunning) {
            return stop()
        }
        val location = selectedDesktopLocation()
        return if (location == null) {
            updateState { it.withStatus(LocationStatusLogic.selectLocationFirst()) }
            Result.failure(IllegalStateException(LocationStatusMessages.selectLocationFirst()))
        } else {
            start(location)
        }
    }

    suspend fun stop(message: String? = null): Result<Unit> {
        return connectionLifecycle.stopConnection(
            state = stateProvider(),
            locations = locationsProvider(),
            message = message,
            currentState = stateProvider,
            setResumeConnectionOnLaunch = setResumeConnectionOnLaunch,
            commitState = commitState,
            updateState = updateState,
        )
    }

    suspend fun stopRuntimeForAppExit(): Result<Unit> {
        return connectionLifecycle.stopRuntimeForAppExit(
            state = stateProvider(),
            locations = locationsProvider(),
            currentState = stateProvider,
            setResumeConnectionOnLaunch = setResumeConnectionOnLaunch,
            commitState = commitState,
            updateState = updateState,
        )
    }

    suspend fun start(
        location: DesktopLocationRecord,
        benchmarkSummary: String? = null,
    ): Result<Unit> {
        return connectionLifecycle.startConnection(
            state = stateProvider(),
            locations = locationsProvider(),
            location = location,
            benchmarkSummary = benchmarkSummary,
            currentState = stateProvider,
            setResumeConnectionOnLaunch = setResumeConnectionOnLaunch,
            commitState = commitState,
            updateState = updateState,
        )
    }

    private fun selectedDesktopLocation(): DesktopLocationRecord? {
        val state = stateProvider()
        val locations = locationsProvider()
        return locations.firstOrNull { it.matchesSelectedLocation(state) }
            ?: locations.firstOrNull { it.rawLink in state.currentLocations && it.isSelected }
    }
}
