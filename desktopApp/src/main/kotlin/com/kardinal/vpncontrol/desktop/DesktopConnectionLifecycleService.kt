package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.ConnectionStatusMessages
import com.kardinal.vpncontrol.model.LocationStatusMessages
import com.kardinal.vpncontrol.MainCommandLogic
import com.kardinal.vpncontrol.MainDraftLogic
import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.data.LocationConfigs
import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.DnsSettings
import com.kardinal.vpncontrol.model.ProxyProfile
import com.kardinal.vpncontrol.model.RoutingRules

internal interface DesktopRuntimeController {
    suspend fun start(
        profile: ProxyProfile,
        routingRules: RoutingRules,
        dnsSettings: DnsSettings,
        appMode: AppMode,
        activeVerificationPort: Int? = null,
    ): Result<DesktopRuntimeSession>

    suspend fun stop(): Result<Unit>

    fun isRunning(): Boolean

    fun currentMode(): AppMode?

    fun currentPort(): Int?
}

internal class DesktopConnectionLifecycleService(
    private val runtime: DesktopRuntimeController,
    private val clockMillis: () -> Long = { System.currentTimeMillis() },
) {
    suspend fun startConnection(
        state: MainUiState,
        locations: List<DesktopLocationRecord>,
        location: DesktopLocationRecord,
        benchmarkSummary: String?,
        currentState: () -> MainUiState,
        setResumeConnectionOnLaunch: (Boolean) -> Unit,
        commitState: (List<DesktopLocationRecord>, MainUiState) -> Unit,
        updateState: ((MainUiState) -> MainUiState) -> Unit,
        activeVerificationPort: Int? = null,
    ): Result<Unit> {
        val targetMode = state.appMode
        val profile = runCatching { LocationConfigs.decodeStoredLocation(location.rawLink) }
        if (profile.isFailure) {
            val error = profile.exceptionOrNull()?.message ?: LocationStatusMessages.invalidLocationConfig()
            updateState { it.withStatus(error) }
            return Result.failure(IllegalStateException(error))
        }

        val selectedLocations = locations.map { it.copy(isSelected = it.index == location.index) }
        val startingState = state.copy(
            isBusy = true,
            selectedProfileName = location.name,
            selectedProfileServer = location.server,
            selectedProfileRawLink = location.rawLink,
            selectedProfileSourceUrl = location.sourceUrl,
        ).withStatus(MainCommandLogic.startingConnectionLabel(targetMode))
        commitState(selectedLocations, startingState)

        val result = runtime.start(
            profile = profile.getOrThrow(),
            routingRules = MainDraftLogic.buildEditedRoutingRules(startingState),
            dnsSettings = startingState.dnsSettings,
            appMode = targetMode,
            activeVerificationPort = activeVerificationPort,
        )
        if (result.isSuccess) {
            val session = result.getOrThrow()
            val startedAt = clockMillis()
            setResumeConnectionOnLaunch(true)
            val startedTarget = when (targetMode) {
                AppMode.PROXY_ONLY -> "127.0.0.1:${session.listenPort}"
                AppMode.VPN -> session.interfaceName ?: DesktopProxyConfigFactory.DEFAULT_VPN_INTERFACE_NAME
            }
            val latestState = currentState()
            commitState(
                selectedLocations,
                latestState.copy(
                    isBusy = false,
                    isVpnRunning = true,
                    hasVpnPermission = true,
                    sessionStartedAtEpochMillis = startedAt,
                    sessionStoppedAtEpochMillis = 0L,
                    successfulStarts = latestState.successfulStarts + 1,
                    lastBenchmarkSummary = benchmarkSummary ?: latestState.lastBenchmarkSummary,
                ).withStatus(ConnectionStatusMessages.connectionStartedOnTarget(targetMode, startedTarget)),
            )
        } else {
            updateState {
                it.copy(
                    isBusy = false,
                    isVpnRunning = false,
                ).withStatus(result.exceptionOrNull()?.message ?: ConnectionStatusMessages.connectionStartFailed(targetMode))
            }
        }
        return result.map { Unit }
    }

    suspend fun stopConnection(
        state: MainUiState,
        locations: List<DesktopLocationRecord>,
        message: String?,
        currentState: () -> MainUiState,
        setResumeConnectionOnLaunch: (Boolean) -> Unit,
        commitState: (List<DesktopLocationRecord>, MainUiState) -> Unit,
        updateState: ((MainUiState) -> MainUiState) -> Unit,
    ): Result<Unit> {
        val wasRunning = state.isVpnRunning || runtime.isRunning()
        val stoppedMode = runtime.currentMode() ?: state.appMode
        setResumeConnectionOnLaunch(false)
        if (!wasRunning) {
            commitState(
                locations,
                state.copy(
                    isBusy = false,
                    isVpnRunning = false,
                ).withStatus(message ?: MainCommandLogic.stoppedConnectionStatus(stoppedMode)),
            )
            return Result.success(Unit)
        }
        updateState { it.copy(isBusy = true) }
        val result = runtime.stop()
        val stoppedAt = clockMillis()
        if (result.isSuccess) {
            val latestState = currentState()
            commitState(
                locations,
                latestState.copy(
                    isBusy = false,
                    isVpnRunning = false,
                    sessionStoppedAtEpochMillis = stoppedAt,
                    successfulStops = latestState.successfulStops + 1,
                ).withStatus(message ?: MainCommandLogic.stoppedConnectionStatus(stoppedMode)),
            )
        } else {
            updateState {
                it.copy(isBusy = false).withStatus(
                    result.exceptionOrNull()?.message ?: ConnectionStatusMessages.connectionStopFailed(stoppedMode),
                )
            }
        }
        return result.map { Unit }
    }

    suspend fun stopRuntimeForAppExit(
        state: MainUiState,
        locations: List<DesktopLocationRecord>,
        currentState: () -> MainUiState,
        setResumeConnectionOnLaunch: (Boolean) -> Unit,
        commitState: (List<DesktopLocationRecord>, MainUiState) -> Unit,
        updateState: ((MainUiState) -> MainUiState) -> Unit,
    ): Result<Unit> {
        val wasRunning = state.isVpnRunning || runtime.isRunning()
        val stoppedMode = runtime.currentMode() ?: state.appMode
        setResumeConnectionOnLaunch(wasRunning)
        if (!wasRunning) {
            commitState(
                locations,
                state.copy(
                    isBusy = false,
                    isVpnRunning = false,
                ).withStatus(ConnectionStatusMessages.appClosedConnectionWasOff()),
            )
            return Result.success(Unit)
        }

        updateState { it.copy(isBusy = true) }
        val result = runtime.stop()
        val stoppedAt = clockMillis()
        if (result.isSuccess) {
            val latestState = currentState()
            commitState(
                locations,
                latestState.copy(
                    isBusy = false,
                    isVpnRunning = false,
                    sessionStoppedAtEpochMillis = stoppedAt,
                ).withStatus(ConnectionStatusMessages.connectionStoppedReconnectOnNextLaunch(stoppedMode)),
            )
        } else {
            updateState {
                it.copy(isBusy = false).withStatus(
                    result.exceptionOrNull()?.message ?: ConnectionStatusMessages.connectionStopBeforeExitFailed(stoppedMode),
                )
            }
        }
        return result.map { Unit }
    }

    fun isRuntimeRunning(): Boolean = runtime.isRunning()

    fun currentRuntimeMode(): AppMode? = runtime.currentMode()

    fun currentRuntimePort(): Int? = runtime.currentPort()
}
