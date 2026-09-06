package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.ConnectionStatusMessages
import com.kardinal.vpncontrol.model.LocationStatusMessages
import com.kardinal.vpncontrol.MainCommandLogic
import com.kardinal.vpncontrol.control.ControlRuntimeConfiguration
import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.data.LocationConfigs
import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.DnsSettings
import com.kardinal.vpncontrol.model.ProxyProfile
import com.kardinal.vpncontrol.model.RoutingRules
import com.kardinal.vpncontrol.model.HomeSshRouteSettings

internal interface DesktopRuntimeController {
    suspend fun start(
        profile: ProxyProfile,
        routingRules: RoutingRules,
        dnsSettings: DnsSettings,
        appMode: AppMode,
        activeVerificationPort: Int? = null,
        homeSshRouteSettings: HomeSshRouteSettings = HomeSshRouteSettings(),
    ): Result<DesktopRuntimeSession>

    suspend fun stop(): Result<Unit>

    fun isRunning(): Boolean

    fun currentMode(): AppMode?

    fun currentPort(): Int?

    fun currentManagementProxyPort(): Int? = currentPort()
}

internal class DesktopConnectionLifecycleService(
    private val runtime: DesktopRuntimeController,
    private val clockMillis: () -> Long = { System.currentTimeMillis() },
) {
    internal data class ActiveConnection(
        val configuration: ControlRuntimeConfiguration,
        val location: DesktopLocationRecord?,
        val runtimeId: String,
        val startedAt: Long,
    ) {
        override fun toString(): String = "ActiveConnection(<redacted>)"
    }
    @Volatile var activeConnection: ActiveConnection? = null
        private set
    val activeConfiguration: ControlRuntimeConfiguration? get() = activeConnection?.configuration
    val activeLocation: DesktopLocationRecord? get() = activeConnection?.location

    private fun recordStarted(configuration: ControlRuntimeConfiguration, location: DesktopLocationRecord?): ActiveConnection =
        ActiveConnection(configuration, location, java.util.UUID.randomUUID().toString(), clockMillis()).also {
            activeConnection = it
        }

    /** Captures the running configuration, never the next selection or open drafts. */
    fun captureRuntimeRestore(): suspend () -> Result<Unit> {
        val captured = activeConnection.takeIf { runtime.isRunning() }
        val configuration = captured?.configuration
        val location = captured?.location
        return restore@{
            if (configuration == null) return@restore Result.failure(IllegalStateException("ROLLBACK_FAILED"))
            if (runtime.isRunning() && activeConfiguration == configuration) return@restore Result.success(Unit)
            val restored = runCatching {
                runtime.start(
                    profile = LocationConfigs.decodeStoredLocation(configuration.locationReference),
                    routingRules = configuration.routing,
                    dnsSettings = configuration.dns,
                    appMode = configuration.mode,
                    homeSshRouteSettings = configuration.ssh,
                ).getOrThrow()
            }
            if (restored.isSuccess) {
                recordStarted(configuration, location)
                Result.success(Unit)
            } else {
                if (!runtime.isRunning()) clearActiveConfiguration()
                Result.failure(IllegalStateException("ROLLBACK_FAILED"))
            }
        }
    }

    suspend fun startConnection(
        state: MainUiState,
        locations: List<DesktopLocationRecord>,
        location: DesktopLocationRecord,
        benchmarkSummary: String?,
        currentState: () -> MainUiState,
        setResumeConnectionOnLaunch: (Boolean) -> Unit,
        commitState: (List<DesktopLocationRecord>, MainUiState) -> Result<Unit>,
        updateState: ((MainUiState) -> MainUiState) -> Unit,
        activeVerificationPort: Int? = null,
    ): Result<Unit> {
        val targetMode = state.appMode
        val previous = activeConnection.takeIf { runtime.isRunning() }
        val previousConfiguration = previous?.configuration
        val previousLocation = previous?.location
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
        val prepared = commitState(selectedLocations, startingState)
        if (prepared.isFailure) return prepared

        val result = runtime.start(
            profile = profile.getOrThrow(),
            routingRules = startingState.routingRules,
            dnsSettings = startingState.dnsSettings,
            appMode = targetMode,
            activeVerificationPort = activeVerificationPort,
            homeSshRouteSettings = startingState.homeSshRouteSettings,
        )
        if (result.isSuccess) {
            val active = recordStarted(ControlRuntimeConfiguration.committed(startingState), location)
            val session = result.getOrThrow()
            val startedAt = active.startedAt
            setResumeConnectionOnLaunch(true)
            val startedTarget = when (targetMode) {
                AppMode.PROXY_ONLY -> "127.0.0.1:${session.listenPort}"
                AppMode.VPN -> session.interfaceName ?: DesktopProxyConfigFactory.DEFAULT_VPN_INTERFACE_NAME
            }
            val latestState = currentState()
            val committed = commitState(
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
            if (committed.isFailure) {
                val rollback = if (previousConfiguration == null) runtime.stop() else runCatching {
                    runtime.start(
                        profile = LocationConfigs.decodeStoredLocation(previousConfiguration.locationReference),
                        routingRules = previousConfiguration.routing,
                        dnsSettings = previousConfiguration.dns,
                        appMode = previousConfiguration.mode,
                        homeSshRouteSettings = previousConfiguration.ssh,
                    ).getOrThrow()
                    Unit
                }
                if (rollback.isSuccess) {
                    if (previousConfiguration != null) recordStarted(previousConfiguration, previousLocation)
                    else clearActiveConfiguration()
                } else if (!runtime.isRunning()) clearActiveConfiguration()
                setResumeConnectionOnLaunch(runtime.isRunning())
                updateState { it.copy(isBusy = false, isVpnRunning = runtime.isRunning()) }
                return if (rollback.isSuccess) committed else Result.failure(IllegalStateException("ROLLBACK_FAILED"))
            }
        } else {
            if (!runtime.isRunning()) clearActiveConfiguration()
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
        commitState: (List<DesktopLocationRecord>, MainUiState) -> Result<Unit>,
        updateState: ((MainUiState) -> MainUiState) -> Unit,
    ): Result<Unit> {
        val wasRunning = state.isVpnRunning || runtime.isRunning()
        val stoppedMode = runtime.currentMode() ?: state.appMode
        setResumeConnectionOnLaunch(false)
        if (!wasRunning) {
            clearActiveConfiguration()
            return commitState(
                locations,
                state.copy(
                    isBusy = false,
                    isVpnRunning = false,
                ).withStatus(message ?: MainCommandLogic.stoppedConnectionStatus(stoppedMode)),
            ).onFailure { updateState { it.copy(isBusy = false, isVpnRunning = false) } }
        }
        updateState { it.copy(isBusy = true) }
        val result = runtime.stop()
        val stoppedAt = clockMillis()
        if (result.isSuccess) {
            clearActiveConfiguration()
            val latestState = currentState()
            return commitState(
                locations,
                latestState.copy(
                    isBusy = false,
                    isVpnRunning = false,
                    sessionStoppedAtEpochMillis = stoppedAt,
                    successfulStops = latestState.successfulStops + 1,
                ).withStatus(message ?: MainCommandLogic.stoppedConnectionStatus(stoppedMode)),
            ).onFailure { updateState { it.copy(isBusy = false, isVpnRunning = false, sessionStoppedAtEpochMillis = stoppedAt) } }
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
        commitState: (List<DesktopLocationRecord>, MainUiState) -> Result<Unit>,
        updateState: ((MainUiState) -> MainUiState) -> Unit,
    ): Result<Unit> {
        val wasRunning = state.isVpnRunning || runtime.isRunning()
        val stoppedMode = runtime.currentMode() ?: state.appMode
        setResumeConnectionOnLaunch(wasRunning)
        if (!wasRunning) {
            clearActiveConfiguration()
            return commitState(
                locations,
                state.copy(
                    isBusy = false,
                    isVpnRunning = false,
                ).withStatus(ConnectionStatusMessages.appClosedConnectionWasOff()),
            ).onFailure { updateState { it.copy(isBusy = false, isVpnRunning = false) } }
        }

        updateState { it.copy(isBusy = true) }
        val result = runtime.stop()
        val stoppedAt = clockMillis()
        if (result.isSuccess) {
            clearActiveConfiguration()
            val latestState = currentState()
            return commitState(
                locations,
                latestState.copy(
                    isBusy = false,
                    isVpnRunning = false,
                    sessionStoppedAtEpochMillis = stoppedAt,
                ).withStatus(ConnectionStatusMessages.connectionStoppedReconnectOnNextLaunch(stoppedMode)),
            ).onFailure { updateState { it.copy(isBusy = false, isVpnRunning = false, sessionStoppedAtEpochMillis = stoppedAt) } }
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

    private fun clearActiveConfiguration() {
        activeConnection = null
    }

    fun currentRuntimeMode(): AppMode? = runtime.currentMode()

    fun currentRuntimePort(): Int? = runtime.currentPort()
}
