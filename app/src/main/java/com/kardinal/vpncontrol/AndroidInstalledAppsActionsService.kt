package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.model.InstalledApp
import com.kardinal.vpncontrol.model.StatusMessages

internal class AndroidInstalledAppsActionsService(
    private val stateProvider: () -> MainUiState,
    private val updateState: ((MainUiState) -> MainUiState) -> Unit,
    private val launch: (suspend () -> Unit) -> Unit,
    private val loadInstalledApps: suspend () -> List<InstalledApp>,
    private val updateStatus: suspend (String) -> Unit,
) {
    fun ensureLoaded() {
        val state = stateProvider()
        if (state.installedAppsLoaded || state.installedAppsLoading) {
            return
        }

        launch {
            updateState { it.copy(installedAppsLoading = true) }
            runCatching { loadInstalledApps() }
                .onSuccess { apps ->
                    updateState {
                        it.copy(
                            installedApps = apps,
                            installedAppsLoaded = true,
                            installedAppsLoading = false,
                        )
                    }
                }
                .onFailure { error ->
                    updateState { it.copy(installedAppsLoading = false) }
                    updateStatus(error.message ?: StatusMessages.appsLoadFailed())
                }
        }
    }
}
