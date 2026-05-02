package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.model.InstalledApp
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Test

class AndroidInstalledAppsActionsServiceTest {
    @Test
    fun ensureLoadedLoadsAppsOnceAndUpdatesState() {
        var state = MainUiState()
        var loadCalls = 0
        val apps = listOf(InstalledApp(packageName = "org.example.app", label = "Example", isSystemApp = false))
        val service = service(
            stateProvider = { state },
            updateState = { transform -> state = transform(state) },
            loadInstalledApps = {
                loadCalls += 1
                apps
            },
        )

        service.ensureLoaded()
        service.ensureLoaded()

        assertEquals(1, loadCalls)
        assertEquals(apps, state.installedApps)
        assertEquals(true, state.installedAppsLoaded)
        assertEquals(false, state.installedAppsLoading)
    }

    @Test
    fun ensureLoadedSkipsWhenAlreadyLoading() {
        var state = MainUiState(installedAppsLoading = true)
        var loadCalls = 0
        val service = service(
            stateProvider = { state },
            updateState = { transform -> state = transform(state) },
            loadInstalledApps = {
                loadCalls += 1
                emptyList()
            },
        )

        service.ensureLoaded()

        assertEquals(0, loadCalls)
        assertEquals(true, state.installedAppsLoading)
    }

    @Test
    fun ensureLoadedFailureClearsLoadingAndReportsStatus() {
        var state = MainUiState()
        val statuses = mutableListOf<String>()
        val service = service(
            stateProvider = { state },
            updateState = { transform -> state = transform(state) },
            loadInstalledApps = { error("package query failed") },
            updateStatus = { statuses += it },
        )

        service.ensureLoaded()

        assertEquals(false, state.installedAppsLoading)
        assertEquals(false, state.installedAppsLoaded)
        assertEquals(listOf("package query failed"), statuses)
    }

    private fun service(
        stateProvider: () -> MainUiState,
        updateState: ((MainUiState) -> MainUiState) -> Unit,
        loadInstalledApps: suspend () -> List<InstalledApp>,
        updateStatus: suspend (String) -> Unit = {},
    ): AndroidInstalledAppsActionsService {
        return AndroidInstalledAppsActionsService(
            stateProvider = stateProvider,
            updateState = updateState,
            launch = { block -> runBlocking { block() } },
            loadInstalledApps = loadInstalledApps,
            updateStatus = updateStatus,
        )
    }
}
