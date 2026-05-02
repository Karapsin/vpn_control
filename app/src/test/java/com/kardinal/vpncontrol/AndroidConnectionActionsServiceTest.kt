package com.kardinal.vpncontrol

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AndroidConnectionActionsServiceTest {
    @Test
    fun onVpnPermissionGrantedUpdatesControllerState() {
        val controller = MainController()
        val service = service(controller = controller)

        service.onVpnPermissionGranted()

        assertTrue(controller.state.value.hasVpnPermission)
    }

    @Test
    fun toggleVpnLaunchesConnectionLifecycleThroughTrackedOperation() = runBlocking {
        var launched = false
        var state = MainUiState(isVpnRunning = true)
        var stopped = false
        val lifecycle = AndroidConnectionLifecycleService(
            stateProvider = { state },
            updateState = { transform -> state = transform(state) },
            setBusy = { busy -> state = state.copy(isBusy = busy) },
            updateStatus = {},
            snapshot = { com.kardinal.vpncontrol.model.PersistedState() },
            restoreSnapshot = { _, _ -> },
            ensureSelection = {
                Result.failure(IllegalStateException("No selection"))
            },
            persistSelection = {},
            rehydrateSelection = {
                Result.failure(IllegalStateException("No saved selection"))
            },
            startConnection = { Result.success(Unit) },
            stopConnection = {
                stopped = true
                state = state.copy(isVpnRunning = false)
                Result.success(Unit)
            },
        )
        val service = service(
            connectionLifecycle = lifecycle,
            launchTrackedBusyOperation = { block ->
                launched = true
                runBlocking { block() }
            },
        )

        service.toggleVpn()

        assertTrue(launched)
        assertTrue(stopped)
        assertFalse(state.isVpnRunning)
    }

    private fun service(
        controller: MainController = MainController(),
        connectionLifecycle: AndroidConnectionLifecycleService = AndroidConnectionLifecycleService(
            stateProvider = { MainUiState() },
            updateState = {},
            setBusy = {},
            updateStatus = {},
            snapshot = { com.kardinal.vpncontrol.model.PersistedState() },
            restoreSnapshot = { _, _ -> },
            ensureSelection = {
                Result.failure(IllegalStateException("No selection"))
            },
            persistSelection = {},
            rehydrateSelection = {
                Result.failure(IllegalStateException("No saved selection"))
            },
            startConnection = { Result.success(Unit) },
            stopConnection = { Result.success(Unit) },
        ),
        launchTrackedBusyOperation: (suspend () -> Unit) -> Unit = {},
    ): AndroidConnectionActionsService {
        return AndroidConnectionActionsService(
            controller = controller,
            connectionLifecycle = connectionLifecycle,
            launchTrackedBusyOperation = launchTrackedBusyOperation,
        )
    }
}
