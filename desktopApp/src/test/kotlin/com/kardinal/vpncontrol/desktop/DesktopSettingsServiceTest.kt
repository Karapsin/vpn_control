package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.model.AppMode
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlinx.coroutines.test.runTest

class DesktopSettingsServiceTest {
    @Test
    fun saveDnsPersistsDraftsAndClosesDialog() {
        var state = MainUiState(
            customDnsDraft = " 1.1.1.1 ",
            useCustomDnsDraft = true,
            showDnsDialog = true,
        )
        val service = service(
            stateProvider = { state },
            commitState = { state = it },
            updateState = { transform -> state = transform(state) },
        )

        service.saveDns()

        assertEquals("1.1.1.1", state.customDns)
        assertEquals("1.1.1.1", state.customDnsDraft)
        assertEquals(true, state.useCustomDns)
        assertFalse(state.showDnsDialog)
    }

    @Test
    fun setAppModeStopsRunningConnectionBeforeChangingMode() = runTest {
        var state = MainUiState(
            appMode = AppMode.VPN,
            isVpnRunning = true,
            showAppModeDialog = true,
        )
        val stopMessages = mutableListOf<String>()
        val service = service(
            stateProvider = { state },
            commitState = { state = it },
            updateState = { transform -> state = transform(state) },
            stopConnection = {
                stopMessages += it
                state = state.copy(isVpnRunning = false)
                Result.success(Unit)
            },
        )

        service.setAppMode(AppMode.PROXY_ONLY)

        assertEquals(listOf("VPN stopped. App mode: PROXY_ONLY"), stopMessages)
        assertEquals(AppMode.PROXY_ONLY, state.appMode)
        assertFalse(state.showAppModeDialog)
    }

    private fun service(
        stateProvider: () -> MainUiState,
        commitState: (MainUiState) -> Unit,
        updateState: ((MainUiState) -> MainUiState) -> Unit,
        stopConnection: suspend (String) -> Result<Unit> = { Result.success(Unit) },
    ): DesktopSettingsService {
        return DesktopSettingsService(
            stateProvider = stateProvider,
            autostartManager = DesktopAutostartManager(platform = DesktopAutostartPlatform.UNSUPPORTED),
            stopConnection = stopConnection,
            commitState = commitState,
            updateState = updateState,
        )
    }
}
