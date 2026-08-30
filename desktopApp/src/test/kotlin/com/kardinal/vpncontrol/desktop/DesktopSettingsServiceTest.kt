package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.SettingsStatusMessages
import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.DnsMode
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlinx.coroutines.test.runTest

class DesktopSettingsServiceTest {
    @Test
    fun saveDnsPersistsDraftsAndClosesDialog() {
        var state = MainUiState(
            dnsModeDraft = DnsMode.CUSTOM_DOH,
            customDnsEndpointDraft = " https://dns.example/dns-query ",
            showDnsDialog = true,
        )
        val service = service(
            stateProvider = { state },
            commitState = { state = it },
            updateState = { transform -> state = transform(state) },
        )

        service.saveDns()

        assertEquals(DnsMode.CUSTOM_DOH, state.dnsSettings.mode)
        assertEquals("https://dns.example/dns-query", state.dnsSettings.endpoint)
        assertEquals("https://dns.example/dns-query", state.customDnsEndpointDraft)
        assertFalse(state.showDnsDialog)
    }

    @Test
    fun invalidDnsEndpointKeepsDialogOpen() {
        var state = MainUiState(
            dnsModeDraft = DnsMode.CUSTOM_DOH,
            customDnsEndpointDraft = "http://dns.example/dns-query",
            showDnsDialog = true,
        )
        val service = service(
            stateProvider = { state },
            commitState = { state = it },
            updateState = { transform -> state = transform(state) },
        )

        service.saveDns()

        assertEquals(true, state.showDnsDialog)
        assertEquals(SettingsStatusMessages.customDnsEndpointInvalid(), state.statusMessage)
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

        assertEquals(listOf(SettingsStatusMessages.connectionStoppedForAppMode(AppMode.VPN, AppMode.PROXY_ONLY)), stopMessages)
        assertEquals(AppMode.PROXY_ONLY, state.appMode)
        assertFalse(state.showAppModeDialog)
        assertEquals(SettingsStatusMessages.appModeChanged(AppMode.PROXY_ONLY), state.statusMessage)
    }

    @Test
    fun setSubscriptionHwidUsesStructuredStatusMessages() {
        var state = MainUiState()
        val service = service(
            stateProvider = { state },
            commitState = { state = it },
            updateState = { transform -> state = transform(state) },
        )

        service.setSubscriptionHwid(" abc ")
        assertEquals("abc", state.subscriptionHwid)
        assertEquals(SettingsStatusMessages.subscriptionHwidSaved(), state.statusMessage)

        service.setSubscriptionHwid(" ")
        assertEquals("", state.subscriptionHwid)
        assertEquals(SettingsStatusMessages.subscriptionHwidCleared(), state.statusMessage)
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
