package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.StatusMessages
import com.kardinal.vpncontrol.model.UiSettingsStatusItem
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class AndroidSettingsActionsServiceTest {
    @Test
    fun setSessionStatsEnabledPersistsAndReportsStatus() {
        val controller = MainController()
        val statuses = mutableListOf<String>()
        var persisted: Boolean? = null
        val service = service(
            controller = controller,
            updateStatus = { statuses += it },
            updateSessionStatsEnabled = { persisted = it },
        )

        service.setSessionStatsEnabled(true)

        assertTrue(controller.currentState().sessionStatsEnabled)
        assertEquals(true, persisted)
        assertEquals(
            listOf(StatusMessages.uiSettingVisibilityChanged(UiSettingsStatusItem.SESSION_STATS, true)),
            statuses,
        )
    }

    @Test
    fun setAppModeForwardsControllerEffects() {
        val controller = MainController(MainUiState(isVpnRunning = true, appMode = AppMode.VPN))
        val effects = mutableListOf<MainControllerEffect>()
        val service = service(
            controller = controller,
            effectSink = AndroidControllerEffectSink { effects += it },
        )

        service.setAppMode(AppMode.PROXY_ONLY)

        assertEquals(AppMode.VPN, controller.currentState().appMode)
        assertEquals(
            listOf(MainControllerEffect.UpdateStatus("Disconnect first to change connection mode")),
            effects,
        )
    }

    @Test
    fun saveDnsForwardsPersistableEffect() {
        val controller = MainController(
            MainUiState(
                customDnsDraft = " 1.1.1.1 ",
                useCustomDnsDraft = true,
                showDnsDialog = true,
            ),
        )
        val effects = mutableListOf<MainControllerEffect>()
        val service = service(
            controller = controller,
            effectSink = AndroidControllerEffectSink { effects += it },
        )

        service.saveDns()

        assertEquals(false, controller.currentState().showDnsDialog)
        assertEquals(
            listOf(
                MainControllerEffect.SaveDns(
                    dns = "1.1.1.1",
                    enabled = true,
                    statusMessage = StatusMessages.customDnsSaved(true),
                ),
            ),
            effects,
        )
    }

    private fun service(
        controller: MainController,
        effectSink: AndroidControllerEffectSink = AndroidControllerEffectSink {},
        updateStatus: suspend (String) -> Unit = {},
        updateSessionStatsEnabled: suspend (Boolean) -> Unit = {},
    ): AndroidSettingsActionsService {
        return AndroidSettingsActionsService(
            controller = controller,
            effectSink = effectSink,
            launch = { block -> runBlocking { block() } },
            updateStatus = updateStatus,
            updateSessionStatsEnabled = updateSessionStatsEnabled,
            updateLiveTrafficStatsEnabled = {},
            updateProfileTotalsEnabled = {},
            updateLatencyHistoryEnabled = {},
            updateConnectionLogEnabled = {},
            updateConnectionTestToolsEnabled = {},
        )
    }
}
