package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.model.SettingsStatusMessages
import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.RoutingStatusMessages
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
            listOf(SettingsStatusMessages.uiSettingVisibilityChanged(UiSettingsStatusItem.SESSION_STATS, true)),
            statuses,
        )
    }

    @Test
    fun setAppModePersistsWhenConnectionIsStopped() {
        val controller = MainController(MainUiState(appMode = AppMode.VPN))
        val effects = mutableListOf<MainControllerEffect>()
        val service = service(
            controller = controller,
            effectSink = AndroidControllerEffectSink { effects += it },
        )

        service.setAppMode(AppMode.PROXY_ONLY)

        assertEquals(AppMode.PROXY_ONLY, controller.currentState().appMode)
        assertEquals(
            listOf(
                MainControllerEffect.UpdateAppMode(AppMode.PROXY_ONLY),
                MainControllerEffect.UpdateStatus(RoutingStatusMessages.connectionModeSet(AppMode.PROXY_ONLY)),
            ),
            effects,
        )
    }

    @Test
    fun setAppModeStopsRunningConnectionBeforePersistingMode() {
        val controller = MainController(
            MainUiState(
                isVpnRunning = true,
                appMode = AppMode.VPN,
                showAppModeDialog = true,
            ),
        )
        val effects = mutableListOf<MainControllerEffect>()
        var stopCalls = 0
        val service = service(
            controller = controller,
            effectSink = AndroidControllerEffectSink { effects += it },
            stopConnection = {
                stopCalls += 1
                Result.success(Unit)
            },
        )

        service.setAppMode(AppMode.PROXY_ONLY)

        assertEquals(1, stopCalls)
        assertEquals(false, controller.currentState().isVpnRunning)
        assertEquals(false, controller.currentState().showAppModeDialog)
        assertEquals(AppMode.PROXY_ONLY, controller.currentState().appMode)
        assertEquals(
            listOf(
                MainControllerEffect.UpdateAppMode(AppMode.PROXY_ONLY),
                MainControllerEffect.UpdateStatus(RoutingStatusMessages.connectionModeSet(AppMode.PROXY_ONLY)),
            ),
            effects,
        )
    }

    @Test
    fun setAppModeKeepsCurrentModeWhenRunningConnectionStopFails() {
        val controller = MainController(MainUiState(isVpnRunning = true, appMode = AppMode.VPN))
        val effects = mutableListOf<MainControllerEffect>()
        val statuses = mutableListOf<String>()
        val service = service(
            controller = controller,
            effectSink = AndroidControllerEffectSink { effects += it },
            stopConnection = { Result.failure(IllegalStateException("stop failed")) },
            updateStatus = { statuses += it },
        )

        service.setAppMode(AppMode.PROXY_ONLY)

        assertEquals(AppMode.VPN, controller.currentState().appMode)
        assertEquals(true, controller.currentState().isVpnRunning)
        assertEquals(emptyList<MainControllerEffect>(), effects)
        assertEquals(listOf("stop failed"), statuses)
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
                    statusMessage = SettingsStatusMessages.customDnsSaved(true),
                ),
            ),
            effects,
        )
    }

    private fun service(
        controller: MainController,
        effectSink: AndroidControllerEffectSink = AndroidControllerEffectSink {},
        stopConnection: suspend () -> Result<Unit> = { Result.success(Unit) },
        updateStatus: suspend (String) -> Unit = {},
        updateSessionStatsEnabled: suspend (Boolean) -> Unit = {},
    ): AndroidSettingsActionsService {
        return AndroidSettingsActionsService(
            controller = controller,
            effectSink = effectSink,
            launch = { block -> runBlocking { block() } },
            stopConnection = stopConnection,
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
