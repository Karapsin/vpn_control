package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.model.SettingsStatusMessages
import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.DnsMode
import com.kardinal.vpncontrol.model.DnsSettings
import com.kardinal.vpncontrol.model.RoutingStatusMessages
import com.kardinal.vpncontrol.model.UiSettingsStatusItem
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runCurrent
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class AndroidSettingsActionsServiceTest {
    @Test fun unchangedSshSaveCannotClearImportedKeyRestartWarning() {
        val settings = com.kardinal.vpncontrol.model.HomeSshRouteSettings(credentialVersion = 1)
        val controller = MainController(MainUiState(isVpnRunning = true, homeSshRouteSettings = settings,
            homeSshRestartPending = true, showHomeSshRouteDialog = true))
        var writtenVersion: Long? = null
        service(controller, updateHomeSshRouteSettings = { writtenVersion = it.credentialVersion },
            homeSshPendingRestart = { assertEquals(1L, writtenVersion); true }).saveHomeSshRoute()
        assertEquals(1L, writtenVersion)
        assertTrue(controller.currentState().homeSshRestartPending)
        assertTrue(controller.currentState().showHomeSshRestartDialog)
    }
    @Test fun actualRevertClearsWarningButUnknownRuntimeCannotClearIt() {
        for (knownPending in listOf(false, true, null)) {
            val controller = MainController(MainUiState(isVpnRunning = true, homeSshRestartPending = true,
                showHomeSshRouteDialog = true, showHomeSshRestartDialog = true,
                homeSshRouteSettings = com.kardinal.vpncontrol.model.HomeSshRouteSettings(credentialVersion = 4)))
            var saved = false
            service(controller, updateHomeSshRouteSettings = { saved = true; assertEquals(4, it.credentialVersion) },
                homeSshPendingRestart = { assertTrue(saved); knownPending }).saveHomeSshRoute()
            assertEquals(knownPending ?: true, controller.currentState().homeSshRestartPending)
            assertEquals(knownPending ?: true, controller.currentState().showHomeSshRestartDialog)
            assertEquals(4, controller.currentState().homeSshRouteSettings.credentialVersion)
            org.junit.Assert.assertFalse(controller.currentState().showHomeSshRouteDialog)
        }
    }
    @Test fun failedPostSaveObservationIsConservativeWithoutUndoingCommittedSave() {
        val controller = MainController(MainUiState(showHomeSshRouteDialog = true))
        var writes = 0
        service(controller, updateHomeSshRouteSettings = { writes++ },
            homeSshPendingRestart = { throw java.io.IOException("PRIVATE_FAILURE") }).saveHomeSshRoute()
        assertEquals(1, writes)
        assertTrue(controller.currentState().homeSshRestartPending)
        assertTrue(controller.currentState().showHomeSshRestartDialog)
        org.junit.Assert.assertFalse(controller.currentState().showHomeSshRouteDialog)
    }
    @OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
    @Test fun sshSaveKeepsDraftOnBusyAndOwnsLeaseUntilPersistenceCompletes() = kotlinx.coroutines.test.runTest {
        val jobs = AndroidCommandJobs(backgroundScope)
        val gate = kotlinx.coroutines.CompletableDeferred<Unit>()
        val controller = MainController(MainUiState(showHomeSshRouteDialog = true))
        var writes = 0
        val service = service(controller, launchMutation = { jobs.launchMutation(it) },
            updateHomeSshRouteSettings = { writes++; gate.await() })
        val lease = requireNotNull(jobs.tryAcquireMutation())
        service.saveHomeSshRoute()
        service.importHomeSshPrivateKey("not-a-real-key")
        runCurrent()
        assertEquals(0, writes)
        assertTrue(controller.currentState().showHomeSshRouteDialog)
        jobs.releaseMutation(lease)
        service.saveHomeSshRoute()
        runCurrent()
        assertEquals(1, writes)
        assertTrue(controller.currentState().showHomeSshRouteDialog)
        jobs.cancelActive()
        org.junit.Assert.assertNull(jobs.tryAcquireMutation())
        gate.complete(Unit)
        runCurrent()
        org.junit.Assert.assertFalse(controller.currentState().showHomeSshRouteDialog)
        org.junit.Assert.assertFalse(jobs.busy.value)
    }
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
                dnsModeDraft = DnsMode.CUSTOM_DOH,
                customDnsEndpointDraft = " https://dns.example/dns-query ",
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
                    settings = DnsSettings(
                        mode = DnsMode.CUSTOM_DOH,
                        endpoint = "https://dns.example/dns-query",
                    ),
                    statusMessage = SettingsStatusMessages.dnsSettingsSaved(DnsMode.CUSTOM_DOH),
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
        launchMutation: (suspend () -> Unit) -> Unit = { block -> runBlocking { block() } },
        updateHomeSshRouteSettings: suspend (com.kardinal.vpncontrol.model.HomeSshRouteSettings) -> Unit = {},
        homeSshPendingRestart: suspend () -> Boolean? = { null },
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
            launchMutation = launchMutation,
            updateHomeSshRouteSettings = updateHomeSshRouteSettings,
            homeSshPendingRestart = homeSshPendingRestart,
        )
    }
}
