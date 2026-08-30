package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.model.RoutingStatusMessages
import com.kardinal.vpncontrol.model.GeneralStatusMessages
import com.kardinal.vpncontrol.model.ConnectionStatusMessages
import com.kardinal.vpncontrol.model.AppLanguage
import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.DnsMode
import com.kardinal.vpncontrol.model.SettingsStatusMessages
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse

class MainControllerTest {
    @Test
    fun invalidSecureDnsEndpointStaysEditable() {
        val controller = MainController(
            MainUiState(
                dnsModeDraft = DnsMode.CUSTOM_DOH,
                customDnsEndpointDraft = "http://dns.example/dns-query",
                showDnsDialog = true,
            ),
        )

        val effects = controller.saveDns()

        assertEquals(true, controller.currentState().showDnsDialog)
        assertEquals(
            listOf(MainControllerEffect.UpdateStatus(SettingsStatusMessages.customDnsEndpointInvalid())),
            effects,
        )
    }

    @Test
    fun setAppLanguageClosesDialogAndEmitsPersistableEffect() {
        val controller = MainController(
            MainUiState(
                appLanguage = AppLanguage.ENGLISH,
                showLanguageDialog = true,
            ),
        )

        val effects = controller.setAppLanguage(AppLanguage.RUSSIAN)

        assertEquals(AppLanguage.RUSSIAN, controller.currentState().appLanguage)
        assertFalse(controller.currentState().showLanguageDialog)
        assertEquals(1, effects.size)
        assertEquals(
            MainControllerEffect.UpdateAppLanguage(
                language = AppLanguage.RUSSIAN,
                statusMessage = GeneralStatusMessages.languageSet(AppLanguage.RUSSIAN.nativeName),
            ),
            effects.single(),
        )
    }

    @Test
    fun setAppModeRequiresStoppedConnection() {
        val controller = MainController(
            MainUiState(
                appMode = AppMode.VPN,
                isVpnRunning = true,
                showAppModeDialog = true,
            ),
        )

        val effects = controller.setAppMode(AppMode.PROXY_ONLY)

        assertEquals(AppMode.VPN, controller.currentState().appMode)
        assertEquals(true, controller.currentState().showAppModeDialog)
        assertEquals(
            listOf(MainControllerEffect.UpdateStatus(ConnectionStatusMessages.disconnectFirstChangeConnectionMode())),
            effects,
        )
    }

    @Test
    fun deleteProfileHistoryEntryEmitsPersistableEffectAndClosesMatchingRenameDialog() {
        val controller = MainController(
            MainUiState(
                showProfileHistoryRenameDialog = true,
                profileHistoryRenameSource = "https://example.com/sub",
                profileHistoryRenameUrlDraft = "https://example.com/sub",
                profileHistoryRenameDraft = "Example",
            ),
        )

        val effects = controller.deleteProfileHistoryEntry(" https://example.com/sub ")

        assertFalse(controller.currentState().showProfileHistoryRenameDialog)
        assertEquals("", controller.currentState().profileHistoryRenameSource)
        assertEquals("", controller.currentState().profileHistoryRenameUrlDraft)
        assertEquals("", controller.currentState().profileHistoryRenameDraft)
        assertEquals(
            listOf(
                MainControllerEffect.DeleteProfileHistoryEntry(
                    source = "https://example.com/sub",
                    statusMessage = RoutingStatusMessages.historyEntryDeleted(),
                ),
            ),
            effects,
        )
    }
}
