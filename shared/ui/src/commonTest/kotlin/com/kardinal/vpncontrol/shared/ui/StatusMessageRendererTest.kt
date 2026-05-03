package com.kardinal.vpncontrol.shared.ui

import com.kardinal.vpncontrol.model.SubscriptionStatusMessages
import com.kardinal.vpncontrol.model.SettingsStatusMessages
import com.kardinal.vpncontrol.model.AppLanguage
import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.StatusMessageKey
import com.kardinal.vpncontrol.model.StatusMessages
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class StatusMessageRendererTest {
    @Test
    fun structuredRendererLocalizesNestedStatusArguments() {
        val message = SubscriptionStatusMessages.backgroundRefreshReplacementFailed(
            appMode = AppMode.VPN,
            failureMessage = SubscriptionStatusMessages.replacementLocationSearchFailed(),
            failedLabel = null,
            selectedSourceFailed = false,
            rollbackMessage = SubscriptionStatusMessages.backgroundRefreshPreviousLocationKept(AppMode.VPN),
        )

        val rendered = AppStrings(AppLanguage.ENGLISH).statusMessage(message)

        assertTrue(rendered.contains("Failed to find a replacement location"))
        assertTrue(rendered.contains("Previous VPN location kept"))
    }

    @Test
    fun structuredTemplateKeysUseDetailVariantsBeforeFallback() {
        val status = StatusMessages.decode(SettingsStatusMessages.startupSettingUpdateFailed("denied"))!!

        assertEquals(
            listOf(
                "${StatusMessageKey.STARTUP_SETTING_UPDATE_FAILED.name}.DETAIL",
                StatusMessageKey.STARTUP_SETTING_UPDATE_FAILED.name,
            ),
            structuredStatusTemplateKeys(status),
        )
    }

    @Test
    fun refreshIntervalFormatterUsesStatusCatalogTemplates() {
        assertEquals("every 30 min", formatLocalizedRefreshInterval(30, AppLanguage.ENGLISH, includeEvery = true))
        assertEquals("every hour", formatLocalizedRefreshInterval(60, AppLanguage.ENGLISH, includeEvery = true))
    }
}
