package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.model.SettingsStatusMessages
import com.kardinal.vpncontrol.model.UiSettingsStatusItem
import kotlin.test.Test
import kotlin.test.assertEquals

class UiSettingsStatusLogicTest {
    @Test
    fun statsVisibilityMessagesReflectEnabledState() {
        assertEquals(
            SettingsStatusMessages.uiSettingVisibilityChanged(UiSettingsStatusItem.SESSION_STATS, true),
            UiSettingsStatusLogic.sessionStats(true),
        )
        assertEquals(
            SettingsStatusMessages.uiSettingVisibilityChanged(UiSettingsStatusItem.SESSION_STATS, false),
            UiSettingsStatusLogic.sessionStats(false),
        )
        assertEquals(
            SettingsStatusMessages.uiSettingVisibilityChanged(UiSettingsStatusItem.LIVE_TRAFFIC_STATS, true),
            UiSettingsStatusLogic.liveTrafficStats(true),
        )
        assertEquals(
            SettingsStatusMessages.uiSettingVisibilityChanged(UiSettingsStatusItem.PROFILE_TOTALS, false),
            UiSettingsStatusLogic.profileTotals(false),
        )
        assertEquals(
            SettingsStatusMessages.uiSettingVisibilityChanged(UiSettingsStatusItem.LATENCY_HISTORY, true),
            UiSettingsStatusLogic.latencyHistory(true),
        )
        assertEquals(
            SettingsStatusMessages.uiSettingVisibilityChanged(UiSettingsStatusItem.CONNECTION_LOG, false),
            UiSettingsStatusLogic.connectionLog(false),
        )
        assertEquals(
            SettingsStatusMessages.uiSettingVisibilityChanged(UiSettingsStatusItem.CONNECTION_TEST_TOOLS, true),
            UiSettingsStatusLogic.connectionTestTools(true),
        )
    }
}
