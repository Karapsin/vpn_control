package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.model.StatusMessages
import com.kardinal.vpncontrol.model.UiSettingsStatusItem
import kotlin.test.Test
import kotlin.test.assertEquals

class UiSettingsStatusLogicTest {
    @Test
    fun statsVisibilityMessagesReflectEnabledState() {
        assertEquals(
            StatusMessages.uiSettingVisibilityChanged(UiSettingsStatusItem.SESSION_STATS, true),
            UiSettingsStatusLogic.sessionStats(true),
        )
        assertEquals(
            StatusMessages.uiSettingVisibilityChanged(UiSettingsStatusItem.SESSION_STATS, false),
            UiSettingsStatusLogic.sessionStats(false),
        )
        assertEquals(
            StatusMessages.uiSettingVisibilityChanged(UiSettingsStatusItem.LIVE_TRAFFIC_STATS, true),
            UiSettingsStatusLogic.liveTrafficStats(true),
        )
        assertEquals(
            StatusMessages.uiSettingVisibilityChanged(UiSettingsStatusItem.PROFILE_TOTALS, false),
            UiSettingsStatusLogic.profileTotals(false),
        )
        assertEquals(
            StatusMessages.uiSettingVisibilityChanged(UiSettingsStatusItem.LATENCY_HISTORY, true),
            UiSettingsStatusLogic.latencyHistory(true),
        )
        assertEquals(
            StatusMessages.uiSettingVisibilityChanged(UiSettingsStatusItem.CONNECTION_LOG, false),
            UiSettingsStatusLogic.connectionLog(false),
        )
        assertEquals(
            StatusMessages.uiSettingVisibilityChanged(UiSettingsStatusItem.CONNECTION_TEST_TOOLS, true),
            UiSettingsStatusLogic.connectionTestTools(true),
        )
    }
}
