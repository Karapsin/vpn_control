package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.model.StatusMessages
import com.kardinal.vpncontrol.model.UiSettingsStatusItem

object UiSettingsStatusLogic {
    fun sessionStats(enabled: Boolean): String =
        StatusMessages.uiSettingVisibilityChanged(UiSettingsStatusItem.SESSION_STATS, enabled)

    fun liveTrafficStats(enabled: Boolean): String =
        StatusMessages.uiSettingVisibilityChanged(UiSettingsStatusItem.LIVE_TRAFFIC_STATS, enabled)

    fun profileTotals(enabled: Boolean): String =
        StatusMessages.uiSettingVisibilityChanged(UiSettingsStatusItem.PROFILE_TOTALS, enabled)

    fun latencyHistory(enabled: Boolean): String =
        StatusMessages.uiSettingVisibilityChanged(UiSettingsStatusItem.LATENCY_HISTORY, enabled)

    fun connectionLog(enabled: Boolean): String =
        StatusMessages.uiSettingVisibilityChanged(UiSettingsStatusItem.CONNECTION_LOG, enabled)

    fun connectionTestTools(enabled: Boolean): String =
        StatusMessages.uiSettingVisibilityChanged(UiSettingsStatusItem.CONNECTION_TEST_TOOLS, enabled)
}
