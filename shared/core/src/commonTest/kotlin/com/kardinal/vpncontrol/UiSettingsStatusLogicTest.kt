package com.kardinal.vpncontrol

import kotlin.test.Test
import kotlin.test.assertEquals

class UiSettingsStatusLogicTest {
    @Test
    fun statsVisibilityMessagesReflectEnabledState() {
        assertEquals("Session stats enabled", UiSettingsStatusLogic.sessionStats(true))
        assertEquals("Session stats hidden", UiSettingsStatusLogic.sessionStats(false))
        assertEquals("Live traffic stats enabled", UiSettingsStatusLogic.liveTrafficStats(true))
        assertEquals("Per-profile totals hidden", UiSettingsStatusLogic.profileTotals(false))
        assertEquals("Latency history enabled", UiSettingsStatusLogic.latencyHistory(true))
        assertEquals("Connection log hidden", UiSettingsStatusLogic.connectionLog(false))
        assertEquals("Connection test tools enabled", UiSettingsStatusLogic.connectionTestTools(true))
    }
}
