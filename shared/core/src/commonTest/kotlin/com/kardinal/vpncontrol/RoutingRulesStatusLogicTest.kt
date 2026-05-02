package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.model.AppMode
import kotlin.test.Test
import kotlin.test.assertEquals

class RoutingRulesStatusLogicTest {
    @Test
    fun savedMessageMentionsRestartOnlyWhenConnectionRuns() {
        assertEquals(
            "Routing rules saved",
            RoutingRulesStatusLogic.saved(isConnectionRunning = false, appMode = AppMode.VPN),
        )
        assertEquals(
            "Routing rules saved. Restart VPN to apply",
            RoutingRulesStatusLogic.saved(isConnectionRunning = true, appMode = AppMode.VPN),
        )
    }

    @Test
    fun importedMessageUsesConnectionModeName() {
        assertEquals(
            "Routing rules imported. Restart proxy to apply",
            RoutingRulesStatusLogic.imported(isConnectionRunning = true, appMode = AppMode.PROXY_ONLY),
        )
    }
}
