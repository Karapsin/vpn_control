package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.StatusMessages
import kotlin.test.Test
import kotlin.test.assertEquals

class RoutingRulesStatusLogicTest {
    @Test
    fun savedMessageMentionsRestartOnlyWhenConnectionRuns() {
        assertEquals(
            StatusMessages.routingRulesSaved(),
            RoutingRulesStatusLogic.saved(isConnectionRunning = false, appMode = AppMode.VPN),
        )
        assertEquals(
            StatusMessages.routingRulesSavedRestartRequired(AppMode.VPN),
            RoutingRulesStatusLogic.saved(isConnectionRunning = true, appMode = AppMode.VPN),
        )
    }

    @Test
    fun importedMessageUsesConnectionModeName() {
        assertEquals(
            StatusMessages.routingRulesImportedRestartRequired(AppMode.PROXY_ONLY),
            RoutingRulesStatusLogic.imported(isConnectionRunning = true, appMode = AppMode.PROXY_ONLY),
        )
    }
}
