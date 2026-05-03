package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.model.RoutingStatusMessages
import com.kardinal.vpncontrol.model.AppMode
import kotlin.test.Test
import kotlin.test.assertEquals

class RoutingRulesStatusLogicTest {
    @Test
    fun savedMessageMentionsRestartOnlyWhenConnectionRuns() {
        assertEquals(
            RoutingStatusMessages.routingRulesSaved(),
            RoutingRulesStatusLogic.saved(isConnectionRunning = false, appMode = AppMode.VPN),
        )
        assertEquals(
            RoutingStatusMessages.routingRulesSavedRestartRequired(AppMode.VPN),
            RoutingRulesStatusLogic.saved(isConnectionRunning = true, appMode = AppMode.VPN),
        )
    }

    @Test
    fun importedMessageUsesConnectionModeName() {
        assertEquals(
            RoutingStatusMessages.routingRulesImportedRestartRequired(AppMode.PROXY_ONLY),
            RoutingRulesStatusLogic.imported(isConnectionRunning = true, appMode = AppMode.PROXY_ONLY),
        )
    }
}
