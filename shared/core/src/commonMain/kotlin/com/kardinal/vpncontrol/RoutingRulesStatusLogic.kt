package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.model.RoutingStatusMessages
import com.kardinal.vpncontrol.model.AppMode

object RoutingRulesStatusLogic {
    fun saved(isConnectionRunning: Boolean, appMode: AppMode): String {
        return if (isConnectionRunning) {
            RoutingStatusMessages.routingRulesSavedRestartRequired(appMode)
        } else {
            RoutingStatusMessages.routingRulesSaved()
        }
    }

    fun imported(isConnectionRunning: Boolean, appMode: AppMode): String {
        return if (isConnectionRunning) {
            RoutingStatusMessages.routingRulesImportedRestartRequired(appMode)
        } else {
            RoutingStatusMessages.routingRulesImported()
        }
    }

    fun saveFailed(error: Throwable?): String {
        return error?.message ?: RoutingStatusMessages.routingRulesSaveFailed()
    }

    fun importFailed(error: Throwable?): String {
        return error?.message ?: RoutingStatusMessages.routingRulesImportFailed()
    }
}
