package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.StatusMessages

object RoutingRulesStatusLogic {
    fun saved(isConnectionRunning: Boolean, appMode: AppMode): String {
        return if (isConnectionRunning) {
            StatusMessages.routingRulesSavedRestartRequired(appMode)
        } else {
            StatusMessages.routingRulesSaved()
        }
    }

    fun imported(isConnectionRunning: Boolean, appMode: AppMode): String {
        return if (isConnectionRunning) {
            StatusMessages.routingRulesImportedRestartRequired(appMode)
        } else {
            StatusMessages.routingRulesImported()
        }
    }

    fun saveFailed(error: Throwable?): String {
        return error?.message ?: StatusMessages.routingRulesSaveFailed()
    }

    fun importFailed(error: Throwable?): String {
        return error?.message ?: StatusMessages.routingRulesImportFailed()
    }
}
