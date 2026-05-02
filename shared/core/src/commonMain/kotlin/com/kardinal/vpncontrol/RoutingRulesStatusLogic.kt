package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.model.AppMode

object RoutingRulesStatusLogic {
    fun saved(isConnectionRunning: Boolean, appMode: AppMode): String {
        return if (isConnectionRunning) {
            "Routing rules saved. Restart ${MainCommandLogic.connectionNoun(appMode)} to apply"
        } else {
            "Routing rules saved"
        }
    }

    fun imported(isConnectionRunning: Boolean, appMode: AppMode): String {
        return if (isConnectionRunning) {
            "Routing rules imported. Restart ${MainCommandLogic.connectionNoun(appMode)} to apply"
        } else {
            "Routing rules imported"
        }
    }

    fun saveFailed(error: Throwable?): String {
        return error?.message ?: "Failed to save routing rules"
    }

    fun importFailed(error: Throwable?): String {
        return error?.message ?: "Failed to import routing rules"
    }
}
