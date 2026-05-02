package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.MainCommandLogic
import com.kardinal.vpncontrol.model.AppMode

internal object DesktopConnectionNameLogic {
    fun activeConnectionName(
        currentRuntimeMode: AppMode?,
        configuredMode: AppMode,
    ): String = MainCommandLogic.connectionDisplayName(currentRuntimeMode ?: configuredMode)
}
