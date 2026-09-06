package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.ControlPlatform
import java.util.Locale

internal fun currentDesktopControlPlatform(): ControlPlatform? {
    val os = System.getProperty("os.name").lowercase(Locale.ROOT)
    return when {
        "mac" in os || "darwin" in os -> ControlPlatform.MACOS
        "win" in os -> ControlPlatform.WINDOWS
        "linux" in os -> ControlPlatform.LINUX
        else -> null
    }
}
