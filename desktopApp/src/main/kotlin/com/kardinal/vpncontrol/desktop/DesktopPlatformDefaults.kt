package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.AppMode

internal fun defaultDesktopAppMode(osName: String = System.getProperty("os.name")): AppMode {
    return if (isMacOsDesktop(osName)) {
        AppMode.PROXY_ONLY
    } else {
        AppMode.VPN
    }
}

internal fun isMacOsDesktop(osName: String = System.getProperty("os.name")): Boolean {
    val normalized = osName.lowercase()
    return normalized.contains("mac") || normalized.contains("darwin")
}
