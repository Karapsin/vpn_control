package com.kardinal.vpncontrol.desktop

import java.util.Properties

internal data class DesktopBuildInfo(
    val buildNumber: Int,
    val displayVersion: String,
) {
    companion object {
        fun current(): DesktopBuildInfo {
            val properties = Properties()
            DesktopBuildInfo::class.java.getResourceAsStream("/vpn-control-version.properties")?.use(properties::load)
            return DesktopBuildInfo(
                buildNumber = properties.getProperty("buildNumber")?.toIntOrNull()?.coerceAtLeast(1) ?: 1,
                displayVersion = properties.getProperty("displayVersion")?.takeIf(String::isNotBlank) ?: "development",
            )
        }
    }
}
