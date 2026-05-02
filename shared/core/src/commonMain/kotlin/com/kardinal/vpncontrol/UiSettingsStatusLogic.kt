package com.kardinal.vpncontrol

object UiSettingsStatusLogic {
    fun sessionStats(enabled: Boolean): String =
        if (enabled) "Session stats enabled" else "Session stats hidden"

    fun liveTrafficStats(enabled: Boolean): String =
        if (enabled) "Live traffic stats enabled" else "Live traffic stats hidden"

    fun profileTotals(enabled: Boolean): String =
        if (enabled) "Per-profile totals enabled" else "Per-profile totals hidden"

    fun latencyHistory(enabled: Boolean): String =
        if (enabled) "Latency history enabled" else "Latency history hidden"

    fun connectionLog(enabled: Boolean): String =
        if (enabled) "Connection log enabled" else "Connection log hidden"

    fun connectionTestTools(enabled: Boolean): String =
        if (enabled) "Connection test tools enabled" else "Connection test tools hidden"
}
