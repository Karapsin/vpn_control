package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.*

/** Cached native facts only. No log scanning, command execution, paths, or raw preflight errors. */
internal data class DesktopRuntimePresentation(
    val mode: AppMode,
    val localProxyPort: Int?,
    val preflightMode: AppMode?,
    val failedPreflightChecks: Int?,
    val outboundStatusAvailable: Boolean = false,
) {
    fun messages(): List<String> = buildList {
        add(RuntimeStatusMessages.runtimeMode(mode.name))
        localProxyPort?.let { add(RuntimeStatusMessages.localProxy("127.0.0.1:$it")) }
        preflightMode?.let { checked -> failedPreflightChecks?.let { failed ->
            add(if (failed == 0) RuntimeStatusMessages.preflightPassed(checked)
                else RuntimeStatusMessages.preflightFailed(checked, failed))
        } }
    }

    fun values() = ControlValue.ObjectValue(mapOf(
        "mode" to ControlValue.Text(mode.name),
        "localProxyPort" to (localProxyPort?.let { ControlValue.IntegerValue(it.toLong()) } ?: ControlValue.Null),
        "preflightMode" to (preflightMode?.let { ControlValue.Text(it.name) } ?: ControlValue.Null),
        "failedPreflightChecks" to (failedPreflightChecks?.let { ControlValue.IntegerValue(it.toLong()) } ?: ControlValue.Null),
        "outboundStatusAvailable" to ControlValue.BooleanValue(outboundStatusAvailable),
    ))

    companion object {
        fun decode(value: ControlValue): DesktopRuntimePresentation {
            val fields = (value as ControlValue.ObjectValue).values
            require(fields.keys == setOf("mode", "localProxyPort", "preflightMode", "failedPreflightChecks", "outboundStatusAvailable"))
            fun mode(key: String): AppMode? = when (val item = fields.getValue(key)) {
                ControlValue.Null -> null
                else -> AppMode.valueOf((item as ControlValue.Text).value)
            }
            fun number(key: String): Int? = when (val item = fields.getValue(key)) {
                ControlValue.Null -> null
                else -> (item as ControlValue.IntegerValue).value.also { require(it in 0..Int.MAX_VALUE.toLong()) }.toInt()
            }
            val port = number("localProxyPort")?.also { require(it in 1..65535) }
            val preflight = mode("preflightMode")
            val failed = number("failedPreflightChecks")
            require((preflight == null) == (failed == null))
            // No cached outbound observation is currently published; don't invent a healthy result.
            require(!(fields.getValue("outboundStatusAvailable") as ControlValue.BooleanValue).value)
            return DesktopRuntimePresentation(requireNotNull(mode("mode")), port, preflight, failed)
        }
    }
}

internal fun safeDesktopReleaseNotesUrl(raw: String): String? = runCatching {
    val uri = java.net.URI(raw)
    require(uri.scheme == "https" && uri.host.equals("github.com", ignoreCase = true) &&
        uri.rawUserInfo == null && uri.rawQuery == null && uri.rawFragment == null && uri.port == -1 &&
        uri.path.startsWith("/Karapsin/vpn_control/releases/"))
    raw
}.getOrNull()
