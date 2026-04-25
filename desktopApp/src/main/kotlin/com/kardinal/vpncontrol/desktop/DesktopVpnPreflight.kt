package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.AppMode

enum class DesktopPreflightStatus {
    PASS,
    FAIL,
    SKIP,
}

data class DesktopPreflightCheck(
    val name: String,
    val status: DesktopPreflightStatus,
    val detail: String,
) {
    fun line(): String {
        return "${status.name.lowercase()} $name: $detail"
    }
}

data class DesktopPreflightReport(
    val appMode: AppMode,
    val checks: List<DesktopPreflightCheck>,
) {
    val isReady: Boolean
        get() = checks.none { it.status == DesktopPreflightStatus.FAIL }

    fun summary(): String {
        val failed = checks.count { it.status == DesktopPreflightStatus.FAIL }
        return if (failed == 0) {
            "${label()} preflight passed"
        } else {
            "${label()} preflight failed: $failed check${if (failed == 1) "" else "s"}"
        }
    }

    fun failureMessage(): String {
        val failed = checks.firstOrNull { it.status == DesktopPreflightStatus.FAIL }
        return if (failed == null) {
            summary()
        } else {
            "${label()} unavailable: ${failed.detail}"
        }
    }

    fun lines(): List<String> {
        return listOf(summary()) + checks.map { it.line() }
    }

    private fun label(): String {
        return when (appMode) {
            AppMode.VPN -> "VPN mode"
            AppMode.PROXY_ONLY -> "Proxy-only mode"
        }
    }
}
