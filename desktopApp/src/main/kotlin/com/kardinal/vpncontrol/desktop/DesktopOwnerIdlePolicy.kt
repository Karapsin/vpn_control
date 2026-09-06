package com.kardinal.vpncontrol.desktop

/** Access under the lifecycle lock. Idle time starts after the last owned activity. */
internal class DesktopOwnerIdlePolicy(
    private val persistent: Boolean,
    private val nowMillis: () -> Long,
    private val idleTimeoutMillis: Long = 30_000,
) {
    private var lastActivity = nowMillis()

    fun activity() { lastActivity = nowMillis() }

    fun shouldExit(hasWork: Boolean): Boolean {
        if (persistent || hasWork) { activity(); return false }
        return nowMillis() - lastActivity >= idleTimeoutMillis
    }
}
