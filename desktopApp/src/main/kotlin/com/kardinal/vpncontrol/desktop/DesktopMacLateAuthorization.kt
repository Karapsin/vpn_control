package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.ControlCode

/**
 * Owner-maintenance-only reconciliation for a coordinator that answered after the initial
 * authorization wait timed out. It never treats process exit as cancellation evidence.
 */
internal class DesktopMacLateAuthorization(
    private val ownerId: String,
    private val lifetime: DesktopMacAuthorizationLifetime,
    private val requireReceiptAbsent: () -> Unit,
    private val stopWatcher: () -> Boolean,
    private val closePrepared: () -> Unit,
    private val markNotStarted: (ControlCode) -> Unit,
    private val onCancellationConfirmed: () -> Unit,
) {
    private var completed = false

    @Synchronized fun isCompleted(): Boolean = completed

    @Synchronized fun reconcile(currentOwnerId: String): Result<Unit> = runCatching {
        if (completed || currentOwnerId != ownerId) return@runCatching
        val code = lifetime.lateAuthorization() ?: return@runCatching
        // A protected receipt wins over a locally observed authorization reply. Do this before
        // changing the original-user watcher, then markNotStarted repeats the check atomically.
        requireReceiptAbsent()
        check(stopWatcher()) { ControlCode.OUTCOME_UNKNOWN.name }
        closePrepared()
        markNotStarted(code)
        completed = true
        onCancellationConfirmed()
    }
}
