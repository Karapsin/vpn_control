package com.kardinal.vpncontrol

/** Explicit interaction preparation for one journaled OS session; never creates a session. */
internal class AndroidInstallConfirmationRecovery<C : Any>(
    private val lifecycle: AndroidInstallSessionLifecycle,
    private val confirmation: (AndroidInstallSessionReceipt) -> C?,
    private val validateSession: (AndroidInstallSessionReceipt) -> Unit,
    private val commit: (AndroidInstallSessionReceipt) -> Unit,
    private val awaitChange: suspend (() -> Boolean) -> Unit,
) {
    suspend fun prepare(): C {
        val before = lifecycle.snapshot()
        check(before.phase in setOf(AndroidInstallSessionPhase.STAGED,
            AndroidInstallSessionPhase.COMMITTING, AndroidInstallSessionPhase.AWAITING_CONFIRMATION,
            AndroidInstallSessionPhase.HANDED_OFF)) { "INSTALL_OUTCOME_UNKNOWN" }
        validateSession(before)
        check(!lifecycle.snapshot().terminal && lifecycle.snapshot().phase != AndroidInstallSessionPhase.UNKNOWN) {
            "INSTALL_OUTCOME_UNKNOWN"
        }
        var ready: C? = confirmation(before)
        if (before.phase == AndroidInstallSessionPhase.STAGED) {
            lifecycle.beforeCommit()
            commit(before)
        } else if (ready == null) {
            // Android retains PendingIntent records weakly. After process loss an
            // explicit retry can request a fresh callback from this same sealed
            // session. The existing journal phase and installation identity stay put.
            commit(before)
        }
        awaitChange {
            val current = lifecycle.snapshot()
            ready = confirmation(current)
            current.terminal || current.phase == AndroidInstallSessionPhase.UNKNOWN ||
                current.phase in setOf(AndroidInstallSessionPhase.AWAITING_CONFIRMATION,
                    AndroidInstallSessionPhase.HANDED_OFF) && ready != null
        }
        check(lifecycle.snapshot().phase in setOf(AndroidInstallSessionPhase.AWAITING_CONFIRMATION,
            AndroidInstallSessionPhase.HANDED_OFF)) { "INSTALL_OUTCOME_UNKNOWN" }
        return checkNotNull(ready) { "INSTALL_CONFIRMATION_UNAVAILABLE" }
    }
}
