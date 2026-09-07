package com.kardinal.vpncontrol.vpn

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.cancel
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/** Serializes final service cleanup with an already admitted native command. */
internal class AndroidVpnServiceCleanup(
    private val scope: CoroutineScope,
    private val mutex: Mutex,
    private val cleanup: suspend (String?) -> Unit,
) {
    // These two hooks are called while holding the same command mutex.
    private var stopAcknowledged = false
    fun runtimeWorkStarted() { stopAcknowledged = false }
    fun stopped() { stopAcknowledged = true }

    @Volatile var finishing: Boolean = false
        private set

    @Synchronized fun finish(status: String?) {
        if (finishing) return
        finishing = true
        // Android invokes destruction/revocation on main. A DataStore transaction
        // can already be waiting to resume its owner caller there. Blocking main
        // while acquiring the command mutex or writing stop telemetry deadlocks it.
        // Keep cleanup alive through service cancellation, then release the scope.
        scope.launch(NonCancellable) {
            try {
                mutex.withLock {
                    // A stopped instance can be destroyed after another instance
                    // has restored the runtime. Never repeat its completed stop.
                    if (!stopAcknowledged) cleanup(status)
                }
            } finally {
                scope.cancel()
            }
        }
    }
}
