package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.ControlCode
import kotlin.coroutines.AbstractCoroutineContextElement
import kotlin.coroutines.CoroutineContext
import kotlinx.coroutines.currentCoroutineContext

/** Owner-local progress, never a transport object or a persistent retry instruction. */
internal class DesktopOperationProgress(private val publish: (ControlCode?) -> Unit) :
    AbstractCoroutineContextElement(Key) {
    companion object Key : CoroutineContext.Key<DesktopOperationProgress>

    private val guard = Any()
    private val publicationGuard = Any()
    private val retainedInputs = DesktopOperationRetainedInputs()
    private var pendingOutcome = false
    private var terminal = false

    val hasPendingOutcome: Boolean get() = synchronized(guard) { pendingOutcome }
    val hasRetainedInputs: Boolean get() = retainedInputs.hasRetainedInputs

    fun retainInputs(inputs: AutoCloseable) = synchronized(guard) {
        check(!terminal) { "CONFLICT" }
        retainedInputs.retain(inputs)
    }

    fun releaseInputs(inputs: AutoCloseable): Result<Unit> {
        synchronized(guard) {
            if (pendingOutcome) return Result.failure(IllegalStateException("OUTCOME_UNKNOWN"))
        }
        return retainedInputs.release(inputs)
    }

    fun releaseAllTerminal(): Result<Unit> {
        synchronized(guard) {
            if (pendingOutcome) return Result.failure(IllegalStateException("OUTCOME_UNKNOWN"))
            terminal = true
        }
        // Cleanup failure remains owned without changing an established native outcome.
        return retainedInputs.releaseAllTerminal()
    }

    fun pending(code: ControlCode) = synchronized(publicationGuard) {
        require(code in setOf(ControlCode.OUTCOME_UNKNOWN, ControlCode.UNAVAILABLE,
            ControlCode.TIMEOUT, ControlCode.INCOMPATIBLE_PROTOCOL))
        synchronized(guard) {
            check(!terminal) { "CONFLICT" }
            pendingOutcome = true
        }
        // Serialize evidence notifications, but never hold the state lock across the runner callback.
        publish(code)
    }

    fun confirmed() = synchronized(publicationGuard) {
        synchronized(guard) { pendingOutcome = false }
        // Native confirmation alone neither replays recovery nor releases its inputs.
        publish(null)
    }
}

/** Continue reconciliation in the same action after reporting its unresolved native outcome. */
internal suspend fun desktopControlReportPendingOutcome(code: ControlCode = ControlCode.OUTCOME_UNKNOWN) {
    currentCoroutineContext()[DesktopOperationProgress]?.pending(code)
}

/** Call only after native evidence establishes the outcome, including cancellation cleanup. */
internal suspend fun desktopControlConfirmOutcome() {
    currentCoroutineContext()[DesktopOperationProgress]?.confirmed()
}
