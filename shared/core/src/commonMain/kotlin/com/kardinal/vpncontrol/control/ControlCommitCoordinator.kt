package com.kardinal.vpncontrol.control

import com.kardinal.vpncontrol.model.ControlCode
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.withContext

data class ControlCommitted<T>(val controllerId: String, val revision: Long, val value: T) {
    override fun toString(): String = "ControlCommitted(revision=$revision, value=<redacted>)"
}

sealed interface ControlCommitResult<out T> {
    data class Applied<T>(val committed: ControlCommitted<T>, val changed: Boolean) : ControlCommitResult<T>
    data class Rejected(val code: ControlCode) : ControlCommitResult<Nothing>
}

/**
 * Durable publication boundary shared by GUI and CLI owners. T is committed storage state,
 * never a GUI draft. configurationIdentity excludes telemetry and operation progress.
 * Platform persistence must atomically retain either the old or new state on failure.
 */
class ControlCommitCoordinator<T>(
    controllerId: String,
    initial: T,
    private val configurationIdentity: (T) -> Any?,
    private val persist: suspend (T) -> Result<Unit>,
) {
    private val mutation = Mutex()
    private val mutable = MutableStateFlow(ControlCommitted(controllerId, 0L, initial))
    val committed: StateFlow<ControlCommitted<T>> = mutable.asStateFlow()

    init { require(controllerId.isNotBlank()) }

    suspend fun commit(
        expectedControllerId: String? = null,
        expectedRevision: Long? = null,
        propose: (T) -> T,
    ): ControlCommitResult<T> {
        currentCoroutineContext().ensureActive()
        if (!mutation.tryLock()) return ControlCommitResult.Rejected(ControlCode.BUSY)
        try {
            val prior = mutable.value
            if ((expectedControllerId != null && expectedControllerId != prior.controllerId) ||
                (expectedRevision != null && (expectedControllerId == null || expectedRevision != prior.revision))) {
                return ControlCommitResult.Rejected(ControlCode.CONFLICT)
            }
            val next = propose(prior.value)
            if (next == prior.value) return ControlCommitResult.Applied(prior, changed = false)
            val configurationChanged = configurationIdentity(next) != configurationIdentity(prior.value)
            if (configurationChanged && prior.revision == Long.MAX_VALUE) return ControlCommitResult.Rejected(ControlCode.CONFLICT)
            val published = ControlCommitted(prior.controllerId, prior.revision + if (configurationChanged) 1 else 0, next)
            // Cancellation before this point is allowed. Once the durable write begins, finish
            // publishing its result; otherwise memory and disk could disagree after cancellation.
            currentCoroutineContext().ensureActive()
            return withContext(NonCancellable) {
                val result = persist(next)
                if (result.isFailure) ControlCommitResult.Rejected(ControlCode.PERSISTENCE_FAILED)
                else {
                    mutable.value = published
                    ControlCommitResult.Applied(published, changed = true)
                }
            }
        } finally {
            mutation.unlock()
        }
    }
}
