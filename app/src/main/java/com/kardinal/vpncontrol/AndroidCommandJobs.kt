package com.kardinal.vpncontrol

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

/** Process-owned command lifetime; observing or destroying a frontend never cancels a command. */
class AndroidCommandJobs(
    val scope: CoroutineScope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate),
) {
    private var activeBusyJob: Job? = null
    private var activeCancellable = true
    private var mutationLease: Any? = null
    private val mutableBusy = MutableStateFlow(false)
    val busy = mutableBusy.asStateFlow()

    fun launch(block: suspend () -> Unit): Job = scope.launch { block() }

    /** The caller only waits; cancelling that wait does not cancel the admitted owner command. */
    suspend fun <T : Any> runTracked(block: suspend () -> T): T? {
        val result = CompletableDeferred<T>()
        val job = launchTracked {
            try {
                result.complete(block())
            } catch (error: Throwable) {
                result.completeExceptionally(error)
                if (error is CancellationException) throw error
            }
        } ?: return null
        job.invokeOnCompletion { error ->
            if (error != null) result.completeExceptionally(error)
        }
        return result.await()
    }

    @Synchronized
    fun setBusy(value: Boolean) {
        mutableBusy.value = value || mutationLease != null
    }

    /** Shared admission only; callers retain the lease through owner-job cleanup. */
    @Synchronized internal fun tryAcquireMutation(): Any? {
        if (mutationLease != null || mutableBusy.value) return null
        return Any().also { mutationLease = it; mutableBusy.value = true }
    }

    @Synchronized internal fun releaseMutation(lease: Any) {
        if (mutationLease === lease) {
            mutationLease = null
            mutableBusy.value = false
        }
    }

    fun launchMutation(block: suspend () -> Unit): Job? = launchAdmitted(block, cancellable = false)

    fun launchTracked(block: suspend () -> Unit): Job? = launchAdmitted(block, cancellable = true)

    private fun launchAdmitted(block: suspend () -> Unit, cancellable: Boolean): Job? {
        val job = synchronized(this) {
            val lease = tryAcquireMutation() ?: return null
            val admitted = scope.launch(start = CoroutineStart.LAZY) { block() }
            activeBusyJob = admitted
            activeCancellable = cancellable
            admitted.invokeOnCompletion {
                synchronized(this) {
                    if (activeBusyJob === admitted) {
                        activeBusyJob = null
                        releaseMutation(lease)
                    }
                }
            }
            admitted
        }
        job.start()
        return job
    }

    fun cancelActive() {
        val job = synchronized(this) { activeBusyJob.takeIf { activeCancellable } }
        job?.cancel(CancellationException("Cancelled by user"))
    }
}
