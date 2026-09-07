package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.ControlCode
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.sync.Mutex

/** A platform adapter returns this only after actual authorization and protected worker readiness. */
internal interface DesktopPreparedInstall : AutoCloseable {
    val jobId: String
    /** Commit to waiting for identified processes to exit, never permission to replace a live image. */
    suspend fun commit(): Result<Unit>
    fun cancel(): Result<Unit>
}

internal data class DesktopInstallHandoffResult(val code: ControlCode, val jobId: String? = null)

/** A worker exists even though readiness failed; its identity and cancellation must remain owned. */
internal class DesktopInstallPreparationFailure(val prepared: DesktopPreparedInstall, cause: Throwable) :
    IllegalStateException(cause.message, cause)

/**
 * Owner-scoped ordering; platform admission, authentication and replacement remain worker duties.
 * Invoke from the owner mutation lane. Close only after that lane has stopped, as with its service.
 * Successful preparation is a handoff, not evidence that any package has been installed.
 */
internal class DesktopInstallHandoff(
    private val prepare: suspend () -> Result<DesktopPreparedInstall>,
    private val stopRuntime: suspend () -> Result<Unit>,
    private val requestExit: (String) -> Unit,
) : AutoCloseable {
    private val admission = Mutex()
    private var worker: DesktopPreparedInstall? = null
    private var committed = false
    private var closed = false
    private var uncertainCancellation = false
    private var validatedJobId: String? = null

    suspend fun prepare(requestId: String): DesktopInstallHandoffResult {
        require(requestId.isNotBlank() && requestId.length <= 256)
        if (!admission.tryLock()) return DesktopInstallHandoffResult(ControlCode.BUSY)
        try {
            if (closed || uncertainCancellation || worker != null) return DesktopInstallHandoffResult(ControlCode.BUSY)
            validatedJobId = null
            val prepared = prepare().getOrElse {
                if (it is DesktopInstallPreparationFailure) {
                    worker = it.prepared
                    validatedJobId = it.prepared.jobId.takeIf(DesktopInstallJobNames::validJob)
                    throw it
                }
                return DesktopInstallHandoffResult(code(it))
            }
            worker = prepared
            val jobId = prepared.jobId
            require(DesktopInstallJobNames.validJob(jobId))
            validatedJobId = jobId
            stopRuntime().getOrThrow()
            prepared.commit().getOrThrow()
            requestExit(requestId)
            committed = true
            return DesktopInstallHandoffResult(ControlCode.OK, jobId)
        } catch (cancelled: CancellationException) {
            // Coroutine interruption is not proof that the external worker stopped.
            // Keep the exact job recoverable instead of allowing a caller to infer
            // a terminal CANCELLED outcome from this exception.
            if (!abandon()) return DesktopInstallHandoffResult(ControlCode.OUTCOME_UNKNOWN, validatedJobId)
            throw cancelled
        } catch (failure: Exception) {
            if (failure is DesktopInstallPreparationFailure && worker == null) {
                worker = failure.prepared
                validatedJobId = failure.prepared.jobId.takeIf(DesktopInstallJobNames::validJob)
            }
            val cancelled = abandon()
            return DesktopInstallHandoffResult(if (cancelled) code(failure) else ControlCode.OUTCOME_UNKNOWN,
                validatedJobId.takeUnless { cancelled })
        } finally { admission.unlock() }
    }

    private fun abandon(): Boolean {
        val current = worker ?: return true
        val cancelled = runCatching { current.cancel().getOrThrow() }.isSuccess
        uncertainCancellation = !cancelled
        if (cancelled) releaseWorker()
        return cancelled
    }

    /** Owner-local retry only: never creates a worker or treats released handles as confirmation. */
    fun retryCancellation(): DesktopInstallHandoffResult {
        if (!admission.tryLock()) return DesktopInstallHandoffResult(ControlCode.BUSY)
        try {
            if (committed) return DesktopInstallHandoffResult(ControlCode.BUSY, validatedJobId)
            if (closed) return DesktopInstallHandoffResult(
                if (uncertainCancellation) ControlCode.OUTCOME_UNKNOWN else ControlCode.NOT_FOUND,
                validatedJobId.takeIf { uncertainCancellation })
            if (worker == null) return DesktopInstallHandoffResult(ControlCode.NOT_FOUND)
            return DesktopInstallHandoffResult(
                if (abandon()) ControlCode.CANCELLED else ControlCode.OUTCOME_UNKNOWN, validatedJobId)
        } finally { admission.unlock() }
    }

    private fun releaseWorker() {
        val current = worker ?: return
        worker = null
        runCatching { current.close() }
    }

    /** Caller has independently re-read the protected terminal receipt and retired adapter ownership. */
    fun releaseAfterTerminal(receipt: DesktopInstallJobReceipt) {
        check(!admission.isLocked)
        require(receipt.phase.terminal && receipt.jobId == validatedJobId)
        releaseWorker()
        committed = false
        uncertainCancellation = false
        validatedJobId = null
    }

    override fun close() {
        check(!admission.isLocked) { "Installer mutation lane must stop before close" }
        if (closed) return
        closed = true
        if (!committed && !uncertainCancellation) abandon()
        // Closing is not a cancellation acknowledgement. Preserve unknown state and identity.
        releaseWorker()
    }

    private fun code(failure: Throwable): ControlCode = ControlCode.entries.firstOrNull {
        it.name == failure.message && it !in setOf(ControlCode.OK, ControlCode.ACCEPTED)
    } ?: ControlCode.RUNTIME_FAILED
}
