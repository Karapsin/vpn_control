package com.kardinal.vpncontrol

import java.io.File
import kotlinx.coroutines.*
import com.kardinal.vpncontrol.model.ControlCode
import com.kardinal.vpncontrol.model.ControlOperationId
import com.kardinal.vpncontrol.model.ControlValue

internal data class AndroidUpdateCheck(val manifest: UpdateManifest, val available: Boolean, val asset: UpdateAsset?)
internal data class AndroidUpdateOutcome(val code: ControlCode, val data: Map<String, ControlValue>) {
    fun asResult(): Result<Unit> = if (code == ControlCode.OK) Result.success(Unit)
        else Result.failure(if (code == ControlCode.CANCELLED) CancellationException("UPDATE_CANCELLED") else IllegalStateException(code.wireName))
}

/** One application-owned transfer slot. Waiter cancellation never cancels accepted work. */
internal class AndroidUpdateControl(
    private val launch: (suspend () -> Unit) -> Job,
    private val currentVersion: String,
    private val currentBuild: Int,
    private val fetch: suspend () -> UpdateManifest,
    private val select: (UpdateManifest) -> UpdateAsset?,
    private val download: suspend (UpdateAsset) -> File,
    private val verify: suspend (File, UpdateAsset, Int) -> Unit,
    private val cleanup: suspend () -> Unit,
    private val cancelNetwork: () -> Unit,
    private val emit: ((AppUpdateState) -> AppUpdateState) -> Unit,
) {
    private class Transfer(val result: CompletableDeferred<AndroidUpdateOutcome> = CompletableDeferred()) { val job = CompletableDeferred<Job>() }
    private var active: Transfer? = null
    private var cancelling = false
    internal data class Installation(val file: File, val checked: AndroidUpdateCheck)
    private var installation: Installation? = null
    @Synchronized fun reserveInstallation(): Installation? {
        if (busy()) return null
        val file = preparedFile ?: return null
        val selected = checked?.takeIf { it.asset != null } ?: return null
        return Installation(file, selected).also { installation = it }
    }
    @Synchronized fun finishInstallation(ticket: Installation, handedOff: Boolean) {
        if (installation !== ticket) return
        if (handedOff) update { it.copy(phase = AppUpdatePhase.INSTALLING, message = "") }
        installation = null
    }
    internal class Cancellation internal constructor(internal val job: Deferred<Job>?, internal val dismiss: Boolean)
    private var cancellation: Cancellation? = null
    private var generation = 0L
    private var published = AppUpdateState(currentVersion = currentVersion)
    @Volatile private var checked: AndroidUpdateCheck? = null
    @Volatile var preparedFile: File? = null
        private set
    fun checkedStatus(): AndroidUpdateCheck? = checked
    @Synchronized fun busy(): Boolean = active != null || cancelling || installation != null
    @Synchronized fun generation(): Long = generation
    @Synchronized fun inspection(state: () -> AppUpdateState) = AndroidControlUpdateInspection.read(state(), checked)
    @Synchronized private fun update(transform: (AppUpdateState) -> AppUpdateState) = emit { transform(it).also { next -> published = next } }
    @Synchronized private fun outcome(code: ControlCode) = AndroidUpdateOutcome(code, AndroidControlUpdateInspection.read(published, checked))
    fun progress(downloaded: Long, total: Long) = update { it.copy(downloadedBytes = downloaded, totalBytes = total) }

    suspend fun execute(operation: ControlOperationId, expectedGeneration: Long? = null): AndroidUpdateOutcome = when (operation) {
        ControlOperationId.UPDATES_CHECK -> checkOutcome(expectedGeneration)
        ControlOperationId.UPDATES_DOWNLOAD -> downloadOutcome(expectedGeneration)
        ControlOperationId.UPDATES_CANCEL -> cancelOutcome(false)
        ControlOperationId.UPDATES_DISMISS -> cancelOutcome(true)
        else -> outcome(ControlCode.UNSUPPORTED)
    }

    companion object {
        val operations = setOf(ControlOperationId.UPDATES_CHECK, ControlOperationId.UPDATES_DOWNLOAD,
            ControlOperationId.UPDATES_CANCEL, ControlOperationId.UPDATES_DISMISS)
        val controlPlane = setOf(ControlOperationId.UPDATES_CANCEL, ControlOperationId.UPDATES_DISMISS)
    }

    suspend fun check(expectedGeneration: Long? = null): Result<Unit> = checkOutcome(expectedGeneration).asResult()
    private suspend fun checkOutcome(expectedGeneration: Long?): AndroidUpdateOutcome = runOwned(expectedGeneration) {
        synchronized(this) {
            checked = null; preparedFile = null
            update { AppUpdateState(showDialog = it.showDialog, currentVersion = currentVersion, phase = AppUpdatePhase.CHECKING) }
        }
        val manifest = fetch()
        currentCoroutineContext().ensureActive()
        val available = AppUpdateLogic.isUpdateAvailable(currentBuild, manifest)
        val asset = if (available) select(manifest) else null
        synchronized(this) {
            checked = AndroidUpdateCheck(manifest, available, asset)
            update { it.copy(phase = if (!available) AppUpdatePhase.UP_TO_DATE else if (asset == null) AppUpdatePhase.UNSUPPORTED else AppUpdatePhase.IDLE,
                availableVersion = asset?.displayVersion.orEmpty(), releaseNotesUrl = manifest.releaseNotesUrl) }
            outcome(if (available && asset == null) ControlCode.UNSUPPORTED else ControlCode.OK)
        }
    }

    suspend fun downloadChecked(expectedGeneration: Long? = null): Result<Unit> = downloadOutcome(expectedGeneration).asResult()
    private suspend fun downloadOutcome(expectedGeneration: Long?): AndroidUpdateOutcome = runOwned(expectedGeneration) {
        val selected = checked ?: return@runOwned outcome(ControlCode.NOT_FOUND)
        val asset = selected.asset ?: return@runOwned outcome(ControlCode.NOT_FOUND)
        preparedFile = null
        update { it.copy(phase = AppUpdatePhase.DOWNLOADING, downloadedBytes = 0, totalBytes = asset.sizeBytes,
            availableVersion = asset.displayVersion, preparedAsset = null, message = "") }
        val file = download(asset)
        currentCoroutineContext().ensureActive()
        update { it.copy(phase = AppUpdatePhase.VERIFYING) }
        verify(file, asset, selected.manifest.buildNumber)
        currentCoroutineContext().ensureActive()
        synchronized(this) {
            preparedFile = file
            update { it.copy(phase = AppUpdatePhase.READY, downloadedBytes = asset.sizeBytes, totalBytes = asset.sizeBytes, preparedAsset = asset) }
            outcome(ControlCode.OK)
        }
    }

    private suspend fun runOwned(expectedGeneration: Long?, action: suspend () -> AndroidUpdateOutcome): AndroidUpdateOutcome {
        val ready = CompletableDeferred<Unit>()
        val transfer = synchronized(this) {
            if (expectedGeneration != null && expectedGeneration != generation) return outcome(ControlCode.CANCELLED)
            if (busy()) return outcome(ControlCode.BUSY)
            Transfer().also { active = it }
        }
        val job = try { launch {
            ready.await()
            try { transfer.result.complete(action()) }
            catch (error: Exception) {
                val cancelled = error is CancellationException || !currentCoroutineContext().isActive
                withContext(NonCancellable) { cleanup() }
                preparedFile = null
                update { it.copy(phase = if (cancelled) AppUpdatePhase.IDLE else AppUpdatePhase.FAILED,
                    message = if (cancelled) "" else "UPDATE_FAILED", preparedAsset = null) }
                transfer.result.complete(outcome(if (cancelled) ControlCode.CANCELLED else ControlCode.RUNTIME_FAILED))
            }
        } } catch (error: Throwable) {
            synchronized(this) { if (active === transfer) active = null }
            transfer.job.completeExceptionally(error)
            return AndroidUpdateOutcome(ControlCode.RUNTIME_FAILED, emptyMap())
        }
        transfer.job.complete(job)
        job.invokeOnCompletion { error ->
            synchronized(this) {
                if (!transfer.result.isCompleted) transfer.result.complete(AndroidUpdateOutcome(
                    if (error is CancellationException) ControlCode.CANCELLED else ControlCode.RUNTIME_FAILED, emptyMap()))
                if (active === transfer) active = null
            }
        }
        ready.complete(Unit)
        // Completion includes cleanup and release, even if the action produced its result earlier.
        val result = transfer.result.await()
        job.join()
        return result
    }

    /** Prevents a new transfer until the cancelled worker and cleanup actually finish. */
    suspend fun cancel(dismiss: Boolean = false): Result<Unit> = cancelOutcome(dismiss).asResult()
    @Synchronized fun reserveCancellation(dismiss: Boolean = false): Cancellation? {
        if (cancelling || installation != null) return null
        cancelling = true
        generation++
        return Cancellation(active?.job, dismiss).also { cancellation = it }
    }
    private suspend fun cancelOutcome(dismiss: Boolean): AndroidUpdateOutcome =
        reserveCancellation(dismiss)?.let { finishCancellation(it) } ?: outcome(ControlCode.BUSY)

    suspend fun finishCancellation(ticket: Cancellation): AndroidUpdateOutcome {
        check(synchronized(this) { cancellation === ticket })
        return try {
            withContext(NonCancellable) {
                val job = ticket.job?.await()
                job?.cancel(CancellationException("UPDATE_CANCELLED"))
                cancelNetwork()
                job?.join()
                cleanup()
                preparedFile = null
                if (ticket.dismiss) synchronized(this@AndroidUpdateControl) { checked = null; update { AppUpdateState(currentVersion = currentVersion) } }
                else update { it.copy(phase = AppUpdatePhase.IDLE, preparedAsset = null, message = "") }
            }
            outcome(ControlCode.OK)
        } catch (_: Exception) { outcome(ControlCode.RUNTIME_FAILED) }
        finally { synchronized(this) { if (cancellation === ticket) { cancellation = null; cancelling = false } } }
    }
}
