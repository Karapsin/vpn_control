package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.ControlCode
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext

/** The commit file requests a transition; only the protected receipt acknowledges it. */
internal class DesktopReceiptPreparedInstall(
    override val jobId: String,
    private val readReceipt: () -> DesktopInstallJobReceipt,
    private val publishCommit: () -> Unit,
    private val requestCancellation: () -> Unit,
    private val release: () -> Unit,
    private val timeoutMillis: Long = 30_000,
    private val onCancellationConfirmed: () -> Unit = {},
    private val authorizationFailure: () -> Throwable? = { null },
) : DesktopPreparedInstall {
    private val tracker = DesktopInstallJobReceiptTracker(jobId)
    private var closed = false
    private var commitPublished = false
    private var cancellationConfirmed = false

    suspend fun awaitAuthorization(): Result<Unit> = await(DesktopInstallJobPhase.AUTHORIZED)

    override suspend fun commit(): Result<Unit> = withContext(Dispatchers.IO) {
        runCatching {
            check(!closed)
            if (!commitPublished) {
                // A lost acknowledgment is retried by reading the same job, never publishing a new job.
                publishCommit()
                commitPublished = true
            }
        }.fold(onSuccess = { await(DesktopInstallJobPhase.WAITING_FOR_EXIT) }, onFailure = { Result.failure(it) })
    }

    private suspend fun await(expected: DesktopInstallJobPhase): Result<Unit> {
        val deadline = System.nanoTime() + timeoutMillis * 1_000_000
        while (true) {
            check(!closed)
            val receipt = try { tracker.accept(readReceipt()) }
            catch (missing: Exception) {
                // CREATE_NEW job directory is observable just before the first atomic receipt publish.
                val notCreated = missing is java.nio.file.NoSuchFileException ||
                    missing is WindowsInstallNativeFailure && missing.code in setOf(2, 3)
                if (expected != DesktopInstallJobPhase.AUTHORIZED || !notCreated) return Result.failure(missing)
                authorizationFailure()?.let { return Result.failure(it) }
                if (System.nanoTime() >= deadline) return Result.failure(IllegalStateException(ControlCode.OUTCOME_UNKNOWN.name))
                delay(50)
                continue
            }
            if (receipt.phase == expected) return Result.success(Unit)
            if (receipt.phase.terminal) return Result.failure(IllegalStateException(
                if (receipt.phase == DesktopInstallJobPhase.SUCCEEDED) ControlCode.OUTCOME_UNKNOWN.name else receipt.code.name))
            if (receipt.phase.ordinal > expected.ordinal) return Result.failure(IllegalStateException(ControlCode.OUTCOME_UNKNOWN.name))
            if (System.nanoTime() >= deadline) return Result.failure(IllegalStateException(ControlCode.OUTCOME_UNKNOWN.name))
            delay(50)
        }
    }

    override fun cancel(): Result<Unit> = runCatching {
        check(!closed)
        if (cancellationConfirmed) return@runCatching
        requestCancellation()
        val deadline = System.nanoTime() + timeoutMillis * 1_000_000
        while (true) {
            val receipt = tracker.accept(readReceipt())
            if (receipt.phase == DesktopInstallJobPhase.CANCELLED || receipt.phase == DesktopInstallJobPhase.FAILED) break
            check(!receipt.phase.terminal && receipt.phase != DesktopInstallJobPhase.INSTALLING) { ControlCode.OUTCOME_UNKNOWN.name }
            check(System.nanoTime() < deadline) { ControlCode.OUTCOME_UNKNOWN.name }
            Thread.sleep(50)
        }
        cancellationConfirmed = true
        onCancellationConfirmed()
    }

    override fun close() { if (!closed) { closed = true; release() } }
}
