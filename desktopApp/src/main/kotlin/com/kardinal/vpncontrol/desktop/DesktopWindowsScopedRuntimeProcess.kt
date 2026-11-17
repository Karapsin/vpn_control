package com.kardinal.vpncontrol.desktop

import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.TimeUnit

internal data class DesktopWindowsRuntimeStatus(
    val running: Boolean,
    val log: ByteArray = byteArrayOf(),
    val resourceReconciliation: DesktopWindowsNativeResourceReconciliation? = null,
)

/** The native channel owns a retained broker handle and a job-contained child, never a PID-only kill. */
internal interface DesktopWindowsRuntimeChannel : AutoCloseable {
    val childPid: Long
    fun status(): DesktopWindowsRuntimeStatus
    fun stop(force: Boolean)
    fun childExited(): Boolean
}

internal interface DesktopWindowsPreparedRuntimeChannel : DesktopWindowsRuntimeChannel {
    fun commit()
    /** Abort only this candidate and return true only after its retained job and helper have exited. */
    fun abort(): Boolean
    /** The exit code of the broker this channel launched once it has exited, or null while it runs or was never launched. */
    fun brokerExitCode(): Int? = null
}

internal class DesktopWindowsRuntimeFailure(
    val code: String,
    /** Retained ownership for the rare case in which native cleanup cannot establish the outcome. */
    val unresolvedRuntime: DesktopRuntimeProcess? = null,
    val stage: DesktopWindowsRuntimePreparationStage? = null,
    /** Read-only native pins still belong to this preparation until exact closure succeeds. */
    val retainedAdmission: AutoCloseable? = null,
    /** Diagnostic only: the exited broker's step code ([DesktopWindowsBrokerExit]). It never changes [code]. */
    val brokerExit: Int? = null,
) : java.io.IOException(code) {
    fun withBrokerExit(exit: Int?): DesktopWindowsRuntimeFailure =
        if (exit == null || brokerExit != null) this
        else DesktopWindowsRuntimeFailure(code, unresolvedRuntime, stage, retainedAdmission, exit)
}

internal enum class DesktopWindowsRuntimePreparationStage { AUTHORIZATION, HELPER_CONNECTION, PEER_IDENTITY, CAPTURED_INPUTS, CHILD_CREATED, READY }

internal class DesktopPreparedWindowsRuntimeProcess(
    private val channel: DesktopWindowsPreparedRuntimeChannel,
    private val logFile: Path,
    private val resources: DesktopWindowsRuntimeResourceReconciliation? = null,
) : DesktopPreparedRuntimeProcess {
    private enum class State { PREPARED, TRANSFERRED, CLOSED }
    private var state = State.PREPARED
    // Allocate the owner before commit; a post-commit allocation failure must not lose the child.
    private val runtime = DesktopWindowsScopedRuntimeProcess(channel, logFile, resources = resources)

    @Synchronized override fun commit(): DesktopRuntimeProcess {
        check(state == State.PREPARED) { "Prepared runtime has already been consumed" }
        try {
            channel.commit()
        } catch (failure: Throwable) {
            disposeCandidate()
            if (failure is OutOfMemoryError) throw DesktopWindowsRuntimeFailure("RESOURCE_EXHAUSTED")
            throw failure
        }
        state = State.TRANSFERRED
        return runtime
    }

    @Synchronized override fun close() {
        if (state == State.PREPARED) disposeCandidate()
    }

    private fun disposeCandidate() {
        state = State.CLOSED
        val disposed = runCatching {
            if (!channel.abort()) false else { channel.close(); true }
        }.getOrDefault(false)
        if (!disposed) throw DesktopWindowsRuntimeFailure("OUTCOME_UNKNOWN", runtime)
    }
}

internal class DesktopWindowsScopedRuntimeProcess(
    private val channel: DesktopWindowsRuntimeChannel,
    private val logFile: Path,
    private val clockNanos: () -> Long = System::nanoTime,
    private val pauseMillis: (Long) -> Unit = Thread::sleep,
    private val resources: DesktopWindowsRuntimeResourceReconciliation? = null,
) : DesktopRuntimeProcess {
    private var verifiedExited = false
    private var warnings = emptyList<DesktopRuntimeResourceWarning>()
    override val resourceWarnings: List<DesktopRuntimeResourceWarning>
        @Synchronized get() = warnings.toList()
    override val isAlive: Boolean
        @Synchronized get() {
            if (verifiedExited) return false
            val status = try { channel.status() } catch (_: Exception) {
                // Loss of the waiter is not proof that the job-contained runtime stopped.
                if (channel.childExited()) confirmExit(null)
                return !verifiedExited
            }
            if (status.log.isNotEmpty()) Files.write(logFile, status.log, java.nio.file.StandardOpenOption.APPEND)
            if (!status.running) confirmExit(status.resourceReconciliation)
            return status.running
        }
    override fun pid() = channel.childPid
    override fun destroy() = channel.stop(false)
    override fun destroyForcibly() {
        try { channel.stop(true) }
        catch (failure: Exception) {
            if (channel is DesktopWindowsPreparedRuntimeChannel && channel.abort()) verifiedExited = true
            else throw failure
        }
    }
    override fun waitFor(timeout: Long, unit: TimeUnit): Boolean {
        val started = clockNanos()
        while (isAlive) {
            if (clockNanos() - started >= unit.toNanos(timeout)) return false
            pauseMillis(25)
        }
        return true
    }
    override fun close() {
        check(!isAlive) { "OUTCOME_UNKNOWN" }
        channel.close()
        warnings.takeIf { it.isNotEmpty() }?.let(::DesktopRuntimeResourcePublicationFailure)?.let { throw it }
    }

    @Synchronized private fun confirmExit(native: DesktopWindowsNativeResourceReconciliation?) {
        verifiedExited = true
        val retained = resources ?: return
        warnings = retained.afterConfirmedExit { native ?: throw java.io.IOException("OUTCOME_UNKNOWN") }
    }
}
