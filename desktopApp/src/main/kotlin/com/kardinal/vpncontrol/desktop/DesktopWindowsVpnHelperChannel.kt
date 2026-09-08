package com.kardinal.vpncontrol.desktop

/** The packaged image/admission fence follows the exact native channel through final disposal. */
internal class DesktopWindowsVpnHelperChannel(
    private val channel: DesktopWindowsPreparedRuntimeChannel,
    private val admission: DesktopWindowsVpnHelperLease,
) : DesktopWindowsPreparedRuntimeChannel {
    private var channelClosed = false
    private var closed = false
    override val childPid: Long get() = channel.childPid

    @Synchronized override fun commit() { check(!channelClosed); channel.commit() }
    @Synchronized override fun abort(): Boolean = channelClosed || channel.abort()
    @Synchronized override fun childExited(): Boolean = channelClosed || channel.childExited()
    @Synchronized override fun status(): DesktopWindowsRuntimeStatus =
        if (channelClosed) DesktopWindowsRuntimeStatus(false) else channel.status()
    @Synchronized override fun stop(force: Boolean) { if (!channelClosed) channel.stop(force) }

    @Synchronized override fun close() {
        if (closed) return
        if (!channelClosed) {
            // The native implementation refuses close until this helper exited and its retained
            // child job is empty. A timeout/exception does not transfer that proof to this wrapper.
            channel.close()
            channelClosed = true
        }
        // Record the native close first: a transient admission close failure must not make its
        // retry query an already closed process handle or pretend a live child still exists.
        admission.close()
        closed = true
    }
}

/** Allocate all candidate owners before the callback is allowed to authorize an external helper. */
internal fun desktopWindowsPrepareFixedHelper(
    channel: DesktopWindowsPreparedRuntimeChannel,
    logFile: java.nio.file.Path,
    resources: DesktopWindowsRuntimeResourceReconciliation? = null,
    stage: () -> DesktopWindowsRuntimePreparationStage,
    authorizeAndPrepare: () -> Unit,
    allocateCandidate: () -> DesktopPreparedRuntimeProcess = {
        DesktopPreparedWindowsRuntimeProcess(channel, logFile, resources)
    },
): DesktopPreparedRuntimeProcess {
    var enteredAuthorization = false
    var retained: DesktopRuntimeProcess? = null
    try {
        retained = DesktopWindowsScopedRuntimeProcess(channel, logFile, resources = resources)
        val candidate = allocateCandidate()
        enteredAuthorization = true
        authorizeAndPrepare()
        return candidate
    } catch (failure: Throwable) {
        if (enteredAuthorization) {
            throw desktopWindowsPreparationFailure(failure, stage(),
                abort = channel::abort, close = channel::close, unresolved = { checkNotNull(retained) })
        }
        // No authorization callback ran. The channel owns only an empty job and read-only pins.
        val pending = if (runCatching { channel.close() }.isFailure) channel else null
        throw DesktopWindowsRuntimeFailure(when (failure) {
            is DesktopWindowsRuntimeFailure -> failure.code
            is OutOfMemoryError -> "RESOURCE_EXHAUSTED"
            is kotlinx.coroutines.CancellationException -> "CANCELLED"
            else -> "UNAVAILABLE"
        }, stage = stage(), retainedAdmission = pending)
    }
}

/** Retain the exact ShellExecute handle even if returning from its native call throws. */
internal fun desktopWindowsRetainAuthorizedHelper(
    authorize: () -> Boolean,
    capturedProcess: () -> com.sun.jna.platform.win32.WinNT.HANDLE?,
    retain: (com.sun.jna.platform.win32.WinNT.HANDLE) -> Unit,
): Boolean {
    try {
        return authorize()
    } finally {
        val process = capturedProcess()
        if (process != null) retain(process)
    }
}
