package com.kardinal.vpncontrol.desktop

import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

/** Only the exact successful terminal response may release a requested owner exit. */
internal class DesktopOwnerExitGate(
    private val releaseInstall: (DesktopInstallCorrelation, String, () -> Unit) -> Unit = { _, _, release -> release() },
) {
    private val pending = AtomicReference<String?>(null)
    private val released = AtomicBoolean()
    private data class InstallExit(val correlation: DesktopInstallCorrelation, val jobId: String)
    private val install = AtomicReference<InstallExit?>(null)
    private val notified = AtomicReference<InstallExit?>(null)
    val exitRequested: Boolean get() = released.get()
    val exitPending: Boolean get() = pending.get() != null || install.get() != null || released.get()

    fun requestExitAfterResponse(requestId: String) {
        require(requestId.isNotBlank() && requestId.length <= 256)
        check(pending.compareAndSet(null, requestId) || pending.get() == requestId)
    }

    fun responseFlushed(command: DesktopCliCommand, response: DesktopCliResponse) {
        val request = (command as? DesktopCliCommand.ControlSubmit)?.request ?: return
        if (!response.success) return
        val result = runCatching {
            com.kardinal.vpncontrol.control.ControlProtocolCodec.decodeResult(response.message)
        }.getOrNull() ?: return
        install.get()?.let { expected ->
            val identity = expected.correlation
            if (result.requestId == request.requestId && result.controllerId == request.controllerId &&
                request.controllerId == identity.controllerId && result.operationId == identity.operationId &&
                !result.final && result.code == com.kardinal.vpncontrol.model.ControlCode.ACCEPTED &&
                response.exitCode == 0 && result.data["jobId"] == com.kardinal.vpncontrol.model.ControlValue.Text(expected.jobId) &&
                result.data["handoffReady"] == com.kardinal.vpncontrol.model.ControlValue.BooleanValue(true) &&
                (request.requestId == identity.requestId && request.command.operation == com.kardinal.vpncontrol.model.ControlOperationId.UPDATES_INSTALL ||
                    request.command.operation == com.kardinal.vpncontrol.model.ControlOperationId.OPERATIONS_STATUS &&
                        request.command.arguments["id"] == com.kardinal.vpncontrol.model.ControlValue.Text(identity.operationId)))
                if (notified.compareAndSet(null, expected)) {
                    try {
                        releaseInstall(identity, expected.jobId) {
                            if (install.get() == expected && notified.get() == expected) released.set(true)
                        }
                    } catch (_: Exception) { notified.compareAndSet(expected, null) }
                }
        }
        if (pending.get() != request.requestId) return
        if (result.requestId == request.requestId && result.controllerId == request.controllerId &&
            result.final && result.code == com.kardinal.vpncontrol.model.ControlCode.OK && response.exitCode == 0)
            released.set(true)
    }

    /** Arm only after the retained worker acknowledged protected WAITING_FOR_EXIT. */
    fun requestInstallExitAfterResponse(correlation: DesktopInstallCorrelation, jobId: String) {
        require(DesktopInstallJobNames.validJob(jobId))
        val expected = InstallExit(correlation, jobId)
        check(install.compareAndSet(null, expected) || install.get() == expected)
    }

    fun revokeInstallExit(correlation: DesktopInstallCorrelation, jobId: String) {
        val expected = install.get() ?: return
        if (expected == InstallExit(correlation, jobId) && install.compareAndSet(expected, null))
            notified.compareAndSet(expected, null)
    }
}
