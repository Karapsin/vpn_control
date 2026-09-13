package com.kardinal.vpncontrol.desktop

import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

/** Only the exact successful terminal response may release a requested owner exit. */
internal class DesktopOwnerExitGate(
    private val releaseInstall: (DesktopInstallCorrelation, String, () -> Unit) -> Unit = { _, _, release -> release() },
    private val releaseQuit: (DesktopFrontendQuitCorrelation, () -> Unit) -> Unit = { _, release -> release() },
) {
    private val pending = AtomicReference<String?>(null)
    private val released = AtomicBoolean()
    private data class InstallExit(val correlation: DesktopInstallCorrelation, val jobId: String)
    private val install = AtomicReference<InstallExit?>(null)
    private val notified = AtomicReference<InstallExit?>(null)
    private val quit = AtomicReference<DesktopFrontendQuitCorrelation?>(null)
    private val quitNotified = AtomicReference<DesktopFrontendQuitCorrelation?>(null)
    val exitRequested: Boolean get() = released.get()
    val exitPending: Boolean get() = pending.get() != null || install.get() != null || quit.get() != null || released.get()

    fun requestExitAfterResponse(requestId: String) {
        require(requestId.isNotBlank() && requestId.length <= 256)
        check(pending.compareAndSet(null, requestId) || pending.get() == requestId)
    }

    fun requestFrontendQuitAfterResponse(correlation: DesktopFrontendQuitCorrelation) {
        check(quit.compareAndSet(null, correlation) || quit.get() == correlation)
    }

    fun responseFlushed(command: DesktopCliCommand, response: DesktopCliResponse) {
        val request = (command as? DesktopCliCommand.ControlSubmit)?.request ?: return
        if (!response.success) return
        val result = runCatching {
            com.kardinal.vpncontrol.control.ControlProtocolCodec.decodeResult(response.message)
        }.getOrNull() ?: return
        install.get()?.let { expected ->
            val identity = expected.correlation
            if (matchesInstallAcknowledgement(request, response, result, expected))
                if (notified.compareAndSet(null, expected)) {
                    try {
                        releaseInstall(identity, expected.jobId) {
                            if (install.get() == expected && notified.get() == expected) released.set(true)
                        }
                    } catch (_: Exception) { notified.compareAndSet(expected, null) }
                }
        }
        quit.get()?.let { expected ->
            if (matchesQuit(command, response, expected) && quitNotified.compareAndSet(null, expected)) {
                try {
                    releaseQuit(expected) {
                        if (quit.get() == expected && quitNotified.get() == expected) released.set(true)
                    }
                } catch (_: Exception) { quitNotified.compareAndSet(expected, null) }
            }
        }
        if (pending.get() != request.requestId) return
        if (result.requestId == request.requestId && result.controllerId == request.controllerId &&
            result.final && result.code == com.kardinal.vpncontrol.model.ControlCode.OK && response.exitCode == 0)
            released.set(true)
    }

    private fun matchesInstallAcknowledgement(request: com.kardinal.vpncontrol.model.ControlRequest,
        response: DesktopCliResponse, result: com.kardinal.vpncontrol.model.ControlResult, expected: InstallExit): Boolean {
        val identity = expected.correlation
        if (result.requestId != request.requestId || result.controllerId != request.controllerId ||
            request.controllerId != identity.controllerId || response.exitCode != 0) return false
        val readyOperation = result.operationId == identity.operationId && !result.final &&
            result.code == com.kardinal.vpncontrol.model.ControlCode.ACCEPTED &&
            result.data["jobId"] == com.kardinal.vpncontrol.model.ControlValue.Text(expected.jobId) &&
            result.data["handoffReady"] == com.kardinal.vpncontrol.model.ControlValue.BooleanValue(true) &&
            (request.requestId == identity.requestId && request.command.operation == com.kardinal.vpncontrol.model.ControlOperationId.UPDATES_INSTALL ||
                request.command.operation == com.kardinal.vpncontrol.model.ControlOperationId.OPERATIONS_STATUS &&
                    request.command.arguments["id"] == com.kardinal.vpncontrol.model.ControlValue.Text(identity.operationId))
        if (readyOperation) return true
        if (request.command.operation != com.kardinal.vpncontrol.model.ControlOperationId.UPDATES_STATUS ||
            !result.final || result.code != com.kardinal.vpncontrol.model.ControlCode.OK) return false
        return (result.data["installations"] as? com.kardinal.vpncontrol.model.ControlValue.ArrayValue)?.values?.any { value ->
            val installation = (value as? com.kardinal.vpncontrol.model.ControlValue.ObjectValue)?.values ?: return@any false
            installation["jobId"] == com.kardinal.vpncontrol.model.ControlValue.Text(expected.jobId) &&
                installation["originControllerId"] == com.kardinal.vpncontrol.model.ControlValue.Text(identity.controllerId) &&
                installation["originRequestId"] == com.kardinal.vpncontrol.model.ControlValue.Text(identity.requestId) &&
                installation["operationId"] == com.kardinal.vpncontrol.model.ControlValue.Text(identity.operationId) &&
                installation["phase"] == com.kardinal.vpncontrol.model.ControlValue.Text("waiting_for_exit") &&
                installation["code"] == com.kardinal.vpncontrol.model.ControlValue.Text(
                    com.kardinal.vpncontrol.model.ControlCode.ACCEPTED.wireName) &&
                installation["final"] == com.kardinal.vpncontrol.model.ControlValue.BooleanValue(false) &&
                installation["installed"] == com.kardinal.vpncontrol.model.ControlValue.Null
        } == true
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

    private fun matchesQuit(command: DesktopCliCommand, response: DesktopCliResponse,
        expected: DesktopFrontendQuitCorrelation): Boolean {
        val request = (command as? DesktopCliCommand.ControlSubmit)?.request ?: return false
        if (request.command.operation != com.kardinal.vpncontrol.model.ControlOperationId.QUIT ||
            request.command.arguments.isNotEmpty() || request.interactive || request.asynchronous ||
            request.requestId != expected.publicRequestId || request.controllerId != expected.owner) return false
        val result = runCatching {
            com.kardinal.vpncontrol.control.ControlProtocolCodec.decodeResult(response.message)
        }.getOrNull() ?: return false
        return response.success && response.exitCode == 0 && result.requestId == expected.publicRequestId &&
            result.controllerId == expected.owner && result.final && result.operationId?.let(::canonicalQuitOperationId) == true &&
            result.code == com.kardinal.vpncontrol.model.ControlCode.OK
    }

    private fun canonicalQuitOperationId(value: String): Boolean = runCatching {
        java.util.UUID.fromString(value).toString() == value
    }.getOrDefault(false)
}
