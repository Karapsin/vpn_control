package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.ControlProtocolCodec
import com.kardinal.vpncontrol.model.ControlCode
import com.kardinal.vpncontrol.model.ControlOperationId
import com.kardinal.vpncontrol.model.ControlRequest
import com.kardinal.vpncontrol.model.ControlResult
import com.kardinal.vpncontrol.model.ControlValue
import java.util.UUID
import javax.swing.SwingUtilities

/** Authenticated, readiness-gated frontend exit used only by an install handoff. */
internal class DesktopFrontendInstallExit(
    private val expectedOwner: () -> String?,
    private val dispatch: ((() -> Unit) -> Unit) = { SwingUtilities.invokeLater(it) },
) {
    private data class ExitRequest(
        val requestId: String,
        val owner: String,
        val operation: String,
        val jobId: String,
        val pid: Long,
        val startedAtEpochMillis: Long,
        val frontend: String,
    )

    private var handler: (() -> Unit)? = null
    private var accepted: ExitRequest? = null
    private var scheduled = false
    private var delivered = false

    @Synchronized fun install(handler: (() -> Unit)?) {
        this.handler = handler
    }

    fun execute(command: DesktopCliCommand.ControlSubmit, identity: DesktopFrontendProcessIdentity): DesktopCliResponse {
        val request = parse(command.request, identity) ?: return DesktopCliResponse.failure("INVALID_ARGUMENT")
        synchronized(this) {
            if (handler == null) return DesktopCliResponse.failure("UNAVAILABLE", DesktopCliResponse.UNAVAILABLE_EXIT_CODE)
            val previous = accepted
            if (previous != null && previous != request) return DesktopCliResponse.failure("CONFLICT")
            if (previous == null) accepted = request
        }
        return success(request)
    }

    fun responseFlushed(command: DesktopCliCommand, response: DesktopCliResponse) {
        val request = synchronized(this) { accepted } ?: return
        if (!matchesCommand(command, request) || !matchesResponse(response, request)) return
        synchronized(this) {
            if (accepted != request || scheduled || delivered) return
            if (handler == null) return
            scheduled = true
        }
        try {
            dispatch { deliver(request) }
        } catch (_: Exception) {
            synchronized(this) { if (!delivered) scheduled = false }
        }
    }

    private fun deliver(request: ExitRequest) {
        val callback = synchronized(this) {
            if (accepted != request || delivered || expectedOwner() != request.owner) {
                scheduled = false
                null
            } else handler ?: run {
                scheduled = false
                null
            }
        } ?: return
        try {
            callback()
            synchronized(this) { delivered = true }
        } catch (_: Exception) {
            synchronized(this) { scheduled = false }
        }
    }

    private fun parse(request: ControlRequest, identity: DesktopFrontendProcessIdentity): ExitRequest? {
        if (request.command.operation != ControlOperationId.QUIT || request.controllerId != identity.registrationId ||
            request.ifRevision != null || request.interactive || request.asynchronous || !canonical(request.requestId)) return null
        val arguments = request.command.arguments
        if (arguments.keys != argumentKeys) return null
        val owner = (arguments["owner"] as? ControlValue.Text)?.value ?: return null
        val operation = (arguments["installOperation"] as? ControlValue.Text)?.value ?: return null
        val jobId = (arguments["jobId"] as? ControlValue.Text)?.value ?: return null
        val pid = (arguments["pid"] as? ControlValue.IntegerValue)?.value ?: return null
        val started = (arguments["startedAtEpochMillis"] as? ControlValue.IntegerValue)?.value ?: return null
        if (!canonical(identity.registrationId) || !canonical(owner) || !canonical(operation) || !canonical(jobId) ||
            owner != expectedOwner() || pid <= 0 || started <= 0 || pid != identity.pid || started != identity.startedAtEpochMillis) return null
        return ExitRequest(request.requestId, owner, operation, jobId, pid, started, identity.registrationId)
    }

    private fun matchesCommand(command: DesktopCliCommand, expected: ExitRequest): Boolean =
        command is DesktopCliCommand.ControlSubmit && parse(command.request,
            DesktopFrontendProcessIdentity(expected.frontend, expected.pid, expected.startedAtEpochMillis)) == expected

    private fun matchesResponse(response: DesktopCliResponse, expected: ExitRequest): Boolean {
        if (!response.success || response.exitCode != 0) return false
        val result = runCatching { ControlProtocolCodec.decodeResult(response.message) }.getOrNull() ?: return false
        return result.controllerId == expected.frontend && result.requestId == expected.requestId && result.code == ControlCode.OK &&
            result.final && result.operationId == null && result.configurationRevision == 0L && !result.restartRequired &&
            result.data == echoedArguments(expected) && result.warnings.isEmpty()
    }

    private fun success(request: ExitRequest): DesktopCliResponse = DesktopCliResponse.success(ControlProtocolCodec.encodeResult(
        ControlResult(request.frontend, request.requestId, ControlCode.OK, 0, data = echoedArguments(request))))

    private fun echoedArguments(request: ExitRequest): Map<String, ControlValue> = mapOf(
        "owner" to ControlValue.Text(request.owner),
        "installOperation" to ControlValue.Text(request.operation),
        "jobId" to ControlValue.Text(request.jobId),
        "pid" to ControlValue.IntegerValue(request.pid),
        "startedAtEpochMillis" to ControlValue.IntegerValue(request.startedAtEpochMillis),
    )

    private fun canonical(value: String): Boolean = runCatching { UUID.fromString(value).toString() == value }.getOrDefault(false)

    private companion object {
        val argumentKeys = setOf("owner", "installOperation", "jobId", "pid", "startedAtEpochMillis")
    }
}
