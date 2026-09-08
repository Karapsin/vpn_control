package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.ControlProtocolCodec
import com.kardinal.vpncontrol.model.ControlCode
import com.kardinal.vpncontrol.model.ControlCommand
import com.kardinal.vpncontrol.model.ControlOperationId
import com.kardinal.vpncontrol.model.ControlRequest
import com.kardinal.vpncontrol.model.ControlResult
import com.kardinal.vpncontrol.model.ControlValue
import java.util.UUID
import javax.swing.SwingUtilities
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive

/** Captured public-owner QUIT correlation; the request id is opaque public protocol data. */
internal data class DesktopFrontendQuitCorrelation(
    val owner: String,
    val publicRequestId: String,
    val frontend: DesktopFrontendProcessIdentity,
) {
    init {
        require(canonicalUuid(owner))
        require(validPublicRequestId(publicRequestId))
    }
}

/** Authenticated frontend closure for a normal, already-flushed owner QUIT. */
internal class DesktopFrontendQuitExit(
    private val expectedOwner: () -> String?,
    private val dispatch: ((() -> Unit) -> Unit) = { SwingUtilities.invokeLater(it) },
) {
    private data class ExitRequest(
        val requestId: String,
        val correlation: DesktopFrontendQuitCorrelation,
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
            if (accepted != request || scheduled || delivered || handler == null) return
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
            if (accepted != request || delivered || expectedOwner() != request.correlation.owner) {
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
            request.ifRevision != null || request.interactive || request.asynchronous || !canonicalUuid(request.requestId)) return null
        val arguments = request.command.arguments
        if (arguments.keys != argumentKeys) return null
        val owner = (arguments["owner"] as? ControlValue.Text)?.value ?: return null
        val publicRequestId = (arguments["quitRequestId"] as? ControlValue.Text)?.value ?: return null
        val pid = (arguments["pid"] as? ControlValue.IntegerValue)?.value ?: return null
        val started = (arguments["startedAtEpochMillis"] as? ControlValue.IntegerValue)?.value ?: return null
        if (!canonicalUuid(identity.registrationId) || !canonicalUuid(owner) || !validPublicRequestId(publicRequestId) ||
            owner != expectedOwner() || pid != identity.pid || started != identity.startedAtEpochMillis) return null
        return ExitRequest(request.requestId, DesktopFrontendQuitCorrelation(owner, publicRequestId, identity))
    }

    private fun matchesCommand(command: DesktopCliCommand, expected: ExitRequest): Boolean =
        command is DesktopCliCommand.ControlSubmit && parse(command.request, expected.correlation.frontend) == expected

    private fun matchesResponse(response: DesktopCliResponse, expected: ExitRequest): Boolean {
        if (!response.success || response.exitCode != 0) return false
        val result = runCatching { ControlProtocolCodec.decodeResult(response.message) }.getOrNull() ?: return false
        return result.controllerId == expected.correlation.frontend.registrationId && result.requestId == expected.requestId &&
            result.code == ControlCode.OK && result.final && result.operationId == null && result.configurationRevision == 0L &&
            !result.restartRequired && result.data == echoedArguments(expected) && result.warnings.isEmpty()
    }

    private fun success(request: ExitRequest): DesktopCliResponse = DesktopCliResponse.success(ControlProtocolCodec.encodeResult(
        ControlResult(request.correlation.frontend.registrationId, request.requestId, ControlCode.OK, 0,
            data = echoedArguments(request))))

    private fun echoedArguments(request: ExitRequest): Map<String, ControlValue> = mapOf(
        "owner" to ControlValue.Text(request.correlation.owner),
        "quitRequestId" to ControlValue.Text(request.correlation.publicRequestId),
        "pid" to ControlValue.IntegerValue(request.correlation.frontend.pid),
        "startedAtEpochMillis" to ControlValue.IntegerValue(request.correlation.frontend.startedAtEpochMillis),
    )

    private companion object {
        val argumentKeys = setOf("owner", "quitRequestId", "pid", "startedAtEpochMillis")
    }
}

/** Retries one fixed endpoint request; it never targets a new frontend generation. */
internal class DesktopOwnerFrontendQuit(
    private val correlation: DesktopFrontendQuitCorrelation,
    private val request: suspend (DesktopCliCommand.ControlSubmit) -> DesktopCliResponse,
    private val observe: () -> DesktopFrontendProcessObservation = {
        desktopFrontendProcessObservation(correlation.frontend)
    },
    private val pause: suspend () -> Unit = { delay(1_000) },
) {
    private val command = DesktopCliCommand.ControlSubmit(ControlRequest(UUID.randomUUID().toString(),
        ControlCommand(ControlOperationId.QUIT, mapOf(
            "owner" to ControlValue.Text(correlation.owner),
            "quitRequestId" to ControlValue.Text(correlation.publicRequestId),
            "pid" to ControlValue.IntegerValue(correlation.frontend.pid),
            "startedAtEpochMillis" to ControlValue.IntegerValue(correlation.frontend.startedAtEpochMillis),
        )), controllerId = correlation.frontend.registrationId), clientTimeoutSeconds = 3)

    suspend fun awaitAcknowledgement() {
        while (true) {
            currentCoroutineContext().ensureActive()
            when (runCatching(observe).getOrDefault(DesktopFrontendProcessObservation.UNKNOWN)) {
                DesktopFrontendProcessObservation.GONE -> return
                DesktopFrontendProcessObservation.UNKNOWN -> Unit
                DesktopFrontendProcessObservation.SAME -> try {
                    val response = request(command)
                    if (matches(response)) return
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (_: Exception) {
                    // Retain the exact request; a response may have been lost after frontend admission.
                }
            }
            pause()
        }
    }

    private fun matches(response: DesktopCliResponse): Boolean {
        if (!response.success || response.exitCode != 0) return false
        val result = runCatching { ControlProtocolCodec.decodeResult(response.message) }.getOrNull() ?: return false
        return result == ControlResult(correlation.frontend.registrationId, command.request.requestId, ControlCode.OK, 0,
            data = command.request.command.arguments)
    }
}

private fun canonicalUuid(value: String): Boolean =
    runCatching { UUID.fromString(value).toString() == value }.getOrDefault(false)

private fun validPublicRequestId(value: String): Boolean =
    value.isNotBlank() && value.length <= 256 && value.none { it.code < 32 }
