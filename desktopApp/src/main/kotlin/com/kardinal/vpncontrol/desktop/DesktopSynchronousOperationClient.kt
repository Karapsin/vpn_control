package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.ControlDocumentCodec
import com.kardinal.vpncontrol.model.*
import java.nio.file.NoSuchFileException
import java.util.UUID

/** Admission and observation share one authenticated endpoint; only the owner executes work. */
internal class DesktopSynchronousOperationClient(
    private val endpoint: () -> DesktopControlEndpoint = {
        DesktopControlEndpoint.read(DesktopWorkspacePaths.root().resolve("activation.port"))
    },
    private val exchange: (DesktopCliCommand, DesktopControlEndpoint, Long) -> DesktopCliResponse =
        DesktopActivationServer::requestCliCommandAtEndpoint,
    private val clockMillis: () -> Long = { System.nanoTime() / 1_000_000 },
    private val pause: (Long) -> Unit = Thread::sleep,
) {
    fun execute(command: DesktopCliCommand.ControlSubmit): DesktopCliResponse {
        val original = command.request
        require(supports(command))
        val started = clockMillis()
        val seconds = command.clientTimeoutSeconds
        if (seconds !in 0..Long.MAX_VALUE / 1000)
            return desktopCliJsonFailure(ControlCode.INVALID_ARGUMENT, original.requestId)
        val budget = seconds * 1000
        var metadata: ControlResult? = null
        var operationId: String? = null
        var dispatched = false

        fun remaining(): Long {
            if (budget == 0L) return 0
            return (budget - (clockMillis() - started).coerceAtLeast(0)).also {
                if (it <= 0) throw ObservationFailure(ControlCode.TIMEOUT)
            }
        }
        fun response(value: ControlResult): DesktopCliResponse {
            val result = value.copy(requestId = original.requestId)
            return DesktopCliResponse(result.ok, ControlDocumentCodec.encodeResult(result), result.exitCode)
        }
        fun failure(code: ControlCode): DesktopCliResponse {
            val outcome = if (dispatched && code == ControlCode.UNAVAILABLE) ControlCode.OUTCOME_UNKNOWN else code
            val observed = metadata ?: return desktopCliJsonFailure(outcome, original.requestId, operationId)
            return response(observed.copy(code = outcome, operationId = operationId,
                final = !dispatched && outcome !in setOf(ControlCode.TIMEOUT, ControlCode.OUTCOME_UNKNOWN),
                message = outcome.wireName, messageKey = null, messageArgs = emptyList(), data = emptyMap()))
        }

        try {
            val captured = endpoint()
            if (original.controllerId != null && original.controllerId != captured.controllerId)
                return desktopCliJsonFailure(ControlCode.CONFLICT, original.requestId)

            fun observe(request: ControlRequest, mutation: Boolean = false): ControlResult {
                val allowance = remaining()
                if (mutation) dispatched = true
                val answer = exchange(DesktopCliCommand.ControlSubmit(request, seconds), captured, allowance)
                if (answer.isDesktopAppNotRunning) throw OwnerAbsent()
                if (!answer.success && answer.message == ControlCode.PERMISSION_DENIED.wireName &&
                    answer.exitCode == ControlCode.PERMISSION_DENIED.exitCode)
                    throw ObservationFailure(ControlCode.PERMISSION_DENIED)
                val result = ControlDocumentCodec.decodeResult(desktopCliJsonResponse(request, answer).message)
                if (result.controllerId != captured.controllerId) {
                    if (result.controllerId == null && result.code in transportFailures)
                        throw ObservationFailure(result.code)
                    throw ObservationFailure(if (dispatched) ControlCode.OUTCOME_UNKNOWN else ControlCode.CONFLICT)
                }
                return result
            }

            val handshake = observe(ControlRequest(UUID.randomUUID().toString(),
                ControlCommand(ControlOperationId.STATUS), controllerId = captured.controllerId))
            metadata = handshake
            if (!handshake.ok) return failure(handshake.code)
            if (!handshake.final || handshake.code != ControlCode.OK || handshake.operationId != null)
                throw ObservationFailure(ControlCode.INCOMPATIBLE_PROTOCOL)

            // Asynchronous is observation metadata. Keep request identity, epoch, guards and input.
            var result = observe(original.copy(controllerId = captured.controllerId, asynchronous = true), mutation = true)
            while (true) {
                if (operationId != null && result.operationId != operationId)
                    throw ObservationFailure(ControlCode.INCOMPATIBLE_PROTOCOL)
                if ((!result.final && result.code !in pendingCodes) ||
                    (result.code == ControlCode.OK && result.operationId == null))
                    throw ObservationFailure(ControlCode.INCOMPATIBLE_PROTOCOL)
                operationId = result.operationId
                metadata = result
                if (result.final || result.code != ControlCode.ACCEPTED) return response(result)
                val id = requireNotNull(operationId)
                val left = remaining()
                pause(if (left == 0L) 100 else minOf(left, 100))
                // Status also exposes pending native uncertainty, which a terminal wait can hide.
                result = observe(ControlRequest(UUID.randomUUID().toString(),
                    ControlCommand(ControlOperationId.OPERATIONS_STATUS, mapOf("id" to ControlValue.Text(id))),
                    controllerId = captured.controllerId))
            }
        } catch (_: OwnerAbsent) {
            return if (!dispatched) DesktopCliResponse.notRunning() else failure(ControlCode.OUTCOME_UNKNOWN)
        } catch (_: NoSuchFileException) {
            return if (!dispatched) DesktopCliResponse.notRunning() else failure(ControlCode.OUTCOME_UNKNOWN)
        } catch (error: ObservationFailure) {
            return failure(error.code)
        } catch (_: DesktopControlProtocolException) {
            return failure(ControlCode.INCOMPATIBLE_PROTOCOL)
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            return failure(ControlCode.OUTCOME_UNKNOWN)
        } catch (_: Exception) {
            return failure(ControlCode.OUTCOME_UNKNOWN)
        }
    }

    companion object {
        fun supports(command: DesktopCliCommand): Boolean = command is DesktopCliCommand.ControlSubmit &&
            !command.request.asynchronous && command.request.command.operation in DesktopControlSupport.asynchronousOperations &&
            command.request.command.operation != ControlOperationId.UPDATES_INSTALL

        private val transportFailures = setOf(ControlCode.TIMEOUT, ControlCode.OUTCOME_UNKNOWN, ControlCode.UNAVAILABLE,
            ControlCode.PERMISSION_DENIED, ControlCode.INCOMPATIBLE_PROTOCOL)
        private val uncertainCodes = setOf(ControlCode.TIMEOUT, ControlCode.OUTCOME_UNKNOWN, ControlCode.UNAVAILABLE,
            ControlCode.INCOMPATIBLE_PROTOCOL)
        private val pendingCodes = uncertainCodes + ControlCode.ACCEPTED
    }

    private class ObservationFailure(val code: ControlCode) : Exception()
    private class OwnerAbsent : Exception()
}
