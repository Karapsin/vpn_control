package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.ControlDocumentCodec
import com.kardinal.vpncontrol.model.*
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import java.util.UUID

/** Public terminal path only; GUI authorization keeps its existing session agent. */
internal object DesktopPublicCliClient {
    fun request(command: DesktopCliCommand): DesktopCliResponse {
        if (DesktopSynchronousOperationClient.supports(command))
            return DesktopSynchronousOperationClient().execute(command as DesktopCliCommand.ControlSubmit)
        if (!System.getProperty("os.name").startsWith("Linux", true) ||
            (command as? DesktopCliCommand.ControlSubmit)?.request?.command?.operation != ControlOperationId.UPDATES_INSTALL)
            return DesktopActivationServer.requestCliCommand(command)
        return DesktopLinuxInstallClient().execute(command)
    }

    fun start(command: DesktopCliCommand): DesktopCliResponse =
        DesktopHeadlessController.startForCliCommand(command, requestCommand = ::request)
}

/** Pins one authenticated owner and retains only our terminal agent until protected handoff. */
internal class DesktopLinuxInstallClient(
    private val endpoint: () -> DesktopControlEndpoint = {
        DesktopControlEndpoint.read(DesktopWorkspacePaths.root().resolve("activation.port"))
    },
    private val exchange: (DesktopCliCommand, DesktopControlEndpoint, Long) -> DesktopCliResponse =
        DesktopActivationServer::requestCliCommandAtEndpoint,
    private val verify: (DesktopControlEndpoint, String) -> DesktopLinuxAuthorizationOwner =
        { descriptor, controller -> verifyLinuxAuthorizationOwnerAfterAuthenticatedHandshake(descriptor, controller) },
    private val terminalAvailable: () -> Boolean = {
        try { java.io.FileInputStream("/dev/tty").use { }; true } catch (_: Exception) { false }
    },
    private val authorize: suspend (DesktopLinuxAuthorizationOwner) -> AutoCloseable = { DesktopLinuxTerminalAuthorization.start(it) },
    private val clockMillis: () -> Long = { System.nanoTime() / 1_000_000 },
    private val pause: (Long) -> Unit = Thread::sleep,
) {
    fun execute(command: DesktopCliCommand.ControlSubmit): DesktopCliResponse = runBlocking {
        val original = command.request
        require(original.command.operation == ControlOperationId.UPDATES_INSTALL)
        val started = clockMillis()
        val budget = command.clientTimeoutSeconds * 1000
        var metadata: ControlResult? = null
        var operationId: String? = null
        var dispatched = false
        fun remaining(): Long {
            if (budget == 0L) return 0
            val left = budget - (clockMillis() - started).coerceAtLeast(0)
            check(left > 0) { "TIMEOUT" }
            return left
        }
        fun response(result: ControlResult): DesktopCliResponse {
            val correlated = result.copy(requestId = original.requestId)
            return DesktopCliResponse(correlated.ok, ControlDocumentCodec.encodeResult(correlated), correlated.exitCode)
        }
        fun failure(code: ControlCode): DesktopCliResponse = metadata?.let {
            response(it.copy(code = code, final = code !in setOf(ControlCode.TIMEOUT, ControlCode.OUTCOME_UNKNOWN),
                operationId = operationId, data = emptyMap(), message = code.wireName))
        } ?: desktopCliJsonFailure(code, original.requestId, operationId)
        try {
            val captured = endpoint()
            if (original.controllerId != null && original.controllerId != captured.controllerId)
                return@runBlocking desktopCliJsonFailure(ControlCode.CONFLICT, original.requestId)
            fun submit(request: ControlRequest): ControlResult {
                val answer = exchange(DesktopCliCommand.ControlSubmit(request, command.clientTimeoutSeconds), captured, remaining())
                val result = ControlDocumentCodec.decodeResult(desktopCliJsonResponse(request, answer).message)
                if (result.controllerId != captured.controllerId) {
                    if (result.controllerId == null && result.code in setOf(ControlCode.TIMEOUT, ControlCode.OUTCOME_UNKNOWN,
                            ControlCode.UNAVAILABLE, ControlCode.PERMISSION_DENIED, ControlCode.INCOMPATIBLE_PROTOCOL))
                        error(result.code.wireName)
                    error("CONFLICT")
                }
                return result
            }
            val handshake = submit(ControlRequest(UUID.randomUUID().toString(), ControlCommand(ControlOperationId.STATUS),
                controllerId = captured.controllerId))
            metadata = handshake
            if (!handshake.ok) return@runBlocking response(handshake)
            check(handshake.final && handshake.code == ControlCode.OK) { "INCOMPATIBLE_PROTOCOL" }
            val owner = verify(captured, requireNotNull(handshake.controllerId))
            if (!terminalAvailable()) return@runBlocking failure(ControlCode.INTERACTION_REQUIRED)
            val allowance = remaining()
            val lease = if (allowance == 0L) authorize(owner) else withTimeout(allowance) { authorize(owner) }
            lease.use {
                remaining()
                dispatched = true
                var result = submit(original.copy(controllerId = captured.controllerId))
                var jobId: String? = null
                while (true) {
                    check(operationId == null || result.operationId == operationId) { "INCOMPATIBLE_PROTOCOL" }
                    metadata = result
                    if (result.final || result.code != ControlCode.ACCEPTED) return@runBlocking response(result)
                    val id = result.operationId ?: error("INCOMPATIBLE_PROTOCOL")
                    check(DesktopInstallJobNames.validJob(id) && (operationId == null || operationId == id)) { "INCOMPATIBLE_PROTOCOL" }
                    operationId = id
                    val job = (result.data["jobId"] as? ControlValue.Text)?.value
                    if (job != null) {
                        check(DesktopInstallJobNames.validJob(job) && (jobId == null || jobId == job)) { "INCOMPATIBLE_PROTOCOL" }
                        jobId = job
                    }
                    if ((result.data["handoffReady"] as? ControlValue.BooleanValue)?.value == true) {
                        check(job != null) { "INCOMPATIBLE_PROTOCOL" }
                        return@runBlocking response(result)
                    }
                    val left = remaining()
                    pause(if (left == 0L) 100 else minOf(left, 100))
                    result = submit(ControlRequest(UUID.randomUUID().toString(), ControlCommand(ControlOperationId.OPERATIONS_STATUS,
                        mapOf("id" to ControlValue.Text(id))), controllerId = captured.controllerId))
                }
            }
            error("Unreachable")
        } catch (_: java.nio.file.NoSuchFileException) {
            if (metadata == null) DesktopCliResponse.notRunning() else failure(ControlCode.OUTCOME_UNKNOWN)
        } catch (_: kotlinx.coroutines.TimeoutCancellationException) { failure(ControlCode.TIMEOUT) }
        catch (error: Exception) {
            failure(when (error.message) {
                "CONFLICT" -> ControlCode.CONFLICT
                "INTERACTION_REQUIRED" -> ControlCode.INTERACTION_REQUIRED
                "PRIVILEGE_REQUIRED", "PERMISSION_DENIED" -> ControlCode.PERMISSION_DENIED
                "TIMEOUT" -> ControlCode.TIMEOUT
                "INCOMPATIBLE_PROTOCOL" -> ControlCode.INCOMPATIBLE_PROTOCOL
                "UNAVAILABLE" -> if (dispatched) ControlCode.OUTCOME_UNKNOWN else ControlCode.UNAVAILABLE
                else -> ControlCode.OUTCOME_UNKNOWN
            })
        }
    }
}
