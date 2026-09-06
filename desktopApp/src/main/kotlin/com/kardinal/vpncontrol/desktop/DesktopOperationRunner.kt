package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.ControlOperationAdmission
import com.kardinal.vpncontrol.control.ControlOperationLedger
import com.kardinal.vpncontrol.model.ControlCode
import com.kardinal.vpncontrol.model.ControlOperation
import com.kardinal.vpncontrol.model.ControlOperationId
import com.kardinal.vpncontrol.model.ControlOperationPhase
import com.kardinal.vpncontrol.model.ControlResult
import java.security.MessageDigest
import java.util.UUID
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject

/** Owner-scoped long actions. Client coroutine cancellation never cancels the owner's work. */
internal class DesktopOperationRunner(
    private val scope: CoroutineScope,
    controllerId: String = UUID.randomUUID().toString(),
    private val now: () -> Long = desktopOperationClock(),
    private val metadataProvider: () -> DesktopControlMetadata = { DesktopControlMetadata(0, false) },
) {
    private val ledger = ControlOperationLedger(controllerId)
    private val guard = Any()
    private val jobs = mutableMapOf<String, Job>()
    private val mutableChanges = kotlinx.coroutines.flow.MutableStateFlow(0L)
    val changes: kotlinx.coroutines.flow.StateFlow<Long> = mutableChanges
    private fun changed() { synchronized(mutableChanges) { mutableChanges.value++ } }

    fun snapshot(): List<ControlOperation> = synchronized(guard) { ledger.list(now()) }

    fun listResponse(): DesktopCliResponse = DesktopCliResponse.success(JsonArray(snapshot().map(::summary)).toString())

    fun statusResponse(id: String): DesktopCliResponse {
        val operation = synchronized(guard) { ledger.get(id, now()) }
            ?: return DesktopCliResponse.failure("NOT_FOUND")
        return DesktopCliResponse.success(summary(operation).toString())
    }

    fun cancelResponse(id: String): DesktopCliResponse {
        val (code, job) = synchronized(guard) {
            ledger.requestCancellation(id, now()) to jobs[id]
        }
        if (code != ControlCode.OK) return DesktopCliResponse.failure(code.wireName, code.exitCode)
        changed()
        job?.cancel()
        // This reports the current phase; cancellation acceptance is not terminal completion.
        return statusResponse(id)
    }

    suspend fun waitResponse(id: String): DesktopCliResponse {
        while (true) {
            val operation = synchronized(guard) { ledger.get(id, now()) }
                ?: return DesktopCliResponse.failure("NOT_FOUND")
            if (operation.phase.terminal) {
                val result = requireNotNull(operation.result)
                return DesktopCliResponse(result.ok, summary(operation).toString(), result.code.exitCode)
            }
            // Cancellation only stops this observer, never the owner-scoped action.
            kotlinx.coroutines.delay(50)
        }
    }

    /** Inspection exposes identifiers and sanitized outcomes, never private input. */
    private fun summary(operation: ControlOperation) = buildJsonObject {
        put("controllerId", JsonPrimitive(ledger.controllerId))
        put("id", JsonPrimitive(operation.id))
        put("requestId", JsonPrimitive(operation.requestId))
        put("operation", JsonPrimitive(operation.operation.wireName))
        put("phase", JsonPrimitive(operation.phase.wireName))
        put("final", JsonPrimitive(operation.phase.terminal))
        put("cancellable", JsonPrimitive(operation.cancellable))
        put("completedUnits", JsonPrimitive(operation.completedUnits))
        put("totalUnits", JsonPrimitive(operation.totalUnits))
        put("code", JsonPrimitive(operation.result?.code?.wireName))
        operation.result?.let { result ->
            put("configurationRevision", JsonPrimitive(result.configurationRevision))
            put("restartRequired", JsonPrimitive(result.restartRequired))
        }
    }

    suspend fun execute(
        operation: ControlOperationId,
        command: DesktopCliCommand,
        requestId: String = UUID.randomUUID().toString(),
        asynchronous: Boolean = false,
        expectedControllerId: String? = null,
        expectedRevision: Long? = null,
        resultEnvelope: Boolean = false,
        retainSettingsValues: Boolean = false,
        retainSubscriptionIdentity: Boolean = false,
        retainLocationIdentity: Boolean = false,
        retainConfigurationValues: Boolean = false,
        mutates: Boolean = true,
        completionMetadata: () -> DesktopControlMetadata? = { null },
        action: suspend () -> DesktopCliResponse,
    ): DesktopCliResponse {
        require(mutates || operation == ControlOperationId.UPDATES_CANCEL)
        require(!retainConfigurationValues || operation in DesktopConfigurationResultData.operations)
        require(!retainSettingsValues || operation in setOf(ControlOperationId.SETTINGS_SET, ControlOperationId.SETTINGS_APPLY))
        require(!retainSubscriptionIdentity || operation in setOf(ControlOperationId.SUBSCRIPTIONS_ADD, ControlOperationId.SUBSCRIPTIONS_UPDATE,
            ControlOperationId.SUBSCRIPTIONS_DELETE, ControlOperationId.SOURCE_SET))
        require(!retainLocationIdentity || operation in setOf(ControlOperationId.LOCATIONS_ADD, ControlOperationId.LOCATIONS_UPDATE,
            ControlOperationId.LOCATIONS_SELECT, ControlOperationId.LOCATIONS_DELETE))
        if (requestId.isBlank()) return DesktopCliResponse.failure("INVALID_ARGUMENT")
        if (expectedControllerId != null && expectedControllerId != ledger.controllerId)
            return DesktopCliResponse.failure("CONFLICT")
        val id = UUID.randomUUID().toString()
        val fingerprint = MessageDigest.getInstance("SHA-256")
            .digest((operation.wireName + "\u0000" + expectedRevision + "\u0000" +
                DesktopCliProtocol.encodeCommand(command)).toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }
        val admission = synchronized(guard) {
            ledger.admit(id, requestId, operation, fingerprint, mutates = mutates,
                cancellable = operation in DesktopControlSupport.cancellableOperations, now = now())
        }
        if (admission is ControlOperationAdmission.Rejected) return DesktopCliResponse.failure(admission.code.wireName)
        if (admission is ControlOperationAdmission.Existing) {
            if (!asynchronous && resultEnvelope) {
                waitResponse(admission.operation.id)
                return acceptedResponse(admission.operation.id)
            }
            return if (asynchronous) acceptedResponse(admission.operation.id) else waitResponse(admission.operation.id)
        }
        val reply = CompletableDeferred<DesktopCliResponse>()
        changed()
        val job = scope.launch(start = CoroutineStart.LAZY) {
            synchronized(guard) {
                if (ledger.get(id, now())?.phase == ControlOperationPhase.CANCELLING) throw CancellationException()
                ledger.advance(id, ControlOperationPhase.RUNNING, now())
            }
            changed()
            val response = try { action() }
            catch (_: CancellationException) { DesktopCliResponse.failure("CANCELLED", 130) }
            catch (_: Exception) { DesktopCliResponse.failure("RUNTIME_FAILED") }
            complete(id, requestId, response, retainSettingsValues, completionMetadata(), retainSubscriptionIdentity || retainLocationIdentity,
                operation.takeIf { retainConfigurationValues })
            reply.complete(response)
        }
        // Includes cancellation before the dispatched coroutine gets its first instruction.
        job.invokeOnCompletion {
            synchronized(guard) { jobs.remove(id) }
            if (!reply.isCompleted) {
                val cancelled = DesktopCliResponse.failure("CANCELLED", 130)
                complete(id, requestId, cancelled)
                reply.complete(cancelled)
            }
        }
        synchronized(guard) {
            if (!job.isCompleted) jobs[id] = job
            if (ledger.get(id, now())?.phase == ControlOperationPhase.CANCELLING) job.cancel()
        }
        job.start()
        if (asynchronous) return acceptedResponse(id)
        val response = reply.await()
        return if (resultEnvelope) acceptedResponse(id) else response
    }

    private fun acceptedResponse(id: String): DesktopCliResponse {
        val operation = synchronized(guard) { ledger.get(id, now()) }
            ?: return DesktopCliResponse.failure("NOT_FOUND")
        if (operation.phase.terminal) {
            val result = requireNotNull(operation.result)
            return DesktopCliResponse(result.ok, com.kardinal.vpncontrol.control.ControlProtocolCodec.encodeResult(result), result.exitCode)
        }
        val metadata = metadataProvider()
        return DesktopCliResponse.success(com.kardinal.vpncontrol.control.ControlProtocolCodec.encodeResult(ControlResult(
            controllerId = ledger.controllerId, requestId = operation.requestId, operationId = id,
            code = ControlCode.ACCEPTED, final = false, configurationRevision = metadata.configurationRevision,
            restartRequired = metadata.restartRequired,
        )))
    }

    private fun complete(id: String, requestId: String, response: DesktopCliResponse,
        retainSettingsValues: Boolean = false, committedMetadata: DesktopControlMetadata? = null,
        retainSubscriptionIdentity: Boolean = false, configurationOperation: ControlOperationId? = null) = synchronized(guard) {
        if (ledger.get(id, now())?.phase?.terminal == true) return@synchronized
        val values = if (response.success && configurationOperation != null) runCatching {
            DesktopConfigurationResultData.decode(configurationOperation, response.message)
        } else if (response.success && (retainSettingsValues || retainSubscriptionIdentity)) runCatching {
            com.kardinal.vpncontrol.control.ControlProtocolCodec.decodeValues(response.message).also { values ->
                if (retainSubscriptionIdentity) require(values.keys == setOf("id") &&
                    (values["id"] as? com.kardinal.vpncontrol.model.ControlValue.Text)?.value?.isNotBlank() == true)
            }
        } else Result.success(emptyMap())
        val code = if (values.isFailure) ControlCode.RUNTIME_FAILED else if (response.success) ControlCode.OK else if (response.exitCode == 130) ControlCode.CANCELLED
            else ControlCode.entries.firstOrNull { it.wireName == response.message && it.exitCode == 1 }
                ?: ControlCode.RUNTIME_FAILED
        // Only validated public settings, committed routing/import results, or exact saved IDs are retained.
        // Never infer data from arbitrary human action messages or private import input.
        val metadata = committedMetadata ?: metadataProvider()
        ledger.complete(id, ControlResult(ledger.controllerId, requestId, code, configurationRevision = metadata.configurationRevision,
            restartRequired = metadata.restartRequired, operationId = id, message = code.wireName,
            data = values.getOrDefault(emptyMap()),
            warnings = DesktopConfigurationResultData.warnings(values.getOrDefault(emptyMap()))), now())
        changed()
    }
}

private fun desktopOperationClock(): () -> Long {
    val origin = System.nanoTime()
    return { (System.nanoTime() - origin) / 1_000_000 }
}
