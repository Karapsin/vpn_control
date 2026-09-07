package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.ControlOperationAdmission
import com.kardinal.vpncontrol.control.ControlOperationLedger
import com.kardinal.vpncontrol.model.ControlCode
import com.kardinal.vpncontrol.model.ControlOperation
import com.kardinal.vpncontrol.model.ControlOperationId
import com.kardinal.vpncontrol.model.ControlOperationPhase
import com.kardinal.vpncontrol.model.ControlResult
import com.kardinal.vpncontrol.model.ControlValue
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
    private val recoverInstalls: (() -> Result<List<DesktopInstallCorrelationRecovery>>)? = null,
) {
    private val ledger = ControlOperationLedger(controllerId)
    private val guard = Any()
    private val jobs = mutableMapOf<String, Job>()
    private val pendingOutcomes = mutableMapOf<String, ControlCode>()
    private data class ExternalInstall(val correlation: DesktopInstallCorrelation, val actions: DesktopControlInstallActions,
        var outcome: DesktopInstallHandoffResult = DesktopInstallHandoffResult(ControlCode.ACCEPTED),
        var ready: Boolean = false, var cancelRequested: Boolean = false)
    private val installs = mutableMapOf<String, ExternalInstall>()
    private val mutableChanges = kotlinx.coroutines.flow.MutableStateFlow(0L)
    val changes: kotlinx.coroutines.flow.StateFlow<Long> = mutableChanges
    private fun changed() { synchronized(mutableChanges) { mutableChanges.value++ } }

    fun snapshot(): List<ControlOperation> {
        val local = synchronized(guard) { ledger.list(now()) }
        val ids = local.mapTo(mutableSetOf()) { it.id }
        return local + recoveredOperations().filter { it.id !in ids }
    }

    fun installBarrier(): Boolean {
        if (synchronized(guard) { installs.isNotEmpty() }) return true
        val recovery = recoverInstalls?.invoke() ?: return false
        return recovery.isFailure || recovery.getOrThrow().any { it.blocksInstallation }
    }

    private fun recoveredOperations(): List<ControlOperation> = recoverInstalls?.invoke()?.getOrNull().orEmpty().mapNotNull { recovered ->
        val binding = recovered.binding ?: return@mapNotNull null
        val terminal = recovered.notStarted || recovered.receipt?.phase?.terminal == true
        val code = if (terminal) recovered.code else if (recovered.receipt == null) ControlCode.OUTCOME_UNKNOWN else ControlCode.ACCEPTED
        val metadata = metadataProvider()
        val result = ControlResult(ledger.controllerId, binding.correlation.requestId, code, metadata.configurationRevision,
            final = terminal, operationId = binding.correlation.operationId, restartRequired = metadata.restartRequired,
            data = mapOf("jobId" to ControlValue.Text(binding.jobId),
                "originControllerId" to ControlValue.Text(binding.correlation.controllerId),
                "originRequestId" to ControlValue.Text(binding.correlation.requestId),
                "handoffReady" to ControlValue.BooleanValue(false)))
        ControlOperation(binding.correlation.operationId, binding.correlation.requestId, ControlOperationId.UPDATES_INSTALL,
            if (!terminal) ControlOperationPhase.RUNNING else when (code) {
                ControlCode.OK -> ControlOperationPhase.SUCCEEDED
                ControlCode.CANCELLED -> ControlOperationPhase.CANCELLED
                else -> ControlOperationPhase.FAILED
            }, cancellable = false, result = result.takeIf { terminal })
    }

    private fun recoveredResult(id: String, requestId: String): ControlResult? {
        val recovered = recoverInstalls?.invoke()?.getOrNull()?.singleOrNull { it.binding?.correlation?.operationId == id } ?: return null
        val binding = requireNotNull(recovered.binding)
        val terminal = recovered.notStarted || recovered.receipt?.phase?.terminal == true
        val metadata = metadataProvider()
        return ControlResult(ledger.controllerId, requestId,
            if (terminal) recovered.code else if (recovered.receipt == null) ControlCode.OUTCOME_UNKNOWN else ControlCode.ACCEPTED,
            metadata.configurationRevision, final = terminal, operationId = id, restartRequired = metadata.restartRequired,
            data = mapOf("jobId" to ControlValue.Text(binding.jobId),
                "originControllerId" to ControlValue.Text(binding.correlation.controllerId),
                "originRequestId" to ControlValue.Text(binding.correlation.requestId),
                "handoffReady" to ControlValue.BooleanValue(false)))
    }

    fun listResponse(): DesktopCliResponse = DesktopCliResponse.success(JsonArray(snapshot().map(::summary)).toString())

    fun statusResponse(id: String): DesktopCliResponse {
        val operation = snapshot().singleOrNull { it.id == id }
            ?: return DesktopCliResponse.failure("NOT_FOUND")
        return DesktopCliResponse.success(summary(operation).toString())
    }

    fun cancelResponse(id: String): DesktopCliResponse {
        val (code, job) = synchronized(guard) {
            ledger.requestCancellation(id, now()) to jobs[id]
        }
        if (code != ControlCode.OK) return DesktopCliResponse.failure(code.wireName, code.exitCode)
        changed()
        val external = synchronized(guard) { installs[id]?.also { it.cancelRequested = true } }
        if (external == null) job?.cancel()
        // This reports the current phase; cancellation acceptance is not terminal completion.
        return statusResponse(id)
    }

    suspend fun waitResponse(id: String): DesktopCliResponse {
        while (true) {
            val operation = snapshot().singleOrNull { it.id == id }
                ?: return DesktopCliResponse.failure("NOT_FOUND")
            if (operation.phase.terminal) {
                val result = requireNotNull(operation.result)
                return DesktopCliResponse(result.ok, summary(operation).toString(), result.code.exitCode)
            }
            // Cancellation only stops this observer, never the owner-scoped action.
            kotlinx.coroutines.delay(50)
        }
    }

    /** Typed inspection preserves the retained result, including its original committed revision.
     * Only correlation with this inspection request changes. Cancelling the observer never
     * cancels the owner operation; nonterminal status remains an accepted operation.
     */
    suspend fun inspectResult(id: String, requestId: String, wait: Boolean): ControlResult? {
        while (true) {
            val operation = synchronized(guard) { ledger.get(id, now()) }
            if (operation == null) {
                val recovered = recoveredResult(id, requestId) ?: return null
                if (recovered.final || !wait) return recovered
                kotlinx.coroutines.delay(250); continue
            }
            operation.result?.let { return it.copy(requestId = requestId) }
            if (!wait) synchronized(guard) { installs[id] }?.let {
                return installResult(it).copy(requestId = requestId)
            }
            if (!wait) {
                val metadata = metadataProvider()
                val code = synchronized(guard) { pendingOutcomes[id] } ?: ControlCode.ACCEPTED
                return ControlResult(ledger.controllerId, requestId, code,
                    metadata.configurationRevision, final = false, operationId = operation.id,
                    restartRequired = metadata.restartRequired,
                    data = com.kardinal.vpncontrol.control.ControlDocumentCodec.decodeValues(summary(operation).toString()))
            }
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
        synchronized(guard) { pendingOutcomes[operation.id] }?.let { put("code", JsonPrimitive(it.wireName)) }
        synchronized(guard) { installs[operation.id] }?.let {
            put("jobId", JsonPrimitive(it.outcome.jobId))
            put("handoffReady", JsonPrimitive(it.ready))
            put("code", JsonPrimitive(it.outcome.code.wireName))
        }
        operation.result?.let { result ->
            put("configurationRevision", JsonPrimitive(result.configurationRevision))
            put("restartRequired", JsonPrimitive(result.restartRequired))
        }
    }

    suspend fun executeInstall(request: com.kardinal.vpncontrol.model.ControlRequest,
        actions: DesktopControlInstallActions): DesktopCliResponse {
        val id = UUID.randomUUID().toString()
        val fingerprint = MessageDigest.getInstance("SHA-256").digest(
            DesktopCliProtocol.encodeCommand(DesktopCliCommand.ControlSubmit(request.copy(asynchronous = false))).toByteArray())
            .joinToString("") { "%02x".format(it) }
        val admission = synchronized(guard) { ledger.admit(id, request.requestId, ControlOperationId.UPDATES_INSTALL,
            fingerprint, mutates = true, cancellable = true, now = now()) }
        when (admission) {
            is ControlOperationAdmission.Rejected -> return DesktopCliResponse.failure(admission.code.wireName, admission.code.exitCode)
            is ControlOperationAdmission.Existing -> return acceptedResponse(admission.operation.id)
            is ControlOperationAdmission.Started -> Unit
        }
        val external = ExternalInstall(DesktopInstallCorrelation(ledger.controllerId, request.requestId, id), actions)
        synchronized(guard) { installs[id] = external; ledger.advance(id, ControlOperationPhase.RUNNING, now()) }
        val first = CompletableDeferred<Unit>()
        scope.launch {
            try {
                val outcome = try { actions.prepare(external.correlation, request.ifRevision) }
                catch (_: CancellationException) { DesktopInstallHandoffResult(ControlCode.OUTCOME_UNKNOWN) }
                catch (_: Exception) { DesktopInstallHandoffResult(ControlCode.OUTCOME_UNKNOWN) }
                synchronized(guard) {
                    external.ready = outcome.code == ControlCode.OK && outcome.jobId != null
                    external.outcome = outcome.copy(code = if (external.ready) ControlCode.ACCEPTED else outcome.code)
                    if (external.ready) ledger.advance(id, requireNotNull(ledger.get(id, now())).phase, now(), cancellable = false)
                }
                if (outcome.code !in setOf(ControlCode.OK, ControlCode.ACCEPTED, ControlCode.OUTCOME_UNKNOWN,
                        ControlCode.TIMEOUT, ControlCode.UNAVAILABLE, ControlCode.INCOMPATIBLE_PROTOCOL)) {
                    completeInstall(external, outcome.code)
                }
                changed(); first.complete(Unit)
                while (synchronized(guard) { installs[id] === external }) {
                    if (synchronized(guard) { external.cancelRequested && !external.ready }) {
                        val cancellation = try { actions.cancel() } catch (_: Exception) {
                            DesktopInstallHandoffResult(ControlCode.OUTCOME_UNKNOWN, external.outcome.jobId)
                        }
                        if (cancellation.code == ControlCode.CANCELLED) completeInstall(external, ControlCode.CANCELLED)
                    }
                    val recovered = try { actions.recover().getOrNull()?.singleOrNull {
                        it.binding?.correlation == external.correlation &&
                            (external.outcome.jobId == null || it.binding.jobId == external.outcome.jobId)
                    } } catch (_: Exception) { null }
                    if (recovered != null) {
                        synchronized(guard) { external.outcome = external.outcome.copy(jobId = recovered.binding?.jobId) }
                        if (recovered.notStarted) completeInstall(external, recovered.code)
                        else recovered.receipt?.takeIf { it.phase.terminal }?.let { receipt ->
                            if (runCatching { actions.settle(external.correlation, receipt).getOrThrow() }.isSuccess)
                                completeInstall(external, recovered.code)
                        }
                    }
                    kotlinx.coroutines.delay(250)
                }
            } finally { first.complete(Unit) }
        }
        changed()
        if (!request.asynchronous) first.await()
        return acceptedResponse(id)
    }

    private fun installResult(external: ExternalInstall): ControlResult {
        val metadata = metadataProvider()
        return ControlResult(ledger.controllerId, external.correlation.requestId, external.outcome.code,
            metadata.configurationRevision, final = false, operationId = external.correlation.operationId,
            restartRequired = metadata.restartRequired, data = buildMap {
                external.outcome.jobId?.let { put("jobId", ControlValue.Text(it)) }
                put("handoffReady", ControlValue.BooleanValue(external.ready))
            })
    }

    private fun completeInstall(external: ExternalInstall, code: ControlCode) {
        if (code in setOf(ControlCode.ACCEPTED, ControlCode.OUTCOME_UNKNOWN, ControlCode.TIMEOUT,
                ControlCode.UNAVAILABLE, ControlCode.INCOMPATIBLE_PROTOCOL)) return
        val result = installResult(external).copy(code = code, final = true)
        synchronized(guard) {
            val id = external.correlation.operationId
            if (installs[id] !== external) return
            ledger.complete(id, result, now()); installs.remove(id)
        }
        changed()
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
        if (mutates && synchronized(guard) { ledger.forRequest(requestId, now()) == null } && installBarrier())
            return DesktopCliResponse.failure("BUSY")
        val id = UUID.randomUUID().toString()
        val fingerprintCommand = if (command is DesktopCliCommand.ControlSubmit)
            command.copy(request = command.request.copy(asynchronous = false)) else command
        val fingerprint = MessageDigest.getInstance("SHA-256")
            .digest((operation.wireName + "\u0000" + expectedRevision + "\u0000" +
                DesktopCliProtocol.encodeCommand(fingerprintCommand)).toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }
        val admission = synchronized(guard) {
            ledger.admit(id, requestId, operation, fingerprint, mutates = mutates,
                cancellable = operation in DesktopControlSupport.cancellableOperations, now = now())
        }
        if (admission is ControlOperationAdmission.Rejected) return DesktopCliResponse.failure(admission.code.wireName)
        if (admission is ControlOperationAdmission.Existing) {
            if (synchronized(guard) { pendingOutcomes.containsKey(admission.operation.id) })
                return acceptedResponse(admission.operation.id)
            if (!asynchronous && resultEnvelope) {
                waitResponse(admission.operation.id)
                return acceptedResponse(admission.operation.id)
            }
            return if (asynchronous) acceptedResponse(admission.operation.id) else waitResponse(admission.operation.id)
        }
        val reply = CompletableDeferred<DesktopCliResponse>()
        changed()
        val progress = DesktopOperationProgress { code ->
            val active = synchronized(guard) {
                if (ledger.get(id, now())?.phase?.terminal != false) false
                else {
                    if (code == null) pendingOutcomes.remove(id) else pendingOutcomes[id] = code
                    true
                }
            }
            if (active) {
                changed()
                // Release the observer with its exact identity; the owner action keeps
                // reconciling native effects in the original coroutine and mutation lane.
                if (code != null) reply.complete(acceptedResponse(id))
            }
        }
        val job = scope.launch(context = progress, start = CoroutineStart.LAZY) {
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
            synchronized(guard) {
                jobs.remove(id)
                if (pendingOutcomes.containsKey(id)) ledger.get(id, now())?.let { operation ->
                    // An observer failure is not native completion. Retain the unknown
                    // outcome, and do not advertise cancellation through a finished job.
                    if (!operation.phase.terminal) ledger.advance(id, operation.phase, now(), cancellable = false)
                }
            }
            changed()
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
        synchronized(guard) { installs[id] }?.let {
            val result = installResult(it)
            return DesktopCliResponse(result.ok, com.kardinal.vpncontrol.control.ControlDocumentCodec.encodeResult(result), result.exitCode)
        }
        val operation = synchronized(guard) { ledger.get(id, now()) }
            ?: return DesktopCliResponse.failure("NOT_FOUND")
        if (operation.phase.terminal) {
            val result = requireNotNull(operation.result)
            return DesktopCliResponse(result.ok, com.kardinal.vpncontrol.control.ControlDocumentCodec.encodeResult(result), result.exitCode)
        }
        val metadata = metadataProvider()
        val code = synchronized(guard) { pendingOutcomes[id] } ?: ControlCode.ACCEPTED
        val result = ControlResult(
            controllerId = ledger.controllerId, requestId = operation.requestId, operationId = id,
            code = code, final = false, configurationRevision = metadata.configurationRevision,
            restartRequired = metadata.restartRequired,
        )
        return DesktopCliResponse(result.ok, com.kardinal.vpncontrol.control.ControlDocumentCodec.encodeResult(result), result.exitCode)
    }

    private fun complete(id: String, requestId: String, response: DesktopCliResponse,
        retainSettingsValues: Boolean = false, committedMetadata: DesktopControlMetadata? = null,
        retainSubscriptionIdentity: Boolean = false, configurationOperation: ControlOperationId? = null) = synchronized(guard) {
        val operation = ledger.get(id, now()) ?: return@synchronized
        if (operation.phase.terminal) return@synchronized
        // Cancellation or a thrown exception cannot erase a previously reported
        // uncertain native effect. Its owner must first confirm the actual outcome.
        if (pendingOutcomes.containsKey(id)) return@synchronized
        val actionData = runCatching { DesktopActionResultData.decode(operation.operation, response) }
        val values = if (response.success && configurationOperation != null) runCatching {
            DesktopConfigurationResultData.decode(configurationOperation, response.message)
        } else if (response.success && (retainSettingsValues || retainSubscriptionIdentity)) runCatching {
            com.kardinal.vpncontrol.control.ControlDocumentCodec.decodeValues(response.message).also { values ->
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
            data = actionData.getOrNull() ?: values.getOrDefault(emptyMap()),
            warnings = DesktopConfigurationResultData.warnings(values.getOrDefault(emptyMap())) +
                if (actionData.isFailure) listOf("RESULT_DATA_UNAVAILABLE") else emptyList()), now())
        changed()
    }
}

private fun desktopOperationClock(): () -> Long {
    val origin = System.nanoTime()
    return { (System.nanoTime() - origin) / 1_000_000 }
}
