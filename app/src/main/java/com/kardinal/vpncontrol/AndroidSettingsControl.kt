package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.control.*
import com.kardinal.vpncontrol.data.AndroidSettingsCommit
import com.kardinal.vpncontrol.model.*
import java.security.MessageDigest
import java.util.UUID
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout

/** Owner jobs survive provider wait cancellation. Only hashed requests are retained in the ledger. */
internal class AndroidSettingsControl(
    private val controllerId: String,
    private val scope: CoroutineScope,
    private val snapshot: suspend () -> ControlCommitted<PersistedState>,
    private val commit: suspend (Map<String, ControlValue>, String, Long?) -> AndroidSettingsCommit,
    private val schedule: suspend (PersistedState) -> Unit,
    private val pendingRestart: (PersistedState) -> Boolean?,
    private val busy: () -> Boolean = { false },
    private val mutationJobs: AndroidCommandJobs? = null,
    private val off: AndroidOffControl? = null,
    private val connection: AndroidConnectionControl? = null,
    private val now: () -> Long = { System.nanoTime() / 1_000_000 },
    private val schedulingTimeoutMillis: Long = 15_000,
    private val importKey: (suspend (String, String, Long?) -> AndroidSettingsCommit)? = null,
    private val setSource: (suspend (Map<String, ControlValue>, String, Long?) -> AndroidSettingsCommit)? = null,
    private val subscription: (suspend (ControlOperationId, Map<String, ControlValue>, String, Long?) -> AndroidSettingsCommit)? = null,
    private val routing: (suspend (ControlOperationId, Map<String, ControlValue>, String, Long?) -> AndroidSettingsCommit)? = null,
    private val location: (suspend (ControlOperationId, Map<String, ControlValue>, String, Long?) -> AndroidSettingsCommit)? = null,
    private val updates: (() -> AndroidUpdateControl)? = null,
    private val updateInspection: (() -> Map<String, ControlValue>)? = null,
) {
    private val ledger = ControlOperationLedger(controllerId)
    private val waiting = mutableMapOf<String, CompletableDeferred<ControlResult>>()

    fun operationIdForRequest(requestId: String): String? = synchronized(ledger) { ledger.forRequest(requestId, now())?.id }

    suspend fun execute(request: ControlRequest): ControlResult {
        if (request.controllerId != controllerId) return rejected(request, ControlCode.CONFLICT)
        if (request.command.operation == ControlOperationId.OPERATIONS_CANCEL) return cancelOperation(request)
        if (request.command.operation in inspectionOperations) return inspectOperation(request)
        val isConnection = request.command.operation in setOf(ControlOperationId.ON, ControlOperationId.RESTART)
        val isRuntime = isConnection || request.command.operation == ControlOperationId.OFF
        val isUpdate = request.command.operation in AndroidUpdateControl.operations
        val updateControlPlane = request.command.operation in AndroidUpdateControl.controlPlane
        val allowsAsync = isRuntime || isUpdate && !updateControlPlane || request.command.operation in setOf(ControlOperationId.SUBSCRIPTIONS_ADD, ControlOperationId.SUBSCRIPTIONS_UPDATE)
        if (request.command.operation !in operations || request.asynchronous && !allowsAsync || request.interactive && !isConnection) {
            return rejected(request, ControlCode.INVALID_ARGUMENT)
        }
        val isOff = request.command.operation == ControlOperationId.OFF
        val isKey = request.command.operation == ControlOperationId.SSH_KEY_IMPORT
        val isSource = request.command.operation == ControlOperationId.SOURCE_SET
        val isSubscription = request.command.operation in com.kardinal.vpncontrol.data.AndroidSubscriptionControl.operations
        val isRouting = request.command.operation in com.kardinal.vpncontrol.data.AndroidRoutingControl.operations
        val isLocation = request.command.operation in com.kardinal.vpncontrol.data.AndroidLocationControl.operations
        if (isUpdate && updates == null) return rejected(request, ControlCode.UNSUPPORTED)
        if (isLocation && location == null) return rejected(request, ControlCode.UNSUPPORTED)
        if (isRouting && routing == null) return rejected(request, ControlCode.UNSUPPORTED)
        if (isSubscription && subscription == null) return rejected(request, ControlCode.UNSUPPORTED)
        if (isSource && setSource == null) return rejected(request, ControlCode.UNSUPPORTED)
        if (isKey && importKey == null) return rejected(request, ControlCode.UNSUPPORTED)
        if (isOff && off == null) return rejected(request, ControlCode.UNSUPPORTED)
        if (isConnection && connection == null) return rejected(request, ControlCode.UNSUPPORTED)
        val patch = if (isLocation) {
            runCatching { com.kardinal.vpncontrol.data.AndroidLocationControl.arguments(request.command.operation, request.command.arguments) }
                .getOrElse { return rejected(request, ControlCode.INVALID_ARGUMENT) }
        } else if (isRouting) {
            runCatching { com.kardinal.vpncontrol.data.AndroidRoutingControl.arguments(request.command.operation, request.command.arguments) }
                .getOrElse { return rejected(request, ControlCode.INVALID_ARGUMENT) }
        } else if (isSubscription) {
            runCatching { com.kardinal.vpncontrol.data.AndroidSubscriptionControl.arguments(request.command.operation, request.command.arguments) }
                .getOrElse { return rejected(request, ControlCode.INVALID_ARGUMENT) }
        } else if (isSource) {
            runCatching { com.kardinal.vpncontrol.data.AndroidSourceControl.arguments(request.command.arguments) }
                .getOrElse { return rejected(request, ControlCode.INVALID_ARGUMENT) }
        } else if (isKey) {
            val content = (request.command.arguments["input"] as? ControlValue.Text)?.value
            if (request.command.arguments.keys != setOf("input") || content.isNullOrBlank())
                return rejected(request, ControlCode.INVALID_ARGUMENT)
            request.command.arguments
        } else if (isRuntime || isUpdate) {
            if (request.command.arguments.isNotEmpty()) return rejected(request, ControlCode.INVALID_ARGUMENT)
            emptyMap()
        } else ControlSettingsLogic.parseRequestArguments(request.command.operation, request.command.arguments)
            .getOrElse { return rejected(request, ControlCode.INVALID_ARGUMENT) }
        val normalized = ControlProtocolCodec.encodeValues(patch.toSortedMap()) + "\u0000" + request.ifRevision + "\u0000" + request.interactive
        val fingerprint = MessageDigest.getInstance("SHA-256").digest(normalized.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }
        val existing = synchronized(ledger) { ledger.forRequest(request.requestId, now()) != null }
        if (!existing) {
            val current = runCatching { snapshot() }.getOrNull()
            if (current == null) return rejected(request, ControlCode.UNAVAILABLE)
            if (isUpdate && request.ifRevision != null && request.ifRevision != current.revision) return rejected(request, ControlCode.CONFLICT)
            if (isConnection) connection?.preflight(request, current.value)?.let { return rejected(request, it) }
            else if (!isUpdate && if (isOff) off?.available() != true else pendingRestart(current.value) == null)
                return rejected(request, ControlCode.UNAVAILABLE)
        }
        var rejection: ControlCode? = null
        val completion = synchronized(ledger) {
            val isNew = ledger.forRequest(request.requestId, now()) == null
            val alreadyBusy = isNew && if (updateControlPlane) ledger.list(now()).count {
                it.operation in AndroidUpdateControl.controlPlane && !it.phase.terminal
            } >= 32 else busy()
            val lease = if (isNew && !alreadyBusy && !updateControlPlane) mutationJobs?.tryAcquireMutation() else null
            if (isNew && (alreadyBusy || !updateControlPlane && mutationJobs != null && lease == null)) {
                rejection = ControlCode.BUSY
                null
            } else when (val admission = ledger.admit(
                UUID.randomUUID().toString(), request.requestId, request.command.operation,
                fingerprint, mutates = !updateControlPlane, cancellable = isUpdate && !updateControlPlane, now = now(),
            )) {
                is ControlOperationAdmission.Rejected -> {
                    if (lease != null) mutationJobs?.releaseMutation(lease)
                    rejection = admission.code; null
                }
                is ControlOperationAdmission.Existing -> waiting[admission.operation.id]
                    ?: CompletableDeferred(requireNotNull(admission.operation.result))
                is ControlOperationAdmission.Started -> {
                    val operation = admission.operation
                    val updateGeneration = if (isUpdate) updates?.invoke()?.generation() else null
                    val result = CompletableDeferred<ControlResult>()
                    waiting[operation.id] = result
                    val job = scope.launch(start = CoroutineStart.LAZY) {
                        synchronized(ledger) {
                            if (ledger.get(operation.id, now())?.phase != ControlOperationPhase.CANCELLING)
                                ledger.advance(operation.id, ControlOperationPhase.RUNNING, now())
                        }
                        val completed = if (isUpdate) performUpdate(request, operation.id, updateGeneration)
                            else if (isOff) requireNotNull(off).execute(request, operation.id)
                            else if (isConnection) requireNotNull(connection).execute(request, operation.id) { awaiting ->
                                synchronized(ledger) {
                                    if (ledger.get(operation.id, now())?.phase == ControlOperationPhase.CANCELLING) false
                                    else {
                                        ledger.advance(operation.id,
                                            if (awaiting) ControlOperationPhase.AWAITING_USER else ControlOperationPhase.RUNNING,
                                            now(), cancellable = awaiting)
                                        true
                                    }
                                }
                            }
                            else perform(request, operation.id, patch)
                        synchronized(ledger) {
                            ledger.complete(operation.id, completed, now())
                        }
                    }
                    job.invokeOnCompletion { error ->
                        val terminal = synchronized(ledger) {
                                ledger.get(operation.id, now())?.result ?: ControlResult(
                                    controllerId, request.requestId,
                                    if (error is CancellationException) ControlCode.CANCELLED else ControlCode.RUNTIME_FAILED,
                                    0, operationId = operation.id,
                                    warnings = listOf("CONFIGURATION_REVISION_UNAVAILABLE"),
                                ).also { ledger.complete(operation.id, it, now()) }
                        }
                        if (lease != null) mutationJobs?.releaseMutation(lease)
                        synchronized(ledger) { waiting.remove(operation.id) }
                        result.complete(terminal)
                    }
                    job.start()
                    result
                }
            }
        }
        if (completion == null) return rejected(request, requireNotNull(rejection))
        if ((request.asynchronous || isConnection && request.interactive) && !completion.isCompleted) {
            val operation = synchronized(ledger) { requireNotNull(ledger.forRequest(request.requestId, now())) }
            return accepted(request.requestId, operation)
        }
        return completion.await()
    }

    private suspend fun accepted(requestId: String, operation: ControlOperation): ControlResult {
        val metadata = runCatching { snapshot() }.getOrNull()
        val pending = metadata?.value?.let(pendingRestart)
        return ControlResult(controllerId, requestId, ControlCode.ACCEPTED, metadata?.revision ?: 0,
            final = false, operationId = operation.id, restartRequired = pending ?: false,
            data = (if (operation.operation in AndroidUpdateControl.operations) updateInspection?.invoke().orEmpty() else emptyMap()) +
                mapOf("phase" to ControlValue.Text(operation.phase.wireName)),
            warnings = (if (metadata == null) listOf("CONFIGURATION_REVISION_UNAVAILABLE") else emptyList()) +
                if (pending == null) listOf("PENDING_RESTART_STATE_UNAVAILABLE") else emptyList())
    }

    private suspend fun inspectOperation(request: ControlRequest): ControlResult {
        if (request.command.operation == ControlOperationId.OPERATIONS_LIST) {
            if (request.command.arguments.isNotEmpty() || request.interactive || request.asynchronous || request.ifRevision != null)
                return rejected(request, ControlCode.INVALID_ARGUMENT)
            val listed = synchronized(ledger) { ledger.list(now()).map(::operationSummary) }
            return rejected(request, ControlCode.OK).copy(data = mapOf(
                "scope" to ControlValue.Text("android-provider-operations"), "operations" to ControlValue.ArrayValue(listed)))
        }
        val id = (request.command.arguments["id"] as? ControlValue.Text)?.value
        if (id.isNullOrBlank() || request.command.arguments.keys != setOf("id") || request.interactive || request.asynchronous || request.ifRevision != null)
            return rejected(request, ControlCode.INVALID_ARGUMENT)
        val operation = synchronized(ledger) { ledger.get(id, now()) } ?: return rejected(request, ControlCode.NOT_FOUND)
        operation.result?.let { return it.copy(requestId = request.requestId) }
        if (request.command.operation == ControlOperationId.OPERATIONS_STATUS) return accepted(request.requestId, operation)
        val completion = synchronized(ledger) { ledger.get(id, now())?.result?.let { CompletableDeferred(it) } ?: waiting[id] }
            ?: return rejected(request, ControlCode.NOT_FOUND)
        return completion.await().copy(requestId = request.requestId)
    }

    private fun operationSummary(operation: ControlOperation): ControlValue {
        val progress = if (operation.operation in AndroidUpdateControl.operations)
            operation.result?.data ?: updateInspection?.invoke().orEmpty() else emptyMap()
        return ControlValue.ObjectValue(mapOf(
        "controllerId" to ControlValue.Text(controllerId), "id" to ControlValue.Text(operation.id),
        "requestId" to ControlValue.Text(operation.requestId), "operation" to ControlValue.Text(operation.operation.wireName),
        "phase" to ControlValue.Text(operation.phase.wireName), "final" to ControlValue.BooleanValue(operation.phase.terminal),
        "cancellable" to ControlValue.BooleanValue(operation.cancellable),
        "completedUnits" to (progress["downloadedBytes"] ?: operation.completedUnits?.let(ControlValue::IntegerValue) ?: ControlValue.Null),
        "totalUnits" to (progress["totalBytes"] ?: operation.totalUnits?.let(ControlValue::IntegerValue) ?: ControlValue.Null),
        "code" to (operation.result?.code?.wireName?.let(ControlValue::Text) ?: ControlValue.Null),
        "configurationRevision" to (operation.result?.configurationRevision?.let(ControlValue::IntegerValue) ?: ControlValue.Null),
        "restartRequired" to (operation.result?.restartRequired?.let(ControlValue::BooleanValue) ?: ControlValue.Null),
    ))
    }

    /** Control-plane admission bypasses the target's mutation lease, never its safe-effect gate. */
    private suspend fun cancelOperation(request: ControlRequest): ControlResult {
        val target = (request.command.arguments["id"] as? ControlValue.Text)?.value
        if (target.isNullOrBlank() || request.command.arguments.keys != setOf("id") || request.interactive || request.asynchronous)
            return rejected(request, ControlCode.INVALID_ARGUMENT)
        val metadata = runCatching { snapshot() }.getOrNull() ?: return rejected(request, ControlCode.UNAVAILABLE)
        val fingerprint = MessageDigest.getInstance("SHA-256")
            .digest((target + "\u0000" + request.ifRevision).toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
        var rejection: ControlCode? = null
        val completion = synchronized(ledger) {
            val existing = ledger.forRequest(request.requestId, now())
            if (existing == null && (metadata.controllerId != controllerId || request.ifRevision != null && request.ifRevision != metadata.revision)) {
                rejection = ControlCode.CONFLICT
                null
            } else if (existing == null && ledger.list(now()).count {
                    it.operation == ControlOperationId.OPERATIONS_CANCEL && !it.phase.terminal
                } >= 32) {
                rejection = ControlCode.BUSY
                null
            } else when (val admission = ledger.admit(UUID.randomUUID().toString(), request.requestId,
                ControlOperationId.OPERATIONS_CANCEL, fingerprint, mutates = false, cancellable = false, now = now())) {
                is ControlOperationAdmission.Rejected -> { rejection = admission.code; null }
                is ControlOperationAdmission.Existing -> waiting[admission.operation.id]
                    ?: CompletableDeferred(requireNotNull(admission.operation.result))
                is ControlOperationAdmission.Started -> {
                    val id = admission.operation.id
                    val deferred = CompletableDeferred<ControlResult>()
                    waiting[id] = deferred
                    // This monitor also guards leaving AWAITING_USER before prepare().
                    val code = ledger.requestCancellation(target, now())
                    val targetCompletion = if (code == ControlCode.OK) waiting[target] else null
                    val updateTarget = code == ControlCode.OK && ledger.get(target, now())?.operation in AndroidUpdateControl.operations
                    // Capture under the same ledger monitor as target cancellation. A delayed
                    // continuation must never cancel a newer transfer after target completion.
                    val updateCancellation = if (updateTarget) updates?.invoke()?.reserveCancellation() else null
                    if (code == ControlCode.OK) connection?.cancelConsentWait(target)
                    val job = scope.launch(start = CoroutineStart.LAZY) {
                        val completedCode = if (updateTarget) updateCancellation?.let {
                            requireNotNull(updates).invoke().finishCancellation(it).code
                        } ?: ControlCode.BUSY else code
                        if (targetCompletion != null) targetCompletion.await()
                        val response = rejected(request, completedCode).copy(operationId = id,
                            data = synchronized(ledger) { ledger.get(target, now())?.let {
                                mapOf("operation" to operationSummary(it))
                            } ?: emptyMap() })
                        synchronized(ledger) { ledger.complete(id, response, now()) }
                    }
                    job.invokeOnCompletion { error ->
                        val terminal = synchronized(ledger) {
                            val result = ledger.get(id, now())?.result ?: ControlResult(controllerId, request.requestId,
                                if (error is CancellationException) ControlCode.CANCELLED else ControlCode.RUNTIME_FAILED,
                                metadata.revision, operationId = id,
                                warnings = listOf("CANCELLATION_OUTCOME_UNAVAILABLE"))
                                .also { ledger.complete(id, it, now()) }
                            waiting.remove(id)
                            result
                        }
                        deferred.complete(terminal)
                    }
                    job.start()
                    deferred
                }
            }
        }
        return completion?.await() ?: rejected(request, requireNotNull(rejection))
    }

    private suspend fun performUpdate(request: ControlRequest, operationId: String, generation: Long?): ControlResult {
        val current = runCatching { snapshot() }.getOrNull() ?: return rejected(request, ControlCode.RUNTIME_FAILED).copy(operationId = operationId,
            warnings = listOf("CONFIGURATION_REVISION_UNAVAILABLE", "UPDATE_NOT_STARTED"))
        if (current.controllerId != controllerId || request.ifRevision != null && request.ifRevision != current.revision)
            return rejected(request, ControlCode.CONFLICT).copy(operationId = operationId)
        val transferWaiters = if (request.command.operation in AndroidUpdateControl.controlPlane) synchronized(ledger) {
            ledger.list(now()).filter { it.operation in AndroidUpdateControl.operations &&
                it.operation !in AndroidUpdateControl.controlPlane && !it.phase.terminal }.mapNotNull { waiting[it.id] }
        } else emptyList()
        val outcome = requireNotNull(updates).invoke().execute(request.command.operation, generation)
        if (outcome.code == ControlCode.OK) transferWaiters.forEach { it.await() }
        return rejected(request, outcome.code).copy(operationId = operationId, data = outcome.data)
    }

    private suspend fun perform(request: ControlRequest, operationId: String, patch: Map<String, ControlValue>): ControlResult {
        var durable: AndroidSettingsCommit? = null
        return try {
            val isKey = request.command.operation == ControlOperationId.SSH_KEY_IMPORT
            val isSource = request.command.operation == ControlOperationId.SOURCE_SET
            val isSubscription = request.command.operation in com.kardinal.vpncontrol.data.AndroidSubscriptionControl.operations
            val isRouting = request.command.operation in com.kardinal.vpncontrol.data.AndroidRoutingControl.operations
            val isLocation = request.command.operation in com.kardinal.vpncontrol.data.AndroidLocationControl.operations
            durable = if (isLocation) requireNotNull(location).invoke(request.command.operation, patch, controllerId, request.ifRevision)
                else if (isRouting) requireNotNull(routing).invoke(request.command.operation, patch, controllerId, request.ifRevision)
                else if (isSubscription) requireNotNull(subscription).invoke(request.command.operation, patch, controllerId, request.ifRevision)
                else if (isSource) requireNotNull(setSource).invoke(patch, controllerId, request.ifRevision)
                else if (isKey) requireNotNull(importKey).invoke(
                (patch.getValue("input") as ControlValue.Text).value, controllerId, request.ifRevision)
                else commit(patch, controllerId, request.ifRevision)
            if (durable.schedulingChanged) withTimeout(schedulingTimeoutMillis) { schedule(durable.committed.value) }
            val pending = pendingRestart(durable.committed.value)
            if (pending == null) return ControlResult(controllerId, request.requestId, ControlCode.RUNTIME_FAILED,
                durable.committed.revision, operationId = operationId,
                data = mapOf("configurationCommitted" to ControlValue.BooleanValue(true)),
                warnings = listOf("CONFIGURATION_COMMITTED", "PENDING_RESTART_STATE_UNAVAILABLE"))
            ControlResult(controllerId, request.requestId, ControlCode.OK, durable.committed.revision,
                operationId = operationId, data = if (isKey) mapOf("present" to ControlValue.BooleanValue(true))
                    else if (isSource) com.kardinal.vpncontrol.data.AndroidSourceControl.result(durable.committed.value)
                    else if (isSubscription) durable.resultData.filterKeys { it == "id" }
                    else if (isLocation) durable.resultData.filterKeys { it == "id" }
                    else if (isRouting) com.kardinal.vpncontrol.data.AndroidRoutingControl.result(durable.committed.value, request.command.operation, patch)
                    else ControlSettingsLogic.inspect(durable.committed.value).filterKeys { it in patch },
                restartRequired = pending)
        } catch (error: Exception) {
            val code = if (durable != null) ControlCode.RUNTIME_FAILED else when (error.message) {
                "CONFLICT" -> ControlCode.CONFLICT
                "NOT_FOUND" -> ControlCode.NOT_FOUND
                "AMBIGUOUS_LOCATION" -> ControlCode.AMBIGUOUS_LOCATION
                "INVALID_ARGUMENT" -> ControlCode.INVALID_ARGUMENT
                "UNSUPPORTED" -> ControlCode.UNSUPPORTED
                "RUNTIME_STATE_UNKNOWN" -> ControlCode.RUNTIME_FAILED
                else -> ControlCode.PERSISTENCE_FAILED
            }
            val metadata = durable?.committed ?: runCatching { snapshot() }.getOrNull()
            val pending = metadata?.value?.let(pendingRestart)
            ControlResult(controllerId, request.requestId, code, metadata?.revision ?: 0, operationId = operationId,
                restartRequired = pending ?: false,
                data = if (durable != null) mapOf("configurationCommitted" to ControlValue.BooleanValue(true)) else emptyMap(),
                warnings = if (durable != null) listOf("CONFIGURATION_COMMITTED", "SCHEDULING_FAILED_OR_UNKNOWN") +
                    if (pending == null) listOf("PENDING_RESTART_STATE_UNAVAILABLE") else emptyList()
                    else if (error.message == "RUNTIME_STATE_UNKNOWN") listOf("CONFIGURATION_NOT_COMMITTED", "PENDING_RESTART_STATE_UNAVAILABLE")
                    else if (metadata == null) listOf("CONFIGURATION_REVISION_UNAVAILABLE") else emptyList())
        }
    }

    private suspend fun rejected(request: ControlRequest, code: ControlCode): ControlResult {
        val committed = runCatching { snapshot() }.getOrNull()
        val pending = committed?.value?.let(pendingRestart)
        return ControlResult(controllerId, request.requestId, code, committed?.revision ?: 0,
            restartRequired = pending ?: false,
            warnings = (if (committed == null) listOf("CONFIGURATION_REVISION_UNAVAILABLE") else emptyList()) +
                if (pending == null) listOf("PENDING_RESTART_STATE_UNAVAILABLE") else emptyList())
    }

    companion object {
        val inspectionOperations = setOf(ControlOperationId.OPERATIONS_LIST, ControlOperationId.OPERATIONS_STATUS, ControlOperationId.OPERATIONS_WAIT)
        val operations = setOf(ControlOperationId.SETTINGS_SET, ControlOperationId.SETTINGS_APPLY,
            ControlOperationId.SSH_KEY_IMPORT, ControlOperationId.SOURCE_SET,
            ControlOperationId.OFF, ControlOperationId.ON, ControlOperationId.RESTART, ControlOperationId.OPERATIONS_CANCEL) + inspectionOperations +
            com.kardinal.vpncontrol.data.AndroidSubscriptionControl.operations + com.kardinal.vpncontrol.data.AndroidRoutingControl.operations +
            com.kardinal.vpncontrol.data.AndroidLocationControl.operations + AndroidUpdateControl.operations
    }
}
