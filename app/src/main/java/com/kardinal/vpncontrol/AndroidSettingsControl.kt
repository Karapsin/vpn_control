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
    private val locationRemoval: AndroidLocationDestructiveControl? = null,
    private val updates: (() -> AndroidUpdateControl)? = null,
    private val updateInspection: (() -> Map<String, ControlValue>)? = null,
    private val updateInstall: (() -> AndroidUpdateInstallControl)? = null,
    private val refresh: (() -> AndroidSubscriptionRefreshControl)? = null,
    private val benchmark: (() -> AndroidLocationBenchmarkControl)? = null,
    private val findBest: (() -> AndroidFindBestControl)? = null,
    private val routingImport: (suspend (com.kardinal.vpncontrol.data.AndroidPreparedRouting, String, Long?) -> AndroidSettingsCommit)? = null,
    private val routingDispatcher: kotlinx.coroutines.CoroutineDispatcher? = null,
    private val retainedResults: AndroidRetainedControlResults? = null,
) {
    private val ledger = ControlOperationLedger(controllerId)
    private val waiting = mutableMapOf<String, CompletableDeferred<ControlResult>>()
    private val mutableFindBestActive = kotlinx.coroutines.flow.MutableStateFlow(false)
    val findBestActive: kotlinx.coroutines.flow.StateFlow<Boolean> = mutableFindBestActive

    init {
        retainedResults?.let { retained ->
            scope.coroutineContext[kotlinx.coroutines.Job]?.invokeOnCompletion { runCatching { retained.close() } }
            scope.launch(kotlinx.coroutines.Dispatchers.IO) {
                while (true) {
                    kotlinx.coroutines.delay(1_000)
                    // Failed closes remain tracked for a later cleanup attempt.
                    runCatching { retained.reap() }
                }
            }
        }
    }

    fun operationIdForRequest(requestId: String): String? = synchronized(ledger) { ledger.forRequest(requestId, now())?.id }
    internal fun activeRefreshOperationId(): String? = synchronized(ledger) {
        ledger.list(now()).firstOrNull { it.operation == ControlOperationId.SUBSCRIPTIONS_REFRESH && !it.phase.terminal }?.id
    }
    internal fun activeBenchmarkOperationId(): String? = synchronized(ledger) {
        ledger.list(now()).firstOrNull { it.operation == ControlOperationId.LOCATIONS_BENCHMARK && !it.phase.terminal }?.id
    }
    internal fun activeFindBestOperationId(): String? = synchronized(ledger) {
        ledger.list(now()).firstOrNull { it.operation == ControlOperationId.FIND_BEST && !it.phase.terminal }?.id
    }

    suspend fun execute(request: ControlRequest): ControlResult = execute(request, null)

    internal suspend fun execute(request: ControlRequest, refreshContinuation: AndroidRefreshContinuation?): ControlResult {
        if (request.command.operation == ControlOperationId.ROUTING_IMPORT && routingImport != null)
            return admitRoutingImport(request).await()
        if (request.controllerId != controllerId) return rejected(request, ControlCode.CONFLICT)
        if (request.command.operation == ControlOperationId.OPERATIONS_CANCEL) return cancelOperation(request)
        if (request.command.operation in inspectionOperations) return inspectOperation(request)
        val isConnection = request.command.operation in setOf(ControlOperationId.ON, ControlOperationId.RESTART)
        val isRuntime = isConnection || request.command.operation == ControlOperationId.OFF
        val isInstall = request.command.operation == ControlOperationId.UPDATES_INSTALL
        val isRefresh = request.command.operation == ControlOperationId.SUBSCRIPTIONS_REFRESH
        val isBenchmark = request.command.operation == ControlOperationId.LOCATIONS_BENCHMARK
        val isFindBest = request.command.operation == ControlOperationId.FIND_BEST
        val isUpdate = isInstall || request.command.operation in AndroidUpdateControl.operations
        val updateControlPlane = request.command.operation in AndroidUpdateControl.controlPlane
        val isLocationRemoval = request.command.operation in com.kardinal.vpncontrol.data.AndroidLocationControl.destructiveOperations
        val allowsAsync = isFindBest || isBenchmark || isRefresh || isRuntime || isLocationRemoval || isUpdate && !updateControlPlane || request.command.operation in setOf(ControlOperationId.SUBSCRIPTIONS_ADD, ControlOperationId.SUBSCRIPTIONS_UPDATE)
        if (request.command.operation !in operations || request.asynchronous && !allowsAsync || request.interactive && !isConnection && !isInstall && !isFindBest) {
            return rejected(request, ControlCode.INVALID_ARGUMENT)
        }
        val isOff = request.command.operation == ControlOperationId.OFF
        val isKey = request.command.operation == ControlOperationId.SSH_KEY_IMPORT
        val isSource = request.command.operation == ControlOperationId.SOURCE_SET
        val isSubscription = request.command.operation in com.kardinal.vpncontrol.data.AndroidSubscriptionControl.operations
        val isRouting = request.command.operation in com.kardinal.vpncontrol.data.AndroidRoutingControl.operations
        val isLocation = request.command.operation in com.kardinal.vpncontrol.data.AndroidLocationControl.operations
        if (isUpdate && updates == null) return rejected(request, ControlCode.UNSUPPORTED)
        if (isRefresh && refresh == null) return rejected(request, ControlCode.UNSUPPORTED)
        if (isBenchmark && benchmark == null) return rejected(request, ControlCode.UNSUPPORTED)
        if (isFindBest && findBest == null) return rejected(request, ControlCode.UNSUPPORTED)
        if (isInstall && updateInstall == null) return rejected(request, ControlCode.UNSUPPORTED)
        if (isLocation && if (isLocationRemoval) locationRemoval == null else location == null) return rejected(request, ControlCode.UNSUPPORTED)
        if (isRouting && routing == null) return rejected(request, ControlCode.UNSUPPORTED)
        if (isSubscription && subscription == null) return rejected(request, ControlCode.UNSUPPORTED)
        if (isSource && setSource == null) return rejected(request, ControlCode.UNSUPPORTED)
        if (isKey && importKey == null) return rejected(request, ControlCode.UNSUPPORTED)
        if (isOff && off == null) return rejected(request, ControlCode.UNSUPPORTED)
        if (isConnection && connection == null) return rejected(request, ControlCode.UNSUPPORTED)
        val patch = if (isBenchmark) {
            runCatching { AndroidLocationBenchmarkControl.arguments(request.command.arguments) }.getOrElse { return rejected(request, ControlCode.INVALID_ARGUMENT) }
        } else if (isRefresh) {
            runCatching { AndroidSubscriptionRefreshControl.arguments(request.command.arguments) }.getOrElse { return rejected(request, ControlCode.INVALID_ARGUMENT) }
        } else if (isLocation) {
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
        } else if (isRuntime || isUpdate || isFindBest) {
            if (request.command.arguments.isNotEmpty()) return rejected(request, ControlCode.INVALID_ARGUMENT)
            emptyMap()
        } else ControlSettingsLogic.parseRequestArguments(request.command.operation, request.command.arguments)
            .getOrElse { return rejected(request, ControlCode.INVALID_ARGUMENT) }
        val fingerprint = androidControlRequestFingerprint(patch, request.ifRevision, request.interactive, refreshContinuation != null)
        val existing = synchronized(ledger) { ledger.forRequest(request.requestId, now()) != null }
        if (!existing) {
            val current = runCatching { snapshot() }.getOrNull()
            if (current == null) return rejected(request, ControlCode.UNAVAILABLE)
            if ((isUpdate || isRefresh || isBenchmark || isFindBest) && request.ifRevision != null && request.ifRevision != current.revision) return rejected(request, ControlCode.CONFLICT)
            if (isInstall && !request.interactive) return rejected(request, ControlCode.INTERACTION_REQUIRED)
            if (isConnection) connection?.preflight(request, current.value)?.let { return rejected(request, it) }
            else if (!isUpdate && !isRefresh && if (isOff) off?.available() != true else pendingRestart(current.value) == null)
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
                fingerprint, mutates = !updateControlPlane, cancellable = isFindBest || isBenchmark || isRefresh || isUpdate && !updateControlPlane, now = now(),
            )) {
                is ControlOperationAdmission.Rejected -> {
                    if (lease != null) mutationJobs?.releaseMutation(lease)
                    rejection = admission.code; null
                }
                is ControlOperationAdmission.Existing -> waiting[admission.operation.id]
                    ?: CompletableDeferred(requireNotNull(admission.operation.result))
                is ControlOperationAdmission.Started -> {
                    val operation = admission.operation
                    if (isFindBest) mutableFindBestActive.value = true
                    val updateGeneration = if (isUpdate) updates?.invoke()?.generation() else null
                    val result = CompletableDeferred<ControlResult>()
                    waiting[operation.id] = result
                    val job = scope.launch(start = CoroutineStart.LAZY) {
                        synchronized(ledger) {
                            if (ledger.get(operation.id, now())?.phase != ControlOperationPhase.CANCELLING)
                                ledger.advance(operation.id, ControlOperationPhase.RUNNING, now())
                        }
                        val completed = androidControlResourceBoundary(controllerId, request.requestId, operation.id) {
                            if (isFindBest) requireNotNull(findBest).invoke().execute(request, operation.id,
                                progress = { done, total -> synchronized(ledger) {
                                    val current = ledger.get(operation.id, now())
                                    if (current != null && !current.phase.terminal) ledger.advance(operation.id, current.phase, now(), done, total)
                                } },
                                awaitingUser = { awaiting -> synchronized(ledger) {
                                    if (ledger.get(operation.id, now())?.phase == ControlOperationPhase.CANCELLING) false
                                    else { ledger.advance(operation.id, if (awaiting) ControlOperationPhase.AWAITING_USER else ControlOperationPhase.RUNNING,
                                        now(), cancellable = true); true }
                                } },
                                canRun = { synchronized(ledger) { ledger.get(operation.id, now())?.phase != ControlOperationPhase.CANCELLING } },
                                beginCommit = { synchronized(ledger) {
                                    if (ledger.get(operation.id, now())?.phase == ControlOperationPhase.CANCELLING) false
                                    else { ledger.advance(operation.id, ControlOperationPhase.RUNNING, now(), cancellable = false); true }
                                } })
                            else if (isBenchmark) requireNotNull(benchmark).invoke().execute(request, operation.id,
                            progress = { done, total -> synchronized(ledger) {
                                val current = ledger.get(operation.id, now())
                                if (current != null && !current.phase.terminal) ledger.advance(operation.id, current.phase, now(), done, total)
                            } },
                            beginCommit = { synchronized(ledger) {
                                if (ledger.get(operation.id, now())?.phase == ControlOperationPhase.CANCELLING) false
                                else { ledger.advance(operation.id, ControlOperationPhase.RUNNING, now(), cancellable = false); true }
                            } },
                            canProbe = { synchronized(ledger) { ledger.get(operation.id, now())?.phase != ControlOperationPhase.CANCELLING } })
                            else if (isRefresh) requireNotNull(refresh).invoke().execute(request, operation.id,
                            progress = { done, total -> synchronized(ledger) {
                                val current = ledger.get(operation.id, now())
                                if (current != null && !current.phase.terminal) ledger.advance(operation.id, current.phase, now(), maxOf(done, current.completedUnits ?: 0), total)
                            } },
                            beginCommit = { synchronized(ledger) {
                                if (ledger.get(operation.id, now())?.phase == ControlOperationPhase.CANCELLING) false
                                else { ledger.advance(operation.id, ControlOperationPhase.RUNNING, now(), cancellable = false); true }
                            } },
                            canFetch = { synchronized(ledger) { ledger.get(operation.id, now())?.phase != ControlOperationPhase.CANCELLING } },
                            continuation = refreshContinuation)
                            else if (isInstall) performInstall(request, operation.id)
                            else if (isLocationRemoval) requireNotNull(locationRemoval).execute(request, operation.id)
                            else if (isUpdate) performUpdate(request, operation.id, updateGeneration)
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
                        }
                        val retained = retainedResults?.retain(completed) ?: completed
                        synchronized(ledger) {
                            ledger.complete(operation.id, retained, now())
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
                        if (isFindBest) mutableFindBestActive.value = false
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
        if ((request.asynchronous || (isConnection || isInstall || isFindBest) && request.interactive) && !completion.isCompleted) {
            val operation = synchronized(ledger) { requireNotNull(ledger.forRequest(request.requestId, now())) }
            return accepted(request.requestId, operation)
        }
        return completion.await()
    }

    /** Returns before awaiting the owner job, so transport callers need not retain its document. */
    internal suspend fun admitRoutingImport(request: ControlRequest): kotlinx.coroutines.Deferred<ControlResult> {
        suspend fun reject(code: ControlCode) = CompletableDeferred(rejected(request, code))
        if (request.controllerId != controllerId) return reject(ControlCode.CONFLICT)
        if (request.command.operation != ControlOperationId.ROUTING_IMPORT || request.asynchronous || request.interactive)
            return reject(ControlCode.INVALID_ARGUMENT)
        if (routingImport == null) return reject(ControlCode.UNSUPPORTED)
        val arguments = try { com.kardinal.vpncontrol.data.AndroidRoutingControl.arguments(request.command.operation, request.command.arguments) }
            catch (_: Exception) { return reject(ControlCode.INVALID_ARGUMENT) }
        val fingerprint = androidControlRequestFingerprint(arguments, request.ifRevision, false, false)
        return admitRoutingPayload(request, fingerprint,
            com.kardinal.vpncontrol.data.AndroidRoutingPreparedInput((arguments.getValue("input") as ControlValue.Text).value))
    }

    /** Adopts the external input on every return path; accepted jobs outlive transport waiters. */
    internal suspend fun admitRoutingDocument(request: ControlRequest, input: AndroidControlInputSpool): kotlinx.coroutines.Deferred<ControlResult> {
        var delegated = false
        try {
            val rejection = when {
                request.controllerId != controllerId -> ControlCode.CONFLICT
                request.command.operation != ControlOperationId.ROUTING_IMPORT || request.asynchronous || request.interactive ||
                    request.command.arguments.isNotEmpty() -> ControlCode.INVALID_ARGUMENT
                routingImport == null -> ControlCode.UNSUPPORTED
                else -> null
            }
            if (rejection != null) return CompletableDeferred(rejected(request, rejection))
            val fingerprint = androidControlInputFingerprint(input.source(), request.ifRevision)
            delegated = true
            return admitRoutingPayload(request, fingerprint, com.kardinal.vpncontrol.data.AndroidRoutingPreparedInput(input))
        } finally { if (!delegated) input.close() }
    }

    private suspend fun admitRoutingPayload(request: ControlRequest, fingerprint: String,
        payload: com.kardinal.vpncontrol.data.AndroidRoutingPreparedInput): kotlinx.coroutines.Deferred<ControlResult> {
        suspend fun reject(code: ControlCode) = CompletableDeferred(rejected(request, code))
        var adopted = false
        try {
        val requestId = request.requestId
        val revision = request.ifRevision
        val existing = synchronized(ledger) { ledger.forRequest(requestId, now()) != null }
        if (!existing) {
            val current = try { snapshot() } catch (_: Exception) { return reject(ControlCode.UNAVAILABLE) }
            if (revision != null && revision != current.revision) return reject(ControlCode.CONFLICT)
            if (pendingRestart(current.value) == null) return reject(ControlCode.UNAVAILABLE)
            payload.reuseMatchingTokens(current.value.routingRules)
        }
        var rejection: ControlCode? = null
        val completion = synchronized(ledger) {
            val isNew = ledger.forRequest(requestId, now()) == null
            val alreadyBusy = isNew && busy()
            val lease = if (isNew && !alreadyBusy) mutationJobs?.tryAcquireMutation() else null
            if (isNew && (alreadyBusy || mutationJobs != null && lease == null)) {
                rejection = ControlCode.BUSY
                null
            } else when (val admission = ledger.admit(UUID.randomUUID().toString(), requestId,
                ControlOperationId.ROUTING_IMPORT, fingerprint, mutates = true, cancellable = false, now = now())) {
                is ControlOperationAdmission.Rejected -> {
                    if (lease != null) mutationJobs?.releaseMutation(lease)
                    rejection = admission.code
                    null
                }
                is ControlOperationAdmission.Existing -> waiting[admission.operation.id]
                    ?: CompletableDeferred(requireNotNull(admission.operation.result))
                is ControlOperationAdmission.Started -> {
                    val id = admission.operation.id
                    val result = CompletableDeferred<ControlResult>()
                    waiting[id] = result
                    val job = scope.launch(context = routingDispatcher ?: kotlin.coroutines.EmptyCoroutineContext,
                        start = CoroutineStart.LAZY) {
                        synchronized(ledger) { ledger.advance(id, ControlOperationPhase.RUNNING, now()) }
                        val completed = performPreparedRouting(payload, requestId, id, revision)
                        val retained = retainedResults?.retain(completed) ?: completed
                        synchronized(ledger) { ledger.complete(id, retained, now()) }
                    }
                    job.invokeOnCompletion { error ->
                        val cleanupWarning = try { payload.close(); emptyList() }
                            catch (_: Exception) { listOf("PRIVATE_INPUT_CLEANUP_UNAVAILABLE") }
                        val terminal = synchronized(ledger) {
                            ledger.get(id, now())?.result ?: ControlResult(controllerId, requestId,
                                if (error is CancellationException) ControlCode.CANCELLED else ControlCode.RUNTIME_FAILED,
                                0, operationId = id, warnings = listOf("CONFIGURATION_REVISION_UNAVAILABLE") + cleanupWarning)
                                .also { ledger.complete(id, it, now()) }
                        }
                        if (lease != null) mutationJobs?.releaseMutation(lease)
                        synchronized(ledger) { waiting.remove(id) }
                        result.complete(terminal)
                    }
                    adopted = true
                    job.start()
                    result
                }
            }
        }
        return completion ?: reject(requireNotNull(rejection))
        } finally { if (!adopted) payload.close() }
    }

    private suspend fun performPreparedRouting(payload: com.kardinal.vpncontrol.data.AndroidRoutingPreparedInput,
        requestId: String, operationId: String, revision: Long?): ControlResult {
        var durable: AndroidSettingsCommit? = null
        return try {
            val rules = try { payload.prepareForStorage() }
                catch (error: java.io.IOException) { throw error }
                catch (_: Exception) { error("INVALID_ARGUMENT") }
            durable = try { requireNotNull(routingImport).invoke(rules, controllerId, revision) }
                finally { rules.discard() }
            val pending = pendingRestart(durable.committed.value)
            ControlResult(controllerId, requestId, if (pending == null) ControlCode.RUNTIME_FAILED else ControlCode.OK,
                durable.committed.revision, operationId = operationId, restartRequired = pending ?: false,
                data = if (pending == null) mapOf("configurationCommitted" to ControlValue.BooleanValue(true))
                    else com.kardinal.vpncontrol.data.AndroidRoutingControl.result(durable.committed.value, ControlOperationId.ROUTING_IMPORT, emptyMap()),
                warnings = if (pending == null) listOf("CONFIGURATION_COMMITTED", "PENDING_RESTART_STATE_UNAVAILABLE") else emptyList())
        } catch (_: OutOfMemoryError) {
            androidControlResourceFailure(controllerId, requestId, operationId, durable?.committed?.revision)
        } catch (error: Exception) {
            val metadata = durable?.committed ?: runCatching { snapshot() }.getOrNull()
            val pending = metadata?.value?.let(pendingRestart)
            val code = if (durable != null) ControlCode.RUNTIME_FAILED else when (error.message) {
                "INVALID_ARGUMENT" -> ControlCode.INVALID_ARGUMENT
                "CONFLICT" -> ControlCode.CONFLICT
                "RUNTIME_STATE_UNKNOWN" -> ControlCode.RUNTIME_FAILED
                else -> ControlCode.PERSISTENCE_FAILED
            }
            ControlResult(controllerId, requestId, code, metadata?.revision ?: 0, operationId = operationId,
                restartRequired = pending ?: false,
                data = if (durable != null) mapOf("configurationCommitted" to ControlValue.BooleanValue(true)) else emptyMap(),
                warnings = (if (durable != null) listOf("CONFIGURATION_COMMITTED", "POST_COMMIT_RESULT_UNAVAILABLE") else emptyList()) +
                    (if (metadata == null) listOf("CONFIGURATION_REVISION_UNAVAILABLE") else emptyList()) +
                    (if (pending == null) listOf("PENDING_RESTART_STATE_UNAVAILABLE") else emptyList()))
        }
    }

    private suspend fun accepted(requestId: String, operation: ControlOperation): ControlResult {
        val metadata = runCatching { snapshot() }.getOrNull()
        val pending = metadata?.value?.let(pendingRestart)
        return ControlResult(controllerId, requestId, ControlCode.ACCEPTED, metadata?.revision ?: 0,
            final = false, operationId = operation.id, restartRequired = pending ?: false,
            data = (if (operation.operation in AndroidUpdateControl.operations) updateInspection?.invoke().orEmpty() else emptyMap()) +
                (if (operation.operation in setOf(ControlOperationId.SUBSCRIPTIONS_REFRESH, ControlOperationId.FIND_BEST, ControlOperationId.LOCATIONS_BENCHMARK)) mapOf(
                    "completedUnits" to (operation.completedUnits?.let(ControlValue::IntegerValue) ?: ControlValue.Null),
                    "totalUnits" to (operation.totalUnits?.let(ControlValue::IntegerValue) ?: ControlValue.Null)) else emptyMap()) +
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
                    if (code == ControlCode.OK) updateInstall?.invoke()?.cancel(target)
                    if (code == ControlCode.OK) refresh?.invoke()?.cancel(target)
                    if (code == ControlCode.OK) benchmark?.invoke()?.cancel(target)
                    if (code == ControlCode.OK) findBest?.invoke()?.cancel(target)
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

    private suspend fun performInstall(request: ControlRequest, operationId: String): ControlResult {
        val current = runCatching { snapshot() }.getOrNull() ?: return rejected(request, ControlCode.RUNTIME_FAILED).copy(operationId = operationId)
        if (request.ifRevision != null && request.ifRevision != current.revision)
            return rejected(request, ControlCode.CONFLICT).copy(operationId = operationId)
        val outcome = requireNotNull(updateInstall).invoke().execute(operationId) { awaiting ->
            synchronized(ledger) {
                if (ledger.get(operationId, now())?.phase == ControlOperationPhase.CANCELLING) false
                else {
                    ledger.advance(operationId, if (awaiting) ControlOperationPhase.AWAITING_USER else ControlOperationPhase.RUNNING,
                        now(), cancellable = awaiting)
                    true
                }
            }
        }
        val result = rejected(request, outcome.code).copy(operationId = operationId, data = outcome.data)
        return if (outcome.code == ControlCode.OK && outcome.data["installed"] != ControlValue.BooleanValue(true))
            result.copy(warnings = result.warnings + "INSTALLER_STARTED_NOT_INSTALLED") else result
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
        } catch (_: OutOfMemoryError) {
            androidControlResourceFailure(controllerId, request.requestId, operationId, durable?.committed?.revision)
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
            com.kardinal.vpncontrol.data.AndroidLocationControl.operations + AndroidUpdateControl.operations + ControlOperationId.UPDATES_INSTALL + ControlOperationId.SUBSCRIPTIONS_REFRESH + ControlOperationId.LOCATIONS_BENCHMARK + ControlOperationId.FIND_BEST
    }
}
