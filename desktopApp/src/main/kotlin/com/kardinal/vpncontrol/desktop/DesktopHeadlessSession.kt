package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.control.toControlValues
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/** Owns headless scheduling and shares mutation admission with terminal commands. */
internal class DesktopHeadlessSession(
    private val scope: CoroutineScope,
    private val stateProvider: () -> MainUiState,
    private val executeCommand: suspend (DesktopCliCommand) -> DesktopCliResponse,
    refresh: suspend () -> Unit,
    nowMillis: () -> Long = System::currentTimeMillis,
    val controllerId: String = java.util.UUID.randomUUID().toString(),
    private val metadataProvider: () -> DesktopControlMetadata = { DesktopControlMetadata(0, false) },
    private val applySettings: ((Map<String, com.kardinal.vpncontrol.model.ControlValue>, Long?) -> DesktopControlWriteResponse)? = null,
    private val inspectSettings: (() -> DesktopControlSettingsSnapshot)? = null,
    private val inspectStatus: ((String) -> com.kardinal.vpncontrol.model.ControlSnapshot)? = null,
    private val inspectRead: ((com.kardinal.vpncontrol.model.ControlCommand) -> DesktopControlReadSnapshot)? = null,
    private val inspectPresentation: ((String) -> DesktopPresentationSnapshot)? = null,
    private val importSshKey: ((String, Long?) -> DesktopControlWriteResponse)? = null,
    private val saveSubscription: ((String?, String?, String?, Long?) -> DesktopControlWriteResponse)? = null,
    private val saveLocation: ((DesktopCliCommand.LocationSave, Long?) -> DesktopControlWriteResponse)? = null,
    private val mutateLocation: (suspend (com.kardinal.vpncontrol.model.ControlCommand, Long?) -> DesktopControlWriteResponse)? = null,
    private val mutateSource: (suspend (com.kardinal.vpncontrol.model.ControlCommand, Long?) -> DesktopControlWriteResponse)? = null,
    private val mutateConfiguration: (suspend (DesktopCliCommand, Long?) -> DesktopControlWriteResponse)? = null,
    private val quitOwner: (suspend (String, Long?) -> DesktopControlWriteResponse)? = null,
) : AutoCloseable {
    private val mutations = Mutex()
    private val operations = DesktopOperationRunner(scope, controllerId, metadataProvider = metadataProvider)

    internal fun operationSnapshot() = operations.snapshot()
    internal val operationChanges get() = operations.changes

    internal fun hasBackgroundWork(): Boolean = mutations.isLocked ||
        operations.snapshot().any { !it.phase.terminal } || scheduler.hasScheduledWork(stateProvider())
    private val scheduler = DesktopAutoRefreshScheduler(
        scope = scope,
        runAutoRefreshCycle = { mutations.withLock { refresh() } },
        nowMillis = nowMillis,
    )
    private var observer: Job? = null

    internal suspend fun initialize(action: suspend () -> Unit) = mutations.withLock { action() }

    fun start() {
        check(observer == null)
        observer = scope.launch {
            while (isActive) {
                scheduler.sync(stateProvider())
                delay(1_000)
            }
        }
    }

    suspend fun execute(command: DesktopCliCommand): DesktopCliResponse {
        if (command is DesktopCliCommand.ControlPresentationRead) {
            if (command.requestId.isBlank()) return DesktopCliResponse.failure("INVALID_ARGUMENT")
            if (command.controllerId != controllerId) return DesktopCliResponse.failure("CONFLICT")
            val captured = inspectPresentation?.invoke(controllerId) ?: return DesktopCliResponse.failure("UNSUPPORTED")
            val result = com.kardinal.vpncontrol.model.ControlResult(controllerId, command.requestId,
                com.kardinal.vpncontrol.model.ControlCode.OK, captured.configurationRevision,
                restartRequired = captured.restartRequired, data = captured.values,
                warnings = listOf("EXPLICIT_CONFIGURATION_READS_REQUIRED"))
            return DesktopCliResponse.success(com.kardinal.vpncontrol.control.ControlProtocolCodec.encodeResult(result))
        }
        if (command is DesktopCliCommand.ControlSnapshotRead) {
            if (command.controllerId != null && command.controllerId != controllerId) return DesktopCliResponse.failure("CONFLICT")
            val retainedOperations = operations.snapshot()
            val snapshot = inspectStatus?.invoke(controllerId) ?: return DesktopCliResponse.failure("UNSUPPORTED")
            return DesktopCliResponse.success(com.kardinal.vpncontrol.control.ControlSnapshotCodec.encode(
                snapshot.copy(operations = retainedOperations)))
        }
        if (command is DesktopCliCommand.ControlSubmit) return submit(command.request)
        if (command == DesktopCliCommand.OperationsList) return operations.listResponse()
        if (command is DesktopCliCommand.OperationStatus) return operations.statusResponse(command.id)
        if (command is DesktopCliCommand.OperationWait) return operations.waitResponse(command.id)
        if (command is DesktopCliCommand.OperationCancel) return operations.cancelResponse(command.id)
        if (command.isReadOnly) return executeCommand(command)
        val operation = when (command) {
            DesktopCliCommand.On -> com.kardinal.vpncontrol.model.ControlOperationId.ON
            DesktopCliCommand.Off -> com.kardinal.vpncontrol.model.ControlOperationId.OFF
            DesktopCliCommand.Restart -> com.kardinal.vpncontrol.model.ControlOperationId.RESTART
            DesktopCliCommand.FindBest -> com.kardinal.vpncontrol.model.ControlOperationId.FIND_BEST
            is DesktopCliCommand.LocationBenchmark -> com.kardinal.vpncontrol.model.ControlOperationId.LOCATIONS_BENCHMARK
            is DesktopCliCommand.SubscriptionRefresh -> com.kardinal.vpncontrol.model.ControlOperationId.SUBSCRIPTIONS_REFRESH
            DesktopCliCommand.UpdatesCheck -> com.kardinal.vpncontrol.model.ControlOperationId.UPDATES_CHECK
            DesktopCliCommand.UpdatesDownload -> com.kardinal.vpncontrol.model.ControlOperationId.UPDATES_DOWNLOAD
            else -> null
        }
        if (operation != null) return operations.execute(operation, command) { executeMutation(command) }
        return executeMutation(command)
    }

    private suspend fun executeMutation(command: DesktopCliCommand): DesktopCliResponse {
        if (!mutations.tryLock()) return DesktopCliResponse.failure("BUSY")
        return try { executeCommand(command) } finally { mutations.unlock() }
    }

    private suspend fun submit(request: com.kardinal.vpncontrol.model.ControlRequest): DesktopCliResponse {
        val response = submitInternal(request)
        // Only this adapter and the owner ledger produce these responses; never copy
        // arbitrary action/error text into the public envelope.
        val retained = runCatching {
            com.kardinal.vpncontrol.control.ControlProtocolCodec.decodeResult(response.message)
        }.getOrNull()
        if (retained != null) return response
        val code = com.kardinal.vpncontrol.model.ControlCode.entries.firstOrNull {
            it.wireName == response.message && it.exitCode == response.exitCode
        } ?: com.kardinal.vpncontrol.model.ControlCode.RUNTIME_FAILED
        val metadata = metadataProvider()
        val result = com.kardinal.vpncontrol.model.ControlResult(
            controllerId, request.requestId, code, metadata.configurationRevision,
            message = code.wireName, restartRequired = metadata.restartRequired,
        )
        return DesktopCliResponse(result.ok,
            com.kardinal.vpncontrol.control.ControlProtocolCodec.encodeResult(result), result.exitCode)
    }

    private suspend fun submitInternal(request: com.kardinal.vpncontrol.model.ControlRequest): DesktopCliResponse {
        if (request.controllerId != controllerId) return DesktopCliResponse.failure("CONFLICT")
        if (request.command.operation == com.kardinal.vpncontrol.model.ControlOperationId.QUIT && quitOwner != null) {
            if (request.command.arguments.isNotEmpty() || request.interactive || request.asynchronous)
                return DesktopCliResponse.failure("INVALID_ARGUMENT")
            var committed: DesktopControlMetadata? = null
            return operations.execute(request.command.operation, DesktopCliCommand.ControlSubmit(request),
                requestId = request.requestId, expectedControllerId = request.controllerId,
                expectedRevision = request.ifRevision, resultEnvelope = true, completionMetadata = { committed }) {
                if (!mutations.tryLock()) DesktopCliResponse.failure("BUSY")
                else try { quitOwner.invoke(request.requestId, request.ifRevision).let { committed = it.metadata; it.response } }
                finally { mutations.unlock() }
            }
        }
        if (request.command.operation == com.kardinal.vpncontrol.model.ControlOperationId.UPDATES_CANCEL) {
            if (request.command.arguments.isNotEmpty() || request.ifRevision != null || request.interactive || request.asynchronous)
                return DesktopCliResponse.failure("INVALID_ARGUMENT")
            return operations.execute(request.command.operation, DesktopCliCommand.ControlSubmit(request),
                requestId = request.requestId, expectedControllerId = request.controllerId,
                resultEnvelope = true, mutates = false) {
                val pending = operations.snapshot().filter { !it.phase.terminal && it.operation in setOf(
                    com.kardinal.vpncontrol.model.ControlOperationId.UPDATES_CHECK,
                    com.kardinal.vpncontrol.model.ControlOperationId.UPDATES_DOWNLOAD) }
                pending.forEach { operations.cancelResponse(it.id) }
                pending.forEach { operations.waitResponse(it.id) }
                // Dismiss only after native IO/download cleanup has completed, not when cancellation is merely requested.
                executeCommand(DesktopCliCommand.UpdatesDismiss)
            }
        }
        if (request.command.operation == com.kardinal.vpncontrol.model.ControlOperationId.DIAGNOSTICS_EXPORT) {
            if (request.interactive || request.asynchronous || request.ifRevision != null || request.command.arguments.isNotEmpty())
                return DesktopCliResponse.failure("INVALID_ARGUMENT")
            val report = executeCommand(DesktopCliCommand.DiagnosticsExport)
            val metadata = metadataProvider()
            val code = if (report.success) com.kardinal.vpncontrol.model.ControlCode.OK else com.kardinal.vpncontrol.model.ControlCode.RUNTIME_FAILED
            val result = com.kardinal.vpncontrol.model.ControlResult(controllerId, request.requestId, code,
                metadata.configurationRevision, restartRequired = metadata.restartRequired,
                data = if (report.success) mapOf("content" to com.kardinal.vpncontrol.model.ControlValue.Text(report.message)) else emptyMap(),
                warnings = listOf("METADATA_OBSERVED_AFTER_REPORT"))
            return DesktopCliResponse(result.ok, com.kardinal.vpncontrol.control.ControlProtocolCodec.encodeResult(result), result.exitCode)
        }
        if (request.command.operation in DesktopControlInspection.operations) {
            if (request.interactive || request.asynchronous || request.ifRevision != null)
                return DesktopCliResponse.failure("UNSUPPORTED")
            val snapshot = inspectRead?.invoke(request.command) ?: return DesktopCliResponse.failure("UNSUPPORTED")
            val code = snapshot.code
            val result = com.kardinal.vpncontrol.model.ControlResult(controllerId, request.requestId, code,
                snapshot.metadata.configurationRevision, restartRequired = snapshot.metadata.restartRequired,
                data = snapshot.values.getOrDefault(emptyMap()))
            return DesktopCliResponse(result.ok,
                com.kardinal.vpncontrol.control.ControlProtocolCodec.encodeResult(result), result.exitCode)
        }
        if (request.command.operation == com.kardinal.vpncontrol.model.ControlOperationId.STATUS) {
            if (request.interactive || request.asynchronous || request.ifRevision != null)
                return DesktopCliResponse.failure("UNSUPPORTED")
            if (request.command.arguments.isNotEmpty()) return DesktopCliResponse.failure("INVALID_ARGUMENT")
            val snapshot = inspectStatus?.invoke(controllerId) ?: return DesktopCliResponse.failure("UNSUPPORTED")
            val result = com.kardinal.vpncontrol.model.ControlResult(controllerId, request.requestId,
                com.kardinal.vpncontrol.model.ControlCode.OK, snapshot.configurationRevision,
                restartRequired = snapshot.restartRequired, data = snapshot.toControlValues())
            return DesktopCliResponse.success(com.kardinal.vpncontrol.control.ControlProtocolCodec.encodeResult(result))
        }
        if (request.command.operation == com.kardinal.vpncontrol.model.ControlOperationId.CAPABILITIES) {
            if (request.interactive || request.asynchronous || request.ifRevision != null)
                return DesktopCliResponse.failure("UNSUPPORTED")
            if (request.command.arguments.isNotEmpty()) return DesktopCliResponse.failure("INVALID_ARGUMENT")
            val platform = currentDesktopControlPlatform() ?: return DesktopCliResponse.failure("UNSUPPORTED")
            val metadata = metadataProvider()
            val result = com.kardinal.vpncontrol.model.ControlResult(controllerId, request.requestId,
                com.kardinal.vpncontrol.model.ControlCode.OK, metadata.configurationRevision,
                restartRequired = metadata.restartRequired, data = DesktopControlSupport.describe(platform),
                warnings = listOf("RUNTIME_READINESS_NOT_CHECKED"))
            return DesktopCliResponse.success(com.kardinal.vpncontrol.control.ControlProtocolCodec.encodeResult(result))
        }
        if (request.command.operation == com.kardinal.vpncontrol.model.ControlOperationId.SETTINGS_SHOW) {
            if (request.interactive || request.asynchronous || request.ifRevision != null)
                return DesktopCliResponse.failure("UNSUPPORTED")
            val arguments = request.command.arguments
            if (arguments.keys.any { it != "key" } || arguments.values.any {
                    it !is com.kardinal.vpncontrol.model.ControlValue.Text || it.value.isBlank()
                }) return DesktopCliResponse.failure("INVALID_ARGUMENT")
            val snapshot = inspectSettings?.invoke() ?: return DesktopCliResponse.failure("UNSUPPORTED")
            val key = (arguments["key"] as? com.kardinal.vpncontrol.model.ControlValue.Text)?.value
            val code = if (key != null && key !in snapshot.values) com.kardinal.vpncontrol.model.ControlCode.NOT_FOUND
                else com.kardinal.vpncontrol.model.ControlCode.OK
            val result = com.kardinal.vpncontrol.model.ControlResult(controllerId, request.requestId, code,
                snapshot.metadata.configurationRevision, restartRequired = snapshot.metadata.restartRequired,
                data = if (key == null) snapshot.values else snapshot.values.filterKeys { it == key })
            return DesktopCliResponse(result.ok,
                com.kardinal.vpncontrol.control.ControlProtocolCodec.encodeResult(result), result.exitCode)
        }
        if (request.command.operation in setOf(com.kardinal.vpncontrol.model.ControlOperationId.SETTINGS_SET,
                com.kardinal.vpncontrol.model.ControlOperationId.SETTINGS_APPLY)) {
            if (request.interactive || request.asynchronous) return DesktopCliResponse.failure("UNSUPPORTED")
            val apply = applySettings ?: return DesktopCliResponse.failure("UNSUPPORTED")
            val patch = com.kardinal.vpncontrol.control.ControlSettingsLogic.parseRequestArguments(
                request.command.operation, request.command.arguments).getOrNull()
                ?: return DesktopCliResponse.failure("INVALID_ARGUMENT")
            var committedMetadata: DesktopControlMetadata? = null
            return operations.execute(request.command.operation, DesktopCliCommand.SettingsApply(patch),
                requestId = request.requestId, expectedControllerId = request.controllerId,
                expectedRevision = request.ifRevision, resultEnvelope = true, retainSettingsValues = true,
                completionMetadata = { committedMetadata }) {
                if (!mutations.tryLock()) DesktopCliResponse.failure("BUSY")
                else try {
                    apply(patch, request.ifRevision).let { committedMetadata = it.metadata; it.response }
                } finally { mutations.unlock() }
            }
        }
        if (request.command.operation == com.kardinal.vpncontrol.model.ControlOperationId.SSH_KEY_IMPORT && importSshKey != null) {
            if (request.interactive || request.asynchronous) return DesktopCliResponse.failure("UNSUPPORTED")
            val command = DesktopControlMutations.command(request.command) as? DesktopCliCommand.SshKeyImport
                ?: return DesktopCliResponse.failure("INVALID_ARGUMENT")
            var committedMetadata: DesktopControlMetadata? = null
            return operations.execute(request.command.operation, command,
                requestId = request.requestId, expectedControllerId = request.controllerId,
                expectedRevision = request.ifRevision, resultEnvelope = true,
                completionMetadata = { committedMetadata }) {
                if (!mutations.tryLock()) DesktopCliResponse.failure("BUSY")
                else try {
                    importSshKey.invoke(command.content, request.ifRevision).let { committedMetadata = it.metadata; it.response }
                } finally { mutations.unlock() }
            }
        }
        if (request.command.operation in setOf(com.kardinal.vpncontrol.model.ControlOperationId.SUBSCRIPTIONS_ADD,
                com.kardinal.vpncontrol.model.ControlOperationId.SUBSCRIPTIONS_UPDATE) && saveSubscription != null) {
            if (request.interactive || (request.asynchronous && request.command.operation !in DesktopControlSupport.asynchronousOperations))
                return DesktopCliResponse.failure("UNSUPPORTED")
            val command = DesktopControlMutations.command(request.command) as? DesktopCliCommand.SubscriptionSave
                ?: return DesktopCliResponse.failure("INVALID_ARGUMENT")
            var committedMetadata: DesktopControlMetadata? = null
            return operations.execute(request.command.operation, command, requestId = request.requestId,
                asynchronous = request.asynchronous,
                expectedControllerId = request.controllerId, expectedRevision = request.ifRevision, resultEnvelope = true,
                retainSubscriptionIdentity = true, completionMetadata = { committedMetadata }) {
                if (!mutations.tryLock()) DesktopCliResponse.failure("BUSY")
                else try {
                    saveSubscription.invoke(command.source, command.name, command.id, request.ifRevision).let {
                        committedMetadata = it.metadata; it.response
                    }
                } finally { mutations.unlock() }
            }
        }
        if (request.command.operation in setOf(com.kardinal.vpncontrol.model.ControlOperationId.LOCATIONS_ADD,
                com.kardinal.vpncontrol.model.ControlOperationId.LOCATIONS_UPDATE) && saveLocation != null) {
            if (request.interactive || (request.asynchronous && request.command.operation !in DesktopControlSupport.asynchronousOperations))
                return DesktopCliResponse.failure("UNSUPPORTED")
            val command = if ("id" in request.command.arguments) {
                val args = request.command.arguments
                if (request.command.operation != com.kardinal.vpncontrol.model.ControlOperationId.LOCATIONS_UPDATE ||
                    args.keys != setOf("id", "input") || args.values.any { it !is com.kardinal.vpncontrol.model.ControlValue.Text })
                    return DesktopCliResponse.failure("INVALID_ARGUMENT")
                val id = (args.getValue("id") as com.kardinal.vpncontrol.model.ControlValue.Text).value
                if (id.isBlank()) return DesktopCliResponse.failure("INVALID_ARGUMENT")
                DesktopCliCommand.LocationSave((args.getValue("input") as com.kardinal.vpncontrol.model.ControlValue.Text).value,
                    configurationId = id)
            } else DesktopControlMutations.command(request.command) as? DesktopCliCommand.LocationSave
                ?: return DesktopCliResponse.failure("INVALID_ARGUMENT")
            var committedMetadata: DesktopControlMetadata? = null
            return operations.execute(request.command.operation, command, requestId = request.requestId,
                asynchronous = request.asynchronous, expectedControllerId = request.controllerId,
                expectedRevision = request.ifRevision, resultEnvelope = true, retainLocationIdentity = true,
                completionMetadata = { committedMetadata }) {
                if (!mutations.tryLock()) DesktopCliResponse.failure("BUSY")
                else try { saveLocation.invoke(command, request.ifRevision).let { committedMetadata = it.metadata; it.response } }
                finally { mutations.unlock() }
            }
        }
        if (request.command.operation in setOf(com.kardinal.vpncontrol.model.ControlOperationId.LOCATIONS_SELECT,
                com.kardinal.vpncontrol.model.ControlOperationId.LOCATIONS_DELETE) && mutateLocation != null) {
            if (request.interactive || (request.asynchronous && request.command.operation !in DesktopControlSupport.asynchronousOperations))
                return DesktopCliResponse.failure("UNSUPPORTED")
            var committedMetadata: DesktopControlMetadata? = null
            return operations.execute(request.command.operation, DesktopCliCommand.ControlSubmit(request), requestId = request.requestId,
                asynchronous = request.asynchronous, expectedControllerId = request.controllerId, expectedRevision = request.ifRevision,
                resultEnvelope = true, retainLocationIdentity = true, completionMetadata = { committedMetadata }) {
                if (!mutations.tryLock()) DesktopCliResponse.failure("BUSY")
                else try { mutateLocation.invoke(request.command, request.ifRevision).let { committedMetadata = it.metadata; it.response } }
                finally { mutations.unlock() }
            }
        }
        if (request.command.operation in setOf(com.kardinal.vpncontrol.model.ControlOperationId.SOURCE_SET,
                com.kardinal.vpncontrol.model.ControlOperationId.SUBSCRIPTIONS_DELETE) && mutateSource != null) {
            if (request.interactive || (request.asynchronous && request.command.operation !in DesktopControlSupport.asynchronousOperations))
                return DesktopCliResponse.failure("UNSUPPORTED")
            var committedMetadata: DesktopControlMetadata? = null
            return operations.execute(request.command.operation, DesktopCliCommand.ControlSubmit(request), requestId = request.requestId,
                asynchronous = request.asynchronous, expectedControllerId = request.controllerId, expectedRevision = request.ifRevision,
                resultEnvelope = true, retainSubscriptionIdentity = true, completionMetadata = { committedMetadata }) {
                if (!mutations.tryLock()) DesktopCliResponse.failure("BUSY")
                else try { mutateSource.invoke(request.command, request.ifRevision).let { committedMetadata = it.metadata; it.response } }
                finally { mutations.unlock() }
            }
        }
        if (request.command.operation in setOf(com.kardinal.vpncontrol.model.ControlOperationId.ROUTING_SET,
                com.kardinal.vpncontrol.model.ControlOperationId.ROUTING_IMPORT,
                com.kardinal.vpncontrol.model.ControlOperationId.LOCATIONS_IMPORT) && mutateConfiguration != null) {
            if (request.interactive || (request.asynchronous && request.command.operation !in DesktopControlSupport.asynchronousOperations))
                return DesktopCliResponse.failure("UNSUPPORTED")
            val command = DesktopControlMutations.command(request.command) ?: return DesktopCliResponse.failure("INVALID_ARGUMENT")
            var committedMetadata: DesktopControlMetadata? = null
            return operations.execute(request.command.operation, command, requestId = request.requestId,
                asynchronous = request.asynchronous, expectedControllerId = request.controllerId, expectedRevision = request.ifRevision,
                resultEnvelope = true, retainConfigurationValues = true, completionMetadata = { committedMetadata }) {
                if (!mutations.tryLock()) DesktopCliResponse.failure("BUSY")
                else try { mutateConfiguration.invoke(command, request.ifRevision).let { committedMetadata = it.metadata; it.response } }
                finally { mutations.unlock() }
            }
        }
        if (request.command.operation == com.kardinal.vpncontrol.model.ControlOperationId.LOCATIONS_BENCHMARK &&
            "id" in request.command.arguments) {
            if (request.ifRevision != null || request.interactive) return DesktopCliResponse.failure("UNSUPPORTED")
            val id = (request.command.arguments["id"] as? com.kardinal.vpncontrol.model.ControlValue.Text)?.value
            if (request.command.arguments.keys != setOf("id") || id.isNullOrBlank()) return DesktopCliResponse.failure("INVALID_ARGUMENT")
            val command = DesktopCliCommand.LocationBenchmark("", configurationId = id)
            return operations.execute(request.command.operation, command, request.requestId, request.asynchronous,
                request.controllerId, resultEnvelope = true) { executeMutation(command) }
        }
        if (request.ifRevision != null || request.interactive) return DesktopCliResponse.failure("UNSUPPORTED")
        if (request.command.operation in DesktopControlMutations.operations) {
            if (request.asynchronous && request.command.operation !in DesktopControlSupport.asynchronousOperations)
                return DesktopCliResponse.failure("UNSUPPORTED")
            val command = DesktopControlMutations.command(request.command) ?: return DesktopCliResponse.failure("INVALID_ARGUMENT")
            return operations.execute(request.command.operation, command, request.requestId, request.asynchronous,
                request.controllerId, resultEnvelope = true) { executeMutation(command) }
        }
        val arguments = request.command.arguments
        val names = com.kardinal.vpncontrol.control.ControlCliParser.schema(request.command.operation).positional
        if (arguments.keys != names.toSet() || arguments.values.any {
                it !is com.kardinal.vpncontrol.model.ControlValue.Text || it.value.isBlank()
            }) return DesktopCliResponse.failure("INVALID_ARGUMENT")
        fun text(name: String) = (arguments.getValue(name) as com.kardinal.vpncontrol.model.ControlValue.Text).value
        if (request.command.operation in setOf(com.kardinal.vpncontrol.model.ControlOperationId.OPERATIONS_LIST,
                com.kardinal.vpncontrol.model.ControlOperationId.OPERATIONS_STATUS,
                com.kardinal.vpncontrol.model.ControlOperationId.OPERATIONS_WAIT,
                com.kardinal.vpncontrol.model.ControlOperationId.OPERATIONS_CANCEL)) {
            if (request.asynchronous) return DesktopCliResponse.failure("UNSUPPORTED")
            val response = when (request.command.operation) {
                com.kardinal.vpncontrol.model.ControlOperationId.OPERATIONS_LIST -> operations.listResponse()
                com.kardinal.vpncontrol.model.ControlOperationId.OPERATIONS_STATUS -> operations.statusResponse(text("id"))
                com.kardinal.vpncontrol.model.ControlOperationId.OPERATIONS_WAIT -> operations.waitResponse(text("id"))
                else -> operations.cancelResponse(text("id"))
            }
            val data = runCatching { com.kardinal.vpncontrol.control.ControlProtocolCodec.decodeValues(
                if (request.command.operation == com.kardinal.vpncontrol.model.ControlOperationId.OPERATIONS_LIST)
                    "{\"operations\":${response.message}}" else response.message)
            }.getOrNull() ?: return response
            val code = if (response.success) com.kardinal.vpncontrol.model.ControlCode.OK
                else com.kardinal.vpncontrol.model.ControlCode.entries.firstOrNull {
                    it.wireName == (data["code"] as? com.kardinal.vpncontrol.model.ControlValue.Text)?.value &&
                        it.exitCode == response.exitCode
                } ?: com.kardinal.vpncontrol.model.ControlCode.RUNTIME_FAILED
            val metadata = metadataProvider()
            val result = com.kardinal.vpncontrol.model.ControlResult(controllerId, request.requestId, code,
                metadata.configurationRevision, restartRequired = metadata.restartRequired, data = data)
            return DesktopCliResponse(result.ok,
                com.kardinal.vpncontrol.control.ControlProtocolCodec.encodeResult(result), result.exitCode)
        }
        val command = when (request.command.operation) {
            com.kardinal.vpncontrol.model.ControlOperationId.ON -> DesktopCliCommand.On
            com.kardinal.vpncontrol.model.ControlOperationId.OFF -> DesktopCliCommand.Off
            com.kardinal.vpncontrol.model.ControlOperationId.RESTART -> DesktopCliCommand.Restart
            com.kardinal.vpncontrol.model.ControlOperationId.FIND_BEST -> DesktopCliCommand.FindBest
            com.kardinal.vpncontrol.model.ControlOperationId.LOCATIONS_BENCHMARK -> DesktopCliCommand.LocationBenchmark(text("selector"))
            com.kardinal.vpncontrol.model.ControlOperationId.SUBSCRIPTIONS_REFRESH -> DesktopCliCommand.SubscriptionRefresh(text("id"))
            com.kardinal.vpncontrol.model.ControlOperationId.UPDATES_CHECK -> DesktopCliCommand.UpdatesCheck
            com.kardinal.vpncontrol.model.ControlOperationId.UPDATES_DOWNLOAD -> DesktopCliCommand.UpdatesDownload
            else -> return DesktopCliResponse.failure("UNSUPPORTED")
        }
        return operations.execute(request.command.operation, command, request.requestId, request.asynchronous,
            request.controllerId, resultEnvelope = true) {
            executeMutation(command)
        }
    }

    override fun close() {
        observer?.cancel()
        scheduler.cancel()
    }
}
