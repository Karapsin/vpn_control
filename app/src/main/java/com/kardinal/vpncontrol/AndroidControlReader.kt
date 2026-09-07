package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.control.ControlOperationRegistry
import com.kardinal.vpncontrol.control.ControlProtocolCodec
import com.kardinal.vpncontrol.control.ControlDocumentCodec
import com.kardinal.vpncontrol.control.ControlCharacterSource
import com.kardinal.vpncontrol.control.ControlReadLogic
import com.kardinal.vpncontrol.control.ControlSettingsLogic
import com.kardinal.vpncontrol.control.ControlConfigurationInspection
import com.kardinal.vpncontrol.control.ControlProtocolException
import com.kardinal.vpncontrol.model.*
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.withTimeout

/** Bounded transport adapter for committed reads and application-owned typed operations. */
internal class AndroidControlReader(
    val controllerId: String,
    private val snapshot: suspend () -> PersistedState,
    private val clockMillis: () -> Long = System::currentTimeMillis,
    private val readTimeoutMillis: Long = 10_000,
    private val runtimeObservation: () -> AndroidRuntimeObservation = { AndroidRuntimeObservation() },
    private val committedSnapshot: (suspend () -> com.kardinal.vpncontrol.control.ControlCommitted<PersistedState>)? = null,
    private val pendingRestart: (PersistedState) -> Boolean? = { null },
    private val settingsWrite: (suspend (ControlRequest) -> ControlResult)? = null,
    private val operationIdForRequest: (String) -> String? = { null },
    private val statusSnapshot: ((PersistedState) -> AndroidControlStatus)? = null,
    private val systemLanguageCode: () -> String = { java.util.Locale.getDefault().language },
    private val credentialPresent: ((PersistedState) -> Boolean)? = null,
    private val updateSnapshot: (() -> AppUpdateState)? = null,
    private val updateInspection: (() -> Map<String, ControlValue>)? = null,
    private val diagnosticsExport: (suspend (PersistedState) -> String)? = null,
    private val installedApps: (suspend () -> List<InstalledApp>)? = null,
    private val routingAdmission: (suspend (ControlRequest) -> kotlinx.coroutines.Deferred<ControlResult>)? = null,
    private val inputSpool: (() -> AndroidControlInputSpool)? = null,
    private val routingDocumentAdmission: (suspend (ControlRequest, AndroidControlInputSpool) -> kotlinx.coroutines.Deferred<ControlResult>)? = null,
) {
    private val logLock = Any()
    private val logJournal = com.kardinal.vpncontrol.control.ControlLogCursorJournal(emptyList(), "log-$controllerId-")
    private var logPublicationObserved = false

    /** Called synchronously after each durable status publication by the application owner. */
    fun observeLogs(entries: List<ConnectionLogEntry>) = synchronized(logLock) {
        logPublicationObserved = true
        // Cursor bookkeeping must not turn a durable status write into a reported
        // persistence failure. Preserve explicit loss if allocation prevents observation.
        try { logJournal.sync(entries) }
        catch (_: OutOfMemoryError) { logJournal.markHistoryGap() }
        Unit
    }

    suspend fun execute(bytes: ByteArray, transferId: String): ByteArray = execute(bytes, transferId, document = false)

    /** Logical JSON over authenticated private streams; the stream adapter owns chunk bounds. */
    suspend fun executeDocument(bytes: ByteArray, transferId: String): ByteArray =
        executeDocument(java.io.ByteArrayInputStream(bytes), transferId)

    suspend fun executeDocument(input: java.io.InputStream, transferId: String): ByteArray = try {
        // Parse/read returns before encoding, releasing the request's large input
        // reference rather than retaining it alongside a similarly large result.
        ControlDocumentCodec.encodeResult(readDocument(input, transferId)).toByteArray(Charsets.UTF_8)
    } catch (_: OutOfMemoryError) { throw AndroidControlDocumentResourceFailure() }

    /** Production logical-document path publishes this result directly to its private spool. */
    suspend fun documentResult(input: java.io.InputStream, transferId: String): ControlResult =
        try { readDocument(input, transferId) }
        catch (_: OutOfMemoryError) { throw AndroidControlDocumentResourceFailure() }

    suspend fun documentResponse(input: java.io.InputStream, transferId: String): AndroidControlDocumentResponse = try {
        var content: ((Appendable) -> Unit)? = null
        val result = readDocument(input, transferId) { content = it }
        AndroidControlDocumentResponse(result, if (result.code == ControlCode.OK) content else null)
    } catch (_: OutOfMemoryError) { throw AndroidControlDocumentResourceFailure() }

    private suspend fun readDocument(input: java.io.InputStream, transferId: String,
        exportContent: ((((Appendable) -> Unit)) -> Unit)? = null): ControlResult {
        if (inputSpool != null) return readExternalDocument(input, transferId, exportContent)
        val request = try {
            java.io.InputStreamReader(input, Charsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)).buffered(8192).use { reader ->
                ControlDocumentCodec.decodeRequest(ControlCharacterSource(reader::read))
            }
        } catch (_: OutOfMemoryError) { throw AndroidControlDocumentResourceFailure() }
        catch (error: ControlProtocolException) {
            if (error.code == ControlCode.INVALID_ARGUMENT) return result(transferId, ControlCode.INVALID_ARGUMENT)
            throw AndroidControlDocumentResourceFailure()
        } catch (_: java.nio.charset.CharacterCodingException) { return result(transferId, ControlCode.INVALID_ARGUMENT) }
        catch (_: java.io.IOException) { throw AndroidControlDocumentResourceFailure() }
        return readDecodedDocument(request, exportContent)
    }

    private suspend fun readExternalDocument(input: java.io.InputStream, transferId: String,
        exportContent: ((((Appendable) -> Unit)) -> Unit)?): ControlResult {
        val external = requireNotNull(inputSpool).invoke()
        var adopted = false
        try {
            val decoded = try {
                java.io.InputStreamReader(input, Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)).buffered(8192).use { reader ->
                    ControlDocumentCodec.decodeRequestWithExternalInput(ControlCharacterSource(reader::read), external)
                }
            } catch (error: ControlProtocolException) {
                if (error.code == ControlCode.INVALID_ARGUMENT) return result(transferId, ControlCode.INVALID_ARGUMENT)
                throw AndroidControlDocumentResourceFailure()
            } catch (_: java.nio.charset.CharacterCodingException) { return result(transferId, ControlCode.INVALID_ARGUMENT) }
            catch (_: java.io.IOException) { throw AndroidControlDocumentResourceFailure() }
            external.seal()
            val request = decoded.request
            if (decoded.inputExtracted && request.command.operation == ControlOperationId.ROUTING_IMPORT && routingDocumentAdmission != null) {
                val completion = routingDocumentAdmission.invoke(request, external)
                adopted = true
                return awaitRouting(completion, request.requestId)
            }
            val ordinary = if (decoded.inputExtracted) request.copy(command = request.command.copy(
                arguments = request.command.arguments + ("input" to ControlValue.Text(external.materialize())))) else request
            external.close()
            return readDecodedDocument(ordinary, exportContent)
        } finally { if (!adopted) external.close() }
    }

    private suspend fun readDecodedDocument(request: ControlRequest,
        exportContent: ((((Appendable) -> Unit)) -> Unit)? = null): ControlResult {
        if (request.command.operation == ControlOperationId.ROUTING_IMPORT && routingAdmission != null) {
            val requestId = request.requestId
            return awaitRouting(routingAdmission.invoke(request), requestId)
        }
        return try { withTimeout(readTimeoutMillis) { read(request, exportContent) } }
        catch (_: TimeoutCancellationException) {
            result(request.requestId, ControlCode.TIMEOUT).copy(operationId =
                if (request.command.operation in AndroidSettingsControl.inspectionOperations)
                    (request.command.arguments["id"] as? ControlValue.Text)?.value else operationIdForRequest(request.requestId))
        } catch (_: Exception) { result(request.requestId, ControlCode.UNAVAILABLE) }
    }

    private suspend fun awaitRouting(completion: kotlinx.coroutines.Deferred<ControlResult>, requestId: String): ControlResult =
        try { withTimeout(readTimeoutMillis) { completion.await() } }
        catch (_: TimeoutCancellationException) {
            result(requestId, ControlCode.TIMEOUT).copy(operationId = operationIdForRequest(requestId))
        } catch (_: Exception) { result(requestId, ControlCode.UNAVAILABLE) }

    private suspend fun execute(bytes: ByteArray, transferId: String, document: Boolean): ByteArray {
        fun encodeResponse(result: ControlResult): ByteArray = if (document)
            ControlDocumentCodec.encodeResult(result).toByteArray(Charsets.UTF_8) else encode(result)
        val request = runCatching {
            val text = Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString()
            if (document) ControlDocumentCodec.decodeRequest(text) else ControlProtocolCodec.decodeRequest(text)
        }.getOrElse { return encode(result(transferId, ControlCode.INVALID_ARGUMENT)) }
        // Once decoding succeeds, even timeout/IO/oversize failures retain the request identity.
        return try {
            val response = encodeResponse(withTimeout(readTimeoutMillis) { read(request) })
            if (document || response.size <= 1_048_576) response else failure(request.requestId)
        } catch (_: TimeoutCancellationException) {
            encode(result(request.requestId, ControlCode.TIMEOUT).copy(operationId =
                if (request.command.operation in AndroidSettingsControl.inspectionOperations)
                    (request.command.arguments["id"] as? ControlValue.Text)?.value else operationIdForRequest(request.requestId)))
        } catch (_: Exception) {
            failure(request.requestId)
        }
    }

    suspend fun read(request: ControlRequest): ControlResult = read(request, null)

    private suspend fun read(request: ControlRequest, exportContent: ((((Appendable) -> Unit)) -> Unit)?): ControlResult {
        if (request.controllerId != null && request.controllerId != controllerId) {
            return result(request.requestId, ControlCode.CONFLICT)
        }
        if (request.command.operation in AndroidSettingsControl.operations && settingsWrite != null) return settingsWrite.invoke(request)
        if (request.command.operation !in supported) return result(request.requestId, ControlCode.UNSUPPORTED)
        if (request.ifRevision != null || request.interactive || request.asynchronous) {
            return result(request.requestId, ControlCode.INVALID_ARGUMENT)
        }
        val command = request.command
        val committed = committedSnapshot?.invoke()
        var pending = committed?.value?.let(pendingRestart)
        var observedStatus: AndroidControlStatus? = null
        fun response(code: ControlCode, data: Map<String, ControlValue> = emptyMap()) =
            result(request.requestId, code, data, committed?.revision, pending, observedStatus?.authoritative == true)
        if (command.operation == ControlOperationId.CAPABILITIES) {
            if (command.arguments.isNotEmpty()) return response(ControlCode.INVALID_ARGUMENT)
            return response(ControlCode.OK, mapOf(
                "scope" to ControlValue.Text(if (settingsWrite == null) "android-read-only-provider" else "android-provider"),
                "publicRevisionGuards" to ControlValue.BooleanValue(settingsWrite != null),
                "runtimeReadinessChecked" to ControlValue.BooleanValue(false),
                "streamingOperations" to ControlValue.ArrayValue(listOf(ControlOperationId.STATUS,
                    ControlOperationId.STATS, ControlOperationId.LOGS).map { ControlValue.Text(it.wireName) }),
                "operations" to ControlValue.ArrayValue(ControlOperationRegistry.operations.map {
                    ControlValue.ObjectValue(mapOf(
                        "id" to ControlValue.Text(it.id.wireName),
                        "supported" to ControlValue.BooleanValue(it.id in supported || settingsWrite != null && it.id in AndroidSettingsControl.operations),
                        "flags" to ControlValue.ArrayValue(com.kardinal.vpncontrol.control.ControlCliParser.schema(it.id)
                            .flags.map(ControlValue::Text)),
                        "reasonCode" to if (it.id in supported || settingsWrite != null && it.id in AndroidSettingsControl.operations)
                            ControlValue.Null else ControlValue.Text("NOT_IMPLEMENTED"),
                    ))
                }),
            ))
        }
        val persisted = committed?.value ?: snapshot()
        observedStatus = statusSnapshot?.invoke(persisted)
        pending = if (observedStatus != null) observedStatus.pending else pendingRestart(persisted)
        if (command.operation == ControlOperationId.LOGS) {
            val logs = synchronized(logLock) {
                // A reader without an attached publisher can still inspect snapshots. Once
                // publication is attached, an older in-flight read must not replace its history.
                if (!logPublicationObserved) logJournal.sync(persisted.connectionLog)
                logJournal.read(command.arguments)
            }
            return logs.fold({ response(ControlCode.OK, it) }, { response(ControlCode.INVALID_ARGUMENT) })
        }
        if (command.operation == ControlOperationId.ROUTING_APPS_LIST) {
            if (com.kardinal.vpncontrol.control.ControlCommandArguments.decode(command) == null)
                return response(ControlCode.INVALID_ARGUMENT)
            val apps = installedApps?.invoke() ?: return response(ControlCode.UNAVAILABLE)
            return response(ControlCode.OK, com.kardinal.vpncontrol.data.AndroidRoutingControl.list(persisted, command.arguments, apps))
        }
        if (command.operation == ControlOperationId.DIAGNOSTICS_EXPORT) {
            if (command.arguments.isNotEmpty()) return response(ControlCode.INVALID_ARGUMENT)
            val exporter = diagnosticsExport ?: return response(ControlCode.UNAVAILABLE)
            return response(ControlCode.OK, mapOf("content" to ControlValue.Text(exporter(persisted))))
        }
        if (command.operation == ControlOperationId.UPDATES_STATUS) {
            if (command.arguments.isNotEmpty()) return response(ControlCode.INVALID_ARGUMENT)
            updateInspection?.let { return response(ControlCode.OK, it()) }
            val update = updateSnapshot?.invoke() ?: return response(ControlCode.UNAVAILABLE)
            return response(ControlCode.OK, AndroidControlUpdateInspection.read(update))
        }
        if (command.operation == ControlOperationId.SSH_KEY_STATUS) {
            if (command.arguments.isNotEmpty()) return response(ControlCode.INVALID_ARGUMENT)
            val present = credentialPresent?.invoke(persisted) ?: return response(ControlCode.UNAVAILABLE)
            return response(ControlCode.OK, mapOf("present" to ControlValue.BooleanValue(present)))
        }
        if (command.operation in AndroidControlLocationInspection.operations) {
            val inspected = AndroidControlLocationInspection.read(
                MainUiStateProjector.committedState(persisted), command,
                com.kardinal.vpncontrol.shared.ui.AppStrings(persisted.appLanguage.effective(systemLanguageCode())))
            return inspected.fold({ response(ControlCode.OK, it) }, {
                response((it as? ControlProtocolException)?.code ?: ControlCode.INVALID_ARGUMENT)
            })
        }
        if (command.operation in ControlConfigurationInspection.operations) {
            if (command.operation == ControlOperationId.ROUTING_EXPORT && exportContent != null) {
                if (command.arguments.isNotEmpty()) return response(ControlCode.INVALID_ARGUMENT)
                val rules = persisted.routingRules
                val timestamp = java.time.Instant.ofEpochMilli(clockMillis()).toString()
                exportContent { output -> com.kardinal.vpncontrol.data.RoutingRulesTransfer.writeExport(rules, timestamp, output) }
                return response(ControlCode.OK)
            }
            val inspected = ControlConfigurationInspection.read(
                MainUiStateProjector.committedState(persisted), command, clockMillis(), domainValues = { domains ->
                    // Only the platform's immutable range-backed preference can be shared.
                    // Ordinary lists retain the shared inspection's defensive snapshot behavior.
                    (domains as? com.kardinal.vpncontrol.data.AndroidPersistedDomainSuffixes)?.controlValues()
                        ?: domains.map(ControlValue::Text)
                })
            return inspected.fold({ response(ControlCode.OK, it) }, {
                response((it as? ControlProtocolException)?.code ?: ControlCode.INVALID_ARGUMENT)
            })
        }
        if (command.operation == ControlOperationId.STATUS) {
            if (command.arguments.isNotEmpty()) return response(ControlCode.INVALID_ARGUMENT)
            val status = observedStatus ?: return response(ControlCode.UNAVAILABLE,
                mapOf("runtimeRunning" to ControlValue.Null, "restartRequired" to ControlValue.Null,
                    "runtimeObservation" to ControlValue.Text("unknown")))
            pending = status.pending
            return response(if (status.authoritative) ControlCode.OK else ControlCode.UNAVAILABLE, status.data)
        }
        val data = when (command.operation) {
            ControlOperationId.SETTINGS_SHOW -> {
                if (command.arguments.keys.any { it != "key" }) return response(ControlCode.INVALID_ARGUMENT)
                val settings = ControlSettingsLogic.inspect(persisted)
                if (command.arguments.isEmpty()) settings else {
                    val key = (command.arguments["key"] as? ControlValue.Text)?.value
                        ?: return response(ControlCode.INVALID_ARGUMENT)
                    val value = settings[key] ?: return response(ControlCode.NOT_FOUND)
                    mapOf(key to value)
                }
            }
            else -> ControlReadLogic.read(
                MainUiStateProjector.committedState(persisted), command, clockMillis(),
            ).getOrElse { return response(ControlCode.INVALID_ARGUMENT) }
        }
        val observedData = if (command.operation == ControlOperationId.STATS) {
            runtimeObservation().stats(data, clockMillis())
        } else data
        return response(ControlCode.OK, observedData)
    }

    private fun failure(requestId: String): ByteArray = encode(result(requestId, ControlCode.UNAVAILABLE))

    private fun result(id: String, code: ControlCode, data: Map<String, ControlValue> = emptyMap(), revision: Long? = null,
        pending: Boolean? = null, runtimeIdentityKnown: Boolean = false) = ControlResult(
        controllerId = controllerId, requestId = id, code = code, configurationRevision = revision ?: 0,
        data = data, final = code != ControlCode.TIMEOUT, restartRequired = pending ?: false,
        warnings = (if (revision == null) listOf("CONFIGURATION_REVISION_UNAVAILABLE") else emptyList()) +
            (if (when (data["runtimeObservation"]) {
                ControlValue.Text("running"), ControlValue.Text("stopped") -> true
                null -> runtimeIdentityKnown
                else -> false
            })
                emptyList() else listOf("ACTIVE_RUNTIME_IDENTITY_UNAVAILABLE")) +
            (if (pending == null) listOf("PENDING_RESTART_STATE_UNAVAILABLE") else emptyList()),
    )

    private fun encode(result: ControlResult): ByteArray = ControlProtocolCodec.encodeResult(result).toByteArray(Charsets.UTF_8)

    companion object {
        val supported = ControlReadLogic.operations + ControlConfigurationInspection.operations + AndroidControlLocationInspection.operations +
            setOf(ControlOperationId.CAPABILITIES, ControlOperationId.SETTINGS_SHOW, ControlOperationId.STATUS,
                ControlOperationId.SSH_KEY_STATUS, ControlOperationId.UPDATES_STATUS, ControlOperationId.DIAGNOSTICS_EXPORT,
                ControlOperationId.ROUTING_APPS_LIST)
    }
}

/** Resource exhaustion is a transport failure, never evidence of malformed user input. */
internal class AndroidControlDocumentResourceFailure : IllegalStateException("UNAVAILABLE")
