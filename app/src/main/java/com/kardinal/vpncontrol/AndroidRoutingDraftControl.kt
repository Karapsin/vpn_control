package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.control.ControlCommitted
import com.kardinal.vpncontrol.data.RoutingRulesTransfer
import com.kardinal.vpncontrol.model.*
import java.io.Reader
import java.util.UUID
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.withContext

/** Frontend guards and retry identity; parsing, admission and persistence belong to the owner. */
internal class AndroidRoutingDraftControl(
    private val inputSpool: () -> AndroidControlInputSpool,
    private val admit: suspend (ControlRequest, AndroidControlInputSpool) -> Deferred<ControlResult>,
    private val operationId: (String) -> String? = { null },
    private val io: CoroutineDispatcher = Dispatchers.IO,
) {
    data class Outcome(val result: ControlResult, val applyToDraft: Boolean = false)
    private class Opening(val owner: String, var revision: Long) { var attempt: Attempt? = null }
    private class Attempt(val fingerprint: String, val request: ControlRequest) { var result: ControlResult? = null }
    private var observed: Pair<String, Long>? = null
    private var editor: Opening? = null
    private var picker: Opening? = null
    private val mutation = Mutex()

    /** Called with the same committed object that is published into the rendered UI state. */
    fun observe(committed: ControlCommitted<PersistedState>) { observed = committed.controllerId to committed.revision }
    fun openEditor(): Boolean {
        editor = observed?.let { Opening(it.first, it.second) }
        return editor != null
    }
    fun beginImport(): Boolean {
        // Reopening a failed picker is an explicit retry. It cannot silently rebase
        // a stale input or repeat an accepted mutation under a new request identity.
        if (picker == null) picker = observed?.let { Opening(it.first, it.second) }
        return picker != null
    }
    fun cancelImport() { picker = null }
    fun closeEditor() { editor = null }

    suspend fun save(rules: RoutingRules): Outcome = perform(editor, imported = false) { output ->
        // A stable timestamp makes identical explicit retries byte-identical.
        RoutingRulesTransfer.writeExport(rules, "1970-01-01T00:00:00Z", output)
    }

    suspend fun importDocument(openReader: () -> Reader): Outcome = perform(picker, imported = true) { output ->
        openReader().use { reader ->
            val characters = CharArray(32768)
            try {
                while (true) {
                    val count = reader.read(characters)
                    if (count < 0) break
                    for (index in 0 until count) output.append(characters[index])
                    characters.fill('\u0000', 0, count)
                }
            } finally { characters.fill('\u0000') }
        }
    }

    private suspend fun perform(opened: Opening?, imported: Boolean, write: (Appendable) -> Unit): Outcome {
        if (opened == null) return Outcome(rejected(null, ControlCode.CONFLICT, "CONFIGURATION_REVISION_UNAVAILABLE"))
        if (!mutation.tryLock()) return Outcome(rejected(opened, ControlCode.BUSY))
        var input: AndroidControlInputSpool? = null
        var delegated = false
        var attempted: Attempt? = null
        try {
            val fingerprint = withContext(io) {
                val spool = inputSpool().also { input = it }
                write(spool)
                spool.seal()
                androidControlInputFingerprint(spool.source(), opened.revision)
            }
            fun current() = if (imported) picker === opened else editor === opened
            if (!current()) return Outcome(rejected(opened, ControlCode.CANCELLED))
            val previous = opened.attempt
            val uncertain = previous != null && (previous.result == null || previous.result?.let(::uncertain) == true)
            if (uncertain && previous!!.fingerprint != fingerprint)
                return Outcome(rejected(opened, ControlCode.CONFLICT, "PREVIOUS_REQUEST_OUTCOME_UNKNOWN"))
            attempted = if (uncertain) previous else Attempt(fingerprint, ControlRequest(UUID.randomUUID().toString(),
                ControlCommand(ControlOperationId.ROUTING_IMPORT), controllerId = opened.owner, ifRevision = opened.revision))
            val attempt = requireNotNull(attempted).also { opened.attempt = it }
            // admit adopts the private input on every return path; cancelling this
            // frontend's wait never cancels the accepted owner operation.
            val completion = withContext(io) {
                delegated = true
                admit(attempt.request, requireNotNull(input))
            }
            val result = completion.await()
            val correlated = result.controllerId == opened.owner && result.requestId == attempt.request.requestId
            if (!correlated) {
                val unknown = unknown(opened, attempt)
                attempt.result = unknown
                return Outcome(unknown)
            }
            attempt.result = result
            val applied = current() && result.final && result.code == ControlCode.OK
            if (applied) {
                opened.revision = result.configurationRevision
                opened.attempt = null
                if (imported) {
                    picker = null
                    // A successful import replaces the visible editor through the
                    // same revision; subsequent edits remain guarded against it.
                    editor = Opening(opened.owner, result.configurationRevision)
                }
            }
            return Outcome(result, applied)
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: OutOfMemoryError) {
            val result = if (delegated && attempted != null) unknown(opened, attempted)
                else rejected(opened, ControlCode.RUNTIME_FAILED, "RESOURCE_EXHAUSTED")
            attempted?.result = result
            return Outcome(result)
        } catch (_: java.nio.charset.CharacterCodingException) {
            return Outcome(rejected(opened, ControlCode.INVALID_ARGUMENT))
        } catch (_: Exception) {
            val result = if (delegated && attempted != null) unknown(opened, attempted)
                else rejected(opened, ControlCode.UNAVAILABLE, "PRIVATE_INPUT_UNAVAILABLE")
            attempted?.result = result
            return Outcome(result)
        } finally {
            try { if (!delegated) input?.close() }
            catch (_: Exception) { /* No admitted or committed outcome is changed by input cleanup. */ }
            finally { mutation.unlock() }
        }
    }

    private fun uncertain(result: ControlResult) = !result.final || result.code in setOf(
        ControlCode.TIMEOUT, ControlCode.OUTCOME_UNKNOWN, ControlCode.UNAVAILABLE) ||
        (result.code != ControlCode.OK && "CONFIGURATION_OUTCOME_UNKNOWN" in result.warnings)
    private fun unknown(opened: Opening, attempt: Attempt) = ControlResult(opened.owner, attempt.request.requestId,
        ControlCode.OUTCOME_UNKNOWN, opened.revision, final = false, operationId = operationId(attempt.request.requestId),
        warnings = listOf("CONFIGURATION_OUTCOME_UNKNOWN"))
    private fun rejected(opened: Opening?, code: ControlCode, warning: String? = null) = ControlResult(
        opened?.owner, UUID.randomUUID().toString(), code, opened?.revision ?: 0, warnings = listOfNotNull(warning))
}
