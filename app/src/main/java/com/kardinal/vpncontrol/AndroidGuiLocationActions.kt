package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.control.ControlCommitted
import com.kardinal.vpncontrol.data.AndroidLocationControl
import com.kardinal.vpncontrol.data.LocationConfigs
import com.kardinal.vpncontrol.model.*
import java.security.MessageDigest
import java.util.UUID

/** Frontend editor state only. Owner remains the sole admission and commit authority. */
internal class AndroidGuiLocationActions(
    private val controller: MainController,
    private val state: () -> MainUiState,
    private val launch: (suspend () -> Unit) -> Unit,
    private val snapshot: suspend () -> ControlCommitted<PersistedState>,
    private val execute: suspend (ControlRequest) -> ControlResult,
) {
    private class Opening(val owner: String, val revision: Long, val target: String?, val seed: String = UUID.randomUUID().toString())
    private var opening: Opening? = null
    private var generation = 0L
    private var retrySelection: Pair<String, ControlRequest>? = null
    private var importOpening: Opening? = null
    private fun scope(state: MainUiState) = state.profileSourceMode.name + ":" + state.activeSubscriptionId
    private fun scope(state: PersistedState) = state.profileSourceMode.name + ":" + state.activeSubscriptionId
    private fun fail(code: ControlCode) { controller.showLocationMutationBlockedDialog(code.wireName) }
    private fun work(block: suspend () -> Unit) = launch {
        try { block() }
        catch (cancelled: kotlinx.coroutines.CancellationException) { throw cancelled }
        catch (_: Exception) { fail(ControlCode.UNAVAILABLE) }
    }

    fun open(raw: String? = null) = openTarget(raw?.let { androidRenderedLocationTarget(state(), it) })
    fun openTarget(target: AndroidRenderedLocationTarget?) {
        val raw = target?.raw
        opening = null
        val token = ++generation
        val renderedScope = target?.scope ?: scope(state())
        work {
            val committed = snapshot()
            if (generation != token) return@work
            if (scope(committed.value) != renderedScope || raw != null && (raw !in committed.value.currentLocations ||
                androidLocationVisualKey(raw, AndroidLocationControl.source(committed.value, raw)) != target?.sourceKey)) {
                fail(ControlCode.CONFLICT); return@work
            }
            if (raw == null && committed.value.profileSourceMode != ProfileSourceMode.CURRENT_LOCATIONS) {
                fail(ControlCode.UNSUPPORTED); return@work
            }
            opening = Opening(committed.controllerId, committed.revision, raw?.let { AndroidLocationControl.identity(committed.controllerId, committed.value, it) })
            if (raw == null) controller.showAddLocationDialog()
            else controller.editLocation(committed.value.currentLocations.indexOf(raw), runCatching { LocationConfigs.prettyStoredLocation(raw) }.getOrDefault(raw))
        }
    }
    fun close() { generation++; opening = null; retrySelection = null }
    fun save() {
        val opened = opening ?: run { fail(ControlCode.CONFLICT); return }
        val input = state().locationDraft
        val requestId = MessageDigest.getInstance("SHA-256").digest((opened.seed + "\u0000" + input).toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }
        val command = ControlCommand(if (opened.target == null) ControlOperationId.LOCATIONS_ADD else ControlOperationId.LOCATIONS_UPDATE,
            mapOf("input" to ControlValue.Text(input)) + (opened.target?.let { mapOf("id" to ControlValue.Text(it)) } ?: emptyMap()))
        work {
            val result = execute(ControlRequest(requestId, command, controllerId = opened.owner, ifRevision = opened.revision))
            if (opening !== opened) return@work
            if (result.code == ControlCode.OK && result.final) { close(); controller.closeLocationDialog() }
            else fail(result.code)
        }
    }
    fun select(raw: String) {
        select(androidRenderedLocationTarget(state(), raw))
    }
    fun select(target: AndroidRenderedLocationTarget) { rowAction(target, ControlOperationId.LOCATIONS_SELECT) }
    fun delete(raw: String) { delete(androidRenderedLocationTarget(state(), raw)) }
    fun delete(target: AndroidRenderedLocationTarget) { rowAction(target, ControlOperationId.LOCATIONS_DELETE) }
    private fun rowAction(target: AndroidRenderedLocationTarget, operation: ControlOperationId) {
        val raw = target.raw
        val renderedScope = target.scope
        val key = operation.name + "\u0000" + renderedScope + "\u0000" + target.sourceKey
        work {
            val request = retrySelection?.takeIf { it.first == key }?.second ?: run {
                val committed = snapshot()
                if (scope(committed.value) != renderedScope || raw !in committed.value.currentLocations ||
                    androidLocationVisualKey(raw, AndroidLocationControl.source(committed.value, raw)) != target.sourceKey) {
                    fail(ControlCode.CONFLICT); return@work
                }
                ControlRequest(UUID.randomUUID().toString(), ControlCommand(operation,
                    mapOf("id" to ControlValue.Text(AndroidLocationControl.identity(committed.controllerId, committed.value, raw)))),
                    controllerId = committed.controllerId, ifRevision = committed.revision).also { retrySelection = key to it }
            }
            val result = execute(request)
            if (result.final && result.code !in setOf(ControlCode.TIMEOUT, ControlCode.OUTCOME_UNKNOWN)) {
                if (retrySelection?.second == request) retrySelection = null
            }
            if (result.code != ControlCode.OK || !result.final) fail(result.code)
        }
    }

    fun beginImport(openPicker: () -> Unit) {
        importOpening = null
        val renderedScope = scope(state())
        work {
            val committed = snapshot()
            if (scope(committed.value) != renderedScope) { fail(ControlCode.CONFLICT); return@work }
            if (committed.value.profileSourceMode != ProfileSourceMode.CURRENT_LOCATIONS) { fail(ControlCode.UNSUPPORTED); return@work }
            importOpening = Opening(committed.controllerId, committed.revision, null)
            openPicker()
        }
    }
    fun cancelImport() { importOpening = null }
    fun import(raw: String) {
        val opened = importOpening ?: run { fail(ControlCode.CONFLICT); return }
        val requestId = MessageDigest.getInstance("SHA-256").digest((opened.seed + "\u0000" + raw).toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }
        work {
            val result = execute(ControlRequest(requestId, ControlCommand(ControlOperationId.LOCATIONS_IMPORT,
                mapOf("input" to ControlValue.Text(raw))), controllerId = opened.owner, ifRevision = opened.revision))
            if (importOpening !== opened) return@work
            if (result.code == ControlCode.OK && result.final) importOpening = null else fail(result.code)
        }
    }
}
