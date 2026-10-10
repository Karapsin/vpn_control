package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.control.ControlCommitted
import com.kardinal.vpncontrol.model.*
import java.util.UUID
import kotlinx.coroutines.CancellationException

/** Frontend rename draft only; the application owner guards and commits the typed command. */
internal class AndroidSubscriptionRenameDraftControl(
    private val controller: MainController,
    private val state: () -> MainUiState,
    private val launch: (suspend () -> Unit) -> Unit,
    private val snapshot: suspend () -> ControlCommitted<PersistedState>,
    private val execute: suspend (ControlRequest) -> ControlResult,
    private val updateStatus: suspend (String) -> Unit,
    private val sourcePreviewTitle: (String) -> String? = { null },
) {
    private class Opening(val owner: String, val revision: Long, val id: String, val source: String) {
        var edits = 0L
        var attempt: Attempt? = null
    }
    private class Attempt(val request: ControlRequest) {
        var waiting = false
        var result: ControlResult? = null
    }
    private var generation = 0L
    private var editGeneration = 0L
    private var opening: Opening? = null

    fun open(source: String) {
        val url = source.trim()
        val renderedId = state().subscriptions.singleOrNull { it.url == url }?.id
        opening = null
        val token = ++generation
        val editToken = editGeneration
        launch {
            try {
                val committed = snapshot()
                if (generation != token || editGeneration != editToken) return@launch
                val target = committed.value.subscriptions.singleOrNull { it.url == url && it.id == renderedId }
                if (target == null) { updateStatus(ControlCode.CONFLICT.wireName); return@launch }
                opening = Opening(committed.controllerId, committed.revision, target.id, target.url)
                controller.showProfileHistoryRenameDialog(target.url,
                    target.customName.takeIf { it.isNotBlank() } ?: sourcePreviewTitle(target.url).orEmpty())
            } catch (cancelled: CancellationException) { throw cancelled }
            catch (_: Exception) { if (generation == token && editGeneration == editToken) updateStatus(ControlCode.UNAVAILABLE.wireName) }
        }
    }

    fun close() { generation++; opening = null }
    fun edited() { editGeneration++; opening?.let { it.edits++ } }

    fun save() {
        val opened = opening
        if (opened == null) { feedback(ControlCode.CONFLICT); return }
        val visible = state()
        if (!visible.showProfileHistoryRenameDialog || visible.profileHistoryRenameSource != opened.source) {
            feedback(ControlCode.CONFLICT); return
        }
        val command = ControlCommand(ControlOperationId.SUBSCRIPTIONS_UPDATE, mapOf(
            "id" to ControlValue.Text(opened.id),
            "source" to ControlValue.Text(visible.profileHistoryRenameUrlDraft.trim()),
            "name" to ControlValue.Text(visible.profileHistoryRenameDraft.take(80).trim()),
        ))
        val prior = opened.attempt
        if (prior?.waiting == true) return
        val uncertain = prior != null && (prior.result == null || uncertain(prior.result!!))
        if (uncertain && prior!!.request.command != command) {
            feedback(ControlCode.OUTCOME_UNKNOWN); return
        }
        val attempt = if (uncertain) prior!! else Attempt(ControlRequest(UUID.randomUUID().toString(), command,
            controllerId = opened.owner, ifRevision = opened.revision))
        opened.attempt = attempt
        attempt.waiting = true
        val edits = opened.edits
        launch {
            try {
                if (opening !== opened || opened.edits != edits) {
                    if (opened.attempt === attempt && attempt.result == null) opened.attempt = null
                    return@launch
                }
                val result = try { execute(attempt.request) }
                    catch (cancelled: CancellationException) { throw cancelled }
                    catch (_: Exception) { unknown(opened, attempt) }
                val correlated = result.controllerId == opened.owner && result.requestId == attempt.request.requestId
                attempt.result = if (correlated) result else unknown(opened, attempt)
                if (opening !== opened || opened.edits != edits) return@launch
                val completed = attempt.result!!
                if (completed.code == ControlCode.OK && completed.final) {
                    close()
                    controller.closeProfileHistoryRenameDialog()
                    updateStatus(when {
                        (command.arguments["source"] as ControlValue.Text).value != opened.source -> SubscriptionStatusMessages.subscriptionSaved()
                        (command.arguments["name"] as ControlValue.Text).value.isBlank() -> SubscriptionStatusMessages.subscriptionNameReset()
                        else -> SubscriptionStatusMessages.subscriptionNameSaved()
                    })
                } else updateStatus(completed.code.wireName)
            } finally { attempt.waiting = false }
        }
    }

    private fun feedback(code: ControlCode) {
        val token = generation
        val edits = editGeneration
        val opened = opening
        launch {
            if (generation == token && editGeneration == edits && opening === opened) updateStatus(code.wireName)
        }
    }

    private fun uncertain(result: ControlResult) = !result.final || result.code in setOf(
        ControlCode.TIMEOUT, ControlCode.OUTCOME_UNKNOWN, ControlCode.UNAVAILABLE) ||
        "CONFIGURATION_COMMITTED" in result.warnings || "CONFIGURATION_OUTCOME_UNKNOWN" in result.warnings
    private fun unknown(opened: Opening, attempt: Attempt) = ControlResult(opened.owner, attempt.request.requestId,
        ControlCode.OUTCOME_UNKNOWN, opened.revision, final = false, warnings = listOf("CONFIGURATION_OUTCOME_UNKNOWN"))
}
