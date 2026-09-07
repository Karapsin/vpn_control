package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.data.RoutingRulesExportDocument
import com.kardinal.vpncontrol.data.RoutingRulesTransfer
import com.kardinal.vpncontrol.model.RoutingRules
import com.kardinal.vpncontrol.model.RoutingRuleSetAction
import com.kardinal.vpncontrol.model.RoutingRuleSetFormat
import com.kardinal.vpncontrol.model.RoutingRuleSetSourceType
import com.kardinal.vpncontrol.model.ControlCode
import com.kardinal.vpncontrol.model.RoutingStatusMessages

internal class AndroidRoutingActionsService(
    private val controller: MainController,
    private val stateProvider: () -> MainUiState,
    private val effectSink: AndroidControllerEffectSink,
    private val launch: (suspend () -> Unit) -> Unit,
    private val setBusy: (Boolean) -> Unit,
    private val updateRoutingRules: suspend (RoutingRules) -> Result<Unit>,
    private val updateStatus: suspend (String) -> Unit,
    private val guarded: AndroidRoutingDraftControl? = null,
    private val committedSnapshot: (suspend () -> com.kardinal.vpncontrol.control.ControlCommitted<com.kardinal.vpncontrol.model.PersistedState>)? = null,
) {
    private var feedbackGeneration = 0L

    private fun clearFeedback(): Long {
        feedbackGeneration++
        controller.update { it.copy(routingDraftFailure = null, routingDraftRetryAvailable = false) }
        return feedbackGeneration
    }

    private fun feedback(message: String?, retry: Boolean, generation: Long) {
        if (generation == feedbackGeneration) {
            controller.update { it.copy(routingDraftFailure = message, routingDraftRetryAvailable = retry) }
        }
    }

    fun observe(committed: com.kardinal.vpncontrol.control.ControlCommitted<com.kardinal.vpncontrol.model.PersistedState>) {
        guarded?.observe(committed)
    }
    fun openEditor(): Boolean {
        val opened = guarded?.openEditor() ?: true
        val generation = clearFeedback()
        if (!opened) {
            val message = RoutingStatusMessages.routingRulesStaleDraft()
            feedback(message, false, generation)
            launch { updateStatus(message) }
        }
        return opened
    }
    fun closeEditor() { guarded?.closeEditor(); clearFeedback() }
    fun beginImport(openPicker: () -> Unit) {
        val generation = clearFeedback()
        if (guarded?.beginImport() != false) openPicker()
        else {
            val message = RoutingStatusMessages.routingRulesStaleDraft()
            feedback(message, false, generation)
            launch { updateStatus(message) }
        }
    }
    fun cancelImport() { guarded?.cancelImport(); clearFeedback() }
    fun importRoutingReader(openReader: () -> java.io.Reader) {
        val owner = guarded ?: return
        val generation = feedbackGeneration
        launch { report(owner.importDocument(openReader), imported = true, generation = generation) }
    }
    fun onRoutingIgnoreRulesDraftChanged(enabled: Boolean) {
        controller.onRoutingIgnoreRulesDraftChanged(enabled)
        persistEditedRoutingRules()
    }

    fun onRoutingBlockQuicUdp443DraftChanged(enabled: Boolean) {
        controller.onRoutingBlockQuicUdp443DraftChanged(enabled)
        persistEditedRoutingRules()
    }

    fun onRoutingAppSearchChanged(value: String) {
        controller.onRoutingAppSearchChanged(value)
    }

    fun onRoutingDirectDomainsDraftChanged(value: String) {
        controller.onRoutingDirectDomainsDraftChanged(value)
        persistEditedRoutingRules()
    }

    fun onRoutingDirectDomainSuffixesDraftChanged(value: List<String>) {
        controller.onRoutingDirectDomainSuffixesDraftChanged(value)
        persistEditedRoutingRules()
    }

    fun showAddRuleSetDialog() {
        controller.showAddRuleSetDialog()
    }

    fun editRuleSet(id: String) {
        controller.editRuleSet(id)
    }

    fun closeRuleSetDialog() {
        controller.closeRuleSetDialog()
    }

    fun onRuleSetNameDraftChanged(value: String) {
        controller.onRuleSetNameDraftChanged(value)
    }

    fun onRuleSetSourceDraftChanged(value: String) {
        controller.onRuleSetSourceDraftChanged(value)
    }

    fun onRuleSetSourceTypeDraftChanged(value: RoutingRuleSetSourceType) {
        controller.onRuleSetSourceTypeDraftChanged(value)
    }

    fun onRuleSetFormatDraftChanged(value: RoutingRuleSetFormat) {
        controller.onRuleSetFormatDraftChanged(value)
    }

    fun onRuleSetActionDraftChanged(value: RoutingRuleSetAction) {
        controller.onRuleSetActionDraftChanged(value)
    }

    fun onRuleSetUpdateHoursDraftChanged(value: String) {
        controller.onRuleSetUpdateHoursDraftChanged(value)
    }

    fun saveRuleSet() {
        effectSink.handle(controller.saveRuleSet())
    }

    fun deleteRuleSet(id: String) {
        effectSink.handle(controller.deleteRuleSet(id))
    }

    fun toggleProxyRoutingApp(packageName: String) {
        controller.toggleProxyRoutingApp(packageName)
        persistEditedRoutingRules()
    }

    fun toggleDirectRoutingApp(packageName: String) {
        controller.toggleDirectRoutingApp(packageName)
        persistEditedRoutingRules()
    }

    fun selectAllVisibleProxyApps() {
        controller.selectAllVisibleProxyApps(filteredRoutingPackages())
        persistEditedRoutingRules()
    }

    fun clearAllVisibleProxyApps() {
        controller.clearAllVisibleProxyApps(filteredRoutingPackages())
        persistEditedRoutingRules()
    }

    fun selectAllVisibleDirectApps() {
        controller.selectAllVisibleDirectApps(filteredRoutingPackages())
        persistEditedRoutingRules()
    }

    fun clearAllVisibleDirectApps() {
        controller.clearAllVisibleDirectApps(filteredRoutingPackages())
        persistEditedRoutingRules()
    }

    fun saveRoutingRules() {
        persistEditedRoutingRules(showBusy = true, edited = false)
    }

    private fun persistEditedRoutingRules(showBusy: Boolean = false, edited: Boolean = true) {
        val generation = if (edited) clearFeedback() else feedbackGeneration
        val rules = MainDraftLogic.buildEditedRoutingRules(stateProvider())
        launch {
            guarded?.let { owner ->
                if (showBusy) setBusy(true)
                try { report(owner.save(rules), imported = false, generation = generation) }
                finally { if (showBusy) setBusy(false) }
                return@launch
            }
            if (showBusy) {
                setBusy(true)
            }
            val result = updateRoutingRules(rules)
            feedback(if (result.isSuccess) null else RoutingStatusMessages.routingRulesSaveFailed(),
                retry = result.isFailure, generation = generation)
            updateStatus(
                result.fold(
                    onSuccess = {
                        controller.update { state -> state.copy(routingRules = rules) }
                        RoutingRulesStatusLogic.saved(
                            isConnectionRunning = stateProvider().isVpnRunning,
                            appMode = stateProvider().appMode,
                        )
                    },
                    onFailure = { RoutingRulesStatusLogic.saveFailed(it) },
                ),
            )
            if (showBusy) {
                setBusy(false)
            }
        }
    }

    fun buildRoutingRulesExport(): RoutingRulesExportDocument {
        return RoutingRulesTransfer.export(MainDraftLogic.buildEditedRoutingRules(stateProvider()))
    }

    fun importRoutingRules(raw: String) {
        if (guarded != null) {
            beginImport { importRoutingReader { java.io.StringReader(raw) } }
            return
        }
        launch { importRoutingRulesWithinMutation(raw) }
    }

    suspend fun importRoutingRulesWithinMutation(raw: String) {
            val generation = clearFeedback()
            if (guarded != null) {
                if (!guarded.beginImport()) {
                    val message = RoutingStatusMessages.routingRulesStaleDraft()
                    feedback(message, false, generation); updateStatus(message); return
                }
                report(guarded.importDocument { java.io.StringReader(raw) }, imported = true, generation = generation)
                return
            }
            setBusy(true)
            val parsed = runCatching { RoutingRulesTransfer.import(raw) }
            if (parsed.isFailure) {
                feedback(RoutingStatusMessages.routingRulesImportFailed(), false, generation)
                updateStatus(RoutingRulesStatusLogic.importFailed(parsed.exceptionOrNull()))
                setBusy(false)
                return
            }

            val rules = MainDraftLogic.sanitizeRoutingRules(parsed.getOrThrow())
            val result = updateRoutingRules(rules)
            feedback(if (result.isSuccess) null else RoutingStatusMessages.routingRulesImportFailed(), false, generation)
            updateStatus(
                result.fold(
                    onSuccess = {
                        controller.applyImportedRoutingRules(rules)
                        RoutingRulesStatusLogic.imported(
                            isConnectionRunning = stateProvider().isVpnRunning,
                            appMode = stateProvider().appMode,
                        )
                    },
                    onFailure = { RoutingRulesStatusLogic.importFailed(it) },
                ),
            )
            setBusy(false)
    }

    private suspend fun report(outcome: AndroidRoutingDraftControl.Outcome, imported: Boolean, generation: Long) {
        val result = outcome.result
        if (outcome.applyToDraft) {
            // Replace the indexed draft with the exact new immutable storage view.
            // Keeping its old source after a successful edit retains an entire
            // obsolete large document while readback/export need working memory.
            val committed = try { committedSnapshot?.invoke() }
                catch (_: Exception) { null }
                catch (_: OutOfMemoryError) { null }
            if (committed?.controllerId == result.controllerId && committed?.revision == result.configurationRevision) {
                controller.applyImportedRoutingRules(requireNotNull(committed).value.routingRules)
            }
        }
        val succeeded = result.code == ControlCode.OK && result.final
        val uncertain = !succeeded && (!result.final || result.code in setOf(ControlCode.TIMEOUT, ControlCode.OUTCOME_UNKNOWN) ||
            result.warnings.any { it in setOf("CONFIGURATION_OUTCOME_UNKNOWN", "PREVIOUS_REQUEST_OUTCOME_UNKNOWN") })
        val message = if (succeeded) {
            if (imported) RoutingRulesStatusLogic.imported(stateProvider().isVpnRunning, stateProvider().appMode)
            else RoutingRulesStatusLogic.saved(stateProvider().isVpnRunning, stateProvider().appMode)
        } else if (uncertain) RoutingStatusMessages.routingRulesOutcomeUnknown()
        else if (result.code == ControlCode.CONFLICT) RoutingStatusMessages.routingRulesStaleDraft()
        else if (imported) RoutingStatusMessages.routingRulesImportFailed()
        else RoutingStatusMessages.routingRulesSaveFailed()
        feedback(if (succeeded) null else message,
            retry = !succeeded && !imported && (uncertain || result.code != ControlCode.CONFLICT), generation = generation)
        updateStatus(message)
    }

    private fun filteredRoutingPackages(): List<String> {
        val query = stateProvider().routingAppSearch.trim()
        return stateProvider().installedApps
            .asSequence()
            .filter { app ->
                query.isBlank() ||
                    app.label.contains(query, ignoreCase = true) ||
                    app.packageName.contains(query, ignoreCase = true)
            }
            .map { it.packageName }
            .toList()
    }
}
