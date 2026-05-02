package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.data.RoutingRulesExportDocument
import com.kardinal.vpncontrol.data.RoutingRulesTransfer
import com.kardinal.vpncontrol.model.RoutingRules
import com.kardinal.vpncontrol.model.RoutingRuleSetAction
import com.kardinal.vpncontrol.model.RoutingRuleSetFormat
import com.kardinal.vpncontrol.model.RoutingRuleSetSourceType

internal class AndroidRoutingActionsService(
    private val controller: MainController,
    private val stateProvider: () -> MainUiState,
    private val effectSink: AndroidControllerEffectSink,
    private val launch: (suspend () -> Unit) -> Unit,
    private val setBusy: (Boolean) -> Unit,
    private val updateRoutingRules: suspend (RoutingRules) -> Result<Unit>,
    private val updateStatus: suspend (String) -> Unit,
) {
    fun onRoutingIgnoreRulesDraftChanged(enabled: Boolean) {
        controller.onRoutingIgnoreRulesDraftChanged(enabled)
    }

    fun onRoutingAppSearchChanged(value: String) {
        controller.onRoutingAppSearchChanged(value)
    }

    fun onRoutingNationalDomainsDraftChanged(value: String) {
        controller.onRoutingNationalDomainsDraftChanged(value)
    }

    fun onRoutingDirectDomainsDraftChanged(value: String) {
        controller.onRoutingDirectDomainsDraftChanged(value)
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
    }

    fun toggleDirectRoutingApp(packageName: String) {
        controller.toggleDirectRoutingApp(packageName)
    }

    fun selectAllVisibleProxyApps() {
        controller.selectAllVisibleProxyApps(filteredRoutingPackages())
    }

    fun clearAllVisibleProxyApps() {
        controller.clearAllVisibleProxyApps(filteredRoutingPackages())
    }

    fun selectAllVisibleDirectApps() {
        controller.selectAllVisibleDirectApps(filteredRoutingPackages())
    }

    fun clearAllVisibleDirectApps() {
        controller.clearAllVisibleDirectApps(filteredRoutingPackages())
    }

    fun saveRoutingRules() {
        val rules = MainDraftLogic.buildEditedRoutingRules(stateProvider())
        launch {
            setBusy(true)
            val result = updateRoutingRules(rules)
            updateStatus(
                result.fold(
                    onSuccess = {
                        RoutingRulesStatusLogic.saved(
                            isConnectionRunning = stateProvider().isVpnRunning,
                            appMode = stateProvider().appMode,
                        )
                    },
                    onFailure = { RoutingRulesStatusLogic.saveFailed(it) },
                ),
            )
            if (result.isSuccess) {
                effectSink.handle(controller.navigateBack())
            }
            setBusy(false)
        }
    }

    fun buildRoutingRulesExport(): RoutingRulesExportDocument {
        return RoutingRulesTransfer.export(MainDraftLogic.buildEditedRoutingRules(stateProvider()))
    }

    fun importRoutingRules(raw: String) {
        launch {
            setBusy(true)
            val parsed = runCatching { RoutingRulesTransfer.import(raw) }
            if (parsed.isFailure) {
                updateStatus(RoutingRulesStatusLogic.importFailed(parsed.exceptionOrNull()))
                setBusy(false)
                return@launch
            }

            val rules = MainDraftLogic.sanitizeRoutingRules(parsed.getOrThrow())
            val result = updateRoutingRules(rules)
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
