package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.RoutingStatusMessages
import com.kardinal.vpncontrol.model.LocationStatusMessages
import androidx.compose.ui.awt.ComposeWindow
import com.kardinal.vpncontrol.MainDraftLogic
import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.data.RoutingRulesTransfer
import com.kardinal.vpncontrol.model.InstalledApp
import com.kardinal.vpncontrol.model.RoutingRules
import com.kardinal.vpncontrol.model.RoutingRuleSet
import com.kardinal.vpncontrol.model.RoutingRuleSetAction
import com.kardinal.vpncontrol.model.RoutingRuleSetFormat
import com.kardinal.vpncontrol.model.RoutingRuleSetSourceType

internal class DesktopRoutingRulesService(
    private val stateProvider: () -> MainUiState,
    private val commitState: (MainUiState) -> Unit,
    private val updateState: ((MainUiState) -> MainUiState) -> Unit,
) {
    fun setIgnoreRulesDraft(enabled: Boolean) {
        updateState { it.copy(routingIgnoreRulesDraft = enabled) }
    }

    fun setAppSearch(query: String) {
        updateState { it.copy(routingAppSearch = query) }
    }

    fun toggleProxyApp(packageName: String) {
        updateState {
            it.copy(
                routingProxyPackagesDraft = if (packageName in it.routingProxyPackagesDraft) {
                    it.routingProxyPackagesDraft - packageName
                } else {
                    it.routingProxyPackagesDraft + packageName
                },
            )
        }
    }

    fun selectAllProxyApps() {
        updateState { it.copy(routingProxyPackagesDraft = it.installedApps.map(InstalledApp::packageName).toSet()) }
    }

    fun clearAllProxyApps() {
        updateState { it.copy(routingProxyPackagesDraft = emptySet()) }
    }

    fun setNationalDomainsDraft(value: String) {
        updateState { it.copy(routingNationalDomainsDraft = value) }
    }

    fun setDirectDomainsDraft(value: String) {
        updateState { it.copy(routingDirectDomainsDraft = value) }
    }

    fun addSampleRuleSet() {
        updateState {
            it.withStatus(RoutingStatusMessages.sampleRuleSetAdded()).copy(
                routingRuleSetsDraft = it.routingRuleSetsDraft + RoutingRuleSet(
                    id = "desktop-${it.routingRuleSetsDraft.size + 1}",
                    name = "Desktop Sample ${it.routingRuleSetsDraft.size + 1}",
                    sourceType = RoutingRuleSetSourceType.INLINE,
                    format = RoutingRuleSetFormat.SOURCE,
                    action = RoutingRuleSetAction.BLOCK,
                    source = """{"version":1,"rules":[{"domain_suffix":["ads.example"]}]}""",
                ),
            )
        }
    }

    fun editRuleSet(id: String) {
        updateState {
            it.copy(
                routingRuleSetsDraft = it.routingRuleSetsDraft.map { ruleSet ->
                    if (ruleSet.id == id) ruleSet.copy(name = "${ruleSet.name} (edited)") else ruleSet
                },
            )
        }
    }

    fun deleteRuleSet(id: String) {
        updateState {
            it.copy(routingRuleSetsDraft = it.routingRuleSetsDraft.filterNot { ruleSet -> ruleSet.id == id })
                .withStatus(RoutingStatusMessages.ruleSetDeleted(id))
        }
    }

    fun saveRoutingRules() {
        updateState {
            it.withStatus(RoutingStatusMessages.routingRulesSaved()).copy(
                routingRules = RoutingRules(
                    ignoreRules = it.routingIgnoreRulesDraft,
                    proxyPackages = RoutingRules.normalizePackageNames(it.routingProxyPackagesDraft),
                    bypassPackages = emptyList(),
                    nationalDomainSuffixes = RoutingRules.parseNationalDomainSuffixes(it.routingNationalDomainsDraft),
                    directDomainSuffixes = RoutingRules.parseDirectDomainSuffixes(it.routingDirectDomainsDraft),
                    ruleSets = emptyList(),
                ),
            )
        }
    }

    fun importRaw(raw: String) {
        val parsed = runCatching { RoutingRulesTransfer.import(raw) }
        if (parsed.isFailure) {
            updateState { it.withStatus(parsed.exceptionOrNull()?.message ?: RoutingStatusMessages.routingRulesImportFailed()) }
            return
        }
        val state = stateProvider()
        val rules = MainDraftLogic.sanitizeRoutingRules(parsed.getOrThrow())
        val message = if (state.isVpnRunning) {
            RoutingStatusMessages.routingRulesImportedRestartRequired(state.appMode)
        } else {
            RoutingStatusMessages.routingRulesImported()
        }
        commitState(
            MainDraftLogic.applyImportedRoutingRules(
                state.copy(routingRules = rules),
                rules,
            ).withStatus(message),
        )
    }

    fun importFromClipboard() {
        val raw = DesktopTextTransfer.readClipboardText()
        if (raw.isFailure) {
            updateState { it.withStatus(raw.exceptionOrNull()?.message ?: LocationStatusMessages.clipboardReadFailed()) }
            return
        }
        importRaw(raw.getOrThrow())
    }

    fun importFromFile(
        window: ComposeWindow,
        title: String = "Import Routing Rules",
    ) {
        val opened = DesktopTextTransfer.openTextFile(window, title)
        if (opened.isFailure) {
            updateState { it.withStatus(opened.exceptionOrNull()?.message ?: RoutingStatusMessages.routingRulesFileOpenFailed()) }
            return
        }
        val raw = opened.getOrNull() ?: return
        importRaw(raw)
    }

    fun exportToClipboard() {
        val document = RoutingRulesTransfer.export(MainDraftLogic.buildEditedRoutingRules(stateProvider()))
        val result = DesktopTextTransfer.writeClipboardText(document.content)
        updateState {
            it.withStatus(
                result.exceptionOrNull()?.message ?: RoutingStatusMessages.routingRulesCopiedToClipboard(),
            )
        }
    }

    fun exportToFile(
        window: ComposeWindow,
        title: String = "Export Routing Rules",
    ) {
        val document = RoutingRulesTransfer.export(MainDraftLogic.buildEditedRoutingRules(stateProvider()))
        val result = DesktopTextTransfer.saveTextFile(
            window = window,
            title = title,
            suggestedFileName = document.fileName,
            content = document.content,
        )
        updateState {
            it.withStatus(
                result.fold(
                    onSuccess = { path ->
                        if (path == null) {
                            RoutingStatusMessages.routingRulesExportCanceled()
                        } else {
                            RoutingStatusMessages.routingRulesExportedTo(path.toString())
                        }
                    },
                    onFailure = { error -> error.message ?: RoutingStatusMessages.routingRulesExportFailed() },
                ),
            )
        }
    }
}
