package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.data.ImportPreference
import com.kardinal.vpncontrol.data.IncomingImportPayload
import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.AppLanguage
import com.kardinal.vpncontrol.model.BenchmarkValidationSettings
import com.kardinal.vpncontrol.model.ProfileSourceMode
import com.kardinal.vpncontrol.model.RoutingRules
import com.kardinal.vpncontrol.model.StatusMessages
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

sealed interface MainControllerEffect {
    data object EnsureInstalledAppsLoaded : MainControllerEffect
    data class UpdateStatus(val message: String) : MainControllerEffect
    data class UpdateProfileSourceMode(val mode: ProfileSourceMode) : MainControllerEffect
    data class UpdateAppMode(val mode: AppMode) : MainControllerEffect
    data class UpdateAppLanguage(val language: AppLanguage, val statusMessage: String) : MainControllerEffect
    data class SelectActiveSubscription(val subscriptionId: String) : MainControllerEffect
    data class ImportRoutingRules(val raw: String) : MainControllerEffect
    data class SaveProfileSource(
        val value: String,
        val mode: ProfileSourceMode,
        val statusMessage: String,
    ) : MainControllerEffect
    data class DeleteProfileHistoryEntry(
        val source: String,
        val statusMessage: String,
    ) : MainControllerEffect
    data class SaveProfileHistoryRename(
        val source: String,
        val normalizedName: String,
        val statusMessage: String,
    ) : MainControllerEffect
    data class SaveSubscriptionRefreshPolicy(
        val policy: com.kardinal.vpncontrol.model.SubscriptionRefreshPolicy,
        val customHours: Double,
        val findBestAfterRefresh: Boolean,
        val statusMessage: String,
    ) : MainControllerEffect
    data class SaveValidationSettings(
        val settings: BenchmarkValidationSettings,
        val statusMessage: String,
    ) : MainControllerEffect
    data class SaveDns(
        val dns: String,
        val enabled: Boolean,
        val statusMessage: String,
    ) : MainControllerEffect
}

class MainController(
    initialState: MainUiState = MainUiState(),
) {
    private val _state = MutableStateFlow(initialState)
    val state: StateFlow<MainUiState> = _state.asStateFlow()

    // Transitional escape hatch while Android still owns many action handlers.
    val mutableState: MutableStateFlow<MainUiState>
        get() = _state

    fun currentState(): MainUiState = _state.value

    fun update(transform: (MainUiState) -> MainUiState) {
        _state.value = transform(_state.value)
    }

    fun mergePersistedState(persistedState: com.kardinal.vpncontrol.model.PersistedState) {
        _state.value = MainUiStateProjector.mergePersistedState(
            current = _state.value,
            persisted = persistedState,
        )
    }

    fun toggleDnsDialog() {
        _state.value = _state.value.copy(
            showDnsDialog = !_state.value.showDnsDialog,
            customDnsDraft = _state.value.customDns,
            useCustomDnsDraft = _state.value.useCustomDns,
        )
    }

    fun toggleUiSettingsDialog() {
        _state.value = _state.value.copy(
            showUiSettingsDialog = !_state.value.showUiSettingsDialog,
        )
    }

    fun setSessionStatsEnabled(enabled: Boolean) {
        _state.value = _state.value.copy(sessionStatsEnabled = enabled)
    }

    fun setLiveTrafficStatsEnabled(enabled: Boolean) {
        _state.value = _state.value.copy(liveTrafficStatsEnabled = enabled)
    }

    fun setProfileTotalsEnabled(enabled: Boolean) {
        _state.value = _state.value.copy(profileTotalsEnabled = enabled)
    }

    fun setLatencyHistoryEnabled(enabled: Boolean) {
        _state.value = _state.value.copy(latencyHistoryEnabled = enabled)
    }

    fun setConnectionLogEnabled(enabled: Boolean) {
        _state.value = _state.value.copy(connectionLogEnabled = enabled)
    }

    fun setConnectionTestToolsEnabled(enabled: Boolean) {
        _state.value = _state.value.copy(connectionTestToolsEnabled = enabled)
    }

    fun toggleAppModeDialog() {
        _state.value = _state.value.copy(
            showAppModeDialog = !_state.value.showAppModeDialog,
        )
    }

    fun toggleLanguageDialog() {
        _state.value = _state.value.copy(
            showLanguageDialog = !_state.value.showLanguageDialog,
        )
    }

    fun setAppLanguage(value: AppLanguage): List<MainControllerEffect> {
        _state.value = _state.value.copy(
            appLanguage = value,
            showLanguageDialog = false,
        )
        return listOf(
            MainControllerEffect.UpdateAppLanguage(
                language = value,
                statusMessage = StatusMessages.languageSet(
                    if (value == AppLanguage.SYSTEM) "" else value.nativeName,
                ),
            ),
        )
    }

    fun toggleRefreshPolicyDialog() {
        _state.value = MainUiStateTransitions.toggleRefreshPolicyDialog(_state.value)
    }

    fun toggleValidationSettingsDialog() {
        _state.value = MainUiStateTransitions.toggleValidationSettingsDialog(_state.value)
    }

    fun onProfileDraftChanged(value: String) {
        _state.value = _state.value.copy(profileDraft = value)
    }

    fun openRoutingRules(): List<MainControllerEffect> {
        _state.value = MainUiStateTransitions.navigateToScreen(
            MainUiStateTransitions.prepareRoutingRulesScreen(_state.value),
            AppScreen.ROUTING_RULES,
        )
        return listOf(MainControllerEffect.EnsureInstalledAppsLoaded)
    }

    fun openMainTab() {
        _state.value = MainUiStateTransitions.navigateToScreen(_state.value, AppScreen.MAIN)
    }

    fun openProfileTab() {
        _state.value = MainUiStateTransitions.navigateToScreen(_state.value, AppScreen.PROFILE)
    }

    fun openLocationsTab() {
        _state.value = MainUiStateTransitions.navigateToScreen(_state.value, AppScreen.LOCATIONS)
    }

    fun openStatsTab() {
        _state.value = MainUiStateTransitions.navigateToScreen(_state.value, AppScreen.STATS)
    }

    fun navigateBack(): List<MainControllerEffect> {
        val previous = _state.value
        _state.value = MainUiStateTransitions.navigateBack(previous)
        return if (previous.currentScreen != _state.value.currentScreen &&
            _state.value.currentScreen == AppScreen.ROUTING_RULES
        ) {
            listOf(MainControllerEffect.EnsureInstalledAppsLoaded)
        } else {
            emptyList()
        }
    }

    fun pasteSubscriptionDraft(raw: String): List<MainControllerEffect> {
        val trimmed = raw.trim()
        if (trimmed.isBlank()) {
            return listOf(MainControllerEffect.UpdateStatus(StatusMessages.clipboardEmpty()))
        }
        _state.value = MainUiStateTransitions.navigateToScreen(_state.value, AppScreen.PROFILE).copy(
            profileSourceMode = ProfileSourceMode.SUBSCRIPTION,
            profileDraft = trimmed,
            showAddSubscriptionEditor = true,
        )
        return listOf(
            MainControllerEffect.UpdateProfileSourceMode(ProfileSourceMode.SUBSCRIPTION),
            MainControllerEffect.UpdateStatus(StatusMessages.subscriptionTextLoadedIntoProfile()),
        )
    }

    fun handleIncomingImport(
        payload: IncomingImportPayload,
        preference: ImportPreference,
    ): List<MainControllerEffect> {
        val effect = MainCommandLogic.incomingImportEffect(
            state = _state.value,
            payload = payload,
            preference = preference,
        )
        _state.value = effect.nextState
        return buildList {
            effect.profileSourceModeUpdate?.let { add(MainControllerEffect.UpdateProfileSourceMode(it)) }
            effect.routingRulesRaw?.let { add(MainControllerEffect.ImportRoutingRules(it)) }
            effect.statusMessage?.let { add(MainControllerEffect.UpdateStatus(it)) }
        }
    }

    fun toggleAddSubscriptionEditor() {
        _state.value = MainUiStateTransitions.toggleAddSubscriptionEditor(_state.value)
    }

    fun showProfileHistoryRenameDialog(source: String, currentName: String) {
        _state.value = _state.value.copy(
            showProfileHistoryRenameDialog = true,
            profileHistoryRenameSource = source.trim(),
            profileHistoryRenameDraft = currentName,
        )
    }

    fun closeProfileHistoryRenameDialog() {
        _state.value = _state.value.copy(
            showProfileHistoryRenameDialog = false,
            profileHistoryRenameSource = "",
            profileHistoryRenameDraft = "",
        )
    }

    fun onProfileHistoryRenameDraftChanged(value: String) {
        _state.value = _state.value.copy(profileHistoryRenameDraft = value.take(80))
    }

    fun setProfileSourceMode(value: ProfileSourceMode): List<MainControllerEffect> {
        _state.value = _state.value.copy(
            profileSourceMode = value,
            profileDraft = _state.value.profileUrl,
            showAddSubscriptionEditor = false,
        )
        return listOf(
            MainControllerEffect.UpdateProfileSourceMode(value),
            MainControllerEffect.UpdateStatus(StatusMessages.profileSourceSet(value)),
        )
    }

    fun setAppMode(value: AppMode): List<MainControllerEffect> {
        if (_state.value.isVpnRunning) {
            return listOf(MainControllerEffect.UpdateStatus(StatusMessages.disconnectFirstChangeConnectionMode()))
        }
        _state.value = _state.value.copy(
            appMode = value,
            showAppModeDialog = false,
        )
        return listOf(
            MainControllerEffect.UpdateAppMode(value),
            MainControllerEffect.UpdateStatus(StatusMessages.connectionModeSet(value)),
        )
    }

    fun onDnsDraftChanged(value: String) {
        _state.value = _state.value.copy(customDnsDraft = value)
    }

    fun onCustomDnsEnabledChanged(enabled: Boolean) {
        _state.value = _state.value.copy(useCustomDnsDraft = enabled)
    }

    fun onSubscriptionRefreshPolicyDraftChanged(policy: com.kardinal.vpncontrol.model.SubscriptionRefreshPolicy) {
        _state.value = _state.value.copy(subscriptionRefreshPolicyDraft = policy)
    }

    fun onFindBestAfterSubscriptionRefreshDraftChanged(enabled: Boolean) {
        _state.value = _state.value.copy(findBestAfterSubscriptionRefreshDraft = enabled)
    }

    fun onSubscriptionRefreshCustomHoursDraftChanged(value: String) {
        _state.value = _state.value.copy(
            subscriptionRefreshCustomHoursDraft = MainCommandLogic.sanitizeDecimalInput(value).take(6),
        )
    }

    fun onValidationPrimaryUrlDraftChanged(value: String) {
        _state.value = _state.value.copy(validationPrimaryUrlDraft = value)
    }

    fun onValidationSecondaryUrlDraftChanged(value: String) {
        _state.value = _state.value.copy(validationSecondaryUrlDraft = value)
    }

    fun onValidationBatchSizeDraftChanged(value: String) {
        _state.value = _state.value.copy(
            validationBatchSizeDraft = value.filter { it.isDigit() }.take(3),
        )
    }

    fun onValidationRetryCountDraftChanged(value: String) {
        _state.value = _state.value.copy(
            validationRetryCountDraft = value.filter { it.isDigit() }.take(3),
        )
    }

    fun onRoutingIgnoreRulesDraftChanged(enabled: Boolean) {
        _state.value = _state.value.copy(routingIgnoreRulesDraft = enabled)
    }

    fun onRoutingAppSearchChanged(value: String) {
        _state.value = _state.value.copy(routingAppSearch = value)
    }

    fun onRoutingNationalDomainsDraftChanged(value: String) {
        _state.value = _state.value.copy(routingNationalDomainsDraft = value)
    }

    fun onRoutingDirectDomainsDraftChanged(value: String) {
        _state.value = _state.value.copy(routingDirectDomainsDraft = value)
    }

    fun showAddRuleSetDialog() {
        _state.value = _state.value.copy(
            showRuleSetDialog = true,
            editingRuleSetId = "",
            routingRuleSetNameDraft = "",
            routingRuleSetSourceDraft = "",
            routingRuleSetSourceTypeDraft = com.kardinal.vpncontrol.model.RoutingRuleSetSourceType.REMOTE,
            routingRuleSetFormatDraft = com.kardinal.vpncontrol.model.RoutingRuleSetFormat.SOURCE,
            routingRuleSetActionDraft = com.kardinal.vpncontrol.model.RoutingRuleSetAction.DIRECT,
            routingRuleSetUpdateHoursDraft = "24",
        )
    }

    fun editRuleSet(id: String) {
        val ruleSet = _state.value.routingRuleSetsDraft.firstOrNull { it.id == id } ?: return
        _state.value = _state.value.copy(
            showRuleSetDialog = true,
            editingRuleSetId = ruleSet.id,
            routingRuleSetNameDraft = ruleSet.name,
            routingRuleSetSourceDraft = ruleSet.source,
            routingRuleSetSourceTypeDraft = ruleSet.sourceType,
            routingRuleSetFormatDraft = ruleSet.format,
            routingRuleSetActionDraft = ruleSet.action,
            routingRuleSetUpdateHoursDraft = ruleSet.updateIntervalHours.toString(),
        )
    }

    fun closeRuleSetDialog() {
        _state.value = _state.value.copy(
            showRuleSetDialog = false,
            editingRuleSetId = "",
            routingRuleSetNameDraft = "",
            routingRuleSetSourceDraft = "",
            routingRuleSetSourceTypeDraft = com.kardinal.vpncontrol.model.RoutingRuleSetSourceType.REMOTE,
            routingRuleSetFormatDraft = com.kardinal.vpncontrol.model.RoutingRuleSetFormat.SOURCE,
            routingRuleSetActionDraft = com.kardinal.vpncontrol.model.RoutingRuleSetAction.DIRECT,
            routingRuleSetUpdateHoursDraft = "24",
        )
    }

    fun onRuleSetNameDraftChanged(value: String) {
        _state.value = _state.value.copy(routingRuleSetNameDraft = value.take(80))
    }

    fun onRuleSetSourceDraftChanged(value: String) {
        _state.value = _state.value.copy(routingRuleSetSourceDraft = value)
    }

    fun onRuleSetSourceTypeDraftChanged(value: com.kardinal.vpncontrol.model.RoutingRuleSetSourceType) {
        _state.value = _state.value.copy(routingRuleSetSourceTypeDraft = value)
    }

    fun onRuleSetFormatDraftChanged(value: com.kardinal.vpncontrol.model.RoutingRuleSetFormat) {
        _state.value = _state.value.copy(routingRuleSetFormatDraft = value)
    }

    fun onRuleSetActionDraftChanged(value: com.kardinal.vpncontrol.model.RoutingRuleSetAction) {
        _state.value = _state.value.copy(routingRuleSetActionDraft = value)
    }

    fun onRuleSetUpdateHoursDraftChanged(value: String) {
        _state.value = _state.value.copy(
            routingRuleSetUpdateHoursDraft = value.filter { it.isDigit() }.take(4),
        )
    }

    fun deleteRuleSet(id: String): List<MainControllerEffect> {
        val existing = _state.value.routingRuleSetsDraft
        if (existing.none { it.id == id }) return emptyList()
        _state.value = _state.value.copy(
            routingRuleSetsDraft = existing.filterNot { it.id == id },
            showRuleSetDialog = if (_state.value.editingRuleSetId == id) false else _state.value.showRuleSetDialog,
            editingRuleSetId = if (_state.value.editingRuleSetId == id) "" else _state.value.editingRuleSetId,
        )
        return listOf(MainControllerEffect.UpdateStatus(StatusMessages.ruleSetRemoved()))
    }

    fun showAddLocationDialog(): List<MainControllerEffect> {
        if (_state.value.profileSourceMode != ProfileSourceMode.CURRENT_LOCATIONS) {
            return listOf(MainControllerEffect.UpdateStatus(StatusMessages.switchToSavedLocationsToAddLocations()))
        }
        _state.value = _state.value.copy(
            showLocationDialog = true,
            locationDraft = "",
            editingLocationIndex = null,
        )
        return emptyList()
    }

    fun editLocation(index: Int, rawLink: String) {
        _state.value = _state.value.copy(
            showLocationDialog = true,
            locationDraft = rawLink,
            editingLocationIndex = index,
        )
    }

    fun closeLocationDialog() {
        _state.value = _state.value.copy(
            showLocationDialog = false,
            locationDraft = "",
            editingLocationIndex = null,
        )
    }

    fun closeLocationMutationBlockedDialog() {
        _state.value = _state.value.copy(
            showLocationMutationBlockedDialog = false,
            locationMutationBlockedMessage = "",
        )
    }

    fun showLocationMutationBlockedDialog(message: String) {
        _state.value = _state.value.copy(
            showLocationMutationBlockedDialog = true,
            locationMutationBlockedMessage = message,
        )
    }

    fun onLocationDraftChanged(value: String) {
        _state.value = _state.value.copy(locationDraft = value)
    }

    fun toggleProxyRoutingApp(packageName: String) {
        val nextProxy = _state.value.routingProxyPackagesDraft.toMutableSet()
        if (!nextProxy.add(packageName)) {
            nextProxy.remove(packageName)
        }
        _state.value = _state.value.copy(
            routingProxyPackagesDraft = nextProxy,
            routingBypassPackagesDraft = emptySet(),
        )
    }

    fun toggleDirectRoutingApp(packageName: String) {
        val nextProxy = _state.value.routingProxyPackagesDraft.toMutableSet()
        nextProxy.remove(packageName)
        _state.value = _state.value.copy(
            routingProxyPackagesDraft = nextProxy,
            routingBypassPackagesDraft = emptySet(),
        )
    }

    fun selectAllVisibleProxyApps(visiblePackages: List<String>) {
        val nextProxy = _state.value.routingProxyPackagesDraft.toMutableSet()
        nextProxy.addAll(visiblePackages)
        _state.value = _state.value.copy(
            routingProxyPackagesDraft = nextProxy,
            routingBypassPackagesDraft = emptySet(),
        )
    }

    fun clearAllVisibleProxyApps(visiblePackages: List<String>) {
        val nextProxy = _state.value.routingProxyPackagesDraft.toMutableSet()
        nextProxy.removeAll(visiblePackages.toSet())
        _state.value = _state.value.copy(routingProxyPackagesDraft = nextProxy)
    }

    fun selectAllVisibleDirectApps(visiblePackages: List<String>) {
        val nextProxy = _state.value.routingProxyPackagesDraft.toMutableSet()
        nextProxy.removeAll(visiblePackages.toSet())
        _state.value = _state.value.copy(
            routingProxyPackagesDraft = nextProxy,
            routingBypassPackagesDraft = emptySet(),
        )
    }

    fun clearAllVisibleDirectApps(visiblePackages: List<String>) {
        val nextProxy = _state.value.routingProxyPackagesDraft.toMutableSet()
        nextProxy.removeAll(visiblePackages.toSet())
        _state.value = _state.value.copy(
            routingProxyPackagesDraft = nextProxy,
            routingBypassPackagesDraft = emptySet(),
        )
    }

    fun onVpnPermissionGranted() {
        _state.value = _state.value.copy(hasVpnPermission = true)
    }

    fun saveProfile(
        validateSubscription: (String) -> Result<Unit>,
    ): List<MainControllerEffect> {
        val value = _state.value.profileDraft.trim()
        val mode = _state.value.profileSourceMode
        val decision = MainCommandLogic.validateProfileSourceSave(
            value = value,
            mode = mode,
            validateSubscription = validateSubscription,
        )
        if (decision.isFailure) {
            return listOf(
                MainControllerEffect.UpdateStatus(
                    decision.exceptionOrNull()?.message ?: "Invalid remote source",
                ),
            )
        }
        _state.value = _state.value.copy(
            profileDraft = value,
            showAddSubscriptionEditor = false,
        )
        return listOf(
            MainControllerEffect.SaveProfileSource(
                value = value,
                mode = mode,
                statusMessage = decision.getOrThrow(),
            ),
        )
    }

    fun clearProfileSource() {
        _state.value = _state.value.copy(profileDraft = "")
    }

    fun deleteProfileHistoryEntry(source: String): List<MainControllerEffect> {
        val trimmed = source.trim()
        if (trimmed.isBlank()) return emptyList()
        if (_state.value.profileHistoryRenameSource == trimmed) {
            closeProfileHistoryRenameDialog()
        }
        return listOf(
            MainControllerEffect.DeleteProfileHistoryEntry(
                source = trimmed,
                statusMessage = StatusMessages.historyEntryDeleted(),
            ),
        )
    }

    fun saveProfileHistoryRename(): List<MainControllerEffect> {
        val source = _state.value.profileHistoryRenameSource.trim()
        if (source.isBlank()) {
            closeProfileHistoryRenameDialog()
            return emptyList()
        }
        val normalizedName = _state.value.profileHistoryRenameDraft.trim()
        closeProfileHistoryRenameDialog()
        return listOf(
            MainControllerEffect.SaveProfileHistoryRename(
                source = source,
                normalizedName = normalizedName,
                statusMessage = if (normalizedName.isBlank()) {
                    "Subscription name reset"
                } else {
                    "Subscription name saved"
                },
            ),
        )
    }

    fun saveSubscriptionRefreshPolicy(): List<MainControllerEffect> {
        val resolution = MainCommandLogic.resolveSubscriptionRefreshPolicySave(_state.value)
        if (resolution.isFailure) {
            return listOf(
                MainControllerEffect.UpdateStatus(
                    resolution.exceptionOrNull()?.message ?: "Failed to save refresh settings",
                ),
            )
        }
        val saved = resolution.getOrThrow()
        _state.value = _state.value.copy(showRefreshPolicyDialog = false)
        return listOf(
            MainControllerEffect.SaveSubscriptionRefreshPolicy(
                policy = saved.policy,
                customHours = saved.resolvedHours,
                findBestAfterRefresh = saved.findBestAfterRefresh,
                statusMessage = saved.statusMessage,
            ),
        )
    }

    fun saveValidationSettings(): List<MainControllerEffect> {
        val plan = MainDraftLogic.resolveValidationSettingsSave(_state.value)
        _state.value = _state.value.copy(showValidationSettingsDialog = false)
        return listOf(
            MainControllerEffect.SaveValidationSettings(
                settings = plan.settings,
                statusMessage = plan.statusMessage,
            ),
        )
    }

    fun saveDns(): List<MainControllerEffect> {
        val plan = MainDraftLogic.resolveDnsSave(_state.value)
        _state.value = _state.value.copy(showDnsDialog = false)
        return listOf(
            MainControllerEffect.SaveDns(
                dns = plan.dns,
                enabled = plan.enabled,
                statusMessage = plan.statusMessage,
            ),
        )
    }

    fun saveRuleSet(): List<MainControllerEffect> {
        val draft = MainDraftLogic.buildRuleSetDraft(_state.value)
        if (draft.isFailure) {
            return listOf(
                MainControllerEffect.UpdateStatus(
                    draft.exceptionOrNull()?.message ?: "Invalid rule-set",
                ),
            )
        }
        val saved = draft.getOrThrow()
        val wasEditing = _state.value.editingRuleSetId.isNotBlank()
        val existingId = _state.value.editingRuleSetId.takeIf { it.isNotBlank() } ?: saved.id
        val updated = _state.value.routingRuleSetsDraft
            .filterNot { it.id == existingId }
            .plus(saved.copy(id = existingId))
            .sortedBy { it.name.lowercase() }
        _state.value = _state.value.copy(routingRuleSetsDraft = updated)
        closeRuleSetDialog()
        return listOf(
            MainControllerEffect.UpdateStatus(
                if (wasEditing) "Rule-set updated" else "Rule-set added",
            ),
        )
    }

    fun applyImportedRoutingRules(rules: RoutingRules) {
        _state.value = MainDraftLogic.applyImportedRoutingRules(_state.value, rules)
    }

    fun useProfileHistoryEntry(subscriptionId: String): List<MainControllerEffect> {
        val normalized = subscriptionId.trim()
        val selectedUrl = _state.value.subscriptions
            .firstOrNull { it.id == normalized }
            ?.url
            .orEmpty()
        _state.value = _state.value.copy(
            profileDraft = if (normalized == com.kardinal.vpncontrol.model.ALL_SUBSCRIPTIONS_ID) "" else selectedUrl,
            profileSourceMode = ProfileSourceMode.SUBSCRIPTION,
            showAddSubscriptionEditor = false,
        )
        return listOf(
            MainControllerEffect.SelectActiveSubscription(normalized),
            MainControllerEffect.UpdateStatus(
                if (normalized == com.kardinal.vpncontrol.model.ALL_SUBSCRIPTIONS_ID) {
                    "All subscriptions selected"
                } else {
                    "Subscription selected"
                },
            ),
        )
    }
}
