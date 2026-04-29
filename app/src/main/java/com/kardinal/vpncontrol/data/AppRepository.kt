package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.model.PersistedState
import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.AppLanguage
import com.kardinal.vpncontrol.model.BenchmarkValidationSettings
import com.kardinal.vpncontrol.model.LatencyHistoryEntry
import com.kardinal.vpncontrol.model.ProfileSourceMode
import com.kardinal.vpncontrol.model.ProfileSelection
import com.kardinal.vpncontrol.model.RoutingRules
import com.kardinal.vpncontrol.model.SubscriptionSource
import com.kardinal.vpncontrol.model.SubscriptionRefreshPolicy
import com.kardinal.vpncontrol.model.sourceUrlForStoredLocation
import com.kardinal.vpncontrol.shared.storageapi.RefreshScheduler
import com.kardinal.vpncontrol.shared.storageapi.RepositoryStateStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first

class AppRepository(
    private val storage: RepositoryStateStore,
    private val orchestrator: BenchmarkOrchestrator,
    private val subscriptionRefreshScheduler: RefreshScheduler,
) {
    val state: Flow<PersistedState> = storage.state

    suspend fun snapshot(): PersistedState = storage.snapshot()

    suspend fun updateProfileSource(url: String, mode: ProfileSourceMode) {
        storage.updateProfileUrl(
            url = url,
            rememberInHistory = mode == ProfileSourceMode.SUBSCRIPTION && url.isNotBlank(),
        )
        storage.updateProfileSourceMode(mode)
        subscriptionRefreshScheduler.sync(snapshotAfterSourceChange())
    }

    suspend fun selectActiveSubscription(subscriptionId: String) {
        storage.selectActiveSubscription(subscriptionId)
        subscriptionRefreshScheduler.sync(snapshotAfterSourceChange())
    }

    suspend fun deleteProfileHistoryEntry(url: String) {
        storage.deleteProfileHistoryEntry(url)
        subscriptionRefreshScheduler.sync(snapshotAfterSourceChange())
    }

    suspend fun updateProfileHistoryName(url: String, name: String) {
        storage.updateProfileHistoryName(url, name)
    }

    suspend fun updateProfileSourceMode(mode: ProfileSourceMode) {
        storage.updateProfileSourceMode(mode)
        subscriptionRefreshScheduler.sync(snapshotAfterSourceChange())
    }

    suspend fun updateAppMode(mode: AppMode) {
        storage.updateAppMode(mode)
    }

    suspend fun updateAppLanguage(language: AppLanguage) {
        storage.updateAppLanguage(language)
    }

    suspend fun updateSubscriptionRefreshPolicy(
        policy: SubscriptionRefreshPolicy,
        customHours: Double,
        findBestAfterRefresh: Boolean,
    ) {
        storage.updateSubscriptionRefreshPolicy(policy, customHours, findBestAfterRefresh)
        subscriptionRefreshScheduler.sync(storage.snapshot())
    }

    suspend fun updateValidationSettings(settings: BenchmarkValidationSettings) {
        storage.updateValidationSettings(settings)
    }

    suspend fun updateSessionStatsEnabled(enabled: Boolean) {
        storage.updateSessionStatsEnabled(enabled)
    }

    suspend fun updateLiveTrafficStatsEnabled(enabled: Boolean) {
        storage.updateLiveTrafficStatsEnabled(enabled)
    }

    suspend fun updateProfileTotalsEnabled(enabled: Boolean) {
        storage.updateProfileTotalsEnabled(enabled)
    }

    suspend fun updateLatencyHistoryEnabled(enabled: Boolean) {
        storage.updateLatencyHistoryEnabled(enabled)
    }

    suspend fun updateConnectionLogEnabled(enabled: Boolean) {
        storage.updateConnectionLogEnabled(enabled)
    }

    suspend fun updateConnectionTestToolsEnabled(enabled: Boolean) {
        storage.updateConnectionTestToolsEnabled(enabled)
    }

    suspend fun appendLatencyHistory(entry: LatencyHistoryEntry) {
        storage.appendLatencyHistory(entry)
    }

    suspend fun syncSubscriptionRefreshScheduling() {
        subscriptionRefreshScheduler.sync(storage.snapshot())
    }

    suspend fun refreshActiveSubscriptionCache(): Result<SubscriptionRefreshBatchResult> {
        val state = storage.snapshot()
        return RepositoryWorkflowService.refreshActiveSubscriptionCache(
            state = state,
            refreshAllSubscriptions = ::refreshAllSubscriptionsCaches,
            fetchSubscriptionLocations = { sourceUrl ->
                orchestrator.fetchSubscriptionLocations(sourceUrl).getOrThrow()
            },
            updateSubscriptionCache = { subscriptionId, rawLinks ->
                storage.updateSubscriptionCache(
                    subscriptionId = subscriptionId,
                    rawLinks = rawLinks,
                )
            },
            updateRefreshStatus = { subscriptionId, status ->
                storage.updateSubscriptionRefreshStatus(subscriptionId, status)
            },
        )
    }

    suspend fun refreshAllSubscriptionsCaches(): Result<SubscriptionRefreshBatchResult> {
        val state = storage.snapshot()
        return RepositoryWorkflowService.refreshAllSubscriptionsCaches(
            state = state,
            fetchSubscriptionLocations = { sourceUrl ->
                orchestrator.fetchSubscriptionLocations(sourceUrl).getOrThrow()
            },
            updateSubscriptionCache = { subscriptionId, rawLinks ->
                storage.updateSubscriptionCache(
                    subscriptionId = subscriptionId,
                    rawLinks = rawLinks,
                )
            },
            updateRefreshStatus = { subscriptionId, status ->
                storage.updateSubscriptionRefreshStatus(subscriptionId, status)
            },
            displayLabel = ::subscriptionDisplayLabel,
        )
    }

    suspend fun updateCurrentLocations(rawLinks: List<String>) = storage.updateCurrentLocations(rawLinks)

    suspend fun restoreSnapshot(state: PersistedState, restoreRuntimeArtifacts: Boolean = true) {
        storage.updateCurrentLocations(state.currentLocations)
        storage.updateLocationBenchmarkDetails(state.locationBenchmarkDetails)
        storage.restoreSelection(state, restoreRuntimeArtifacts = restoreRuntimeArtifacts)
    }

    suspend fun updateCustomDns(dns: String, enabled: Boolean) = storage.updateDns(dns, enabled)

    suspend fun updateRoutingRules(rules: RoutingRules): Result<Unit> = runCatching {
        storage.updateRoutingRules(rules)

        val state = storage.snapshot()
        val hasStoredSelection =
            state.selectedProfileJson.isNotBlank() ||
                state.selectedProfileRawLink.isNotBlank() ||
                storage.readLastSelectedProfile() != null
        if (!hasStoredSelection || state.selectedProfileName.isBlank()) {
            return@runCatching
        }

        syncSelection(
            selection = orchestrator.rehydrateSelection(state).getOrThrow(),
            sourceUrlOverride = state.selectedProfileSourceUrl,
        )
    }

    suspend fun updateStatus(message: String) = storage.updateStatus(message)

    suspend fun ensureSelection(): Result<ProfileSelection> {
        val state = storage.state.first()
        val hasStoredSelection = RepositoryWorkflowService.hasStoredSelection(
            state = state,
            hasLastSelectedProfile = storage.readLastSelectedProfile() != null,
        )
        val selectedAllowed = RepositoryWorkflowService.isStoredSelectionAllowed(state)
        if (hasStoredSelection && state.selectedProfileName.isNotBlank() && selectedAllowed) {
            return orchestrator.rehydrateSelection(state)
        }
        return refreshBestProfile()
    }

    suspend fun selectionFromRawLink(rawLink: String, detail: String): Result<ProfileSelection> = runCatching {
        val state = storage.snapshot()
        orchestrator.selectionFromRawLink(
            state = state,
            rawLink = rawLink,
            detail = detail,
        ).getOrThrow()
    }

    suspend fun benchmarkLocation(rawLink: String) = orchestrator.benchmarkLocation(rawLink)

    suspend fun refreshBestProfile(): Result<ProfileSelection> = orchestrator.refreshBestProfile()

    suspend fun rehydrateSelection(state: PersistedState): Result<ProfileSelection> =
        orchestrator.rehydrateSelection(state)

    suspend fun persistSelection(selection: ProfileSelection, sourceUrlOverride: String? = null) {
        syncSelection(selection, sourceUrlOverride)
    }

    private suspend fun syncSelection(selection: ProfileSelection, sourceUrlOverride: String? = null) {
        val state = storage.snapshot()
        val resolvedSourceUrl = RepositoryWorkflowService.resolveSelectionSourceUrl(
            state = state,
            selection = selection,
            sourceUrlOverride = sourceUrlOverride,
            sourceUrlForStoredLocation = { storedSelection ->
                sourceUrlForStoredLocation(state.subscriptions, storedSelection)
                    .ifBlank { state.profileUrl }
            },
        )
        storage.updateSelection(
            profile = selection.profile,
            summary = RepositoryWorkflowService.selectionSummary(
                state = state,
                detail = selection.benchmark.detail,
                sourceUrl = resolvedSourceUrl,
                sourceLabelForUrl = { sourceUrl ->
                    subscriptionDisplayLabel(state.subscriptions, sourceUrl)
                },
            ),
            runtimeConfigJson = selection.runtimeConfigJson,
            sourceUrl = resolvedSourceUrl,
        )
    }

    private fun subscriptionDisplayLabel(
        subscriptions: List<SubscriptionSource>,
        sourceUrl: String,
    ): String? {
        return subscriptions.firstOrNull { it.url == sourceUrl }?.let(::subscriptionDisplayLabel)
    }

    private fun subscriptionDisplayLabel(subscription: SubscriptionSource): String {
        return subscription.customName.ifBlank {
            RemoteSourceResolver.preview(subscription.url)?.title ?: "Remote source"
        }
    }

    private suspend fun snapshotAfterSourceChange(): PersistedState {
        val state = storage.snapshot()
        return if (!state.isVpnRunning && RepositoryWorkflowService.shouldClearSelectionForSourceState(state)) {
            storage.clearSelection()
            storage.snapshot()
        } else {
            state
        }
    }
}
