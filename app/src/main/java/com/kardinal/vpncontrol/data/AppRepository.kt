package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.model.PersistedState
import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.BenchmarkValidationSettings
import com.kardinal.vpncontrol.model.LatencyHistoryEntry
import com.kardinal.vpncontrol.model.ProfileSourceMode
import com.kardinal.vpncontrol.model.ProfileSelection
import com.kardinal.vpncontrol.model.RoutingRules
import com.kardinal.vpncontrol.model.SubscriptionSource
import com.kardinal.vpncontrol.model.SubscriptionRefreshPolicy
import com.kardinal.vpncontrol.model.activeSubscriptionUrls
import com.kardinal.vpncontrol.model.isAllSubscriptionsGroupActive
import com.kardinal.vpncontrol.model.sourceUrlForStoredLocation
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first

class AppRepository(
    private val storage: ProfileStorage,
    private val orchestrator: BenchmarkOrchestrator,
    private val subscriptionRefreshScheduler: SubscriptionRefreshScheduler,
) {
    data class SubscriptionRefreshFailure(
        val subscriptionId: String,
        val sourceUrl: String,
        val displayName: String,
        val message: String,
    )

    data class SubscriptionRefreshBatchResult(
        val refreshedCount: Int,
        val failedSubscriptions: List<SubscriptionRefreshFailure> = emptyList(),
    ) {
        val failedCount: Int get() = failedSubscriptions.size
        val hasFailures: Boolean get() = failedSubscriptions.isNotEmpty()
    }

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

    suspend fun refreshActiveSubscriptionCache(): Result<SubscriptionRefreshBatchResult> = runCatching {
        val state = storage.snapshot()
        if (isAllSubscriptionsGroupActive(state.activeSubscriptionId, state.subscriptions)) {
            val refreshed = refreshAllSubscriptionsCaches().getOrThrow()
            require(refreshed.refreshedCount > 0) { "No subscriptions were refreshed" }
            return@runCatching refreshed
        }
        val subscriptionId = state.activeSubscriptionId
        val sourceUrl = state.profileUrl
        require(subscriptionId.isNotBlank() && sourceUrl.isNotBlank()) { "No active subscription selected" }
        val profiles = orchestrator.fetchSubscriptionLocations(sourceUrl).getOrThrow()
        require(profiles.isNotEmpty()) { "No locations were found in the subscription" }
        storage.updateSubscriptionCache(
            subscriptionId = subscriptionId,
            rawLinks = profiles.map { it.rawLink },
        )
        SubscriptionRefreshBatchResult(refreshedCount = 1)
    }
        .also { result ->
            if (result.isFailure) {
                val activeId = storage.snapshot().activeSubscriptionId
                if (activeId.isNotBlank()) {
                    storage.updateSubscriptionRefreshStatus(
                        subscriptionId = activeId,
                        status = result.exceptionOrNull()?.message ?: "Refresh failed",
                    )
                }
            }
        }

    suspend fun refreshAllSubscriptionsCaches(): Result<SubscriptionRefreshBatchResult> = runCatching {
        val state = storage.snapshot()
        var refreshed = 0
        var lastFailure: Throwable? = null
        val failures = mutableListOf<SubscriptionRefreshFailure>()
        state.subscriptions.forEach { subscription ->
            val result = refreshSingleSubscription(subscription)
            if (result.isSuccess) {
                refreshed += 1
            } else {
                lastFailure = result.exceptionOrNull()
                failures += SubscriptionRefreshFailure(
                    subscriptionId = subscription.id,
                    sourceUrl = subscription.url,
                    displayName = subscriptionDisplayLabel(subscription),
                    message = result.exceptionOrNull()?.message ?: "Refresh failed",
                )
            }
        }
        if (refreshed == 0 && lastFailure != null) {
            throw lastFailure!!
        }
        SubscriptionRefreshBatchResult(
            refreshedCount = refreshed,
            failedSubscriptions = failures,
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
                storage.lastProfileFile().exists()
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
        val selectedStored = LocationConfigs.selectedStoredReference(
            selectedProfileJson = state.selectedProfileJson,
            selectedProfileRawLink = state.selectedProfileRawLink,
        )
        val hasStoredSelection =
            state.selectedProfileJson.isNotBlank() ||
                state.selectedProfileRawLink.isNotBlank() ||
                storage.lastProfileFile().exists()
        val selectedAllowed = when (state.profileSourceMode) {
            ProfileSourceMode.SUBSCRIPTION -> {
                val activeUrls = activeSubscriptionUrls(state.activeSubscriptionId, state.subscriptions)
                state.selectedProfileSourceUrl.isNotBlank() &&
                    state.selectedProfileSourceUrl in activeUrls &&
                    (selectedStored.isBlank() || state.currentLocations.isEmpty() || selectedStored in state.currentLocations)
            }
            ProfileSourceMode.CURRENT_LOCATIONS -> {
                when {
                    state.selectedProfileJson.isNotBlank() -> state.selectedProfileJson in state.currentLocations
                    state.selectedProfileRawLink.isNotBlank() ->
                        selectedStored in state.currentLocations
                    else -> true
                }
            }
        }
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

    private suspend fun refreshSingleSubscription(subscription: SubscriptionSource): Result<Unit> = runCatching {
        val profiles = orchestrator.fetchSubscriptionLocations(subscription.url).getOrThrow()
        require(profiles.isNotEmpty()) { "No locations were found in the subscription" }
        storage.updateSubscriptionCache(
            subscriptionId = subscription.id,
            rawLinks = profiles.map { it.rawLink },
        )
    }
        .map { }
        .also { result ->
            if (result.isFailure) {
                storage.updateSubscriptionRefreshStatus(
                    subscriptionId = subscription.id,
                    status = result.exceptionOrNull()?.message ?: "Refresh failed",
                )
            }
        }

    private suspend fun syncSelection(selection: ProfileSelection, sourceUrlOverride: String? = null) {
        val state = storage.snapshot()
        val storedSelection = LocationConfigs.encodeStoredLocation(selection.profile)
        val resolvedSourceUrl = sourceUrlOverride ?: selection.sourceUrl.ifBlank {
            if (state.profileSourceMode == ProfileSourceMode.SUBSCRIPTION) {
                sourceUrlForStoredLocation(state.subscriptions, storedSelection)
                    .ifBlank { state.profileUrl }
            } else {
                ""
            }
        }
        storage.updateSelection(
            profile = selection.profile,
            summary = selectionSummary(
                state = state,
                detail = selection.benchmark.detail,
                sourceUrl = resolvedSourceUrl,
            ),
            runtimeConfigJson = selection.runtimeConfigJson,
            sourceUrl = resolvedSourceUrl,
        )
    }

    private fun selectionSummary(
        state: PersistedState,
        detail: String,
        sourceUrl: String,
    ): String {
        val normalizedSourceUrl = sourceUrl.trim()
        if (state.profileSourceMode != ProfileSourceMode.SUBSCRIPTION || normalizedSourceUrl.isBlank()) {
            return detail
        }
        val shouldShowSource =
            isAllSubscriptionsGroupActive(state.activeSubscriptionId, state.subscriptions) ||
                (state.profileUrl.isNotBlank() && normalizedSourceUrl != state.profileUrl)
        if (!shouldShowSource) {
            return detail
        }
        val sourceLabel = subscriptionDisplayLabel(state.subscriptions, normalizedSourceUrl) ?: return detail
        return "$detail • Best from: $sourceLabel"
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

    private fun shouldClearSelectionForSourceState(state: PersistedState): Boolean {
        if (state.selectedProfileName.isBlank()) return false
        return when (state.profileSourceMode) {
            ProfileSourceMode.SUBSCRIPTION -> {
                val activeUrls = activeSubscriptionUrls(state.activeSubscriptionId, state.subscriptions)
                if (isAllSubscriptionsGroupActive(state.activeSubscriptionId, state.subscriptions)) {
                    val selectedStored = LocationConfigs.selectedStoredReference(
                        selectedProfileJson = state.selectedProfileJson,
                        selectedProfileRawLink = state.selectedProfileRawLink,
                    )
                    selectedStored.isNotBlank() && selectedStored !in state.currentLocations
                } else {
                    state.selectedProfileSourceUrl.isBlank() ||
                        state.selectedProfileSourceUrl !in activeUrls
                }
            }
            ProfileSourceMode.CURRENT_LOCATIONS -> {
                val selectedStored = LocationConfigs.selectedStoredReference(
                    selectedProfileJson = state.selectedProfileJson,
                    selectedProfileRawLink = state.selectedProfileRawLink,
                )
                selectedStored.isNotBlank() && selectedStored !in state.currentLocations
            }
        }
    }

    private suspend fun snapshotAfterSourceChange(): PersistedState {
        val state = storage.snapshot()
        return if (!state.isVpnRunning && shouldClearSelectionForSourceState(state)) {
            storage.clearSelection()
            storage.snapshot()
        } else {
            state
        }
    }
}
