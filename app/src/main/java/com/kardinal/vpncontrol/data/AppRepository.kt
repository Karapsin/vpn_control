package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.model.PersistedState
import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.BenchmarkValidationSettings
import com.kardinal.vpncontrol.model.ProfileSourceMode
import com.kardinal.vpncontrol.model.ProfileSelection
import com.kardinal.vpncontrol.model.RoutingRules
import com.kardinal.vpncontrol.model.SubscriptionSource
import com.kardinal.vpncontrol.model.SubscriptionRefreshPolicy
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first

class AppRepository(
    private val storage: ProfileStorage,
    private val orchestrator: BenchmarkOrchestrator,
    private val subscriptionRefreshScheduler: SubscriptionRefreshScheduler,
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

    suspend fun updateSubscriptionRefreshPolicy(policy: SubscriptionRefreshPolicy, customHours: Int) {
        storage.updateSubscriptionRefreshPolicy(policy, customHours)
        subscriptionRefreshScheduler.sync(storage.snapshot())
    }

    suspend fun updateValidationSettings(settings: BenchmarkValidationSettings) {
        storage.updateValidationSettings(settings)
    }

    suspend fun updateSessionStatsEnabled(enabled: Boolean) {
        storage.updateSessionStatsEnabled(enabled)
    }

    suspend fun syncSubscriptionRefreshScheduling() {
        subscriptionRefreshScheduler.sync(storage.snapshot())
    }

    suspend fun refreshActiveSubscriptionCache(): Result<Unit> = runCatching {
        val state = storage.snapshot()
        val subscriptionId = state.activeSubscriptionId
        val sourceUrl = state.profileUrl
        require(subscriptionId.isNotBlank() && sourceUrl.isNotBlank()) { "No active subscription selected" }
        val profiles = orchestrator.fetchSubscriptionLocations(sourceUrl).getOrThrow()
        require(profiles.isNotEmpty()) { "No locations were found in the subscription" }
        storage.updateSubscriptionCache(
            subscriptionId = subscriptionId,
            rawLinks = profiles.map { it.rawLink },
        )
    }
        .map { }
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

    suspend fun refreshAllSubscriptionsCaches(): Result<Int> = runCatching {
        val state = storage.snapshot()
        var refreshed = 0
        var lastFailure: Throwable? = null
        state.subscriptions.forEach { subscription ->
            val result = refreshSingleSubscription(subscription)
            if (result.isSuccess) {
                refreshed += 1
            } else {
                lastFailure = result.exceptionOrNull()
            }
        }
        if (refreshed == 0 && lastFailure != null) {
            throw lastFailure!!
        }
        refreshed
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
            ProfileSourceMode.SUBSCRIPTION ->
                state.selectedProfileSourceUrl.isNotBlank() &&
                    state.selectedProfileSourceUrl == state.profileUrl &&
                    (selectedStored.isBlank() || state.currentLocations.isEmpty() || selectedStored in state.currentLocations)
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
        storage.updateSelection(
            profile = selection.profile,
            summary = selection.benchmark.detail,
            runtimeConfigJson = selection.runtimeConfigJson,
            sourceUrl = sourceUrlOverride ?: if (state.profileSourceMode == ProfileSourceMode.SUBSCRIPTION) {
                state.profileUrl
            } else {
                ""
            },
        )
    }

    private fun shouldClearSelectionForSourceState(state: PersistedState): Boolean {
        if (state.selectedProfileName.isBlank()) return false
        return when (state.profileSourceMode) {
            ProfileSourceMode.SUBSCRIPTION ->
                state.selectedProfileSourceUrl.isBlank() ||
                    state.selectedProfileSourceUrl != state.profileUrl
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
