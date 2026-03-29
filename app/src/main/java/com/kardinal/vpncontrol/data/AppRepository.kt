package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.model.PersistedState
import com.kardinal.vpncontrol.model.BenchmarkValidationSettings
import com.kardinal.vpncontrol.model.ProfileSourceMode
import com.kardinal.vpncontrol.model.ProfileSelection
import com.kardinal.vpncontrol.model.RoutingRules
import com.kardinal.vpncontrol.model.SubscriptionRefreshPolicy
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first

class AppRepository(
    private val storage: ProfileStorage,
    private val orchestrator: BenchmarkOrchestrator,
    private val subscriptionRefreshScheduler: SubscriptionRefreshScheduler,
) {
    val state: Flow<PersistedState> = storage.state

    suspend fun updateProfileSource(url: String, mode: ProfileSourceMode) {
        storage.updateProfileUrl(
            url = url,
            rememberInHistory = mode == ProfileSourceMode.SUBSCRIPTION && url.isNotBlank(),
        )
        storage.updateProfileSourceMode(mode)
        subscriptionRefreshScheduler.sync(storage.snapshot())
    }

    suspend fun updateProfileUrl(url: String) {
        storage.updateProfileUrl(url)
        subscriptionRefreshScheduler.sync(storage.snapshot())
    }

    suspend fun deleteProfileHistoryEntry(url: String) {
        storage.deleteProfileHistoryEntry(url)
    }

    suspend fun updateProfileHistoryName(url: String, name: String) {
        storage.updateProfileHistoryName(url, name)
    }

    suspend fun updateProfileSourceMode(mode: ProfileSourceMode) {
        storage.updateProfileSourceMode(mode)
        subscriptionRefreshScheduler.sync(storage.snapshot())
    }

    suspend fun updateSubscriptionRefreshPolicy(policy: SubscriptionRefreshPolicy, customHours: Int) {
        storage.updateSubscriptionRefreshPolicy(policy, customHours)
        subscriptionRefreshScheduler.sync(storage.snapshot())
    }

    suspend fun updateValidationSettings(settings: BenchmarkValidationSettings) {
        storage.updateValidationSettings(settings)
    }

    suspend fun syncSubscriptionRefreshScheduling() {
        subscriptionRefreshScheduler.sync(storage.snapshot())
    }

    suspend fun updateCurrentLocations(rawLinks: List<String>) = storage.updateCurrentLocations(rawLinks)

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

        syncSelection(orchestrator.rehydrateSelection(state).getOrThrow())
    }

    suspend fun updateStatus(message: String) = storage.updateStatus(message)

    suspend fun ensureSelection(): Result<ProfileSelection> {
        val state = storage.state.first()
        val hasStoredSelection =
            state.selectedProfileJson.isNotBlank() ||
                state.selectedProfileRawLink.isNotBlank() ||
                storage.lastProfileFile().exists()
        val selectedAllowed = when (state.profileSourceMode) {
            ProfileSourceMode.SUBSCRIPTION -> true
            ProfileSourceMode.CURRENT_LOCATIONS -> {
                when {
                    state.selectedProfileJson.isNotBlank() -> state.selectedProfileJson in state.currentLocations
                    state.selectedProfileRawLink.isNotBlank() -> state.selectedProfileRawLink in state.currentLocations
                    else -> true
                }
            }
        }
        if (hasStoredSelection && state.selectedProfileName.isNotBlank() && selectedAllowed) {
            return orchestrator.rehydrateSelection(state)
        }
        return refreshBestProfile()
    }

    suspend fun syncSelectedLocation(rawLink: String, detail: String): Result<ProfileSelection> = runCatching {
        val state = storage.snapshot()
        val selection = orchestrator.selectionFromRawLink(
            state = state,
            rawLink = rawLink,
            detail = detail,
        ).getOrThrow()
        syncSelection(selection)
        selection
    }

    suspend fun benchmarkLocation(rawLink: String) = orchestrator.benchmarkLocation(rawLink)

    suspend fun refreshBestProfile(): Result<ProfileSelection> {
        val result = orchestrator.refreshBestProfile()
        if (result.isSuccess) {
            syncSelection(result.getOrThrow())
        }
        return result
    }

    private suspend fun syncSelection(selection: ProfileSelection) {
        storage.updateSelection(
            profile = selection.profile,
            summary = selection.benchmark.detail,
            runtimeConfigJson = selection.runtimeConfigJson,
        )
        storage.runtimeConfigFile().apply {
            parentFile?.mkdirs()
            writeText(selection.runtimeConfigJson)
        }
        if (selection.profile.rawLink.isNotBlank()) {
            storage.lastProfileFile().writeText(selection.profile.rawLink)
        }
    }
}
