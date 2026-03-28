package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.model.PersistedState
import com.kardinal.vpncontrol.model.ProfileSelection
import com.kardinal.vpncontrol.model.RoutingRules
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first

class AppRepository(
    private val storage: ProfileStorage,
    private val orchestrator: BenchmarkOrchestrator,
) {
    val state: Flow<PersistedState> = storage.state

    suspend fun updateProfileUrl(url: String) = storage.updateProfileUrl(url)

    suspend fun updateCustomDns(dns: String, enabled: Boolean) = storage.updateDns(dns, enabled)

    suspend fun updateRoutingRules(rules: RoutingRules): Result<Unit> = runCatching {
        storage.updateRoutingRules(rules)

        val state = storage.snapshot()
        val hasRawSelection = state.selectedProfileRawLink.isNotBlank() || storage.lastProfileFile().exists()
        if (!hasRawSelection || state.selectedProfileName.isBlank()) {
            return@runCatching
        }

        orchestrator.rehydrateSelection(state).getOrThrow().also { selection ->
            storage.updateSelection(
                name = selection.profile.remarks,
                server = selection.profile.server,
                rawLink = selection.profile.rawLink,
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

    suspend fun updateStatus(message: String) = storage.updateStatus(message)

    suspend fun ensureSelection(): Result<ProfileSelection> {
        val state = storage.state.first()
        val hasRawSelection = state.selectedProfileRawLink.isNotBlank() || storage.lastProfileFile().exists()
        if (hasRawSelection && state.selectedProfileName.isNotBlank()) {
            return orchestrator.rehydrateSelection(state)
        }
        return refreshBestProfile()
    }

    suspend fun refreshBestProfile(): Result<ProfileSelection> {
        return orchestrator.refreshBestProfile().onSuccess { selection ->
            storage.updateSelection(
                name = selection.profile.remarks,
                server = selection.profile.server,
                rawLink = selection.profile.rawLink,
                summary = selection.benchmark.detail,
                runtimeConfigJson = selection.runtimeConfigJson,
            )
            storage.lastProfileFile().writeText(selection.profile.rawLink)
        }
    }
}
