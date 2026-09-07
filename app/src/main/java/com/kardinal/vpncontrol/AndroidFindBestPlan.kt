package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.data.ProfileSelectionAttemptPlan
import com.kardinal.vpncontrol.model.PersistedState
import com.kardinal.vpncontrol.model.ProfileSelection
import com.kardinal.vpncontrol.model.SubscriptionSource
import com.kardinal.vpncontrol.data.LocationConfigs

/** Private staged data, published only in the winner's guarded storage transaction. */
internal data class AndroidFindBestPlan(val candidates: ProfileSelectionAttemptPlan,
    val caches: Map<String, List<String>> = emptyMap()) {
    /** All durable selection effects must match before recovering a lost commit response. */
    fun matchesCommittedSelection(state: PersistedState, selection: ProfileSelection): Boolean =
        state.selectedProfileName == selection.profile.remarks &&
            state.selectedProfileServer == selection.profile.server &&
            state.selectedProfileRawLink == selection.profile.rawLink &&
            state.selectedProfileJson == LocationConfigs.encodeStoredLocation(selection.profile) &&
            state.runtimeConfigJson == selection.runtimeConfigJson &&
            state.selectedProfileSourceUrl == selection.sourceUrl &&
            state.managementProxyPort == (selection.managementProxyPort?.takeIf { it in 1..65535 } ?: 0) &&
            state.lastBenchmarkSummary == selection.benchmark.detail &&
            state.locationBenchmarkDetails == candidates.locationBenchmarkDetails &&
            caches.all { (id, rows) -> state.subscriptions.any {
                it.id == id && it.cachedLocations == rows && it.lastRefreshStatus == "OK"
            } }

    fun subscriptions(state: PersistedState): List<SubscriptionSource> {
        check(caches.keys.all { id -> state.subscriptions.any { it.id == id } }) { "CONFLICT" }
        return state.subscriptions.map { source ->
            caches[source.id]?.let { source.copy(cachedLocations = it.toList(),
                lastRefreshedAtEpochMillis = System.currentTimeMillis(), lastRefreshStatus = "OK") } ?: source
        }
    }
}
