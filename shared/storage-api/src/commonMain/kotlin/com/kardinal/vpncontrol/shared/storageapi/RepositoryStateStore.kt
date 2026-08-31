package com.kardinal.vpncontrol.shared.storageapi

import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.AppLanguage
import com.kardinal.vpncontrol.model.BenchmarkValidationSettings
import com.kardinal.vpncontrol.model.DnsSettings
import com.kardinal.vpncontrol.model.LatencyHistoryEntry
import com.kardinal.vpncontrol.model.HomeSshRouteSettings
import com.kardinal.vpncontrol.model.PersistedState
import com.kardinal.vpncontrol.model.ProfileSourceMode
import com.kardinal.vpncontrol.model.RoutingRules
import com.kardinal.vpncontrol.model.SubscriptionRefreshPolicy
import com.kardinal.vpncontrol.model.ProxyProfile

interface RepositoryStateStore : SearchStateStore, RuntimeConfigStore {
    suspend fun updateProfileUrl(url: String, rememberInHistory: Boolean = false, name: String = "")

    suspend fun deleteProfileHistoryEntry(url: String)

    suspend fun updateProfileHistoryName(url: String, name: String)

    suspend fun updateSubscriptionSource(source: String, newSource: String, name: String)

    suspend fun updateProfileSourceMode(mode: ProfileSourceMode)

    suspend fun selectActiveSubscription(subscriptionId: String)

    suspend fun updateAppMode(mode: AppMode)

    suspend fun updateAppLanguage(language: AppLanguage)

    suspend fun updateSubscriptionRefreshPolicy(
        policy: SubscriptionRefreshPolicy,
        customHours: Double,
        findBestAfterRefresh: Boolean,
    )

    suspend fun updateValidationSettings(settings: BenchmarkValidationSettings)

    suspend fun updateDns(settings: DnsSettings)

    suspend fun updateHomeSshRouteSettings(settings: HomeSshRouteSettings)

    suspend fun updateRoutingRules(rules: RoutingRules)

    suspend fun updateSelection(
        profile: ProxyProfile,
        summary: String,
        runtimeConfigJson: String,
        sourceUrl: String = "",
        managementProxyPort: Int = 0,
    )

    suspend fun updateSessionStatsEnabled(enabled: Boolean)

    suspend fun updateLiveTrafficStatsEnabled(enabled: Boolean)

    suspend fun updateProfileTotalsEnabled(enabled: Boolean)

    suspend fun updateLatencyHistoryEnabled(enabled: Boolean)

    suspend fun updateConnectionLogEnabled(enabled: Boolean)

    suspend fun updateConnectionTestToolsEnabled(enabled: Boolean)

    suspend fun appendLatencyHistory(entry: LatencyHistoryEntry)

    suspend fun clearSelection()

    suspend fun restoreSelection(
        state: PersistedState,
        restoreRuntimeArtifacts: Boolean = true,
        sourceUrlOverride: String? = null,
    )

    suspend fun updateSubscriptionRefreshStatus(
        subscriptionId: String,
        status: String,
    )
}
