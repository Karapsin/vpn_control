package com.kardinal.vpncontrol.control

import com.kardinal.vpncontrol.model.PersistedState

/** Committed product configuration only; runtime, refresh timestamps and measurements are not edits. */
data class ControlConfigurationIdentity private constructor(private val configuration: PersistedState) {
    override fun toString(): String = "ControlConfigurationIdentity(<redacted>)"

    companion object {
        fun of(state: PersistedState): ControlConfigurationIdentity = ControlConfigurationIdentity(PersistedState(
            appLanguage = state.appLanguage,
            profileUrl = state.profileUrl,
            activeSubscriptionId = state.activeSubscriptionId,
            subscriptions = state.subscriptions.map { it.copy(lastRefreshedAtEpochMillis = 0, lastRefreshStatus = "") },
            profileHistory = state.profileHistory,
            profileHistoryNames = state.profileHistoryNames,
            profileSourceMode = state.profileSourceMode,
            appMode = state.appMode,
            subscriptionRefreshPolicy = state.subscriptionRefreshPolicy,
            findBestAfterSubscriptionRefresh = state.findBestAfterSubscriptionRefresh,
            subscriptionRefreshCustomHours = state.subscriptionRefreshCustomHours,
            validationSettings = state.validationSettings,
            savedLocations = state.savedLocations,
            currentLocations = state.currentLocations,
            dnsSettings = state.dnsSettings,
            homeSshRouteSettings = state.homeSshRouteSettings,
            routingRules = state.routingRules,
            selectedProfileName = state.selectedProfileName,
            selectedProfileServer = state.selectedProfileServer,
            selectedProfileRawLink = state.selectedProfileRawLink,
            selectedProfileJson = state.selectedProfileJson,
            selectedProfileSourceUrl = state.selectedProfileSourceUrl,
        ))
    }
}
