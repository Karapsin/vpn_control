package com.kardinal.vpncontrol.shared.ui

import com.kardinal.vpncontrol.AppScreen
import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.model.ALL_SUBSCRIPTIONS_ID
import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.ProfileSourceMode
import com.kardinal.vpncontrol.model.activeSubscriptionUrls
import com.kardinal.vpncontrol.model.isAllSubscriptionsGroupActive

fun selectedTabIndex(screen: AppScreen): Int {
    return when (screen) {
        AppScreen.MAIN -> 0
        AppScreen.PROFILE -> 1
        AppScreen.LOCATIONS -> 2
        AppScreen.STATS -> 3
        AppScreen.ROUTING_RULES -> 4
    }
}

fun activeProfileLabel(
    state: MainUiState,
    resolveSourceLabel: (String) -> String,
): String {
    return when (state.profileSourceMode) {
        ProfileSourceMode.SUBSCRIPTION -> {
            val selectedSource = state.selectedProfileSourceUrl.trim()
            val activeSource = when {
                state.selectedProfileName.isNotBlank() && selectedSource.isNotBlank() -> selectedSource
                state.selectedProfileName.isNotBlank() && selectedSource.isBlank() -> ""
                isAllSubscriptionsActive(state) -> ALL_SUBSCRIPTIONS_ID
                state.profileUrl.isNotBlank() -> state.profileUrl.trim()
                else -> ""
            }
            when {
                activeSource == ALL_SUBSCRIPTIONS_ID -> "All subscriptions"
                activeSource.isNotBlank() -> resolveSourceLabel(activeSource)
                state.selectedProfileName.isNotBlank() -> "Different subscription"
                else -> "none"
            }
        }
        ProfileSourceMode.CURRENT_LOCATIONS -> "Saved Locations"
    }
}

fun currentSubscriptionSelectionLabel(
    state: MainUiState,
    resolveSourceLabel: (String) -> String,
): String {
    return when (state.profileSourceMode) {
        ProfileSourceMode.CURRENT_LOCATIONS -> "Saved Locations"
        ProfileSourceMode.SUBSCRIPTION -> when {
            isAllSubscriptionsActive(state) -> "All subscriptions"
            state.activeSubscriptionId.isNotBlank() ->
                state.subscriptions
                    .firstOrNull { it.id == state.activeSubscriptionId }
                    ?.let { subscription -> resolveSourceLabel(subscription.url) }
                    ?: "none"
            else -> "none"
        }
    }
}

fun formatLocationCountLabel(
    count: Int,
    merged: Boolean = false,
): String {
    val noun = if (count == 1) "location" else "locations"
    return if (merged) {
        "$count merged $noun"
    } else {
        "$count $noun"
    }
}

fun selectedLocationOutsideCurrentSubscription(state: MainUiState): Boolean {
    if (state.profileSourceMode != ProfileSourceMode.SUBSCRIPTION || state.selectedProfileName.isBlank()) {
        return false
    }
    if (isAllSubscriptionsActive(state)) {
        return false
    }
    return state.selectedProfileSourceUrl.isNotBlank() &&
        state.selectedProfileSourceUrl !in activeSubscriptionUrls(
            activeSubscriptionId = state.activeSubscriptionId,
            subscriptions = state.subscriptions,
        )
}

fun formatLocationLabel(
    mode: ProfileSourceMode,
    name: String,
): String {
    val trimmed = name.trim()
    if (trimmed.isBlank()) return "none"
    return when (mode) {
        ProfileSourceMode.SUBSCRIPTION -> "Subscription: $trimmed"
        ProfileSourceMode.CURRENT_LOCATIONS -> "Saved location: $trimmed"
    }
}

fun routingSummary(state: MainUiState): String {
    if (state.routingRules.ignoreRules) {
        return if (state.appMode == AppMode.VPN) {
            "Ignored • all normal app traffic through VPN"
        } else {
            "Ignored • all proxied traffic through the selected proxy outbound"
        }
    }
    return buildString {
        append("${state.routingRules.proxyPackages.size} VPN apps")
        append(" • ")
        append("${state.routingRules.nationalDomainSuffixes.size} country-code domains")
        append(" • ")
        append("${state.routingRules.directDomainSuffixes.size} bypass domains")
    }
}

fun connectionLabel(appMode: AppMode): String {
    return when (appMode) {
        AppMode.VPN -> "VPN"
        AppMode.PROXY_ONLY -> "proxy"
    }
}

private fun isAllSubscriptionsActive(state: MainUiState): Boolean =
    isAllSubscriptionsGroupActive(state.activeSubscriptionId, state.subscriptions)
