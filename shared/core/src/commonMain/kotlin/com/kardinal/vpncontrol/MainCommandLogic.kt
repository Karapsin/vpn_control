package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.data.ImportPreference
import com.kardinal.vpncontrol.data.IncomingImportPayload
import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.MIN_SUBSCRIPTION_REFRESH_MINUTES
import com.kardinal.vpncontrol.model.ProfileSourceMode
import com.kardinal.vpncontrol.model.StatusMessages
import com.kardinal.vpncontrol.model.SubscriptionRefreshPolicy
import com.kardinal.vpncontrol.model.SubscriptionSource
import com.kardinal.vpncontrol.model.isAllSubscriptionsGroupActive
import com.kardinal.vpncontrol.model.normalizeSubscriptionRefreshCustomHours

data class RefreshPolicyResolution(
    val policy: SubscriptionRefreshPolicy,
    val resolvedHours: Double,
    val findBestAfterRefresh: Boolean,
    val statusMessage: String,
)

data class IncomingImportEffect(
    val nextState: MainUiState,
    val profileSourceModeUpdate: ProfileSourceMode? = null,
    val statusMessage: String? = null,
    val routingRulesRaw: String? = null,
)

object MainCommandLogic {
    fun sanitizeDecimalInput(value: String): String {
        val normalized = value.replace(',', '.')
        val builder = StringBuilder()
        var dotSeen = false
        normalized.forEach { char ->
            when {
                char.isDigit() -> builder.append(char)
                char == '.' && !dotSeen -> {
                    if (builder.isEmpty()) {
                        builder.append('0')
                    }
                    builder.append('.')
                    dotSeen = true
                }
            }
        }
        return builder.toString()
    }

    fun resolveSubscriptionRefreshPolicySave(state: MainUiState): Result<RefreshPolicyResolution> {
        val policy = state.subscriptionRefreshPolicyDraft
        val customHours = state.subscriptionRefreshCustomHoursDraft
            .replace(',', '.')
            .toDoubleOrNull()
        return runCatching {
            if (policy == SubscriptionRefreshPolicy.CUSTOM && customHours == null) {
                error("Enter a valid custom refresh interval in hours")
            }
            if (policy == SubscriptionRefreshPolicy.CUSTOM &&
                customHours != null &&
                customHours * 60.0 < MIN_SUBSCRIPTION_REFRESH_MINUTES
            ) {
                error("Custom refresh interval must be at least $MIN_SUBSCRIPTION_REFRESH_MINUTES minutes")
            }
            val resolvedHours = when (policy) {
                SubscriptionRefreshPolicy.OFF ->
                    normalizeSubscriptionRefreshCustomHours(state.subscriptionRefreshCustomHours)
                SubscriptionRefreshPolicy.EVERY_HOUR -> 1.0
                SubscriptionRefreshPolicy.CUSTOM ->
                    normalizeSubscriptionRefreshCustomHours(
                        customHours ?: state.subscriptionRefreshCustomHours,
                    )
            }
            RefreshPolicyResolution(
                policy = policy,
                resolvedHours = resolvedHours,
                findBestAfterRefresh = state.findBestAfterSubscriptionRefreshDraft,
                statusMessage = StatusMessages.subscriptionAutoRefreshSet(policy, resolvedHours),
            )
        }
    }

    fun currentSubscriptionSearchTargets(state: MainUiState): List<SubscriptionSource> {
        return if (isAllSubscriptionsGroupActive(state.activeSubscriptionId, state.subscriptions)) {
            state.subscriptions.filter { it.url.isNotBlank() }
        } else {
            state.subscriptions.filter { it.id == state.activeSubscriptionId && it.url.isNotBlank() }
        }
    }

    fun refreshPreconditionError(state: MainUiState): String? {
        return when {
            state.profileSourceMode == ProfileSourceMode.SUBSCRIPTION &&
                currentSubscriptionSearchTargets(state).isEmpty() ->
                "Set a remote source first"
            state.profileSourceMode == ProfileSourceMode.CURRENT_LOCATIONS &&
                state.currentLocations.isEmpty() ->
                "Add at least one saved location first"
            else -> null
        }
    }

    fun refreshStartMessage(state: MainUiState): String {
        return if (state.profileSourceMode == ProfileSourceMode.SUBSCRIPTION) {
            "Finding the best location from the subscription..."
        } else {
            "Finding the best location from saved locations..."
        }
    }

    fun formatRefreshSummaryMessage(
        refreshedCount: Int,
        failedSubscriptions: List<String>,
        totalCount: Int,
        defaultSuccess: String,
    ): String {
        if (failedSubscriptions.isEmpty()) {
            return defaultSuccess
        }
        val distinctFailures = failedSubscriptions.distinct()
        val failedLabel = distinctFailures
            .take(2)
            .joinToString(", ")
        val overflow = (distinctFailures.size - 2).coerceAtLeast(0)
        val failedSuffix = if (overflow > 0) {
            "$failedLabel +$overflow more"
        } else {
            failedLabel
        }
        return "Subscriptions refreshed: $refreshedCount/$totalCount. Failed: $failedSuffix"
    }

    fun connectionNoun(appMode: AppMode): String {
        return when (appMode) {
            AppMode.VPN -> "VPN"
            AppMode.PROXY_ONLY -> "proxy"
        }
    }

    fun connectionDisplayName(appMode: AppMode): String {
        return when (appMode) {
            AppMode.VPN -> "VPN"
            AppMode.PROXY_ONLY -> "Proxy"
        }
    }

    fun startingConnectionLabel(appMode: AppMode): String {
        return StatusMessages.startingConnection(appMode)
    }

    fun startedConnectionLabel(appMode: AppMode): String {
        return when (appMode) {
            AppMode.VPN -> "VPN started"
            AppMode.PROXY_ONLY -> "Proxy started"
        }
    }

    fun stoppedConnectionLabel(appMode: AppMode): String {
        return when (appMode) {
            AppMode.VPN -> "VPN stopped"
            AppMode.PROXY_ONLY -> "Proxy stopped"
        }
    }

    fun bestSelectionStartMessage(appMode: AppMode): String {
        return StatusMessages.startingConnectionWithBestLocation(appMode)
    }

    fun incomingImportEffect(
        state: MainUiState,
        payload: IncomingImportPayload,
        preference: ImportPreference,
    ): IncomingImportEffect {
        return when (payload) {
            is IncomingImportPayload.Subscription -> {
                val next = MainUiStateTransitions.navigateToScreen(state, AppScreen.PROFILE).copy(
                    profileSourceMode = ProfileSourceMode.SUBSCRIPTION,
                    profileDraft = payload.raw,
                    showAddSubscriptionEditor = true,
                )
                IncomingImportEffect(
                    nextState = next,
                    profileSourceModeUpdate = ProfileSourceMode.SUBSCRIPTION,
                    statusMessage = when (preference) {
                        ImportPreference.SUBSCRIPTION -> "Subscription received. Review and save it on the Profile tab."
                        else -> "Subscription link received. Review and save it on the Profile tab."
                    },
                )
            }
            is IncomingImportPayload.Location -> {
                val next = MainUiStateTransitions.navigateToScreen(state, AppScreen.LOCATIONS).copy(
                    profileSourceMode = ProfileSourceMode.CURRENT_LOCATIONS,
                    showLocationDialog = true,
                    locationDraft = payload.raw,
                    editingLocationIndex = null,
                )
                IncomingImportEffect(
                    nextState = next,
                    profileSourceModeUpdate = ProfileSourceMode.CURRENT_LOCATIONS,
                    statusMessage = when (preference) {
                        ImportPreference.LOCATION -> "Location config received. Review and save it on the Locations tab."
                        else -> "Location config received. Review and save it on the Locations tab."
                    },
                )
            }
            is IncomingImportPayload.RoutingRules -> {
                val next = MainUiStateTransitions.navigateToScreen(
                    MainUiStateTransitions.prepareRoutingRulesScreen(state),
                    AppScreen.ROUTING_RULES,
                )
                IncomingImportEffect(
                    nextState = next,
                    routingRulesRaw = payload.raw,
                )
            }
        }
    }

    fun validateProfileSourceSave(
        value: String,
        mode: ProfileSourceMode,
        validateSubscription: (String) -> Result<Unit>,
    ): Result<String> {
        return runCatching {
            if (mode == ProfileSourceMode.SUBSCRIPTION && value.isBlank()) {
                error("Paste a subscription URL or choose one from the list")
            }
            if (mode == ProfileSourceMode.SUBSCRIPTION && value.isNotBlank()) {
                validateSubscription(value).getOrThrow()
            }
            if (mode == ProfileSourceMode.SUBSCRIPTION) {
                "Subscription saved"
            } else {
                "Profile source set to saved locations"
            }
        }
    }
}
