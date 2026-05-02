package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.data.SubscriptionRefreshFailure
import com.kardinal.vpncontrol.model.PersistedState

enum class SubscriptionRefreshScope {
    ACTIVE,
    ALL,
}

object SubscriptionRefreshResultLogic {
    const val NO_SUBSCRIPTIONS_MESSAGE = "No subscriptions saved yet"
    const val NO_REMOTE_SOURCE_MESSAGE = "Set a remote source first"

    fun refreshStartMessage(
        targetCount: Int,
        auto: Boolean = false,
    ): String {
        val prefix = if (auto) "Auto-refreshing" else "Refreshing"
        return if (targetCount == 1) {
            "$prefix subscription..."
        } else {
            "$prefix subscriptions..."
        }
    }

    fun manualSummary(
        scope: SubscriptionRefreshScope,
        refreshedCount: Int,
        failedSubscriptionNames: List<String>,
        totalCount: Int,
    ): String {
        val defaultSuccess = when (scope) {
            SubscriptionRefreshScope.ACTIVE -> "Active subscription refreshed"
            SubscriptionRefreshScope.ALL -> {
                if (totalCount == refreshedCount) {
                    "All subscriptions refreshed"
                } else {
                    "Subscriptions refreshed: $refreshedCount/$totalCount"
                }
            }
        }
        return summary(
            refreshedCount = refreshedCount,
            failedSubscriptionNames = failedSubscriptionNames,
            totalCount = totalCount,
            defaultSuccess = defaultSuccess,
        )
    }

    fun genericSummary(
        refreshedCount: Int,
        failedSubscriptionNames: List<String>,
        totalCount: Int,
    ): String {
        val defaultSuccess = if (refreshedCount == 1 && totalCount == 1) {
            "Subscription refreshed"
        } else {
            "Subscriptions refreshed"
        }
        return summary(
            refreshedCount = refreshedCount,
            failedSubscriptionNames = failedSubscriptionNames,
            totalCount = totalCount,
            defaultSuccess = defaultSuccess,
        )
    }

    fun summary(
        refreshedCount: Int,
        failedSubscriptionNames: List<String>,
        totalCount: Int,
        defaultSuccess: String,
    ): String {
        if (failedSubscriptionNames.isEmpty()) {
            return defaultSuccess
        }
        val failedSuffix = failureLabel(failedSubscriptionNames)
        return "Subscriptions refreshed: $refreshedCount/$totalCount. Failed: $failedSuffix"
    }

    fun failureSummary(failedSubscriptionNames: List<String>): String? {
        if (failedSubscriptionNames.isEmpty()) return null
        return "Failed to refresh: ${failureLabel(failedSubscriptionNames)}"
    }

    fun selectedSourceFailed(
        selectedProfileSourceUrl: String,
        failures: List<SubscriptionRefreshFailure>,
    ): Boolean {
        val selected = selectedProfileSourceUrl.trim()
        return selected.isNotBlank() && failures.any { it.sourceUrl == selected }
    }

    fun selectedMissingAfterRefresh(
        refreshAll: Boolean,
        previousState: PersistedState,
        refreshedState: PersistedState,
        previousSelectedStored: String,
    ): Boolean {
        if (previousSelectedStored.isBlank()) return false
        return if (refreshAll) {
            previousSelectedStored !in refreshedState.currentLocations
        } else {
            val activeLocations = refreshedState.subscriptions
                .firstOrNull { it.id == refreshedState.activeSubscriptionId }
                ?.cachedLocations
                .orEmpty()
            previousState.selectedProfileSourceUrl.isNotBlank() &&
                previousState.selectedProfileSourceUrl == previousState.profileUrl &&
                previousSelectedStored !in activeLocations
        }
    }

    fun backgroundSwitchedMessage(
        connectionLabel: String,
        selectedProfileName: String,
        winnerSource: String?,
        failedSubscriptionNames: List<String>,
    ): String {
        return buildString {
            append("Subscriptions refreshed")
            if (failedSubscriptionNames.isNotEmpty()) {
                append(" with partial failures")
            }
            append(". Switched $connectionLabel to $selectedProfileName")
            winnerSource?.let {
                append(" (best from $it)")
            }
            failureSummary(failedSubscriptionNames)?.let {
                append(". ")
                append(it)
            }
        }
    }

    fun backgroundReplacementFailedMessage(
        connectionLabel: String,
        failureMessage: String,
        failedSubscriptionNames: List<String>,
        selectedSourceFailed: Boolean,
        rollbackMessage: String,
    ): String {
        return buildString {
            append("Subscription refresh finished. ")
            append(failureMessage)
            failureSummary(failedSubscriptionNames)?.let {
                append(". ")
                append(it)
            }
            if (selectedSourceFailed) {
                append(". Current $connectionLabel location belongs to a subscription that did not refresh")
            }
            if (rollbackMessage.isNotBlank()) {
                append(" ")
                append(rollbackMessage)
            }
        }.trim()
    }

    fun backgroundSelectedMissingMessage(
        connectionLabel: String,
        failedSubscriptionNames: List<String>,
    ): String {
        return buildString {
            append("Active subscription changed, but the current $connectionLabel location was kept as a fallback")
            failureSummary(failedSubscriptionNames)?.let {
                append(". ")
                append(it)
            }
        }
    }

    fun backgroundKeptCurrentMessage(
        connectionLabel: String,
        failedSubscriptionNames: List<String>,
        selectedSourceFailed: Boolean,
    ): String {
        return buildString {
            append("Subscriptions refreshed")
            if (failedSubscriptionNames.isNotEmpty()) {
                append(" with partial failures")
            }
            append(". Current $connectionLabel location kept")
            if (selectedSourceFailed) {
                append(" from the previous cache")
            }
            failureSummary(failedSubscriptionNames)?.let {
                append(". ")
                append(it)
            }
        }
    }

    private fun failureLabel(failedSubscriptionNames: List<String>): String {
        val distinctFailures = failedSubscriptionNames.distinct()
        val visible = distinctFailures.take(2).joinToString(", ")
        val overflow = (distinctFailures.size - 2).coerceAtLeast(0)
        return if (overflow > 0) {
            "$visible +$overflow more"
        } else {
            visible
        }
    }
}
