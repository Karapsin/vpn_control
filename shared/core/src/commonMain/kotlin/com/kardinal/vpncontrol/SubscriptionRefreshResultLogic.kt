package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.model.SubscriptionStatusMessages
import com.kardinal.vpncontrol.data.SubscriptionRefreshFailure
import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.PersistedState

enum class SubscriptionRefreshScope {
    ACTIVE,
    ALL,
}

object SubscriptionRefreshResultLogic {
    val NO_SUBSCRIPTIONS_MESSAGE: String
        get() = SubscriptionStatusMessages.noSubscriptionsSaved()
    val NO_REMOTE_SOURCE_MESSAGE: String
        get() = SubscriptionStatusMessages.noRemoteSource()

    fun refreshStartMessage(
        targetCount: Int,
        auto: Boolean = false,
    ): String {
        return SubscriptionStatusMessages.subscriptionRefreshStart(targetCount = targetCount, auto = auto)
    }

    fun manualSummary(
        scope: SubscriptionRefreshScope,
        refreshedCount: Int,
        failedSubscriptionNames: List<String>,
        totalCount: Int,
    ): String {
        val defaultSuccess = when (scope) {
            SubscriptionRefreshScope.ACTIVE -> SubscriptionStatusMessages.activeSubscriptionRefreshed()
            SubscriptionRefreshScope.ALL -> {
                if (totalCount == refreshedCount) {
                    SubscriptionStatusMessages.allSubscriptionsRefreshed()
                } else {
                    SubscriptionStatusMessages.subscriptionsRefreshedCount(refreshedCount, totalCount)
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
            SubscriptionStatusMessages.subscriptionRefreshed()
        } else {
            SubscriptionStatusMessages.subscriptionsRefreshed()
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
        return SubscriptionStatusMessages.subscriptionsRefreshedPartial(refreshedCount, totalCount, failedSuffix)
    }

    fun failureSummary(failedSubscriptionNames: List<String>): String? {
        if (failedSubscriptionNames.isEmpty()) return null
        return SubscriptionStatusMessages.failedToRefresh(failureLabel(failedSubscriptionNames))
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
        appMode: AppMode,
        selectedProfileName: String,
        winnerSource: String?,
        failedSubscriptionNames: List<String>,
    ): String {
        return SubscriptionStatusMessages.backgroundRefreshSwitched(
            appMode = appMode,
            selectedProfileName = selectedProfileName,
            winnerSource = winnerSource,
            failedLabel = failureLabelOrNull(failedSubscriptionNames),
        )
    }

    fun backgroundReplacementFailedMessage(
        appMode: AppMode,
        failureMessage: String,
        failedSubscriptionNames: List<String>,
        selectedSourceFailed: Boolean,
        rollbackMessage: String,
    ): String {
        return SubscriptionStatusMessages.backgroundRefreshReplacementFailed(
            appMode = appMode,
            failureMessage = failureMessage,
            failedLabel = failureLabelOrNull(failedSubscriptionNames),
            selectedSourceFailed = selectedSourceFailed,
            rollbackMessage = rollbackMessage,
        )
    }

    fun backgroundSelectedMissingMessage(
        appMode: AppMode,
        failedSubscriptionNames: List<String>,
    ): String {
        return SubscriptionStatusMessages.backgroundRefreshSelectedMissingKept(
            appMode = appMode,
            failedLabel = failureLabelOrNull(failedSubscriptionNames),
        )
    }

    fun backgroundKeptCurrentMessage(
        appMode: AppMode,
        failedSubscriptionNames: List<String>,
        selectedSourceFailed: Boolean,
    ): String {
        return SubscriptionStatusMessages.backgroundRefreshKeptCurrent(
            appMode = appMode,
            failedLabel = failureLabelOrNull(failedSubscriptionNames),
            selectedSourceFailed = selectedSourceFailed,
        )
    }

    private fun failureLabelOrNull(failedSubscriptionNames: List<String>): String? {
        if (failedSubscriptionNames.isEmpty()) return null
        return failureLabel(failedSubscriptionNames)
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
