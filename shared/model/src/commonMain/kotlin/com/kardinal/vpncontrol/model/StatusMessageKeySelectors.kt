package com.kardinal.vpncontrol.model

internal object ConnectionStatusMessageKeys {
    fun findBestStart(sourceMode: ProfileSourceMode): StatusMessageKey =
        when (sourceMode) {
            ProfileSourceMode.SUBSCRIPTION -> StatusMessageKey.FIND_BEST_FROM_SUBSCRIPTION
            ProfileSourceMode.CURRENT_LOCATIONS -> StatusMessageKey.FIND_BEST_FROM_SAVED
        }
}

internal object SubscriptionStatusMessageKeys {
    fun refreshStart(targetCount: Int, auto: Boolean): StatusMessageKey {
        val many = targetCount != 1
        return when {
            auto && many -> StatusMessageKey.AUTO_REFRESHING_SUBSCRIPTIONS
            auto -> StatusMessageKey.AUTO_REFRESHING_SUBSCRIPTION
            many -> StatusMessageKey.REFRESHING_SUBSCRIPTIONS
            else -> StatusMessageKey.REFRESHING_SUBSCRIPTION
        }
    }

    fun locationsRefreshed(count: Int): StatusMessageKey =
        if (count == 1) {
            StatusMessageKey.LOCATION_REFRESHED_COUNT
        } else {
            StatusMessageKey.LOCATIONS_REFRESHED_COUNT
        }
}

internal object BackgroundRefreshStatusMessageKeys {
    fun switched(winnerSource: String?, failedLabel: String?): StatusMessageKey =
        when {
            !failedLabel.isNullOrBlank() && !winnerSource.isNullOrBlank() ->
                StatusMessageKey.BACKGROUND_REFRESH_SWITCHED_PARTIAL_SOURCE
            !failedLabel.isNullOrBlank() ->
                StatusMessageKey.BACKGROUND_REFRESH_SWITCHED_PARTIAL
            !winnerSource.isNullOrBlank() ->
                StatusMessageKey.BACKGROUND_REFRESH_SWITCHED_SOURCE
            else -> StatusMessageKey.BACKGROUND_REFRESH_SWITCHED
        }

    fun replacementFailed(
        failedLabel: String?,
        selectedSourceFailed: Boolean,
        rollbackMessage: String,
    ): StatusMessageKey {
        val hasFailures = !failedLabel.isNullOrBlank()
        val hasRollback = rollbackMessage.isNotBlank()
        return when {
            hasFailures && selectedSourceFailed && hasRollback ->
                StatusMessageKey.BACKGROUND_REFRESH_REPLACEMENT_FAILED_WITH_FAILURES_SOURCE_FAILED_ROLLBACK
            hasFailures && selectedSourceFailed ->
                StatusMessageKey.BACKGROUND_REFRESH_REPLACEMENT_FAILED_WITH_FAILURES_SOURCE_FAILED
            hasFailures && hasRollback ->
                StatusMessageKey.BACKGROUND_REFRESH_REPLACEMENT_FAILED_WITH_FAILURES_ROLLBACK
            selectedSourceFailed && hasRollback ->
                StatusMessageKey.BACKGROUND_REFRESH_REPLACEMENT_FAILED_SOURCE_FAILED_ROLLBACK
            hasFailures ->
                StatusMessageKey.BACKGROUND_REFRESH_REPLACEMENT_FAILED_WITH_FAILURES
            selectedSourceFailed ->
                StatusMessageKey.BACKGROUND_REFRESH_REPLACEMENT_FAILED_SOURCE_FAILED
            hasRollback ->
                StatusMessageKey.BACKGROUND_REFRESH_REPLACEMENT_FAILED_ROLLBACK
            else ->
                StatusMessageKey.BACKGROUND_REFRESH_REPLACEMENT_FAILED
        }
    }

    fun selectedMissingKept(failedLabel: String?): StatusMessageKey =
        if (failedLabel.isNullOrBlank()) {
            StatusMessageKey.BACKGROUND_REFRESH_SELECTED_MISSING_KEPT
        } else {
            StatusMessageKey.BACKGROUND_REFRESH_SELECTED_MISSING_KEPT_WITH_FAILURES
        }

    fun keptCurrent(
        failedLabel: String?,
        selectedSourceFailed: Boolean,
    ): StatusMessageKey =
        when {
            !failedLabel.isNullOrBlank() && selectedSourceFailed ->
                StatusMessageKey.BACKGROUND_REFRESH_KEPT_CURRENT_PARTIAL_PREVIOUS_CACHE
            !failedLabel.isNullOrBlank() ->
                StatusMessageKey.BACKGROUND_REFRESH_KEPT_CURRENT_PARTIAL
            selectedSourceFailed ->
                StatusMessageKey.BACKGROUND_REFRESH_KEPT_CURRENT_PREVIOUS_CACHE
            else ->
                StatusMessageKey.BACKGROUND_REFRESH_KEPT_CURRENT
        }
}
