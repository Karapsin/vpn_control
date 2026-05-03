package com.kardinal.vpncontrol.model

object SubscriptionStatusMessages {
    fun noSubscriptionsSaved(): String =
        StatusMessageCodec.encode(StatusMessageKey.NO_SUBSCRIPTIONS_SAVED)

    fun noRemoteSource(): String =
        StatusMessageCodec.encode(StatusMessageKey.NO_REMOTE_SOURCE)

    fun addSavedLocationFirst(): String =
        StatusMessageCodec.encode(StatusMessageKey.ADD_SAVED_LOCATION_FIRST)

    fun subscriptionRefreshStart(targetCount: Int, auto: Boolean = false): String =
        StatusMessageCodec.encode(SubscriptionStatusMessageKeys.refreshStart(targetCount, auto))

    fun refreshingSubscriptionNamed(name: String): String =
        StatusMessageCodec.encode(StatusMessageKey.REFRESHING_SUBSCRIPTION_NAMED, name)

    fun activeSubscriptionRefreshed(): String =
        StatusMessageCodec.encode(StatusMessageKey.ACTIVE_SUBSCRIPTION_REFRESHED)

    fun allSubscriptionsRefreshed(): String =
        StatusMessageCodec.encode(StatusMessageKey.ALL_SUBSCRIPTIONS_REFRESHED)

    fun subscriptionRefreshed(): String =
        StatusMessageCodec.encode(StatusMessageKey.SUBSCRIPTION_REFRESHED)

    fun subscriptionsRefreshed(): String =
        StatusMessageCodec.encode(StatusMessageKey.SUBSCRIPTIONS_REFRESHED)

    fun subscriptionsRefreshedCount(refreshedCount: Int, totalCount: Int): String =
        StatusMessageCodec.encode(
            StatusMessageKey.SUBSCRIPTIONS_REFRESHED_COUNT,
            refreshedCount.toString(),
            totalCount.toString(),
        )

    fun subscriptionsRefreshedPartial(
        refreshedCount: Int,
        totalCount: Int,
        failedLabel: String,
    ): String = StatusMessageCodec.encode(
        StatusMessageKey.SUBSCRIPTIONS_REFRESHED_PARTIAL,
        refreshedCount.toString(),
        totalCount.toString(),
        failedLabel,
    )

    fun locationsRefreshed(count: Int): String =
        StatusMessageCodec.encode(SubscriptionStatusMessageKeys.locationsRefreshed(count), count.toString())

    fun failedToRefresh(failedLabel: String): String =
        StatusMessageCodec.encode(StatusMessageKey.FAILED_TO_REFRESH, failedLabel)

    fun failedToRefreshActiveSubscription(): String =
        StatusMessageCodec.encode(StatusMessageKey.FAILED_TO_REFRESH_ACTIVE_SUBSCRIPTION)

    fun failedToRefreshSubscriptions(): String =
        StatusMessageCodec.encode(StatusMessageKey.FAILED_TO_REFRESH_SUBSCRIPTIONS)

    fun noSubscriptionsRefreshed(): String =
        StatusMessageCodec.encode(StatusMessageKey.NO_SUBSCRIPTIONS_REFRESHED)

    fun noActiveSubscriptionSelected(): String =
        StatusMessageCodec.encode(StatusMessageKey.NO_ACTIVE_SUBSCRIPTION_SELECTED)

    fun activatedAllSubscriptions(): String =
        StatusMessageCodec.encode(StatusMessageKey.ACTIVATED_ALL_SUBSCRIPTIONS)

    fun activatedSubscription(label: String): String =
        StatusMessageCodec.encode(StatusMessageKey.ACTIVATED_SUBSCRIPTION, label)

    fun profileSourceMode(mode: ProfileSourceMode): String =
        StatusMessageCodec.encode(StatusMessageKey.PROFILE_SOURCE_MODE, mode.name)

    fun subscriptionNameReset(): String =
        StatusMessageCodec.encode(StatusMessageKey.SUBSCRIPTION_NAME_RESET)

    fun subscriptionNameSaved(): String =
        StatusMessageCodec.encode(StatusMessageKey.SUBSCRIPTION_NAME_SAVED)

    fun subscriptionDeleted(): String =
        StatusMessageCodec.encode(StatusMessageKey.SUBSCRIPTION_DELETED)

    fun subscriptionTextLoadedIntoProfile(): String =
        StatusMessageCodec.encode(StatusMessageKey.SUBSCRIPTION_TEXT_LOADED_INTO_PROFILE)

    fun profileSourceSet(mode: ProfileSourceMode): String =
        StatusMessageCodec.encode(StatusMessageKey.PROFILE_SOURCE_SET, mode.name)

    fun noSubscriptionsToRefresh(): String =
        StatusMessageCodec.encode(StatusMessageKey.NO_SUBSCRIPTIONS_TO_REFRESH)

    fun subscriptionReceived(): String =
        StatusMessageCodec.encode(StatusMessageKey.SUBSCRIPTION_RECEIVED)

    fun subscriptionLinkReceived(): String =
        StatusMessageCodec.encode(StatusMessageKey.SUBSCRIPTION_LINK_RECEIVED)

    fun locationConfigReceived(): String =
        StatusMessageCodec.encode(StatusMessageKey.LOCATION_CONFIG_RECEIVED)

    fun sharedTextUnsupportedImport(): String =
        StatusMessageCodec.encode(StatusMessageKey.SHARED_TEXT_UNSUPPORTED_IMPORT)

    fun pasteSubscriptionRequired(): String =
        StatusMessageCodec.encode(StatusMessageKey.PASTE_SUBSCRIPTION_REQUIRED)

    fun subscriptionSaved(): String =
        StatusMessageCodec.encode(StatusMessageKey.SUBSCRIPTION_SAVED)

    fun invalidRemoteSource(): String =
        StatusMessageCodec.encode(StatusMessageKey.INVALID_REMOTE_SOURCE)

    fun allSubscriptionsSelected(): String =
        StatusMessageCodec.encode(StatusMessageKey.ALL_SUBSCRIPTIONS_SELECTED)

    fun subscriptionSelected(): String =
        StatusMessageCodec.encode(StatusMessageKey.SUBSCRIPTION_SELECTED)

    fun invalidSubscriptionUrl(): String =
        StatusMessageCodec.encode(StatusMessageKey.INVALID_SUBSCRIPTION_URL)

    fun subscriptionRefreshRemovedSelectedStopped(appMode: AppMode): String =
        StatusMessageCodec.encode(StatusMessageKey.SUBSCRIPTION_REFRESH_REMOVED_SELECTED_STOPPED, appMode.name)

    fun subscriptionDeleteRemovedSelectedStopped(appMode: AppMode): String =
        StatusMessageCodec.encode(StatusMessageKey.SUBSCRIPTION_DELETE_REMOVED_SELECTED_STOPPED, appMode.name)

    fun backgroundRefreshFindingBest(): String =
        StatusMessageCodec.encode(StatusMessageKey.BACKGROUND_REFRESH_FINDING_BEST)

    fun backgroundRefreshSwitched(
        appMode: AppMode,
        selectedProfileName: String,
        winnerSource: String?,
        failedLabel: String?,
    ): String {
        val key = BackgroundRefreshStatusMessageKeys.switched(winnerSource, failedLabel)
        return StatusMessageCodec.encode(
            key,
            appMode.name,
            selectedProfileName,
            winnerSource.orEmpty(),
            failedLabel.orEmpty(),
        )
    }

    fun backgroundRefreshReplacementFailed(
        appMode: AppMode,
        failureMessage: String,
        failedLabel: String?,
        selectedSourceFailed: Boolean,
        rollbackMessage: String,
    ): String {
        val key = BackgroundRefreshStatusMessageKeys.replacementFailed(
            failedLabel = failedLabel,
            selectedSourceFailed = selectedSourceFailed,
            rollbackMessage = rollbackMessage,
        )
        return StatusMessageCodec.encode(key, appMode.name, failureMessage, failedLabel.orEmpty(), rollbackMessage)
    }

    fun backgroundRefreshSelectedMissingKept(appMode: AppMode, failedLabel: String?): String {
        val key = BackgroundRefreshStatusMessageKeys.selectedMissingKept(failedLabel)
        return StatusMessageCodec.encode(key, appMode.name, failedLabel.orEmpty())
    }

    fun backgroundRefreshKeptCurrent(
        appMode: AppMode,
        failedLabel: String?,
        selectedSourceFailed: Boolean,
    ): String {
        val key = BackgroundRefreshStatusMessageKeys.keptCurrent(failedLabel, selectedSourceFailed)
        return StatusMessageCodec.encode(key, appMode.name, failedLabel.orEmpty())
    }

    fun backgroundRefreshPreviousLocationKept(appMode: AppMode): String =
        StatusMessageCodec.encode(StatusMessageKey.BACKGROUND_REFRESH_PREVIOUS_LOCATION_KEPT, appMode.name)

    fun backgroundRefreshReplacementStopped(appMode: AppMode): String =
        StatusMessageCodec.encode(StatusMessageKey.BACKGROUND_REFRESH_REPLACEMENT_STOPPED, appMode.name)

    fun backgroundRefreshRestoreOrStopFailed(appMode: AppMode, detail: String): String =
        StatusMessageCodec.encode(StatusMessageKey.BACKGROUND_REFRESH_RESTORE_OR_STOP_FAILED, appMode.name, detail)

    fun backgroundRefreshFailed(): String =
        StatusMessageCodec.encode(StatusMessageKey.BACKGROUND_REFRESH_FAILED)

    fun replacementLocationSearchFailed(): String =
        StatusMessageCodec.encode(StatusMessageKey.REPLACEMENT_LOCATION_SEARCH_FAILED)

    fun replacementLocationSaveFailed(): String =
        StatusMessageCodec.encode(StatusMessageKey.REPLACEMENT_LOCATION_SAVE_FAILED)
}
