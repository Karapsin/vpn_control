package com.kardinal.vpncontrol.model

object StatusMessages {
    fun encode(
        key: StatusMessageKey,
        vararg args: String,
    ): String = StatusMessageCodec.encode(key, *args)

    fun decode(raw: String): StructuredStatusMessage? = StatusMessageCodec.decode(raw)

    fun idle(): String = encode(StatusMessageKey.IDLE)

    fun languageSet(languageName: String): String =
        encode(StatusMessageKey.LANGUAGE_SET, languageName)

    fun subscriptionAutoRefreshSet(
        policy: SubscriptionRefreshPolicy,
        customIntervalHours: Double,
    ): String = encode(
        StatusMessageKey.SUBSCRIPTION_AUTO_REFRESH_SET,
        policy.name,
        policy.effectiveIntervalMinutes(customIntervalHours)?.toString().orEmpty(),
    )

    fun validationSettingsSaved(settings: BenchmarkValidationSettings): String {
        val normalized = settings.normalized()
        return encode(
            StatusMessageKey.VALIDATION_SETTINGS_SAVED,
            normalized.primaryUrl.displayHost(),
            normalized.secondaryUrl.displayHost(),
            normalized.batchSize.toString(),
            normalized.retryCount.toString(),
        )
    }

    fun customDnsSaved(enabled: Boolean): String =
        encode(if (enabled) StatusMessageKey.CUSTOM_DNS_SAVED else StatusMessageKey.CUSTOM_DNS_DISABLED)

    fun findBestStart(sourceMode: ProfileSourceMode): String =
        encode(ConnectionStatusMessageKeys.findBestStart(sourceMode))

    fun startingConnection(appMode: AppMode): String =
        encode(StatusMessageKey.STARTING_CONNECTION, appMode.name)

    fun startingConnectionWithBestLocation(appMode: AppMode): String =
        encode(StatusMessageKey.STARTING_CONNECTION_WITH_BEST, appMode.name)

    fun connectionStarted(appMode: AppMode): String =
        encode(StatusMessageKey.CONNECTION_STARTED, appMode.name)

    fun connectionStopped(appMode: AppMode): String =
        encode(StatusMessageKey.CONNECTION_STOPPED, appMode.name)

    fun connectionStartCancelled(appMode: AppMode): String =
        encode(StatusMessageKey.CONNECTION_START_CANCELLED, appMode.name)

    fun connectionStopCancelled(appMode: AppMode): String =
        encode(StatusMessageKey.CONNECTION_STOP_CANCELLED, appMode.name)

    fun connectionReadyOnComputer(appMode: AppMode): String =
        encode(StatusMessageKey.CONNECTION_READY_ON_COMPUTER, appMode.name)

    fun desktopAppInitialized(): String =
        encode(StatusMessageKey.DESKTOP_APP_INITIALIZED)

    fun runtimeMode(mode: String): String =
        encode(StatusMessageKey.RUNTIME_MODE, mode)

    fun localProxy(address: String): String =
        encode(StatusMessageKey.LOCAL_PROXY, address)

    fun runtimeLog(path: String): String =
        encode(StatusMessageKey.RUNTIME_LOG, path)

    fun preflightPassed(appMode: AppMode): String =
        encode(StatusMessageKey.PREFLIGHT_PASSED, appMode.name)

    fun preflightFailed(appMode: AppMode, failedChecks: Int): String =
        encode(StatusMessageKey.PREFLIGHT_FAILED, appMode.name, failedChecks.toString())

    fun desktopVpnCapabilityReady(): String =
        encode(StatusMessageKey.DESKTOP_VPN_CAPABILITY_READY)

    fun desktopVpnCapabilityError(detail: String): String =
        encode(StatusMessageKey.DESKTOP_VPN_CAPABILITY_ERROR, detail)

    fun noLocationsAvailableForBenchmarking(): String =
        encode(StatusMessageKey.NO_LOCATIONS_AVAILABLE_FOR_BENCHMARKING)

    fun bestLocationSearchTimedOut(): String =
        encode(StatusMessageKey.BEST_LOCATION_SEARCH_TIMED_OUT)

    fun retryingBestLocationSearch(attempt: Int, total: Int): String =
        encode(
            StatusMessageKey.RETRYING_BEST_LOCATION_SEARCH,
            attempt.coerceAtLeast(1).toString(),
            total.coerceAtLeast(1).toString(),
        )

    fun locationSearchCancelled(): String =
        encode(StatusMessageKey.LOCATION_SEARCH_CANCELLED)

    fun locationSearchFailed(): String =
        encode(StatusMessageKey.LOCATION_SEARCH_FAILED)

    fun locationSearchCancelledStopFailed(appMode: AppMode, detail: String = ""): String =
        encode(StatusMessageKey.LOCATION_SEARCH_CANCELLED_STOP_FAILED, appMode.name, detail)

    fun vpnPermissionRequired(): String =
        encode(StatusMessageKey.VPN_PERMISSION_REQUIRED)

    fun noSuitableLocationFound(): String =
        encode(StatusMessageKey.NO_SUITABLE_LOCATION_FOUND)

    fun bestLocationNotMapped(): String =
        encode(StatusMessageKey.BEST_LOCATION_NOT_MAPPED)

    fun noSubscriptionsSaved(): String =
        encode(StatusMessageKey.NO_SUBSCRIPTIONS_SAVED)

    fun noRemoteSource(): String =
        encode(StatusMessageKey.NO_REMOTE_SOURCE)

    fun addSavedLocationFirst(): String =
        encode(StatusMessageKey.ADD_SAVED_LOCATION_FIRST)

    fun subscriptionRefreshStart(targetCount: Int, auto: Boolean = false): String {
        return encode(SubscriptionStatusMessageKeys.refreshStart(targetCount, auto))
    }

    fun refreshingSubscriptionNamed(name: String): String =
        encode(StatusMessageKey.REFRESHING_SUBSCRIPTION_NAMED, name)

    fun activeSubscriptionRefreshed(): String =
        encode(StatusMessageKey.ACTIVE_SUBSCRIPTION_REFRESHED)

    fun allSubscriptionsRefreshed(): String =
        encode(StatusMessageKey.ALL_SUBSCRIPTIONS_REFRESHED)

    fun subscriptionRefreshed(): String =
        encode(StatusMessageKey.SUBSCRIPTION_REFRESHED)

    fun subscriptionsRefreshed(): String =
        encode(StatusMessageKey.SUBSCRIPTIONS_REFRESHED)

    fun subscriptionsRefreshedCount(refreshedCount: Int, totalCount: Int): String =
        encode(StatusMessageKey.SUBSCRIPTIONS_REFRESHED_COUNT, refreshedCount.toString(), totalCount.toString())

    fun subscriptionsRefreshedPartial(
        refreshedCount: Int,
        totalCount: Int,
        failedLabel: String,
    ): String = encode(
        StatusMessageKey.SUBSCRIPTIONS_REFRESHED_PARTIAL,
        refreshedCount.toString(),
        totalCount.toString(),
        failedLabel,
    )

    fun locationsRefreshed(count: Int): String =
        encode(SubscriptionStatusMessageKeys.locationsRefreshed(count), count.toString())

    fun failedToRefresh(failedLabel: String): String =
        encode(StatusMessageKey.FAILED_TO_REFRESH, failedLabel)

    fun failedToRefreshActiveSubscription(): String =
        encode(StatusMessageKey.FAILED_TO_REFRESH_ACTIVE_SUBSCRIPTION)

    fun failedToRefreshSubscriptions(): String =
        encode(StatusMessageKey.FAILED_TO_REFRESH_SUBSCRIPTIONS)

    fun noSubscriptionsRefreshed(): String =
        encode(StatusMessageKey.NO_SUBSCRIPTIONS_REFRESHED)

    fun noActiveSubscriptionSelected(): String =
        encode(StatusMessageKey.NO_ACTIVE_SUBSCRIPTION_SELECTED)

    fun loadingSavedLocations(): String =
        encode(StatusMessageKey.LOADING_SAVED_LOCATIONS)

    fun downloadingRemoteSource(): String =
        encode(StatusMessageKey.DOWNLOADING_REMOTE_SOURCE)

    fun resolvingRemoteSource(sourceLabel: String): String =
        encode(StatusMessageKey.RESOLVING_REMOTE_SOURCE, sourceLabel)

    fun subscriptionSourceLoadFailed(sourceLabel: String): String =
        encode(StatusMessageKey.SUBSCRIPTION_SOURCE_LOAD_FAILED, sourceLabel)

    fun noLocationsFoundSelectedSubscription(): String =
        encode(StatusMessageKey.NO_LOCATIONS_FOUND_SELECTED_SUBSCRIPTION)

    fun noLocationsFoundInSource(sourceLabel: String): String =
        encode(StatusMessageKey.NO_LOCATIONS_FOUND_IN_SOURCE, sourceLabel)

    fun checkingTcpSpeed(remarks: String): String =
        encode(StatusMessageKey.CHECKING_TCP_SPEED, remarks)

    fun checkingLocations(count: Int): String =
        encode(StatusMessageKey.CHECKING_LOCATIONS, count.toString())

    fun checkingLocationSource(count: Int, sourceLabel: String): String =
        encode(StatusMessageKey.CHECKING_LOCATION_SOURCE, count.toString(), sourceLabel)

    fun testingFastestCandidates(): String =
        encode(StatusMessageKey.TESTING_FASTEST_CANDIDATES)

    fun testingLocationsRange(start: Int, end: Int, total: Int): String =
        encode(StatusMessageKey.TESTING_LOCATIONS_RANGE, start.toString(), end.toString(), total.toString())

    fun findBestTestingFastest(sourceMode: ProfileSourceMode): String =
        encode(StatusMessageKey.FIND_BEST_TESTING_FASTEST, sourceMode.name)

    fun bestLocationSummary(remarks: String, detail: String): String =
        encode(StatusMessageKey.BEST_LOCATION_SUMMARY, remarks, detail)

    fun activatedAllSubscriptions(): String =
        encode(StatusMessageKey.ACTIVATED_ALL_SUBSCRIPTIONS)

    fun activatedSubscription(label: String): String =
        encode(StatusMessageKey.ACTIVATED_SUBSCRIPTION, label)

    fun profileSourceMode(mode: ProfileSourceMode): String =
        encode(StatusMessageKey.PROFILE_SOURCE_MODE, mode.name)

    fun subscriptionNameReset(): String =
        encode(StatusMessageKey.SUBSCRIPTION_NAME_RESET)

    fun subscriptionNameSaved(): String =
        encode(StatusMessageKey.SUBSCRIPTION_NAME_SAVED)

    fun subscriptionDeleted(): String =
        encode(StatusMessageKey.SUBSCRIPTION_DELETED)

    fun selectLocationFirst(): String =
        encode(StatusMessageKey.SELECT_LOCATION_FIRST)

    fun checkingLocation(remarks: String): String =
        encode(StatusMessageKey.CHECKING_LOCATION, remarks)

    fun testingLocation(remarks: String): String =
        encode(StatusMessageKey.TESTING_LOCATION, remarks)

    fun locationCheckCancelled(): String =
        encode(StatusMessageKey.LOCATION_CHECK_CANCELLED)

    fun noLocationsToExport(): String =
        encode(StatusMessageKey.NO_LOCATIONS_TO_EXPORT)

    fun uiSettingVisibilityChanged(
        item: UiSettingsStatusItem,
        enabled: Boolean,
    ): String = encode(StatusMessageKey.UI_SETTING_VISIBILITY_CHANGED, item.name, enabled.toString())

    fun subscriptionLocationSaveReadOnly(): String =
        encode(StatusMessageKey.SUBSCRIPTION_LOCATION_SAVE_READ_ONLY)

    fun invalidLocationConfig(): String =
        encode(StatusMessageKey.INVALID_LOCATION_CONFIG)

    fun locationAlreadySaved(remarks: String): String =
        encode(StatusMessageKey.LOCATION_ALREADY_SAVED, remarks)

    fun locationEditUnavailable(): String =
        encode(StatusMessageKey.LOCATION_EDIT_UNAVAILABLE)

    fun locationAdded(remarks: String): String =
        encode(StatusMessageKey.LOCATION_ADDED, remarks)

    fun locationUpdatedAndMerged(remarks: String): String =
        encode(StatusMessageKey.LOCATION_UPDATED_AND_MERGED, remarks)

    fun locationUpdated(remarks: String): String =
        encode(StatusMessageKey.LOCATION_UPDATED, remarks)

    fun subscriptionLocationDeleteReadOnly(): String =
        encode(StatusMessageKey.SUBSCRIPTION_LOCATION_DELETE_READ_ONLY)

    fun selectedLocationRemoved(remarks: String): String =
        encode(StatusMessageKey.SELECTED_LOCATION_REMOVED, remarks)

    fun locationRemoved(remarks: String): String =
        encode(StatusMessageKey.LOCATION_REMOVED, remarks)

    fun selectedLocationRemovedConnectionStopped(
        appMode: AppMode,
        remarks: String,
    ): String = encode(StatusMessageKey.SELECTED_LOCATION_REMOVED_CONNECTION_STOPPED, appMode.name, remarks)

    fun locationRemovalRollbackFailed(appMode: AppMode): String =
        encode(StatusMessageKey.LOCATION_REMOVAL_ROLLBACK_FAILED, appMode.name)

    fun importLocationsBlocked(): String =
        encode(StatusMessageKey.IMPORT_LOCATIONS_BLOCKED)

    fun importLocationsFailed(): String =
        encode(StatusMessageKey.IMPORT_LOCATIONS_FAILED)

    fun locationsImported(removedSelected: Boolean): String =
        encode(
            if (removedSelected) {
                StatusMessageKey.LOCATIONS_IMPORTED_SELECTED_UNAVAILABLE
            } else {
                StatusMessageKey.LOCATIONS_IMPORTED
            },
        )

    fun locationsImportedSelectedUnavailableConnectionStopped(appMode: AppMode): String =
        encode(StatusMessageKey.LOCATIONS_IMPORTED_SELECTED_UNAVAILABLE_CONNECTION_STOPPED, appMode.name)

    fun locationsImportRollbackFailed(appMode: AppMode): String =
        encode(StatusMessageKey.LOCATIONS_IMPORT_ROLLBACK_FAILED, appMode.name)

    fun clipboardEmpty(): String =
        encode(StatusMessageKey.CLIPBOARD_EMPTY)

    fun clipboardReadFailed(): String =
        encode(StatusMessageKey.CLIPBOARD_READ_FAILED)

    fun subscriptionTextLoadedIntoProfile(): String =
        encode(StatusMessageKey.SUBSCRIPTION_TEXT_LOADED_INTO_PROFILE)

    fun profileSourceSet(mode: ProfileSourceMode): String =
        encode(StatusMessageKey.PROFILE_SOURCE_SET, mode.name)

    fun disconnectFirstChangeConnectionMode(): String =
        encode(StatusMessageKey.DISCONNECT_FIRST_CHANGE_CONNECTION_MODE)

    fun connectionModeSet(mode: AppMode): String =
        encode(StatusMessageKey.CONNECTION_MODE_SET, mode.name)

    fun ruleSetRemoved(): String =
        encode(StatusMessageKey.RULE_SET_REMOVED)

    fun switchToSavedLocationsToAddLocations(): String =
        encode(StatusMessageKey.SWITCH_TO_SAVED_LOCATIONS_TO_ADD_LOCATIONS)

    fun historyEntryDeleted(): String =
        encode(StatusMessageKey.HISTORY_ENTRY_DELETED)

    fun selectedLocationUnchanged(remarks: String): String =
        encode(StatusMessageKey.SELECTED_LOCATION_UNCHANGED, remarks)

    fun selectedLocationSet(remarks: String): String =
        encode(StatusMessageKey.SELECTED_LOCATION_SET, remarks)

    fun selectedLocationApplying(): String =
        encode(StatusMessageKey.SELECTED_LOCATION_APPLYING)

    fun updatedSelectedLocationApplying(): String =
        encode(StatusMessageKey.UPDATED_SELECTED_LOCATION_APPLYING)

    fun selectedLocationApplyFailed(): String =
        encode(StatusMessageKey.SELECTED_LOCATION_APPLY_FAILED)

    fun selectedLocationSelectFailed(): String =
        encode(StatusMessageKey.SELECTED_LOCATION_SELECT_FAILED)

    fun updatedSelectedLocationApplyFailed(): String =
        encode(StatusMessageKey.UPDATED_SELECTED_LOCATION_APPLY_FAILED)

    fun updatedSelectedLocationSaveFailed(): String =
        encode(StatusMessageKey.UPDATED_SELECTED_LOCATION_SAVE_FAILED)

    fun updatedSelectedLocationAppliedSaveFailed(): String =
        encode(StatusMessageKey.UPDATED_SELECTED_LOCATION_APPLIED_SAVE_FAILED)

    fun connectionStoppedKeepStateConsistent(appMode: AppMode): String =
        encode(StatusMessageKey.CONNECTION_STOPPED_KEEP_STATE_CONSISTENT, appMode.name)

    fun previousConnectionRestored(appMode: AppMode): String =
        encode(StatusMessageKey.PREVIOUS_CONNECTION_RESTORED, appMode.name)

    fun previousConnectionRestoredWithReason(appMode: AppMode, reason: String): String =
        encode(StatusMessageKey.PREVIOUS_CONNECTION_RESTORED_WITH_REASON, appMode.name, reason)

    fun previousConnectionRestoreFailedStopped(appMode: AppMode, detail: String): String =
        encode(StatusMessageKey.PREVIOUS_CONNECTION_RESTORE_FAILED_STOPPED, appMode.name, detail)

    fun previousConnectionRestoreOrStopFailed(
        appMode: AppMode,
        restoreFailure: String,
        stopFailure: String,
    ): String = encode(
        StatusMessageKey.PREVIOUS_CONNECTION_RESTORE_OR_STOP_FAILED,
        appMode.name,
        restoreFailure,
        stopFailure,
    )

    fun locationChecked(remarks: String): String =
        encode(StatusMessageKey.LOCATION_CHECKED, remarks)

    fun locationCheckFailed(): String =
        encode(StatusMessageKey.LOCATION_CHECK_FAILED)

    fun locationEdited(index: Int): String =
        encode(StatusMessageKey.LOCATION_EDITED, index.toString())

    fun sampleRuleSetAdded(): String =
        encode(StatusMessageKey.SAMPLE_RULE_SET_ADDED)

    fun ruleSetDeleted(id: String): String =
        encode(StatusMessageKey.RULE_SET_DELETED, id)

    fun routingRulesSaved(): String =
        encode(StatusMessageKey.ROUTING_RULES_SAVED)

    fun routingRulesSavedRestartRequired(appMode: AppMode): String =
        encode(StatusMessageKey.ROUTING_RULES_SAVED_RESTART_REQUIRED, appMode.name)

    fun routingRulesSaveFailed(): String =
        encode(StatusMessageKey.ROUTING_RULES_SAVE_FAILED)

    fun routingRulesImported(): String =
        encode(StatusMessageKey.ROUTING_RULES_IMPORTED)

    fun routingRulesImportedRestartRequired(appMode: AppMode): String =
        encode(StatusMessageKey.ROUTING_RULES_IMPORTED_RESTART_REQUIRED, appMode.name)

    fun routingRulesImportFailed(): String =
        encode(StatusMessageKey.ROUTING_RULES_IMPORT_FAILED)

    fun routingRulesCopiedToClipboard(): String =
        encode(StatusMessageKey.ROUTING_RULES_COPIED_TO_CLIPBOARD)

    fun routingRulesExportCanceled(): String =
        encode(StatusMessageKey.ROUTING_RULES_EXPORT_CANCELED)

    fun routingRulesExportedTo(path: String): String =
        encode(StatusMessageKey.ROUTING_RULES_EXPORTED_TO, path)

    fun routingRulesExportFailed(): String =
        encode(StatusMessageKey.ROUTING_RULES_EXPORT_FAILED)

    fun routingRulesFileOpenFailed(): String =
        encode(StatusMessageKey.ROUTING_RULES_FILE_OPEN_FAILED)

    fun locationsCopiedToClipboard(): String =
        encode(StatusMessageKey.LOCATIONS_COPIED_TO_CLIPBOARD)

    fun locationsExportCanceled(): String =
        encode(StatusMessageKey.LOCATIONS_EXPORT_CANCELED)

    fun locationsExportedTo(path: String): String =
        encode(StatusMessageKey.LOCATIONS_EXPORTED_TO, path)

    fun locationsExportFailed(): String =
        encode(StatusMessageKey.LOCATIONS_EXPORT_FAILED)

    fun locationsFileOpenFailed(): String =
        encode(StatusMessageKey.LOCATIONS_FILE_OPEN_FAILED)

    fun locationsFileReadFailed(): String =
        encode(StatusMessageKey.LOCATIONS_FILE_READ_FAILED)

    fun diagnosticsExportCanceled(): String =
        encode(StatusMessageKey.DIAGNOSTICS_EXPORT_CANCELED)

    fun diagnosticsExportedTo(path: String): String =
        encode(StatusMessageKey.DIAGNOSTICS_EXPORTED_TO, path)

    fun diagnosticsExportFailed(): String =
        encode(StatusMessageKey.DIAGNOSTICS_EXPORT_FAILED)

    fun diagnosticsDestinationOpenFailed(): String =
        encode(StatusMessageKey.DIAGNOSTICS_DESTINATION_OPEN_FAILED)

    fun diagnosticsExportOpened(): String =
        encode(StatusMessageKey.DIAGNOSTICS_EXPORT_OPENED)

    fun appsLoadFailed(): String =
        encode(StatusMessageKey.APPS_LOAD_FAILED)

    fun noSubscriptionsToRefresh(): String =
        encode(StatusMessageKey.NO_SUBSCRIPTIONS_TO_REFRESH)

    fun startOnLoginEnabled(): String =
        encode(StatusMessageKey.START_ON_LOGIN_ENABLED)

    fun startOnLoginDisabled(): String =
        encode(StatusMessageKey.START_ON_LOGIN_DISABLED)

    fun startupSettingUpdateFailed(detail: String = ""): String =
        encode(StatusMessageKey.STARTUP_SETTING_UPDATE_FAILED, detail)

    fun subscriptionHwidCleared(): String =
        encode(StatusMessageKey.SUBSCRIPTION_HWID_CLEARED)

    fun subscriptionHwidSaved(): String =
        encode(StatusMessageKey.SUBSCRIPTION_HWID_SAVED)

    fun refreshSettingsSaveFailed(detail: String = ""): String =
        encode(StatusMessageKey.REFRESH_SETTINGS_SAVE_FAILED, detail)

    fun appModeChanged(mode: AppMode): String =
        encode(StatusMessageKey.APP_MODE_CHANGED, mode.name)

    fun connectionStoppedForAppMode(
        stoppedMode: AppMode,
        nextMode: AppMode,
    ): String = encode(StatusMessageKey.CONNECTION_STOPPED_FOR_APP_MODE, stoppedMode.name, nextMode.name)

    fun previousConnectionRestorePending(): String =
        encode(StatusMessageKey.PREVIOUS_CONNECTION_RESTORE_PENDING)

    fun previousLocationUnavailable(): String =
        encode(StatusMessageKey.PREVIOUS_LOCATION_UNAVAILABLE)

    fun restoringPreviousConnection(locationName: String): String =
        encode(StatusMessageKey.RESTORING_PREVIOUS_CONNECTION, locationName)

    fun connectionStartedOnTarget(appMode: AppMode, target: String): String =
        encode(StatusMessageKey.CONNECTION_STARTED_ON_TARGET, appMode.name, target)

    fun connectionStartFailed(appMode: AppMode): String =
        encode(StatusMessageKey.CONNECTION_START_FAILED, appMode.name)

    fun connectionStopFailed(appMode: AppMode): String =
        encode(StatusMessageKey.CONNECTION_STOP_FAILED, appMode.name)

    fun selectedLocationSaveFailed(): String =
        encode(StatusMessageKey.SELECTED_LOCATION_SAVE_FAILED)

    fun selectedLocationStartedSaveFailed(appMode: AppMode): String =
        encode(StatusMessageKey.SELECTED_LOCATION_STARTED_SAVE_FAILED, appMode.name)

    fun bestLocationStartFailed(appMode: AppMode): String =
        encode(StatusMessageKey.BEST_LOCATION_START_FAILED, appMode.name)

    fun bestLocationSaveFailed(): String =
        encode(StatusMessageKey.BEST_LOCATION_SAVE_FAILED)

    fun bestLocationStartedSaveFailed(appMode: AppMode): String =
        encode(StatusMessageKey.BEST_LOCATION_STARTED_SAVE_FAILED, appMode.name)

    fun backgroundRefreshFindingBest(): String =
        encode(StatusMessageKey.BACKGROUND_REFRESH_FINDING_BEST)

    fun backgroundVpnPermissionRequiredKeepingPrevious(): String =
        encode(StatusMessageKey.BACKGROUND_VPN_PERMISSION_REQUIRED_KEEPING_PREVIOUS)

    fun appClosedConnectionWasOff(): String =
        encode(StatusMessageKey.APP_CLOSED_CONNECTION_WAS_OFF)

    fun connectionStoppedReconnectOnNextLaunch(appMode: AppMode): String =
        encode(StatusMessageKey.CONNECTION_STOPPED_RECONNECT_ON_NEXT_LAUNCH, appMode.name)

    fun connectionStopBeforeExitFailed(appMode: AppMode): String =
        encode(StatusMessageKey.CONNECTION_STOP_BEFORE_EXIT_FAILED, appMode.name)

    fun subscriptionReceived(): String =
        encode(StatusMessageKey.SUBSCRIPTION_RECEIVED)

    fun subscriptionLinkReceived(): String =
        encode(StatusMessageKey.SUBSCRIPTION_LINK_RECEIVED)

    fun locationConfigReceived(): String =
        encode(StatusMessageKey.LOCATION_CONFIG_RECEIVED)

    fun sharedTextUnsupportedImport(): String =
        encode(StatusMessageKey.SHARED_TEXT_UNSUPPORTED_IMPORT)

    fun pasteSubscriptionRequired(): String =
        encode(StatusMessageKey.PASTE_SUBSCRIPTION_REQUIRED)

    fun subscriptionSaved(): String =
        encode(StatusMessageKey.SUBSCRIPTION_SAVED)

    fun invalidRemoteSource(): String =
        encode(StatusMessageKey.INVALID_REMOTE_SOURCE)

    fun invalidRuleSet(): String =
        encode(StatusMessageKey.INVALID_RULE_SET)

    fun ruleSetAdded(): String =
        encode(StatusMessageKey.RULE_SET_ADDED)

    fun ruleSetUpdated(): String =
        encode(StatusMessageKey.RULE_SET_UPDATED)

    fun allSubscriptionsSelected(): String =
        encode(StatusMessageKey.ALL_SUBSCRIPTIONS_SELECTED)

    fun subscriptionSelected(): String =
        encode(StatusMessageKey.SUBSCRIPTION_SELECTED)

    fun invalidSubscriptionUrl(): String =
        encode(StatusMessageKey.INVALID_SUBSCRIPTION_URL)

    fun subscriptionRefreshRemovedSelectedStopped(appMode: AppMode): String =
        encode(StatusMessageKey.SUBSCRIPTION_REFRESH_REMOVED_SELECTED_STOPPED, appMode.name)

    fun subscriptionDeleteRemovedSelectedStopped(appMode: AppMode): String =
        encode(StatusMessageKey.SUBSCRIPTION_DELETE_REMOVED_SELECTED_STOPPED, appMode.name)

    fun benchmarkedLocation(locationName: String, primaryStatus: String, secondaryStatus: String): String =
        encode(StatusMessageKey.BENCHMARKED_LOCATION, locationName, primaryStatus, secondaryStatus)

    fun benchmarkLocationFailed(locationName: String): String =
        encode(StatusMessageKey.BENCHMARK_LOCATION_FAILED, locationName)

    fun backgroundRefreshSwitched(
        appMode: AppMode,
        selectedProfileName: String,
        winnerSource: String?,
        failedLabel: String?,
    ): String {
        val key = BackgroundRefreshStatusMessageKeys.switched(winnerSource, failedLabel)
        return encode(key, appMode.name, selectedProfileName, winnerSource.orEmpty(), failedLabel.orEmpty())
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
        return encode(key, appMode.name, failureMessage, failedLabel.orEmpty(), rollbackMessage)
    }

    fun backgroundRefreshSelectedMissingKept(appMode: AppMode, failedLabel: String?): String {
        val key = BackgroundRefreshStatusMessageKeys.selectedMissingKept(failedLabel)
        return encode(key, appMode.name, failedLabel.orEmpty())
    }

    fun backgroundRefreshKeptCurrent(
        appMode: AppMode,
        failedLabel: String?,
        selectedSourceFailed: Boolean,
    ): String {
        val key = BackgroundRefreshStatusMessageKeys.keptCurrent(failedLabel, selectedSourceFailed)
        return encode(key, appMode.name, failedLabel.orEmpty())
    }

    fun backgroundRefreshPreviousLocationKept(appMode: AppMode): String =
        encode(StatusMessageKey.BACKGROUND_REFRESH_PREVIOUS_LOCATION_KEPT, appMode.name)

    fun backgroundRefreshReplacementStopped(appMode: AppMode): String =
        encode(StatusMessageKey.BACKGROUND_REFRESH_REPLACEMENT_STOPPED, appMode.name)

    fun backgroundRefreshRestoreOrStopFailed(appMode: AppMode, detail: String): String =
        encode(StatusMessageKey.BACKGROUND_REFRESH_RESTORE_OR_STOP_FAILED, appMode.name, detail)

    fun backgroundRefreshFailed(): String =
        encode(StatusMessageKey.BACKGROUND_REFRESH_FAILED)

    fun replacementLocationSearchFailed(): String =
        encode(StatusMessageKey.REPLACEMENT_LOCATION_SEARCH_FAILED)

    fun replacementLocationSaveFailed(): String =
        encode(StatusMessageKey.REPLACEMENT_LOCATION_SAVE_FAILED)

}
