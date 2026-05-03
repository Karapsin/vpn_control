package com.kardinal.vpncontrol.model

object StatusMessages {
    fun encode(
        key: StatusMessageKey,
        vararg args: String,
    ): String = StatusMessageCodec.encode(key, *args)

    fun decode(raw: String): StructuredStatusMessage? = StatusMessageCodec.decode(raw)

    fun idle(): String = GeneralStatusMessages.idle()

    fun languageSet(languageName: String): String = GeneralStatusMessages.languageSet(languageName)

    fun subscriptionAutoRefreshSet(
        policy: SubscriptionRefreshPolicy,
        customIntervalHours: Double,
    ): String = SettingsStatusMessages.subscriptionAutoRefreshSet(policy, customIntervalHours)

    fun validationSettingsSaved(settings: BenchmarkValidationSettings): String =
        SettingsStatusMessages.validationSettingsSaved(settings)

    fun customDnsSaved(enabled: Boolean): String = SettingsStatusMessages.customDnsSaved(enabled)

    fun findBestStart(sourceMode: ProfileSourceMode): String = ConnectionStatusMessages.findBestStart(sourceMode)

    fun startingConnection(appMode: AppMode): String = ConnectionStatusMessages.startingConnection(appMode)

    fun startingConnectionWithBestLocation(appMode: AppMode): String =
        ConnectionStatusMessages.startingConnectionWithBestLocation(appMode)

    fun connectionStarted(appMode: AppMode): String = ConnectionStatusMessages.connectionStarted(appMode)

    fun connectionStopped(appMode: AppMode): String = ConnectionStatusMessages.connectionStopped(appMode)

    fun connectionStartCancelled(appMode: AppMode): String =
        ConnectionStatusMessages.connectionStartCancelled(appMode)

    fun connectionStopCancelled(appMode: AppMode): String = ConnectionStatusMessages.connectionStopCancelled(appMode)

    fun connectionReadyOnComputer(appMode: AppMode): String =
        ConnectionStatusMessages.connectionReadyOnComputer(appMode)

    fun desktopAppInitialized(): String = RuntimeStatusMessages.desktopAppInitialized()

    fun runtimeMode(mode: String): String = RuntimeStatusMessages.runtimeMode(mode)

    fun localProxy(address: String): String = RuntimeStatusMessages.localProxy(address)

    fun runtimeLog(path: String): String = RuntimeStatusMessages.runtimeLog(path)

    fun preflightPassed(appMode: AppMode): String = RuntimeStatusMessages.preflightPassed(appMode)

    fun preflightFailed(appMode: AppMode, failedChecks: Int): String =
        RuntimeStatusMessages.preflightFailed(appMode, failedChecks)

    fun desktopVpnCapabilityReady(): String = RuntimeStatusMessages.desktopVpnCapabilityReady()

    fun desktopVpnCapabilityError(detail: String): String = RuntimeStatusMessages.desktopVpnCapabilityError(detail)

    fun noLocationsAvailableForBenchmarking(): String = BenchmarkStatusMessages.noLocationsAvailableForBenchmarking()

    fun bestLocationSearchTimedOut(): String = BenchmarkStatusMessages.bestLocationSearchTimedOut()

    fun retryingBestLocationSearch(attempt: Int, total: Int): String =
        BenchmarkStatusMessages.retryingBestLocationSearch(attempt, total)

    fun locationSearchCancelled(): String = BenchmarkStatusMessages.locationSearchCancelled()

    fun locationSearchFailed(): String = BenchmarkStatusMessages.locationSearchFailed()

    fun locationSearchCancelledStopFailed(appMode: AppMode, detail: String = ""): String =
        BenchmarkStatusMessages.locationSearchCancelledStopFailed(appMode, detail)

    fun vpnPermissionRequired(): String = BenchmarkStatusMessages.vpnPermissionRequired()

    fun noSuitableLocationFound(): String = BenchmarkStatusMessages.noSuitableLocationFound()

    fun bestLocationNotMapped(): String = BenchmarkStatusMessages.bestLocationNotMapped()

    fun noSubscriptionsSaved(): String = SubscriptionStatusMessages.noSubscriptionsSaved()

    fun noRemoteSource(): String = SubscriptionStatusMessages.noRemoteSource()

    fun addSavedLocationFirst(): String = SubscriptionStatusMessages.addSavedLocationFirst()

    fun subscriptionRefreshStart(targetCount: Int, auto: Boolean = false): String =
        SubscriptionStatusMessages.subscriptionRefreshStart(targetCount, auto)

    fun refreshingSubscriptionNamed(name: String): String = SubscriptionStatusMessages.refreshingSubscriptionNamed(name)

    fun activeSubscriptionRefreshed(): String = SubscriptionStatusMessages.activeSubscriptionRefreshed()

    fun allSubscriptionsRefreshed(): String = SubscriptionStatusMessages.allSubscriptionsRefreshed()

    fun subscriptionRefreshed(): String = SubscriptionStatusMessages.subscriptionRefreshed()

    fun subscriptionsRefreshed(): String = SubscriptionStatusMessages.subscriptionsRefreshed()

    fun subscriptionsRefreshedCount(refreshedCount: Int, totalCount: Int): String =
        SubscriptionStatusMessages.subscriptionsRefreshedCount(refreshedCount, totalCount)

    fun subscriptionsRefreshedPartial(
        refreshedCount: Int,
        totalCount: Int,
        failedLabel: String,
    ): String = SubscriptionStatusMessages.subscriptionsRefreshedPartial(refreshedCount, totalCount, failedLabel)

    fun locationsRefreshed(count: Int): String = SubscriptionStatusMessages.locationsRefreshed(count)

    fun failedToRefresh(failedLabel: String): String = SubscriptionStatusMessages.failedToRefresh(failedLabel)

    fun failedToRefreshActiveSubscription(): String = SubscriptionStatusMessages.failedToRefreshActiveSubscription()

    fun failedToRefreshSubscriptions(): String = SubscriptionStatusMessages.failedToRefreshSubscriptions()

    fun noSubscriptionsRefreshed(): String = SubscriptionStatusMessages.noSubscriptionsRefreshed()

    fun noActiveSubscriptionSelected(): String = SubscriptionStatusMessages.noActiveSubscriptionSelected()

    fun loadingSavedLocations(): String = BenchmarkStatusMessages.loadingSavedLocations()

    fun downloadingRemoteSource(): String = BenchmarkStatusMessages.downloadingRemoteSource()

    fun resolvingRemoteSource(sourceLabel: String): String = BenchmarkStatusMessages.resolvingRemoteSource(sourceLabel)

    fun subscriptionSourceLoadFailed(sourceLabel: String): String =
        BenchmarkStatusMessages.subscriptionSourceLoadFailed(sourceLabel)

    fun noLocationsFoundSelectedSubscription(): String = BenchmarkStatusMessages.noLocationsFoundSelectedSubscription()

    fun noLocationsFoundInSource(sourceLabel: String): String = BenchmarkStatusMessages.noLocationsFoundInSource(sourceLabel)

    fun checkingTcpSpeed(remarks: String): String = BenchmarkStatusMessages.checkingTcpSpeed(remarks)

    fun checkingLocations(count: Int): String = BenchmarkStatusMessages.checkingLocations(count)

    fun checkingLocationSource(count: Int, sourceLabel: String): String =
        BenchmarkStatusMessages.checkingLocationSource(count, sourceLabel)

    fun testingFastestCandidates(): String = BenchmarkStatusMessages.testingFastestCandidates()

    fun testingLocationsRange(start: Int, end: Int, total: Int): String =
        BenchmarkStatusMessages.testingLocationsRange(start, end, total)

    fun findBestTestingFastest(sourceMode: ProfileSourceMode): String =
        BenchmarkStatusMessages.findBestTestingFastest(sourceMode)

    fun bestLocationSummary(remarks: String, detail: String): String =
        BenchmarkStatusMessages.bestLocationSummary(remarks, detail)

    fun activatedAllSubscriptions(): String = SubscriptionStatusMessages.activatedAllSubscriptions()

    fun activatedSubscription(label: String): String = SubscriptionStatusMessages.activatedSubscription(label)

    fun profileSourceMode(mode: ProfileSourceMode): String = SubscriptionStatusMessages.profileSourceMode(mode)

    fun subscriptionNameReset(): String = SubscriptionStatusMessages.subscriptionNameReset()

    fun subscriptionNameSaved(): String = SubscriptionStatusMessages.subscriptionNameSaved()

    fun subscriptionDeleted(): String = SubscriptionStatusMessages.subscriptionDeleted()

    fun selectLocationFirst(): String = LocationStatusMessages.selectLocationFirst()

    fun checkingLocation(remarks: String): String = LocationStatusMessages.checkingLocation(remarks)

    fun testingLocation(remarks: String): String = LocationStatusMessages.testingLocation(remarks)

    fun locationCheckCancelled(): String = LocationStatusMessages.locationCheckCancelled()

    fun noLocationsToExport(): String = LocationStatusMessages.noLocationsToExport()

    fun uiSettingVisibilityChanged(
        item: UiSettingsStatusItem,
        enabled: Boolean,
    ): String = SettingsStatusMessages.uiSettingVisibilityChanged(item, enabled)

    fun subscriptionLocationSaveReadOnly(): String = LocationStatusMessages.subscriptionLocationSaveReadOnly()

    fun invalidLocationConfig(): String = LocationStatusMessages.invalidLocationConfig()

    fun locationAlreadySaved(remarks: String): String = LocationStatusMessages.locationAlreadySaved(remarks)

    fun locationEditUnavailable(): String = LocationStatusMessages.locationEditUnavailable()

    fun locationAdded(remarks: String): String = LocationStatusMessages.locationAdded(remarks)

    fun locationUpdatedAndMerged(remarks: String): String = LocationStatusMessages.locationUpdatedAndMerged(remarks)

    fun locationUpdated(remarks: String): String = LocationStatusMessages.locationUpdated(remarks)

    fun subscriptionLocationDeleteReadOnly(): String = LocationStatusMessages.subscriptionLocationDeleteReadOnly()

    fun selectedLocationRemoved(remarks: String): String = LocationStatusMessages.selectedLocationRemoved(remarks)

    fun locationRemoved(remarks: String): String = LocationStatusMessages.locationRemoved(remarks)

    fun selectedLocationRemovedConnectionStopped(appMode: AppMode, remarks: String): String =
        LocationStatusMessages.selectedLocationRemovedConnectionStopped(appMode, remarks)

    fun locationRemovalRollbackFailed(appMode: AppMode): String = LocationStatusMessages.locationRemovalRollbackFailed(appMode)

    fun importLocationsBlocked(): String = LocationStatusMessages.importLocationsBlocked()

    fun importLocationsFailed(): String = LocationStatusMessages.importLocationsFailed()

    fun locationsImported(removedSelected: Boolean): String = LocationStatusMessages.locationsImported(removedSelected)

    fun locationsImportedSelectedUnavailableConnectionStopped(appMode: AppMode): String =
        LocationStatusMessages.locationsImportedSelectedUnavailableConnectionStopped(appMode)

    fun locationsImportRollbackFailed(appMode: AppMode): String =
        LocationStatusMessages.locationsImportRollbackFailed(appMode)

    fun clipboardEmpty(): String = LocationStatusMessages.clipboardEmpty()

    fun clipboardReadFailed(): String = LocationStatusMessages.clipboardReadFailed()

    fun subscriptionTextLoadedIntoProfile(): String = SubscriptionStatusMessages.subscriptionTextLoadedIntoProfile()

    fun profileSourceSet(mode: ProfileSourceMode): String = SubscriptionStatusMessages.profileSourceSet(mode)

    fun disconnectFirstChangeConnectionMode(): String = ConnectionStatusMessages.disconnectFirstChangeConnectionMode()

    fun connectionModeSet(mode: AppMode): String = RoutingStatusMessages.connectionModeSet(mode)

    fun ruleSetRemoved(): String = RoutingStatusMessages.ruleSetRemoved()

    fun switchToSavedLocationsToAddLocations(): String = RoutingStatusMessages.switchToSavedLocationsToAddLocations()

    fun historyEntryDeleted(): String = RoutingStatusMessages.historyEntryDeleted()

    fun selectedLocationUnchanged(remarks: String): String = ConnectionStatusMessages.selectedLocationUnchanged(remarks)

    fun selectedLocationSet(remarks: String): String = ConnectionStatusMessages.selectedLocationSet(remarks)

    fun selectedLocationApplying(): String = ConnectionStatusMessages.selectedLocationApplying()

    fun updatedSelectedLocationApplying(): String = ConnectionStatusMessages.updatedSelectedLocationApplying()

    fun selectedLocationApplyFailed(): String = ConnectionStatusMessages.selectedLocationApplyFailed()

    fun selectedLocationSelectFailed(): String = ConnectionStatusMessages.selectedLocationSelectFailed()

    fun updatedSelectedLocationApplyFailed(): String = ConnectionStatusMessages.updatedSelectedLocationApplyFailed()

    fun updatedSelectedLocationSaveFailed(): String = ConnectionStatusMessages.updatedSelectedLocationSaveFailed()

    fun updatedSelectedLocationAppliedSaveFailed(): String =
        ConnectionStatusMessages.updatedSelectedLocationAppliedSaveFailed()

    fun connectionStoppedKeepStateConsistent(appMode: AppMode): String =
        ConnectionStatusMessages.connectionStoppedKeepStateConsistent(appMode)

    fun previousConnectionRestored(appMode: AppMode): String = ConnectionStatusMessages.previousConnectionRestored(appMode)

    fun previousConnectionRestoredWithReason(appMode: AppMode, reason: String): String =
        ConnectionStatusMessages.previousConnectionRestoredWithReason(appMode, reason)

    fun previousConnectionRestoreFailedStopped(appMode: AppMode, detail: String): String =
        ConnectionStatusMessages.previousConnectionRestoreFailedStopped(appMode, detail)

    fun previousConnectionRestoreOrStopFailed(
        appMode: AppMode,
        restoreFailure: String,
        stopFailure: String,
    ): String = ConnectionStatusMessages.previousConnectionRestoreOrStopFailed(appMode, restoreFailure, stopFailure)

    fun locationChecked(remarks: String): String = LocationStatusMessages.locationChecked(remarks)

    fun locationCheckFailed(): String = LocationStatusMessages.locationCheckFailed()

    fun locationEdited(index: Int): String = LocationStatusMessages.locationEdited(index)

    fun sampleRuleSetAdded(): String = RoutingStatusMessages.sampleRuleSetAdded()

    fun ruleSetDeleted(id: String): String = RoutingStatusMessages.ruleSetDeleted(id)

    fun routingRulesSaved(): String = RoutingStatusMessages.routingRulesSaved()

    fun routingRulesSavedRestartRequired(appMode: AppMode): String =
        RoutingStatusMessages.routingRulesSavedRestartRequired(appMode)

    fun routingRulesSaveFailed(): String = RoutingStatusMessages.routingRulesSaveFailed()

    fun routingRulesImported(): String = RoutingStatusMessages.routingRulesImported()

    fun routingRulesImportedRestartRequired(appMode: AppMode): String =
        RoutingStatusMessages.routingRulesImportedRestartRequired(appMode)

    fun routingRulesImportFailed(): String = RoutingStatusMessages.routingRulesImportFailed()

    fun routingRulesCopiedToClipboard(): String = RoutingStatusMessages.routingRulesCopiedToClipboard()

    fun routingRulesExportCanceled(): String = RoutingStatusMessages.routingRulesExportCanceled()

    fun routingRulesExportedTo(path: String): String = RoutingStatusMessages.routingRulesExportedTo(path)

    fun routingRulesExportFailed(): String = RoutingStatusMessages.routingRulesExportFailed()

    fun routingRulesFileOpenFailed(): String = RoutingStatusMessages.routingRulesFileOpenFailed()

    fun locationsCopiedToClipboard(): String = LocationStatusMessages.locationsCopiedToClipboard()

    fun locationsExportCanceled(): String = LocationStatusMessages.locationsExportCanceled()

    fun locationsExportedTo(path: String): String = LocationStatusMessages.locationsExportedTo(path)

    fun locationsExportFailed(): String = LocationStatusMessages.locationsExportFailed()

    fun locationsFileOpenFailed(): String = LocationStatusMessages.locationsFileOpenFailed()

    fun locationsFileReadFailed(): String = LocationStatusMessages.locationsFileReadFailed()

    fun diagnosticsExportCanceled(): String = DiagnosticsStatusMessages.diagnosticsExportCanceled()

    fun diagnosticsExportedTo(path: String): String = DiagnosticsStatusMessages.diagnosticsExportedTo(path)

    fun diagnosticsExportFailed(): String = DiagnosticsStatusMessages.diagnosticsExportFailed()

    fun diagnosticsDestinationOpenFailed(): String = DiagnosticsStatusMessages.diagnosticsDestinationOpenFailed()

    fun diagnosticsExportOpened(): String = DiagnosticsStatusMessages.diagnosticsExportOpened()

    fun appsLoadFailed(): String = DiagnosticsStatusMessages.appsLoadFailed()

    fun noSubscriptionsToRefresh(): String = SubscriptionStatusMessages.noSubscriptionsToRefresh()

    fun startOnLoginEnabled(): String = SettingsStatusMessages.startOnLoginEnabled()

    fun startOnLoginDisabled(): String = SettingsStatusMessages.startOnLoginDisabled()

    fun startupSettingUpdateFailed(detail: String = ""): String = SettingsStatusMessages.startupSettingUpdateFailed(detail)

    fun subscriptionHwidCleared(): String = SettingsStatusMessages.subscriptionHwidCleared()

    fun subscriptionHwidSaved(): String = SettingsStatusMessages.subscriptionHwidSaved()

    fun refreshSettingsSaveFailed(detail: String = ""): String = SettingsStatusMessages.refreshSettingsSaveFailed(detail)

    fun appModeChanged(mode: AppMode): String = SettingsStatusMessages.appModeChanged(mode)

    fun connectionStoppedForAppMode(stoppedMode: AppMode, nextMode: AppMode): String =
        SettingsStatusMessages.connectionStoppedForAppMode(stoppedMode, nextMode)

    fun previousConnectionRestorePending(): String = ConnectionStatusMessages.previousConnectionRestorePending()

    fun previousLocationUnavailable(): String = ConnectionStatusMessages.previousLocationUnavailable()

    fun restoringPreviousConnection(locationName: String): String =
        ConnectionStatusMessages.restoringPreviousConnection(locationName)

    fun connectionStartedOnTarget(appMode: AppMode, target: String): String =
        ConnectionStatusMessages.connectionStartedOnTarget(appMode, target)

    fun connectionStartFailed(appMode: AppMode): String = ConnectionStatusMessages.connectionStartFailed(appMode)

    fun connectionStopFailed(appMode: AppMode): String = ConnectionStatusMessages.connectionStopFailed(appMode)

    fun selectedLocationSaveFailed(): String = ConnectionStatusMessages.selectedLocationSaveFailed()

    fun selectedLocationStartedSaveFailed(appMode: AppMode): String =
        ConnectionStatusMessages.selectedLocationStartedSaveFailed(appMode)

    fun bestLocationStartFailed(appMode: AppMode): String = ConnectionStatusMessages.bestLocationStartFailed(appMode)

    fun bestLocationSaveFailed(): String = ConnectionStatusMessages.bestLocationSaveFailed()

    fun bestLocationStartedSaveFailed(appMode: AppMode): String =
        ConnectionStatusMessages.bestLocationStartedSaveFailed(appMode)

    fun backgroundRefreshFindingBest(): String = SubscriptionStatusMessages.backgroundRefreshFindingBest()

    fun backgroundVpnPermissionRequiredKeepingPrevious(): String =
        ConnectionStatusMessages.backgroundVpnPermissionRequiredKeepingPrevious()

    fun appClosedConnectionWasOff(): String = ConnectionStatusMessages.appClosedConnectionWasOff()

    fun connectionStoppedReconnectOnNextLaunch(appMode: AppMode): String =
        ConnectionStatusMessages.connectionStoppedReconnectOnNextLaunch(appMode)

    fun connectionStopBeforeExitFailed(appMode: AppMode): String =
        ConnectionStatusMessages.connectionStopBeforeExitFailed(appMode)

    fun subscriptionReceived(): String = SubscriptionStatusMessages.subscriptionReceived()

    fun subscriptionLinkReceived(): String = SubscriptionStatusMessages.subscriptionLinkReceived()

    fun locationConfigReceived(): String = SubscriptionStatusMessages.locationConfigReceived()

    fun sharedTextUnsupportedImport(): String = SubscriptionStatusMessages.sharedTextUnsupportedImport()

    fun pasteSubscriptionRequired(): String = SubscriptionStatusMessages.pasteSubscriptionRequired()

    fun subscriptionSaved(): String = SubscriptionStatusMessages.subscriptionSaved()

    fun invalidRemoteSource(): String = SubscriptionStatusMessages.invalidRemoteSource()

    fun invalidRuleSet(): String = RoutingStatusMessages.invalidRuleSet()

    fun ruleSetAdded(): String = RoutingStatusMessages.ruleSetAdded()

    fun ruleSetUpdated(): String = RoutingStatusMessages.ruleSetUpdated()

    fun allSubscriptionsSelected(): String = SubscriptionStatusMessages.allSubscriptionsSelected()

    fun subscriptionSelected(): String = SubscriptionStatusMessages.subscriptionSelected()

    fun invalidSubscriptionUrl(): String = SubscriptionStatusMessages.invalidSubscriptionUrl()

    fun subscriptionRefreshRemovedSelectedStopped(appMode: AppMode): String =
        SubscriptionStatusMessages.subscriptionRefreshRemovedSelectedStopped(appMode)

    fun subscriptionDeleteRemovedSelectedStopped(appMode: AppMode): String =
        SubscriptionStatusMessages.subscriptionDeleteRemovedSelectedStopped(appMode)

    fun benchmarkedLocation(locationName: String, primaryStatus: String, secondaryStatus: String): String =
        BenchmarkStatusMessages.benchmarkedLocation(locationName, primaryStatus, secondaryStatus)

    fun benchmarkLocationFailed(locationName: String): String = BenchmarkStatusMessages.benchmarkLocationFailed(locationName)

    fun backgroundRefreshSwitched(
        appMode: AppMode,
        selectedProfileName: String,
        winnerSource: String?,
        failedLabel: String?,
    ): String = SubscriptionStatusMessages.backgroundRefreshSwitched(
        appMode,
        selectedProfileName,
        winnerSource,
        failedLabel,
    )

    fun backgroundRefreshReplacementFailed(
        appMode: AppMode,
        failureMessage: String,
        failedLabel: String?,
        selectedSourceFailed: Boolean,
        rollbackMessage: String,
    ): String = SubscriptionStatusMessages.backgroundRefreshReplacementFailed(
        appMode,
        failureMessage,
        failedLabel,
        selectedSourceFailed,
        rollbackMessage,
    )

    fun backgroundRefreshSelectedMissingKept(appMode: AppMode, failedLabel: String?): String =
        SubscriptionStatusMessages.backgroundRefreshSelectedMissingKept(appMode, failedLabel)

    fun backgroundRefreshKeptCurrent(
        appMode: AppMode,
        failedLabel: String?,
        selectedSourceFailed: Boolean,
    ): String = SubscriptionStatusMessages.backgroundRefreshKeptCurrent(appMode, failedLabel, selectedSourceFailed)

    fun backgroundRefreshPreviousLocationKept(appMode: AppMode): String =
        SubscriptionStatusMessages.backgroundRefreshPreviousLocationKept(appMode)

    fun backgroundRefreshReplacementStopped(appMode: AppMode): String =
        SubscriptionStatusMessages.backgroundRefreshReplacementStopped(appMode)

    fun backgroundRefreshRestoreOrStopFailed(appMode: AppMode, detail: String): String =
        SubscriptionStatusMessages.backgroundRefreshRestoreOrStopFailed(appMode, detail)

    fun backgroundRefreshFailed(): String = SubscriptionStatusMessages.backgroundRefreshFailed()

    fun replacementLocationSearchFailed(): String = SubscriptionStatusMessages.replacementLocationSearchFailed()

    fun replacementLocationSaveFailed(): String = SubscriptionStatusMessages.replacementLocationSaveFailed()
}
