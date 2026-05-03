package com.kardinal.vpncontrol.model

object ConnectionStatusMessages {
    fun findBestStart(sourceMode: ProfileSourceMode): String =
        StatusMessageCodec.encode(ConnectionStatusMessageKeys.findBestStart(sourceMode))

    fun startingConnection(appMode: AppMode): String =
        StatusMessageCodec.encode(StatusMessageKey.STARTING_CONNECTION, appMode.name)

    fun startingConnectionWithBestLocation(appMode: AppMode): String =
        StatusMessageCodec.encode(StatusMessageKey.STARTING_CONNECTION_WITH_BEST, appMode.name)

    fun connectionStarted(appMode: AppMode): String =
        StatusMessageCodec.encode(StatusMessageKey.CONNECTION_STARTED, appMode.name)

    fun connectionStopped(appMode: AppMode): String =
        StatusMessageCodec.encode(StatusMessageKey.CONNECTION_STOPPED, appMode.name)

    fun connectionStartCancelled(appMode: AppMode): String =
        StatusMessageCodec.encode(StatusMessageKey.CONNECTION_START_CANCELLED, appMode.name)

    fun connectionStopCancelled(appMode: AppMode): String =
        StatusMessageCodec.encode(StatusMessageKey.CONNECTION_STOP_CANCELLED, appMode.name)

    fun connectionReadyOnComputer(appMode: AppMode): String =
        StatusMessageCodec.encode(StatusMessageKey.CONNECTION_READY_ON_COMPUTER, appMode.name)

    fun disconnectFirstChangeConnectionMode(): String =
        StatusMessageCodec.encode(StatusMessageKey.DISCONNECT_FIRST_CHANGE_CONNECTION_MODE)

    fun selectedLocationUnchanged(remarks: String): String =
        StatusMessageCodec.encode(StatusMessageKey.SELECTED_LOCATION_UNCHANGED, remarks)

    fun selectedLocationSet(remarks: String): String =
        StatusMessageCodec.encode(StatusMessageKey.SELECTED_LOCATION_SET, remarks)

    fun selectedLocationApplying(): String =
        StatusMessageCodec.encode(StatusMessageKey.SELECTED_LOCATION_APPLYING)

    fun updatedSelectedLocationApplying(): String =
        StatusMessageCodec.encode(StatusMessageKey.UPDATED_SELECTED_LOCATION_APPLYING)

    fun selectedLocationApplyFailed(): String =
        StatusMessageCodec.encode(StatusMessageKey.SELECTED_LOCATION_APPLY_FAILED)

    fun selectedLocationSelectFailed(): String =
        StatusMessageCodec.encode(StatusMessageKey.SELECTED_LOCATION_SELECT_FAILED)

    fun updatedSelectedLocationApplyFailed(): String =
        StatusMessageCodec.encode(StatusMessageKey.UPDATED_SELECTED_LOCATION_APPLY_FAILED)

    fun updatedSelectedLocationSaveFailed(): String =
        StatusMessageCodec.encode(StatusMessageKey.UPDATED_SELECTED_LOCATION_SAVE_FAILED)

    fun updatedSelectedLocationAppliedSaveFailed(): String =
        StatusMessageCodec.encode(StatusMessageKey.UPDATED_SELECTED_LOCATION_APPLIED_SAVE_FAILED)

    fun connectionStoppedKeepStateConsistent(appMode: AppMode): String =
        StatusMessageCodec.encode(StatusMessageKey.CONNECTION_STOPPED_KEEP_STATE_CONSISTENT, appMode.name)

    fun previousConnectionRestored(appMode: AppMode): String =
        StatusMessageCodec.encode(StatusMessageKey.PREVIOUS_CONNECTION_RESTORED, appMode.name)

    fun previousConnectionRestoredWithReason(appMode: AppMode, reason: String): String =
        StatusMessageCodec.encode(StatusMessageKey.PREVIOUS_CONNECTION_RESTORED_WITH_REASON, appMode.name, reason)

    fun previousConnectionRestoreFailedStopped(appMode: AppMode, detail: String): String =
        StatusMessageCodec.encode(StatusMessageKey.PREVIOUS_CONNECTION_RESTORE_FAILED_STOPPED, appMode.name, detail)

    fun previousConnectionRestoreOrStopFailed(
        appMode: AppMode,
        restoreFailure: String,
        stopFailure: String,
    ): String = StatusMessageCodec.encode(
        StatusMessageKey.PREVIOUS_CONNECTION_RESTORE_OR_STOP_FAILED,
        appMode.name,
        restoreFailure,
        stopFailure,
    )

    fun previousConnectionRestorePending(): String =
        StatusMessageCodec.encode(StatusMessageKey.PREVIOUS_CONNECTION_RESTORE_PENDING)

    fun previousLocationUnavailable(): String =
        StatusMessageCodec.encode(StatusMessageKey.PREVIOUS_LOCATION_UNAVAILABLE)

    fun restoringPreviousConnection(locationName: String): String =
        StatusMessageCodec.encode(StatusMessageKey.RESTORING_PREVIOUS_CONNECTION, locationName)

    fun connectionStartedOnTarget(appMode: AppMode, target: String): String =
        StatusMessageCodec.encode(StatusMessageKey.CONNECTION_STARTED_ON_TARGET, appMode.name, target)

    fun connectionStartFailed(appMode: AppMode): String =
        StatusMessageCodec.encode(StatusMessageKey.CONNECTION_START_FAILED, appMode.name)

    fun connectionStopFailed(appMode: AppMode): String =
        StatusMessageCodec.encode(StatusMessageKey.CONNECTION_STOP_FAILED, appMode.name)

    fun selectedLocationSaveFailed(): String =
        StatusMessageCodec.encode(StatusMessageKey.SELECTED_LOCATION_SAVE_FAILED)

    fun selectedLocationStartedSaveFailed(appMode: AppMode): String =
        StatusMessageCodec.encode(StatusMessageKey.SELECTED_LOCATION_STARTED_SAVE_FAILED, appMode.name)

    fun bestLocationStartFailed(appMode: AppMode): String =
        StatusMessageCodec.encode(StatusMessageKey.BEST_LOCATION_START_FAILED, appMode.name)

    fun bestLocationSaveFailed(): String =
        StatusMessageCodec.encode(StatusMessageKey.BEST_LOCATION_SAVE_FAILED)

    fun bestLocationStartedSaveFailed(appMode: AppMode): String =
        StatusMessageCodec.encode(StatusMessageKey.BEST_LOCATION_STARTED_SAVE_FAILED, appMode.name)

    fun backgroundVpnPermissionRequiredKeepingPrevious(): String =
        StatusMessageCodec.encode(StatusMessageKey.BACKGROUND_VPN_PERMISSION_REQUIRED_KEEPING_PREVIOUS)

    fun appClosedConnectionWasOff(): String =
        StatusMessageCodec.encode(StatusMessageKey.APP_CLOSED_CONNECTION_WAS_OFF)

    fun connectionStoppedReconnectOnNextLaunch(appMode: AppMode): String =
        StatusMessageCodec.encode(StatusMessageKey.CONNECTION_STOPPED_RECONNECT_ON_NEXT_LAUNCH, appMode.name)

    fun connectionStopBeforeExitFailed(appMode: AppMode): String =
        StatusMessageCodec.encode(StatusMessageKey.CONNECTION_STOP_BEFORE_EXIT_FAILED, appMode.name)
}
