package com.kardinal.vpncontrol.model

object LocationStatusMessages {
    fun selectLocationFirst(): String =
        StatusMessageCodec.encode(StatusMessageKey.SELECT_LOCATION_FIRST)

    fun checkingLocation(remarks: String): String =
        StatusMessageCodec.encode(StatusMessageKey.CHECKING_LOCATION, remarks)

    fun testingLocation(remarks: String): String =
        StatusMessageCodec.encode(StatusMessageKey.TESTING_LOCATION, remarks)

    fun locationCheckCancelled(): String =
        StatusMessageCodec.encode(StatusMessageKey.LOCATION_CHECK_CANCELLED)

    fun noLocationsToExport(): String =
        StatusMessageCodec.encode(StatusMessageKey.NO_LOCATIONS_TO_EXPORT)

    fun subscriptionLocationSaveReadOnly(): String =
        StatusMessageCodec.encode(StatusMessageKey.SUBSCRIPTION_LOCATION_SAVE_READ_ONLY)

    fun invalidLocationConfig(): String =
        StatusMessageCodec.encode(StatusMessageKey.INVALID_LOCATION_CONFIG)

    fun locationAlreadySaved(remarks: String): String =
        StatusMessageCodec.encode(StatusMessageKey.LOCATION_ALREADY_SAVED, remarks)

    fun locationEditUnavailable(): String =
        StatusMessageCodec.encode(StatusMessageKey.LOCATION_EDIT_UNAVAILABLE)

    fun locationAdded(remarks: String): String =
        StatusMessageCodec.encode(StatusMessageKey.LOCATION_ADDED, remarks)

    fun locationUpdatedAndMerged(remarks: String): String =
        StatusMessageCodec.encode(StatusMessageKey.LOCATION_UPDATED_AND_MERGED, remarks)

    fun locationUpdated(remarks: String): String =
        StatusMessageCodec.encode(StatusMessageKey.LOCATION_UPDATED, remarks)

    fun subscriptionLocationDeleteReadOnly(): String =
        StatusMessageCodec.encode(StatusMessageKey.SUBSCRIPTION_LOCATION_DELETE_READ_ONLY)

    fun selectedLocationRemoved(remarks: String): String =
        StatusMessageCodec.encode(StatusMessageKey.SELECTED_LOCATION_REMOVED, remarks)

    fun locationRemoved(remarks: String): String =
        StatusMessageCodec.encode(StatusMessageKey.LOCATION_REMOVED, remarks)

    fun selectedLocationRemovedConnectionStopped(
        appMode: AppMode,
        remarks: String,
    ): String = StatusMessageCodec.encode(
        StatusMessageKey.SELECTED_LOCATION_REMOVED_CONNECTION_STOPPED,
        appMode.name,
        remarks,
    )

    fun locationRemovalRollbackFailed(appMode: AppMode): String =
        StatusMessageCodec.encode(StatusMessageKey.LOCATION_REMOVAL_ROLLBACK_FAILED, appMode.name)

    fun importLocationsBlocked(): String =
        StatusMessageCodec.encode(StatusMessageKey.IMPORT_LOCATIONS_BLOCKED)

    fun importLocationsFailed(): String =
        StatusMessageCodec.encode(StatusMessageKey.IMPORT_LOCATIONS_FAILED)

    fun locationsImported(removedSelected: Boolean): String =
        StatusMessageCodec.encode(
            if (removedSelected) {
                StatusMessageKey.LOCATIONS_IMPORTED_SELECTED_UNAVAILABLE
            } else {
                StatusMessageKey.LOCATIONS_IMPORTED
            },
        )

    fun locationsImportedSelectedUnavailableConnectionStopped(appMode: AppMode): String =
        StatusMessageCodec.encode(StatusMessageKey.LOCATIONS_IMPORTED_SELECTED_UNAVAILABLE_CONNECTION_STOPPED, appMode.name)

    fun locationsImportRollbackFailed(appMode: AppMode): String =
        StatusMessageCodec.encode(StatusMessageKey.LOCATIONS_IMPORT_ROLLBACK_FAILED, appMode.name)

    fun clipboardEmpty(): String =
        StatusMessageCodec.encode(StatusMessageKey.CLIPBOARD_EMPTY)

    fun clipboardReadFailed(): String =
        StatusMessageCodec.encode(StatusMessageKey.CLIPBOARD_READ_FAILED)

    fun locationChecked(remarks: String): String =
        StatusMessageCodec.encode(StatusMessageKey.LOCATION_CHECKED, remarks)

    fun locationCheckFailed(): String =
        StatusMessageCodec.encode(StatusMessageKey.LOCATION_CHECK_FAILED)

    fun locationEdited(index: Int): String =
        StatusMessageCodec.encode(StatusMessageKey.LOCATION_EDITED, index.toString())

    fun locationsCopiedToClipboard(): String =
        StatusMessageCodec.encode(StatusMessageKey.LOCATIONS_COPIED_TO_CLIPBOARD)

    fun locationsExportCanceled(): String =
        StatusMessageCodec.encode(StatusMessageKey.LOCATIONS_EXPORT_CANCELED)

    fun locationsExportedTo(path: String): String =
        StatusMessageCodec.encode(StatusMessageKey.LOCATIONS_EXPORTED_TO, path)

    fun locationsExportFailed(): String =
        StatusMessageCodec.encode(StatusMessageKey.LOCATIONS_EXPORT_FAILED)

    fun locationsFileOpenFailed(): String =
        StatusMessageCodec.encode(StatusMessageKey.LOCATIONS_FILE_OPEN_FAILED)

    fun locationsFileReadFailed(): String =
        StatusMessageCodec.encode(StatusMessageKey.LOCATIONS_FILE_READ_FAILED)
}
