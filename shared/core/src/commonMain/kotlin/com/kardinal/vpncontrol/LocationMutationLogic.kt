package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.model.LocationStatusMessages
import com.kardinal.vpncontrol.data.LocationConfigs
import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.ProfileSourceMode

sealed interface SaveLocationDecision {
    data class MutationBlocked(val message: String) : SaveLocationDecision
    data class Invalid(val message: String) : SaveLocationDecision
    data class Duplicate(val message: String) : SaveLocationDecision
    data class Plan(
        val nextLocations: List<String>,
        val normalizedLocation: String,
        val remarks: String,
        val editIndex: Int?,
        val replacedRawLink: String?,
        val mergedWithExisting: Boolean,
    ) : SaveLocationDecision
}

sealed interface DeleteLocationDecision {
    data class MutationBlocked(val message: String) : DeleteLocationDecision
    data object Missing : DeleteLocationDecision
    data class Plan(
        val nextLocations: List<String>,
        val removedRawLink: String,
        val remarks: String,
    ) : DeleteLocationDecision
}

sealed interface ImportLocationsDecision {
    data class Blocked(val message: String) : ImportLocationsDecision
    data class Invalid(val message: String) : ImportLocationsDecision
    data class Plan(val importedLocations: List<String>) : ImportLocationsDecision
}

object LocationMutationLogic {
    fun planSaveLocation(state: MainUiState): SaveLocationDecision {
        if (state.profileSourceMode == ProfileSourceMode.SUBSCRIPTION &&
            state.editingLocationIndex != null
        ) {
            return SaveLocationDecision.MutationBlocked(
                LocationStatusMessages.subscriptionLocationSaveReadOnly(),
            )
        }

        val parsed = runCatching { LocationConfigs.parseLocationInput(state.locationDraft.trim()) }
        if (parsed.isFailure) {
            return SaveLocationDecision.Invalid(
                parsed.exceptionOrNull()?.message ?: LocationStatusMessages.invalidLocationConfig(),
            )
        }

        val profile = parsed.getOrThrow()
        // Use the same canonical form for direct links and re-imported editor JSON.
        val canonical = LocationConfigs.normalizeStoredReference(LocationConfigs.encodeStoredLocation(profile))
        val nextLocations = state.currentLocations.toMutableList()
        val editIndex = state.editingLocationIndex
        val replacedRawLink = editIndex?.let { nextLocations.getOrNull(it) }
        val duplicateIndex = nextLocations.indexOfFirst { LocationConfigs.normalizeStoredReference(it) == canonical }
        val normalized = nextLocations.getOrNull(duplicateIndex) ?: canonical

        if (editIndex == null && duplicateIndex != -1) {
            return SaveLocationDecision.Duplicate(LocationStatusMessages.locationAlreadySaved(profile.remarks))
        }
        if (editIndex != null && editIndex !in nextLocations.indices) {
            return SaveLocationDecision.Invalid(LocationStatusMessages.locationEditUnavailable())
        }

        val mergedWithExisting = editIndex != null && duplicateIndex != -1 && duplicateIndex != editIndex
        if (editIndex == null) {
            nextLocations.add(normalized)
        } else {
            nextLocations[editIndex] = normalized
        }

        return SaveLocationDecision.Plan(
            nextLocations = nextLocations,
            normalizedLocation = normalized,
            remarks = profile.remarks,
            editIndex = editIndex,
            replacedRawLink = replacedRawLink,
            mergedWithExisting = mergedWithExisting,
        )
    }

    fun saveLocationSuccessMessage(plan: SaveLocationDecision.Plan): String {
        return when {
            plan.editIndex == null -> LocationStatusMessages.locationAdded(plan.remarks)
            plan.mergedWithExisting -> LocationStatusMessages.locationUpdatedAndMerged(plan.remarks)
            else -> LocationStatusMessages.locationUpdated(plan.remarks)
        }
    }

    fun planDeleteLocation(state: MainUiState, index: Int): DeleteLocationDecision {
        if (state.profileSourceMode == ProfileSourceMode.SUBSCRIPTION) {
            return DeleteLocationDecision.MutationBlocked(
                LocationStatusMessages.subscriptionLocationDeleteReadOnly(),
            )
        }
        val nextLocations = state.currentLocations.toMutableList()
        val removed = nextLocations.getOrNull(index) ?: return DeleteLocationDecision.Missing
        nextLocations.removeAt(index)
        val remarks = runCatching { LocationConfigs.decodeStoredLocation(removed).remarks }
            .getOrDefault("Location")
        return DeleteLocationDecision.Plan(
            nextLocations = nextLocations,
            removedRawLink = removed,
            remarks = remarks,
        )
    }

    fun deleteLocationStatusMessage(
        removedSelected: Boolean,
        appMode: AppMode,
        remarks: String,
    ): String {
        return if (removedSelected) {
            LocationStatusMessages.selectedLocationRemoved(remarks)
        } else {
            LocationStatusMessages.locationRemoved(remarks)
        }
    }

    fun deleteLocationStoppedStatusMessage(
        appMode: AppMode,
        remarks: String,
    ): String {
        return LocationStatusMessages.selectedLocationRemovedConnectionStopped(appMode, remarks)
    }

    fun deleteLocationRollbackFailureMessage(appMode: AppMode): String {
        return LocationStatusMessages.locationRemovalRollbackFailed(appMode)
    }

    fun planImportLocations(state: MainUiState, raw: String): ImportLocationsDecision {
        if (state.profileSourceMode != ProfileSourceMode.CURRENT_LOCATIONS) {
            return ImportLocationsDecision.Blocked(LocationStatusMessages.importLocationsBlocked())
        }
        val parsed = runCatching { LocationConfigs.import(raw) }
        if (parsed.isFailure) {
            return ImportLocationsDecision.Invalid(
                parsed.exceptionOrNull()?.message ?: LocationStatusMessages.importLocationsFailed(),
            )
        }
        return ImportLocationsDecision.Plan(parsed.getOrThrow())
    }

    fun importLocationsStatusMessage(removedSelected: Boolean): String {
        return LocationStatusMessages.locationsImported(removedSelected)
    }

    fun importLocationsStoppedStatusMessage(appMode: AppMode): String {
        return LocationStatusMessages.locationsImportedSelectedUnavailableConnectionStopped(appMode)
    }

    fun importLocationsRollbackFailureMessage(appMode: AppMode): String {
        return LocationStatusMessages.locationsImportRollbackFailed(appMode)
    }
}
