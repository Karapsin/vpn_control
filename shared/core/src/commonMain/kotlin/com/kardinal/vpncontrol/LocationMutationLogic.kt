package com.kardinal.vpncontrol

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
                "Subscription locations are read-only. Switch to Saved Locations to save edits.",
            )
        }

        val parsed = runCatching { LocationConfigs.parseLocationInput(state.locationDraft.trim()) }
        if (parsed.isFailure) {
            return SaveLocationDecision.Invalid(
                parsed.exceptionOrNull()?.message ?: "Invalid location config",
            )
        }

        val profile = parsed.getOrThrow()
        val normalized = LocationConfigs.encodeStoredLocation(profile)
        val nextLocations = state.currentLocations.toMutableList()
        val editIndex = state.editingLocationIndex
        val replacedRawLink = editIndex?.let { nextLocations.getOrNull(it) }
        val duplicateIndex = nextLocations.indexOf(normalized)

        if (editIndex == null && duplicateIndex != -1) {
            return SaveLocationDecision.Duplicate("Location already saved: ${profile.remarks}")
        }
        if (editIndex != null && editIndex !in nextLocations.indices) {
            return SaveLocationDecision.Invalid("Location to edit is no longer available")
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
            plan.editIndex == null -> "Location added: ${plan.remarks}"
            plan.mergedWithExisting -> "Location updated and merged: ${plan.remarks}"
            else -> "Location updated: ${plan.remarks}"
        }
    }

    fun planDeleteLocation(state: MainUiState, index: Int): DeleteLocationDecision {
        if (state.profileSourceMode == ProfileSourceMode.SUBSCRIPTION) {
            return DeleteLocationDecision.MutationBlocked(
                "Subscription locations are read-only. Switch to Saved Locations to delete them.",
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
            "Selected location removed: $remarks"
        } else {
            "Location removed: $remarks"
        }
    }

    fun deleteLocationStoppedStatusMessage(
        appMode: AppMode,
        remarks: String,
    ): String {
        return "Selected location removed. ${MainCommandLogic.stoppedConnectionLabel(appMode)}: $remarks"
    }

    fun deleteLocationRollbackFailureMessage(appMode: AppMode): String {
        return "Location removal rolled back because the ${MainCommandLogic.connectionNoun(appMode)} could not be stopped"
    }

    fun planImportLocations(state: MainUiState, raw: String): ImportLocationsDecision {
        if (state.profileSourceMode != ProfileSourceMode.CURRENT_LOCATIONS) {
            return ImportLocationsDecision.Blocked("Switch to Saved Locations to import locations")
        }
        val parsed = runCatching { LocationConfigs.import(raw) }
        if (parsed.isFailure) {
            return ImportLocationsDecision.Invalid(
                parsed.exceptionOrNull()?.message ?: "Failed to import locations",
            )
        }
        return ImportLocationsDecision.Plan(parsed.getOrThrow())
    }

    fun importLocationsStatusMessage(removedSelected: Boolean): String {
        return if (removedSelected) {
            "Locations imported. Selected location is no longer available"
        } else {
            "Locations imported"
        }
    }

    fun importLocationsStoppedStatusMessage(appMode: AppMode): String {
        return "Locations imported. Selected location is no longer available, ${MainCommandLogic.stoppedConnectionLabel(appMode).lowercase()}"
    }

    fun importLocationsRollbackFailureMessage(appMode: AppMode): String {
        return "Locations import rolled back because the ${MainCommandLogic.connectionNoun(appMode)} could not be stopped"
    }
}
