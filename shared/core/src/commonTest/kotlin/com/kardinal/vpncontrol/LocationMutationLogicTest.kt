package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.ProfileSourceMode
import com.kardinal.vpncontrol.model.StatusMessages
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs

class LocationMutationLogicTest {
    @Test
    fun subscriptionModeMutationBlocksUseStructuredStatuses() {
        val saveDecision = LocationMutationLogic.planSaveLocation(
            MainUiState(
                profileSourceMode = ProfileSourceMode.SUBSCRIPTION,
                editingLocationIndex = 0,
            ),
        )
        val deleteDecision = LocationMutationLogic.planDeleteLocation(
            MainUiState(profileSourceMode = ProfileSourceMode.SUBSCRIPTION),
            index = 0,
        )
        val importDecision = LocationMutationLogic.planImportLocations(
            MainUiState(profileSourceMode = ProfileSourceMode.SUBSCRIPTION),
            raw = "",
        )

        assertEquals(
            StatusMessages.subscriptionLocationSaveReadOnly(),
            assertIs<SaveLocationDecision.MutationBlocked>(saveDecision).message,
        )
        assertEquals(
            StatusMessages.subscriptionLocationDeleteReadOnly(),
            assertIs<DeleteLocationDecision.MutationBlocked>(deleteDecision).message,
        )
        assertEquals(
            StatusMessages.importLocationsBlocked(),
            assertIs<ImportLocationsDecision.Blocked>(importDecision).message,
        )
    }

    @Test
    fun locationMutationStatusHelpersUseStructuredStatuses() {
        assertEquals(
            StatusMessages.locationAdded("Germany"),
            LocationMutationLogic.saveLocationSuccessMessage(
                SaveLocationDecision.Plan(
                    nextLocations = emptyList(),
                    normalizedLocation = "",
                    remarks = "Germany",
                    editIndex = null,
                    replacedRawLink = null,
                    mergedWithExisting = false,
                ),
            ),
        )
        assertEquals(
            StatusMessages.locationUpdatedAndMerged("Germany"),
            LocationMutationLogic.saveLocationSuccessMessage(
                SaveLocationDecision.Plan(
                    nextLocations = emptyList(),
                    normalizedLocation = "",
                    remarks = "Germany",
                    editIndex = 0,
                    replacedRawLink = "old",
                    mergedWithExisting = true,
                ),
            ),
        )
        assertEquals(
            StatusMessages.locationUpdated("Germany"),
            LocationMutationLogic.saveLocationSuccessMessage(
                SaveLocationDecision.Plan(
                    nextLocations = emptyList(),
                    normalizedLocation = "",
                    remarks = "Germany",
                    editIndex = 0,
                    replacedRawLink = "old",
                    mergedWithExisting = false,
                ),
            ),
        )
        assertEquals(
            StatusMessages.selectedLocationRemoved("Germany"),
            LocationMutationLogic.deleteLocationStatusMessage(
                removedSelected = true,
                appMode = AppMode.VPN,
                remarks = "Germany",
            ),
        )
        assertEquals(
            StatusMessages.locationRemoved("Germany"),
            LocationMutationLogic.deleteLocationStatusMessage(
                removedSelected = false,
                appMode = AppMode.VPN,
                remarks = "Germany",
            ),
        )
        assertEquals(
            StatusMessages.selectedLocationRemovedConnectionStopped(AppMode.VPN, "Germany"),
            LocationMutationLogic.deleteLocationStoppedStatusMessage(AppMode.VPN, "Germany"),
        )
        assertEquals(
            StatusMessages.locationRemovalRollbackFailed(AppMode.PROXY_ONLY),
            LocationMutationLogic.deleteLocationRollbackFailureMessage(AppMode.PROXY_ONLY),
        )
        assertEquals(
            StatusMessages.locationsImported(removedSelected = true),
            LocationMutationLogic.importLocationsStatusMessage(removedSelected = true),
        )
        assertEquals(
            StatusMessages.locationsImportedSelectedUnavailableConnectionStopped(AppMode.VPN),
            LocationMutationLogic.importLocationsStoppedStatusMessage(AppMode.VPN),
        )
        assertEquals(
            StatusMessages.locationsImportRollbackFailed(AppMode.PROXY_ONLY),
            LocationMutationLogic.importLocationsRollbackFailureMessage(AppMode.PROXY_ONLY),
        )
    }
}
