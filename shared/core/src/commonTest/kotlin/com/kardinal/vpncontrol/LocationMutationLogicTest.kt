package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.model.LocationStatusMessages
import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.ProfileSourceMode
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs

class LocationMutationLogicTest {
    @Test
    fun directLinkAndItsEditorJsonCannotCreateDuplicateLocations() {
        val state = MainUiState(profileSourceMode = ProfileSourceMode.CURRENT_LOCATIONS,
            locationDraft = "socks://127.0.0.1:1080#First")
        val added = assertIs<SaveLocationDecision.Plan>(LocationMutationLogic.planSaveLocation(state))
        assertIs<SaveLocationDecision.Duplicate>(LocationMutationLogic.planSaveLocation(state.copy(
            currentLocations = added.nextLocations, locationDraft = added.normalizedLocation,
        )))
        assertIs<SaveLocationDecision.Duplicate>(LocationMutationLogic.planSaveLocation(state.copy(
            currentLocations = added.nextLocations,
        )))
    }

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
            LocationStatusMessages.subscriptionLocationSaveReadOnly(),
            assertIs<SaveLocationDecision.MutationBlocked>(saveDecision).message,
        )
        assertEquals(
            LocationStatusMessages.subscriptionLocationDeleteReadOnly(),
            assertIs<DeleteLocationDecision.MutationBlocked>(deleteDecision).message,
        )
        assertEquals(
            LocationStatusMessages.importLocationsBlocked(),
            assertIs<ImportLocationsDecision.Blocked>(importDecision).message,
        )
    }

    @Test
    fun locationMutationStatusHelpersUseStructuredStatuses() {
        assertEquals(
            LocationStatusMessages.locationAdded("Germany"),
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
            LocationStatusMessages.locationUpdatedAndMerged("Germany"),
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
            LocationStatusMessages.locationUpdated("Germany"),
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
            LocationStatusMessages.selectedLocationRemoved("Germany"),
            LocationMutationLogic.deleteLocationStatusMessage(
                removedSelected = true,
                appMode = AppMode.VPN,
                remarks = "Germany",
            ),
        )
        assertEquals(
            LocationStatusMessages.locationRemoved("Germany"),
            LocationMutationLogic.deleteLocationStatusMessage(
                removedSelected = false,
                appMode = AppMode.VPN,
                remarks = "Germany",
            ),
        )
        assertEquals(
            LocationStatusMessages.selectedLocationRemovedConnectionStopped(AppMode.VPN, "Germany"),
            LocationMutationLogic.deleteLocationStoppedStatusMessage(AppMode.VPN, "Germany"),
        )
        assertEquals(
            LocationStatusMessages.locationRemovalRollbackFailed(AppMode.PROXY_ONLY),
            LocationMutationLogic.deleteLocationRollbackFailureMessage(AppMode.PROXY_ONLY),
        )
        assertEquals(
            LocationStatusMessages.locationsImported(removedSelected = true),
            LocationMutationLogic.importLocationsStatusMessage(removedSelected = true),
        )
        assertEquals(
            LocationStatusMessages.locationsImportedSelectedUnavailableConnectionStopped(AppMode.VPN),
            LocationMutationLogic.importLocationsStoppedStatusMessage(AppMode.VPN),
        )
        assertEquals(
            LocationStatusMessages.locationsImportRollbackFailed(AppMode.PROXY_ONLY),
            LocationMutationLogic.importLocationsRollbackFailureMessage(AppMode.PROXY_ONLY),
        )
    }
}
