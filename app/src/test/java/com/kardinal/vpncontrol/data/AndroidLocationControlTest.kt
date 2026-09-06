package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.model.*
import com.kardinal.vpncontrol.shared.ui.AppStrings
import org.junit.Assert.*
import org.junit.Test

class AndroidLocationControlTest {
    private val a = LocationConfigs.normalizeStoredReference("socks://127.0.0.1:1080#A")
    private val b = LocationConfigs.normalizeStoredReference("socks://127.0.0.1:1081#2")
    private val state = PersistedState(profileSourceMode = ProfileSourceMode.CURRENT_LOCATIONS, currentLocations = listOf(b, a), savedLocations = listOf(b, a))
    private fun plan(op: ControlOperationId, state: PersistedState = this.state, vararg values: Pair<String, String>) =
        AndroidLocationControl.plan(state, op, values.associate { it.first to ControlValue.Text(it.second) }, "owner", AppStrings(AppLanguage.ENGLISH))

    @Test fun exactVisibleNameAndIndexUseGuiProjectionAndOpaqueTargetsNeverRetarget() {
        val selected = plan(ControlOperationId.LOCATIONS_SELECT, values = arrayOf("selector" to AppStrings(AppLanguage.ENGLISH).locationLabel(ProfileSourceMode.CURRENT_LOCATIONS, "2")))
        assertEquals(b, selected.selected)
        assertEquals(a, plan(ControlOperationId.LOCATIONS_SELECT, values = arrayOf("selector" to "2")).selected)
        val id = AndroidLocationControl.identity("owner", state, a)
        assertEquals(a, plan(ControlOperationId.LOCATIONS_SELECT, state.copy(currentLocations = listOf(a, b)), "id" to id).selected)
        assertEquals("CONFLICT", runCatching { plan(ControlOperationId.LOCATIONS_SELECT, state.copy(currentLocations = listOf(b)), "id" to id) }.exceptionOrNull()?.message)
        assertEquals("CONFLICT", runCatching { plan(ControlOperationId.LOCATIONS_SELECT, values = arrayOf("id" to AndroidLocationControl.identity("old", state, a))) }.exceptionOrNull()?.message)
    }
    @Test fun savedEditsCanonicalizeMergeAndNeverMutateSubscriptionRows() {
        val duplicate = plan(ControlOperationId.LOCATIONS_ADD, values = arrayOf("input" to a))
        assertNull(duplicate.locations)
        val updated = plan(ControlOperationId.LOCATIONS_UPDATE, values = arrayOf("id" to AndroidLocationControl.identity("owner", state, a), "input" to b))
        assertEquals(listOf(b), updated.locations)
        for (operation in listOf(ControlOperationId.LOCATIONS_ADD, ControlOperationId.LOCATIONS_UPDATE)) {
            val args = mapOf("input" to ControlValue.Text(a)) + if (operation == ControlOperationId.LOCATIONS_UPDATE) mapOf("selector" to ControlValue.Text("2")) else emptyMap()
            assertEquals("UNSUPPORTED", runCatching { AndroidLocationControl.plan(state.copy(profileSourceMode = ProfileSourceMode.SUBSCRIPTION), operation, args, "owner", AppStrings(AppLanguage.ENGLISH)) }.exceptionOrNull()?.message)
        }
    }
    @Test fun selectingSamePendingIdentityIsNoOpButSwitchingBackToActivePreparesIt() {
        val pending = state.copy(selectedProfileJson = b, selectedProfileRawLink = LocationConfigs.decodeStoredLocation(b).rawLink)
        assertNull(plan(ControlOperationId.LOCATIONS_SELECT, pending, "id" to AndroidLocationControl.identity("owner", pending, b)).selected)
        assertEquals(a, plan(ControlOperationId.LOCATIONS_SELECT, pending, "id" to AndroidLocationControl.identity("owner", pending, a)).selected)
    }
    @Test fun manualPreparationDropsPreviousSubscriptionSourceAndSingleSubscriptionUsesItsOwnSource() {
        val prior = state.copy(selectedProfileSourceUrl = "https://old.invalid")
        val selected = plan(ControlOperationId.LOCATIONS_SELECT, prior, "selector" to "2")
        assertEquals("", selected.source)
        assertEquals("", AndroidLocationControl.preparationState(prior, selected).selectedProfileSourceUrl)
        assertEquals("https://old.invalid", prior.selectedProfileSourceUrl)
        val subscription = prior.copy(profileSourceMode = ProfileSourceMode.SUBSCRIPTION, activeSubscriptionId = "two",
            profileUrl = "https://two.invalid", subscriptions = listOf(
                SubscriptionSource("one", "https://one.invalid", cachedLocations = listOf(b)),
                SubscriptionSource("two", "https://two.invalid", cachedLocations = listOf(b))))
        assertEquals("https://two.invalid", AndroidLocationControl.source(subscription, b))
    }
}
