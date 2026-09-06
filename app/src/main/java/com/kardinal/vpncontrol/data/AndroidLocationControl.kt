package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.*
import com.kardinal.vpncontrol.control.*
import com.kardinal.vpncontrol.model.*
import com.kardinal.vpncontrol.shared.ui.AppStrings
import java.security.MessageDigest

internal class AndroidLocationPlan(val locations: List<String>?, val selected: String?, val source: String, val id: String)

internal object AndroidLocationControl {
    val destructiveOperations = setOf(ControlOperationId.LOCATIONS_DELETE, ControlOperationId.LOCATIONS_IMPORT)
    val operations = setOf(ControlOperationId.LOCATIONS_ADD, ControlOperationId.LOCATIONS_UPDATE, ControlOperationId.LOCATIONS_SELECT) + destructiveOperations
    fun arguments(operation: ControlOperationId, values: Map<String, ControlValue>): Map<String, ControlValue> {
        require(operation in operations && values.values.all { it is ControlValue.Text && it.value.isNotBlank() }) { "INVALID_ARGUMENT" }
        val targets = values.keys.intersect(setOf("selector", "id"))
        val keys = when (operation) {
            ControlOperationId.LOCATIONS_ADD, ControlOperationId.LOCATIONS_IMPORT -> setOf("input")
            ControlOperationId.LOCATIONS_UPDATE -> targets + "input"
            else -> targets
        }
        require(values.keys == keys && (operation in setOf(ControlOperationId.LOCATIONS_ADD, ControlOperationId.LOCATIONS_IMPORT) || targets.size == 1)) { "INVALID_ARGUMENT" }
        return values
    }
    fun source(state: PersistedState, raw: String): String = when {
        state.profileSourceMode == ProfileSourceMode.CURRENT_LOCATIONS -> ""
        isAllSubscriptionsGroupActive(state.activeSubscriptionId, state.subscriptions) ->
            sourceUrlForStoredLocation(state.subscriptions, LocationConfigs.normalizeStoredReference(raw))
        else -> state.profileUrl
    }
    fun preparationState(state: PersistedState, plan: AndroidLocationPlan): PersistedState = state.copy(selectedProfileSourceUrl = plan.source)
    fun identity(owner: String, state: PersistedState, raw: String): String = MessageDigest.getInstance("SHA-256")
        .digest((owner + "\u0000" + source(state, raw) + "\u0000" + LocationConfigs.normalizeStoredReference(raw)).toByteArray(Charsets.UTF_8))
        .joinToString("") { "%02x".format(it) }

    fun plan(state: PersistedState, operation: ControlOperationId, values: Map<String, ControlValue>, owner: String, strings: AppStrings): AndroidLocationPlan {
        arguments(operation, values)
        fun text(key: String) = (values[key] as? ControlValue.Text)?.value
        val ui = MainUiStateProjector.mergePersistedState(MainUiState(), state)
        val target = if (operation in setOf(ControlOperationId.LOCATIONS_ADD, ControlOperationId.LOCATIONS_IMPORT)) null else if (text("id") != null) {
            state.currentLocations.singleOrNull { identity(owner, state, it) == text("id") } ?: error("CONFLICT")
        } else when (val result = ControlLocationSelection.resolve(requireNotNull(text("selector")), androidLocationRows(ui, strings), { it.name })) {
            is ControlLocationResolution.Found -> result.location.rawLink
            is ControlLocationResolution.Rejected -> error(result.code.wireName)
        }
        val selected = LocationConfigs.selectedStoredReference(state.selectedProfileJson, state.selectedProfileRawLink)
        if (operation == ControlOperationId.LOCATIONS_SELECT) {
            val raw = requireNotNull(target)
            val source = source(state, raw)
            val same = LocationConfigs.normalizeStoredReference(selected) == LocationConfigs.normalizeStoredReference(raw) && state.selectedProfileSourceUrl == source
            return AndroidLocationPlan(null, if (same) null else raw, source, identity(owner, state, raw))
        }
        check(state.profileSourceMode == ProfileSourceMode.CURRENT_LOCATIONS) { "UNSUPPORTED" }
        if (operation == ControlOperationId.LOCATIONS_DELETE) {
            val deletion = LocationMutationLogic.planDeleteLocation(ui, state.currentLocations.indexOf(target)) as? DeleteLocationDecision.Plan
                ?: error("NOT_FOUND")
            return AndroidLocationPlan(deletion.nextLocations.map(LocationConfigs::normalizeStoredReference).distinct(), null, "",
                identity(owner, state, requireNotNull(target)))
        }
        if (operation == ControlOperationId.LOCATIONS_IMPORT) {
            val imported = LocationMutationLogic.planImportLocations(ui, requireNotNull(text("input"))) as? ImportLocationsDecision.Plan
                ?: error("INVALID_ARGUMENT")
            return AndroidLocationPlan(imported.importedLocations.map(LocationConfigs::normalizeStoredReference).distinct(), null, "", "")
        }
        val decision = LocationMutationLogic.planSaveLocation(ui.copy(locationDraft = requireNotNull(text("input")),
            editingLocationIndex = target?.let(state.currentLocations::indexOf)))
        if (decision is SaveLocationDecision.Duplicate) {
            val normalized = LocationConfigs.normalizeStoredReference(LocationConfigs.encodeStoredLocation(LocationConfigs.parseLocationInput(requireNotNull(text("input")).trim())))
            return AndroidLocationPlan(null, null, "", identity(owner, state, normalized))
        }
        val plan = decision as? SaveLocationDecision.Plan ?: error("INVALID_ARGUMENT")
        val next = plan.nextLocations.map(LocationConfigs::normalizeStoredReference).distinct()
        val replaceSelected = target != null && LocationConfigs.normalizeStoredReference(target) == LocationConfigs.normalizeStoredReference(selected)
        return AndroidLocationPlan(next, plan.normalizedLocation.takeIf { replaceSelected && it != selected }, "", identity(owner, state, plan.normalizedLocation))
    }
}
