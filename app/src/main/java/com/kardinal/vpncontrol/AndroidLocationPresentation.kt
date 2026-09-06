package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.control.ControlLocationResolution
import com.kardinal.vpncontrol.control.ControlLocationSelection
import com.kardinal.vpncontrol.control.ControlProtocolException
import com.kardinal.vpncontrol.data.LocationConfigs
import com.kardinal.vpncontrol.model.*
import com.kardinal.vpncontrol.shared.ui.AppStrings
import com.kardinal.vpncontrol.shared.ui.SavedLocationRow
import com.kardinal.vpncontrol.shared.ui.UiText
import java.util.Locale

data class AndroidLocationVisualState(val activeLocationKey: String? = null, val restartRequired: Boolean? = null)

internal fun androidLocationVisualKey(raw: String, source: String): String = java.security.MessageDigest.getInstance("SHA-256")
    .digest((source + "\u0000" + LocationConfigs.normalizeStoredReference(raw)).toByteArray(Charsets.UTF_8))
    .joinToString("") { "%02x".format(it) }

/** The same immutable visible rows feed Android Compose and explicit CLI inspection. */
internal fun androidLocationRows(state: MainUiState, strings: AppStrings, visual: AndroidLocationVisualState? = null): List<SavedLocationRow> {
    val selected = LocationConfigs.selectedStoredReference(state.selectedProfileJson, state.selectedProfileRawLink)
    return state.currentLocations.mapIndexed { index, raw ->
        val profile = runCatching { LocationConfigs.decodeStoredLocation(raw) }.getOrNull()
        SavedLocationRow(
            index = index,
            rawLink = raw,
            name = profile?.remarks?.let { strings.locationLabel(state.profileSourceMode, it) }
                ?: strings.get(UiText.INVALID_LOCATION_CONFIG),
            server = profile?.server ?: strings.get(UiText.COULD_NOT_READ_LOCATION),
            details = profile?.let {
                if (it.protocol == ProxyProtocol.CUSTOM) strings.get(UiText.CUSTOM_SING_BOX_CONFIG)
                else listOf(it.protocol.name.lowercase(), it.serverPort.toString(), it.network, it.sni)
                    .filter(String::isNotBlank).joinToString(" • ")
            } ?: strings.get(UiText.TAP_EDIT_TO_FIX_LOCATION),
            benchmarkDetail = state.locationBenchmarkDetails[raw].orEmpty().let { it.substringAfter(": ", it).trim() },
            autoSelectable = profile != null,
            isSelected = raw == selected,
            selection = visual?.let { observed -> com.kardinal.vpncontrol.shared.ui.SavedLocationSelection(
                selected = raw == selected,
                active = observed.activeLocationKey == androidLocationVisualKey(raw,
                    when {
                        state.profileSourceMode == ProfileSourceMode.CURRENT_LOCATIONS -> ""
                        isAllSubscriptionsGroupActive(state.activeSubscriptionId, state.subscriptions) -> sourceUrlForStoredLocation(state.subscriptions, LocationConfigs.normalizeStoredReference(raw))
                        else -> state.profileUrl
                    }),
            ) },
        )
    }.sortedWith(androidLocationRowComparator())
}

internal fun androidLocationRowComparator(): Comparator<SavedLocationRow> =
    compareBy<SavedLocationRow> {
        when {
            benchmarkScore(it.benchmarkDetail) != null -> 0
            benchmarkTiming(it.benchmarkDetail) != null -> 1
            else -> 2
        }
    }.thenBy { benchmarkScore(it.benchmarkDetail) ?: Double.POSITIVE_INFINITY }
        .thenBy { benchmarkTiming(it.benchmarkDetail) ?: Double.POSITIVE_INFINITY }
        .thenBy { it.name.lowercase(Locale.ROOT) }

private fun benchmarkScore(detail: String): Double? = Regex("""\bscore=([0-9]+(?:\.[0-9]+)?)""")
    .find(detail)?.groupValues?.getOrNull(1)?.toDoubleOrNull()
private fun benchmarkTiming(detail: String): Double? = Regex("""\btcp=([0-9]+(?:\.[0-9]+)?)ms""")
    .find(detail)?.groupValues?.getOrNull(1)?.toDoubleOrNull()

internal object AndroidControlLocationInspection {
    val operations = setOf(ControlOperationId.LOCATIONS_LIST, ControlOperationId.LOCATIONS_SHOW)

    fun read(state: MainUiState, command: ControlCommand, strings: AppStrings): Result<Map<String, ControlValue>> = runCatching {
        if (command.operation !in operations) throw ControlProtocolException(ControlCode.UNSUPPORTED)
        val expected = if (command.operation == ControlOperationId.LOCATIONS_SHOW) setOf("selector") else emptySet()
        if (command.arguments.keys != expected || command.arguments.values.any { it !is ControlValue.Text || it.value.isBlank() })
            throw ControlProtocolException(ControlCode.INVALID_ARGUMENT)
        val rows = androidLocationRows(state, strings)
        if (command.operation == ControlOperationId.LOCATIONS_LIST) mapOf("locations" to ControlValue.ArrayValue(
            rows.mapIndexed { index, row -> ControlValue.ObjectValue(mapOf(
                "index" to ControlValue.IntegerValue(index.toLong() + 1), "name" to ControlValue.Text(row.name))) }))
        else when (val selected = ControlLocationSelection.resolve(
            (command.arguments.getValue("selector") as ControlValue.Text).value, rows, SavedLocationRow::name)) {
            is ControlLocationResolution.Rejected -> throw ControlProtocolException(selected.code)
            is ControlLocationResolution.Found -> mapOf("configuration" to ControlValue.Text(
                // Invalid records remain repairable through explicit show, just like the GUI editor.
                runCatching { LocationConfigs.prettyStoredLocation(selected.location.rawLink) }.getOrDefault(selected.location.rawLink)))
        }
    }
}
