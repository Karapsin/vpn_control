package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.control.ControlProtocolCodec
import com.kardinal.vpncontrol.control.ControlProtocolException
import com.kardinal.vpncontrol.data.LocationConfigs
import com.kardinal.vpncontrol.model.*
import com.kardinal.vpncontrol.shared.ui.AppStrings
import com.kardinal.vpncontrol.shared.ui.UiText
import org.junit.Assert.*
import org.junit.Test

class AndroidLocationPresentationTest {
    private fun location(name: String, port: Int = 1080) = LocationConfigs.normalizeStoredReference(
        "socks://user:PROFILE_SECRET@127.0.0.1:$port#$name")

    @Test fun equalBenchmarkResultsSortByCaseInsensitiveNameWithStableStorageTies() {
        val locations = listOf(location("Beta"), location("alpha", 1081), location("ALPHA", 1082))
        val state = MainUiState(profileSourceMode = ProfileSourceMode.CURRENT_LOCATIONS, currentLocations = locations,
            locationBenchmarkDetails = locations.associateWith { "Location: score=7 tcp=5ms" })
        assertEquals(listOf(1, 2, 0), androidLocationRows(state, AppStrings(AppLanguage.ENGLISH)).map { it.index })
    }

    @Test fun guiRowsPreserveBenchmarkRankingPrefixRemovalAndStorageCallbacks() {
        val plain = location("Zulu")
        val high = location("Alpha", 1081)
        val tcp = location("TCP", 1082)
        val slowLow = location("Bravo", 1083)
        val fastLow = location("Charlie", 1084)
        val state = MainUiState(profileSourceMode = ProfileSourceMode.CURRENT_LOCATIONS,
            currentLocations = listOf(plain, high, tcp, slowLow, fastLow, "BROKEN_SECRET"), selectedProfileJson = slowLow,
            locationBenchmarkDetails = mapOf(high to "Alpha: score=20 tcp=1ms", tcp to "TCP: tcp=2ms",
                slowLow to "Bravo: score=10 tcp=90ms", fastLow to "Charlie: score=10 tcp=3ms"))
        val strings = AppStrings(AppLanguage.RUSSIAN)
        val rows = androidLocationRows(state, strings)
        assertEquals(listOf(fastLow, slowLow, high, tcp), rows.take(4).map { it.rawLink })
        assertEquals(listOf(4, 3, 1, 2), rows.take(4).map { it.index })
        assertEquals("score=10 tcp=3ms", rows.first().benchmarkDetail)
        assertEquals(strings.locationLabel(state.profileSourceMode, "Charlie"), rows.first().name)
        assertTrue(rows[1].isSelected)
        assertEquals(1, rows.count { it.isSelected })
        val invalid = rows.single { !it.autoSelectable }
        assertEquals(strings.get(UiText.INVALID_LOCATION_CONFIG), invalid.name)
        assertEquals(strings.get(UiText.COULD_NOT_READ_LOCATION), invalid.server)
        assertEquals(strings.get(UiText.TAP_EDIT_TO_FIX_LOCATION), invalid.details)
        assertEquals(rows.drop(4).map { it.name.lowercase(java.util.Locale.ROOT) }.sorted(),
            rows.drop(4).map { it.name.lowercase(java.util.Locale.ROOT) })
    }

    @Test fun listAndShowUseVisibleLocalizedNamesAndNotStorageIndicesOrRawSummaryData() {
        val slow = location("2")
        val fast = location("First", 1081)
        val state = MainUiState(profileSourceMode = ProfileSourceMode.SUBSCRIPTION, currentLocations = listOf(slow, fast),
            locationBenchmarkDetails = mapOf(slow to "2: tcp=90ms", fast to "First: score=1 tcp=2ms"))
        val strings = AppStrings(AppLanguage.RUSSIAN)
        val rows = androidLocationRows(state, strings)
        val listed = AndroidControlLocationInspection.read(state, ControlCommand(ControlOperationId.LOCATIONS_LIST), strings).getOrThrow()
        val objects = (listed.getValue("locations") as ControlValue.ArrayValue).values.map { (it as ControlValue.ObjectValue).values }
        assertEquals(rows.map { ControlValue.Text(it.name) }, objects.map { it["name"] })
        assertEquals(listOf(ControlValue.IntegerValue(1), ControlValue.IntegerValue(2)), objects.map { it["index"] })
        assertTrue(objects.all { it.keys == setOf("index", "name") })
        assertFalse(ControlProtocolCodec.encodeValues(listed).contains("PROFILE_SECRET"))
        fun shown(selector: String) = AndroidControlLocationInspection.read(state, ControlCommand(ControlOperationId.LOCATIONS_SHOW,
            mapOf("selector" to ControlValue.Text(selector))), strings).getOrThrow().getValue("configuration")
        assertEquals(ControlValue.Text(LocationConfigs.prettyStoredLocation(fast)), shown("1"))
        assertEquals(ControlValue.Text(LocationConfigs.prettyStoredLocation(slow)), shown("2"))
        assertEquals(shown("1"), shown(rows.first().name))
        assertEquals(shown("2"), shown(strings.locationLabel(state.profileSourceMode, "2")))
        assertTrue((shown("1") as ControlValue.Text).value.contains("PROFILE_SECRET"))
    }

    @Test fun duplicateNamesAndMalformedSelectorsAreTypedAndInvalidRowsRemainExplicitlyRepairable() {
        val state = MainUiState(profileSourceMode = ProfileSourceMode.CURRENT_LOCATIONS,
            currentLocations = listOf(location("Duplicate"), location("Duplicate", 1081), "BROKEN_SECRET"))
        val strings = AppStrings(AppLanguage.ENGLISH)
        fun inspect(arguments: Map<String, ControlValue>) = AndroidControlLocationInspection.read(state,
            ControlCommand(ControlOperationId.LOCATIONS_SHOW, arguments), strings)
        fun error(arguments: Map<String, ControlValue>) = (inspect(arguments).exceptionOrNull() as ControlProtocolException).code
        assertEquals(ControlCode.AMBIGUOUS_LOCATION, error(mapOf("selector" to ControlValue.Text(
            strings.locationLabel(state.profileSourceMode, "Duplicate")))))
        assertEquals(ControlCode.NOT_FOUND, error(mapOf("selector" to ControlValue.Text("MISSING_SECRET"))))
        for (arguments in listOf(emptyMap(), mapOf("selector" to ControlValue.IntegerValue(1)),
            mapOf("selector" to ControlValue.Text("")), mapOf("selector" to ControlValue.Text("1"), "extra" to ControlValue.Text("SECRET")))) {
            assertEquals(ControlCode.INVALID_ARGUMENT, error(arguments))
        }
        assertEquals(ControlValue.Text("BROKEN_SECRET"), inspect(mapOf("selector" to ControlValue.Text(
            strings.get(UiText.INVALID_LOCATION_CONFIG)))).getOrThrow()["configuration"])
    }
}
