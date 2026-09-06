package com.kardinal.vpncontrol.data

import kotlin.test.Test
import kotlin.test.assertEquals

class LocationConfigsRoundTripTest {
    @Test
    fun explicitlyEmptySniSurvivesEditorAndBulkExportRoundTrips() {
        val original = "socks://127.0.0.1:1080#Fixture"
        val profile = LocationConfigs.decodeStoredLocation(original)
        assertEquals("", profile.sni)
        assertEquals(profile, LocationConfigs.parseLocationInput(LocationConfigs.prettyStoredLocation(original)))
        val imported = LocationConfigs.import(LocationConfigs.export(listOf(original)).content).single()
        assertEquals(LocationConfigs.normalizeStoredReference(original), imported)
        assertEquals(profile, LocationConfigs.decodeStoredLocation(imported))
    }

    @Test
    fun omittedSniRetainsLegacyServerDefault() {
        val profile = LocationConfigs.parseLocationInput("""{"protocol":"socks","server":"example.test","server_port":1080}""")
        assertEquals("example.test", profile.sni)
    }
}
