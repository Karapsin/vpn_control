package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.model.LocationStatusMessages
import kotlin.test.Test
import kotlin.test.assertEquals

class LocationStatusLogicTest {
    @Test
    fun statusMessagesUseStructuredKeysForLocalization() {
        assertEquals(
            LocationStatusMessages.selectLocationFirst(),
            LocationStatusLogic.selectLocationFirst(),
        )
        assertEquals(
            LocationStatusMessages.checkingLocation("Germany"),
            LocationStatusLogic.checkingLocation("Germany"),
        )
        assertEquals(
            LocationStatusMessages.testingLocation("Germany"),
            LocationStatusLogic.testingLocation("Germany"),
        )
        assertEquals(
            LocationStatusMessages.locationCheckCancelled(),
            LocationStatusLogic.locationCheckCancelled(),
        )
        assertEquals(
            LocationStatusMessages.noLocationsToExport(),
            LocationStatusLogic.noLocationsToExport(),
        )
    }
}
