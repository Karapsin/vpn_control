package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.model.StatusMessageKey
import com.kardinal.vpncontrol.model.StatusMessages
import kotlin.test.Test
import kotlin.test.assertEquals

class LocationStatusLogicTest {
    @Test
    fun statusMessagesUseStructuredKeysForLocalization() {
        assertEquals(
            StatusMessageKey.SELECT_LOCATION_FIRST,
            StatusMessages.decode(LocationStatusLogic.selectLocationFirst())?.key,
        )
        assertEquals(
            listOf("Germany"),
            StatusMessages.decode(LocationStatusLogic.checkingLocation("Germany"))?.args,
        )
        assertEquals(
            listOf("Germany"),
            StatusMessages.decode(LocationStatusLogic.testingLocation("Germany"))?.args,
        )
        assertEquals(
            StatusMessageKey.LOCATION_CHECK_CANCELLED,
            StatusMessages.decode(LocationStatusLogic.locationCheckCancelled())?.key,
        )
        assertEquals(
            StatusMessageKey.NO_LOCATIONS_TO_EXPORT,
            StatusMessages.decode(LocationStatusLogic.noLocationsToExport())?.key,
        )
    }
}
