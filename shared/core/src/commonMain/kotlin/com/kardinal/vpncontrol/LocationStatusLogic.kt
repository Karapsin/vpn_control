package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.model.LocationStatusMessages

object LocationStatusLogic {
    fun selectLocationFirst(): String = LocationStatusMessages.selectLocationFirst()

    fun checkingLocation(remarks: String): String = LocationStatusMessages.checkingLocation(remarks)

    fun testingLocation(remarks: String): String = LocationStatusMessages.testingLocation(remarks)

    fun locationCheckCancelled(): String = LocationStatusMessages.locationCheckCancelled()

    fun noLocationsToExport(): String = LocationStatusMessages.noLocationsToExport()
}
