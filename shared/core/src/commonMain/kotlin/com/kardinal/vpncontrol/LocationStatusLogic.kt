package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.model.StatusMessages

object LocationStatusLogic {
    fun selectLocationFirst(): String = StatusMessages.selectLocationFirst()

    fun checkingLocation(remarks: String): String = StatusMessages.checkingLocation(remarks)

    fun testingLocation(remarks: String): String = StatusMessages.testingLocation(remarks)

    fun locationCheckCancelled(): String = StatusMessages.locationCheckCancelled()

    fun noLocationsToExport(): String = StatusMessages.noLocationsToExport()
}
