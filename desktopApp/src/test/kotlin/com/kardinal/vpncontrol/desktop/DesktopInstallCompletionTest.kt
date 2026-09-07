package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.ControlCode
import com.kardinal.vpncontrol.model.ControlResult
import kotlin.test.*

class DesktopInstallCompletionTest {
    @Test fun onlyProtectedReadyCorrelatedHandoffClosesFrontend() {
        val ready = ControlResult("owner", "install", ControlCode.ACCEPTED, 1, final = false, operationId = "operation",
            data = mapOf("jobId" to com.kardinal.vpncontrol.model.ControlValue.Text("00000000-0000-0000-0000-000000000001"),
                "handoffReady" to com.kardinal.vpncontrol.model.ControlValue.BooleanValue(true)))
        assertTrue(desktopInstallHandoffIsFinal(ready))
        assertFalse(desktopInstallHandoffIsFinal(ready.copy(data = emptyMap())))
    }
    @Test fun acceptanceAndUncertainResultsDoNotCloseFrontend() {
        for (code in ControlCode.entries) {
            for (final in listOf(false, true)) {
                if (code == ControlCode.ACCEPTED && final) continue
                val result = ControlResult("owner", "install", code, 1, final = final, operationId = "job")
                assertEquals(false, desktopInstallHandoffIsFinal(result), "$code/$final")
            }
        }
    }
}
