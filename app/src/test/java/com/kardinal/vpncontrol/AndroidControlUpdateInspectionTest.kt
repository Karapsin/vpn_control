package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.model.ControlValue
import org.junit.Assert.*
import org.junit.Test

class AndroidControlUpdateInspectionTest {
    @Test fun unresolvedOrFailedCheckCannotInventAnAvailabilityVerdictOrLeakRawErrors() {
        for (phase in listOf(AppUpdatePhase.IDLE, AppUpdatePhase.CHECKING, AppUpdatePhase.FAILED)) {
            val data = AndroidControlUpdateInspection.read(AppUpdateState(phase = phase, message = "PRIVATE_PATH",
                releaseNotesUrl = "https://example.com/?token=SECRET"))
            assertEquals(ControlValue.Null, data["available"])
            assertEquals(ControlValue.Null, data["compatible"])
            assertEquals(if (phase == AppUpdatePhase.FAILED) ControlValue.Null else ControlValue.BooleanValue(false), data["checked"])
            assertFalse(data.toString().contains("PRIVATE_PATH"))
            assertFalse(data.toString().contains("SECRET"))
        }
    }

    @Test fun resolvedPhasesExposeActualGuiProgressAndTypedAvailability() {
        for (phase in listOf(AppUpdatePhase.DOWNLOADING, AppUpdatePhase.VERIFYING, AppUpdatePhase.READY, AppUpdatePhase.INSTALLING)) {
            val data = AndroidControlUpdateInspection.read(AppUpdateState(phase = phase, availableVersion = "2.1.1",
                downloadedBytes = 123, totalBytes = 456))
            assertEquals(ControlValue.BooleanValue(true), data["checked"])
            assertEquals(ControlValue.BooleanValue(true), data["available"])
            assertEquals(ControlValue.BooleanValue(true), data["compatible"])
            assertEquals(ControlValue.Text("2.1.1"), data["availableVersion"])
            assertEquals(ControlValue.IntegerValue(123), data["downloadedBytes"])
            assertEquals(ControlValue.IntegerValue(456), data["totalBytes"])
        }
        assertEquals(ControlValue.BooleanValue(false), AndroidControlUpdateInspection.read(
            AppUpdateState(phase = AppUpdatePhase.UP_TO_DATE))["available"])
        assertEquals(ControlValue.BooleanValue(false), AndroidControlUpdateInspection.read(
            AppUpdateState(phase = AppUpdatePhase.UNSUPPORTED))["compatible"])
    }
}
