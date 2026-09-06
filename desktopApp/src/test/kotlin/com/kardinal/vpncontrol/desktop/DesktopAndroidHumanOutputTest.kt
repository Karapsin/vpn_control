package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.ControlProtocolCodec
import com.kardinal.vpncontrol.model.*
import kotlin.test.*

class DesktopAndroidHumanOutputTest {
    @Test fun nestedValuesAndUnknownMetadataRemainExplicit() {
        val output = desktopAndroidHumanOutput(ControlResult("owner", "request", ControlCode.OK, 0,
            warnings = listOf("CONFIGURATION_REVISION_UNAVAILABLE", "PENDING_RESTART_STATE_UNAVAILABLE"),
            data = mapOf("apps" to ControlValue.ArrayValue(listOf(ControlValue.ObjectValue(mapOf(
                "label" to ControlValue.Text("東京\u009b2J"), "selected" to ControlValue.BooleanValue(false))))))))
        assertContains(output, "Revision: unknown")
        assertContains(output, "Restart required: unknown")
        assertContains(output, "apps:\n    [1]:\n      label: 東京")
        assertContains(output, "selected: false")
        assertFalse(output.contains('\u009b'))
    }
    @Test fun plainStatusRetainsAuthoritativeMetadataWithoutJsonEnvelope() {
        val lines = mutableListOf<String>()
        assertEquals(0, DesktopCli.handleArgs(arrayOf("--android", "status"), printLine = lines::add,
            androidRequest = { request, _, _ -> DesktopCliResponse.success(ControlProtocolCodec.encodeResult(
                ControlResult("android-owner", request.requestId, ControlCode.OK, 7, restartRequired = true,
                    data = mapOf("runtimeRunning" to ControlValue.BooleanValue(true), "activeLocation" to ControlValue.Null),
                    warnings = listOf("ACTIVE_LOCATION_UNAVAILABLE")))) }))
        val output = lines.joinToString("\n")
        assertFalse(output.startsWith("{"))
        assertContains(output, "Controller: android-owner")
        assertContains(output, "Revision: 7")
        assertContains(output, "Restart required: yes")
        assertContains(output, "runtimeRunning: true")
        assertContains(output, "activeLocation: unknown")
        assertContains(output, "ACTIVE_LOCATION_UNAVAILABLE")
    }

    @Test fun plainAsyncAcceptanceNeverLooksFinalAndEscapesTerminalControls() {
        val lines = mutableListOf<String>()
        assertEquals(0, DesktopCli.handleArgs(arrayOf("--android", "--async", "subscriptions", "add", "--source", "https://test.invalid"),
            printLine = lines::add, androidRequest = { request, _, _ ->
                DesktopCliResponse.success(ControlProtocolCodec.encodeResult(ControlResult("owner", request.requestId,
                    ControlCode.ACCEPTED, 3, final = false, operationId = "job-id",
                    data = mapOf("phase" to ControlValue.Text("running"), "name" to ControlValue.Text("東京\u001b[2J")))))
            }))
        val output = lines.joinToString("\n")
        assertContains(output, "ACCEPTED")
        assertContains(output, "Completion: pending")
        assertContains(output, "Operation: job-id")
        assertContains(output, "東京")
        assertFalse(output.contains('\u001b'))
    }

    @Test fun plainLocalFailureDoesNotPresentUnknownRevisionAsZero() {
        val lines = mutableListOf<String>()
        assertEquals(2, DesktopCli.handleArgs(arrayOf("--android", "status"), printLine = lines::add,
            androidRequest = { request, _, _ -> desktopCliJsonFailure(ControlCode.UNAVAILABLE, request.requestId) }))
        val output = lines.joinToString("\n")
        assertContains(output, "UNAVAILABLE")
        assertContains(output, "Revision: unknown")
        assertContains(output, "OWNER_METADATA_UNAVAILABLE")
        assertFalse(output.contains("Revision: 0"))
    }
}
