package com.kardinal.vpncontrol.control

import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.model.*
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ControlReadLogicTest {
    @Test
    fun statsUseCapturedStateAndClockWithoutInventingTrafficOrMissingTiming() {
        val state = MainUiState(isVpnRunning = true, sessionStartedAtEpochMillis = 100,
            successfulStarts = 3, successfulStops = 2)
        val command = ControlCommand(ControlOperationId.STATS)
        val values = ControlReadLogic.read(state, command, 250).getOrThrow()
        assertEquals(ControlValue.IntegerValue(150), values["elapsedMillis"])
        assertEquals(ControlValue.IntegerValue(3), values["successfulStarts"])
        assertEquals(ControlValue.Null, values["stoppedAtEpochMillis"])
        assertFalse("rxBytes" in values)
        assertEquals(ControlValue.IntegerValue(0), ControlReadLogic.read(state, command, 50).getOrThrow()["elapsedMillis"])
        assertEquals(ControlValue.Null, ControlReadLogic.read(state.copy(isVpnRunning = false), command, 250)
            .getOrThrow()["elapsedMillis"])
    }

    @Test
    fun logReadsAreBoundedRedactedAndRejectMalformedArguments() {
        val state = MainUiState(connectionLog = listOf(
            ConnectionLogEntry("1", "first", 1),
            ConnectionLogEntry("2", SettingsStatusMessages.homeSshPrivateKeyImportFailed("https://example.test/SECRET"), 2)))
        fun read(value: ControlValue) = ControlReadLogic.read(state,
            ControlCommand(ControlOperationId.LOGS, mapOf("limit" to value)), 0)
        val latest = read(ControlValue.Text("1")).getOrThrow()
        assertEquals(1, (latest.getValue("entries") as ControlValue.ArrayValue).values.size)
        assertFalse(ControlProtocolCodec.encodeValues(latest).contains("SECRET"))
        assertEquals(emptyList(), (read(ControlValue.Text("0")).getOrThrow().getValue("entries") as ControlValue.ArrayValue).values)
        for (value in listOf(ControlValue.Text("-1"), ControlValue.Text("2147483648"), ControlValue.IntegerValue(1), ControlValue.Null))
            assertTrue(read(value).isFailure)
        assertTrue(ControlReadLogic.read(state, ControlCommand(ControlOperationId.LOGS,
            mapOf("unknown" to ControlValue.Text("secret"))), 0).isFailure)
        assertTrue(ControlReadLogic.read(state, ControlCommand(ControlOperationId.STATS,
            mapOf("limit" to ControlValue.Text("1"))), 0).isFailure)
    }

    @Test
    fun sourceKeepsSelectionScopeWithoutExposingConfiguration() {
        val state = MainUiState(profileSourceMode = ProfileSourceMode.SUBSCRIPTION, activeSubscriptionId = "source-id")
        val command = ControlCommand(ControlOperationId.SOURCE_SHOW)
        assertEquals(mapOf("mode" to ControlValue.Text("subscription"), "subscriptionId" to ControlValue.Text("source-id")),
            ControlReadLogic.read(state, command, 0).getOrThrow())
        assertEquals(ControlValue.Null, ControlReadLogic.read(state.copy(profileSourceMode = ProfileSourceMode.CURRENT_LOCATIONS),
            command, 0).getOrThrow()["subscriptionId"])
    }
}
