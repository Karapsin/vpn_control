package com.kardinal.vpncontrol.control

import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.data.DiagnosticsSanitizer
import com.kardinal.vpncontrol.model.*

/** Pure projections shared by terminal and platform adapters. Never invent unavailable telemetry. */
object ControlReadLogic {
    val operations = setOf(ControlOperationId.STATS, ControlOperationId.LOGS,
        ControlOperationId.SOURCE_SHOW, ControlOperationId.SETTINGS_LANGUAGES)

    fun read(state: MainUiState, command: ControlCommand, nowMillis: Long): Result<Map<String, ControlValue>> = runCatching {
        require(command.operation in operations)
        val arguments = command.arguments
        val limit = if (command.operation == ControlOperationId.LOGS) {
            require(arguments.keys.all { it == "limit" })
            if ("limit" in arguments) {
                val text = (arguments["limit"] as? ControlValue.Text)?.value
                requireNotNull(text?.toIntOrNull()?.takeIf { it >= 0 })
            } else 100
        } else {
            require(arguments.isEmpty())
            0
        }
        fun timestamp(value: Long): ControlValue = if (value > 0) ControlValue.IntegerValue(value) else ControlValue.Null
        when (command.operation) {
            ControlOperationId.STATS -> mapOf(
                "running" to ControlValue.BooleanValue(state.isVpnRunning),
                "startedAtEpochMillis" to timestamp(state.sessionStartedAtEpochMillis),
                "stoppedAtEpochMillis" to timestamp(state.sessionStoppedAtEpochMillis),
                "elapsedMillis" to if (state.isVpnRunning && state.sessionStartedAtEpochMillis > 0)
                    ControlValue.IntegerValue((nowMillis - state.sessionStartedAtEpochMillis).coerceAtLeast(0)) else ControlValue.Null,
                "successfulStarts" to ControlValue.IntegerValue(state.successfulStarts.toLong()),
                "successfulStops" to ControlValue.IntegerValue(state.successfulStops.toLong()),
            )
            ControlOperationId.LOGS -> mapOf("entries" to ControlValue.ArrayValue(state.connectionLog.takeLast(limit).map {
                ControlValue.ObjectValue(mapOf(
                    "createdAtEpochMillis" to ControlValue.IntegerValue(it.createdAtEpochMillis),
                    "message" to ControlValue.Text(DiagnosticsSanitizer.redactText(it.message)),
                ))
            }))
            ControlOperationId.SOURCE_SHOW -> mapOf(
                "mode" to ControlValue.Text(if (state.profileSourceMode == ProfileSourceMode.CURRENT_LOCATIONS)
                    "current-locations" else "subscription"),
                "subscriptionId" to if (state.profileSourceMode == ProfileSourceMode.SUBSCRIPTION)
                    ControlValue.Text(state.activeSubscriptionId) else ControlValue.Null,
            )
            ControlOperationId.SETTINGS_LANGUAGES -> mapOf("languages" to ControlValue.ArrayValue(AppLanguage.entries.map {
                ControlValue.ObjectValue(mapOf(
                    "code" to ControlValue.Text(if (it == AppLanguage.SYSTEM) "system" else it.code),
                    "name" to ControlValue.Text(it.nativeName),
                ))
            }))
            else -> error("Unsupported read operation")
        }
    }
}
