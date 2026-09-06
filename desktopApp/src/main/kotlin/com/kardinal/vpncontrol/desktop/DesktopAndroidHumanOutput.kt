package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.ControlResult
import com.kardinal.vpncontrol.model.ControlValue
import kotlinx.serialization.json.JsonPrimitive

/** Human presentation of an already validated/redacted owner result, not a second status model. */
internal fun desktopAndroidHumanOutput(result: ControlResult): String = buildString {
    fun safe(text: String): String = buildString {
        JsonPrimitive(text).toString().removeSurrounding("\"").forEach { char ->
            if (char.isISOControl()) append("\\u").append(char.code.toString(16).padStart(4, '0'))
            else append(char)
        }
    }
    fun field(name: String, value: ControlValue, indent: String) {
        append(indent).append(safe(name)).append(':')
        when (value) {
            is ControlValue.ObjectValue -> if (value.values.isEmpty()) append(" {}\n") else {
                append('\n')
                value.values.forEach { (key, child) -> field(key, child, "$indent  ") }
            }
            is ControlValue.ArrayValue -> if (value.values.isEmpty()) append(" []\n") else {
                append('\n')
                value.values.forEachIndexed { index, child -> field("[${index + 1}]", child, "$indent  ") }
            }
            else -> {
                append(' ').append(when (value) {
                    ControlValue.Null -> "unknown"
                    is ControlValue.Text -> safe(value.value)
                    is ControlValue.BooleanValue -> value.value.toString()
                    is ControlValue.IntegerValue -> value.value.toString()
                    is ControlValue.DecimalValue -> value.value.toString()
                    else -> error("Container handled above")
                }).append('\n')
            }
        }
    }
    val ownerUnknown = result.controllerId == null || "OWNER_METADATA_UNAVAILABLE" in result.warnings
    appendLine(result.code.wireName)
    appendLine("Controller: ${result.controllerId?.let(::safe) ?: "unknown"}")
    appendLine("Request: ${safe(result.requestId)}")
    appendLine("Revision: ${if (ownerUnknown || "CONFIGURATION_REVISION_UNAVAILABLE" in result.warnings) "unknown" else result.configurationRevision}")
    appendLine("Completion: ${if (result.final) "final" else "pending"}")
    result.operationId?.let { appendLine("Operation: ${safe(it)}") }
    appendLine("Restart required: ${when {
        ownerUnknown || "PENDING_RESTART_STATE_UNAVAILABLE" in result.warnings -> "unknown"
        result.restartRequired -> "yes"
        else -> "no"
    }}")
    if (result.message.isNotBlank() && result.message != result.code.wireName) appendLine("Message: ${safe(result.message)}")
    if (result.warnings.isNotEmpty()) {
        appendLine("Warnings:")
        result.warnings.forEach { appendLine("  - ${safe(it)}") }
    }
    if (result.data.isNotEmpty()) {
        appendLine("Data:")
        result.data.forEach { (key, value) -> field(key, value, "  ") }
    }
}.trimEnd('\n')
