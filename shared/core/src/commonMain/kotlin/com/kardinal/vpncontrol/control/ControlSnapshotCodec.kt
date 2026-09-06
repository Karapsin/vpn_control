package com.kardinal.vpncontrol.control

import com.kardinal.vpncontrol.model.*

/** Explicit controller DTO transport, never serialization of platform service or Compose state. */
object ControlSnapshotCodec {
    fun encode(snapshot: ControlSnapshot): String = ControlProtocolCodec.encodeValues(snapshot.toControlValues() + mapOf(
        "schemaVersion" to ControlValue.IntegerValue(CONTROL_SCHEMA_VERSION.toLong()),
        "controllerId" to ControlValue.Text(snapshot.controllerId),
        "configurationRevision" to ControlValue.IntegerValue(snapshot.configurationRevision),
        "operations" to ControlValue.ArrayValue(snapshot.operations.map { operation ->
            ControlValue.ObjectValue(mapOf(
                "id" to ControlValue.Text(operation.id),
                "requestId" to ControlValue.Text(operation.requestId),
                "operation" to ControlValue.Text(operation.operation.wireName),
                "phase" to ControlValue.Text(operation.phase.wireName),
                "cancellable" to ControlValue.BooleanValue(operation.cancellable),
                "completedUnits" to operation.completedUnits.value(),
                "totalUnits" to operation.totalUnits.value(),
                "result" to (operation.result?.let {
                    ControlValue.ObjectValue(ControlProtocolCodec.decodeValues(ControlProtocolCodec.encodeResult(it)))
                } ?: ControlValue.Null),
            ))
        }),
    ))

    fun decode(frame: String): ControlSnapshot = try {
        val values = ControlProtocolCodec.decodeValues(frame)
        require(values.keys == setOf("schemaVersion", "controllerId", "configurationRevision", "operations",
            "runtimeRunning", "selectedLocationId", "activeLocationId", "configuredMode", "activeMode",
            "runtimeId", "runtimeStartedAt", "restartRequired"))
        if (values.integer("schemaVersion") != CONTROL_SCHEMA_VERSION.toLong())
            throw ControlProtocolException(ControlCode.INCOMPATIBLE_PROTOCOL)
        val controllerId = values.text("controllerId")
        val operations = (values["operations"] as? ControlValue.ArrayValue)?.values ?: error("INVALID_ARGUMENT")
        val decodedOperations = operations.map { value ->
            val row = (value as? ControlValue.ObjectValue)?.values ?: error("INVALID_ARGUMENT")
            require(row.keys == setOf("id", "requestId", "operation", "phase", "cancellable", "completedUnits", "totalUnits", "result"))
            val id = row.text("id")
            val requestId = row.text("requestId")
            val result = when (val resultValue = row.getValue("result")) {
                ControlValue.Null -> null
                is ControlValue.ObjectValue -> ControlProtocolCodec.decodeResult(ControlProtocolCodec.encodeValues(resultValue.values))
                else -> error("INVALID_ARGUMENT")
            }
            require(result == null || result.controllerId == controllerId && result.requestId == requestId && result.operationId == id)
            ControlOperation(id, requestId,
                ControlOperationId.entries.single { it.wireName == row.text("operation") },
                ControlOperationPhase.entries.single { it.wireName == row.text("phase") },
                row.boolean("cancellable"), row.optionalInteger("completedUnits"), row.optionalInteger("totalUnits"), result)
        }
        require(decodedOperations.map { it.id }.distinct().size == decodedOperations.size)
        ControlSnapshot(controllerId, values.integer("configurationRevision"),
            values.optionalText("selectedLocationId"), values.optionalText("activeLocationId"),
            mode(values.text("configuredMode")), values.optionalText("activeMode")?.let(::mode),
            values.optionalText("runtimeId"), values.optionalInteger("runtimeStartedAt"),
            values.boolean("restartRequired"), decodedOperations, values.boolean("runtimeRunning"))
    } catch (error: ControlProtocolException) {
        throw error
    } catch (_: Exception) {
        throw ControlProtocolException(ControlCode.INVALID_ARGUMENT)
    }

    private fun mode(value: String): AppMode = when (value) {
        "vpn" -> AppMode.VPN
        "proxy-only" -> AppMode.PROXY_ONLY
        else -> error("INVALID_ARGUMENT")
    }
    private fun Long?.value(): ControlValue = this?.let(ControlValue::IntegerValue) ?: ControlValue.Null
    private fun Map<String, ControlValue>.text(key: String): String =
        requireNotNull((getValue(key) as? ControlValue.Text)?.value?.takeIf { it.isNotBlank() })
    private fun Map<String, ControlValue>.optionalText(key: String): String? =
        if (getValue(key) == ControlValue.Null) null else text(key)
    private fun Map<String, ControlValue>.integer(key: String): Long =
        requireNotNull((getValue(key) as? ControlValue.IntegerValue)?.value?.takeIf { it >= 0 })
    private fun Map<String, ControlValue>.optionalInteger(key: String): Long? =
        if (getValue(key) == ControlValue.Null) null else integer(key)
    private fun Map<String, ControlValue>.boolean(key: String): Boolean =
        requireNotNull((getValue(key) as? ControlValue.BooleanValue)?.value)
}
