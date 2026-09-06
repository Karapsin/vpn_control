package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.*
import com.kardinal.vpncontrol.data.LocationConfigs
import com.kardinal.vpncontrol.data.RoutingRulesTransfer
import com.kardinal.vpncontrol.model.*

/** Called while holding the service's commit monitor. Explicit show preserves usable configuration. */
internal object DesktopControlInspection {
    val operations = ControlReadLogic.operations + (DesktopControlExports.operations - ControlOperationId.DIAGNOSTICS_EXPORT) + setOf(ControlOperationId.LOCATIONS_LIST,
        ControlOperationId.LOCATIONS_SHOW, ControlOperationId.SUBSCRIPTIONS_LIST, ControlOperationId.SUBSCRIPTIONS_SHOW,
        ControlOperationId.ROUTING_SHOW, ControlOperationId.SSH_KEY_STATUS, ControlOperationId.UPDATES_STATUS)

    fun read(service: DesktopAppService, command: ControlCommand, metadata: DesktopControlMetadata): DesktopControlReadSnapshot {
        fun success(values: Map<String, ControlValue>) = DesktopControlReadSnapshot(metadata, Result.success(values))
        fun failure(code: ControlCode) = DesktopControlReadSnapshot(metadata,
            Result.failure(IllegalArgumentException(code.wireName)), code)
        if (command.operation in ControlReadLogic.operations)
            return DesktopControlReadSnapshot(metadata, ControlReadLogic.read(service.state, command, System.currentTimeMillis()))
        if (command.operation in ControlConfigurationInspection.operations) {
            return ControlConfigurationInspection.read(service.state, command, System.currentTimeMillis()).fold(
                { success(it) }, { failure((it as? ControlProtocolException)?.code ?: ControlCode.INVALID_ARGUMENT) })
        }
        if (command.operation !in operations) return failure(ControlCode.UNSUPPORTED)
        // Internal frontend reads bind a rendered configuration, never reinterpret it
        // as a public name/index selector after the list has changed.
        if (command.operation == ControlOperationId.LOCATIONS_SHOW && "id" in command.arguments) {
            val id = (command.arguments["id"] as? ControlValue.Text)?.value
            if (command.arguments.keys != setOf("id") || id.isNullOrBlank()) return failure(ControlCode.INVALID_ARGUMENT)
            val location = service.resolveControlLocation(id).getOrElse { return failure(ControlCode.CONFLICT) }
            return success(mapOf("id" to ControlValue.Text(id),
                "configuration" to ControlValue.Text(LocationConfigs.prettyStoredLocation(location.rawLink))))
        }
        val names = ControlCliParser.schema(command.operation).positional
        if (command.arguments.keys != names.toSet() || command.arguments.values.any { it !is ControlValue.Text || it.value.isBlank() })
            return failure(ControlCode.INVALID_ARGUMENT)
        fun text(name: String) = (command.arguments.getValue(name) as ControlValue.Text).value
        return when (command.operation) {
            ControlOperationId.LOCATIONS_EXPORT -> if (service.state.currentLocations.isEmpty()) failure(ControlCode.NOT_FOUND)
                else success(mapOf("content" to ControlValue.Text(LocationConfigs.export(service.state.currentLocations).content)))
            ControlOperationId.ROUTING_EXPORT -> success(mapOf("content" to ControlValue.Text(
                RoutingRulesTransfer.export(service.state.routingRules).content)))
            ControlOperationId.LOCATIONS_LIST -> success(mapOf("locations" to ControlValue.ArrayValue(
                service.visibleDesktopLocations().mapIndexed { index, record -> ControlValue.ObjectValue(mapOf(
                    "index" to ControlValue.IntegerValue(index.toLong() + 1), "name" to ControlValue.Text(record.name))) })))
            ControlOperationId.LOCATIONS_SHOW -> when (val location = ControlLocationSelection.resolve(text("selector"),
                service.visibleDesktopLocations(), DesktopLocationRecord::name)) {
                is ControlLocationResolution.Rejected -> failure(location.code)
                is ControlLocationResolution.Found -> success(mapOf("configuration" to
                    ControlValue.Text(LocationConfigs.prettyStoredLocation(location.location.rawLink))))
            }
            ControlOperationId.SSH_KEY_STATUS -> success(mapOf("present" to ControlValue.BooleanValue(service.hasHomeSshPrivateKey())))
            ControlOperationId.UPDATES_STATUS -> success(ControlProtocolCodec.decodeValues(service.controlUpdateStatus()))
            else -> failure(ControlCode.UNSUPPORTED)
        }
    }
}
