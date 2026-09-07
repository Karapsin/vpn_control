package com.kardinal.vpncontrol.control

import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.data.RoutingRulesTransfer
import com.kardinal.vpncontrol.data.LocationConfigs
import com.kardinal.vpncontrol.model.*
import kotlinx.datetime.Instant

/** Shared committed configuration reads. Only explicit show returns source URLs. */
object ControlConfigurationInspection {
    val operations = setOf(ControlOperationId.SUBSCRIPTIONS_LIST, ControlOperationId.SUBSCRIPTIONS_SHOW, ControlOperationId.ROUTING_SHOW,
        ControlOperationId.LOCATIONS_EXPORT, ControlOperationId.ROUTING_EXPORT)

    fun read(state: MainUiState, command: ControlCommand, nowMillis: Long,
        domainValues: (List<String>) -> List<ControlValue> = { it.map(ControlValue::Text) },
    ): Result<Map<String, ControlValue>> = try {
        Result.success(readValues(state, command, nowMillis, domainValues))
    } catch (failure: Exception) {
        Result.failure(failure)
    }

    private fun readValues(state: MainUiState, command: ControlCommand, nowMillis: Long,
        domainValues: (List<String>) -> List<ControlValue>,
    ): Map<String, ControlValue> {
        if (command.operation !in operations) throw ControlProtocolException(ControlCode.UNSUPPORTED)
        val expected = if (command.operation == ControlOperationId.SUBSCRIPTIONS_SHOW) setOf("id") else emptySet()
        if (command.arguments.keys != expected || command.arguments.values.any { it !is ControlValue.Text || it.value.isBlank() })
            throw ControlProtocolException(ControlCode.INVALID_ARGUMENT)
        return when (command.operation) {
            ControlOperationId.LOCATIONS_EXPORT -> {
                if (state.currentLocations.isEmpty()) throw ControlProtocolException(ControlCode.NOT_FOUND)
                mapOf("content" to ControlValue.Text(LocationConfigs.export(state.currentLocations,
                    Instant.fromEpochMilliseconds(nowMillis).toString()).content))
            }
            ControlOperationId.ROUTING_EXPORT -> mapOf("content" to ControlValue.Text(
                RoutingRulesTransfer.export(state.routingRules, Instant.fromEpochMilliseconds(nowMillis).toString()).content))
            ControlOperationId.SUBSCRIPTIONS_LIST -> mapOf("subscriptions" to ControlValue.ArrayValue(state.subscriptions.map {
                ControlValue.ObjectValue(mapOf("id" to ControlValue.Text(it.id), "name" to ControlValue.Text(it.customName),
                    "cachedLocations" to ControlValue.IntegerValue(it.cachedLocations.size.toLong())))
            }))
            ControlOperationId.SUBSCRIPTIONS_SHOW -> {
                val id = (command.arguments.getValue("id") as ControlValue.Text).value
                val source = state.subscriptions.singleOrNull { it.id == id } ?: throw ControlProtocolException(ControlCode.NOT_FOUND)
                mapOf("id" to ControlValue.Text(source.id), "name" to ControlValue.Text(source.customName),
                    "source" to ControlValue.Text(source.url), "cachedLocations" to ControlValue.IntegerValue(source.cachedLocations.size.toLong()))
            }
            ControlOperationId.ROUTING_SHOW -> mapOf("routing" to ControlValue.ObjectValue(linkedMapOf(
                "type" to ControlValue.Text(RoutingRulesTransfer.FORMAT_TYPE),
                "version" to ControlValue.IntegerValue(RoutingRulesTransfer.FORMAT_VERSION.toLong()),
                "exported_at" to ControlValue.Text(Instant.fromEpochMilliseconds(nowMillis).toString()),
                "rules" to ControlValue.ObjectValue(linkedMapOf(
                    "ignore_rules" to ControlValue.BooleanValue(state.routingRules.ignoreRules),
                    "block_quic_udp_443" to ControlValue.BooleanValue(state.routingRules.blockQuicUdp443),
                    "proxy_packages" to ControlValue.ArrayValue(state.routingRules.proxyPackages.map(ControlValue::Text)),
                    "direct_domain_suffixes" to ControlValue.ArrayValue(domainValues(state.routingRules.directDomainSuffixes)),
                )),
            )))
            else -> error("Unreachable operation")
        }
    }
}
