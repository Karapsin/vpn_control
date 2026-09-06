package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.ControlProtocolCodec
import com.kardinal.vpncontrol.model.*

/** Explicit committed public values only; never retain import content or arbitrary human messages. */
internal object DesktopConfigurationResultData {
    val operations = setOf(ControlOperationId.ROUTING_SET, ControlOperationId.ROUTING_IMPORT, ControlOperationId.LOCATIONS_IMPORT)
    private val routingKeys = setOf("ignore-rules", "block-quic-udp443", "direct-domains")

    fun routing(rules: RoutingRules, key: String? = null): Map<String, ControlValue> {
        val values = mapOf(
            "ignore-rules" to ControlValue.BooleanValue(rules.ignoreRules),
            "block-quic-udp443" to ControlValue.BooleanValue(rules.blockQuicUdp443),
            "direct-domains" to ControlValue.ArrayValue(rules.directDomainSuffixes.map(ControlValue::Text)),
        )
        if (key != null) return mapOf(key to values.getValue(key))
        return values + ("unsupportedFields" to ControlValue.ArrayValue(buildList {
            if (rules.proxyPackages.isNotEmpty()) add(ControlValue.Text("proxyPackages"))
            if (rules.bypassPackages.isNotEmpty()) add(ControlValue.Text("bypassPackages"))
        }))
    }

    fun decode(operation: ControlOperationId, raw: String): Map<String, ControlValue> {
        require(operation in operations)
        return ControlProtocolCodec.decodeValues(raw).also { values ->
            when (operation) {
                ControlOperationId.LOCATIONS_IMPORT -> {
                    require(values.keys == setOf("importedLocations"))
                    require((values.getValue("importedLocations") as ControlValue.IntegerValue).value >= 0)
                }
                else -> {
                    if (operation == ControlOperationId.ROUTING_SET) require(values.size == 1 && values.keys.all { it in routingKeys })
                    else {
                        require(values.keys == routingKeys + "unsupportedFields")
                        val unsupported = (values.getValue("unsupportedFields") as ControlValue.ArrayValue).values
                        require(unsupported.distinct().size == unsupported.size)
                        require(unsupported.all { it is ControlValue.Text && it.value in setOf("proxyPackages", "bypassPackages") })
                    }
                    values.filterKeys { it in routingKeys }.forEach { (key, value) ->
                        if (key == "direct-domains") require((value as ControlValue.ArrayValue).values.all { it is ControlValue.Text })
                        else require(value is ControlValue.BooleanValue)
                    }
                }
            }
        }
    }

    fun warnings(values: Map<String, ControlValue>): List<String> =
        if ((values["unsupportedFields"] as? ControlValue.ArrayValue)?.values?.isNotEmpty() == true)
            listOf("ROUTING_APP_ASSIGNMENTS_UNSUPPORTED") else emptyList()
}
