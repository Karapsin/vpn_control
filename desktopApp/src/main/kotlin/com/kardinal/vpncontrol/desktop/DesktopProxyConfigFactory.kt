@file:OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)

package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.data.SingBoxOutboundBuilder
import com.kardinal.vpncontrol.data.SingBoxRouteDnsBuilder
import com.kardinal.vpncontrol.model.ProxyProfile
import com.kardinal.vpncontrol.model.ProxyProtocol
import com.kardinal.vpncontrol.model.RoutingRules
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

data class DesktopDnsSettings(
    val enabled: Boolean,
    val value: String,
)

object DesktopProxyConfigFactory {
    const val DEFAULT_VPN_INTERFACE_NAME = "vpn-control"
    private val json = Json {
        explicitNulls = false
        prettyPrint = true
        prettyPrintIndent = "  "
    }

    fun buildProxyOnlyConfig(
        profile: ProxyProfile,
        dns: DesktopDnsSettings,
        routingRules: RoutingRules,
        listenPort: Int,
    ): String {
        require(profile.protocol != ProxyProtocol.CUSTOM) {
            "Custom configs are not supported by the desktop proxy runtime yet"
        }
        val routeDns = SingBoxRouteDnsBuilder.buildRouteDnsConfig(
            dnsEnabled = dns.enabled,
            dnsValue = dns.value,
            routingRules = routingRules,
            leadingRouteRules = listOf(SingBoxRouteDnsBuilder.sniffRouteRule(inboundTag = "mixed-in")),
        )

        val root = buildJsonObject {
            put(
                "log",
                buildJsonObject {
                    put("level", "info")
                    put("timestamp", true)
                },
            )
            put(
                "dns",
                routeDns.dns,
            )
            put(
                "inbounds",
                buildJsonArray {
                    add(
                        buildJsonObject {
                            put("type", "mixed")
                            put("tag", "mixed-in")
                            put("listen", "127.0.0.1")
                            put("listen_port", listenPort)
                        },
                    )
                },
            )
            put(
                "outbounds",
                buildJsonArray {
                    add(buildOutbound(profile))
                    add(buildJsonObject { put("type", "direct"); put("tag", "direct") })
                    add(buildJsonObject { put("type", "block"); put("tag", "block") })
                },
            )
            put("route", routeDns.route)
            routeDns.experimental?.let { put("experimental", it) }
        }
        return json.encodeToString(JsonObject.serializer(), root)
    }

    fun buildVpnConfig(
        profile: ProxyProfile,
        dns: DesktopDnsSettings,
        routingRules: RoutingRules,
        interfaceName: String = DEFAULT_VPN_INTERFACE_NAME,
        directProbeRouting: DesktopDirectProbeRouting = DesktopDirectProbeRouting(),
    ): String {
        require(profile.protocol != ProxyProtocol.CUSTOM) {
            "Custom configs are not supported by the desktop VPN runtime yet"
        }
        val routeDns = SingBoxRouteDnsBuilder.buildRouteDnsConfig(
            dnsEnabled = dns.enabled,
            dnsValue = dns.value,
            routingRules = routingRules,
            leadingRouteRules = listOf(SingBoxRouteDnsBuilder.sniffRouteRule()) +
                buildDirectProbeRouteRules(directProbeRouting) +
                listOf(SingBoxRouteDnsBuilder.dnsHijackRouteRule()),
        )

        val root = buildJsonObject {
            put(
                "log",
                buildJsonObject {
                    put("level", "info")
                    put("timestamp", true)
                },
            )
            put(
                "dns",
                routeDns.dns,
            )
            put(
                "inbounds",
                buildJsonArray {
                    add(
                        buildJsonObject {
                            put("type", "tun")
                            put("tag", "tun-in")
                            put("interface_name", interfaceName)
                            put("address", listOf("172.19.250.1/30").asJsonArray())
                            put("mtu", 1400)
                            put("auto_route", true)
                            put("strict_route", true)
                            put("stack", "system")
                        },
                    )
                },
            )
            put(
                "outbounds",
                buildJsonArray {
                    add(buildOutbound(profile))
                    add(buildJsonObject { put("type", "direct"); put("tag", "direct") })
                    add(buildJsonObject { put("type", "block"); put("tag", "block") })
                },
            )
            put("route", routeDns.route)
            routeDns.experimental?.let { put("experimental", it) }
        }
        return json.encodeToString(JsonObject.serializer(), root)
    }

    private fun buildOutbound(profile: ProxyProfile): JsonObject {
        return SingBoxOutboundBuilder.buildOutbound(
            profile = profile,
            customConfigErrorMessage = "Custom configs are not supported by the desktop proxy runtime yet",
        )
    }

    private fun buildDirectProbeRouteRules(routing: DesktopDirectProbeRouting): List<JsonObject> {
        val processNames = routing.processNames
            .map(String::trim)
            .filter(String::isNotEmpty)
            .distinct()
        val processPaths = routing.processPaths
            .map(String::trim)
            .filter(String::isNotEmpty)
            .distinct()
        return buildList {
            if (processNames.isNotEmpty()) {
                add(
                    buildJsonObject {
                        put("process_name", processNames.asJsonArray())
                        put("action", "route")
                        put("outbound", "direct")
                    },
                )
            }
            if (processPaths.isNotEmpty()) {
                add(
                    buildJsonObject {
                        put("process_path", processPaths.asJsonArray())
                        put("action", "route")
                        put("outbound", "direct")
                    },
                )
            }
        }
    }

    private fun List<String>.asJsonArray(): JsonArray = buildJsonArray {
        forEach { add(JsonPrimitive(it)) }
    }
}
