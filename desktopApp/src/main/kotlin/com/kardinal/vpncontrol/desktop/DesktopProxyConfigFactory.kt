@file:OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)

package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.data.SingBoxOutboundBuilder
import com.kardinal.vpncontrol.data.HomeSshRouteConfigBuilder
import com.kardinal.vpncontrol.data.HomeSshRouteRuntimeOptions
import com.kardinal.vpncontrol.data.SingBoxRouteDnsBuilder
import com.kardinal.vpncontrol.model.ProxyProfile
import com.kardinal.vpncontrol.model.ProxyProtocol
import com.kardinal.vpncontrol.model.RoutingRules
import com.kardinal.vpncontrol.model.DnsSettings
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

object DesktopProxyConfigFactory {
    const val DEFAULT_VPN_INTERFACE_NAME = "vpn-control"
    private val json = Json {
        explicitNulls = false
        prettyPrint = true
        prettyPrintIndent = "  "
    }

    fun buildProxyOnlyConfig(
        profile: ProxyProfile,
        dns: DnsSettings,
        routingRules: RoutingRules,
        listenPort: Int,
        managementProxyPort: Int? = null,
        homeRoute: HomeSshRouteRuntimeOptions? = null,
    ): String {
        require(profile.protocol != ProxyProtocol.CUSTOM) {
            "Custom configs are not supported by the desktop proxy runtime yet"
        }
        require(managementProxyPort == null || managementProxyPort != listenPort) {
            "Management proxy port must differ from the user proxy port"
        }
        val validatedHomeRoute = homeRoute?.validated()
        val directOutboundTag = validatedHomeRoute?.let { HomeSshRouteConfigBuilder.HOME_EGRESS_TAG } ?: "direct"
        val routeDns = SingBoxRouteDnsBuilder.buildRouteDnsConfig(
            dnsSettings = dns,
            routingRules = routingRules,
            leadingRouteRules = buildList {
                add(SingBoxRouteDnsBuilder.sniffRouteRule(inboundTag = "mixed-in"))
                managementProxyPort?.let {
                    add(SingBoxRouteDnsBuilder.sniffRouteRule(inboundTag = HomeSshRouteConfigBuilder.MANAGEMENT_INBOUND_TAG))
                    add(SingBoxRouteDnsBuilder.inboundProxyRouteRule(HomeSshRouteConfigBuilder.MANAGEMENT_INBOUND_TAG))
                }
            },
            directOutboundTag = directOutboundTag,
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
                    managementProxyPort?.let { port ->
                        add(
                            buildJsonObject {
                                put("type", "mixed")
                                put("tag", HomeSshRouteConfigBuilder.MANAGEMENT_INBOUND_TAG)
                                put("listen", "127.0.0.1")
                                put("listen_port", port)
                            },
                        )
                    }
                },
            )
            put(
                "outbounds",
                buildOutbounds(profile, validatedHomeRoute),
            )
            put("route", routeDns.route)
            routeDns.experimental?.let { put("experimental", it) }
        }
        return json.encodeToString(JsonObject.serializer(), root)
    }

    fun buildVpnConfig(
        profile: ProxyProfile,
        dns: DnsSettings,
        routingRules: RoutingRules,
        interfaceName: String = DEFAULT_VPN_INTERFACE_NAME,
        directProbeRouting: DesktopDirectProbeRouting = DesktopDirectProbeRouting(),
        activeVerificationPort: Int? = null,
        homeRoute: HomeSshRouteRuntimeOptions? = null,
    ): String {
        require(profile.protocol != ProxyProtocol.CUSTOM) {
            "Custom configs are not supported by the desktop VPN runtime yet"
        }
        val validatedHomeRoute = homeRoute?.validated()
        val directOutboundTag = validatedHomeRoute?.let { HomeSshRouteConfigBuilder.HOME_EGRESS_TAG } ?: "direct"
        val routeDns = SingBoxRouteDnsBuilder.buildRouteDnsConfig(
            dnsSettings = dns,
            routingRules = routingRules,
            leadingRouteRules = buildList {
                add(SingBoxRouteDnsBuilder.sniffRouteRule())
                if (activeVerificationPort != null) {
                    add(SingBoxRouteDnsBuilder.sniffRouteRule(inboundTag = "active-verify-in"))
                    add(SingBoxRouteDnsBuilder.inboundProxyRouteRule("active-verify-in"))
                }
            } +
                buildDirectProbeRouteRules(directProbeRouting) +
                listOf(SingBoxRouteDnsBuilder.dnsHijackRouteRule()),
            directOutboundTag = directOutboundTag,
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
                            // Keep the destinations that the shared route builder marks direct
                            // out of the TUN routing table as well.  Otherwise the Windows system
                            // stack can reinject a loopback SOCKS endpoint into the TUN and turn
                            // the outbound's SOCKS handshake into a raw direct connection.
                            put("route_exclude_address", routeDns.directCidrs.asJsonArray())
                            put("strict_route", true)
                            put("stack", "system")
                        },
                    )
                    if (activeVerificationPort != null) {
                        add(
                            buildJsonObject {
                                put("type", "mixed")
                                put("tag", "active-verify-in")
                                put("listen", "127.0.0.1")
                                put("listen_port", activeVerificationPort)
                            },
                        )
                    }
                },
            )
            put(
                "outbounds",
                buildOutbounds(profile, validatedHomeRoute),
            )
            put("route", routeDns.route)
            routeDns.experimental?.let { put("experimental", it) }
        }
        return json.encodeToString(JsonObject.serializer(), root)
    }

    private fun buildOutbounds(
        profile: ProxyProfile,
        homeRoute: HomeSshRouteRuntimeOptions?,
    ): JsonArray {
        return buildJsonArray {
            add(buildOutbound(profile, homeRoute))
            homeRoute?.let { HomeSshRouteConfigBuilder.buildOutbounds(it).forEach(::add) }
            add(buildJsonObject { put("type", "direct"); put("tag", "direct") })
            add(buildJsonObject { put("type", "block"); put("tag", "block") })
        }
    }

    private fun buildOutbound(
        profile: ProxyProfile,
        homeRoute: HomeSshRouteRuntimeOptions?,
    ): JsonObject {
        return SingBoxOutboundBuilder.buildOutbound(
            profile = profile,
            domainResolverTag = SingBoxRouteDnsBuilder.BOOTSTRAP_DNS_SERVER_TAG,
            detourTag = homeRoute?.let { HomeSshRouteConfigBuilder.HOME_EGRESS_TAG },
            customConfigErrorMessage = "Custom configs are not supported by the desktop proxy runtime yet",
        )
    }

    internal fun buildDirectProbeRouteRules(
        routing: DesktopDirectProbeRouting,
        outboundTag: String = "direct",
    ): List<JsonObject> {
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
                        put("outbound", outboundTag)
                    },
                )
            }
            if (processPaths.isNotEmpty()) {
                add(
                    buildJsonObject {
                        put("process_path", processPaths.asJsonArray())
                        put("action", "route")
                        put("outbound", outboundTag)
                    },
                )
            }
        }
    }

    private fun List<String>.asJsonArray(): JsonArray = buildJsonArray {
        forEach { add(JsonPrimitive(it)) }
    }
}
