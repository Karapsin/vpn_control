@file:OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)

package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.ProxyProtocol
import com.kardinal.vpncontrol.model.RoutingRules
import com.kardinal.vpncontrol.model.RoutingRuleSet
import com.kardinal.vpncontrol.model.RoutingRuleSetAction
import com.kardinal.vpncontrol.model.RoutingRuleSetFormat
import com.kardinal.vpncontrol.model.RoutingRuleSetSourceType
import com.kardinal.vpncontrol.model.VlessProfile
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
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
    private const val DEFAULT_DNS_SERVER = "1.1.1.1"
    const val DEFAULT_VPN_INTERFACE_NAME = "vpn-control"
    private val json = Json {
        explicitNulls = false
        prettyPrint = true
        prettyPrintIndent = "  "
    }
    private val localDirectCidrs = listOf(
        "127.0.0.0/8",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.0.0/16",
    )

    fun buildProxyOnlyConfig(
        profile: VlessProfile,
        dns: DesktopDnsSettings,
        routingRules: RoutingRules,
        listenPort: Int,
    ): String {
        require(profile.protocol != ProxyProtocol.CUSTOM) {
            "Custom configs are not supported by the desktop proxy runtime yet"
        }
        val customDnsEnabled = dns.enabled && dns.value.isNotBlank()
        val dnsServerTag = if (customDnsEnabled) "custom-dns" else "remote-dns"
        val directCidrs = localDirectCidrs + listOfNotNull(
            dns.value.takeIf { customDnsEnabled }?.let { "$it/32" },
        )

        val routeRules = buildJsonArray {
            add(
                buildJsonObject {
                    put("inbound", "mixed-in")
                    put("action", "sniff")
                    put("timeout", "1s")
                },
            )
            add(
                buildJsonObject {
                    put("ip_cidr", directCidrs.asJsonArray())
                    put("action", "route")
                    put("outbound", "direct")
                },
            )
            if (!routingRules.ignoreRules && routingRules.allDirectDomainSuffixes.isNotEmpty()) {
                add(
                    buildJsonObject {
                        put("domain_suffix", routingRules.allDirectDomainSuffixes.asJsonArray())
                        put("action", "route")
                        put("outbound", "direct")
                    },
                )
            }
            if (!routingRules.ignoreRules) {
                buildRuleSetRouteRules(routingRules.ruleSets).forEach(::add)
            }
        }

        val route = buildJsonObject {
            put("auto_detect_interface", true)
            put("default_domain_resolver", dnsServerTag)
            put("final", "proxy")
            put("rules", routeRules)
            val definitions = buildRuleSetDefinitions(routingRules.ruleSets)
            if (!routingRules.ignoreRules && definitions.isNotEmpty()) {
                put("rule_set", JsonArray(definitions))
            }
        }

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
                buildJsonObject {
                    put(
                        "servers",
                        buildJsonArray {
                            add(
                                if (customDnsEnabled) {
                                    buildJsonObject {
                                        put("type", "udp")
                                        put("tag", "custom-dns")
                                        put("server", dns.value)
                                        put("server_port", 53)
                                    }
                                } else {
                                    buildJsonObject {
                                        put("type", "udp")
                                        put("tag", "remote-dns")
                                        put("server", DEFAULT_DNS_SERVER)
                                        put("server_port", 53)
                                    }
                                },
                            )
                        },
                    )
                    put(
                        "rules",
                        buildJsonArray {
                            add(
                                buildJsonObject {
                                    put("action", "route")
                                    put("server", dnsServerTag)
                                },
                            )
                        },
                    )
                    put("final", dnsServerTag)
                    put("strategy", "prefer_ipv4")
                    put("independent_cache", true)
                },
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
            put("route", route)
            if (!routingRules.ignoreRules && routingRules.ruleSets.any { it.sourceType == RoutingRuleSetSourceType.REMOTE }) {
                put(
                    "experimental",
                    buildJsonObject {
                        put(
                            "cache_file",
                            buildJsonObject {
                                put("enabled", true)
                            },
                        )
                    },
                )
            }
        }
        return json.encodeToString(JsonObject.serializer(), root)
    }

    fun buildVpnConfig(
        profile: VlessProfile,
        dns: DesktopDnsSettings,
        routingRules: RoutingRules,
        interfaceName: String = DEFAULT_VPN_INTERFACE_NAME,
        directProbeRouting: DesktopDirectProbeRouting = DesktopDirectProbeRouting(),
    ): String {
        require(profile.protocol != ProxyProtocol.CUSTOM) {
            "Custom configs are not supported by the desktop VPN runtime yet"
        }
        val customDnsEnabled = dns.enabled && dns.value.isNotBlank()
        val dnsServerTag = if (customDnsEnabled) "custom-dns" else "remote-dns"
        val directCidrs = localDirectCidrs + listOfNotNull(
            dns.value.takeIf { customDnsEnabled }?.let { "$it/32" },
        )

        val routeRules = buildJsonArray {
            add(
                buildJsonObject {
                    put("action", "sniff")
                    put("timeout", "1s")
                },
            )
            buildDirectProbeRouteRules(directProbeRouting).forEach(::add)
            add(
                buildJsonObject {
                    put("type", "logical")
                    put("mode", "or")
                    put(
                        "rules",
                        buildJsonArray {
                            add(buildJsonObject { put("protocol", "dns") })
                            add(buildJsonObject { put("port", 53) })
                        },
                    )
                    put("action", "hijack-dns")
                },
            )
            add(
                buildJsonObject {
                    put("ip_cidr", directCidrs.asJsonArray())
                    put("action", "route")
                    put("outbound", "direct")
                },
            )
            if (!routingRules.ignoreRules && routingRules.allDirectDomainSuffixes.isNotEmpty()) {
                add(
                    buildJsonObject {
                        put("domain_suffix", routingRules.allDirectDomainSuffixes.asJsonArray())
                        put("action", "route")
                        put("outbound", "direct")
                    },
                )
            }
            if (!routingRules.ignoreRules) {
                buildRuleSetRouteRules(routingRules.ruleSets).forEach(::add)
            }
        }

        val route = buildJsonObject {
            put("auto_detect_interface", true)
            put("default_domain_resolver", dnsServerTag)
            put("final", "proxy")
            put("rules", routeRules)
            val definitions = buildRuleSetDefinitions(routingRules.ruleSets)
            if (!routingRules.ignoreRules && definitions.isNotEmpty()) {
                put("rule_set", JsonArray(definitions))
            }
        }

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
                buildJsonObject {
                    put(
                        "servers",
                        buildJsonArray {
                            add(
                                if (customDnsEnabled) {
                                    buildJsonObject {
                                        put("type", "udp")
                                        put("tag", "custom-dns")
                                        put("server", dns.value)
                                        put("server_port", 53)
                                    }
                                } else {
                                    buildJsonObject {
                                        put("type", "udp")
                                        put("tag", "remote-dns")
                                        put("server", DEFAULT_DNS_SERVER)
                                        put("server_port", 53)
                                    }
                                },
                            )
                        },
                    )
                    put(
                        "rules",
                        buildJsonArray {
                            add(
                                buildJsonObject {
                                    put("action", "route")
                                    put("server", dnsServerTag)
                                },
                            )
                        },
                    )
                    put("final", dnsServerTag)
                    put("strategy", "prefer_ipv4")
                    put("independent_cache", true)
                },
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
            put("route", route)
            if (!routingRules.ignoreRules && routingRules.ruleSets.any { it.sourceType == RoutingRuleSetSourceType.REMOTE }) {
                put(
                    "experimental",
                    buildJsonObject {
                        put(
                            "cache_file",
                            buildJsonObject {
                                put("enabled", true)
                            },
                        )
                    },
                )
            }
        }
        return json.encodeToString(JsonObject.serializer(), root)
    }

    private fun buildOutbound(profile: VlessProfile): JsonObject {
        val base = when (profile.protocol) {
            ProxyProtocol.VLESS -> buildJsonObject {
                put("type", "vless")
                put("tag", "proxy")
                put("server", profile.server)
                put("server_port", profile.serverPort)
                put("uuid", profile.uuid)
                put("packet_encoding", "xudp")
                if (profile.flow.isNotBlank()) {
                    put("flow", profile.flow)
                }
            }
            ProxyProtocol.TROJAN -> buildJsonObject {
                put("type", "trojan")
                put("tag", "proxy")
                put("server", profile.server)
                put("server_port", profile.serverPort)
                put("password", profile.password)
            }
            ProxyProtocol.SHADOWSOCKS -> buildJsonObject {
                put("type", "shadowsocks")
                put("tag", "proxy")
                put("server", profile.server)
                put("server_port", profile.serverPort)
                put("method", profile.method)
                put("password", profile.password)
            }
            ProxyProtocol.VMESS -> buildJsonObject {
                put("type", "vmess")
                put("tag", "proxy")
                put("server", profile.server)
                put("server_port", profile.serverPort)
                put("uuid", profile.uuid)
                put("security", profile.vmessSecurity.ifBlank { "auto" })
                put("alter_id", profile.alterId)
                put("packet_encoding", "xudp")
            }
            ProxyProtocol.SOCKS -> buildJsonObject {
                put("type", "socks")
                put("tag", "proxy")
                put("server", profile.server)
                put("server_port", profile.serverPort)
                put("version", "5")
                if (profile.username.isNotBlank()) {
                    put("username", profile.username)
                }
                if (profile.password.isNotBlank()) {
                    put("password", profile.password)
                }
            }
            ProxyProtocol.CUSTOM -> error("Custom configs are not supported by the desktop proxy runtime yet")
        }

        return buildJsonObject {
            base.forEach { (key, value) -> put(key, value) }
            if (profile.network.isNotBlank() &&
                profile.protocol != ProxyProtocol.SHADOWSOCKS &&
                profile.protocol != ProxyProtocol.SOCKS
            ) {
                put("network", profile.network)
            } else if (profile.protocol == ProxyProtocol.SHADOWSOCKS &&
                profile.network.isNotBlank() &&
                profile.network != "tcp"
            ) {
                put("network", profile.network)
            }
            buildTls(profile)?.let { put("tls", it) }
            buildTransport(profile)?.let { put("transport", it) }
        }
    }

    private fun buildTls(profile: VlessProfile): JsonObject? {
        val shouldEnable = when (profile.protocol) {
            ProxyProtocol.VLESS -> profile.security.isNotBlank()
            ProxyProtocol.TROJAN -> true
            ProxyProtocol.VMESS -> profile.security.isNotBlank()
            ProxyProtocol.SHADOWSOCKS, ProxyProtocol.SOCKS, ProxyProtocol.CUSTOM -> false
        }
        if (!shouldEnable) return null

        return buildJsonObject {
            put("enabled", true)
            put("server_name", profile.sni.ifBlank { profile.server })
            put(
                "utls",
                buildJsonObject {
                    put("enabled", true)
                    put("fingerprint", profile.fingerprint.ifBlank { "chrome" })
                },
            )
            if (profile.protocol == ProxyProtocol.VLESS && profile.security == "reality") {
                put(
                    "reality",
                    buildJsonObject {
                        put("enabled", true)
                        put("public_key", profile.publicKey)
                        put("short_id", profile.shortId)
                    },
                )
            }
        }
    }

    private fun buildTransport(profile: VlessProfile): JsonObject? {
        return when (profile.network) {
            "ws" -> buildJsonObject {
                put("type", "ws")
                if (profile.path.isNotBlank()) {
                    put("path", profile.path)
                }
                if (profile.hostHeader.isNotBlank()) {
                    put(
                        "headers",
                        buildJsonObject {
                            put("Host", profile.hostHeader)
                        },
                    )
                }
            }
            "grpc" -> buildJsonObject {
                put("type", "grpc")
                if (profile.serviceName.isNotBlank()) {
                    put("service_name", profile.serviceName)
                }
            }
            else -> null
        }
    }

    private fun buildRuleSetDefinitions(ruleSets: List<RoutingRuleSet>): List<JsonObject> {
        return ruleSets.map { ruleSet ->
            val tag = ruleSetTag(ruleSet)
            when (ruleSet.sourceType) {
                RoutingRuleSetSourceType.INLINE -> buildJsonObject {
                    put("type", "inline")
                    put("tag", tag)
                    put("rules", inlineRuleArray(ruleSet.source))
                }
                RoutingRuleSetSourceType.REMOTE -> buildJsonObject {
                    put("type", "remote")
                    put("tag", tag)
                    put("format", ruleSet.format.label())
                    put("url", ruleSet.source)
                    put("download_detour", "direct")
                    put("update_interval", "${ruleSet.updateIntervalHours.coerceAtLeast(1)}h")
                }
            }
        }
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

    private fun buildRuleSetRouteRules(ruleSets: List<RoutingRuleSet>): List<JsonObject> {
        return ruleSets.map { ruleSet ->
            buildJsonObject {
                put("rule_set", buildJsonArray { add(JsonPrimitive(ruleSetTag(ruleSet))) })
                put("action", "route")
                put(
                    "outbound",
                    when (ruleSet.action) {
                        RoutingRuleSetAction.DIRECT -> "direct"
                        RoutingRuleSetAction.PROXY -> "proxy"
                        RoutingRuleSetAction.BLOCK -> "block"
                    },
                )
            }
        }
    }

    private fun inlineRuleArray(raw: String): JsonArray {
        val trimmed = raw.trim()
        val parsed = json.parseToJsonElement(trimmed)
        return when (parsed) {
            is JsonArray -> parsed
            is JsonObject -> parsed["rules"] as? JsonArray
                ?: error("Inline rule-set JSON must contain a rules array")
            else -> error("Inline rule-set JSON must contain a rules array")
        }
    }

    private fun ruleSetTag(ruleSet: RoutingRuleSet): String {
        val slug = ruleSet.name
            .lowercase()
            .replace(Regex("[^a-z0-9]+"), "-")
            .trim('-')
            .ifBlank { "ruleset" }
        val suffix = ruleSet.id.filter { it.isLetterOrDigit() }.takeLast(8).ifBlank { "set" }
        return "ruleset-$slug-$suffix"
    }

    private fun RoutingRuleSetFormat.label(): String {
        return when (this) {
            RoutingRuleSetFormat.SOURCE -> "source"
            RoutingRuleSetFormat.BINARY -> "binary"
        }
    }

    private fun List<String>.asJsonArray(): JsonArray = buildJsonArray {
        forEach { add(JsonPrimitive(it)) }
    }
}
