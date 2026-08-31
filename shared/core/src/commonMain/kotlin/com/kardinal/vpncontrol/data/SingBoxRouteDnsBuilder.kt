package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.model.RoutingRules
import com.kardinal.vpncontrol.model.DnsSettings
import com.kardinal.vpncontrol.model.RoutingRuleSet
import com.kardinal.vpncontrol.model.RoutingRuleSetAction
import com.kardinal.vpncontrol.model.RoutingRuleSetFormat
import com.kardinal.vpncontrol.model.RoutingRuleSetSourceType
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

data class SingBoxRouteDnsConfig(
    val dnsServerTag: String,
    val bootstrapDnsServerTag: String,
    val directCidrs: List<String>,
    val dns: JsonObject,
    val route: JsonObject,
    val experimental: JsonObject?,
)

object SingBoxRouteDnsBuilder {
    const val BOOTSTRAP_DNS_SERVER = "1.1.1.1"
    const val BOOTSTRAP_DNS_SERVER_TAG = "bootstrap-dns"
    const val SECURE_DNS_SERVER_TAG = "secure-dns"
    private val json = Json { explicitNulls = false }
    private val localDirectCidrs = listOf(
        "127.0.0.0/8",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.0.0/16",
    )

    fun buildRouteDnsConfig(
        dnsSettings: DnsSettings,
        routingRules: RoutingRules,
        leadingRouteRules: List<JsonObject> = emptyList(),
        directOutboundTag: String = "direct",
    ): SingBoxRouteDnsConfig {
        val directCidrs = directCidrs()
        val routeRules = buildRouteRules(
            routingRules = routingRules,
            directCidrs = directCidrs,
            leadingRouteRules = leadingRouteRules,
            directOutboundTag = directOutboundTag,
        )
        val route = buildJsonObject {
            put("auto_detect_interface", true)
            put("default_domain_resolver", SECURE_DNS_SERVER_TAG)
            put("final", "proxy")
            put("rules", routeRules)
            val definitions = buildRuleSetDefinitions(routingRules.ruleSets, directOutboundTag)
            if (!routingRules.ignoreRules && definitions.isNotEmpty()) {
                put("rule_set", JsonArray(definitions))
            }
        }
        return SingBoxRouteDnsConfig(
            dnsServerTag = SECURE_DNS_SERVER_TAG,
            bootstrapDnsServerTag = BOOTSTRAP_DNS_SERVER_TAG,
            directCidrs = directCidrs,
            dns = buildDnsConfig(
                settings = dnsSettings,
            ),
            route = route,
            experimental = buildExperimentalConfig(routingRules),
        )
    }

    fun buildValidationDnsConfig(
        settings: DnsSettings,
    ): JsonObject {
        return buildDnsConfig(
            settings = settings,
            includeRouteRule = false,
        )
    }

    fun directCidrs(): List<String> = localDirectCidrs + "$BOOTSTRAP_DNS_SERVER/32"

    fun sniffRouteRule(inboundTag: String? = null): JsonObject {
        return buildJsonObject {
            inboundTag?.let { put("inbound", it) }
            put("action", "sniff")
            put("timeout", "1s")
        }
    }

    fun dnsHijackRouteRule(): JsonObject {
        return buildJsonObject {
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
        }
    }

    fun inboundProxyRouteRule(inboundTag: String): JsonObject {
        return buildJsonObject {
            put("inbound", inboundTag)
            put("action", "route")
            put("outbound", "proxy")
        }
    }

    fun quicCompatibilityBlockRouteRule(): JsonObject {
        return buildJsonObject {
            put("network", "udp")
            put("port", 443)
            put("action", "route")
            put("outbound", "block")
        }
    }

    fun directCidrRouteRule(
        directCidrs: List<String>,
        outboundTag: String = "direct",
    ): JsonObject {
        return buildJsonObject {
            put("ip_cidr", directCidrs.asJsonArray())
            put("action", "route")
            put("outbound", outboundTag)
        }
    }

    private fun buildRouteRules(
        routingRules: RoutingRules,
        directCidrs: List<String>,
        leadingRouteRules: List<JsonObject>,
        directOutboundTag: String,
    ): JsonArray {
        return buildJsonArray {
            leadingRouteRules.forEach(::add)
            add(directCidrRouteRule(directCidrs, directOutboundTag))
            if (!routingRules.ignoreRules && routingRules.allDirectDomainSuffixes.isNotEmpty()) {
                add(
                    buildJsonObject {
                        put("domain_suffix", routingRules.allDirectDomainSuffixes.asJsonArray())
                        put("action", "route")
                        put("outbound", directOutboundTag)
                    },
                )
            }
            if (!routingRules.ignoreRules) {
                buildRuleSetRouteRules(routingRules.ruleSets, directOutboundTag).forEach(::add)
            }
        }
    }

    private fun buildDnsConfig(
        settings: DnsSettings,
        includeRouteRule: Boolean = true,
    ): JsonObject {
        val endpoint = SecureDnsEndpointParser.resolve(settings)
        return buildJsonObject {
            put(
                "servers",
                buildJsonArray {
                    add(
                        buildJsonObject {
                            put("type", "udp")
                            put("tag", BOOTSTRAP_DNS_SERVER_TAG)
                            put("server", BOOTSTRAP_DNS_SERVER)
                            put("server_port", 53)
                        },
                    )
                    add(
                        buildJsonObject {
                            put(
                                "type",
                                when (endpoint.transport) {
                                    SecureDnsTransport.HTTPS -> "https"
                                    SecureDnsTransport.TLS -> "tls"
                                },
                            )
                            put("tag", SECURE_DNS_SERVER_TAG)
                            put("server", endpoint.server)
                            put("server_port", endpoint.serverPort)
                            if (endpoint.transport == SecureDnsTransport.HTTPS) {
                                put("path", endpoint.path)
                            }
                            put("detour", "proxy")
                            if (endpoint.requiresBootstrap) {
                                put("domain_resolver", BOOTSTRAP_DNS_SERVER_TAG)
                            }
                            put(
                                "tls",
                                buildJsonObject {
                                    put("enabled", true)
                                    put("server_name", endpoint.server)
                                },
                            )
                        },
                    )
                },
            )
            if (includeRouteRule) {
                put(
                    "rules",
                    buildJsonArray {
                        add(
                            buildJsonObject {
                                put("action", "route")
                                put("server", SECURE_DNS_SERVER_TAG)
                            },
                        )
                    },
                )
            }
            put("final", SECURE_DNS_SERVER_TAG)
            put("strategy", "ipv4_only")
            put("independent_cache", true)
        }
    }

    private fun buildExperimentalConfig(routingRules: RoutingRules): JsonObject? {
        if (routingRules.ignoreRules || routingRules.ruleSets.none { it.sourceType == RoutingRuleSetSourceType.REMOTE }) {
            return null
        }
        return buildJsonObject {
            put(
                "cache_file",
                buildJsonObject {
                    put("enabled", true)
                },
            )
        }
    }

    private fun buildRuleSetDefinitions(
        ruleSets: List<RoutingRuleSet>,
        directOutboundTag: String,
    ): List<JsonObject> {
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
                    put("download_detour", directOutboundTag)
                    put("update_interval", "${ruleSet.updateIntervalHours.coerceAtLeast(1)}h")
                }
            }
        }
    }

    private fun buildRuleSetRouteRules(
        ruleSets: List<RoutingRuleSet>,
        directOutboundTag: String,
    ): List<JsonObject> {
        return ruleSets.map { ruleSet ->
            buildJsonObject {
                put("rule_set", buildJsonArray { add(JsonPrimitive(ruleSetTag(ruleSet))) })
                put("action", "route")
                put(
                    "outbound",
                    when (ruleSet.action) {
                        RoutingRuleSetAction.DIRECT -> directOutboundTag
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
