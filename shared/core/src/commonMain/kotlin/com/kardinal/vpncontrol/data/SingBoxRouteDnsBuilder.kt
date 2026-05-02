package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.model.RoutingRules
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
    val directCidrs: List<String>,
    val dns: JsonObject,
    val route: JsonObject,
    val experimental: JsonObject?,
)

object SingBoxRouteDnsBuilder {
    const val DEFAULT_DNS_SERVER = "1.1.1.1"
    private val json = Json { explicitNulls = false }
    private val localDirectCidrs = listOf(
        "127.0.0.0/8",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.0.0/16",
    )

    fun buildRouteDnsConfig(
        dnsEnabled: Boolean,
        dnsValue: String,
        routingRules: RoutingRules,
        leadingRouteRules: List<JsonObject> = emptyList(),
    ): SingBoxRouteDnsConfig {
        val customDnsEnabled = dnsEnabled && dnsValue.isNotBlank()
        val dnsServerTag = if (customDnsEnabled) "custom-dns" else "remote-dns"
        val directCidrs = localDirectCidrs + listOfNotNull(
            dnsValue.takeIf { customDnsEnabled }?.let { "$it/32" },
        )
        val routeRules = buildRouteRules(
            routingRules = routingRules,
            directCidrs = directCidrs,
            leadingRouteRules = leadingRouteRules,
        )
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
        return SingBoxRouteDnsConfig(
            dnsServerTag = dnsServerTag,
            directCidrs = directCidrs,
            dns = buildDnsConfig(
                dnsServerTag = dnsServerTag,
                dnsServer = dnsValue.takeIf { customDnsEnabled } ?: DEFAULT_DNS_SERVER,
            ),
            route = route,
            experimental = buildExperimentalConfig(routingRules),
        )
    }

    fun buildValidationDnsConfig(
        dnsEnabled: Boolean,
        dnsValue: String,
    ): JsonObject {
        val dnsServer = dnsValue.takeIf { dnsEnabled && it.isNotBlank() } ?: DEFAULT_DNS_SERVER
        return buildDnsConfig(
            dnsServerTag = "validation-dns",
            dnsServer = dnsServer,
            includeRouteRule = false,
        )
    }

    fun directCidrs(dnsEnabled: Boolean, dnsValue: String): List<String> {
        return localDirectCidrs + listOfNotNull(
            dnsValue.takeIf { dnsEnabled && it.isNotBlank() }?.let { "$it/32" },
        )
    }

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

    fun directCidrRouteRule(directCidrs: List<String>): JsonObject {
        return buildJsonObject {
            put("ip_cidr", directCidrs.asJsonArray())
            put("action", "route")
            put("outbound", "direct")
        }
    }

    private fun buildRouteRules(
        routingRules: RoutingRules,
        directCidrs: List<String>,
        leadingRouteRules: List<JsonObject>,
    ): JsonArray {
        return buildJsonArray {
            leadingRouteRules.forEach(::add)
            add(directCidrRouteRule(directCidrs))
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
    }

    private fun buildDnsConfig(
        dnsServerTag: String,
        dnsServer: String,
        includeRouteRule: Boolean = true,
    ): JsonObject {
        return buildJsonObject {
            put(
                "servers",
                buildJsonArray {
                    add(
                        buildJsonObject {
                            put("type", "udp")
                            put("tag", dnsServerTag)
                            put("server", dnsServer)
                            put("server_port", 53)
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
                                put("server", dnsServerTag)
                            },
                        )
                    },
                )
            }
            put("final", dnsServerTag)
            put("strategy", "prefer_ipv4")
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
