package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.model.ProxyProfile
import com.kardinal.vpncontrol.model.RoutingRules
import com.kardinal.vpncontrol.model.RoutingRuleSet
import com.kardinal.vpncontrol.model.RoutingRuleSetAction
import com.kardinal.vpncontrol.model.RoutingRuleSetFormat
import com.kardinal.vpncontrol.model.RoutingRuleSetSourceType
import org.json.JSONArray
import org.json.JSONObject

data class DnsSettings(
    val enabled: Boolean,
    val value: String,
)

object SingBoxConfigFactory {
    private const val DEFAULT_DNS_SERVER = "1.1.1.1"
    const val DEFAULT_PROXY_ONLY_PORT = 2080
    private val LOCAL_DIRECT_CIDRS = listOf(
        "127.0.0.0/8",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.0.0/16",
    )

    fun buildTunConfig(
        profile: ProxyProfile,
        dns: DnsSettings,
        routingRules: RoutingRules,
    ): String {
        val customDnsEnabled = dns.enabled && dns.value.isNotBlank()
        val directCidrs = JSONArray(
            LOCAL_DIRECT_CIDRS + listOfNotNull(dns.value.takeIf { customDnsEnabled }?.let { "$it/32" }),
        )

        val dnsServerTag = if (customDnsEnabled) "custom-dns" else "remote-dns"
        val dnsServers = JSONArray().apply {
            if (customDnsEnabled) {
                put(
                    JSONObject()
                        .put("type", "udp")
                        .put("tag", "custom-dns")
                        .put("server", dns.value)
                        .put("server_port", 53),
                )
            } else {
                put(
                    JSONObject()
                        .put("type", "udp")
                        .put("tag", "remote-dns")
                        .put("server", DEFAULT_DNS_SERVER)
                        .put("server_port", 53),
                )
            }
        }

        val directDomainSuffixes = routingRules.allDirectDomainSuffixes
        val routeRules = JSONArray()
            .put(JSONObject().put("action", "sniff").put("timeout", "1s"))
            .put(
                JSONObject()
                    .put("type", "logical")
                    .put("mode", "or")
                    .put(
                        "rules",
                        JSONArray()
                            .put(JSONObject().put("protocol", "dns"))
                            .put(JSONObject().put("port", 53)),
                    )
                    .put("action", "hijack-dns"),
            )
            .put(
                JSONObject()
                    .put("ip_cidr", directCidrs)
                    .put("action", "route")
                    .put("outbound", "direct"),
            )

        if (!routingRules.ignoreRules && directDomainSuffixes.isNotEmpty()) {
            routeRules.put(
                JSONObject()
                    .put("domain_suffix", JSONArray(directDomainSuffixes))
                    .put("action", "route")
                    .put("outbound", "direct"),
            )
        }
        if (!routingRules.ignoreRules) {
            buildRuleSetRouteRules(routingRules.ruleSets).forEach(routeRules::put)
        }

        val tunInbound = JSONObject()
            .put("type", "tun")
            .put("tag", "tun-in")
            .put("interface_name", "vpn-control")
            .put("address", JSONArray().put("172.19.250.1/30"))
            .put("mtu", 1400)
            .put("auto_route", true)
            .put("strict_route", true)
            .put("stack", "system")

        if (!routingRules.ignoreRules && routingRules.proxyPackages.isNotEmpty()) {
            tunInbound.put(
                "include_package",
                JSONArray(routingRules.proxyPackages),
            )
        }

        val route = JSONObject()
            .put("auto_detect_interface", true)
            .put("default_domain_resolver", dnsServerTag)
            .put("final", "proxy")
            .put("rules", routeRules)
        buildRuleSetDefinitions(routingRules.ruleSets)
            .takeIf { it.length() > 0 && !routingRules.ignoreRules }
            ?.let { route.put("rule_set", it) }

        val root = JSONObject()
            .put("log", JSONObject().put("level", "info").put("timestamp", true))
            .put(
                "dns",
                JSONObject()
                    .put("servers", dnsServers)
                    .put(
                        "rules",
                        JSONArray().put(
                            JSONObject()
                                .put("action", "route")
                                .put("server", dnsServerTag),
                        ),
                    )
                    .put("final", dnsServerTag)
                    .put("strategy", "prefer_ipv4")
                    .put("independent_cache", true),
            )
            .put(
                "inbounds",
                JSONArray().put(tunInbound),
            )
            .put(
                "outbounds",
                JSONArray()
                    .put(buildOutbound(profile))
                    .put(JSONObject().put("type", "direct").put("tag", "direct"))
                    .put(JSONObject().put("type", "block").put("tag", "block")),
            )
            .put("route", route)
        if (!routingRules.ignoreRules && routingRules.ruleSets.any { it.sourceType == RoutingRuleSetSourceType.REMOTE }) {
            root.put(
                "experimental",
                JSONObject()
                    .put("cache_file", JSONObject().put("enabled", true)),
            )
        }
        return root.toString(2)
    }

    fun buildProxyValidationConfig(profile: ProxyProfile, httpPort: Int, dns: DnsSettings): String {
        return buildValidationConfig(
            profile = profile,
            listenPort = httpPort,
            dns = dns,
            inboundType = "http",
            inboundTag = "http-in",
        )
    }

    fun buildProxyOnlyConfig(
        profile: ProxyProfile,
        dns: DnsSettings,
        routingRules: RoutingRules,
        listenPort: Int = DEFAULT_PROXY_ONLY_PORT,
    ): String {
        val customDnsEnabled = dns.enabled && dns.value.isNotBlank()
        val directCidrs = JSONArray(
            LOCAL_DIRECT_CIDRS + listOfNotNull(dns.value.takeIf { customDnsEnabled }?.let { "$it/32" }),
        )
        val dnsServerTag = if (customDnsEnabled) "custom-dns" else "remote-dns"
        val dnsServers = JSONArray().apply {
            if (customDnsEnabled) {
                put(
                    JSONObject()
                        .put("type", "udp")
                        .put("tag", "custom-dns")
                        .put("server", dns.value)
                        .put("server_port", 53),
                )
            } else {
                put(
                    JSONObject()
                        .put("type", "udp")
                        .put("tag", "remote-dns")
                        .put("server", DEFAULT_DNS_SERVER)
                        .put("server_port", 53),
                )
            }
        }

        val routeRules = JSONArray()
            .put(
                JSONObject()
                    .put("ip_cidr", directCidrs)
                    .put("action", "route")
                    .put("outbound", "direct"),
            )

        if (!routingRules.ignoreRules && routingRules.allDirectDomainSuffixes.isNotEmpty()) {
            routeRules.put(
                JSONObject()
                    .put("domain_suffix", JSONArray(routingRules.allDirectDomainSuffixes))
                    .put("action", "route")
                    .put("outbound", "direct"),
            )
        }
        if (!routingRules.ignoreRules) {
            buildRuleSetRouteRules(routingRules.ruleSets).forEach(routeRules::put)
        }

        val route = JSONObject()
            .put("auto_detect_interface", true)
            .put("default_domain_resolver", dnsServerTag)
            .put("final", "proxy")
            .put("rules", routeRules)
        buildRuleSetDefinitions(routingRules.ruleSets)
            .takeIf { it.length() > 0 && !routingRules.ignoreRules }
            ?.let { route.put("rule_set", it) }

        val root = JSONObject()
            .put("log", JSONObject().put("level", "info").put("timestamp", true))
            .put(
                "dns",
                JSONObject()
                    .put("servers", dnsServers)
                    .put(
                        "rules",
                        JSONArray().put(
                            JSONObject()
                                .put("action", "route")
                                .put("server", dnsServerTag),
                        ),
                    )
                    .put("final", dnsServerTag)
                    .put("strategy", "prefer_ipv4")
                    .put("independent_cache", true),
            )
            .put(
                "inbounds",
                JSONArray().put(
                    JSONObject()
                        .put("type", "mixed")
                        .put("tag", "mixed-in")
                        .put("listen", "127.0.0.1")
                        .put("listen_port", listenPort)
                        .put("sniff", true),
                ),
            )
            .put(
                "outbounds",
                JSONArray()
                    .put(buildOutbound(profile))
                    .put(JSONObject().put("type", "direct").put("tag", "direct"))
                    .put(JSONObject().put("type", "block").put("tag", "block")),
            )
            .put("route", route)
        if (!routingRules.ignoreRules && routingRules.ruleSets.any { it.sourceType == RoutingRuleSetSourceType.REMOTE }) {
            root.put(
                "experimental",
                JSONObject()
                    .put("cache_file", JSONObject().put("enabled", true)),
            )
        }
        return root.toString(2)
    }

    private fun buildValidationConfig(
        profile: ProxyProfile,
        listenPort: Int,
        dns: DnsSettings,
        inboundType: String,
        inboundTag: String,
    ): String {
        val dnsServer = dns.value.takeIf { dns.enabled && it.isNotBlank() } ?: "1.1.1.1"
        val directCidrs = JSONArray(
            LOCAL_DIRECT_CIDRS + listOfNotNull(
                dns.value.takeIf { dns.enabled && it.isNotBlank() }?.let { "$it/32" },
            ),
        )
        val outbound = buildOutbound(profile)
        val inbounds = JSONArray().put(
            JSONObject()
                .put("type", inboundType)
                .put("tag", inboundTag)
                .put("listen", "127.0.0.1")
                .put("listen_port", listenPort),
        )
        val outbounds = JSONArray()
            .put(outbound)
            .put(JSONObject().put("type", "direct").put("tag", "direct"))
            .put(JSONObject().put("type", "block").put("tag", "block"))
        return JSONObject()
            .put("log", JSONObject().put("level", "warning"))
            .put(
                "dns",
                JSONObject()
                    .put(
                        "servers",
                        JSONArray().put(
                            JSONObject()
                                .put("type", "udp")
                                .put("tag", "validation-dns")
                                .put("server", dnsServer)
                                .put("server_port", 53),
                        ),
                    )
                    .put("final", "validation-dns")
                    .put("strategy", "prefer_ipv4")
                    .put("independent_cache", true),
            )
            .put("inbounds", inbounds)
            .put("outbounds", outbounds)
            .put(
                "route",
                JSONObject()
                    .put(
                        "rules",
                        JSONArray().put(
                            JSONObject()
                                .put("ip_cidr", directCidrs)
                                .put("action", "route")
                                .put("outbound", "direct"),
                        ),
                    )
                    .put("default_domain_resolver", "validation-dns")
                    .put("final", "proxy"),
            )
            .toString(2)
    }

    private fun buildOutbound(profile: ProxyProfile): JSONObject {
        return JSONObject(SingBoxOutboundBuilder.buildOutbound(profile).toString())
    }

    private fun buildRuleSetDefinitions(ruleSets: List<RoutingRuleSet>): JSONArray {
        val definitions = JSONArray()
        ruleSets.forEach { ruleSet ->
            val tag = ruleSetTag(ruleSet)
            when (ruleSet.sourceType) {
                RoutingRuleSetSourceType.INLINE -> {
                    definitions.put(
                        JSONObject()
                            .put("type", "inline")
                            .put("tag", tag)
                            .put("rules", inlineRuleArray(ruleSet.source)),
                    )
                }
                RoutingRuleSetSourceType.REMOTE -> {
                    definitions.put(
                        JSONObject()
                            .put("type", "remote")
                            .put("tag", tag)
                            .put("format", ruleSet.format.label())
                            .put("url", ruleSet.source)
                            .put("download_detour", "direct")
                            .put("update_interval", "${ruleSet.updateIntervalHours.coerceAtLeast(1)}h"),
                    )
                }
            }
        }
        return definitions
    }

    private fun buildRuleSetRouteRules(ruleSets: List<RoutingRuleSet>): List<JSONObject> {
        return ruleSets.map { ruleSet ->
            JSONObject()
                .put("rule_set", JSONArray().put(ruleSetTag(ruleSet)))
                .put("action", "route")
                .put(
                    "outbound",
                    when (ruleSet.action) {
                        RoutingRuleSetAction.DIRECT -> "direct"
                        RoutingRuleSetAction.PROXY -> "proxy"
                        RoutingRuleSetAction.BLOCK -> "block"
                    },
                )
        }
    }

    private fun inlineRuleArray(raw: String): JSONArray {
        val trimmed = raw.trim()
        return if (trimmed.startsWith("[")) {
            JSONArray(trimmed)
        } else {
            JSONObject(trimmed).optJSONArray("rules")
                ?: error("Inline rule-set JSON must contain a rules array")
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

}
