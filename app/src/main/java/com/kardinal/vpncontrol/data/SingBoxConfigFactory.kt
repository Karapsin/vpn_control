package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.model.ProxyProfile
import com.kardinal.vpncontrol.model.RoutingRules
import kotlinx.serialization.json.JsonObject
import org.json.JSONArray
import org.json.JSONObject

data class DnsSettings(
    val enabled: Boolean,
    val value: String,
)

object SingBoxConfigFactory {
    const val DEFAULT_PROXY_ONLY_PORT = 2080

    fun buildTunConfig(
        profile: ProxyProfile,
        dns: DnsSettings,
        routingRules: RoutingRules,
        activeVerificationPort: Int? = null,
    ): String {
        val routeDns = SingBoxRouteDnsBuilder.buildRouteDnsConfig(
            dnsEnabled = dns.enabled,
            dnsValue = dns.value,
            routingRules = routingRules,
            leadingRouteRules = buildList {
                add(SingBoxRouteDnsBuilder.sniffRouteRule())
                if (activeVerificationPort != null) {
                    add(SingBoxRouteDnsBuilder.sniffRouteRule(inboundTag = "active-verify-in"))
                    add(SingBoxRouteDnsBuilder.inboundProxyRouteRule("active-verify-in"))
                }
                add(SingBoxRouteDnsBuilder.dnsHijackRouteRule())
            },
        )

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

        val root = JSONObject()
            .put("log", JSONObject().put("level", "info").put("timestamp", true))
            .put("dns", routeDns.dns.toAndroidJsonObject())
            .put(
                "inbounds",
                JSONArray().put(tunInbound).apply {
                    if (activeVerificationPort != null) {
                        put(
                            JSONObject()
                                .put("type", "mixed")
                                .put("tag", "active-verify-in")
                                .put("listen", "127.0.0.1")
                                .put("listen_port", activeVerificationPort),
                        )
                    }
                },
            )
            .put(
                "outbounds",
                JSONArray()
                    .put(buildOutbound(profile))
                    .put(JSONObject().put("type", "direct").put("tag", "direct"))
                    .put(JSONObject().put("type", "block").put("tag", "block")),
            )
            .put("route", routeDns.route.toAndroidJsonObject())
        routeDns.experimental?.let { root.put("experimental", it.toAndroidJsonObject()) }
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
        val routeDns = SingBoxRouteDnsBuilder.buildRouteDnsConfig(
            dnsEnabled = dns.enabled,
            dnsValue = dns.value,
            routingRules = routingRules,
        )

        val root = JSONObject()
            .put("log", JSONObject().put("level", "info").put("timestamp", true))
            .put("dns", routeDns.dns.toAndroidJsonObject())
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
            .put("route", routeDns.route.toAndroidJsonObject())
        routeDns.experimental?.let { root.put("experimental", it.toAndroidJsonObject()) }
        return root.toString(2)
    }

    private fun buildValidationConfig(
        profile: ProxyProfile,
        listenPort: Int,
        dns: DnsSettings,
        inboundType: String,
        inboundTag: String,
    ): String {
        val directCidrs = SingBoxRouteDnsBuilder.directCidrs(
            dnsEnabled = dns.enabled,
            dnsValue = dns.value,
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
                SingBoxRouteDnsBuilder.buildValidationDnsConfig(dns.enabled, dns.value)
                    .toAndroidJsonObject(),
            )
            .put("inbounds", inbounds)
            .put("outbounds", outbounds)
            .put(
                "route",
                JSONObject()
                    .put(
                        "rules",
                        JSONArray().put(
                            SingBoxRouteDnsBuilder.directCidrRouteRule(directCidrs).toAndroidJsonObject(),
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
}

private fun JsonObject.toAndroidJsonObject(): JSONObject {
    return JSONObject(toString())
}
