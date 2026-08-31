package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.model.ProxyProfile
import com.kardinal.vpncontrol.model.RoutingRules
import com.kardinal.vpncontrol.model.DnsSettings
import kotlinx.serialization.json.JsonObject
import org.json.JSONArray
import org.json.JSONObject

object SingBoxConfigFactory {
    const val DEFAULT_PROXY_ONLY_PORT = 2080
    const val DEFAULT_VPN_MANAGEMENT_PROXY_PORT = 2081

    fun buildTunConfig(
        profile: ProxyProfile,
        dns: DnsSettings,
        routingRules: RoutingRules,
        activeVerificationPort: Int? = null,
        homeRoute: HomeSshRouteRuntimeOptions? = null,
    ): String {
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
                add(SingBoxRouteDnsBuilder.dnsHijackRouteRule())
                if (!routingRules.ignoreRules && routingRules.blockQuicUdp443) {
                    add(SingBoxRouteDnsBuilder.quicCompatibilityBlockRouteRule())
                }
            },
            directOutboundTag = directOutboundTag,
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
                buildOutbounds(profile, validatedHomeRoute),
            )
            .put("route", routeDns.route.toAndroidJsonObject())
        routeDns.experimental?.let { root.put("experimental", it.toAndroidJsonObject()) }
        return root.toString(2)
    }

    fun buildProxyValidationConfig(
        profile: ProxyProfile,
        httpPort: Int,
        dns: DnsSettings,
        homeRoute: HomeSshRouteRuntimeOptions? = null,
    ): String {
        return buildValidationConfig(
            profile = profile,
            listenPort = httpPort,
            dns = dns,
            inboundType = "http",
            inboundTag = "http-in",
            homeRoute = homeRoute,
        )
    }

    fun buildProxyOnlyConfig(
        profile: ProxyProfile,
        dns: DnsSettings,
        routingRules: RoutingRules,
        listenPort: Int = DEFAULT_PROXY_ONLY_PORT,
        managementProxyPort: Int? = null,
        homeRoute: HomeSshRouteRuntimeOptions? = null,
    ): String {
        require(managementProxyPort == null || managementProxyPort != listenPort) {
            "Management proxy port must differ from the user proxy port"
        }
        val validatedHomeRoute = homeRoute?.validated()
        val directOutboundTag = validatedHomeRoute?.let { HomeSshRouteConfigBuilder.HOME_EGRESS_TAG } ?: "direct"
        val routeDns = SingBoxRouteDnsBuilder.buildRouteDnsConfig(
            dnsSettings = dns,
            routingRules = routingRules,
            leadingRouteRules = buildList {
                managementProxyPort?.let {
                    add(SingBoxRouteDnsBuilder.sniffRouteRule(inboundTag = HomeSshRouteConfigBuilder.MANAGEMENT_INBOUND_TAG))
                    add(SingBoxRouteDnsBuilder.inboundProxyRouteRule(HomeSshRouteConfigBuilder.MANAGEMENT_INBOUND_TAG))
                }
            },
            directOutboundTag = directOutboundTag,
        )

        val root = JSONObject()
            .put("log", JSONObject().put("level", "info").put("timestamp", true))
            .put("dns", routeDns.dns.toAndroidJsonObject())
            .put(
                "inbounds",
                JSONArray()
                    .put(
                        JSONObject()
                            .put("type", "mixed")
                            .put("tag", "mixed-in")
                            .put("listen", "127.0.0.1")
                            .put("listen_port", listenPort)
                            .put("sniff", true),
                    )
                    .apply {
                        managementProxyPort?.let { port ->
                            put(
                                JSONObject()
                                    .put("type", "mixed")
                                    .put("tag", HomeSshRouteConfigBuilder.MANAGEMENT_INBOUND_TAG)
                                    .put("listen", "127.0.0.1")
                                    .put("listen_port", port),
                            )
                        }
                    },
            )
            .put(
                "outbounds",
                buildOutbounds(profile, validatedHomeRoute),
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
        homeRoute: HomeSshRouteRuntimeOptions?,
    ): String {
        val validatedHomeRoute = homeRoute?.validated()
        val directOutboundTag = validatedHomeRoute?.let { HomeSshRouteConfigBuilder.HOME_EGRESS_TAG } ?: "direct"
        val directCidrs = SingBoxRouteDnsBuilder.directCidrs()
        val inbounds = JSONArray().put(
            JSONObject()
                .put("type", inboundType)
                .put("tag", inboundTag)
                .put("listen", "127.0.0.1")
                .put("listen_port", listenPort),
        )
        val outbounds = buildOutbounds(profile, validatedHomeRoute)
        return JSONObject()
            .put("log", JSONObject().put("level", "warning"))
            .put(
                "dns",
                SingBoxRouteDnsBuilder.buildValidationDnsConfig(dns)
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
                            SingBoxRouteDnsBuilder.directCidrRouteRule(
                                directCidrs,
                                directOutboundTag,
                            ).toAndroidJsonObject(),
                        ),
                    )
                    .put("default_domain_resolver", SingBoxRouteDnsBuilder.SECURE_DNS_SERVER_TAG)
                    .put("final", "proxy"),
            )
            .toString(2)
    }

    private fun buildOutbounds(
        profile: ProxyProfile,
        homeRoute: HomeSshRouteRuntimeOptions?,
    ): JSONArray {
        return JSONArray()
            .put(buildOutbound(profile, homeRoute))
            .apply {
                homeRoute?.let { options ->
                    HomeSshRouteConfigBuilder.buildOutbounds(options).forEach {
                        put(it.toAndroidJsonObject())
                    }
                }
            }
            .put(JSONObject().put("type", "direct").put("tag", "direct"))
            .put(JSONObject().put("type", "block").put("tag", "block"))
    }

    private fun buildOutbound(
        profile: ProxyProfile,
        homeRoute: HomeSshRouteRuntimeOptions?,
    ): JSONObject {
        return JSONObject(
            SingBoxOutboundBuilder.buildOutbound(
                profile = profile,
                domainResolverTag = SingBoxRouteDnsBuilder.BOOTSTRAP_DNS_SERVER_TAG,
                detourTag = homeRoute?.let { HomeSshRouteConfigBuilder.HOME_EGRESS_TAG },
            ).toString(),
        )
    }
}

private fun JsonObject.toAndroidJsonObject(): JSONObject {
    return JSONObject(toString())
}
