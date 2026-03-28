package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.model.VlessProfile
import com.kardinal.vpncontrol.model.RoutingRules
import org.json.JSONArray
import org.json.JSONObject

data class DnsSettings(
    val enabled: Boolean,
    val value: String,
)

object SingBoxConfigFactory {
    private const val DEFAULT_DNS_SERVER = "1.1.1.1"

    fun buildTunConfig(
        profile: VlessProfile,
        dns: DnsSettings,
        routingRules: RoutingRules,
    ): String {
        val directCidrs = JSONArray(
            listOf(
                "127.0.0.0/8",
                "10.0.0.0/8",
                "172.16.0.0/12",
                "192.168.0.0/16",
                "169.254.0.0/16",
            ) + listOfNotNull(dns.value.takeIf { dns.enabled && it.isNotBlank() }?.let { "$it/32" }),
        )

        val dnsServerTag = if (dns.enabled && dns.value.isNotBlank()) "custom-dns" else "remote-dns"
        val dnsServers = JSONArray().apply {
            if (dns.enabled && dns.value.isNotBlank()) {
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

        if (directDomainSuffixes.isNotEmpty()) {
            routeRules.put(
                JSONObject()
                    .put("domain_suffix", JSONArray(directDomainSuffixes))
                    .put("action", "route")
                    .put("outbound", "direct"),
            )
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

        if (routingRules.proxyPackages.isNotEmpty()) {
            tunInbound.put("include_package", JSONArray(routingRules.proxyPackages))
        } else if (routingRules.bypassPackages.isNotEmpty()) {
            tunInbound.put("exclude_package", JSONArray(routingRules.bypassPackages))
        }

        return JSONObject()
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
            .put(
                "route",
                JSONObject()
                    .put("auto_detect_interface", true)
                    .put("default_domain_resolver", dnsServerTag)
                    .put("final", "proxy")
                    .put("rules", routeRules),
            )
            .toString(2)
    }

    fun buildProxyValidationConfig(profile: VlessProfile, httpPort: Int, dns: DnsSettings): String {
        val dnsServer = dns.value.takeIf { dns.enabled && it.isNotBlank() } ?: "1.1.1.1"
        val outbound = buildOutbound(profile)
        val inbounds = JSONArray().put(
            JSONObject()
                .put("type", "http")
                .put("tag", "http-in")
                .put("listen", "127.0.0.1")
                .put("listen_port", httpPort),
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
                    .put("default_domain_resolver", "validation-dns")
                    .put("final", "proxy"),
            )
            .toString(2)
    }

    private fun buildOutbound(profile: VlessProfile): JSONObject {
        val outbound = JSONObject()
            .put("type", "vless")
            .put("tag", "proxy")
            .put("server", profile.server)
            .put("server_port", profile.serverPort)
            .put("uuid", profile.uuid)
            .put("packet_encoding", "xudp")

        if (profile.flow.isNotBlank()) {
            outbound.put("flow", profile.flow)
        }

        if (profile.security.isNotBlank()) {
            val tls = JSONObject()
                .put("enabled", true)
                .put("server_name", profile.sni)
                .put(
                    "utls",
                    JSONObject()
                        .put("enabled", true)
                        .put("fingerprint", profile.fingerprint),
                )
            if (profile.security == "reality") {
                tls.put(
                    "reality",
                    JSONObject()
                        .put("enabled", true)
                        .put("public_key", profile.publicKey)
                        .put("short_id", profile.shortId),
                )
            }
            outbound.put("tls", tls)
        }

        when (profile.network) {
            "ws" -> {
                val transport = JSONObject().put("type", "ws")
                if (profile.path.isNotBlank()) {
                    transport.put("path", profile.path)
                }
                if (profile.hostHeader.isNotBlank()) {
                    transport.put("headers", JSONObject().put("Host", profile.hostHeader))
                }
                outbound.put("transport", transport)
            }
            "grpc" -> {
                val transport = JSONObject().put("type", "grpc")
                if (profile.serviceName.isNotBlank()) {
                    transport.put("service_name", profile.serviceName)
                }
                outbound.put("transport", transport)
            }
        }

        return outbound
    }
}
