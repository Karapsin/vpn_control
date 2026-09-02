@file:OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)

package com.kardinal.vpncontrol.data

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put

object SingBoxCustomConfigTransformer {
    const val TRUSTED_DIRECT_BYPASS_OUTBOUND_TAG = "vpn-control-direct-probe"
    private val json = Json {
        explicitNulls = false
        prettyPrint = true
        prettyPrintIndent = "  "
    }
    private val dialableOutboundTypes = setOf(
        "vless",
        "vmess",
        "trojan",
        "shadowsocks",
        "socks",
        "http",
        "hysteria",
        "hysteria2",
        "tuic",
        "anytls",
        "naive",
        "shadowtls",
        "snell",
        "tor",
        "ssh",
        "wireguard",
    )
    private val logicalOutboundTypes = setOf("selector", "urltest", "block", "dns")
    private val localDnsServerTypes = setOf("local", "hosts", "fakeip")
    private val dialableDnsServerTypes = setOf("udp", "tcp", "tls", "https", "quic", "h3")

    fun transform(
        rawConfig: String,
        managementProxyPort: Int,
        homeRoute: HomeSshRouteRuntimeOptions? = null,
        trustedDirectBypassRules: List<JsonObject> = emptyList(),
    ): String {
        require(managementProxyPort in 1..65535) { "Management proxy port must be between 1 and 65535" }
        val root = json.parseToJsonElement(rawConfig) as? JsonObject
            ?: error("Custom config must be a JSON object")
        val originalOutbounds = root["outbounds"] as? JsonArray
            ?: error("Custom config must define outbounds")
        require(originalOutbounds.isNotEmpty()) { "Custom config must define at least one outbound" }
        val originalOutboundObjects = originalOutbounds.map { element ->
            element as? JsonObject ?: error("Custom config outbounds must be JSON objects")
        }
        val tags = originalOutboundObjects.map { it.string("tag") }.filter(String::isNotBlank)
        require(tags.size == tags.distinct().size) { "Custom config outbound tags must be unique" }
        val customEndpointTags = endpointTags(root)
        require((tags + customEndpointTags).size == (tags + customEndpointTags).distinct().size) {
            "Custom config outbound and endpoint tags must be unique"
        }

        val validatedHomeRoute = homeRoute?.validated()
        if (validatedHomeRoute != null) {
            rejectUnsupportedTopLevelNetworkFeatures(root)
            validateOutboundReferences(originalOutboundObjects)
        }
        val reserved = buildSet {
            if (validatedHomeRoute != null) {
                add(HomeSshRouteConfigBuilder.SSH_OUTBOUND_TAG)
                add(HomeSshRouteConfigBuilder.HOME_EGRESS_TAG)
            }
            if (trustedDirectBypassRules.isNotEmpty()) add(TRUSTED_DIRECT_BYPASS_OUTBOUND_TAG)
        }
        if (reserved.isNotEmpty()) {
            require((tags + customEndpointTags).none(reserved::contains)) {
                "Custom config uses a reserved VPN Control outbound tag"
            }
        }

        val routedOutbounds = if (validatedHomeRoute == null) {
            originalOutboundObjects
        } else {
            originalOutboundObjects.map { outbound ->
                routeOutboundThroughHome(outbound, validatedHomeRoute.settings.relayPort)
            } +
                HomeSshRouteConfigBuilder.buildOutbounds(validatedHomeRoute)
        }
        val transformedOutbounds = if (trustedDirectBypassRules.isEmpty()) {
            routedOutbounds
        } else {
            routedOutbounds + buildJsonObject {
                put("type", "direct")
                put("tag", TRUSTED_DIRECT_BYPASS_OUTBOUND_TAG)
            }
        }
        val finalOutbound = (root["route"] as? JsonObject)
            ?.get("final")
            ?.jsonPrimitive
            ?.contentOrNull
            ?.takeIf(String::isNotBlank)
            ?: originalOutboundObjects.firstOrNull()?.string("tag")?.takeIf(String::isNotBlank)
            ?: error("Custom config must tag its first outbound or define route.final")
        val availableRouteTags = transformedOutbounds.map { it.string("tag") }.toMutableSet().apply {
            if (validatedHomeRoute == null) addAll(customEndpointTags)
        }
        require(finalOutbound in availableRouteTags) {
            "Custom config route.final references an unknown outbound"
        }
        if (validatedHomeRoute != null) {
            validateRouteOutboundReferences(root["route"] as? JsonObject, availableRouteTags)
        }

        val inbounds = injectManagementInbound(root["inbounds"] as? JsonArray, managementProxyPort)
        val route = injectManagementRoute(
            existing = root["route"] as? JsonObject,
            finalOutbound = finalOutbound,
            homeRouteEnabled = validatedHomeRoute != null,
            trustedDirectBypassRules = trustedDirectBypassRules,
        )
        val dns = if (validatedHomeRoute == null) {
            root["dns"]
        } else {
            injectBootstrapDns(root["dns"] as? JsonObject)
        }

        val transformed = buildJsonObject {
            root.forEach { (key, value) -> put(key, value) }
            put("inbounds", inbounds)
            put("outbounds", JsonArray(transformedOutbounds))
            put("route", route)
            dns?.let { put("dns", it) }
        }
        return json.encodeToString(JsonObject.serializer(), transformed)
    }

    private fun routeOutboundThroughHome(outbound: JsonObject, relayPort: Int): JsonObject {
        val type = outbound.string("type").lowercase()
        require(type.isNotBlank()) { "Custom config outbound type is missing" }
        return when {
            type == "direct" -> buildJsonObject {
                put("type", "socks")
                outbound["tag"]?.let { put("tag", it) }
                put("server", "127.0.0.1")
                put("server_port", relayPort)
                put("version", "5")
                put(
                    "udp_over_tcp",
                    buildJsonObject {
                        put("enabled", true)
                        put("version", 2)
                    },
                )
                put("detour", HomeSshRouteConfigBuilder.SSH_OUTBOUND_TAG)
            }
            type in dialableOutboundTypes -> buildJsonObject {
                outbound.forEach { (key, value) -> put(key, value) }
                if (outbound["detour"] == null) {
                    put("detour", HomeSshRouteConfigBuilder.HOME_EGRESS_TAG)
                }
            }
            type in logicalOutboundTypes -> outbound
            else -> error(
                "Custom config outbound type '$type' cannot be proven to use the SSH route",
            )
        }
    }

    private fun injectManagementInbound(existing: JsonArray?, port: Int): JsonArray {
        val inbounds = existing?.map { it as? JsonObject ?: error("Custom config inbounds must be JSON objects") }
            .orEmpty()
        val inboundTags = inbounds.map { it.string("tag") }.filter(String::isNotBlank)
        require(inboundTags.size == inboundTags.distinct().size) { "Custom config inbound tags must be unique" }
        require(HomeSshRouteConfigBuilder.MANAGEMENT_INBOUND_TAG !in inboundTags) {
            "Custom config uses the reserved management inbound tag"
        }
        require(inbounds.none { it["listen_port"]?.jsonPrimitive?.intOrNull == port }) {
            "Custom config already uses management port $port"
        }
        return buildJsonArray {
            inbounds.forEach(::add)
            add(
                buildJsonObject {
                    put("type", "mixed")
                    put("tag", HomeSshRouteConfigBuilder.MANAGEMENT_INBOUND_TAG)
                    put("listen", "127.0.0.1")
                    put("listen_port", port)
                },
            )
        }
    }

    private fun injectManagementRoute(
        existing: JsonObject?,
        finalOutbound: String,
        homeRouteEnabled: Boolean,
        trustedDirectBypassRules: List<JsonObject>,
    ): JsonObject {
        val current = existing ?: JsonObject(emptyMap())
        val currentRules = current["rules"] as? JsonArray ?: JsonArray(emptyList())
        return buildJsonObject {
            current.forEach { (key, value) -> put(key, value) }
            if (homeRouteEnabled || trustedDirectBypassRules.isNotEmpty()) {
                put("auto_detect_interface", true)
            }
            if (current["final"] == null) put("final", finalOutbound)
            if (homeRouteEnabled && current["rule_set"] != null) {
                put("rule_set", routeRuleSetsThroughHome(current["rule_set"] as? JsonArray))
            }
            put(
                "rules",
                buildJsonArray {
                    add(SingBoxRouteDnsBuilder.sniffRouteRule(HomeSshRouteConfigBuilder.MANAGEMENT_INBOUND_TAG))
                    add(SingBoxRouteDnsBuilder.inboundProxyRouteRule(HomeSshRouteConfigBuilder.MANAGEMENT_INBOUND_TAG).let {
                        buildJsonObject {
                            it.forEach { (key, value) -> put(key, value) }
                            put("outbound", finalOutbound)
                        }
                    })
                    trustedDirectBypassRules.forEach(::add)
                    currentRules.forEach(::add)
                },
            )
        }
    }

    private fun injectBootstrapDns(existing: JsonObject?): JsonObject {
        val current = existing ?: JsonObject(emptyMap())
        val servers = (current["servers"] as? JsonArray)?.map { element ->
            element as? JsonObject ?: error("Custom config DNS servers must be JSON objects")
        }.orEmpty()
        require(servers.none { it.string("tag") == SingBoxRouteDnsBuilder.BOOTSTRAP_DNS_SERVER_TAG }) {
            "Custom config uses the reserved bootstrap DNS tag"
        }
        return buildJsonObject {
            current.forEach { (key, value) -> put(key, value) }
            put(
                "servers",
                buildJsonArray {
                    servers.map(::routeDnsServerThroughHome).forEach(::add)
                    add(
                        buildJsonObject {
                            put("type", "udp")
                            put("tag", SingBoxRouteDnsBuilder.BOOTSTRAP_DNS_SERVER_TAG)
                            put("server", SingBoxRouteDnsBuilder.BOOTSTRAP_DNS_SERVER)
                            put("server_port", 53)
                        },
                    )
                },
            )
        }
    }

    private fun routeDnsServerThroughHome(server: JsonObject): JsonObject {
        val type = server.string("type").lowercase()
        require(type.isNotBlank()) {
            "Legacy or untyped custom DNS servers cannot be proven to use the SSH route"
        }
        return when (type) {
            in localDnsServerTypes -> server
            in dialableDnsServerTypes -> buildJsonObject {
                server.forEach { (key, value) -> put(key, value) }
                if (server["detour"] == null) put("detour", HomeSshRouteConfigBuilder.HOME_EGRESS_TAG)
            }
            else -> error("Custom DNS server type '$type' cannot be proven to use the SSH route")
        }
    }

    private fun routeRuleSetsThroughHome(raw: JsonArray?): JsonArray {
        val definitions = raw ?: error("Custom config route.rule_set must be an array")
        return buildJsonArray {
            definitions.forEach { element ->
                val definition = element as? JsonObject
                    ?: error("Custom config rule-set definitions must be JSON objects")
                when (definition.string("type").lowercase()) {
                    "inline", "local" -> add(definition)
                    "remote" -> add(
                        buildJsonObject {
                            definition.forEach { (key, value) -> put(key, value) }
                            put("download_detour", HomeSshRouteConfigBuilder.HOME_EGRESS_TAG)
                        },
                    )
                    else -> error("Custom rule-set type cannot be proven to use the SSH route")
                }
            }
        }
    }

    private fun validateOutboundReferences(outbounds: List<JsonObject>) {
        val byTag = outbounds.associateBy { it.string("tag") }
        outbounds.forEach { outbound ->
            val type = outbound.string("type").lowercase()
            if (type in setOf("selector", "urltest")) {
                val members = outbound["outbounds"] as? JsonArray
                    ?: error("Custom $type outbound must define an outbounds array")
                members.forEach { member ->
                    val tag = member.jsonPrimitive.contentOrNull.orEmpty()
                    require(tag.isNotBlank() && tag in byTag) { "Custom $type outbound references an unknown outbound" }
                }
            }
        }
        outbounds.forEach { outbound ->
            if (outbound.string("type").lowercase() !in dialableOutboundTypes) return@forEach
            val visited = mutableSetOf<String>()
            var current = outbound
            while (true) {
                val detour = current.string("detour")
                if (detour.isBlank()) break
                require(visited.add(detour)) { "Custom config contains an outbound detour cycle" }
                val target = byTag[detour] ?: error("Custom config outbound detour references an unknown outbound")
                val targetType = target.string("type").lowercase()
                require(targetType == "direct" || targetType in dialableOutboundTypes) {
                    "Custom config outbound detour does not end in a dialable outbound"
                }
                current = target
            }
        }
    }

    private fun validateRouteOutboundReferences(route: JsonObject?, knownTags: Set<String>) {
        fun visit(element: JsonElement) {
            when (element) {
                is JsonObject -> element.forEach { (key, value) ->
                    if (key == "outbound") {
                        val tag = value.jsonPrimitive.contentOrNull.orEmpty()
                        require(tag.isNotBlank() && tag in knownTags) {
                            "Custom config route rule references an unknown outbound"
                        }
                    } else {
                        visit(value)
                    }
                }
                is JsonArray -> element.forEach(::visit)
                else -> Unit
            }
        }
        route?.get("rules")?.let(::visit)
    }

    private fun rejectUnsupportedTopLevelNetworkFeatures(root: JsonObject) {
        listOf("endpoints", "services", "ntp", "certificate", "experimental").forEach { key ->
            val value = root[key] ?: return@forEach
            val empty = when (value) {
                is JsonArray -> value.isEmpty()
                is JsonObject -> value.isEmpty()
                else -> false
            }
            require(empty) { "Custom config '$key' cannot be proven to use the SSH route" }
        }
    }

    private fun endpointTags(root: JsonObject): Set<String> {
        val endpoints = root["endpoints"] as? JsonArray ?: return emptySet()
        return endpoints.map { element ->
            (element as? JsonObject)?.string("tag")?.takeIf(String::isNotBlank)
                ?: error("Custom config endpoints must be tagged JSON objects")
        }.also { tags ->
            require(tags.size == tags.distinct().size) { "Custom config endpoint tags must be unique" }
        }.toSet()
    }

    private fun JsonObject.string(key: String): String {
        return this[key]?.jsonPrimitive?.contentOrNull.orEmpty()
    }
}
