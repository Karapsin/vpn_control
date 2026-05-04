package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.model.RoutingRules
import kotlinx.datetime.Clock
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

data class RoutingRulesExportDocument(
    val fileName: String,
    val content: String,
)

object RoutingRulesTransfer {
    private const val FORMAT_TYPE = "vpn_control_routing_rules"
    private const val FORMAT_VERSION = 6

    fun export(rules: RoutingRules): RoutingRulesExportDocument {
        val timestamp = Clock.System.now().toString()
        val content = PrettyJson.encodeToString(
            JsonObject.serializer(),
            buildJsonObject {
                put("type", JsonPrimitive(FORMAT_TYPE))
                put("version", JsonPrimitive(FORMAT_VERSION))
                put("exported_at", JsonPrimitive(timestamp))
                put(
                    "rules",
                    buildJsonObject {
                        put("ignore_rules", JsonPrimitive(rules.ignoreRules))
                        put("proxy_packages", stringArray(rules.proxyPackages))
                        put("direct_domain_suffixes", stringArray(rules.directDomainSuffixes))
                    },
                )
            },
        )
        return RoutingRulesExportDocument(
            fileName = "vpn-control-routing-rules-${timestamp.replace(':', '-')}.json",
            content = content,
        )
    }

    fun import(raw: String): RoutingRules {
        val root = CompactJson.parseToJsonElement(raw).jsonObject
        val rules = root["rules"]?.jsonObject ?: root
        require(looksLikeRulesDocument(root, rules)) {
            "Routing rules JSON format is not recognized"
        }
        return RoutingRules(
            ignoreRules = rules["ignore_rules"]?.jsonPrimitive?.contentOrNull == "true",
            proxyPackages = RoutingRules.normalizePackageNames(
                readStringArray(rules, "proxy_packages"),
            ),
            bypassPackages = emptyList(),
            directDomainSuffixes = RoutingRules.parseDirectDomainSuffixes(
                readStringArray(rules, "direct_domain_suffixes").joinToString("\n"),
            ),
            ruleSets = emptyList(),
        )
    }

    private fun looksLikeRulesDocument(root: JsonObject, rules: JsonObject): Boolean {
        if (root["type"]?.jsonPrimitive?.contentOrNull == FORMAT_TYPE) {
            return true
        }
        return rules.containsKey("ignore_rules") ||
            rules.containsKey("proxy_packages") ||
            rules.containsKey("national_domain_suffixes") ||
            rules.containsKey("direct_domain_suffixes") ||
            rules.containsKey("rule_sets")
    }

    private fun readStringArray(root: JsonObject, key: String): List<String> {
        val array = root[key]?.jsonArray ?: return emptyList()
        return array.mapNotNull { element ->
            element.jsonPrimitive.contentOrNull
                ?.trim()
                ?.takeIf { it.isNotBlank() }
        }
    }

    private fun stringArray(values: List<String>): JsonArray {
        return JsonArray(values.map(::JsonPrimitive))
    }
}
