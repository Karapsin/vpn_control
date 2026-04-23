package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.model.RoutingRules
import org.json.JSONArray
import org.json.JSONObject
import java.time.Instant

data class RoutingRulesExportDocument(
    val fileName: String,
    val content: String,
)

object RoutingRulesTransfer {
    private const val FORMAT_VERSION = 4

    fun export(rules: RoutingRules): RoutingRulesExportDocument {
        val fileName = "vpn-control-routing-rules-${Instant.now().toString().replace(':', '-')}.json"
        val content = JSONObject()
            .put("type", "vpn_control_routing_rules")
            .put("version", FORMAT_VERSION)
            .put("exported_at", Instant.now().toString())
            .put(
                "rules",
                JSONObject()
                    .put("ignore_rules", rules.ignoreRules)
                    .put("proxy_packages", JSONArray(rules.proxyPackages))
                    .put("national_domain_suffixes", JSONArray(rules.nationalDomainSuffixes))
                    .put("direct_domain_suffixes", JSONArray(rules.directDomainSuffixes))
                    .put("rule_sets", JSONArray(RoutingRuleSetCodec.encode(rules.ruleSets).ifBlank { "[]" })),
            )
            .toString(2)
        return RoutingRulesExportDocument(fileName = fileName, content = content)
    }

    fun import(raw: String): RoutingRules {
        val root = JSONObject(raw)
        val rules = root.optJSONObject("rules") ?: root
        require(looksLikeRulesDocument(root, rules)) { "Routing rules JSON format is not recognized" }
        return RoutingRules(
            ignoreRules = rules.optBoolean("ignore_rules", false),
            proxyPackages = RoutingRules.normalizePackageNames(
                readStringArray(rules, "proxy_packages"),
            ),
            bypassPackages = emptyList(),
            nationalDomainSuffixes = RoutingRules.parseNationalDomainSuffixes(
                readStringArray(rules, "national_domain_suffixes").joinToString("\n"),
            ),
            directDomainSuffixes = RoutingRules.parseDirectDomainSuffixes(
                readStringArray(rules, "direct_domain_suffixes").joinToString("\n"),
            ),
            ruleSets = RoutingRuleSetCodec.decode(rules.optJSONArray("rule_sets")?.toString()),
        )
    }

    private fun looksLikeRulesDocument(root: JSONObject, rules: JSONObject): Boolean {
        if (root.has("type") && root.optString("type") == "vpn_control_routing_rules") {
            return true
        }
        return rules.has("ignore_rules") ||
            rules.has("proxy_packages") ||
            rules.has("national_domain_suffixes") ||
            rules.has("direct_domain_suffixes") ||
            rules.has("rule_sets")
    }

    private fun readStringArray(root: JSONObject, key: String): List<String> {
        val array = root.optJSONArray(key) ?: return emptyList()
        return buildList {
            for (index in 0 until array.length()) {
                array.optString(index)
                    .trim()
                    .takeIf { it.isNotBlank() }
                    ?.let(::add)
            }
        }
    }
}
