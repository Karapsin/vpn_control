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
    private const val FORMAT_VERSION = 1

    fun export(rules: RoutingRules): RoutingRulesExportDocument {
        val fileName = "vpn-control-routing-rules-${Instant.now().toString().replace(':', '-')}.json"
        val content = JSONObject()
            .put("type", "vpn_control_routing_rules")
            .put("version", FORMAT_VERSION)
            .put("exported_at", Instant.now().toString())
            .put(
                "rules",
                JSONObject()
                    .put("proxy_packages", JSONArray(rules.proxyPackages))
                    .put("bypass_packages", JSONArray(rules.bypassPackages))
                    .put("national_domain_suffixes", JSONArray(rules.nationalDomainSuffixes))
                    .put("direct_domain_suffixes", JSONArray(rules.directDomainSuffixes)),
            )
            .toString(2)
        return RoutingRulesExportDocument(fileName = fileName, content = content)
    }

    fun import(raw: String): RoutingRules {
        val root = JSONObject(raw)
        val rules = root.optJSONObject("rules") ?: root
        return RoutingRules(
            proxyPackages = RoutingRules.normalizePackageNames(
                readStringArray(rules, "proxy_packages"),
            ),
            bypassPackages = RoutingRules.normalizePackageNames(
                readStringArray(rules, "bypass_packages"),
            ),
            nationalDomainSuffixes = RoutingRules.parseNationalDomainSuffixes(
                readStringArray(rules, "national_domain_suffixes").joinToString("\n"),
            ),
            directDomainSuffixes = RoutingRules.parseDirectDomainSuffixes(
                readStringArray(rules, "direct_domain_suffixes").joinToString("\n"),
            ),
        )
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
