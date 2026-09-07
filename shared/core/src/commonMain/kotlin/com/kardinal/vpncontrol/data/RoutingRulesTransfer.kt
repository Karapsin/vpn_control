package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.model.RoutingRules
import kotlinx.datetime.Clock
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

data class RoutingRulesExportDocument(
    val fileName: String,
    val content: String,
)

object RoutingRulesTransfer {
    internal const val FORMAT_TYPE = "vpn_control_routing_rules"
    internal const val FORMAT_VERSION = 7

    /** Stream opaque routing JSON independently of control-envelope depth/frame limits. */
    fun import(source: com.kardinal.vpncontrol.control.ControlCharacterSource): RoutingRules =
        RoutingRulesCharacterImport(source).read()

    /** Reuse exactly equal normalized strings, never skip parsing or mutate the existing snapshot. */
    fun import(source: com.kardinal.vpncontrol.control.ControlCharacterSource, existing: RoutingRules): RoutingRules =
        RoutingRulesCharacterImport(source, existing).read()

    fun export(
        rules: RoutingRules,
        exportedAt: String? = null,
    ): RoutingRulesExportDocument {
        val timestamp = exportedAt ?: Clock.System.now().toString()
        val content = buildString { writeExport(rules, timestamp, this) }
        return RoutingRulesExportDocument(
            fileName = "vpn-control-routing-rules-${timestamp.replace(':', '-')}.json",
            content = content,
        )
    }

    /** Exact existing two-space pretty JSON, without a JSON tree or whole export String. */
    fun writeExport(rules: RoutingRules, exportedAt: String? = null, output: Appendable) {
        fun quoted(value: String) {
            var index = 0
            com.kardinal.vpncontrol.control.ControlDocumentCodec.writeQuotedText(
                { if (index == value.length) -1 else value[index++].code }, output)
        }
        fun array(values: List<String>) {
            output.append('[')
            values.forEachIndexed { index, value ->
                if (index != 0) output.append(',')
                output.append("\n      "); quoted(value)
            }
            if (values.isNotEmpty()) output.append("\n    ")
            output.append(']')
        }
        output.append("{\n  \"type\": "); quoted(FORMAT_TYPE)
        output.append(",\n  \"version\": ").append(FORMAT_VERSION.toString())
        output.append(",\n  \"exported_at\": "); quoted(exportedAt ?: Clock.System.now().toString())
        output.append(",\n  \"rules\": {\n    \"ignore_rules\": ").append(rules.ignoreRules.toString())
        output.append(",\n    \"block_quic_udp_443\": ").append(rules.blockQuicUdp443.toString())
        output.append(",\n    \"proxy_packages\": "); array(rules.proxyPackages)
        output.append(",\n    \"direct_domain_suffixes\": "); array(rules.directDomainSuffixes)
        output.append("\n  }\n}")
    }

    fun import(raw: String): RoutingRules {
        val root = CompactJson.parseToJsonElement(raw).jsonObject
        val rules = root["rules"]?.jsonObject ?: root
        require(looksLikeRulesDocument(root, rules)) {
            "Routing rules JSON format is not recognized"
        }
        return RoutingRules(
            ignoreRules = rules["ignore_rules"]?.jsonPrimitive?.contentOrNull == "true",
            blockQuicUdp443 = rules["block_quic_udp_443"]?.jsonPrimitive?.contentOrNull == "true",
            proxyPackages = RoutingRules.normalizePackageNames(
                readStringArray(rules, "proxy_packages"),
            ),
            bypassPackages = emptyList(),
            directDomainSuffixes = RoutingRules.parseDirectDomainSuffixes(
                readStringArray(rules, "direct_domain_suffixes"),
            ),
            ruleSets = emptyList(),
        )
    }

    private fun looksLikeRulesDocument(root: JsonObject, rules: JsonObject): Boolean {
        if (root["type"]?.jsonPrimitive?.contentOrNull == FORMAT_TYPE) {
            return true
        }
        return rules.containsKey("ignore_rules") ||
            rules.containsKey("block_quic_udp_443") ||
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

}
