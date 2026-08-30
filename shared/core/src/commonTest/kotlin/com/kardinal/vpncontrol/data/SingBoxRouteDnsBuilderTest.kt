package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.model.RoutingRules
import com.kardinal.vpncontrol.model.DnsMode
import com.kardinal.vpncontrol.model.DnsSettings
import com.kardinal.vpncontrol.model.RoutingRuleSet
import com.kardinal.vpncontrol.model.RoutingRuleSetAction
import com.kardinal.vpncontrol.model.RoutingRuleSetFormat
import com.kardinal.vpncontrol.model.RoutingRuleSetSourceType
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

class SingBoxRouteDnsBuilderTest {
    @Test
    fun routeDnsConfigPreservesLeadingRulesDirectCidrsDomainsAndRuleSets() {
        val config = SingBoxRouteDnsBuilder.buildRouteDnsConfig(
            dnsSettings = DnsSettings(
                mode = DnsMode.CUSTOM_DOH,
                endpoint = "https://dns.example/dns-query",
            ),
            routingRules = RoutingRules(
                ignoreRules = false,
                directDomainSuffixes = listOf("local.example", "direct.example"),
                ruleSets = listOf(
                    RoutingRuleSet(
                        id = "remote-abc12345",
                        name = "Remote Ads",
                        sourceType = RoutingRuleSetSourceType.REMOTE,
                        format = RoutingRuleSetFormat.SOURCE,
                        source = "https://example.com/rules.srs",
                        action = RoutingRuleSetAction.BLOCK,
                        updateIntervalHours = 2,
                    ),
                ),
            ),
            leadingRouteRules = listOf(
                SingBoxRouteDnsBuilder.sniffRouteRule(),
                SingBoxRouteDnsBuilder.dnsHijackRouteRule(),
            ),
        )

        val routeRules = config.route.array("rules")
        val directRule = routeRules[2].jsonObject
        val directCidrs = directRule.array("ip_cidr").map { it.jsonPrimitive.content }
        val domainRule = routeRules[3].jsonObject
        val ruleSetRule = routeRules[4].jsonObject
        val ruleSetDefinition = config.route.array("rule_set").single().jsonObject

        assertEquals("secure-dns", config.dnsServerTag)
        val dnsServers = config.dns.array("servers").map { it.jsonObject }
        assertEquals("1.1.1.1", dnsServers[0].string("server"))
        assertEquals("https", dnsServers[1].string("type"))
        assertEquals("dns.example", dnsServers[1].string("server"))
        assertEquals("/dns-query", dnsServers[1].string("path"))
        assertEquals("proxy", dnsServers[1].string("detour"))
        assertEquals("bootstrap-dns", dnsServers[1].string("domain_resolver"))
        assertEquals("sniff", routeRules[0].jsonObject.string("action"))
        assertEquals("hijack-dns", routeRules[1].jsonObject.string("action"))
        assertTrue(directCidrs.contains("1.1.1.1/32"))
        assertEquals("direct", directRule.string("outbound"))
        assertEquals(
            listOf(".local.example", ".direct.example"),
            domainRule.array("domain_suffix").map { it.jsonPrimitive.content },
        )
        assertEquals("direct", domainRule.string("outbound"))
        assertEquals("block", ruleSetRule.string("outbound"))
        assertEquals("remote", ruleSetDefinition.string("type"))
        assertEquals("source", ruleSetDefinition.string("format"))
        assertEquals("direct", ruleSetDefinition.string("download_detour"))
        assertEquals("2h", ruleSetDefinition.string("update_interval"))
        assertNotNull(config.experimental?.objectValue("cache_file"))
        assertTrue(config.experimental!!.objectValue("cache_file").boolean("enabled"))
    }

    @Test
    fun ignoredRulesSkipDomainsRuleSetsAndExperimentalCache() {
        val config = SingBoxRouteDnsBuilder.buildRouteDnsConfig(
            dnsSettings = DnsSettings(),
            routingRules = RoutingRules(
                ignoreRules = true,
                directDomainSuffixes = listOf("direct.example"),
                ruleSets = listOf(
                    RoutingRuleSet(
                        id = "remote",
                        name = "Remote",
                        sourceType = RoutingRuleSetSourceType.REMOTE,
                        format = RoutingRuleSetFormat.SOURCE,
                        source = "https://example.com/rules.srs",
                        action = RoutingRuleSetAction.DIRECT,
                    ),
                ),
            ),
        )

        val routeRules = config.route.array("rules")

        assertEquals("secure-dns", config.dnsServerTag)
        val dnsServers = config.dns.array("servers").map { it.jsonObject }
        assertEquals("1.1.1.1", dnsServers[0].string("server"))
        assertEquals("https", dnsServers[1].string("type"))
        assertEquals("1.1.1.1", dnsServers[1].string("server"))
        assertEquals(1, routeRules.size)
        assertFalse("rule_set" in config.route)
        assertEquals(null, config.experimental)
    }

    @Test
    fun inlineRuleSetUsesInlineDefinitionAndDoesNotEnableCacheFile() {
        val config = SingBoxRouteDnsBuilder.buildRouteDnsConfig(
            dnsSettings = DnsSettings(),
            routingRules = RoutingRules(
                ignoreRules = false,
                ruleSets = listOf(
                    RoutingRuleSet(
                        id = "inline-12345678",
                        name = "Inline Ads",
                        sourceType = RoutingRuleSetSourceType.INLINE,
                        format = RoutingRuleSetFormat.SOURCE,
                        source = """{"rules":[{"domain_suffix":["ads.example"]}]}""",
                        action = RoutingRuleSetAction.PROXY,
                    ),
                ),
            ),
        )

        val ruleSetDefinition = config.route.array("rule_set").single().jsonObject
        val ruleSetRoute = config.route.array("rules").last().jsonObject

        assertEquals("inline", ruleSetDefinition.string("type"))
        assertEquals("ruleset-inline-ads-12345678", ruleSetDefinition.string("tag"))
        assertEquals("ads.example", ruleSetDefinition.array("rules").single().jsonObject.array("domain_suffix").single().jsonPrimitive.content)
        assertFalse("url" in ruleSetDefinition)
        assertEquals("proxy", ruleSetRoute.string("outbound"))
        assertEquals(null, config.experimental)
    }

    @Test
    fun directCidrsAlwaysIncludeOnlyTheBootstrapResolver() {
        val directCidrs = SingBoxRouteDnsBuilder.directCidrs()

        assertTrue(directCidrs.contains("1.1.1.1/32"))
        assertFalse(directCidrs.contains("9.9.9.9/32"))
    }

    @Test
    fun validationDnsConfigDoesNotAddRouteRules() {
        val dns = SingBoxRouteDnsBuilder.buildValidationDnsConfig(
            settings = DnsSettings(
                mode = DnsMode.CUSTOM_DOT,
                endpoint = "tls://dns.example:853",
            ),
        )

        val servers = dns.array("servers").map { it.jsonObject }
        assertEquals("bootstrap-dns", servers[0].string("tag"))
        assertEquals("secure-dns", servers[1].string("tag"))
        assertEquals("tls", servers[1].string("type"))
        assertEquals("dns.example", servers[1].string("server"))
        assertEquals("proxy", servers[1].string("detour"))
        assertFalse("rules" in dns)
        assertTrue(dns.boolean("independent_cache"))
    }
}

private fun JsonObject.string(key: String): String {
    return this[key]!!.jsonPrimitive.content
}

private fun JsonObject.boolean(key: String): Boolean {
    return this[key]!!.jsonPrimitive.boolean
}

private fun JsonObject.objectValue(key: String): JsonObject {
    return this[key]!!.jsonObject
}

private fun JsonObject.array(key: String): JsonArray {
    return this[key]!!.jsonArray
}
