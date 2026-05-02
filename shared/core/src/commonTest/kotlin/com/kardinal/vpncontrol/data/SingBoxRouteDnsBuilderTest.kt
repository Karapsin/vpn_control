package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.model.RoutingRules
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
            dnsEnabled = true,
            dnsValue = "9.9.9.9",
            routingRules = RoutingRules(
                ignoreRules = false,
                nationalDomainSuffixes = listOf("local.example"),
                directDomainSuffixes = listOf("direct.example"),
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

        assertEquals("custom-dns", config.dnsServerTag)
        assertEquals("9.9.9.9", config.dns.array("servers").single().jsonObject.string("server"))
        assertEquals("sniff", routeRules[0].jsonObject.string("action"))
        assertEquals("hijack-dns", routeRules[1].jsonObject.string("action"))
        assertTrue(directCidrs.contains("9.9.9.9/32"))
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
            dnsEnabled = false,
            dnsValue = "",
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

        assertEquals("remote-dns", config.dnsServerTag)
        assertEquals("1.1.1.1", config.dns.array("servers").single().jsonObject.string("server"))
        assertEquals(1, routeRules.size)
        assertFalse("rule_set" in config.route)
        assertEquals(null, config.experimental)
    }

    @Test
    fun validationDnsConfigDoesNotAddRouteRules() {
        val dns = SingBoxRouteDnsBuilder.buildValidationDnsConfig(
            dnsEnabled = true,
            dnsValue = "8.8.8.8",
        )

        assertEquals("validation-dns", dns.array("servers").single().jsonObject.string("tag"))
        assertEquals("8.8.8.8", dns.array("servers").single().jsonObject.string("server"))
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
