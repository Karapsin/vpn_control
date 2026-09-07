package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.control.ControlCharacterSource
import com.kardinal.vpncontrol.model.RoutingRules
import kotlin.test.*

class RoutingRulesCharacterImportTest {
    @Test fun immutableLazyViewsDoNotMaterializeOldDomainsToParseAnEdit() {
        var lookups = 0
        val retained = "retained.example".toCharArray().concatToString()
        val existingDomains = object : AbstractList<String>(), RoutingRulesRetainedStrings {
            override val size = 56_000
            override fun get(index: Int): String = error("Existing domain view must not be materialized for token reuse")
            override fun findRetainedString(value: String): String? {
                lookups++
                return when (value) {
                    retained -> retained
                    // A lookup is an allocation optimization, never authority to
                    // replace the parsed token with different configuration.
                    "fresh.example" -> "incorrect.example"
                    else -> null
                }
            }
        }
        val document = """{"direct_domain_suffixes":["*.RETAINED.EXAMPLE.,fresh.example retained.example"],"proxy_packages":[]}"""
        val parsed = RoutingRulesTransfer.import(source(document), RoutingRules(directDomainSuffixes = existingDomains))
        assertEquals(listOf("retained.example", "fresh.example"), parsed.directDomainSuffixes)
        assertSame(retained, parsed.directDomainSuffixes.first())
        assertEquals(3, lookups)
    }

    @Test fun existingStringsAreReusedOnlyAfterExactNormalizationWithoutChangingOrder() {
        fun fresh(value: String) = value.toCharArray().concatToString()
        val first = fresh("first.example")
        val second = fresh("second.example")
        val app = fresh("com.example.app")
        val existing = RoutingRules(directDomainSuffixes = listOf(first, second), proxyPackages = listOf(app))
        val document = """{"direct_domain_suffixes":["*.SECOND.EXAMPLE.,new.example first.example second.example"],"proxy_packages":[" com.example.app ","other.app"]}"""
        val parsed = RoutingRulesTransfer.import(source(document), existing)
        assertEquals(RoutingRulesTransfer.import(document), parsed)
        assertSame(second, parsed.directDomainSuffixes[0])
        assertEquals("new.example", parsed.directDomainSuffixes[1])
        assertSame(first, parsed.directDomainSuffixes[2])
        assertSame(app, parsed.proxyPackages[0])
        assertEquals(listOf(first, second), existing.directDomainSuffixes)
    }

    @Test fun existingPoolDoesNotAcceptMalformedInputOrKeepAbsentOrOverwrittenRules() {
        val existing = RoutingRules(directDomainSuffixes = listOf("old.example"), proxyPackages = listOf("old.app"))
        val document = """{"direct_domain_suffixes":["old.example"],"direct_domain_suffixes":["new.example"],"proxy_packages":[]}"""
        assertEquals(RoutingRulesTransfer.import(document), RoutingRulesTransfer.import(source(document), existing))
        for (malformed in listOf("""{"direct_domain_suffixes":["old.example",{}]}""",
            """{"direct_domain_suffixes":["old.example"]} trailing""")) {
            assertFailsWith<IllegalArgumentException> { RoutingRulesTransfer.import(source(malformed), existing) }
        }
        class StorageFailure : Exception()
        val failure = StorageFailure()
        assertSame(failure, assertFailsWith<StorageFailure> {
            RoutingRulesTransfer.import(ControlCharacterSource { throw failure }, existing)
        })
    }

    @Test fun sourceFailureIsNotReclassifiedAsMalformedRouting() {
        class StorageFailure : Exception()
        val failure = StorageFailure()
        assertSame(failure, assertFailsWith<StorageFailure> {
            RoutingRulesTransfer.import(ControlCharacterSource { throw failure })
        })
    }
    private fun source(text: String): ControlCharacterSource {
        var index = 0
        return ControlCharacterSource { if (index == text.length) -1 else text[index++].code }
    }

    @Test fun streamingMatchesLegacyWrapperPrimitiveCoercionAndDuplicateSemantics() {
        val documents = listOf(
            "{}", "[]", "null", "{\"type\":\"vpn_control_routing_rules\"}",
            "{\"rules\":{\"ignore_rules\":true}}", "{\"rules\":null}",
            "{\"ignore_rules\":\"true\",\"block_quic_udp_443\":false}",
            "{\"ignore_rules\":[],\"ignore_rules\":true}",
            "{\"rules\":[],\"rules\":{\"proxy_packages\":[\" a \",3,true,null,\"a\"]}}",
            "{\"proxy_packages\":{},\"proxy_packages\":[\"valid\"]}",
            "{\"proxy_packages\":[{}]}", "{\"proxy_packages\":[[]]}",
            "{\"ignore_rules\":true,\"rules\":{}}", "{\"type\":[],\"ignore_rules\":true}",
            "{\"type\":[],\"type\":\"vpn_control_routing_rules\",\"rules\":{}}",
            "{\"national_domain_suffixes\":[{}],\"rule_sets\":{\"arbitrary\":true}}",
            "{\"direct_domain_suffixes\":[\" *.EXAMPLE.com.,\\n東京.jp\\t.x. \",\"example.com\",123,true,null]}",
            "{\"direct_domain_suffixes\":[\"a\\u002cb\",\"\\u00a0.C.\\u00a0\",\"\\uD800\"]}",
            "{\"proxy_packages\":[01,1.,1e3]}", "{\"ignore_rules\":true,}",
            "{\"ignore_rules\":true} trailing", "{\"ignore_rules\":true,\"unknown\":[1,]}",
            "{\"ignore_rules\":true,\"unknown\":{\"a\":1,\"a\":2}}",
        )
        for ((index, text) in documents.withIndex()) {
            val legacy = runCatching { RoutingRulesTransfer.import(text) }
            val streamed = runCatching { RoutingRulesTransfer.import(source(text)) }
            assertEquals(legacy.isSuccess, streamed.isSuccess, "case $index")
            if (legacy.isSuccess) assertEquals(legacy.getOrThrow(), streamed.getOrThrow(), "case $index")
        }
    }

    @Test fun opaqueIgnoredJsonDoesNotInheritControlEnvelopeDepthLimit() {
        val text = "{\"ignore_rules\":true,\"ignored\":" + "[".repeat(128) + "0" + "]".repeat(128) + "}"
        assertEquals(RoutingRulesTransfer.import(text), RoutingRulesTransfer.import(source(text)))
    }

    @Test fun largeRepeatedDomainStringNormalizesAsItStreams() {
        val prefix = "{\"direct_domain_suffixes\":[\""
        val repeated = "*.EXAMPLE.com., "
        val repeats = 800_000
        val suffix = "\"]}"
        var index = 0
        val parsed = RoutingRulesTransfer.import(ControlCharacterSource {
            val position = index++
            when {
                position < prefix.length -> prefix[position].code
                position < prefix.length + repeated.length * repeats -> repeated[(position - prefix.length) % repeated.length].code
                position < prefix.length + repeated.length * repeats + suffix.length -> suffix[position - prefix.length - repeated.length * repeats].code
                else -> -1
            }
        })
        assertEquals(listOf("example.com"), parsed.directDomainSuffixes)
    }
}
