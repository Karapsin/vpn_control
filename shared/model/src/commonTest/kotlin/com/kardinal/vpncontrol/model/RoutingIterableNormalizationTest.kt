package com.kardinal.vpncontrol.model

import kotlin.test.Test
import kotlin.test.assertEquals

class RoutingIterableNormalizationTest {
    @Test fun iterablePreservesLegacyTokenizationOrderAndDistinctness() {
        val input = listOf(" *.EXAMPLE.COM., .Example.com ", "", "a\tb\rc\nd e", "*.\n...", "\u00a0İ.COM\u00a0",
            "x\u000Cy", "foo,bar", "a", ".例子.测试.", "*.*.Odd.", "\uD800.test")
        val legacy = input.joinToString("\n").split(Regex("[,\\n\\r\\t ]+")).map { it.trim() }
            .filter { it.isNotBlank() }.map { it.removePrefix("*.").trimStart('.').trimEnd('.').lowercase() }
            .filter { it.isNotBlank() }.distinct()
        assertEquals(legacy, RoutingRules.parseDirectDomainSuffixes(input))
        assertEquals(legacy, RoutingRules.parseDirectDomainSuffixes(input.joinToString("\n")))
        assertEquals(emptyList(), RoutingRules.parseDirectDomainSuffixes(emptyList()))
    }
}
