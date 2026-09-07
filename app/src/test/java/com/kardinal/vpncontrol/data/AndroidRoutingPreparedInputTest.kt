package com.kardinal.vpncontrol.data

import java.lang.ref.WeakReference
import org.junit.Assert.*
import org.junit.Test

class AndroidRoutingPreparedInputTest {
    @Test fun equivalentPreparedRulesCanBeDiscardedWithoutConsumingSharedState() {
        val domains = mutableListOf("one.test", "two.test")
        val rules = com.kardinal.vpncontrol.model.RoutingRules(directDomainSuffixes = domains)
        val prepared = AndroidPreparedRouting(rules)
        assertTrue(prepared.matches(rules.copy(directDomainSuffixes = domains.toList())))
        assertFalse(prepared.matches(rules.copy(directDomainSuffixes = domains.reversed())))
        assertFalse(prepared.matches(rules.copy(ignoreRules = true)))
        prepared.discard()
        assertEquals(listOf("one.test", "two.test"), domains)
        assertTrue(runCatching { prepared.consume() }.isFailure)
    }

    @Test fun consumingPrivateCopyDoesNotMutateRepositoryCollectionsAndPreservesUtf16() {
        val values = mutableListOf("example.test", "東京", "\uD800", "\uDC00")
        val rules = com.kardinal.vpncontrol.model.RoutingRules(directDomainSuffixes = values,
            proxyPackages = listOf("one", "two"), ignoreRules = true, blockQuicUdp443 = true)
        val prior = values.toList()
        val prepared = AndroidPreparedRouting(rules)
        val encoded = prepared.consume()
        assertEquals(prior, values)
        assertSame(values, rules.directDomainSuffixes)
        assertEquals(prior.joinToString("\n"), encoded.directDomainSuffixes)
        assertEquals("one\ntwo", encoded.proxyPackages)
        assertTrue(encoded.ignoreRules && encoded.blockQuicUdp443)
        assertTrue(runCatching { prepared.consume() }.isFailure)
    }

    private fun payload(): Pair<AndroidRoutingPreparedInput, WeakReference<String>> {
        val input = """{"direct_domain_suffixes":["example.test"],"ignore_rules":false}""" + " ".repeat(1_000_000)
        return AndroidRoutingPreparedInput(input) to WeakReference(input)
    }

    @Test fun parsingReleasesRawDocumentWhilePreparedRulesRemainLive() {
        val (holder, raw) = payload()
        val rules = holder.prepare()
        repeat(40) { if (raw.get() != null) {
            val pressure = Array(8) { ByteArray(128 * 1024) }
            System.gc()
            assertEquals(8, pressure.size)
        } }
        assertNull("Raw document must not survive into persistence", raw.get())
        assertEquals(listOf("example.test"), rules.directDomainSuffixes)
        assertTrue(runCatching { holder.prepare() }.isFailure)
    }
}
