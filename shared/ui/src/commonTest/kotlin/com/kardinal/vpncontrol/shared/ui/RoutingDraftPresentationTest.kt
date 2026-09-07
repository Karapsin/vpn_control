package com.kardinal.vpncontrol.shared.ui

import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.model.AppLanguage
import com.kardinal.vpncontrol.model.RoutingStatusMessages
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals

class RoutingDraftPresentationTest {
    @Test fun guardedRoutingFeedbackHasTypedTranslationsInEveryCatalog() {
        for (language in AppLanguage.entries.filter { it != AppLanguage.SYSTEM }) {
            val strings = AppStrings(language)
            val catalog = requireNotNull(generatedStatusTranslations[language]).structured
            for ((key, message) in listOf(
                "ROUTING_RULES_OUTCOME_UNKNOWN" to RoutingStatusMessages.routingRulesOutcomeUnknown(),
                "ROUTING_RULES_STALE_DRAFT" to RoutingStatusMessages.routingRulesStaleDraft(),
            )) {
                val expected = requireNotNull(catalog[key]) { "$language has no $key translation" }
                assertEquals(expected, strings.statusMessage(message), "$language $key")
                assertNotEquals(key, expected)
            }
        }
    }

    @Test fun equalDomainContentsDoNotRetainThePreviousBackingThroughComposeKeys() {
        val old = mutableListOf("one.test", "two.test")
        val replacement = old.toList()
        assertEquals(routingDomainCacheKey(old), routingDomainCacheKey(old))
        assertNotEquals(routingDomainCacheKey(old), routingDomainCacheKey(replacement))
    }

    @Test
    fun largeListDraftCountDoesNotMaterializeDomainsOrUseStaleText() {
        val domains = object : AbstractList<String>() {
            override val size = 56_000
            override fun get(index: Int): String = error("Count must not materialize domains")
        }
        assertEquals(56_000, routingDirectDomainCount(MainUiState(
            routingDirectDomainSuffixesDraft = domains,
            routingDirectDomainsDraft = "stale.example",
        )))
        assertEquals(0, routingDirectDomainCount(MainUiState(
            routingDirectDomainSuffixesDraft = emptyList(),
            routingDirectDomainsDraft = "stale.example",
        )))
    }

    @Test
    fun legacyTextDraftCountsNormalizedUniqueDomains() {
        assertEquals(2, routingDirectDomainCount(MainUiState(
            routingDirectDomainsDraft = "example.com\nexample.com\nother.example",
        )))
    }
}
