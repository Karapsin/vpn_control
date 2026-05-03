package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.RoutingStatusMessages
import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.model.AppMode
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DesktopRoutingRulesServiceTest {
    @Test
    fun saveRoutingRulesSanitizesDraftsAndKeepsDesktopRuleSetsEmpty() {
        var state = MainUiState(
            routingIgnoreRulesDraft = false,
            routingProxyPackagesDraft = setOf(" org.telegram.messenger ", "org.telegram.messenger", ""),
            routingNationalDomainsDraft = "ru\n.by\n",
            routingDirectDomainsDraft = "example.com\n.local",
        )
        val service = DesktopRoutingRulesService(
            stateProvider = { state },
            commitState = { nextState -> state = nextState },
            updateState = { transform -> state = transform(state) },
        )

        service.saveRoutingRules()

        assertFalse(state.routingRules.ignoreRules)
        assertEquals(listOf("org.telegram.messenger"), state.routingRules.proxyPackages)
        assertEquals(listOf("ru", "by"), state.routingRules.nationalDomainSuffixes)
        assertEquals(listOf("example.com", "local"), state.routingRules.directDomainSuffixes)
        assertTrue(state.routingRules.ruleSets.isEmpty())
        assertEquals(RoutingStatusMessages.routingRulesSaved(), state.statusMessage)
    }

    @Test
    fun importRoutingRulesUpdatesDraftsAndWarnsWhenRestartIsNeeded() {
        var state = MainUiState(isVpnRunning = true, appMode = AppMode.VPN)
        val service = DesktopRoutingRulesService(
            stateProvider = { state },
            commitState = { nextState -> state = nextState },
            updateState = { transform -> state = transform(state) },
        )

        service.importRaw(
            """
            {
              "ignore_rules": true,
              "proxy_packages": ["com.example.browser"],
              "national_domain_suffixes": [".ru"],
              "direct_domain_suffixes": [".example.com"]
            }
            """.trimIndent(),
        )

        assertTrue(state.routingRules.ignoreRules)
        assertEquals(setOf("com.example.browser"), state.routingProxyPackagesDraft)
        assertEquals("ru", state.routingNationalDomainsDraft)
        assertEquals("example.com", state.routingDirectDomainsDraft)
        assertEquals(RoutingStatusMessages.routingRulesImportedRestartRequired(AppMode.VPN), state.statusMessage)
    }
}
