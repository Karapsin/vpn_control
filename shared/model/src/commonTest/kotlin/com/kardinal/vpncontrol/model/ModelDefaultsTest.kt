package com.kardinal.vpncontrol.model

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class ModelDefaultsTest {
    @Test
    fun persistedStateDefaultsToVpnMode() {
        assertEquals(AppMode.VPN, PersistedState().appMode)
    }

    @Test
    fun routingRulesDefaultToEmptyDomainLists() {
        val rules = RoutingRules()

        assertTrue(rules.nationalDomainSuffixes.isEmpty())
        assertTrue(rules.directDomainSuffixes.isEmpty())
        assertTrue(rules.allDirectDomainSuffixes.isEmpty())
    }
}
