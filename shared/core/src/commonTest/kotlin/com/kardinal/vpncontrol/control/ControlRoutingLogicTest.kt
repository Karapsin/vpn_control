package com.kardinal.vpncontrol.control

import com.kardinal.vpncontrol.MainUiState
import kotlin.test.*

class ControlRoutingLogicTest {
    @Test fun jsonArrayAndGuiTextHaveTheSameNormalizedDomainMeaning() {
        val json = ControlRoutingLogic.set(MainUiState(), "direct-domains", "[\"*.Example.COM.\",\".local\",\"example.com\"]").getOrThrow()
        val text = ControlRoutingLogic.set(MainUiState(), "direct-domains", "*.Example.COM.\n.local\nexample.com").getOrThrow()
        assertEquals(listOf("example.com", "local"), json.routingRules.directDomainSuffixes)
        assertEquals(text.routingRules, json.routingRules)
        assertTrue(ControlRoutingLogic.set(json, "direct-domains", "[]").getOrThrow().routingRules.directDomainSuffixes.isEmpty())
    }

    @Test fun malformedStructuredDomainInputIsNeverSavedAsLiteralBracketsOrQuotes() {
        for (input in listOf("[", "[true]", "[null]", "[1]", "[{}]", "{}", "\"private.example\""))
            assertTrue(ControlRoutingLogic.set(MainUiState(), "direct-domains", input).isFailure, input)
    }
}
