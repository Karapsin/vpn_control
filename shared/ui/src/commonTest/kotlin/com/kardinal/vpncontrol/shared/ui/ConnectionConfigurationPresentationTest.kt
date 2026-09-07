package com.kardinal.vpncontrol.shared.ui

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import com.kardinal.vpncontrol.model.AppLanguage

class ConnectionConfigurationPresentationTest {
    @Test fun runningAWithPendingConfigurationShowsBothFacts() {
        assertEquals(listOf(ConnectionConfigurationDetail.ActiveLocation("Actual A"),
            ConnectionConfigurationDetail.RestartPending),
            connectionConfigurationDetails(ConnectionConfigurationPresentation(true, "Actual A", true)))
    }

    @Test fun unavailableRuntimeIdentityNeverClaimsSelectedLocationIsActive() {
        assertEquals(listOf(ConnectionConfigurationDetail.ActiveLocationUnavailable,
            ConnectionConfigurationDetail.RestartPending),
            connectionConfigurationDetails(ConnectionConfigurationPresentation(true, null, true)))
    }

    @Test fun disconnectedPresentationDoesNotRenderStaleActiveFacts() {
        assertEquals(emptyList(), connectionConfigurationDetails(ConnectionConfigurationPresentation(false, "Old A", false)))
        assertEquals(emptyList(), connectionConfigurationDetails(null))
    }

    @Test fun everyCatalogDistinguishesKnownUnknownAndPendingWithoutLosingLocationName() {
        val details = listOf(ConnectionConfigurationDetail.ActiveLocation("Actual A"),
            ConnectionConfigurationDetail.ActiveLocationUnavailable, ConnectionConfigurationDetail.RestartPending,
            ConnectionConfigurationDetail.RestartRequirementUnavailable)
        for (language in AppLanguage.entries.filter { it != AppLanguage.SYSTEM }) {
            val strings = AppStrings(language)
            val labels = details.map { connectionConfigurationText(it, strings) }
            assertTrue(labels.first().contains("Actual A"), language.name)
            assertEquals(4, labels.distinct().size, language.name)
            assertTrue(labels.none { it.contains("{0}") }, language.name)
            if (language != AppLanguage.ENGLISH) details.forEach { detail ->
                assertNotEquals(connectionConfigurationText(detail, AppStrings(AppLanguage.ENGLISH)),
                    connectionConfigurationText(detail, strings), language.name)
            }
        }
    }

    @Test fun unknownRuntimeAndRestartFactsAreNotRenderedAsDisconnectedOrAlreadyApplied() {
        val expected = listOf(ConnectionConfigurationDetail.ActiveLocationUnavailable,
            ConnectionConfigurationDetail.RestartRequirementUnavailable)
        assertEquals(expected, connectionConfigurationDetails(ConnectionConfigurationPresentation(null, "stale", null)))
        assertEquals(expected, connectionConfigurationDetails(ConnectionConfigurationPresentation(true, null, null)))
    }
}
