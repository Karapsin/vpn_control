package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.model.ALL_SUBSCRIPTIONS_ID
import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.ProfileSourceMode
import com.kardinal.vpncontrol.model.StatusMessageKey
import com.kardinal.vpncontrol.model.StatusMessages
import com.kardinal.vpncontrol.model.SubscriptionRefreshPolicy
import com.kardinal.vpncontrol.model.SubscriptionSource
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertNull

class MainCommandLogicTest {
    @Test
    fun sanitizeDecimalInputKeepsOnlyOneDecimalSeparator() {
        assertEquals("0.5", MainCommandLogic.sanitizeDecimalInput(",5"))
        assertEquals("12.34", MainCommandLogic.sanitizeDecimalInput("12..3h4"))
        assertEquals("1.25", MainCommandLogic.sanitizeDecimalInput("1,25 hours"))
    }

    @Test
    fun customRefreshPolicyAcceptsHalfHourIntervals() {
        val resolution = MainCommandLogic.resolveSubscriptionRefreshPolicySave(
            MainUiState(
                subscriptionRefreshPolicyDraft = SubscriptionRefreshPolicy.CUSTOM,
                subscriptionRefreshCustomHoursDraft = "0.5",
                findBestAfterSubscriptionRefreshDraft = false,
            ),
        ).getOrThrow()

        assertEquals(SubscriptionRefreshPolicy.CUSTOM, resolution.policy)
        assertEquals(0.5, resolution.resolvedHours)
        assertEquals(false, resolution.findBestAfterRefresh)
    }

    @Test
    fun customRefreshPolicyRejectsIntervalsBelowFiveMinutes() {
        val result = MainCommandLogic.resolveSubscriptionRefreshPolicySave(
            MainUiState(
                subscriptionRefreshPolicyDraft = SubscriptionRefreshPolicy.CUSTOM,
                subscriptionRefreshCustomHoursDraft = "0.05",
            ),
        )

        assertFails { result.getOrThrow() }
        assertEquals(
            "Custom refresh interval must be at least 5 minutes",
            result.exceptionOrNull()?.message,
        )
    }

    @Test
    fun allSubscriptionGroupTargetsEverySubscriptionWithAUrl() {
        val targets = MainCommandLogic.currentSubscriptionSearchTargets(
            MainUiState(
                activeSubscriptionId = ALL_SUBSCRIPTIONS_ID,
                subscriptions = listOf(
                    subscription("one", "https://example.com/one"),
                    subscription("two", ""),
                    subscription("three", "https://example.com/three"),
                ),
            ),
        )

        assertEquals(listOf("one", "three"), targets.map { it.id })
    }

    @Test
    fun activeSubscriptionTargetsOnlySelectedSubscription() {
        val targets = MainCommandLogic.currentSubscriptionSearchTargets(
            MainUiState(
                activeSubscriptionId = "two",
                subscriptions = listOf(
                    subscription("one", "https://example.com/one"),
                    subscription("two", "https://example.com/two"),
                ),
            ),
        )

        assertEquals(listOf("two"), targets.map { it.id })
    }

    @Test
    fun refreshPreconditionRequiresRemoteSourceForSubscriptionMode() {
        val error = MainCommandLogic.refreshPreconditionError(
            MainUiState(
                profileSourceMode = ProfileSourceMode.SUBSCRIPTION,
                activeSubscriptionId = "missing",
                subscriptions = listOf(subscription("one", "https://example.com/one")),
            ),
        )

        assertEquals("Set a remote source first", error)
    }

    @Test
    fun refreshPreconditionRequiresSavedLocationForCurrentLocationsMode() {
        val error = MainCommandLogic.refreshPreconditionError(
            MainUiState(profileSourceMode = ProfileSourceMode.CURRENT_LOCATIONS),
        )

        assertEquals("Add at least one saved location first", error)
    }

    @Test
    fun refreshPreconditionPassesForCurrentLocationsWithSavedLocations() {
        val error = MainCommandLogic.refreshPreconditionError(
            MainUiState(
                profileSourceMode = ProfileSourceMode.CURRENT_LOCATIONS,
                currentLocations = listOf("vless://example"),
            ),
        )

        assertNull(error)
    }

    @Test
    fun findBestStartStatusUsesStructuredKeysForLocalization() {
        assertEquals(
            StatusMessageKey.FIND_BEST_FROM_SUBSCRIPTION,
            StatusMessages.decode(
                MainCommandLogic.refreshStartStatus(
                    MainUiState(profileSourceMode = ProfileSourceMode.SUBSCRIPTION),
                ),
            )?.key,
        )
        assertEquals(
            StatusMessageKey.FIND_BEST_FROM_SAVED,
            StatusMessages.decode(
                MainCommandLogic.refreshStartStatus(
                    MainUiState(profileSourceMode = ProfileSourceMode.CURRENT_LOCATIONS),
                ),
            )?.key,
        )
    }

    @Test
    fun connectionLifecycleStatusesUseStructuredKeysForLocalization() {
        val started = StatusMessages.decode(MainCommandLogic.startedConnectionStatus(AppMode.VPN))
        val stopped = StatusMessages.decode(MainCommandLogic.stoppedConnectionStatus(AppMode.PROXY_ONLY))

        assertEquals(StatusMessageKey.CONNECTION_STARTED, started?.key)
        assertEquals(listOf(AppMode.VPN.name), started?.args)
        assertEquals(StatusMessageKey.CONNECTION_STOPPED, stopped?.key)
        assertEquals(listOf(AppMode.PROXY_ONLY.name), stopped?.args)
    }

    private fun subscription(id: String, url: String): SubscriptionSource {
        return SubscriptionSource(
            id = id,
            url = url,
        )
    }
}
