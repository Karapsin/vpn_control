package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.model.ALL_SUBSCRIPTIONS_ID
import com.kardinal.vpncontrol.model.SubscriptionSource
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class AutoRefreshLogicTest {
    @Test
    fun busyStateDoesNotPlanRefresh() {
        val plan = AutoRefreshLogic.plan(
            state = MainUiState(
                isBusy = true,
                subscriptions = listOf(subscription("one")),
                activeSubscriptionId = "one",
            ),
            isRuntimeRunning = true,
        )

        assertNull(plan)
    }

    @Test
    fun allGroupRefreshesAllSubscriptionsAndKeepsConnectionForFindBest() {
        val plan = AutoRefreshLogic.plan(
            state = MainUiState(
                isVpnRunning = true,
                findBestAfterSubscriptionRefresh = true,
                activeSubscriptionId = ALL_SUBSCRIPTIONS_ID,
                subscriptions = listOf(subscription("one"), subscription("two")),
            ),
            isRuntimeRunning = false,
        )

        requireNotNull(plan)
        assertEquals(listOf("one", "two"), plan.subscriptionsToRefresh.map { it.id })
        assertEquals("Auto-refreshing subscriptions...", plan.statusPrefix)
        assertTrue(plan.shouldFindBestAfterRefresh)
        assertFalse(plan.stopVpnIfSelectedRemoved)
    }

    @Test
    fun stoppedConnectionRefreshesActiveSubscriptionWithoutFindBest() {
        val plan = AutoRefreshLogic.plan(
            state = MainUiState(
                isVpnRunning = false,
                findBestAfterSubscriptionRefresh = true,
                activeSubscriptionId = "one",
                subscriptions = listOf(subscription("one"), subscription("two")),
            ),
            isRuntimeRunning = false,
        )

        requireNotNull(plan)
        assertEquals(listOf("one"), plan.subscriptionsToRefresh.map { it.id })
        assertEquals("Auto-refreshing subscription...", plan.statusPrefix)
        assertFalse(plan.shouldFindBestAfterRefresh)
        assertTrue(plan.stopVpnIfSelectedRemoved)
    }

    @Test
    fun runtimeRunningCountsAsActiveConnection() {
        val plan = AutoRefreshLogic.plan(
            state = MainUiState(
                isVpnRunning = false,
                findBestAfterSubscriptionRefresh = true,
                activeSubscriptionId = "one",
                subscriptions = listOf(subscription("one")),
            ),
            isRuntimeRunning = true,
        )

        requireNotNull(plan)
        assertTrue(plan.shouldFindBestAfterRefresh)
        assertFalse(plan.stopVpnIfSelectedRemoved)
    }

    private fun subscription(id: String): SubscriptionSource {
        return SubscriptionSource(
            id = id,
            url = "https://example.com/$id",
        )
    }
}
