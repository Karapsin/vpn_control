package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.model.ProfileSourceMode
import com.kardinal.vpncontrol.model.SubscriptionRefreshPolicy
import com.kardinal.vpncontrol.model.SubscriptionSource
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest

@OptIn(ExperimentalCoroutinesApi::class)
class DesktopAutoRefreshSchedulerTest {
    @Test
    fun offPolicyDoesNotScheduleRefresh() = runTest {
        var refreshRuns = 0
        val scheduler = DesktopAutoRefreshScheduler(
            scope = backgroundScope,
            runAutoRefreshCycle = { refreshRuns += 1 },
        )
        try {
            scheduler.sync(
                schedulerState(
                    policy = SubscriptionRefreshPolicy.OFF,
                ),
            )

            advanceTimeBy(2 * 60 * 60 * 1000L)
            runCurrent()

            assertEquals(0, refreshRuns)
        } finally {
            scheduler.cancel()
        }
    }

    @Test
    fun customPolicySchedulesRefreshForSupportedHttpsSubscriptions() = runTest {
        var refreshRuns = 0
        val scheduler = DesktopAutoRefreshScheduler(
            scope = backgroundScope,
            runAutoRefreshCycle = { refreshRuns += 1 },
        )
        try {
            scheduler.sync(
                schedulerState(
                    policy = SubscriptionRefreshPolicy.CUSTOM,
                    customHours = 0.5,
                ),
            )

            advanceTimeBy(29 * 60 * 1000L)
            runCurrent()
            assertEquals(0, refreshRuns)

            advanceTimeBy(60 * 1000L)
            runCurrent()
            assertEquals(1, refreshRuns)
        } finally {
            scheduler.cancel()
        }
    }

    @Test
    fun syncCancelsOldScheduleAndRespectsLaterPolicyChanges() = runTest {
        var refreshRuns = 0
        val scheduler = DesktopAutoRefreshScheduler(
            scope = backgroundScope,
            runAutoRefreshCycle = { refreshRuns += 1 },
        )
        try {
            scheduler.sync(
                schedulerState(
                    policy = SubscriptionRefreshPolicy.CUSTOM,
                    customHours = 0.5,
                ),
            )

            advanceTimeBy(10 * 60 * 1000L)
            runCurrent()
            scheduler.sync(
                schedulerState(
                    policy = SubscriptionRefreshPolicy.OFF,
                ),
            )

            advanceTimeBy(25 * 60 * 1000L)
            runCurrent()
            assertEquals(0, refreshRuns)

            scheduler.sync(
                schedulerState(
                    policy = SubscriptionRefreshPolicy.EVERY_HOUR,
                ),
            )
            advanceTimeBy(60 * 60 * 1000L)
            runCurrent()
            assertEquals(1, refreshRuns)
        } finally {
            scheduler.cancel()
        }
    }
}

private fun schedulerState(
    policy: SubscriptionRefreshPolicy,
    customHours: Double = 1.0,
    profileSourceMode: ProfileSourceMode = ProfileSourceMode.SUBSCRIPTION,
    subscriptions: List<SubscriptionSource> = listOf(
        SubscriptionSource(
            id = "desktop-scheduler-subscription",
            url = "https://example.com/subscription.txt",
        ),
    ),
): MainUiState {
    return MainUiState(
        profileSourceMode = profileSourceMode,
        subscriptionRefreshPolicy = policy,
        subscriptionRefreshCustomHours = customHours,
        subscriptions = subscriptions,
    )
}
