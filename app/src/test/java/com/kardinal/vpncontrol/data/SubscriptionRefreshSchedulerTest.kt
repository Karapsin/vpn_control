package com.kardinal.vpncontrol.data

import androidx.work.ExistingWorkPolicy
import com.kardinal.vpncontrol.model.PersistedState
import com.kardinal.vpncontrol.model.ProfileSourceMode
import com.kardinal.vpncontrol.model.SubscriptionRefreshPolicy
import com.kardinal.vpncontrol.model.SubscriptionSource
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SubscriptionRefreshSchedulerTest {
    @Test
    fun syncSchedulesCustomHalfHourAsThirtyMinuteReplacement() = runBlocking {
        val operations = FakeSubscriptionRefreshWorkOperations()
        val logs = mutableListOf<String>()
        val scheduler = SubscriptionRefreshScheduler(
            workOperations = operations,
            diagnosticsLogger = { logs += it },
        )

        scheduler.sync(scheduleableState(customHours = 0.5))

        assertEquals(emptyList<String>(), operations.cancelled)
        assertEquals(
            listOf(
                EnqueuedRefresh(
                    workName = SubscriptionRefreshScheduler.WORK_NAME,
                    policy = ExistingWorkPolicy.REPLACE,
                    intervalMinutes = 30L,
                ),
            ),
            operations.enqueued,
        )
        assertTrue(logs.single().contains("intervalMinutes=30"))
        assertTrue(logs.single().contains("workPolicy=REPLACE"))
    }

    @Test
    fun scheduleNextReplacesExistingUniqueWorkInsteadOfAppending() = runBlocking {
        val operations = FakeSubscriptionRefreshWorkOperations()
        val scheduler = SubscriptionRefreshScheduler(workOperations = operations)

        scheduler.scheduleNext(scheduleableState(customHours = 0.5))

        assertEquals(1, operations.enqueued.size)
        assertEquals(ExistingWorkPolicy.REPLACE, operations.enqueued.single().policy)
    }

    @Test
    fun ineligibleStatesCancelUniqueRefreshWork() = runBlocking {
        val states = listOf(
            scheduleableState(policy = SubscriptionRefreshPolicy.OFF),
            scheduleableState(profileSourceMode = ProfileSourceMode.CURRENT_LOCATIONS),
            scheduleableState(url = "http://example.com/subscription.txt"),
        )

        states.forEach { state ->
            val operations = FakeSubscriptionRefreshWorkOperations()
            val scheduler = SubscriptionRefreshScheduler(workOperations = operations)

            scheduler.sync(state)

            assertEquals(listOf(SubscriptionRefreshScheduler.WORK_NAME), operations.cancelled)
            assertEquals(emptyList<EnqueuedRefresh>(), operations.enqueued)
        }
    }
}

private fun scheduleableState(
    policy: SubscriptionRefreshPolicy = SubscriptionRefreshPolicy.CUSTOM,
    customHours: Double = 1.0,
    profileSourceMode: ProfileSourceMode = ProfileSourceMode.SUBSCRIPTION,
    url: String = "https://example.com/subscription.txt",
): PersistedState {
    return PersistedState(
        profileSourceMode = profileSourceMode,
        subscriptionRefreshPolicy = policy,
        subscriptionRefreshCustomHours = customHours,
        profileUrl = url,
        activeSubscriptionId = "subscription-1",
        subscriptions = listOf(
            SubscriptionSource(
                id = "subscription-1",
                url = url,
            ),
        ),
    )
}

private data class EnqueuedRefresh(
    val workName: String,
    val policy: ExistingWorkPolicy,
    val intervalMinutes: Long,
)

private class FakeSubscriptionRefreshWorkOperations : SubscriptionRefreshWorkOperations {
    val cancelled = mutableListOf<String>()
    val enqueued = mutableListOf<EnqueuedRefresh>()

    override fun cancelUniqueWork(workName: String) {
        cancelled += workName
    }

    override fun enqueueUniqueRefresh(
        workName: String,
        policy: ExistingWorkPolicy,
        intervalMinutes: Long,
    ) {
        enqueued += EnqueuedRefresh(
            workName = workName,
            policy = policy,
            intervalMinutes = intervalMinutes,
        )
    }
}
