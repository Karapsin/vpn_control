package com.kardinal.vpncontrol.data

import androidx.work.ExistingWorkPolicy
import com.kardinal.vpncontrol.model.PersistedState
import com.kardinal.vpncontrol.model.ProfileSourceMode
import com.kardinal.vpncontrol.model.SubscriptionRefreshPolicy
import com.kardinal.vpncontrol.model.SubscriptionSource
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.runCurrent
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SubscriptionRefreshSchedulerTest {
    @OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
    @Test fun schedulingWaitsForConfirmationAndQueuedCallerUsesLatestState() = runTest {
        val confirmation = CompletableDeferred<Unit>()
        val events = mutableListOf<String>()
        var current = scheduleableState()
        val scheduler = SubscriptionRefreshScheduler(object : SubscriptionRefreshWorkOperations {
            override fun cancelUniqueWork(workName: String) = SubscriptionRefreshCompletion { events += "cancelled" }
            override fun enqueueUniqueRefresh(workName: String, policy: ExistingWorkPolicy, intervalMinutes: Long): SubscriptionRefreshCompletion {
                events += "submitted"
                return SubscriptionRefreshCompletion { confirmation.await(); events += "confirmed" }
            }
        }, latestState = { current })
        val first = async { scheduler.sync(current) }
        runCurrent()
        assertEquals(listOf("submitted"), events)
        assertTrue(!first.isCompleted)
        val staleSnapshot = current
        current = current.copy(subscriptionRefreshPolicy = SubscriptionRefreshPolicy.OFF)
        val second = async { scheduler.sync(staleSnapshot) }
        runCurrent()
        assertEquals(listOf("submitted"), events)
        confirmation.complete(Unit)
        first.await()
        second.await()
        assertEquals(listOf("submitted", "confirmed", "cancelled"), events)
    }

    @Test fun schedulingFailureIsNotReportedAsSuccessfulCompletion() = runTest {
        val scheduler = SubscriptionRefreshScheduler(object : SubscriptionRefreshWorkOperations {
            override fun cancelUniqueWork(workName: String) = SubscriptionRefreshCompletion { error("fixture failure") }
            override fun enqueueUniqueRefresh(workName: String, policy: ExistingWorkPolicy, intervalMinutes: Long) =
                SubscriptionRefreshCompletion { error("fixture failure") }
        })
        assertEquals("fixture failure", runCatching { scheduler.sync(scheduleableState()) }.exceptionOrNull()?.message)
        assertEquals("fixture failure", runCatching { scheduler.sync(scheduleableState(policy = SubscriptionRefreshPolicy.OFF)) }.exceptionOrNull()?.message)
    }

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

    override fun cancelUniqueWork(workName: String): SubscriptionRefreshCompletion {
        cancelled += workName
        return SubscriptionRefreshCompletion {}
    }

    override fun enqueueUniqueRefresh(
        workName: String,
        policy: ExistingWorkPolicy,
        intervalMinutes: Long,
    ): SubscriptionRefreshCompletion {
        enqueued += EnqueuedRefresh(
            workName = workName,
            policy = policy,
            intervalMinutes = intervalMinutes,
        )
        return SubscriptionRefreshCompletion {}
    }
}
