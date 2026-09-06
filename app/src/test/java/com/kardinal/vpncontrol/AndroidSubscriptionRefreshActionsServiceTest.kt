package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.model.SubscriptionStatusMessages
import com.kardinal.vpncontrol.data.SubscriptionRefreshBatchResult
import com.kardinal.vpncontrol.data.SubscriptionRefreshFailure
import com.kardinal.vpncontrol.model.ALL_SUBSCRIPTIONS_ID
import com.kardinal.vpncontrol.model.SubscriptionSource
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runCurrent
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

class AndroidSubscriptionRefreshActionsServiceTest {
    @OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
    @Test fun manualRefreshExcludesOtherMutationsUntilItsFinalStatusCompletes() = kotlinx.coroutines.test.runTest {
        val jobs = AndroidCommandJobs(backgroundScope)
        val gate = kotlinx.coroutines.CompletableDeferred<Unit>()
        var refreshed = 0
        val controller = MainController(MainUiState(subscriptions = listOf(SubscriptionSource("sub", "https://example.com/sub"))))
        val service = service(controller,
            launch = { jobs.launchMutation(it) },
            runAllRefresh = { refreshed++; gate.await(); Result.success(SubscriptionRefreshBatchResult(1)) })
        val lease = requireNotNull(jobs.tryAcquireMutation())
        service.refreshAllSubscriptionsCaches()
        runCurrent()
        assertEquals(0, refreshed)
        jobs.releaseMutation(lease)
        service.refreshAllSubscriptionsCaches()
        runCurrent()
        assertEquals(1, refreshed)
        org.junit.Assert.assertNull(jobs.tryAcquireMutation())
        jobs.cancelActive()
        gate.complete(Unit)
        runCurrent()
        assertFalse(jobs.busy.value)
    }
    @Test
    fun activeRefreshWithoutSubscriptionsReportsEmptyState() {
        val controller = MainController(MainUiState())
        val statuses = mutableListOf<String>()
        var refreshCalled = false
        val service = service(
            controller = controller,
            updateStatus = { statuses += it },
            runActiveRefresh = {
                refreshCalled = true
                Result.success(SubscriptionRefreshBatchResult(refreshedCount = 1))
            },
        )

        service.refreshActiveSubscriptionCache()

        assertFalse(refreshCalled)
        assertEquals(listOf(SubscriptionRefreshResultLogic.NO_SUBSCRIPTIONS_MESSAGE), statuses)
        assertFalse(controller.currentState().isBusy)
    }

    @Test
    fun activeRefreshReportsManualSummary() {
        val controller = MainController(
            MainUiState(
                activeSubscriptionId = "sub-1",
                subscriptions = listOf(SubscriptionSource(id = "sub-1", url = "https://example.com/sub")),
            ),
        )
        val statuses = mutableListOf<String>()
        val service = service(
            controller = controller,
            updateStatus = { statuses += it },
            runActiveRefresh = {
                Result.success(SubscriptionRefreshBatchResult(refreshedCount = 1))
            },
        )

        service.refreshActiveSubscriptionCache()

        assertEquals(
            listOf(
                SubscriptionStatusMessages.subscriptionRefreshStart(targetCount = 1),
                SubscriptionStatusMessages.activeSubscriptionRefreshed(),
            ),
            statuses,
        )
        assertFalse(controller.currentState().isBusy)
    }

    @Test
    fun allRefreshReportsPartialFailureSummary() {
        val controller = MainController(
            MainUiState(
                activeSubscriptionId = ALL_SUBSCRIPTIONS_ID,
                subscriptions = listOf(
                    SubscriptionSource(id = "sub-1", url = "https://example.com/one", customName = "One"),
                    SubscriptionSource(id = "sub-2", url = "https://example.com/two", customName = "Two"),
                ),
            ),
        )
        val statuses = mutableListOf<String>()
        val service = service(
            controller = controller,
            updateStatus = { statuses += it },
            runActiveRefresh = {
                Result.success(
                    SubscriptionRefreshBatchResult(
                        refreshedCount = 1,
                        failedSubscriptions = listOf(
                            SubscriptionRefreshFailure(
                                subscriptionId = "sub-2",
                                sourceUrl = "https://example.com/two",
                                displayName = "Two",
                                message = "bad",
                            ),
                        ),
                    ),
                )
            },
        )

        service.refreshActiveSubscriptionCache()

        assertEquals(
            listOf(
                SubscriptionStatusMessages.subscriptionRefreshStart(targetCount = 2),
                SubscriptionStatusMessages.subscriptionsRefreshedPartial(
                    refreshedCount = 1,
                    totalCount = 2,
                    failedLabel = "Two",
                ),
            ),
            statuses,
        )
        assertFalse(controller.currentState().isBusy)
    }

    @Test
    fun subscriptionRefreshUsesRequestedSubscription() {
        val controller = MainController(
            MainUiState(
                activeSubscriptionId = "sub-1",
                subscriptions = listOf(
                    SubscriptionSource(id = "sub-1", url = "https://example.com/one", customName = "One"),
                    SubscriptionSource(id = "sub-2", url = "https://example.com/two", customName = "Two"),
                ),
            ),
        )
        val statuses = mutableListOf<String>()
        var refreshedSubscriptionId = ""
        val service = service(
            controller = controller,
            updateStatus = { statuses += it },
            runSubscriptionRefresh = { subscriptionId ->
                refreshedSubscriptionId = subscriptionId
                Result.success(SubscriptionRefreshBatchResult(refreshedCount = 1))
            },
        )

        service.refreshSubscriptionCache("sub-2")

        assertEquals("sub-2", refreshedSubscriptionId)
        assertEquals(
            listOf(
                SubscriptionStatusMessages.subscriptionRefreshStart(targetCount = 1),
                SubscriptionStatusMessages.subscriptionRefreshed(),
            ),
            statuses,
        )
        assertFalse(controller.currentState().isBusy)
    }

    @Test
    fun allRefreshUsesFailureFallback() {
        val controller = MainController(
            MainUiState(
                subscriptions = listOf(SubscriptionSource(id = "sub-1", url = "https://example.com/sub")),
            ),
        )
        val statuses = mutableListOf<String>()
        val service = service(
            controller = controller,
            updateStatus = { statuses += it },
            runAllRefresh = {
                Result.failure(IllegalStateException("network failed"))
            },
        )

        service.refreshAllSubscriptionsCaches()

        assertEquals(listOf(SubscriptionStatusMessages.subscriptionRefreshStart(targetCount = 1), "network failed"), statuses)
        assertFalse(controller.currentState().isBusy)
    }

    private fun service(
        controller: MainController,
        launch: (suspend () -> Unit) -> Unit = { block -> runBlocking { block() } },
        updateStatus: suspend (String) -> Unit = {},
        runActiveRefresh: suspend () -> Result<SubscriptionRefreshBatchResult> = {
            Result.success(SubscriptionRefreshBatchResult(refreshedCount = 1))
        },
        runSubscriptionRefresh: suspend (String) -> Result<SubscriptionRefreshBatchResult> = {
            Result.success(SubscriptionRefreshBatchResult(refreshedCount = 1))
        },
        runAllRefresh: suspend () -> Result<SubscriptionRefreshBatchResult> = {
            Result.success(SubscriptionRefreshBatchResult(refreshedCount = 1))
        },
    ): AndroidSubscriptionRefreshActionsService {
        return AndroidSubscriptionRefreshActionsService(
            stateProvider = controller::currentState,
            launch = launch,
            setBusy = { busy -> controller.update { it.copy(isBusy = busy) } },
            updateStatus = updateStatus,
            runActiveRefresh = runActiveRefresh,
            runSubscriptionRefresh = runSubscriptionRefresh,
            runAllRefresh = runAllRefresh,
        )
    }
}
