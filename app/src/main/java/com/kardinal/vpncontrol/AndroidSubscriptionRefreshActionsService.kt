package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.data.SubscriptionRefreshBatchResult
import com.kardinal.vpncontrol.model.ALL_SUBSCRIPTIONS_ID
import com.kardinal.vpncontrol.model.StatusMessages

internal class AndroidSubscriptionRefreshActionsService(
    private val stateProvider: () -> MainUiState,
    private val launch: (suspend () -> Unit) -> Unit,
    private val setBusy: (Boolean) -> Unit,
    private val updateStatus: suspend (String) -> Unit,
    private val runActiveRefresh: suspend () -> Result<SubscriptionRefreshBatchResult>,
    private val runAllRefresh: suspend () -> Result<SubscriptionRefreshBatchResult>,
) {
    fun refreshActiveSubscriptionCache() {
        launch {
            val state = stateProvider()
            if (state.subscriptions.isEmpty()) {
                updateStatus(SubscriptionRefreshResultLogic.NO_SUBSCRIPTIONS_MESSAGE)
                return@launch
            }
            setBusy(true)
            try {
                val refreshAll = state.activeSubscriptionId == ALL_SUBSCRIPTIONS_ID
                updateStatus(
                    SubscriptionRefreshResultLogic.refreshStartMessage(
                        targetCount = if (refreshAll) state.subscriptions.size else 1,
                    ),
                )
                val result = runActiveRefresh()
                updateStatus(
                    result.fold(
                        onSuccess = { refresh ->
                            SubscriptionRefreshResultLogic.manualSummary(
                                scope = if (refreshAll) {
                                    SubscriptionRefreshScope.ALL
                                } else {
                                    SubscriptionRefreshScope.ACTIVE
                                },
                                refreshedCount = refresh.refreshedCount,
                                failedSubscriptionNames = refresh.failedSubscriptions.map { it.displayName },
                                totalCount = if (refreshAll) state.subscriptions.size else 1,
                            )
                        },
                        onFailure = { it.message ?: StatusMessages.failedToRefreshActiveSubscription() },
                    ),
                )
            } finally {
                setBusy(false)
            }
        }
    }

    fun refreshAllSubscriptionsCaches() {
        launch {
            val state = stateProvider()
            if (state.subscriptions.isEmpty()) {
                updateStatus(SubscriptionRefreshResultLogic.NO_SUBSCRIPTIONS_MESSAGE)
                return@launch
            }
            setBusy(true)
            try {
                updateStatus(
                    SubscriptionRefreshResultLogic.refreshStartMessage(
                        targetCount = state.subscriptions.size,
                    ),
                )
                val result = runAllRefresh()
                updateStatus(
                    result.fold(
                        onSuccess = { refresh ->
                            SubscriptionRefreshResultLogic.manualSummary(
                                scope = SubscriptionRefreshScope.ALL,
                                refreshedCount = refresh.refreshedCount,
                                failedSubscriptionNames = refresh.failedSubscriptions.map { it.displayName },
                                totalCount = state.subscriptions.size,
                            )
                        },
                        onFailure = { it.message ?: StatusMessages.failedToRefreshSubscriptions() },
                    ),
                )
            } finally {
                setBusy(false)
            }
        }
    }
}
