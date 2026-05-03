package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.model.SubscriptionStatusMessages
import com.kardinal.vpncontrol.data.SubscriptionRefreshBatchResult
import com.kardinal.vpncontrol.model.ALL_SUBSCRIPTIONS_ID

internal class AndroidSubscriptionRefreshActionsService(
    private val stateProvider: () -> MainUiState,
    private val launch: (suspend () -> Unit) -> Unit,
    private val setBusy: (Boolean) -> Unit,
    private val updateStatus: suspend (String) -> Unit,
    private val runActiveRefresh: suspend () -> Result<SubscriptionRefreshBatchResult>,
    private val runSubscriptionRefresh: suspend (String) -> Result<SubscriptionRefreshBatchResult>,
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
                        onFailure = { it.message ?: SubscriptionStatusMessages.failedToRefreshActiveSubscription() },
                    ),
                )
            } finally {
                setBusy(false)
            }
        }
    }

    fun refreshSubscriptionCache(subscriptionId: String) {
        launch {
            val state = stateProvider()
            val normalizedSubscriptionId = subscriptionId.trim()
            val target = state.subscriptions.firstOrNull { it.id == normalizedSubscriptionId }
            if (target == null) {
                updateStatus(
                    if (state.subscriptions.isEmpty()) {
                        SubscriptionRefreshResultLogic.NO_SUBSCRIPTIONS_MESSAGE
                    } else {
                        SubscriptionStatusMessages.noSubscriptionsToRefresh()
                    },
                )
                return@launch
            }
            setBusy(true)
            try {
                updateStatus(SubscriptionRefreshResultLogic.refreshStartMessage(targetCount = 1))
                val targetLabel = SubscriptionSourceLogic.sourceLabelFor(state.subscriptions, target.url)
                val result = runSubscriptionRefresh(normalizedSubscriptionId)
                updateStatus(
                    result.fold(
                        onSuccess = { refresh ->
                            SubscriptionRefreshResultLogic.genericSummary(
                                refreshedCount = refresh.refreshedCount,
                                failedSubscriptionNames = refresh.failedSubscriptions.map { it.displayName },
                                totalCount = 1,
                            )
                        },
                        onFailure = { error ->
                            error.message ?: SubscriptionStatusMessages.failedToRefresh(targetLabel)
                        },
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
                        onFailure = { it.message ?: SubscriptionStatusMessages.failedToRefreshSubscriptions() },
                    ),
                )
            } finally {
                setBusy(false)
            }
        }
    }
}
