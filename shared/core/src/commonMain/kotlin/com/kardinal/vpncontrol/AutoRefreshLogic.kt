package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.model.SubscriptionSource

data class AutoRefreshPlan(
    val subscriptionsToRefresh: List<SubscriptionSource>,
    val statusPrefix: String,
    val shouldFindBestAfterRefresh: Boolean,
    val stopVpnIfSelectedRemoved: Boolean,
)

object AutoRefreshLogic {
    fun plan(
        state: MainUiState,
        isRuntimeRunning: Boolean,
    ): AutoRefreshPlan? {
        if (state.isBusy) return null
        val refreshTargets = MainCommandLogic.currentSubscriptionSearchTargets(state)
        if (refreshTargets.isEmpty()) return null

        val wasConnectionRunning = state.isVpnRunning || isRuntimeRunning
        val shouldFindBestAfterRefresh = wasConnectionRunning && state.findBestAfterSubscriptionRefresh
        return AutoRefreshPlan(
            subscriptionsToRefresh = refreshTargets,
            statusPrefix = if (refreshTargets.size == 1) {
                "Auto-refreshing subscription..."
            } else {
                "Auto-refreshing subscriptions..."
            },
            shouldFindBestAfterRefresh = shouldFindBestAfterRefresh,
            stopVpnIfSelectedRemoved = !shouldFindBestAfterRefresh,
        )
    }
}
