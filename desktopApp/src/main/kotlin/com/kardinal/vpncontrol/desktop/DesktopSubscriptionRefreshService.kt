package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.AutoRefreshLogic
import com.kardinal.vpncontrol.MainCommandLogic
import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.SubscriptionRefreshResultLogic
import com.kardinal.vpncontrol.model.SubscriptionSource

internal class DesktopSubscriptionRefreshService(
    private val stateProvider: () -> MainUiState,
    private val locationsProvider: () -> List<DesktopLocationRecord>,
    private val subscriptionService: DesktopSubscriptionService,
    private val isRuntimeRunning: () -> Boolean,
    private val stopConnection: suspend (String?) -> Result<Unit>,
    private val activeConnectionName: () -> String,
    private val findBestAfterRefresh: suspend () -> Unit,
    private val commitState: (nextState: MainUiState, nextLocations: List<DesktopLocationRecord>) -> Unit,
    private val updateState: ((MainUiState) -> MainUiState) -> Unit,
) {
    suspend fun refreshAll() {
        val subscriptions = stateProvider().subscriptions.filter { it.url.isNotBlank() }
        refresh(
            subscriptionsToRefresh = subscriptions,
            statusPrefix = SubscriptionRefreshResultLogic.refreshStartMessage(subscriptions.size),
        )
    }

    suspend fun refreshActive() {
        val refreshTargets = MainCommandLogic.currentSubscriptionSearchTargets(stateProvider())
        if (refreshTargets.isEmpty()) {
            updateState { it.withStatus(SubscriptionRefreshResultLogic.NO_REMOTE_SOURCE_MESSAGE) }
            return
        }
        refresh(
            subscriptionsToRefresh = refreshTargets,
            statusPrefix = SubscriptionRefreshResultLogic.refreshStartMessage(refreshTargets.size),
        )
    }

    suspend fun runAutoRefreshCycle() {
        val plan = AutoRefreshLogic.plan(
            state = stateProvider(),
            isRuntimeRunning = isRuntimeRunning(),
        ) ?: return
        val refreshResult = refresh(
            subscriptionsToRefresh = plan.subscriptionsToRefresh,
            statusPrefix = plan.statusPrefix,
            stopVpnIfSelectedRemoved = plan.stopVpnIfSelectedRemoved,
        )
        if (refreshResult.isFailure) return
        if (plan.shouldFindBestAfterRefresh) {
            findBestAfterRefresh()
        }
    }

    suspend fun refresh(
        subscriptionsToRefresh: List<SubscriptionSource>,
        statusPrefix: String,
        stopVpnIfSelectedRemoved: Boolean = true,
    ): Result<Int> {
        if (subscriptionsToRefresh.isEmpty()) {
            updateState { it.withStatus(SubscriptionRefreshResultLogic.NO_REMOTE_SOURCE_MESSAGE) }
            return Result.failure(IllegalStateException("No subscriptions to refresh"))
        }

        updateState { it.copy(isBusy = true, isRefreshing = true).withStatus(statusPrefix) }

        val refreshResult = subscriptionService.refreshSubscriptions(
            state = stateProvider(),
            locations = locationsProvider(),
            subscriptionsToRefresh = subscriptionsToRefresh,
            onProgress = { message ->
                updateState { it.withStatus(message) }
            },
        )
        if (refreshResult.isFailure) {
            updateState { it.copy(isBusy = false, isRefreshing = false) }
            return Result.failure(refreshResult.exceptionOrNull() ?: IllegalStateException("Refresh failed"))
        }
        val refreshed = refreshResult.getOrThrow()

        val state = stateProvider()
        val removedSelected = state.selectedProfileRawLink.isNotBlank() &&
            refreshed.locations.none { it.matchesSelectedLocation(state) }
        if (removedSelected && state.isVpnRunning && stopVpnIfSelectedRemoved) {
            val stopResult = stopConnection("${activeConnectionName()} stopped. Refreshed subscriptions removed the selected location.")
            if (stopResult.isFailure) {
                updateState { it.copy(isBusy = false) }
                return Result.failure(stopResult.exceptionOrNull() ?: IllegalStateException("Failed to stop ${activeConnectionName()}"))
            }
        }

        val latestState = stateProvider()
        commitState(
            latestState.clearSelectedLocationIf(removedSelected && stopVpnIfSelectedRemoved)
                .copy(
                    isBusy = false,
                    isRefreshing = false,
                    subscriptionHwid = refreshed.subscriptionHwid,
                    subscriptions = refreshed.subscriptions,
                )
                .withStatus(refreshed.statusMessage),
            refreshed.locations,
        )
        return Result.success(refreshed.refreshedCount)
    }
}
