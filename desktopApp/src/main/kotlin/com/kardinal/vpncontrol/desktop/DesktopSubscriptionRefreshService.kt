package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.SubscriptionStatusMessages
import com.kardinal.vpncontrol.model.ConnectionStatusMessages
import com.kardinal.vpncontrol.AutoRefreshLogic
import com.kardinal.vpncontrol.MainCommandLogic
import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.SubscriptionRefreshResultLogic
import com.kardinal.vpncontrol.model.SubscriptionSource

internal data class DesktopAutoRefreshResult(
    val refreshed: DesktopSubscriptionRefreshPayload,
    val postRefreshFailure: DesktopCliResponse? = null,
)

internal class DesktopSubscriptionRefreshService(
    private val stateProvider: () -> MainUiState,
    private val locationsProvider: () -> List<DesktopLocationRecord>,
    private val subscriptionService: DesktopSubscriptionService,
    private val isRuntimeRunning: () -> Boolean,
    private val stopConnection: suspend (String?) -> Result<Unit>,
    private val findBestAfterRefresh: suspend () -> Result<Unit>,
    private val commitState: (nextState: MainUiState, nextLocations: List<DesktopLocationRecord>) -> Result<Unit>,
    private val updateState: ((MainUiState) -> MainUiState) -> Unit,
    private val isActiveLocation: (DesktopLocationRecord) -> Boolean = { it.matchesSelectedLocation(stateProvider()) },
    private val captureRestore: () -> (suspend () -> Result<Unit>) = {
        { Result.failure(IllegalStateException("ROLLBACK_FAILED")) }
    },
) {
    suspend fun refreshAll(): Result<DesktopSubscriptionRefreshPayload> {
        val subscriptions = stateProvider().subscriptions.filter { it.url.isNotBlank() }
        return refreshDetailed(
            subscriptionsToRefresh = subscriptions,
            statusPrefix = SubscriptionRefreshResultLogic.refreshStartMessage(subscriptions.size),
        )
    }

    suspend fun refreshActive(): Result<DesktopSubscriptionRefreshPayload> {
        val refreshTargets = MainCommandLogic.currentSubscriptionSearchTargets(stateProvider())
        if (refreshTargets.isEmpty()) {
            updateState { it.withStatus(SubscriptionRefreshResultLogic.NO_REMOTE_SOURCE_MESSAGE) }
            return Result.failure(IllegalStateException("NOT_FOUND"))
        }
        return refreshDetailed(
            subscriptionsToRefresh = refreshTargets,
            statusPrefix = SubscriptionRefreshResultLogic.refreshStartMessage(refreshTargets.size),
        )
    }

    suspend fun refreshSubscription(subscriptionId: String): Result<DesktopSubscriptionRefreshPayload> {
        val target = stateProvider().subscriptions.firstOrNull { subscription ->
            subscription.id == subscriptionId.trim() && subscription.url.isNotBlank()
        }
        if (target == null) {
            updateState { it.withStatus(SubscriptionStatusMessages.noSubscriptionsToRefresh()) }
            return Result.failure(IllegalStateException("NOT_FOUND"))
        }
        return refreshDetailed(
            subscriptionsToRefresh = listOf(target),
            statusPrefix = SubscriptionRefreshResultLogic.refreshStartMessage(targetCount = 1),
        )
    }

    /** Captures an eligible auto-refresh plan before owner operation admission. */
    fun prepareAutoRefreshCycle(): (suspend () -> Result<DesktopAutoRefreshResult>)? {
        val plan = AutoRefreshLogic.plan(
            state = stateProvider(),
            isRuntimeRunning = isRuntimeRunning(),
        ) ?: return null
        return suspend {
            refreshDetailed(
                subscriptionsToRefresh = plan.subscriptionsToRefresh,
                statusPrefix = plan.statusPrefix,
                stopVpnIfSelectedRemoved = plan.stopVpnIfSelectedRemoved,
            ).fold(
                onSuccess = { refreshed ->
                    if (plan.shouldFindBestAfterRefresh) runCatching { findBestAfterRefresh() }.getOrElse {
                        Result.failure(it)
                    }.fold(
                        onSuccess = { Result.success(DesktopAutoRefreshResult(refreshed)) },
                        onFailure = { failure -> Result.success(DesktopAutoRefreshResult(refreshed,
                            failure.toConnectionFailureResponse())) },
                    ) else Result.success(DesktopAutoRefreshResult(refreshed))
                },
                onFailure = { Result.failure(it) },
            )
        }
    }

    fun hasAutoRefreshCycle(): Boolean = AutoRefreshLogic.plan(
        state = stateProvider(),
        isRuntimeRunning = isRuntimeRunning(),
    ) != null

    suspend fun refresh(
        subscriptionsToRefresh: List<SubscriptionSource>,
        statusPrefix: String,
        stopVpnIfSelectedRemoved: Boolean = true,
    ): Result<Int> {
        return refreshDetailed(subscriptionsToRefresh, statusPrefix, stopVpnIfSelectedRemoved).map { it.refreshedCount }
    }

    private suspend fun refreshDetailed(
        subscriptionsToRefresh: List<SubscriptionSource>,
        statusPrefix: String,
        stopVpnIfSelectedRemoved: Boolean = true,
    ): Result<DesktopSubscriptionRefreshPayload> {
        if (subscriptionsToRefresh.isEmpty()) {
            updateState { it.withStatus(SubscriptionRefreshResultLogic.NO_REMOTE_SOURCE_MESSAGE) }
            return Result.failure(IllegalStateException(SubscriptionStatusMessages.noSubscriptionsToRefresh()))
        }

        updateState { it.copy(isBusy = true, isRefreshing = true).withStatus(statusPrefix) }

        val refreshResult = try { subscriptionService.refreshSubscriptions(
            state = stateProvider(),
            locations = locationsProvider(),
            subscriptionsToRefresh = subscriptionsToRefresh,
            concurrency = stateProvider().validationSettings.normalized().subscriptionRefreshConcurrency,
            onProgress = { message ->
                updateState { it.withStatus(message) }
            },
        ) } catch (cancelled: kotlinx.coroutines.CancellationException) {
            updateState { it.copy(isBusy = false, isRefreshing = false) }
            throw cancelled
        } catch (_: Exception) {
            Result.failure(IllegalStateException("REFRESH_FAILED"))
        }
        if (refreshResult.isFailure) {
            updateState { it.copy(isBusy = false, isRefreshing = false) }
            return Result.failure(
                refreshResult.exceptionOrNull()
                    ?: IllegalStateException(SubscriptionStatusMessages.failedToRefreshSubscriptions()),
            )
        }
        val refreshed = refreshResult.getOrThrow()

        // Once runtime effects begin, finish persistence or rollback even if the client cancels.
        return kotlinx.coroutines.withContext(kotlinx.coroutines.NonCancellable) {
            finishRefresh(refreshed, stopVpnIfSelectedRemoved)
        }
    }

    private suspend fun finishRefresh(
        refreshed: DesktopSubscriptionRefreshPayload,
        stopVpnIfSelectedRemoved: Boolean,
    ): Result<DesktopSubscriptionRefreshPayload> {
        val state = stateProvider()
        val removedSelected = state.selectedProfileRawLink.isNotBlank() &&
            refreshed.locations.none { it.matchesSelectedLocation(state) }
        val removedActive = locationsProvider().any(isActiveLocation) && refreshed.locations.none(isActiveLocation)
        var restore: (suspend () -> Result<Unit>)? = null
        try {
            if (removedActive && state.isVpnRunning && stopVpnIfSelectedRemoved) {
                restore = captureRestore()
                retainDesktopRuntimeInputs(restore as? AutoCloseable)
                val stopResult = runCatching {
                    stopConnection(SubscriptionStatusMessages.subscriptionRefreshRemovedSelectedStopped(state.appMode)).getOrThrow()
                }
                if (stopResult.isFailure) {
                    if (stopResult.exceptionOrNull()?.message == "OUTCOME_UNKNOWN") {
                        desktopControlReportPendingOutcome()
                        return Result.failure(stopResult.exceptionOrNull()!!)
                    }
                    val rollback = kotlinx.coroutines.withContext(kotlinx.coroutines.NonCancellable) { restore() }
                    if (rollback.exceptionOrNull()?.message == "OUTCOME_UNKNOWN") {
                        desktopControlReportPendingOutcome()
                        return Result.failure(rollback.exceptionOrNull()!!)
                    }
                    updateState { it.copy(isBusy = false, isRefreshing = false) }
                    if (rollback.isFailure) return Result.failure(IllegalStateException("ROLLBACK_FAILED"))
                    return Result.failure(stopResult.exceptionOrNull() ?: IllegalStateException(ConnectionStatusMessages.connectionStopFailed(state.appMode)))
                }
            }

            val latestState = stateProvider()
            val committed = commitState(
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
            if (committed.isFailure) {
                if (committed.exceptionOrNull()?.message == "OUTCOME_UNKNOWN") {
                    desktopControlReportPendingOutcome()
                    return Result.failure(committed.exceptionOrNull()!!)
                }
                val rollback = restore?.let { action ->
                    kotlinx.coroutines.withContext(kotlinx.coroutines.NonCancellable) { action() }
                }
                if (rollback?.exceptionOrNull()?.message == "OUTCOME_UNKNOWN") {
                    desktopControlReportPendingOutcome()
                    return Result.failure(rollback.exceptionOrNull()!!)
                }
                updateState { it.copy(isBusy = false, isRefreshing = false) }
                if (rollback?.isFailure == true) return Result.failure(IllegalStateException("ROLLBACK_FAILED"))
            }
            return committed.map { refreshed }
        } finally {
            releaseDesktopRuntimeRestore(restore)
        }
    }
}
