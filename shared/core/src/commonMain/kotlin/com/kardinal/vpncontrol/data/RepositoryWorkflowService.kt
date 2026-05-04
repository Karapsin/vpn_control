package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.BenchmarkSummaryFormatter
import com.kardinal.vpncontrol.model.SubscriptionStatusMessages
import com.kardinal.vpncontrol.model.BenchmarkStatusMessages
import com.kardinal.vpncontrol.model.PersistedState
import com.kardinal.vpncontrol.model.ProfileSelection
import com.kardinal.vpncontrol.model.ProfileSourceMode
import com.kardinal.vpncontrol.model.SubscriptionSource
import com.kardinal.vpncontrol.model.ProxyProfile
import com.kardinal.vpncontrol.model.activeSubscriptionUrls
import com.kardinal.vpncontrol.model.isAllSubscriptionsGroupActive
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit

data class SubscriptionRefreshFailure(
    val subscriptionId: String,
    val sourceUrl: String,
    val displayName: String,
    val message: String,
)

data class SubscriptionRefreshBatchResult(
    val refreshedCount: Int,
    val failedSubscriptions: List<SubscriptionRefreshFailure> = emptyList(),
) {
    val failedCount: Int get() = failedSubscriptions.size
    val hasFailures: Boolean get() = failedSubscriptions.isNotEmpty()
}

object RepositoryWorkflowService {
    suspend fun refreshActiveSubscriptionCache(
        state: PersistedState,
        refreshAllSubscriptions: suspend () -> Result<SubscriptionRefreshBatchResult>,
        fetchSubscriptionLocations: suspend (String) -> List<ProxyProfile>,
        updateSubscriptionCache: suspend (subscriptionId: String, rawLinks: List<String>) -> Unit,
        updateRefreshStatus: suspend (subscriptionId: String, status: String) -> Unit,
    ): Result<SubscriptionRefreshBatchResult> {
        return runCatching {
            if (isAllSubscriptionsGroupActive(state.activeSubscriptionId, state.subscriptions)) {
                val refreshed = refreshAllSubscriptions().getOrThrow()
                require(refreshed.refreshedCount > 0) { SubscriptionStatusMessages.noSubscriptionsRefreshed() }
                return@runCatching refreshed
            }
            val subscriptionId = state.activeSubscriptionId
            val sourceUrl = state.profileUrl
            require(subscriptionId.isNotBlank() && sourceUrl.isNotBlank()) {
                SubscriptionStatusMessages.noActiveSubscriptionSelected()
            }
            val profiles = fetchSubscriptionLocations(sourceUrl)
            require(profiles.isNotEmpty()) { BenchmarkStatusMessages.noLocationsFoundSelectedSubscription() }
            updateSubscriptionCache(subscriptionId, profiles.map { it.rawLink })
            SubscriptionRefreshBatchResult(refreshedCount = 1)
        }.also { result ->
            if (result.isFailure) {
                val activeId = state.activeSubscriptionId
                if (activeId.isNotBlank()) {
                    updateRefreshStatus(
                        activeId,
                        result.exceptionOrNull()?.message ?: SubscriptionStatusMessages.backgroundRefreshFailed(),
                    )
                }
            }
        }
    }

    suspend fun refreshSubscriptionCache(
        state: PersistedState,
        subscriptionId: String,
        fetchSubscriptionLocations: suspend (String) -> List<ProxyProfile>,
        updateSubscriptionCache: suspend (subscriptionId: String, rawLinks: List<String>) -> Unit,
        updateRefreshStatus: suspend (subscriptionId: String, status: String) -> Unit,
    ): Result<SubscriptionRefreshBatchResult> {
        return runCatching {
            val target = state.subscriptions.firstOrNull { subscription ->
                subscription.id == subscriptionId && subscription.url.isNotBlank()
            }
            require(target != null) { SubscriptionStatusMessages.noSubscriptionsToRefresh() }
            refreshSingleSubscription(
                subscription = target,
                fetchSubscriptionLocations = fetchSubscriptionLocations,
                updateSubscriptionCache = updateSubscriptionCache,
                updateRefreshStatus = updateRefreshStatus,
            ).getOrThrow()
            SubscriptionRefreshBatchResult(refreshedCount = 1)
        }
    }

    suspend fun refreshAllSubscriptionsCaches(
        state: PersistedState,
        fetchSubscriptionLocations: suspend (String) -> List<ProxyProfile>,
        updateSubscriptionCache: suspend (subscriptionId: String, rawLinks: List<String>) -> Unit,
        updateRefreshStatus: suspend (subscriptionId: String, status: String) -> Unit,
        displayLabel: (SubscriptionSource) -> String,
    ): Result<SubscriptionRefreshBatchResult> {
        return runCatching {
            var refreshed = 0
            var lastFailure: Throwable? = null
            val failures = mutableListOf<SubscriptionRefreshFailure>()
            val loaded = loadSubscriptionsConcurrently(
                subscriptions = state.subscriptions,
                concurrency = state.validationSettings.normalized().subscriptionRefreshConcurrency,
                fetchSubscriptionLocations = fetchSubscriptionLocations,
            )
            loaded.forEach { load ->
                val subscription = load.subscription
                val error = load.error
                if (error == null) {
                    val profiles = checkNotNull(load.profiles)
                    runCatching {
                        updateSubscriptionCache(subscription.id, profiles.map { it.rawLink })
                    }.onSuccess {
                        refreshed += 1
                    }.onFailure { updateError ->
                        lastFailure = updateError
                        updateRefreshStatus(
                            subscription.id,
                            updateError.message ?: SubscriptionStatusMessages.backgroundRefreshFailed(),
                        )
                        failures += SubscriptionRefreshFailure(
                            subscriptionId = subscription.id,
                            sourceUrl = subscription.url,
                            displayName = displayLabel(subscription),
                            message = updateError.message ?: SubscriptionStatusMessages.backgroundRefreshFailed(),
                        )
                    }
                } else {
                    lastFailure = error
                    updateRefreshStatus(
                        subscription.id,
                        error.message ?: SubscriptionStatusMessages.backgroundRefreshFailed(),
                    )
                    failures += SubscriptionRefreshFailure(
                        subscriptionId = subscription.id,
                        sourceUrl = subscription.url,
                        displayName = displayLabel(subscription),
                        message = error.message ?: SubscriptionStatusMessages.backgroundRefreshFailed(),
                    )
                }
            }
            if (refreshed == 0 && lastFailure != null) {
                throw lastFailure!!
            }
            SubscriptionRefreshBatchResult(
                refreshedCount = refreshed,
                failedSubscriptions = failures,
            )
        }
    }

    private suspend fun loadSubscriptionsConcurrently(
        subscriptions: List<SubscriptionSource>,
        concurrency: Int,
        fetchSubscriptionLocations: suspend (String) -> List<ProxyProfile>,
    ): List<SubscriptionRefreshLoad> = coroutineScope {
        val semaphore = Semaphore(concurrency.coerceAtLeast(1))
        subscriptions.mapIndexed { index, subscription ->
            async {
                semaphore.withPermit {
                    val result = runCatching {
                        val profiles = fetchSubscriptionLocations(subscription.url)
                        require(profiles.isNotEmpty()) {
                            BenchmarkStatusMessages.noLocationsFoundSelectedSubscription()
                        }
                        profiles
                    }
                    SubscriptionRefreshLoad(
                        index = index,
                        subscription = subscription,
                        profiles = result.getOrNull(),
                        error = result.exceptionOrNull(),
                    )
                }
            }
        }.awaitAll().sortedBy(SubscriptionRefreshLoad::index)
    }

    private data class SubscriptionRefreshLoad(
        val index: Int,
        val subscription: SubscriptionSource,
        val profiles: List<ProxyProfile>?,
        val error: Throwable?,
    )

    fun hasStoredSelection(
        state: PersistedState,
        hasLastSelectedProfile: Boolean,
    ): Boolean {
        return state.selectedProfileJson.isNotBlank() ||
            state.selectedProfileRawLink.isNotBlank() ||
            hasLastSelectedProfile
    }

    fun isStoredSelectionAllowed(state: PersistedState): Boolean {
        val selectedStored = LocationConfigs.selectedStoredReference(
            selectedProfileJson = state.selectedProfileJson,
            selectedProfileRawLink = state.selectedProfileRawLink,
        )
        return when (state.profileSourceMode) {
            ProfileSourceMode.SUBSCRIPTION -> {
                val activeUrls = activeSubscriptionUrls(state.activeSubscriptionId, state.subscriptions)
                state.selectedProfileSourceUrl.isNotBlank() &&
                    state.selectedProfileSourceUrl in activeUrls &&
                    (selectedStored.isBlank() || state.currentLocations.isEmpty() || selectedStored in state.currentLocations)
            }
            ProfileSourceMode.CURRENT_LOCATIONS -> {
                when {
                    state.selectedProfileJson.isNotBlank() -> state.selectedProfileJson in state.currentLocations
                    state.selectedProfileRawLink.isNotBlank() -> selectedStored in state.currentLocations
                    else -> true
                }
            }
        }
    }

    fun shouldClearSelectionForSourceState(state: PersistedState): Boolean {
        if (state.selectedProfileName.isBlank()) return false
        return when (state.profileSourceMode) {
            ProfileSourceMode.SUBSCRIPTION -> {
                val activeUrls = activeSubscriptionUrls(state.activeSubscriptionId, state.subscriptions)
                if (isAllSubscriptionsGroupActive(state.activeSubscriptionId, state.subscriptions)) {
                    val selectedStored = LocationConfigs.selectedStoredReference(
                        selectedProfileJson = state.selectedProfileJson,
                        selectedProfileRawLink = state.selectedProfileRawLink,
                    )
                    selectedStored.isNotBlank() && selectedStored !in state.currentLocations
                } else {
                    state.selectedProfileSourceUrl.isBlank() ||
                        state.selectedProfileSourceUrl !in activeUrls
                }
            }
            ProfileSourceMode.CURRENT_LOCATIONS -> {
                val selectedStored = LocationConfigs.selectedStoredReference(
                    selectedProfileJson = state.selectedProfileJson,
                    selectedProfileRawLink = state.selectedProfileRawLink,
                )
                selectedStored.isNotBlank() && selectedStored !in state.currentLocations
            }
        }
    }

    fun resolveSelectionSourceUrl(
        state: PersistedState,
        selection: ProfileSelection,
        sourceUrlOverride: String? = null,
        sourceUrlForStoredLocation: (String) -> String,
    ): String {
        return sourceUrlOverride ?: selection.sourceUrl.ifBlank {
            if (state.profileSourceMode == ProfileSourceMode.SUBSCRIPTION) {
                sourceUrlForStoredLocation(LocationConfigs.encodeStoredLocation(selection.profile))
            } else {
                ""
            }
        }
    }

    fun selectionSummary(
        state: PersistedState,
        detail: String,
        sourceUrl: String,
        sourceLabelForUrl: (String) -> String?,
    ): String {
        val baseDetail = BenchmarkSummaryFormatter.detailWithoutBestSource(detail)
        val normalizedSourceUrl = sourceUrl.trim()
        if (state.profileSourceMode != ProfileSourceMode.SUBSCRIPTION || normalizedSourceUrl.isBlank()) {
            return baseDetail
        }
        val shouldShowSource =
            isAllSubscriptionsGroupActive(state.activeSubscriptionId, state.subscriptions) ||
                (state.profileUrl.isNotBlank() && normalizedSourceUrl != state.profileUrl)
        if (!shouldShowSource) {
            return baseDetail
        }
        val sourceLabel = sourceLabelForUrl(normalizedSourceUrl) ?: return baseDetail
        return BenchmarkSummaryFormatter.appendBestSource(baseDetail, sourceLabel)
    }

    private suspend fun refreshSingleSubscription(
        subscription: SubscriptionSource,
        fetchSubscriptionLocations: suspend (String) -> List<ProxyProfile>,
        updateSubscriptionCache: suspend (subscriptionId: String, rawLinks: List<String>) -> Unit,
        updateRefreshStatus: suspend (subscriptionId: String, status: String) -> Unit,
    ): Result<Unit> {
        return runCatching {
            val profiles = fetchSubscriptionLocations(subscription.url)
            require(profiles.isNotEmpty()) { BenchmarkStatusMessages.noLocationsFoundSelectedSubscription() }
            updateSubscriptionCache(subscription.id, profiles.map { it.rawLink })
        }.also { result ->
            if (result.isFailure) {
                updateRefreshStatus(
                    subscription.id,
                    result.exceptionOrNull()?.message ?: SubscriptionStatusMessages.backgroundRefreshFailed(),
                )
            }
        }
    }
}
