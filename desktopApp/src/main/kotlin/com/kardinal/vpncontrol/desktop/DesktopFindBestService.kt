package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.MainCommandLogic
import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.SubscriptionRefreshResultLogic
import com.kardinal.vpncontrol.data.BenchmarkUrls
import com.kardinal.vpncontrol.data.LocationConfigs
import com.kardinal.vpncontrol.data.SearchEvaluation
import com.kardinal.vpncontrol.model.ProfileSourceMode
import com.kardinal.vpncontrol.model.ProxyProfile
import com.kardinal.vpncontrol.model.StatusMessages
import com.kardinal.vpncontrol.model.SubscriptionSource
import kotlinx.coroutines.withTimeoutOrNull

internal typealias DesktopProfileEvaluator = suspend (
    profiles: List<ProxyProfile>,
    dnsSettings: DesktopDnsSettings,
    benchmarkUrls: BenchmarkUrls,
    settings: DesktopValidationSettings,
    onProgress: suspend (String) -> Unit,
) -> SearchEvaluation

internal class DesktopFindBestService(
    private val stateProvider: () -> MainUiState,
    private val visibleLocationsProvider: () -> List<DesktopLocationRecord>,
    private val locationsProvider: () -> List<DesktopLocationRecord>,
    private val refreshSubscriptions: suspend (subscriptions: List<SubscriptionSource>, statusPrefix: String) -> Result<Int>,
    private val startConnection: suspend (location: DesktopLocationRecord, benchmarkSummary: String?) -> Result<Unit>,
    private val commitState: (locations: List<DesktopLocationRecord>, state: MainUiState) -> Unit,
    private val updateState: ((MainUiState) -> MainUiState) -> Unit,
    private val evaluateProfiles: DesktopProfileEvaluator,
) {
    suspend fun findBestLocation(refreshSubscriptionsFirst: Boolean = true) {
        val preconditionError = MainCommandLogic.refreshPreconditionError(stateProvider())
        if (preconditionError != null) {
            updateState { it.withStatus(preconditionError) }
            return
        }

        if (refreshSubscriptionsFirst && stateProvider().profileSourceMode == ProfileSourceMode.SUBSCRIPTION) {
            val refreshTargets = MainCommandLogic.currentSubscriptionSearchTargets(stateProvider())
            val refreshResult = refreshSubscriptions(
                refreshTargets,
                SubscriptionRefreshResultLogic.refreshStartMessage(refreshTargets.size),
            )
            if (refreshResult.isFailure) {
                return
            }
        }

        val profiles = visibleLocationsProvider().mapNotNull { location ->
            runCatching { LocationConfigs.decodeStoredLocation(location.rawLink) }.getOrNull()
        }
        if (profiles.isEmpty()) {
            updateState { it.withStatus(StatusMessages.noLocationsAvailableForBenchmarking()) }
            return
        }

        updateState {
            it.copy(isBusy = true, isRefreshing = true).withStatus(
                "${MainCommandLogic.refreshStartMessage(it)} Testing fastest candidates in batches...",
            )
        }

        val state = stateProvider()
        val validationSettings = state.validationSettings.normalized()
        val desktopValidationSettings = validationSettings.toDesktopValidationSettings()
        val evaluation = withTimeoutOrNull(desktopValidationSettings.searchTimeoutMillis) {
            evaluateProfiles(
                profiles,
                DesktopDnsSettings(
                    enabled = state.useCustomDns,
                    value = state.customDns,
                ),
                BenchmarkUrls(
                    primary = validationSettings.primaryUrl,
                    secondary = validationSettings.secondaryUrl,
                ),
                desktopValidationSettings,
            ) { progress ->
                updateState {
                    it.copy(isBusy = true, isRefreshing = true).withStatus(progress)
                }
            }
        } ?: run {
            updateState {
                it.copy(isBusy = false, isRefreshing = false).withStatus(
                    StatusMessages.bestLocationSearchTimedOut(),
                )
            }
            return
        }

        val winning = evaluation.winner ?: evaluation.fallback
        val winningRawKey = winning?.let {
            LocationConfigs.normalizeStoredReference(LocationConfigs.encodeStoredLocation(it.profile))
        }
        updateLocationBenchmarks(
            detailsByRawKey = evaluation.locationBenchmarkDetails,
            winningRawKey = winningRawKey,
        )

        if (winning == null) {
            updateState {
                it.copy(isBusy = false, isRefreshing = false).withStatus(
                    evaluation.failureMessage ?: StatusMessages.noSuitableLocationFound(),
                )
            }
            return
        }

        val winnerLocation = locationsProvider().firstOrNull { it.normalizedStorageKey() == winningRawKey }
        if (winnerLocation == null) {
            updateState {
                it.copy(isBusy = false, isRefreshing = false).withStatus(StatusMessages.bestLocationNotMapped())
            }
            return
        }

        startConnection(
            winnerLocation,
            "Best: ${winning.profile.remarks} • ${winning.detail.toCompactBenchmarkLabel()}",
        )
        updateState { it.copy(isRefreshing = false) }
    }

    private fun updateLocationBenchmarks(
        detailsByRawKey: Map<String, String>,
        winningRawKey: String?,
    ) {
        if (detailsByRawKey.isEmpty()) return
        val normalizedDetails = detailsByRawKey.mapKeys { (rawKey, _) ->
            LocationConfigs.normalizeStoredReference(rawKey)
        }
        val updatedLocations = locationsProvider().map { location ->
            val normalized = location.normalizedStorageKey()
            val detail = normalizedDetails[normalized] ?: return@map location
            location.copy(
                benchmarkDetail = detail.toCompactBenchmarkLabel(),
                isValid = benchmarkDetailIndicatesSelectable(detail, location.isValid),
                isSelected = if (winningRawKey != null) {
                    normalized == winningRawKey
                } else {
                    location.isSelected
                },
            )
        }
        commitState(updatedLocations, stateProvider())
    }
}
