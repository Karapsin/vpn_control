package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.BenchmarkStatusMessages
import com.kardinal.vpncontrol.model.ConnectionStatusMessages
import com.kardinal.vpncontrol.MainCommandLogic
import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.SubscriptionRefreshResultLogic
import com.kardinal.vpncontrol.data.BenchmarkUrls
import com.kardinal.vpncontrol.data.BenchmarkSearchLogic
import com.kardinal.vpncontrol.data.BestCandidateAttemptPlan
import com.kardinal.vpncontrol.data.LocationConfigs
import com.kardinal.vpncontrol.data.PreflightResult
import com.kardinal.vpncontrol.model.ProfileBenchmark
import com.kardinal.vpncontrol.model.ProfileSourceMode
import com.kardinal.vpncontrol.model.ProxyProfile
import com.kardinal.vpncontrol.model.SubscriptionSource
import kotlinx.coroutines.withTimeoutOrNull

internal typealias DesktopProfileEvaluator = suspend (
    profiles: List<ProxyProfile>,
    dnsSettings: DesktopDnsSettings,
    benchmarkUrls: BenchmarkUrls,
    settings: DesktopValidationSettings,
    onProgress: suspend (String) -> Unit,
) -> BestCandidateAttemptPlan

internal typealias DesktopCandidateVerifierFn = suspend (
    candidate: PreflightResult,
    dnsSettings: DesktopDnsSettings,
    benchmarkUrls: BenchmarkUrls,
    settings: DesktopValidationSettings,
) -> Result<ProfileBenchmark>

internal class DesktopFindBestService(
    private val stateProvider: () -> MainUiState,
    private val visibleLocationsProvider: () -> List<DesktopLocationRecord>,
    private val locationsProvider: () -> List<DesktopLocationRecord>,
    private val refreshSubscriptions: suspend (subscriptions: List<SubscriptionSource>, statusPrefix: String) -> Result<Int>,
    private val startConnection: suspend (
        location: DesktopLocationRecord,
        benchmarkSummary: String?,
        activeVerificationPort: Int?,
    ) -> Result<Unit>,
    private val verifyCandidate: DesktopCandidateVerifierFn,
    private val commitState: (locations: List<DesktopLocationRecord>, state: MainUiState) -> Unit,
    private val updateState: ((MainUiState) -> MainUiState) -> Unit,
    private val evaluateProfiles: DesktopProfileEvaluator,
) {
    suspend fun findBestLocation(refreshSubscriptionsFirst: Boolean = true): Result<Unit> {
        val preconditionError = MainCommandLogic.refreshPreconditionError(stateProvider())
        if (preconditionError != null) {
            updateState { it.withStatus(preconditionError) }
            return Result.failure(IllegalStateException(preconditionError))
        }

        if (refreshSubscriptionsFirst && stateProvider().profileSourceMode == ProfileSourceMode.SUBSCRIPTION) {
            val refreshTargets = MainCommandLogic.currentSubscriptionSearchTargets(stateProvider())
            val refreshResult = refreshSubscriptions(
                refreshTargets,
                SubscriptionRefreshResultLogic.refreshStartMessage(refreshTargets.size),
            )
            if (refreshResult.isFailure) {
                return refreshResult.map { Unit }
            }
        }

        val profiles = visibleLocationsProvider().mapNotNull { location ->
            runCatching { LocationConfigs.decodeStoredLocation(location.rawLink) }.getOrNull()
        }
        if (profiles.isEmpty()) {
            val message = BenchmarkStatusMessages.noLocationsAvailableForBenchmarking()
            updateState { it.withStatus(message) }
            return Result.failure(IllegalStateException(message))
        }

        updateState {
            it.copy(isBusy = true, isRefreshing = true).withStatus(
                BenchmarkStatusMessages.findBestTestingFastest(it.profileSourceMode),
            )
        }

        val state = stateProvider()
        val previousLocations = locationsProvider()
        val previousLocation = previousLocations.firstOrNull { it.matchesSelectedLocation(state) }
        val previousBenchmarkSummary = state.lastBenchmarkSummary
        val wasRunning = state.isVpnRunning
        val validationSettings = state.validationSettings.normalized()
        val benchmarkUrls = BenchmarkUrls(
            test = validationSettings.testUrl,
        )
        val desktopValidationSettings = validationSettings.toDesktopValidationSettings()
        val attemptPlan = withTimeoutOrNull(desktopValidationSettings.searchTimeoutMillis) {
            evaluateProfiles(
                profiles,
                DesktopDnsSettings(
                    enabled = state.useCustomDns,
                    value = state.customDns,
                ),
                benchmarkUrls,
                desktopValidationSettings,
            ) { progress ->
                updateState {
                    it.copy(isBusy = true, isRefreshing = true).withStatus(progress)
                }
            }
        } ?: run {
            val message = BenchmarkStatusMessages.bestLocationSearchTimedOut()
            updateState {
                it.copy(isBusy = false, isRefreshing = false).withStatus(
                    message,
                )
            }
            return Result.failure(IllegalStateException(message))
        }

        updateLocationBenchmarks(
            detailsByRawKey = attemptPlan.locationBenchmarkDetails,
            winningRawKey = null,
        )

        if (attemptPlan.orderedAttempts.isEmpty()) {
            val message = attemptPlan.failureMessage ?: BenchmarkStatusMessages.noSuitableLocationFound()
            updateState {
                it.copy(isBusy = false, isRefreshing = false).withStatus(
                    message,
                )
            }
            return Result.failure(IllegalStateException(message))
        }

        val verificationWindowSize = validationSettings.activeVerificationWindowSize
        val candidateBenchmarks = mutableMapOf<String, ProfileBenchmark>()
        var lastFailureMessage: String? = attemptPlan.failureMessage
        var currentIndex = 0
        while (currentIndex < attemptPlan.orderedAttempts.size) {
            val window = BenchmarkSearchLogic.activeVerificationWindow(
                attempts = attemptPlan.orderedAttempts,
                currentIndex = currentIndex,
                windowSize = verificationWindowSize,
            )
            val windowStart = currentIndex + 1
            val windowEnd = currentIndex + window.size
            updateState {
                it.copy(isBusy = true, isRefreshing = true).withStatus(
                    BenchmarkStatusMessages.testingLocationsRange(
                        start = windowStart,
                        end = windowEnd,
                        total = attemptPlan.orderedAttempts.size,
                    ),
                )
            }
            val precheck = BenchmarkSearchLogic.validateCandidateWindowForBestPass(
                attempts = attemptPlan.orderedAttempts,
                currentIndex = currentIndex,
                windowSize = verificationWindowSize,
            ) { candidate, _ ->
                val rawKey = normalizedProfileKey(candidate.profile)
                candidateBenchmarks[rawKey] ?: verifyCandidate(
                    candidate,
                    DesktopDnsSettings(
                        enabled = state.useCustomDns,
                        value = state.customDns,
                    ),
                    benchmarkUrls,
                    desktopValidationSettings,
                ).getOrElse { error ->
                    BenchmarkSearchLogic.failedActiveVerificationBenchmark(
                        candidate = candidate,
                        reason = error.message ?: "candidate_verification_failed",
                        secondaryStatus = "error",
                    )
                }
            }
            precheck.completed.forEach { result ->
                val rawKey = normalizedProfileKey(result.benchmark.profile)
                candidateBenchmarks[rawKey] = result.benchmark
            }
            updateLocationBenchmarks(
                detailsByRawKey = precheck.completed.associate { result ->
                    normalizedProfileKey(result.benchmark.profile) to result.benchmark.detail
                },
                winningRawKey = null,
            )
            logBenchmarkDetails(precheck.completed.map { it.benchmark })

            val verifiedCandidates = precheck.verifiedCandidates
            if (verifiedCandidates.isEmpty()) {
                lastFailureMessage = precheck.completed.lastOrNull()?.benchmark?.detail ?: lastFailureMessage
                currentIndex += window.size.coerceAtLeast(1)
                continue
            }

            for (winner in verifiedCandidates) {
                val candidate = winner.attempt
                val candidateRawKey = normalizedProfileKey(candidate.profile)
                val candidateLocation = locationsProvider().firstOrNull {
                    it.normalizedStorageKey() == candidateRawKey
                }
                if (candidateLocation == null) {
                    lastFailureMessage = BenchmarkStatusMessages.bestLocationNotMapped()
                    continue
                }

                updateState {
                    it.copy(isBusy = true, isRefreshing = true).withStatus(
                        BenchmarkStatusMessages.tryingBestCandidate(
                            attempt = winner.attemptIndex + 1,
                            total = attemptPlan.orderedAttempts.size,
                            remarks = candidate.profile.remarks,
                        ),
                    )
                }
                val selectedBenchmark = winner.benchmark
                val summary = BenchmarkStatusMessages.bestLocationSummary(
                    selectedBenchmark.profile.remarks,
                    selectedBenchmark.detail.toCompactBenchmarkLabel(),
                )
                val startResult = startConnection(candidateLocation, summary, null)
                if (startResult.isFailure) {
                    val benchmark = BenchmarkSearchLogic.failedActiveVerificationBenchmark(
                        candidate = candidate,
                        reason = startResult.exceptionOrNull()?.message ?: "start_failed",
                        secondaryStatus = "error",
                    )
                    updateLocationBenchmarks(
                        detailsByRawKey = mapOf(candidateRawKey to benchmark.detail),
                        winningRawKey = null,
                    )
                    logBenchmarkDetails(listOf(benchmark))
                    lastFailureMessage = benchmark.detail
                    continue
                }

                candidateBenchmarks[candidateRawKey] = selectedBenchmark
                updateLocationBenchmarks(
                    detailsByRawKey = mapOf(candidateRawKey to selectedBenchmark.detail),
                    winningRawKey = candidateRawKey,
                )
                commitState(
                    locationsProvider(),
                    stateProvider().copy(
                        isBusy = false,
                        isRefreshing = false,
                        lastBenchmarkSummary = summary,
                    ).withStatus(
                        ConnectionStatusMessages.connectionStartedOnTarget(
                            stateProvider().appMode,
                            selectedBenchmark.profile.remarks,
                        ),
                    ),
                )
                return Result.success(Unit)
            }
            currentIndex += window.size.coerceAtLeast(1)
        }

        val finalMessage = lastFailureMessage ?: BenchmarkStatusMessages.noSuitableLocationFound()
        if (wasRunning && previousLocation != null) {
            val restoreResult = startConnection(previousLocation, previousBenchmarkSummary, null)
            updateState {
                it.copy(isBusy = false, isRefreshing = false).withStatus(
                    if (restoreResult.isSuccess) {
                        ConnectionStatusMessages.previousConnectionRestoredWithReason(state.appMode, finalMessage)
                    } else {
                        restoreResult.exceptionOrNull()?.message ?: finalMessage
                    },
                )
            }
        } else {
            commitState(
                previousLocations,
                state.copy(isBusy = false, isRefreshing = false, isVpnRunning = false).withStatus(finalMessage),
            )
        }
        return Result.failure(IllegalStateException(finalMessage))
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

    private fun normalizedProfileKey(profile: ProxyProfile): String =
        LocationConfigs.normalizeStoredReference(LocationConfigs.encodeStoredLocation(profile))

    private fun logBenchmarkDetails(benchmarks: List<ProfileBenchmark>) {
        benchmarks.forEach { benchmark ->
            updateState { it.withStatus(benchmark.detail) }
        }
    }
}
