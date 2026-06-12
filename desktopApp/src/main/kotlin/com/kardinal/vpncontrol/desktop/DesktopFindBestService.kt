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
import com.kardinal.vpncontrol.model.AppMode
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

internal typealias DesktopActiveConnectionVerifierFn = suspend (
    candidate: PreflightResult,
    appMode: AppMode,
    proxyPort: Int?,
    benchmarkUrls: BenchmarkUrls,
    settings: DesktopValidationSettings,
) -> Result<ProfileBenchmark>

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
    private val stopConnection: suspend (message: String?) -> Result<Unit>,
    private val currentRuntimePort: () -> Int?,
    private val activeVerificationPortAllocator: () -> Int,
    private val verifyActiveConnection: DesktopActiveConnectionVerifierFn,
    private val verifyCandidate: DesktopCandidateVerifierFn,
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
            updateState { it.withStatus(BenchmarkStatusMessages.noLocationsAvailableForBenchmarking()) }
            return
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
            updateState {
                it.copy(isBusy = false, isRefreshing = false).withStatus(
                    BenchmarkStatusMessages.bestLocationSearchTimedOut(),
                )
            }
            return
        }

        updateLocationBenchmarks(
            detailsByRawKey = attemptPlan.locationBenchmarkDetails,
            winningRawKey = null,
        )

        if (attemptPlan.orderedAttempts.isEmpty()) {
            updateState {
                it.copy(isBusy = false, isRefreshing = false).withStatus(
                    attemptPlan.failureMessage ?: BenchmarkStatusMessages.noSuitableLocationFound(),
                )
            }
            return
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
                val activeVerificationPort = if (stateProvider().appMode == AppMode.VPN) {
                    activeVerificationPortAllocator()
                } else {
                    null
                }
                val startResult = startConnection(candidateLocation, null, activeVerificationPort)
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

                updateState {
                    it.copy(isBusy = true, isRefreshing = true).withStatus(
                        BenchmarkStatusMessages.verifyingBlockedResource(candidate.profile.remarks),
                    )
                }
                val proxyPort = when (stateProvider().appMode) {
                    AppMode.VPN -> activeVerificationPort
                    AppMode.PROXY_ONLY -> currentRuntimePort()
                }
                val verificationBenchmark = verifyActiveConnection(
                    candidate,
                    stateProvider().appMode,
                    proxyPort,
                    benchmarkUrls,
                    desktopValidationSettings,
                ).getOrElse { error ->
                    BenchmarkSearchLogic.failedActiveVerificationBenchmark(
                        candidate = candidate,
                        reason = error.message ?: "active_verification_failed",
                        secondaryStatus = "error",
                    )
                }
                candidateBenchmarks[candidateRawKey] = verificationBenchmark
                updateLocationBenchmarks(
                    detailsByRawKey = mapOf(candidateRawKey to verificationBenchmark.detail),
                    winningRawKey = if (verificationBenchmark.testStatus == "ok") candidateRawKey else null,
                )
                logBenchmarkDetails(listOf(verificationBenchmark))
                val verified = verificationBenchmark.testStatus == "ok"
                if (verified) {
                    val summary = BenchmarkStatusMessages.bestLocationSummary(
                        verificationBenchmark.profile.remarks,
                        verificationBenchmark.detail.toCompactBenchmarkLabel(),
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
                                verificationBenchmark.profile.remarks,
                            ),
                        ),
                    )
                    return
                }

                lastFailureMessage = verificationBenchmark.detail
                val switchMessage = BenchmarkStatusMessages.switchingAfterVerificationFailure(candidate.profile.remarks)
                updateState { it.withStatus(switchMessage) }
                val stopResult = stopConnection(switchMessage)
                if (stopResult.isFailure) {
                    updateState {
                        it.copy(isBusy = false, isRefreshing = false).withStatus(
                            stopResult.exceptionOrNull()?.message ?: switchMessage,
                        )
                    }
                    return
                }
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
