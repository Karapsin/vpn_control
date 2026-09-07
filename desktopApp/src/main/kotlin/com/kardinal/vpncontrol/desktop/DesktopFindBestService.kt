package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.DnsSettings
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
    dnsSettings: DnsSettings,
    benchmarkUrls: BenchmarkUrls,
    settings: DesktopValidationSettings,
    onProgress: suspend (String) -> Unit,
) -> BestCandidateAttemptPlan

internal typealias DesktopCandidateVerifierFn = suspend (
    candidate: PreflightResult,
    dnsSettings: DnsSettings,
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
    private val commitState: (locations: List<DesktopLocationRecord>, state: MainUiState) -> Result<Unit>,
    private val updateState: ((MainUiState) -> MainUiState) -> Unit,
    private val evaluateProfiles: DesktopProfileEvaluator,
    private val captureRuntimeRestore: () -> (suspend () -> Result<Unit>),
) {
    suspend fun findBestLocation(refreshSubscriptionsFirst: Boolean = true): Result<Unit> {
        val preconditionError = MainCommandLogic.refreshPreconditionError(stateProvider())
        if (preconditionError != null) {
            updateState { it.withStatus(preconditionError) }
            return Result.failure(IllegalStateException(preconditionError))
        }

        var unresolvedRuntime = false
        var runtimeMayHaveChanged = false
        var runtimeCommitted = false
        var capturedRestore: (suspend () -> Result<Unit>)? = null
        var restoration: Result<Unit>? = null
        suspend fun restoreOnce(): Result<Unit> {
            if (!runtimeMayHaveChanged || runtimeCommitted || unresolvedRuntime) return Result.success(Unit)
            restoration?.let { return it }
            val result = kotlinx.coroutines.withContext(kotlinx.coroutines.NonCancellable) {
                try {
                    requireNotNull(capturedRestore).invoke()
                } catch (failure: Exception) {
                    Result.failure<Unit>(failure)
                }
            }
            restoration = result
            return result
        }
        suspend fun reconcileFailure(failure: Throwable): Throwable {
            if (failure.message == "OUTCOME_UNKNOWN") {
                unresolvedRuntime = true
                desktopControlReportPendingOutcome()
                return failure
            }
            val restoreFailure = restoreOnce().exceptionOrNull() ?: return failure
            if (restoreFailure.message == "OUTCOME_UNKNOWN") {
                unresolvedRuntime = true
                desktopControlReportPendingOutcome()
                return restoreFailure
            }
            return IllegalStateException("ROLLBACK_FAILED")
        }
        return try {
            // Capture before refresh: staged selection is never a runtime recovery target.
            capturedRestore = captureRuntimeRestore()
            val result = findBestAdmitted(
                refreshSubscriptionsFirst,
                restoreRuntime = { restoreOnce() },
                onRuntimeMutation = { runtimeMayHaveChanged = true },
                onRuntimeCommitted = { runtimeCommitted = true },
            )
            result.exceptionOrNull()?.let { Result.failure(reconcileFailure(it)) } ?: result
        } catch (cancelled: kotlinx.coroutines.CancellationException) {
            val failure = reconcileFailure(cancelled)
            if (failure === cancelled) throw cancelled
            Result.failure(failure)
        } catch (failure: Exception) {
            Result.failure(reconcileFailure(failure))
        } finally {
            updateState { it.copy(isBusy = unresolvedRuntime, isRefreshing = false) }
        }
    }

    private suspend fun findBestAdmitted(
        refreshSubscriptionsFirst: Boolean,
        restoreRuntime: suspend () -> Result<Unit>,
        onRuntimeMutation: () -> Unit,
        onRuntimeCommitted: () -> Unit,
    ): Result<Unit> {
        if (refreshSubscriptionsFirst && stateProvider().profileSourceMode == ProfileSourceMode.SUBSCRIPTION) {
            val refreshTargets = MainCommandLogic.currentSubscriptionSearchTargets(stateProvider())
            onRuntimeMutation()
            val refreshResult = refreshSubscriptions(
                refreshTargets,
                SubscriptionRefreshResultLogic.refreshStartMessage(refreshTargets.size),
            )
            if (refreshResult.isFailure) {
                return refreshResult.map { Unit }
            }
        }

        val observedLocations = visibleLocationsProvider().toList()
        val profiles = observedLocations.mapNotNull { location ->
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
        val validationSettings = state.validationSettings.normalized()
        val benchmarkUrls = BenchmarkUrls(
            test = validationSettings.testUrl,
        )
        val desktopValidationSettings = validationSettings.toDesktopValidationSettings()
        val attemptPlan = withTimeoutOrNull(desktopValidationSettings.searchTimeoutMillis) {
            evaluateProfiles(
                profiles,
                state.dnsSettings,
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
            winningLocation = null,
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
                    state.dnsSettings,
                    benchmarkUrls,
                    desktopValidationSettings,
                ).getOrElse { error ->
                    if (error is kotlinx.coroutines.CancellationException) throw error
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
                winningLocation = null,
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
                val observedLocation = observedLocations.firstOrNull {
                    it.normalizedStorageKey() == candidateRawKey
                }
                val candidateLocation = observedLocation?.let { observed ->
                    locationsProvider().firstOrNull {
                        it.sourceUrl == observed.sourceUrl && it.rawLink == observed.rawLink
                    }
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
                onRuntimeMutation()
                val startResult = startConnection(candidateLocation, summary, null)
                if (startResult.isFailure) {
                    val failure = requireNotNull(startResult.exceptionOrNull())
                    if (failure.message == "OUTCOME_UNKNOWN") return startResult
                    if (failure is kotlinx.coroutines.CancellationException || failure.message == "CANCELLED") {
                        val restored = kotlinx.coroutines.withContext(kotlinx.coroutines.NonCancellable) { restoreRuntime() }
                        if (restored.isFailure) return Result.failure(IllegalStateException("ROLLBACK_FAILED"))
                        return startResult
                    }
                    val benchmark = BenchmarkSearchLogic.failedActiveVerificationBenchmark(
                        candidate = candidate,
                        reason = startResult.exceptionOrNull()?.message ?: "start_failed",
                        secondaryStatus = "error",
                    )
                    updateLocationBenchmarks(
                        detailsByRawKey = mapOf(candidateRawKey to benchmark.detail),
                        winningLocation = null,
                    )
                    logBenchmarkDetails(listOf(benchmark))
                    lastFailureMessage = benchmark.detail
                    continue
                }

                onRuntimeCommitted()
                candidateBenchmarks[candidateRawKey] = selectedBenchmark
                updateLocationBenchmarks(
                    detailsByRawKey = mapOf(candidateRawKey to selectedBenchmark.detail),
                    winningLocation = candidateLocation,
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
                ).getOrThrow()
                return Result.success(Unit)
            }
            currentIndex += window.size.coerceAtLeast(1)
        }

        val finalMessage = lastFailureMessage ?: BenchmarkStatusMessages.noSuitableLocationFound()
        val restoreResult = restoreRuntime()
        updateState {
            it.copy(isBusy = false, isRefreshing = false).withStatus(
                if (restoreResult.isFailure) {
                    if (it.isVpnRunning) ConnectionStatusMessages.connectionStartFailed(state.appMode)
                    else ConnectionStatusMessages.previousConnectionRestoreFailedStopped(state.appMode, finalMessage)
                } else if (it.isVpnRunning) ConnectionStatusMessages.previousConnectionRestoredWithReason(state.appMode, finalMessage)
                else finalMessage,
            )
        }
        if (restoreResult.isFailure) return Result.failure(IllegalStateException("ROLLBACK_FAILED"))
        return Result.failure(IllegalStateException(finalMessage))
    }

    private fun updateLocationBenchmarks(
        detailsByRawKey: Map<String, String>,
        winningLocation: DesktopLocationRecord?,
    ) {
        if (detailsByRawKey.isEmpty()) return
        val normalizedDetails = detailsByRawKey.mapKeys { (rawKey, _) ->
            LocationConfigs.normalizeStoredReference(rawKey)
        }
        val updatedLocations = locationsProvider().map { location ->
            val normalized = location.normalizedStorageKey()
            val detail = normalizedDetails[normalized]
            location.copy(
                benchmarkDetail = detail?.toCompactBenchmarkLabel() ?: location.benchmarkDetail,
                isValid = detail?.let { benchmarkDetailIndicatesSelectable(it, location.isValid) } ?: location.isValid,
                isSelected = if (winningLocation != null) {
                    location.sourceUrl == winningLocation.sourceUrl && location.rawLink == winningLocation.rawLink
                } else {
                    location.isSelected
                },
            )
        }
        commitState(updatedLocations, stateProvider()).getOrThrow()
    }

    private fun normalizedProfileKey(profile: ProxyProfile): String =
        LocationConfigs.normalizeStoredReference(LocationConfigs.encodeStoredLocation(profile))

    private fun logBenchmarkDetails(benchmarks: List<ProfileBenchmark>) {
        benchmarks.forEach { benchmark ->
            updateState { it.withStatus(benchmark.detail) }
        }
    }
}
