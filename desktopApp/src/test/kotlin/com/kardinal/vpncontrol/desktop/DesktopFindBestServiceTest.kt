package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.BenchmarkStatusMessages
import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.data.BenchmarkSearchLogic
import com.kardinal.vpncontrol.data.BestCandidateAttemptPlan
import com.kardinal.vpncontrol.data.LocationConfigs
import com.kardinal.vpncontrol.data.PreflightResult
import com.kardinal.vpncontrol.data.ProxyRunResult
import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.ProfileSourceMode
import com.kardinal.vpncontrol.model.ProxyProfile
import com.kardinal.vpncontrol.model.SubscriptionSource
import kotlin.test.Test
import kotlin.test.assertSame
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest

class DesktopFindBestServiceTest {
    @Test
    fun findBestUpdatesBenchmarksAndStartsWinner() = runTest {
        val profile = testProfile("Germany")
        val rawLink = LocationConfigs.encodeStoredLocation(profile)
        var state = MainUiState(
            profileSourceMode = ProfileSourceMode.CURRENT_LOCATIONS,
            currentLocations = listOf(rawLink),
        )
        var locations = listOf(testLocation(profile, rawLink))
        var startedLocation: DesktopLocationRecord? = null
        val events = mutableListOf<String>()
        val service = DesktopFindBestService(
            captureRuntimeRestore = { { Result.success(Unit) } },
            stateProvider = { state },
            visibleLocationsProvider = { locations },
            locationsProvider = { locations },
            refreshSubscriptions = { _, _ -> error("refresh should not run") },
            startConnection = { location, summary, activeVerificationPort ->
                events += "start ${location.name}"
                startedLocation = location
                assertEquals(
                    BenchmarkStatusMessages.bestLocationSummary("Germany", "test ok • tcp 50.0ms"),
                    summary,
                )
                assertEquals(null, activeVerificationPort)
                Result.success(Unit)
            },
            verifyCandidate = { candidate, _, _, _ ->
                events += "precheck ${candidate.profile.remarks}"
                Result.success(okBenchmark(candidate, total = 55.0))
            },
            commitState = { nextLocations, nextState ->
                locations = nextLocations
                state = nextState
                Result.success(Unit)
            },
            updateState = { transform -> state = transform(state) },
            evaluateProfiles = { profiles, _, _, _, onProgress ->
                assertEquals(listOf(profile.rawLink), profiles.map { it.rawLink })
                onProgress("Testing locations 1-1 of 1...")
                val preflight = PreflightResult(
                    profile = profile,
                    connectMillis = 50.0,
                    detail = "Germany: tcp=50.0ms country=DE",
                    candidateCountryCode = "DE",
                )
                BestCandidateAttemptPlan(
                    orderedAttempts = listOf(preflight),
                    excluded = emptyList(),
                    locationBenchmarkDetails = mapOf(rawLink to preflight.detail),
                    failureMessage = null,
                )
            },
        )

        service.findBestLocation(refreshSubscriptionsFirst = false)

        assertEquals(
            "Germany",
            startedLocation?.name,
            "status=${state.statusMessage}; keys=${locations.map { it.normalizedStorageKey() }}; raw=$rawLink",
        )
        assertEquals(
            BenchmarkStatusMessages.bestLocationSummary("Germany", "test ok • tcp 50.0ms"),
            state.lastBenchmarkSummary,
        )
        assertEquals(listOf("precheck Germany", "start Germany"), events)
        assertTrue(locations.single().isSelected)
        assertEquals("test ok • tcp 50.0ms", locations.single().benchmarkDetail)
        assertFalse(state.isRefreshing)
    }

    @Test
    fun firstCandidateInWindowFailsPrecheckSecondStarts() = runTest {
        val first = testProfile("First")
        val second = testProfile("Second")
        val firstRaw = LocationConfigs.encodeStoredLocation(first)
        val secondRaw = LocationConfigs.encodeStoredLocation(second)
        var state = MainUiState(
            profileSourceMode = ProfileSourceMode.CURRENT_LOCATIONS,
            currentLocations = listOf(firstRaw, secondRaw),
            appMode = AppMode.PROXY_ONLY,
        )
        var locations = listOf(
            testLocation(first, firstRaw, index = 0),
            testLocation(second, secondRaw, index = 1),
        )
        val starts = mutableListOf<String>()
        val prechecks = mutableListOf<String>()
        val firstPreflight = PreflightResult(
            profile = first,
            connectMillis = 20.0,
            detail = "First: tcp=20.0ms country=DE",
            candidateCountryCode = "DE",
        )
        val secondPreflight = PreflightResult(
            profile = second,
            connectMillis = 40.0,
            detail = "Second: tcp=40.0ms country=NL",
            candidateCountryCode = "NL",
        )
        val service = DesktopFindBestService(
            captureRuntimeRestore = { { Result.success(Unit) } },
            stateProvider = { state },
            visibleLocationsProvider = { locations },
            locationsProvider = { locations },
            refreshSubscriptions = { _, _ -> error("refresh should not run") },
            startConnection = { location, _, _ ->
                starts += location.name
                Result.success(Unit)
            },
            verifyCandidate = { candidate, _, _, _ ->
                prechecks += candidate.profile.remarks
                if (candidate.profile.remarks == "First") {
                    Result.success(blockedBenchmark(candidate))
                } else {
                    Result.success(okBenchmark(candidate, total = 55.0))
                }
            },
            commitState = { nextLocations, nextState ->
                locations = nextLocations
                state = nextState
                Result.success(Unit)
            },
            updateState = { transform -> state = transform(state) },
            evaluateProfiles = { _, _, _, _, _ ->
                BestCandidateAttemptPlan(
                    orderedAttempts = listOf(firstPreflight, secondPreflight),
                    excluded = emptyList(),
                    locationBenchmarkDetails = mapOf(
                        firstRaw to firstPreflight.detail,
                        secondRaw to secondPreflight.detail,
                    ),
                    failureMessage = null,
                )
            },
        )

        service.findBestLocation(refreshSubscriptionsFirst = false)

        assertEquals(listOf("First", "Second"), prechecks)
        assertEquals(listOf("Second"), starts)
        assertEquals("Second", locations.single { it.isSelected }.name)
        assertEquals("test blocked • tcp 20.0ms", locations.first().benchmarkDetail)
        assertEquals("test ok • tcp 40.0ms", locations.last().benchmarkDetail)
    }

    @Test
    fun lowerScoreCandidateInWindowStartsAfterFullPrecheck() = runTest {
        val first = testProfile("First")
        val second = testProfile("Second")
        val firstRaw = LocationConfigs.encodeStoredLocation(first)
        val secondRaw = LocationConfigs.encodeStoredLocation(second)
        var state = MainUiState(
            profileSourceMode = ProfileSourceMode.CURRENT_LOCATIONS,
            currentLocations = listOf(firstRaw, secondRaw),
            appMode = AppMode.PROXY_ONLY,
        )
        var locations = listOf(
            testLocation(first, firstRaw, index = 0),
            testLocation(second, secondRaw, index = 1),
        )
        val firstPreflight = preflight(first, connectMillis = 20.0, country = "DE")
        val secondPreflight = preflight(second, connectMillis = 40.0, country = "NL")
        val starts = mutableListOf<String>()
        val prechecks = mutableListOf<String>()
        val service = DesktopFindBestService(
            captureRuntimeRestore = { { Result.success(Unit) } },
            stateProvider = { state },
            visibleLocationsProvider = { locations },
            locationsProvider = { locations },
            refreshSubscriptions = { _, _ -> error("refresh should not run") },
            startConnection = { location, _, _ ->
                starts += location.name
                Result.success(Unit)
            },
            verifyCandidate = { candidate, _, _, _ ->
                prechecks += candidate.profile.remarks
                Result.success(
                    okBenchmark(
                        candidate = candidate,
                        total = if (candidate.profile.remarks == "First") 80.0 else 45.0,
                    ),
                )
            },
            commitState = { nextLocations, nextState ->
                locations = nextLocations
                state = nextState
                Result.success(Unit)
            },
            updateState = { transform -> state = transform(state) },
            evaluateProfiles = { _, _, _, _, _ ->
                BestCandidateAttemptPlan(
                    orderedAttempts = listOf(firstPreflight, secondPreflight),
                    excluded = emptyList(),
                    locationBenchmarkDetails = mapOf(
                        firstRaw to firstPreflight.detail,
                        secondRaw to secondPreflight.detail,
                    ),
                    failureMessage = null,
                )
            },
        )

        service.findBestLocation(refreshSubscriptionsFirst = false)

        assertEquals(listOf("First", "Second"), prechecks)
        assertEquals(listOf("Second"), starts)
        assertEquals("Second", locations.single { it.isSelected }.name)
        assertEquals("test ok • tcp 20.0ms", locations.first().benchmarkDetail)
        assertEquals("test ok • tcp 40.0ms", locations.last().benchmarkDetail)
    }

    @Test
    fun startedCandidateDoesNotRunAdditionalVerificationOrAdvanceWindow() = runTest {
        val first = testProfile("First")
        val second = testProfile("Second")
        val third = testProfile("Third")
        val firstRaw = LocationConfigs.encodeStoredLocation(first)
        val secondRaw = LocationConfigs.encodeStoredLocation(second)
        val thirdRaw = LocationConfigs.encodeStoredLocation(third)
        var state = MainUiState(
            profileSourceMode = ProfileSourceMode.CURRENT_LOCATIONS,
            currentLocations = listOf(firstRaw, secondRaw, thirdRaw),
            appMode = AppMode.PROXY_ONLY,
            validationSettings = com.kardinal.vpncontrol.model.BenchmarkValidationSettings(
                activeVerificationWindowSize = 2,
            ),
        )
        var locations = listOf(
            testLocation(first, firstRaw, index = 0),
            testLocation(second, secondRaw, index = 1),
            testLocation(third, thirdRaw, index = 2),
        )
        val firstPreflight = preflight(first, connectMillis = 20.0, country = "DE")
        val secondPreflight = preflight(second, connectMillis = 30.0, country = "NL")
        val thirdPreflight = preflight(third, connectMillis = 40.0, country = "FR")
        val starts = mutableListOf<String>()
        val prechecks = mutableListOf<String>()
        val service = DesktopFindBestService(
            captureRuntimeRestore = { { Result.success(Unit) } },
            stateProvider = { state },
            visibleLocationsProvider = { locations },
            locationsProvider = { locations },
            refreshSubscriptions = { _, _ -> error("refresh should not run") },
            startConnection = { location, _, _ ->
                starts += location.name
                Result.success(Unit)
            },
            verifyCandidate = { candidate, _, _, _ ->
                prechecks += candidate.profile.remarks
                Result.success(
                    okBenchmark(
                        candidate = candidate,
                        total = if (candidate.profile.remarks == "First") 40.0 else 50.0,
                    ),
                )
            },
            commitState = { nextLocations, nextState ->
                locations = nextLocations
                state = nextState
                Result.success(Unit)
            },
            updateState = { transform -> state = transform(state) },
            evaluateProfiles = { _, _, _, _, _ ->
                BestCandidateAttemptPlan(
                    orderedAttempts = listOf(firstPreflight, secondPreflight, thirdPreflight),
                    excluded = emptyList(),
                    locationBenchmarkDetails = mapOf(
                        firstRaw to firstPreflight.detail,
                        secondRaw to secondPreflight.detail,
                        thirdRaw to thirdPreflight.detail,
                    ),
                    failureMessage = null,
                )
            },
        )

        service.findBestLocation(refreshSubscriptionsFirst = false)

        assertEquals(listOf("First", "Second"), prechecks)
        assertEquals(listOf("First"), starts)
        assertEquals("First", locations.single { it.isSelected }.name)
        assertEquals(
            BenchmarkStatusMessages.bestLocationSummary("First", "test ok • tcp 20.0ms"),
            state.lastBenchmarkSummary,
        )
        assertFalse(locations.single { it.name == "Third" }.isSelected)
    }

    @Test
    fun subscriptionRefreshFailureStopsBeforeBenchmarking() = runTest {
        var state = MainUiState(
            profileSourceMode = ProfileSourceMode.SUBSCRIPTION,
            activeSubscriptionId = "sub",
            subscriptions = listOf(SubscriptionSource(id = "sub", url = "https://example.com/sub")),
        )
        val profile = testProfile("Germany")
        val rawLink = LocationConfigs.encodeStoredLocation(profile)
        val locations = listOf(testLocation(profile, rawLink))
        var evaluated = false

        val service = DesktopFindBestService(
            captureRuntimeRestore = { { Result.success(Unit) } },
            stateProvider = { state },
            visibleLocationsProvider = { locations },
            locationsProvider = { locations },
            refreshSubscriptions = { _, _ -> Result.failure(IllegalStateException("refresh failed")) },
            startConnection = { _, _, _ -> error("start should not run") },
            verifyCandidate = { _, _, _, _ -> error("fallback verify should not run") },
            commitState = { _, nextState -> state = nextState; Result.success(Unit) },
            updateState = { transform -> state = transform(state) },
            evaluateProfiles = { _, _, _, _, _ ->
                evaluated = true
                error("benchmark should not run")
            },
        )

        service.findBestLocation(refreshSubscriptionsFirst = true)

        assertFalse(evaluated)
    }

    @Test
    fun failedBenchmarkPersistenceStopsBeforeCandidateVerificationOrRuntimeChange() = runTest {
        val profile = testProfile("Candidate")
        val raw = LocationConfigs.encodeStoredLocation(profile)
        val locations = listOf(testLocation(profile, raw))
        var state = MainUiState(profileSourceMode = ProfileSourceMode.CURRENT_LOCATIONS,
            currentLocations = listOf(raw))
        var verified = false
        var started = false
        val failure = DesktopPersistenceException()
        val candidate = preflight(profile, 20.0, "DE")
        val service = DesktopFindBestService(
            captureRuntimeRestore = { { Result.success(Unit) } },
            stateProvider = { state }, visibleLocationsProvider = { locations }, locationsProvider = { locations },
            refreshSubscriptions = { _, _ -> error("unexpected refresh") },
            startConnection = { _, _, _ -> started = true; Result.success(Unit) },
            verifyCandidate = { attempt, _, _, _ -> verified = true; Result.success(okBenchmark(attempt, 25.0)) },
            commitState = { _, _ -> Result.failure<Unit>(failure) },
            updateState = { state = it(state) },
            evaluateProfiles = { _, _, _, _, _ -> BestCandidateAttemptPlan(listOf(candidate), emptyList(),
                mapOf(raw to candidate.detail), null) })
        val result = service.findBestLocation(false)
        kotlin.test.assertSame(failure, result.exceptionOrNull())
        assertFalse(verified)
        assertFalse(started)
        assertFalse(state.isBusy)
        assertFalse(state.isRefreshing)
    }

    @Test
    fun cancelledProbeClearsBusyFlagsWithoutStartingRuntime() = runTest {
        val profile = testProfile("Candidate")
        val raw = LocationConfigs.encodeStoredLocation(profile)
        val locations = listOf(testLocation(profile, raw))
        var state = MainUiState(profileSourceMode = ProfileSourceMode.CURRENT_LOCATIONS,
            currentLocations = listOf(raw))
        val cancelled = kotlinx.coroutines.CancellationException("cancelled probe")
        val service = DesktopFindBestService(
            captureRuntimeRestore = { { Result.success(Unit) } },
            stateProvider = { state }, visibleLocationsProvider = { locations }, locationsProvider = { locations },
            refreshSubscriptions = { _, _ -> error("unexpected refresh") },
            startConnection = { _, _, _ -> error("unexpected runtime mutation") },
            verifyCandidate = { _, _, _, _ -> error("unexpected verification") },
            commitState = { _, _ -> Result.success(Unit) },
            updateState = { state = it(state) },
            evaluateProfiles = { _, _, _, _, _ -> throw cancelled })
        val observed = kotlin.test.assertFailsWith<kotlinx.coroutines.CancellationException> {
            service.findBestLocation(false)
        }
        assertEquals(cancelled.message, observed.message)
        assertFalse(state.isBusy)
        assertFalse(state.isRefreshing)
    }

    @Test fun failedSearchRestoresCapturedActualRuntimeBeforeRefreshWithoutStartingPendingSelection() = runTest {
        val profile = testProfile("Pending B")
        val raw = LocationConfigs.encodeStoredLocation(profile)
        val locations = listOf(testLocation(profile, raw))
        var state = MainUiState(profileSourceMode = ProfileSourceMode.SUBSCRIPTION,
            activeSubscriptionId = "sub", subscriptions = listOf(SubscriptionSource(id = "sub", url = "https://example.com/sub")),
            selectedProfileRawLink = raw, selectedProfileSourceUrl = "", selectedProfileName = "Pending B",
            isVpnRunning = true)
        var actual = "Actual A"
        val events = mutableListOf<String>()
        val candidate = preflight(profile, 20.0, "DE")
        val service = DesktopFindBestService(
            captureRuntimeRestore = {
                events += "capture"
                val captured = actual
                DesktopRuntimeRestoreAction(AutoCloseable { events += "release" }) {
                    events += "restore"; actual = captured; Result.success(Unit)
                }
            },
            stateProvider = { state }, visibleLocationsProvider = { locations }, locationsProvider = { locations },
            refreshSubscriptions = { _, _ -> events += "refresh"; actual = "Refresh temporary runtime"; Result.success(1) },
            startConnection = { location, _, _ -> events += "start pending"; actual = location.name; Result.success(Unit) },
            verifyCandidate = { _, _, _, _ -> Result.failure(IllegalStateException("verification failed")) },
            commitState = { _, next -> state = next; Result.success(Unit) },
            updateState = { state = it(state) },
            evaluateProfiles = { _, _, _, _, _ -> BestCandidateAttemptPlan(listOf(candidate), emptyList(), emptyMap(), null) })
        assertTrue(service.findBestLocation().isFailure)
        assertEquals("Actual A", actual)
        assertEquals(listOf("capture", "refresh", "restore", "release"), events)
        assertEquals(raw, state.selectedProfileRawLink)
        assertFalse(state.isBusy)
    }

    @Test
    fun cancellationAfterRefreshRestoresActualRuntimeAndPreservesPendingSelection() = runTest {
        val profile = testProfile("Pending B")
        val raw = LocationConfigs.encodeStoredLocation(profile)
        val locations = listOf(testLocation(profile, raw))
        var state = MainUiState(profileSourceMode = ProfileSourceMode.SUBSCRIPTION,
            activeSubscriptionId = "sub", subscriptions = listOf(SubscriptionSource(id = "sub", url = "https://example.com/sub")),
            selectedProfileRawLink = raw, selectedProfileName = "Pending B", isVpnRunning = true)
        var actual = "Actual A"
        var restorations = 0
        val cancelled = kotlinx.coroutines.CancellationException("cancelled after refresh")
        val service = DesktopFindBestService(
            captureRuntimeRestore = {
                val captured = actual
                suspend { restorations++; actual = captured; Result.success(Unit) }
            },
            stateProvider = { state }, visibleLocationsProvider = { locations }, locationsProvider = { locations },
            refreshSubscriptions = { _, _ -> actual = "Refresh temporary runtime"; Result.success(1) },
            startConnection = { _, _, _ -> error("no candidate start") },
            verifyCandidate = { _, _, _, _ -> error("no verification") },
            commitState = { _, next -> state = next; Result.success(Unit) },
            updateState = { state = it(state) },
            evaluateProfiles = { _, _, _, _, _ -> throw cancelled },
        )
        assertEquals(cancelled.message, kotlin.test.assertFailsWith<kotlinx.coroutines.CancellationException> { service.findBestLocation() }.message)
        assertEquals("Actual A", actual)
        assertEquals(1, restorations)
        assertEquals(raw, state.selectedProfileRawLink)
        assertFalse(state.isBusy)
    }

    @Test
    fun failedRecoveryReportsFailureOrUnknownWithoutRepeatingRestoration() = runTest {
        for ((restoreCode, expectedCode) in listOf("runtime_failed" to "ROLLBACK_FAILED", "OUTCOME_UNKNOWN" to "OUTCOME_UNKNOWN")) {
            val profile = testProfile("Pending B")
            val raw = LocationConfigs.encodeStoredLocation(profile)
            var state = MainUiState(profileSourceMode = ProfileSourceMode.SUBSCRIPTION,
                activeSubscriptionId = "sub", subscriptions = listOf(SubscriptionSource(id = "sub", url = "https://example.com/sub")),
                selectedProfileRawLink = raw, isVpnRunning = true)
            var restorations = 0
            var released = 0
            val service = DesktopFindBestService(
                captureRuntimeRestore = { DesktopRuntimeRestoreAction(AutoCloseable { released++ }) {
                    restorations++; Result.failure(IllegalStateException(restoreCode))
                } },
                stateProvider = { state }, visibleLocationsProvider = { emptyList() }, locationsProvider = { emptyList() },
                refreshSubscriptions = { _, _ -> Result.success(0) },
                startConnection = { _, _, _ -> error("no candidate") },
                verifyCandidate = { _, _, _, _ -> error("no candidate") },
                commitState = { _, _ -> error("no benchmark persistence") },
                updateState = { state = it(state) },
                evaluateProfiles = { _, _, _, _, _ -> error("no profiles") },
            )
            assertEquals(expectedCode, service.findBestLocation().exceptionOrNull()?.message)
            assertEquals(1, restorations)
            assertEquals(expectedCode == "OUTCOME_UNKNOWN", state.isBusy)
            assertEquals(if (expectedCode == "OUTCOME_UNKNOWN") 0 else 1, released)
            assertEquals(raw, state.selectedProfileRawLink)
        }
    }

    @Test
    fun metadataFailureAfterSuccessfulStartDoesNotRollBackCommittedRuntime() = runTest {
        val profile = testProfile("Winner")
        val raw = LocationConfigs.encodeStoredLocation(profile)
        var locations = listOf(testLocation(profile, raw))
        var state = MainUiState(profileSourceMode = ProfileSourceMode.CURRENT_LOCATIONS, currentLocations = listOf(raw))
        var committed = false
        val failure = DesktopPersistenceException()
        val service = DesktopFindBestService(
            captureRuntimeRestore = { { error("committed runtime must not be rolled back") } },
            stateProvider = { state }, visibleLocationsProvider = { locations }, locationsProvider = { locations },
            refreshSubscriptions = { _, _ -> error("no refresh") },
            startConnection = { _, _, _ -> committed = true; Result.success(Unit) },
            verifyCandidate = { candidate, _, _, _ -> Result.success(okBenchmark(candidate, 25.0)) },
            commitState = { nextLocations, nextState ->
                if (committed) Result.failure(failure)
                else { locations = nextLocations; state = nextState; Result.success(Unit) }
            },
            updateState = { state = it(state) },
            evaluateProfiles = { _, _, _, _, _ ->
                BestCandidateAttemptPlan(listOf(preflight(profile, 20.0, "DE")), emptyList(), emptyMap(), null)
            },
        )
        assertSame(failure, service.findBestLocation(false).exceptionOrNull())
        assertTrue(committed)
        assertFalse(state.isBusy)
    }

    @Test fun authorizationCancellationDoesNotPromptForAnotherCandidate() = runTest {
        val profiles = listOf(testProfile("First"), testProfile("Second"))
        val locations = profiles.mapIndexed { index, profile -> testLocation(profile, LocationConfigs.encodeStoredLocation(profile), index) }
        var state = MainUiState(profileSourceMode = ProfileSourceMode.CURRENT_LOCATIONS,
            currentLocations = locations.map { it.rawLink })
        val starts = mutableListOf<String>()
        val cancelled = IllegalStateException("CANCELLED")
        val service = DesktopFindBestService(
            captureRuntimeRestore = { { Result.success(Unit) } },
            stateProvider = { state }, visibleLocationsProvider = { locations }, locationsProvider = { locations },
            refreshSubscriptions = { _, _ -> error("unexpected refresh") },
            startConnection = { location, _, _ -> starts += location.name; Result.failure(cancelled) },
            verifyCandidate = { candidate, _, _, _ -> Result.success(okBenchmark(candidate, 25.0)) },
            commitState = { _, next -> state = next; Result.success(Unit) },
            updateState = { state = it(state) },
            evaluateProfiles = { _, _, _, _, _ -> BestCandidateAttemptPlan(profiles.map { preflight(it, 20.0, "DE") },
                emptyList(), emptyMap(), null) })
        assertSame(cancelled, service.findBestLocation(false).exceptionOrNull())
        assertEquals(listOf("First"), starts)
        assertFalse(state.isBusy)
    }

    @Test fun uncertainCandidateOutcomeNeitherRetriesNorRollsBackAndRemainsObservable() = runTest {
        val profiles = listOf(testProfile("First"), testProfile("Second"))
        val locations = profiles.mapIndexed { index, profile -> testLocation(profile, LocationConfigs.encodeStoredLocation(profile), index) }
        var state = MainUiState(profileSourceMode = ProfileSourceMode.CURRENT_LOCATIONS,
            currentLocations = locations.map { it.rawLink })
        val starts = mutableListOf<String>()
        val observations = mutableListOf<com.kardinal.vpncontrol.model.ControlCode?>()
        val unknown = IllegalStateException("OUTCOME_UNKNOWN")
        var attempted = false
        val service = DesktopFindBestService(
            captureRuntimeRestore = { { error("unknown outcome must not be rolled back") } },
            stateProvider = { state }, visibleLocationsProvider = { locations }, locationsProvider = { locations },
            refreshSubscriptions = { _, _ -> error("unexpected refresh") },
            startConnection = { location, _, _ -> attempted = true; starts += location.name; Result.failure(unknown) },
            verifyCandidate = { candidate, _, _, _ -> Result.success(okBenchmark(candidate, 25.0)) },
            commitState = { _, next -> check(!attempted) { "unknown mutation must not be overwritten" }; state = next; Result.success(Unit) },
            updateState = { state = it(state) },
            evaluateProfiles = { _, _, _, _, _ -> BestCandidateAttemptPlan(profiles.map { preflight(it, 20.0, "DE") },
                emptyList(), emptyMap(), null) })
        val result = kotlinx.coroutines.withContext(DesktopOperationProgress { observations += it }) {
            service.findBestLocation(false)
        }
        assertSame(unknown, result.exceptionOrNull())
        assertEquals(listOf("First"), starts)
        assertEquals(listOf<com.kardinal.vpncontrol.model.ControlCode?>(com.kardinal.vpncontrol.model.ControlCode.OUTCOME_UNKNOWN), observations)
        assertTrue(state.isBusy, "An uncertain runtime mutation must keep competing GUI actions blocked")
    }

    @Test
    fun winnerKeepsObservedSourceWhenAnotherSourceHasTheSameProfile() = runTest {
        val profile = testProfile("Duplicate")
        val raw = LocationConfigs.encodeStoredLocation(profile)
        val hidden = testLocation(profile, raw).copy(sourceUrl = "https://hidden.invalid/sub", isSelected = true)
        val visible = testLocation(profile, raw, 1).copy(sourceUrl = "https://visible.invalid/sub")
        var locations = listOf(hidden, visible)
        var state = MainUiState(profileSourceMode = ProfileSourceMode.CURRENT_LOCATIONS, currentLocations = listOf(raw))
        var started: DesktopLocationRecord? = null
        val service = DesktopFindBestService(
            captureRuntimeRestore = { { Result.success(Unit) } },
            stateProvider = { state },
            visibleLocationsProvider = { locations.filter { it.sourceUrl == visible.sourceUrl } },
            locationsProvider = { locations },
            refreshSubscriptions = { _, _ -> error("unexpected refresh") },
            startConnection = { location, _, _ -> started = location; Result.success(Unit) },
            verifyCandidate = { candidate, _, _, _ -> Result.success(okBenchmark(candidate, 25.0)) },
            commitState = { nextLocations, nextState -> locations = nextLocations; state = nextState; Result.success(Unit) },
            updateState = { state = it(state) },
            evaluateProfiles = { _, _, _, _, _ ->
                BestCandidateAttemptPlan(listOf(preflight(profile, 20.0, "DE")), emptyList(), emptyMap(), null)
            },
        )
        assertTrue(service.findBestLocation(false).isSuccess)
        assertEquals(visible.sourceUrl, started?.sourceUrl)
        assertEquals(listOf(visible.sourceUrl), locations.filter { it.isSelected }.map { it.sourceUrl })
    }

    private fun testLocation(profile: ProxyProfile, rawLink: String, index: Int = 0): DesktopLocationRecord {
        return DesktopLocationRecord(
            index = index,
            sourceUrl = "",
            rawLink = rawLink,
            name = profile.remarks,
            server = profile.server,
            details = "VLESS",
            benchmarkDetail = "Imported",
            isValid = true,
        )
    }

    private fun testProfile(name: String): ProxyProfile {
        return ProxyProfile(
            remarks = name,
            server = "example.com",
            serverPort = 443,
            uuid = "00000000-0000-4000-8000-000000000000",
            network = "tcp",
            flow = "",
            security = "tls",
            sni = "example.com",
            fingerprint = "chrome",
            publicKey = "",
            shortId = "",
            path = "",
            hostHeader = "",
            serviceName = "",
            headerType = "",
            rawLink = "vless://00000000-0000-4000-8000-000000000000@example.com:443?security=tls#$name",
        )
    }

    private fun preflight(
        profile: ProxyProfile,
        connectMillis: Double,
        country: String,
    ): PreflightResult {
        return PreflightResult(
            profile = profile,
            connectMillis = connectMillis,
            detail = "${profile.remarks}: tcp=${connectMillis}ms country=$country",
            candidateCountryCode = country,
        )
    }

    private fun okBenchmark(candidate: PreflightResult, total: Double): com.kardinal.vpncontrol.model.ProfileBenchmark {
        return BenchmarkSearchLogic.buildActiveVerificationBenchmark(
            candidate = candidate,
            testResult = ProxyRunResult(codes = listOf("200"), totals = listOf(total)),
        )
    }

    private fun blockedBenchmark(candidate: PreflightResult): com.kardinal.vpncontrol.model.ProfileBenchmark {
        return BenchmarkSearchLogic.failedActiveVerificationBenchmark(
            candidate = candidate,
            reason = "active_verification_failed",
            secondaryStatus = "blocked",
        )
    }
}
