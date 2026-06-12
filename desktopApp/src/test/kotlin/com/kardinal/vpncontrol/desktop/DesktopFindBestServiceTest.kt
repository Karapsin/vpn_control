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
            stateProvider = { state },
            visibleLocationsProvider = { locations },
            locationsProvider = { locations },
            refreshSubscriptions = { _, _ -> error("refresh should not run") },
            startConnection = { location, summary, activeVerificationPort ->
                events += "start ${location.name}"
                startedLocation = location
                assertEquals(null, summary)
                assertEquals(28081, activeVerificationPort)
                Result.success(Unit)
            },
            stopConnection = { Result.success(Unit) },
            currentRuntimePort = { 28080 },
            activeVerificationPortAllocator = { 28081 },
            verifyActiveConnection = { candidate, appMode, proxyPort, _, _ ->
                events += "active ${candidate.profile.remarks}"
                assertEquals(AppMode.VPN, appMode)
                assertEquals(28081, proxyPort)
                Result.success(okBenchmark(candidate, total = 60.0))
            },
            verifyCandidate = { candidate, _, _, _ ->
                events += "precheck ${candidate.profile.remarks}"
                Result.success(okBenchmark(candidate, total = 55.0))
            },
            commitState = { nextLocations, nextState ->
                locations = nextLocations
                state = nextState
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
        assertEquals(listOf("precheck Germany", "start Germany", "active Germany"), events)
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
            stateProvider = { state },
            visibleLocationsProvider = { locations },
            locationsProvider = { locations },
            refreshSubscriptions = { _, _ -> error("refresh should not run") },
            startConnection = { location, _, _ ->
                starts += location.name
                Result.success(Unit)
            },
            stopConnection = { Result.success(Unit) },
            currentRuntimePort = { 28080 },
            activeVerificationPortAllocator = { 28081 },
            verifyActiveConnection = { candidate, _, _, _, _ ->
                Result.success(okBenchmark(candidate, total = 60.0))
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
        val activeVerifications = mutableListOf<String>()
        val prechecks = mutableListOf<String>()
        val service = DesktopFindBestService(
            stateProvider = { state },
            visibleLocationsProvider = { locations },
            locationsProvider = { locations },
            refreshSubscriptions = { _, _ -> error("refresh should not run") },
            startConnection = { location, _, _ ->
                starts += location.name
                Result.success(Unit)
            },
            stopConnection = { Result.success(Unit) },
            currentRuntimePort = { 28080 },
            activeVerificationPortAllocator = { 28081 },
            verifyActiveConnection = { candidate, _, _, _, _ ->
                activeVerifications += candidate.profile.remarks
                Result.success(okBenchmark(candidate, total = 60.0))
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
        assertEquals(listOf("Second"), activeVerifications)
        assertEquals("Second", locations.single { it.isSelected }.name)
        assertEquals("test ok • tcp 20.0ms", locations.first().benchmarkDetail)
        assertEquals("test ok • tcp 40.0ms", locations.last().benchmarkDetail)
    }

    @Test
    fun activeVerificationFailureAfterPrecheckTriesNextVerifiedCandidateInSameWindow() = runTest {
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
        var stopCalls = 0
        val service = DesktopFindBestService(
            stateProvider = { state },
            visibleLocationsProvider = { locations },
            locationsProvider = { locations },
            refreshSubscriptions = { _, _ -> error("refresh should not run") },
            startConnection = { location, _, _ ->
                starts += location.name
                Result.success(Unit)
            },
            stopConnection = {
                stopCalls += 1
                Result.success(Unit)
            },
            currentRuntimePort = { 28080 },
            activeVerificationPortAllocator = { 28081 },
            verifyActiveConnection = { candidate, _, _, _, _ ->
                if (candidate.profile.remarks == "First") {
                    Result.success(blockedBenchmark(candidate))
                } else {
                    Result.success(okBenchmark(candidate, total = 60.0))
                }
            },
            verifyCandidate = { candidate, _, _, _ ->
                prechecks += candidate.profile.remarks
                Result.success(okBenchmark(candidate, total = 50.0))
            },
            commitState = { nextLocations, nextState ->
                locations = nextLocations
                state = nextState
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

        assertEquals(listOf("First", "Second"), starts)
        assertEquals(listOf("First", "Second"), prechecks)
        assertEquals(1, stopCalls)
        assertEquals("Second", locations.single { it.isSelected }.name)
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
            stateProvider = { state },
            visibleLocationsProvider = { locations },
            locationsProvider = { locations },
            refreshSubscriptions = { _, _ -> Result.failure(IllegalStateException("refresh failed")) },
            startConnection = { _, _, _ -> error("start should not run") },
            stopConnection = { Result.success(Unit) },
            currentRuntimePort = { null },
            activeVerificationPortAllocator = { 0 },
            verifyActiveConnection = { _, _, _, _, _ -> error("verify should not run") },
            verifyCandidate = { _, _, _, _ -> error("fallback verify should not run") },
            commitState = { _, nextState -> state = nextState },
            updateState = { transform -> state = transform(state) },
            evaluateProfiles = { _, _, _, _, _ ->
                evaluated = true
                error("benchmark should not run")
            },
        )

        service.findBestLocation(refreshSubscriptionsFirst = true)

        assertFalse(evaluated)
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
