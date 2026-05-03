package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.data.LocationConfigs
import com.kardinal.vpncontrol.data.SearchEvaluation
import com.kardinal.vpncontrol.model.ProfileBenchmark
import com.kardinal.vpncontrol.model.ProfileSourceMode
import com.kardinal.vpncontrol.model.ProxyProfile
import com.kardinal.vpncontrol.model.StatusMessages
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
        var startedSummary = ""
        val service = DesktopFindBestService(
            stateProvider = { state },
            visibleLocationsProvider = { locations },
            locationsProvider = { locations },
            refreshSubscriptions = { _, _ -> error("refresh should not run") },
            startConnection = { location, summary ->
                startedLocation = location
                startedSummary = summary.orEmpty()
                Result.success(Unit)
            },
            commitState = { nextLocations, nextState ->
                locations = nextLocations
                state = nextState
            },
            updateState = { transform -> state = transform(state) },
            evaluateProfiles = { profiles, _, _, _, onProgress ->
                assertEquals(listOf(profile.rawLink), profiles.map { it.rawLink })
                onProgress("Testing locations 1-1 of 1...")
                val benchmark = ProfileBenchmark(
                    profile = profile,
                    primaryStatus = "ok",
                    secondaryStatus = "ok",
                    primaryTotal = 50.0,
                    secondaryTotal = 60.0,
                    score = 110.0,
                    detail = "Germany: tcp=50.0ms primary=ok primary_codes=204 secondary=ok secondary_codes=200",
                )
                SearchEvaluation(
                    locationBenchmarkDetails = mapOf(rawLink to benchmark.detail),
                    candidateBenchmarks = listOf(benchmark),
                    winner = benchmark,
                    fallback = null,
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
            StatusMessages.bestLocationSummary("Germany", "primary ok • secondary ok • tcp 50.0ms"),
            startedSummary,
        )
        assertTrue(locations.single().isSelected)
        assertEquals("primary ok • secondary ok • tcp 50.0ms", locations.single().benchmarkDetail)
        assertFalse(state.isRefreshing)
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
            startConnection = { _, _ -> error("start should not run") },
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

    private fun testLocation(profile: ProxyProfile, rawLink: String): DesktopLocationRecord {
        return DesktopLocationRecord(
            index = 0,
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
}
