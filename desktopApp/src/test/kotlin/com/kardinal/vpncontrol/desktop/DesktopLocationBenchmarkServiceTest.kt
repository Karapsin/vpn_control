package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.DnsMode
import com.kardinal.vpncontrol.model.DnsSettings
import com.kardinal.vpncontrol.model.BenchmarkStatusMessages
import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.data.BenchmarkUrls
import com.kardinal.vpncontrol.data.LocationConfigs
import com.kardinal.vpncontrol.model.BenchmarkValidationSettings
import com.kardinal.vpncontrol.model.ProfileBenchmark
import com.kardinal.vpncontrol.model.ProxyProfile
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest

class DesktopLocationBenchmarkServiceTest {
    @Test
    fun capturedBenchmarkRejectsReplacementBeforeProbeAndFollowsSameConfigurationAfterReindex() = runTest {
        val original = testLocation(7)
        val replacement = testLocation(7, profile = testProfile("Replacement"))
        var state = MainUiState()
        var locations = listOf(replacement)
        var probes = 0
        val service = DesktopLocationBenchmarkService(
            stateProvider = { state }, locationsProvider = { locations },
            benchmarkLocation = { profile, _, _, _ ->
                probes++
                locations = listOf(replacement, original.copy(index = 9))
                Result.success(ProfileBenchmark(profile = profile, primaryStatus = "ok", secondaryStatus = "ok",
                    primaryTotal = 1.0, secondaryTotal = null, score = 1.0, detail = "tcp=1ms test=ok"))
            },
            commitState = { nextState, nextLocations -> state = nextState; locations = nextLocations; Result.success(Unit) },
            updateState = { state = it(state) },
        )
        assertEquals("CONFLICT", service.benchmark(7, original).exceptionOrNull()?.message)
        assertEquals(0, probes)
        locations = listOf(original)
        assertTrue(service.benchmark(7, original).isSuccess)
        assertEquals(1, probes)
        assertEquals(replacement, locations[0])
        assertEquals(9, locations[1].index)
        assertTrue(locations[1].isValid)
        assertFalse(state.isBusy)
    }

    @Test
    fun benchmarkNeverAppliesMeasurementsToReplacementOrAmbiguousConfiguration() = runTest {
        val original = testLocation(7)
        val replacement = testLocation(7, profile = testProfile("Replacement"))
        for (afterProbe in listOf(listOf(replacement), emptyList(), listOf(original, original.copy(index = 9)))) {
            var state = MainUiState()
            var locations = listOf(original)
            var commits = 0
            val service = DesktopLocationBenchmarkService(
                stateProvider = { state }, locationsProvider = { locations },
                benchmarkLocation = { profile, _, _, _ ->
                    locations = afterProbe
                    Result.success(ProfileBenchmark(profile = profile, primaryStatus = "ok", secondaryStatus = "ok",
                        primaryTotal = 1.0, secondaryTotal = null, score = 1.0, detail = "test=ok"))
                },
                commitState = { _, _ -> commits++; Result.success(Unit) },
                updateState = { state = it(state) },
            )
            assertEquals("CONFLICT", service.benchmark(7, original).exceptionOrNull()?.message)
            assertEquals(0, commits)
            assertEquals(afterProbe, locations)
            assertFalse(state.isBusy)
        }
    }

    @Test
    fun benchmarkSuccessUpdatesLocationAndUsesStateSettings() = runTest {
        val profile = testProfile("Germany")
        val rawLink = LocationConfigs.encodeStoredLocation(profile)
        var state = MainUiState(
            dnsSettings = DnsSettings(
                mode = DnsMode.CUSTOM_DOH,
                endpoint = "https://1.1.1.1/dns-query",
            ),
            validationSettings = BenchmarkValidationSettings(
                testUrl = "https://test.example/path",
                batchSize = 9,
                subscriptionRefreshConcurrency = 7,
            ),
        )
        var locations = listOf(
            testLocation(index = 7, profile = profile, rawLink = rawLink, benchmarkDetail = "Imported"),
        )
        var capturedDns: DnsSettings? = null
        var capturedUrls: BenchmarkUrls? = null
        var capturedSettings: DesktopValidationSettings? = null
        val service = DesktopLocationBenchmarkService(
            stateProvider = { state },
            locationsProvider = { locations },
            benchmarkLocation = { checkedProfile, dnsSettings, benchmarkUrls, settings ->
                assertEquals(profile.rawLink, checkedProfile.rawLink)
                capturedDns = dnsSettings
                capturedUrls = benchmarkUrls
                capturedSettings = settings
                Result.success(
                    ProfileBenchmark(
                        profile = checkedProfile,
                        primaryStatus = "manual",
                        secondaryStatus = "timeout",
                        primaryTotal = null,
                        secondaryTotal = null,
                        score = 40.0,
                        detail = "Germany: tcp=40.0ms test=timeout",
                    ),
                )
            },
            commitState = { nextState, nextLocations ->
                state = nextState
                locations = nextLocations
                Result.success(Unit)
            },
            updateState = { transform -> state = transform(state) },
        )

        service.benchmark(7)

        assertFalse(state.isBusy)
        assertEquals(BenchmarkStatusMessages.benchmarkedLocation("Germany", "timeout"), state.statusMessage)
        assertEquals("test timeout • tcp 40.0ms", locations.single().benchmarkDetail)
        assertFalse(locations.single().isValid)
        assertEquals(DnsSettings(mode = DnsMode.CUSTOM_DOH, endpoint = "https://1.1.1.1/dns-query"), capturedDns)
        assertEquals("https://test.example/path", capturedUrls?.test)
        assertEquals(9, capturedSettings?.batchSize)
        assertEquals(5, capturedSettings?.preflightConcurrency)
    }

    @Test
    fun invalidLocationConfigPostsErrorWithoutBenchmarking() = runTest {
        var state = MainUiState()
        val locations = listOf(
            testLocation(index = 1, rawLink = "not-a-proxy-link"),
        )
        var benchmarkCalled = false
        val service = DesktopLocationBenchmarkService(
            stateProvider = { state },
            locationsProvider = { locations },
            benchmarkLocation = { _, _, _, _ ->
                benchmarkCalled = true
                error("benchmark should not run")
            },
            commitState = { _, _ -> error("commit should not run") },
            updateState = { transform -> state = transform(state) },
        )

        service.benchmark(1)

        assertFalse(benchmarkCalled)
        assertFalse(state.isBusy)
        assertTrue(state.statusMessage.isNotBlank())
    }

    @Test
    fun benchmarkFailureClearsBusyAndKeepsLocationUnchanged() = runTest {
        val profile = testProfile("France")
        val rawLink = LocationConfigs.encodeStoredLocation(profile)
        var state = MainUiState()
        var locations = listOf(
            testLocation(index = 2, profile = profile, rawLink = rawLink, benchmarkDetail = "Imported"),
        )
        val service = DesktopLocationBenchmarkService(
            stateProvider = { state },
            locationsProvider = { locations },
            benchmarkLocation = { _, _, _, _ ->
                Result.failure(IllegalStateException("network failed"))
            },
            commitState = { nextState, nextLocations ->
                state = nextState
                locations = nextLocations
                Result.success(Unit)
            },
            updateState = { transform -> state = transform(state) },
        )

        service.benchmark(2)

        assertFalse(state.isBusy)
        assertEquals(BenchmarkStatusMessages.benchmarkLocationFailed("France"), state.statusMessage)
        assertEquals("Imported", locations.single().benchmarkDetail)
        assertTrue(locations.single().isValid)
    }

    @Test
    fun rejectedAndFailedBenchmarksPreserveSelectionAndReleaseBusy() = runTest {
        val location = testLocation(7)
        val initial = MainUiState(isVpnRunning = true, selectedProfileRawLink = location.rawLink)
        var state = initial
        var calls = 0
        var commitCalls = 0
        var failure: Throwable? = null
        val service = DesktopLocationBenchmarkService(
            stateProvider = { state },
            locationsProvider = { listOf(location) },
            benchmarkLocation = { profile, _, _, _ ->
                calls++
                failure?.let { throw it }
                Result.success(ProfileBenchmark(
                    profile = profile, primaryStatus = "ok", secondaryStatus = "ok",
                    primaryTotal = 1.0, secondaryTotal = 1.0, score = 1.0, detail = "ok",
                ))
            },
            commitState = { _, _ ->
                commitCalls++
                Result.failure(IllegalStateException("PERSISTENCE_FAILED"))
            },
            updateState = { state = it(state) },
        )
        assertEquals("NOT_FOUND", service.benchmark(99).exceptionOrNull()?.message)
        state = initial.copy(isBusy = true)
        assertEquals("BUSY", service.benchmark(7).exceptionOrNull()?.message)
        assertEquals(0, calls)
        assertEquals(0, commitCalls)
        state = initial
        assertEquals("PERSISTENCE_FAILED", service.benchmark(7).exceptionOrNull()?.message)
        assertFalse(state.isBusy)
        assertEquals(1, commitCalls)
        failure = IllegalStateException("https://secret.example/token")
        assertEquals("BENCHMARK_FAILED", service.benchmark(7).exceptionOrNull()?.message)
        assertFalse(state.statusMessage.contains("secret.example"))
        assertFalse(state.isBusy)
        failure = kotlinx.coroutines.CancellationException("cancelled")
        var cancelled = false
        try { service.benchmark(7) } catch (_: kotlinx.coroutines.CancellationException) { cancelled = true }
        assertTrue(cancelled)
        assertFalse(state.isBusy)
        assertTrue(state.isVpnRunning)
        assertEquals(initial.selectedProfileRawLink, state.selectedProfileRawLink)
        assertEquals(1, commitCalls)
    }
}

private fun testLocation(
    index: Int,
    profile: ProxyProfile = testProfile("Location $index"),
    rawLink: String = LocationConfigs.encodeStoredLocation(profile),
    benchmarkDetail: String = "not checked",
): DesktopLocationRecord {
    return DesktopLocationRecord(
        index = index,
        sourceUrl = "",
        rawLink = rawLink,
        name = profile.remarks,
        server = profile.server,
        details = "VLESS",
        benchmarkDetail = benchmarkDetail,
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
