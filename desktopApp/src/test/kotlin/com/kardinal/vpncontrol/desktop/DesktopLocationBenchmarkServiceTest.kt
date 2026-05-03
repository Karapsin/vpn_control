package com.kardinal.vpncontrol.desktop

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
    fun benchmarkSuccessUpdatesLocationAndUsesStateSettings() = runTest {
        val profile = testProfile("Germany")
        val rawLink = LocationConfigs.encodeStoredLocation(profile)
        var state = MainUiState(
            useCustomDns = true,
            customDns = "1.1.1.1",
            validationSettings = BenchmarkValidationSettings(
                primaryUrl = "https://primary.example/path",
                secondaryUrl = "https://secondary.example/",
                batchSize = 9,
            ),
        )
        var locations = listOf(
            testLocation(index = 7, profile = profile, rawLink = rawLink, benchmarkDetail = "Imported"),
        )
        var capturedDns: DesktopDnsSettings? = null
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
                        primaryStatus = "ok",
                        secondaryStatus = "timeout",
                        primaryTotal = 40.0,
                        secondaryTotal = null,
                        score = 40.0,
                        detail = "Germany: tcp=40.0ms primary=ok secondary=timeout",
                    ),
                )
            },
            commitState = { nextState, nextLocations ->
                state = nextState
                locations = nextLocations
            },
            updateState = { transform -> state = transform(state) },
        )

        service.benchmark(7)

        assertFalse(state.isBusy)
        assertEquals(BenchmarkStatusMessages.benchmarkedLocation("Germany", "ok", "timeout"), state.statusMessage)
        assertEquals("primary ok • secondary timeout • tcp 40.0ms", locations.single().benchmarkDetail)
        assertTrue(locations.single().isValid)
        assertEquals(DesktopDnsSettings(enabled = true, value = "1.1.1.1"), capturedDns)
        assertEquals("https://primary.example/path", capturedUrls?.primary)
        assertEquals("https://secondary.example/", capturedUrls?.secondary)
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
            },
            updateState = { transform -> state = transform(state) },
        )

        service.benchmark(2)

        assertFalse(state.isBusy)
        assertEquals("network failed", state.statusMessage)
        assertEquals("Imported", locations.single().benchmarkDetail)
        assertTrue(locations.single().isValid)
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
