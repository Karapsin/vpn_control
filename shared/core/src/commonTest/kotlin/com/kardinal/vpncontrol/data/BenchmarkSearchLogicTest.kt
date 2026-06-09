package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.model.ProxyProfile
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class BenchmarkSearchLogicTest {
    @Test
    fun sameCountryCandidateIsExcluded() {
        val sameCountry = preflight("Same", connectMillis = 25.0, country = "US")
        val foreign = preflight("Foreign", connectMillis = 50.0, country = "DE")

        val plan = BenchmarkSearchLogic.planActiveVerificationAttempts(
            profiles = listOf(sameCountry.profile, foreign.profile),
            preflightResults = listOf(sameCountry, foreign),
            userCountryCode = "US",
        )

        assertEquals(listOf("Foreign"), plan.orderedAttempts.map { it.profile.remarks })
        assertEquals(listOf("Same"), plan.excluded.map { it.profile.remarks })
        assertTrue(plan.locationBenchmarkDetails.getValue(LocationConfigs.encodeStoredLocation(sameCountry.profile))
            .contains("excluded_same_country"))
    }

    @Test
    fun differentCountryCandidateRemainsEligible() {
        val candidate = preflight("Foreign", connectMillis = 50.0, country = "DE")

        val plan = BenchmarkSearchLogic.planActiveVerificationAttempts(
            profiles = listOf(candidate.profile),
            preflightResults = listOf(candidate),
            userCountryCode = "US",
        )

        assertEquals(listOf("Foreign"), plan.orderedAttempts.map { it.profile.remarks })
        assertTrue(plan.excluded.isEmpty())
    }

    @Test
    fun unknownCandidateCountryRemainsEligible() {
        val candidate = preflight("Unknown", connectMillis = 50.0, country = null)

        val plan = BenchmarkSearchLogic.planActiveVerificationAttempts(
            profiles = listOf(candidate.profile),
            preflightResults = listOf(candidate),
            userCountryCode = "US",
        )

        assertEquals(listOf("Unknown"), plan.orderedAttempts.map { it.profile.remarks })
        assertTrue(plan.locationBenchmarkDetails.getValue(LocationConfigs.encodeStoredLocation(candidate.profile))
            .contains("country=unknown"))
    }

    @Test
    fun unknownUserCountryDisablesSameCountryExclusion() {
        val candidate = preflight("Maybe Same", connectMillis = 50.0, country = "US")

        val plan = BenchmarkSearchLogic.planActiveVerificationAttempts(
            profiles = listOf(candidate.profile),
            preflightResults = listOf(candidate),
            userCountryCode = null,
        )

        assertEquals(listOf("Maybe Same"), plan.orderedAttempts.map { it.profile.remarks })
        assertTrue(plan.excluded.isEmpty())
        assertTrue(plan.locationBenchmarkDetails.getValue(LocationConfigs.encodeStoredLocation(candidate.profile))
            .contains("user_country=unknown"))
    }

    @Test
    fun candidatesAreOrderedByCurrentTcpLatency() {
        val slow = preflight("Slow", connectMillis = 120.0, country = "DE")
        val fast = preflight("Fast", connectMillis = 30.0, country = "NL")
        val timeout = preflight("Timeout", connectMillis = null, country = "FR", status = "tcp_timeout")

        val plan = BenchmarkSearchLogic.planActiveVerificationAttempts(
            profiles = listOf(slow.profile, fast.profile, timeout.profile),
            preflightResults = listOf(slow, fast, timeout),
            userCountryCode = "US",
        )

        assertEquals(listOf("Fast", "Slow", "Timeout"), plan.orderedAttempts.map { it.profile.remarks })
    }

    private fun preflight(
        name: String,
        connectMillis: Double?,
        country: String?,
        status: String? = null,
    ): PreflightResult {
        val profile = profile(name)
        return PreflightResult(
            profile = profile,
            connectMillis = connectMillis,
            detail = BenchmarkSearchLogic.preflightDetail(
                profile = profile,
                connectMillis = connectMillis,
                status = status,
                candidateCountryCode = country,
            ),
            candidateCountryCode = country,
        )
    }

    private fun profile(name: String): ProxyProfile {
        val host = "${name.lowercase().replace(" ", "-")}.example.com"
        return ProxyProfile(
            remarks = name,
            server = host,
            serverPort = 443,
            network = "tcp",
            flow = "",
            security = "tls",
            sni = host,
            fingerprint = "",
            publicKey = "",
            shortId = "",
            path = "",
            hostHeader = "",
            serviceName = "",
            headerType = "",
            rawLink = "vless://$host#$name",
        )
    }
}
