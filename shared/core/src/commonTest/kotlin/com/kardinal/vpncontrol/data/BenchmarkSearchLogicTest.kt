package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.model.ProxyProfile
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class BenchmarkSearchLogicTest {
    @Test
    fun activeVerificationWindowIncludesCurrentAndNextCandidates() {
        val attempts = listOf("first", "second", "third", "fourth")

        assertEquals(
            listOf("second", "third", "fourth"),
            BenchmarkSearchLogic.activeVerificationWindow(attempts, currentIndex = 1, windowSize = 3),
        )
    }

    @Test
    fun activeVerificationWindowHandlesBoundaries() {
        val attempts = listOf("first", "second")

        assertEquals(
            listOf("second"),
            BenchmarkSearchLogic.activeVerificationWindow(attempts, currentIndex = 1, windowSize = 3),
        )
        assertEquals(
            emptyList(),
            BenchmarkSearchLogic.activeVerificationWindow(attempts, currentIndex = 2, windowSize = 3),
        )
        assertEquals(
            listOf("first"),
            BenchmarkSearchLogic.activeVerificationWindow(attempts, currentIndex = 0, windowSize = 0),
        )
    }

    @Test
    fun validateCandidateWindowChoosesLowestScorePassingCandidate() = runTest {
        val fasterTcpSlowerTest = preflight("Faster TCP", connectMillis = 10.0, country = "DE")
        val slowerTcpFasterTest = preflight("Better Score", connectMillis = 30.0, country = "NL")
        val blocked = preflight("Blocked", connectMillis = 5.0, country = "FR")

        val result = BenchmarkSearchLogic.validateCandidateWindowForBestPass(
            attempts = listOf(fasterTcpSlowerTest, slowerTcpFasterTest, blocked),
            currentIndex = 0,
            windowSize = 3,
        ) { candidate, _ ->
            when (candidate.profile.remarks) {
                "Faster TCP" -> BenchmarkSearchLogic.buildActiveVerificationBenchmark(
                    candidate = candidate,
                    testResult = ProxyRunResult(codes = listOf("200"), totals = listOf(100.0)),
                )
                "Better Score" -> BenchmarkSearchLogic.buildActiveVerificationBenchmark(
                    candidate = candidate,
                    testResult = ProxyRunResult(codes = listOf("200"), totals = listOf(20.0)),
                )
                else -> BenchmarkSearchLogic.failedActiveVerificationBenchmark(
                    candidate = candidate,
                    reason = "blocked",
                    secondaryStatus = "blocked",
                )
            }
        }

        assertEquals(
            listOf("Faster TCP", "Better Score", "Blocked"),
            result.completed.map { it.attempt.profile.remarks },
        )
        assertEquals("Better Score", result.winner?.attempt?.profile?.remarks)
        assertEquals(
            listOf("Better Score", "Faster TCP"),
            result.verifiedCandidates.map { it.attempt.profile.remarks },
        )
    }

    @Test
    fun strictTargetVerificationSkipsChallengeCandidatesWithReason() = runTest {
        val challenged = preflight("Challenge", connectMillis = 10.0, country = "NL")

        val result = BenchmarkSearchLogic.validateCandidateWindowForBestPass(
            attempts = listOf(challenged),
            currentIndex = 0,
            windowSize = 1,
        ) { candidate, _ ->
            BenchmarkSearchLogic.buildActiveVerificationBenchmark(
                candidate = candidate,
                testResult = ProxyRunResult(codes = listOf("403"), totals = listOf(30.0)),
            )
        }

        val benchmark = result.completed.single().benchmark
        val summary = BenchmarkSearchLogic.strictTargetSkipSummary(result.completed.map { it.benchmark })

        assertEquals("challenge", benchmark.testStatus)
        assertTrue(result.verifiedCandidates.isEmpty())
        assertEquals(null, result.winner)
        assertContains(benchmark.detail, "strict_target_skip_reason=target_challenge")
        assertContains(benchmark.detail, "auto_select=false")
        assertContains(benchmark.detail, "manual_selection_may_still_connect=true")
        assertContains(summary, "strict_target_skipped=1")
        assertContains(summary, "target_challenge:1")
    }

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
