package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.data.BenchmarkSearchLogic
import com.kardinal.vpncontrol.data.LocationConfigs
import com.kardinal.vpncontrol.data.PreflightResult
import com.kardinal.vpncontrol.model.ProfileBenchmark
import com.kardinal.vpncontrol.model.ProxyProfile
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class BenchmarkSearchLogicTest {
    @Test
    fun timedOutPreflightCanStillUseSuccessfulValidationCandidate() {
        val profile = testProfile("Timeout Candidate")
        val benchmark = ProfileBenchmark(
            profile = profile,
            primaryStatus = "manual",
            secondaryStatus = "ok",
            primaryTotal = null,
            secondaryTotal = 180.0,
            score = 310.0,
            detail = "Timeout Candidate: tcp=unreachable test=ok test_codes=200 score=310.0",
        )

        val evaluation = BenchmarkSearchLogic.evaluateProfilesForSelection(
            profiles = listOf(profile),
            preflightResults = listOf(
                PreflightResult(
                    profile = profile,
                    connectMillis = null,
                    detail = "Timeout Candidate: tcp_timeout",
                ),
            ),
            candidateBenchmarks = listOf(benchmark),
            winner = benchmark,
        )

        assertEquals(benchmark, evaluation.winner)
        assertNull(evaluation.failureMessage)
        assertEquals(
            benchmark.detail,
            evaluation.locationBenchmarkDetails[LocationConfigs.encodeStoredLocation(profile)],
        )
    }

    private fun testProfile(name: String): ProxyProfile {
        return ProxyProfile(
            remarks = name,
            server = "example.com",
            serverPort = 443,
            network = "tcp",
            flow = "",
            security = "none",
            sni = "",
            fingerprint = "",
            publicKey = "",
            shortId = "",
            path = "",
            hostHeader = "",
            serviceName = "",
            headerType = "",
            rawLink = "vless://example",
        )
    }
}
