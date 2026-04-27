package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.model.ProfileBenchmark
import com.kardinal.vpncontrol.model.ProxyProtocol
import com.kardinal.vpncontrol.model.VlessProfile
import kotlin.math.round

data class BenchmarkUrls(
    val primary: String = "https://www.google.com/generate_204",
    val secondary: String = "https://chatgpt.com/",
)

data class ProxyRunResult(
    val codes: List<String>,
    val totals: List<Double>,
)

data class PreflightResult(
    val profile: VlessProfile,
    val connectMillis: Double?,
    val detail: String,
) {
    val sortScore: Double
        get() = connectMillis ?: Double.POSITIVE_INFINITY
}

data class ValidationWalkResult(
    val benchmarks: List<ProfileBenchmark>,
    val winner: ProfileBenchmark?,
)

data class SearchEvaluation(
    val locationBenchmarkDetails: Map<String, String>,
    val candidateBenchmarks: List<ProfileBenchmark>,
    val winner: ProfileBenchmark?,
    val fallback: ProfileBenchmark?,
    val failureMessage: String?,
)

object BenchmarkSearchLogic {
    fun evaluateProfilesForSelection(
        profiles: List<VlessProfile>,
        preflightResults: List<PreflightResult>,
        candidateBenchmarks: List<ProfileBenchmark>,
        winner: ProfileBenchmark?,
    ): SearchEvaluation {
        val benchmarkableProfiles = profiles.filterNot { it.protocol == ProxyProtocol.CUSTOM }
        val customProfiles = profiles.filter { it.protocol == ProxyProtocol.CUSTOM }
        val locationBenchmarkDetails = preflightResults.associate { result ->
            LocationConfigs.encodeStoredLocation(result.profile) to result.detail
        }.toMutableMap().apply {
            customProfiles.forEach { profile ->
                this[LocationConfigs.encodeStoredLocation(profile)] =
                    "${profile.remarks}: custom_config_manual_only"
            }
        }

        if (benchmarkableProfiles.isEmpty()) {
            return SearchEvaluation(
                locationBenchmarkDetails = locationBenchmarkDetails,
                candidateBenchmarks = emptyList(),
                winner = null,
                fallback = null,
                failureMessage = "Best location search does not support custom sing-box configs. Select one manually and connect.",
            )
        }

        val reachableProfiles = preflightResults
            .filter { it.connectMillis != null }
            .sortedBy { it.connectMillis }
        if (reachableProfiles.isEmpty() && candidateBenchmarks.isEmpty()) {
            val bestAttempt = preflightResults.minByOrNull { it.sortScore }
            return SearchEvaluation(
                locationBenchmarkDetails = locationBenchmarkDetails,
                candidateBenchmarks = emptyList(),
                winner = null,
                fallback = null,
                failureMessage = "No reachable location found. Best attempt: ${bestAttempt?.detail ?: "no benchmark results"}",
            )
        }

        candidateBenchmarks.forEach { benchmark ->
            locationBenchmarkDetails[LocationConfigs.encodeStoredLocation(benchmark.profile)] = benchmark.detail
        }
        val fallback = if (winner == null) bestSecondaryFallback(candidateBenchmarks) else null
        val failureMessage = if (winner == null && fallback == null) {
            val bestAttempt = candidateBenchmarks.minByOrNull { it.score }?.detail
            "No location fully reached the secondary site. Best attempt: ${bestAttempt ?: "no benchmark results"}"
        } else {
            null
        }
        return SearchEvaluation(
            locationBenchmarkDetails = locationBenchmarkDetails,
            candidateBenchmarks = candidateBenchmarks,
            winner = winner,
            fallback = fallback,
            failureMessage = failureMessage,
        )
    }

    fun buildValidatedBenchmark(
        candidate: PreflightResult,
        primaryResult: ProxyRunResult,
        secondaryResult: ProxyRunResult,
    ): ProfileBenchmark {
        val primaryMedian = medianOrNull(primaryResult.totals)
        val secondaryMedian = medianOrNull(secondaryResult.totals)
        val primaryStatus = classifyCodes(primaryResult.codes, secondarySite = false)
        val secondaryStatus = classifyCodes(secondaryResult.codes, secondarySite = true)
        val score = scorePenalty(primaryStatus, secondaryStatus) +
            (primaryMedian ?: 999_999.0) +
            (secondaryMedian ?: 999_999.0)

        return ProfileBenchmark(
            profile = candidate.profile,
            primaryStatus = primaryStatus,
            secondaryStatus = secondaryStatus,
            primaryTotal = primaryMedian,
            secondaryTotal = secondaryMedian,
            score = score,
            detail = buildString {
                append(candidate.profile.remarks)
                append(": tcp=")
                append(candidate.connectMillis?.let(::formatMillis) ?: "unreachable")
                append(" primary=")
                append(primaryStatus)
                append(" primary_codes=")
                append(primaryResult.codes.joinToString(","))
                append(" secondary=")
                append(secondaryStatus)
                append(" secondary_codes=")
                append(secondaryResult.codes.joinToString(","))
                append(" score=")
                append(score)
            },
        )
    }

    fun failedBenchmark(
        profile: VlessProfile,
        candidate: PreflightResult,
        reason: String,
    ): ProfileBenchmark {
        return ProfileBenchmark(
            profile = profile,
            primaryStatus = "error",
            secondaryStatus = "error",
            primaryTotal = null,
            secondaryTotal = null,
            score = Double.POSITIVE_INFINITY,
            detail = "${profile.remarks}: tcp=${candidate.connectMillis?.let(::formatMillis) ?: "unreachable"} $reason",
        )
    }

    fun formatMillis(value: Double): String {
        val rounded = round(value * 10.0) / 10.0
        return "${rounded}ms"
    }

    private fun classifyCodes(codes: List<String>, secondarySite: Boolean): String {
        val numericCodes = codes.mapNotNull { it.toIntOrNull() }
        val has2xx = numericCodes.any { it in 200..299 }
        val has403 = codes.any { it == "403" }
        val has451 = codes.any { it == "451" }
        return when {
            has2xx && secondarySite && (has403 || has451) -> "partial"
            has2xx -> "ok"
            secondarySite && has451 -> "blocked"
            secondarySite && has403 -> "challenge"
            else -> "bad"
        }
    }

    private fun scorePenalty(primaryStatus: String, secondaryStatus: String): Double {
        return when (primaryStatus to secondaryStatus) {
            "ok" to "ok" -> 0.0
            "ok" to "partial" -> 100.0
            "ok" to "challenge" -> 150.0
            else -> 1_000_000.0
        }
    }

    private fun bestSecondaryFallback(benchmarks: List<ProfileBenchmark>): ProfileBenchmark? {
        val acceptableSecondaryStatuses = listOf("partial", "challenge")
        for (secondaryStatus in acceptableSecondaryStatuses) {
            val best = benchmarks
                .asSequence()
                .filter { it.primaryStatus == "ok" && it.secondaryStatus == secondaryStatus }
                .minByOrNull { it.score }
            if (best != null) {
                return best
            }
        }
        return null
    }

    private fun medianOrNull(values: List<Double>): Double? {
        if (values.isEmpty()) return null
        val sorted = values.sorted()
        return sorted[sorted.size / 2]
    }
}
