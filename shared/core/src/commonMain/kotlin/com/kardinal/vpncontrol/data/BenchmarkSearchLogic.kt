package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.model.ProfileBenchmark
import com.kardinal.vpncontrol.model.ProfileSelection
import com.kardinal.vpncontrol.model.ProxyProtocol
import com.kardinal.vpncontrol.model.ProxyProfile
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlin.math.round

data class BenchmarkUrls(
    val test: String = "https://chatgpt.com/",
)

data class ProxyRunResult(
    val codes: List<String>,
    val totals: List<Double>,
)

data class PreflightResult(
    val profile: ProxyProfile,
    val connectMillis: Double?,
    val detail: String,
    val resolvedServerAddress: String? = null,
    val candidateCountryCode: String? = null,
    val exclusionReason: PreflightExclusionReason? = null,
) {
    val sortScore: Double
        get() = connectMillis ?: Double.POSITIVE_INFINITY
}

enum class PreflightExclusionReason {
    SAME_COUNTRY,
}

data class ValidationWalkResult(
    val benchmarks: List<ProfileBenchmark>,
    val winner: ProfileBenchmark?,
)

data class CandidatePrecheckResult<T>(
    val attempt: T,
    val attemptIndex: Int,
    val benchmark: ProfileBenchmark,
)

data class CandidatePrecheckWindowResult<T>(
    val completed: List<CandidatePrecheckResult<T>>,
    val winner: CandidatePrecheckResult<T>?,
) {
    val verifiedCandidates: List<CandidatePrecheckResult<T>>
        get() = completed
            .filter { it.benchmark.testStatus == "ok" }
            .sortedWith(
                compareBy<CandidatePrecheckResult<T>> { it.benchmark.score }
                    .thenBy { it.attemptIndex },
            )
}

data class BestCandidateAttemptPlan(
    val orderedAttempts: List<PreflightResult>,
    val excluded: List<PreflightResult>,
    val locationBenchmarkDetails: Map<String, String>,
    val failureMessage: String?,
)

data class ProfileSelectionAttempt(
    val selection: ProfileSelection,
    val preflight: PreflightResult,
    val activeVerificationPort: Int? = null,
)

data class ProfileSelectionAttemptPlan(
    val attempts: List<ProfileSelectionAttempt>,
    val locationBenchmarkDetails: Map<String, String>,
    val failureMessage: String?,
)

data class SearchEvaluation(
    val locationBenchmarkDetails: Map<String, String>,
    val candidateBenchmarks: List<ProfileBenchmark>,
    val winner: ProfileBenchmark?,
    val fallback: ProfileBenchmark?,
    val failureMessage: String?,
)

object BenchmarkSearchLogic {
    fun <T> activeVerificationWindow(
        attempts: List<T>,
        currentIndex: Int,
        windowSize: Int,
    ): List<T> {
        if (currentIndex !in attempts.indices) return emptyList()
        return attempts.drop(currentIndex).take(windowSize.coerceAtLeast(1))
    }

    suspend fun <T> validateCandidateWindowUntilFirstPass(
        attempts: List<T>,
        currentIndex: Int,
        windowSize: Int,
        validate: suspend (attempt: T, attemptIndex: Int) -> ProfileBenchmark,
    ): CandidatePrecheckWindowResult<T> = validateCandidateWindowForBestPass(
        attempts = attempts,
        currentIndex = currentIndex,
        windowSize = windowSize,
        validate = validate,
    )

    suspend fun <T> validateCandidateWindowForBestPass(
        attempts: List<T>,
        currentIndex: Int,
        windowSize: Int,
        validate: suspend (attempt: T, attemptIndex: Int) -> ProfileBenchmark,
    ): CandidatePrecheckWindowResult<T> = coroutineScope {
        val window = activeVerificationWindow(attempts, currentIndex, windowSize)
        if (window.isEmpty()) {
            return@coroutineScope CandidatePrecheckWindowResult(
                completed = emptyList(),
                winner = null,
            )
        }

        val completed = window.mapIndexed { offset, attempt ->
            val attemptIndex = currentIndex + offset
            async {
                val benchmark = validate(attempt, attemptIndex)
                CandidatePrecheckResult(
                    attempt = attempt,
                    attemptIndex = attemptIndex,
                    benchmark = benchmark,
                )
            }
        }.awaitAll()
        CandidatePrecheckWindowResult(
            completed = completed,
            winner = completed
                .filter { it.benchmark.testStatus == "ok" }
                .minWithOrNull(
                    compareBy<CandidatePrecheckResult<T>> { it.benchmark.score }
                        .thenBy { it.attemptIndex },
                ),
        )
    }

    fun planActiveVerificationAttempts(
        profiles: List<ProxyProfile>,
        preflightResults: List<PreflightResult>,
        userCountryCode: String?,
    ): BestCandidateAttemptPlan {
        val benchmarkableProfiles = profiles.filterNot { it.protocol == ProxyProtocol.CUSTOM }
        val customProfiles = profiles.filter { it.protocol == ProxyProtocol.CUSTOM }
        val normalizedUserCountry = normalizeCountryCode(userCountryCode)
        val resultsByLocation = preflightResults.associateBy {
            LocationConfigs.encodeStoredLocation(it.profile)
        }
        val enrichedResults = benchmarkableProfiles.mapNotNull { profile ->
            val rawKey = LocationConfigs.encodeStoredLocation(profile)
            resultsByLocation[rawKey]?.withSelectionMetadata(normalizedUserCountry)
        }
        val excluded = enrichedResults.filter { it.exclusionReason != null }
        val eligible = enrichedResults.filter { it.exclusionReason == null }
        val reachable = eligible
            .filter { it.connectMillis != null }
            .sortedBy { it.connectMillis }
        val timedOut = eligible
            .filter { it.connectMillis == null && it.detail.contains("tcp_timeout") }
        val orderedAttempts = (reachable + timedOut)
            .distinctBy { LocationConfigs.encodeStoredLocation(it.profile) }

        val locationBenchmarkDetails = linkedMapOf<String, String>()
        enrichedResults.forEach { result ->
            locationBenchmarkDetails[LocationConfigs.encodeStoredLocation(result.profile)] = result.detail
        }
        customProfiles.forEach { profile ->
            locationBenchmarkDetails[LocationConfigs.encodeStoredLocation(profile)] =
                "${profile.remarks}: custom_config_manual_only country=unknown"
        }

        val failureMessage = when {
            benchmarkableProfiles.isEmpty() ->
                "Best location search does not support custom sing-box configs. Select one manually and connect."
            orderedAttempts.isEmpty() && excluded.isNotEmpty() ->
                "No eligible location found. Same-country locations were excluded."
            orderedAttempts.isEmpty() ->
                "No reachable location found. Best attempt: ${enrichedResults.minByOrNull { it.sortScore }?.detail ?: "no benchmark results"}"
            else -> null
        }
        return BestCandidateAttemptPlan(
            orderedAttempts = orderedAttempts,
            excluded = excluded,
            locationBenchmarkDetails = locationBenchmarkDetails,
            failureMessage = failureMessage,
        )
    }

    fun evaluateProfilesForSelection(
        profiles: List<ProxyProfile>,
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
        val fallback = if (winner == null) bestTestFallback(candidateBenchmarks) else null
        val failureMessage = if (winner == null && fallback == null) {
            val bestAttempt = candidateBenchmarks.minByOrNull { it.score }?.detail
            "No location reached the test site. Best attempt: ${bestAttempt ?: "no benchmark results"}"
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
        testResult: ProxyRunResult,
    ): ProfileBenchmark {
        val testMedian = medianOrNull(testResult.totals)
        val testStatus = classifyTestCodes(testResult.codes)
            .let { if (it == "bad") "error" else it }
        val score = activeVerificationScore(candidate.connectMillis, testMedian, testStatus)

        return ProfileBenchmark(
            profile = candidate.profile,
            primaryStatus = "manual",
            secondaryStatus = testStatus,
            primaryTotal = null,
            secondaryTotal = testMedian,
            score = score,
            detail = buildString {
                append(candidate.profile.remarks)
                append(": tcp=")
                append(candidate.connectMillis?.let(::formatMillis) ?: "unreachable")
                append(" country=")
                append(countryLabel(candidate.candidateCountryCode))
                append(" test=")
                append(testStatus)
                append(" test_codes=")
                append(testResult.codes.joinToString(","))
                append(" score=")
                append(score)
            },
        )
    }

    fun buildActiveVerificationBenchmark(
        candidate: PreflightResult,
        testResult: ProxyRunResult,
    ): ProfileBenchmark {
        val testMedian = medianOrNull(testResult.totals)
        val testStatus = classifyTestCodes(testResult.codes)
            .let { if (it == "bad") "error" else it }
        val score = activeVerificationScore(candidate.connectMillis, testMedian, testStatus)

        return ProfileBenchmark(
            profile = candidate.profile,
            primaryStatus = "manual",
            secondaryStatus = testStatus,
            primaryTotal = null,
            secondaryTotal = testMedian,
            score = score,
            detail = buildString {
                append(candidate.profile.remarks)
                append(": tcp=")
                append(candidate.connectMillis?.let(::formatMillis) ?: "unreachable")
                append(" country=")
                append(countryLabel(candidate.candidateCountryCode))
                append(" test=")
                append(testStatus)
                append(" test_codes=")
                append(testResult.codes.joinToString(","))
                append(" score=")
                append(score)
            },
        )
    }

    fun failedActiveVerificationBenchmark(
        candidate: PreflightResult,
        reason: String,
        secondaryStatus: String = "error",
    ): ProfileBenchmark {
        return ProfileBenchmark(
            profile = candidate.profile,
            primaryStatus = "manual",
            secondaryStatus = secondaryStatus,
            primaryTotal = null,
            secondaryTotal = null,
            score = Double.POSITIVE_INFINITY,
            detail = buildString {
                append(candidate.profile.remarks)
                append(": tcp=")
                append(candidate.connectMillis?.let(::formatMillis) ?: "unreachable")
                append(" country=")
                append(countryLabel(candidate.candidateCountryCode))
                append(" test=")
                append(secondaryStatus)
                append(' ')
                append(reason)
            },
        )
    }

    fun failedBenchmark(
        profile: ProxyProfile,
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
            detail = "${profile.remarks}: tcp=${candidate.connectMillis?.let(::formatMillis) ?: "unreachable"} country=${countryLabel(candidate.candidateCountryCode)} $reason",
        )
    }

    fun preflightDetail(
        profile: ProxyProfile,
        connectMillis: Double?,
        status: String? = null,
        candidateCountryCode: String? = null,
    ): String = buildString {
        append(profile.remarks)
        append(": ")
        if (connectMillis != null) {
            append("tcp=")
            append(formatMillis(connectMillis))
        } else {
            append(status ?: "tcp_unreachable")
        }
        append(" country=")
        append(countryLabel(candidateCountryCode))
    }

    fun formatMillis(value: Double): String {
        val rounded = round(value * 10.0) / 10.0
        return "${rounded}ms"
    }

    fun normalizeCountryCode(raw: String?): String? {
        val normalized = raw
            ?.trim()
            ?.uppercase()
            ?.takeIf { it.matches(Regex("[A-Z]{2}")) }
        return normalized
    }

    fun countryLabel(countryCode: String?): String = normalizeCountryCode(countryCode) ?: "unknown"

    private fun classifyTestCodes(codes: List<String>): String {
        val numericCodes = codes.mapNotNull { it.toIntOrNull() }
        val has2xxOr3xx = numericCodes.any { it in 200..399 }
        val has403 = codes.any { it == "403" }
        val has451 = codes.any { it == "451" }
        return when {
            has2xxOr3xx && (has403 || has451) -> "partial"
            has2xxOr3xx -> "ok"
            has451 -> "blocked"
            has403 -> "challenge"
            else -> "bad"
        }
    }

    private fun bestTestFallback(benchmarks: List<ProfileBenchmark>): ProfileBenchmark? {
        val acceptableTestStatuses = listOf("partial", "challenge")
        for (testStatus in acceptableTestStatuses) {
            val best = benchmarks
                .asSequence()
                .filter { it.testStatus == testStatus }
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

    private fun activeVerificationScore(
        connectMillis: Double?,
        secondaryMedian: Double?,
        secondaryStatus: String,
    ): Double {
        return (connectMillis ?: 999_999.0) +
            (secondaryMedian ?: 999_999.0) +
            if (secondaryStatus == "ok") 0.0 else 1_000_000.0
    }

    private fun PreflightResult.withSelectionMetadata(userCountryCode: String?): PreflightResult {
        val candidateCountry = normalizeCountryCode(candidateCountryCode)
        val excludedSameCountry = userCountryCode != null &&
            candidateCountry != null &&
            candidateCountry == userCountryCode
        val reason = if (excludedSameCountry) PreflightExclusionReason.SAME_COUNTRY else exclusionReason
        return copy(
            candidateCountryCode = candidateCountry,
            exclusionReason = reason,
            detail = buildString {
                append(detailWithoutCountry(detail))
                append(" country=")
                append(countryLabel(candidateCountry))
                if (userCountryCode == null) {
                    append(" user_country=unknown")
                }
                if (reason == PreflightExclusionReason.SAME_COUNTRY) {
                    append(" excluded_same_country")
                }
            },
        )
    }

    private fun detailWithoutCountry(detail: String): String {
        return detail
            .replace(Regex("""\s+country=(?:[A-Za-z]{2}|unknown)"""), "")
            .replace(Regex("""\s+user_country=unknown"""), "")
            .replace(Regex("""\s+excluded_same_country"""), "")
            .trim()
    }
}
