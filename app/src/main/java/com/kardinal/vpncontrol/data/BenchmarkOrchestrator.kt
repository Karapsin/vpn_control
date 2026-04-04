package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.model.PersistedState
import com.kardinal.vpncontrol.model.ProfileBenchmark
import com.kardinal.vpncontrol.model.ProfileSourceMode
import com.kardinal.vpncontrol.model.ProfileSelection
import com.kardinal.vpncontrol.model.VlessProfile
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import java.io.File
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.Socket
import java.net.URI
import java.util.Locale
import java.util.concurrent.TimeUnit

class BenchmarkOrchestrator(
    private val context: android.content.Context,
    private val storage: ProfileStorage,
) {
    data class SubscriptionSyncResult(
        val selectedMissing: Boolean,
    )

    private data class ValidationWalkResult(
        val benchmarks: List<ProfileBenchmark>,
        val winner: ProfileBenchmark?,
    )

    private val browserUserAgent =
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 " +
            "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
    private val settings = ValidationSettings()
    private val genericSecondaryBlockedMarkers = listOf(
        "not available in your country",
        "not available in your region",
        "not available in your country, region, or territory",
        "unsupported country",
        "service is unavailable in your country",
        "service is not available in your country",
        "this content is not available in your country",
        "access from your country is not allowed",
        "unavailable in your country",
    )
    private val chatGptBlockedMarkers = listOf(
        "openai's services are not available in your country",
        "you do not have access to chat.openai.com",
    )

    suspend fun refreshBestProfile(): Result<ProfileSelection> = withContext(Dispatchers.IO) {
        try {
            Result.success(
                withTimeout(settings.refreshTimeoutMillis) {
                    val state = storage.snapshot()
                    val validationSettings = state.validationSettings.normalized()
                    val benchmarkUrls = BenchmarkUrls(
                        primary = validationSettings.primaryUrl,
                        secondary = validationSettings.secondaryUrl,
                    )
                    val profiles = when (state.profileSourceMode) {
                        ProfileSourceMode.SUBSCRIPTION -> {
                            require(state.profileUrl.isNotBlank()) { "Remote source is empty" }
                            storage.updateStatus("Resolving remote source...")
                            loadRemoteSourceLocations(state.profileUrl)
                        }
                        ProfileSourceMode.CURRENT_LOCATIONS -> {
                            storage.updateStatus("Loading saved locations...")
                            decodeStoredLocations(state.currentLocations)
                        }
                    }
                    require(profiles.isNotEmpty()) {
                        if (state.profileSourceMode == ProfileSourceMode.SUBSCRIPTION) {
                            "No locations were found in the subscription"
                        } else {
                            "No saved locations available"
                        }
                    }

                    val dnsSettings = DnsSettings(
                        enabled = state.useCustomDns,
                        value = state.customDns,
                    )

                    storage.updateStatus(
                        "Checking ${profiles.size} " +
                            if (state.profileSourceMode == ProfileSourceMode.SUBSCRIPTION) "subscription locations..." else "saved locations...",
                    )
                    val preflightResults = preflightProfiles(profiles)
                    val locationBenchmarkDetails = preflightResults.associate { result ->
                        LocationConfigs.encodeStoredLocation(result.profile) to result.detail
                    }.toMutableMap()
                    val reachableProfiles = preflightResults
                        .filter { it.connectMillis != null }
                        .sortedBy { it.connectMillis }

                    if (reachableProfiles.isEmpty()) {
                        if (state.profileSourceMode != ProfileSourceMode.SUBSCRIPTION) {
                            storage.updateLocationBenchmarkDetails(locationBenchmarkDetails)
                        }
                        val bestAttempt = preflightResults.minByOrNull { it.sortScore }
                        error("No reachable location found. Best attempt: ${bestAttempt?.detail ?: "no benchmark results"}")
                    }

                    storage.updateStatus(
                        "Testing locations in batches from fastest to slowest until the secondary site works...",
                    )
                    val walk = validateInBatchesUntilSuccess(
                        candidates = reachableProfiles,
                        batchSize = validationSettings.batchSize,
                        dnsSettings = dnsSettings,
                        benchmarkUrls = benchmarkUrls,
                    ) { benchmark ->
                        benchmark.primaryStatus == "ok" && benchmark.secondaryStatus == "ok"
                    }
                    val candidateBenchmarks = walk.benchmarks
                    candidateBenchmarks.forEach { benchmark ->
                        locationBenchmarkDetails[LocationConfigs.encodeStoredLocation(benchmark.profile)] = benchmark.detail
                    }
                    val winner = walk.winner ?: bestSecondaryFallback(candidateBenchmarks) ?: run {
                        if (state.profileSourceMode != ProfileSourceMode.SUBSCRIPTION) {
                            storage.updateLocationBenchmarkDetails(locationBenchmarkDetails)
                        }
                        val bestAttempt = candidateBenchmarks.minByOrNull { it.score }?.detail
                        val detail = bestAttempt ?: "no benchmark results"
                        error(
                            "No location fully reached the secondary site. Best attempt: $detail",
                        )
                    }

                    if (state.profileSourceMode == ProfileSourceMode.SUBSCRIPTION) {
                        storage.updateCurrentLocations(profiles.map { it.rawLink })
                    }
                    storage.updateLocationBenchmarkDetails(locationBenchmarkDetails)

                    val runtimeConfig = SingBoxConfigFactory.buildTunConfig(
                        profile = winner.profile,
                        dns = dnsSettings,
                        routingRules = state.routingRules,
                    )
                    ProfileSelection(
                        profile = winner.profile,
                        benchmark = winner,
                        runtimeConfigJson = runtimeConfig,
                    )
                },
            )
        } catch (_: TimeoutCancellationException) {
            Result.failure(IOException("Location search timed out after ${settings.refreshTimeoutMillis / 1000}s"))
        } catch (error: Throwable) {
            Result.failure(error)
        }
    }

    suspend fun syncSubscriptionLocations(): Result<SubscriptionSyncResult> = withContext(Dispatchers.IO) {
        runCatching {
            val state = storage.snapshot()
            require(state.profileUrl.isNotBlank()) { "Remote source is empty" }
            val parsed = loadRemoteSourceLocations(state.profileUrl)
            require(parsed.isNotEmpty()) { "No locations were found in the subscription" }
            val update = storage.updateCurrentLocations(parsed.map { it.rawLink })
            SubscriptionSyncResult(
                selectedMissing = update.selectedMissing,
            )
        }
    }

    suspend fun benchmarkLocation(rawLink: String): Result<ProfileBenchmark> = withContext(Dispatchers.IO) {
        runCatching {
            withTimeout(settings.refreshTimeoutMillis) {
                val state = storage.snapshot()
                val validationSettings = state.validationSettings.normalized()
                val benchmarkUrls = BenchmarkUrls(
                    primary = validationSettings.primaryUrl,
                    secondary = validationSettings.secondaryUrl,
                )
                val profile = LocationConfigs.decodeStoredLocation(rawLink)
                val normalizedRawLink = LocationConfigs.encodeStoredLocation(profile)
                val dnsSettings = DnsSettings(
                    enabled = state.useCustomDns,
                    value = state.customDns,
                )

                storage.updateStatus("Checking TCP speed for ${profile.remarks}...")
                val preflight = preflightProfile(profile)
                val updatedDetails = state.locationBenchmarkDetails.toMutableMap()

                val benchmark = if (preflight.connectMillis == null) {
                    failedBenchmark(profile, preflight, "unreachable")
                } else {
                    storage.updateStatus("Testing ${profile.remarks}...")
                    benchmarkPreflightCandidate(
                        candidate = preflight,
                        idx = 0,
                        dnsSettings = dnsSettings,
                        benchmarkUrls = benchmarkUrls,
                    )
                }

                updatedDetails[normalizedRawLink] = benchmark.detail
                storage.updateLocationBenchmarkDetails(updatedDetails)
                benchmark
            }
        }
    }

    suspend fun rehydrateSelection(state: PersistedState): Result<ProfileSelection> = withContext(Dispatchers.Default) {
        runCatching {
            val storedSelection = state.selectedProfileJson.ifBlank {
                state.selectedProfileRawLink.ifBlank {
                    storage.lastProfileFile()
                        .takeIf { it.exists() }
                        ?.readText()
                        ?.trim()
                        .orEmpty()
                }
            }
            val profile = if (storedSelection.isNotBlank()) {
                LocationConfigs.decodeStoredLocation(storedSelection)
            } else {
                cachedProfile(state)
            }
            val dnsSettings = DnsSettings(
                enabled = state.useCustomDns,
                value = state.customDns,
            )
            ProfileSelection(
                profile = profile,
                benchmark = ProfileBenchmark(
                    profile = profile,
                    primaryStatus = "cached",
                    secondaryStatus = "cached",
                    primaryTotal = null,
                    secondaryTotal = null,
                    score = 0.0,
                    detail = state.lastBenchmarkSummary.ifBlank { "Using cached selection" },
                ),
                runtimeConfigJson = if (profile.rawLink.isNotBlank()) {
                    SingBoxConfigFactory.buildTunConfig(
                        profile = profile,
                        dns = dnsSettings,
                        routingRules = state.routingRules,
                    )
                } else {
                    state.runtimeConfigJson
                },
            )
        }
    }

    suspend fun selectionFromRawLink(
        state: PersistedState,
        rawLink: String,
        detail: String,
    ): Result<ProfileSelection> = withContext(Dispatchers.Default) {
        runCatching {
            val profile = LocationConfigs.parseLocationInput(rawLink)
            val dnsSettings = DnsSettings(
                enabled = state.useCustomDns,
                value = state.customDns,
            )
            ProfileSelection(
                profile = profile,
                benchmark = ProfileBenchmark(
                    profile = profile,
                    primaryStatus = "manual",
                    secondaryStatus = "manual",
                    primaryTotal = null,
                    secondaryTotal = null,
                    score = 0.0,
                    detail = detail,
                ),
                runtimeConfigJson = SingBoxConfigFactory.buildTunConfig(
                    profile = profile,
                    dns = dnsSettings,
                    routingRules = state.routingRules,
                ),
            )
        }
    }

    private fun cachedProfile(state: PersistedState): VlessProfile {
        val name = state.selectedProfileName.ifBlank { "Cached selection" }
        val server = state.selectedProfileServer.ifBlank { "cached" }
        return VlessProfile(
            remarks = name,
            uuid = "",
            server = server,
            serverPort = 443,
            network = "tcp",
            flow = "",
            security = "",
            sni = server,
            fingerprint = "chrome",
            publicKey = "",
            shortId = "",
            path = "",
            hostHeader = "",
            serviceName = "",
            headerType = "none",
            rawLink = "",
        )
    }

    private fun downloadSubscription(url: String): String {
        val request = Request.Builder()
            .url(url)
            .header("User-Agent", browserUserAgent)
            .header("Accept", "*/*")
            .build()
        OkHttpClient.Builder()
            .callTimeout(settings.subscriptionMaxTime.toLong(), TimeUnit.SECONDS)
            .build()
            .newCall(request)
            .execute()
            .use { response ->
                if (!response.isSuccessful) throw IOException("Subscription fetch failed: HTTP ${response.code}")
                return response.body?.string().orEmpty()
            }
    }

    private suspend fun loadRemoteSourceLocations(rawSource: String): List<VlessProfile> {
        val resolved = RemoteSourceResolver.resolveForFetch(rawSource)
        val fetchUrl = resolved.fetchUrl ?: error("Remote source did not produce any locations")
        storage.updateStatus("Downloading remote source...")
        val body = downloadSubscription(fetchUrl)
        return runCatching {
            VlessParser.parseSubscription(body)
        }.getOrElse { error ->
            val baseMessage = error.message ?: "Remote source format is not recognized as a VLESS link list"
            if (resolved.preview.kindLabel.equals("Subscription URL", ignoreCase = true)) {
                throw IllegalArgumentException(baseMessage, error)
            }
            throw IllegalArgumentException(
                "${resolved.preview.kindLabel} resolved successfully, but the downloaded content is not a VLESS location list.",
                error,
            )
        }
    }

    private fun decodeStoredLocations(storedLocations: List<String>): List<VlessProfile> {
        return storedLocations.mapIndexed { index, stored ->
            runCatching { LocationConfigs.decodeStoredLocation(stored) }
                .getOrElse { error("Invalid saved location #${index + 1}: ${it.message}") }
        }
    }

    private suspend fun preflightProfiles(profiles: List<VlessProfile>): List<PreflightResult> = coroutineScope {
        val semaphore = Semaphore(settings.prefilterConcurrency)
        profiles.map { profile ->
            async(Dispatchers.IO) {
                semaphore.withPermit {
                    preflightProfile(profile)
                }
            }
        }.awaitAll()
    }

    private suspend fun preflightProfile(profile: VlessProfile): PreflightResult = withContext(Dispatchers.IO) {
        try {
            val connectMillis = withTimeout(settings.prefilterTimeoutMillis) {
                val startedAt = System.nanoTime()
                Socket().use { socket ->
                    socket.connect(
                        InetSocketAddress(profile.server, profile.serverPort),
                        settings.prefilterConnectTimeoutMillis,
                    )
                }
                (System.nanoTime() - startedAt) / 1_000_000.0
            }
            PreflightResult(
                profile = profile,
                connectMillis = connectMillis,
                detail = "${profile.remarks}: tcp=${formatMillis(connectMillis)}",
            )
        } catch (_: TimeoutCancellationException) {
            PreflightResult(
                profile = profile,
                connectMillis = null,
                detail = "${profile.remarks}: tcp_timeout",
            )
        } catch (error: IOException) {
            PreflightResult(
                profile = profile,
                connectMillis = null,
                detail = "${profile.remarks}: ${error.javaClass.simpleName}",
            )
        }
    }

    private suspend fun validateInBatchesUntilSuccess(
        candidates: List<PreflightResult>,
        batchSize: Int,
        dnsSettings: DnsSettings,
        benchmarkUrls: BenchmarkUrls,
        isWinner: (ProfileBenchmark) -> Boolean,
    ): ValidationWalkResult = coroutineScope {
        val benchmarks = mutableListOf<ProfileBenchmark>()
        val normalizedBatchSize = batchSize.coerceAtLeast(1)
        val validationConcurrency = minOf(normalizedBatchSize, 5)
        val semaphore = Semaphore(validationConcurrency)
        for ((batchIndex, batch) in candidates.chunked(normalizedBatchSize).withIndex()) {
            val start = batchIndex * normalizedBatchSize + 1
            val end = start + batch.size - 1
            storage.updateStatus(
                "Testing locations $start-$end of ${candidates.size}...",
            )
            val batchBenchmarks = batch.mapIndexed { offset, candidate ->
                async(Dispatchers.IO) {
                    semaphore.withPermit {
                        benchmarkPreflightCandidate(
                            candidate = candidate,
                            idx = (start - 1) + offset,
                            dnsSettings = dnsSettings,
                            benchmarkUrls = benchmarkUrls,
                        )
                    }
                }
            }.awaitAll()
            benchmarks += batchBenchmarks
            val winner = batchBenchmarks.firstOrNull(isWinner)
            if (winner != null) {
                return@coroutineScope ValidationWalkResult(
                    benchmarks = benchmarks,
                    winner = winner,
                )
            }
        }
        ValidationWalkResult(
            benchmarks = benchmarks,
            winner = null,
        )
    }

    private suspend fun benchmarkPreflightCandidate(
        candidate: PreflightResult,
        idx: Int,
        dnsSettings: DnsSettings,
        benchmarkUrls: BenchmarkUrls,
    ): ProfileBenchmark {
        return validateProfile(
            candidate = candidate,
            idx = idx,
            dnsSettings = dnsSettings,
            benchmarkUrls = benchmarkUrls,
        )
    }

    private suspend fun validateProfile(
        candidate: PreflightResult,
        idx: Int,
        dnsSettings: DnsSettings,
        benchmarkUrls: BenchmarkUrls,
    ): ProfileBenchmark = withContext(Dispatchers.IO) {
        val profile = candidate.profile
        val httpPort = settings.baseHttpPort + idx
        val configFile = createProxyConfig(profile, httpPort, dnsSettings)
        val binary = SingBoxInstaller.resolveBinary(context)
        var process: Process? = null

        try {
            val benchmark = withTimeoutOrNull(settings.profileTimeoutMillis) {
                process = ProcessBuilder(binary.absolutePath, "run", "-c", configFile.absolutePath)
                    .redirectOutput(File("/dev/null"))
                    .redirectError(File("/dev/null"))
                    .start()

                if (!waitForPort("127.0.0.1", httpPort, settings.portWaitMillis)) {
                    return@withTimeoutOrNull failedBenchmark(profile, candidate, "proxy_not_ready")
                }

                val primaryResult = runProxyRuns(httpPort, benchmarkUrls.primary, settings.primaryRuns)
                val secondaryResult = runProxyRuns(httpPort, benchmarkUrls.secondary, settings.secondaryRuns)

                val primaryMedian = medianOrNull(primaryResult.totals)
                val secondaryMedian = medianOrNull(secondaryResult.totals)
                val primaryStatus = classifyCodes(primaryResult.codes, false)
                val secondaryStatus = classifyCodes(secondaryResult.codes, true)
                val statusPenalty = scorePenalty(primaryStatus, secondaryStatus)
                val score = statusPenalty +
                    (primaryMedian ?: 999_999.0) +
                    (secondaryMedian ?: 999_999.0)

                ProfileBenchmark(
                    profile = profile,
                    primaryStatus = primaryStatus,
                    secondaryStatus = secondaryStatus,
                    primaryTotal = primaryMedian,
                    secondaryTotal = secondaryMedian,
                    score = score,
                    detail = buildString {
                        append(profile.remarks)
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

            benchmark ?: failedBenchmark(profile, candidate, "validation_timeout")
        } finally {
            process?.destroy()
            if (process?.waitFor(2, TimeUnit.SECONDS) == false) {
                process?.destroyForcibly()
            }
            configFile.delete()
        }
    }

    private fun createProxyConfig(profile: VlessProfile, httpPort: Int, dnsSettings: DnsSettings): File {
        val temp = File.createTempFile("vpn_proxy", ".json", context.cacheDir)
        temp.writeText(SingBoxConfigFactory.buildProxyValidationConfig(profile, httpPort, dnsSettings))
        return temp
    }

    private fun runProxyRuns(httpPort: Int, url: String, runs: Int): ProxyRunResult {
        val codes = mutableListOf<String>()
        val totals = mutableListOf<Double>()

        repeat(runs) {
            val result = try {
                executeProxyRequest(httpPort, url)
            } catch (_: Exception) {
                ProxyCallResult(code = "000", total = null)
            }
            codes.add(result.code)
            result.total?.let { totals.add(it) }
        }

        return ProxyRunResult(codes = codes, totals = totals)
    }

    private fun executeProxyRequest(httpPort: Int, url: String): ProxyCallResult {
        val client = OkHttpClient.Builder()
            .proxy(Proxy(Proxy.Type.HTTP, InetSocketAddress("127.0.0.1", httpPort)))
            .connectTimeout(settings.connectTimeout.toLong(), TimeUnit.SECONDS)
            .readTimeout(settings.maxTime.toLong(), TimeUnit.SECONDS)
            .callTimeout(settings.maxTime.toLong(), TimeUnit.SECONDS)
            .build()
        val request = Request.Builder()
            .url(url)
            .header("User-Agent", browserUserAgent)
            .header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
            .header("Accept-Language", "en-US,en;q=0.9")
            .header("Cache-Control", "no-cache")
            .build()
        val startedAt = System.nanoTime()
        client.newCall(request).execute().use { response ->
            val duration = (System.nanoTime() - startedAt) / 1_000_000.0
            return ProxyCallResult(inspectResponseCode(url, response), duration)
        }
    }


    private fun inspectResponseCode(url: String, response: Response): String {
        val responseCode = response.code.toString()
        if (response.code !in 200..399) {
            return responseCode
        }
        val bodyPreview = runCatching { response.peekBody(64 * 1024).string() }
            .getOrNull()
            .orEmpty()
            .lowercase(Locale.ROOT)
        val blockedMarkers = buildList {
            addAll(genericSecondaryBlockedMarkers)
            if (looksLikeChatGptHost(url)) {
                addAll(chatGptBlockedMarkers)
            }
        }
        val geoBlocked = blockedMarkers.any { marker -> marker in bodyPreview }
        return if (geoBlocked) {
            "451"
        } else {
            responseCode
        }
    }

    private fun looksLikeChatGptHost(url: String): Boolean {
        val host = runCatching { URI(url).host.orEmpty().lowercase(Locale.ROOT) }
            .getOrDefault("")
        return host == "chatgpt.com" ||
            host.endsWith(".chatgpt.com") ||
            host == "chat.openai.com"
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

    private fun failedBenchmark(
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

    private fun formatMillis(value: Double): String {
        return String.format(Locale.US, "%.1fms", value)
    }

    private suspend fun waitForPort(host: String, port: Int, timeoutMillis: Long): Boolean {
        val deadline = System.currentTimeMillis() + timeoutMillis
        while (System.currentTimeMillis() < deadline) {
            try {
                Socket().use { socket ->
                    socket.connect(InetSocketAddress(host, port), 500)
                }
                return true
            } catch (_: IOException) {
                delay(200)
            }
        }
        return false
    }

    private data class BenchmarkUrls(
        val primary: String = "https://www.google.com/generate_204",
        val secondary: String = "https://chatgpt.com/",
    )

    private data class ValidationSettings(
        val baseHttpPort: Int = 24080,
        val subscriptionMaxTime: Int = 20,
        val prefilterConcurrency: Int = 8,
        val prefilterConnectTimeoutMillis: Int = 1_500,
        val prefilterTimeoutMillis: Long = 2_000L,
        val primaryRuns: Int = 1,
        val secondaryRuns: Int = 1,
        val connectTimeout: Int = 5,
        val maxTime: Int = 5,
        val portWaitMillis: Long = 2_000L,
        val profileTimeoutMillis: Long = 10_000L,
        val refreshTimeoutMillis: Long = 240_000L,
    )

    private data class ProxyRunResult(
        val codes: List<String>,
        val totals: List<Double>,
    )

    private data class ProxyCallResult(
        val code: String,
        val total: Double?,
    )

    private data class PreflightResult(
        val profile: VlessProfile,
        val connectMillis: Double?,
        val detail: String,
    ) {
        val sortScore: Double
            get() = connectMillis ?: Double.POSITIVE_INFINITY
    }
}
