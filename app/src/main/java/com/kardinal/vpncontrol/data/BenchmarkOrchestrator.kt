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
import java.io.File
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.Socket
import java.util.Locale
import java.util.concurrent.TimeUnit

class BenchmarkOrchestrator(
    private val context: android.content.Context,
    private val storage: ProfileStorage,
) {
    private val browserUserAgent =
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 " +
            "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
    private val httpUrls = BenchmarkUrls()
    private val settings = ValidationSettings()

    suspend fun refreshBestProfile(): Result<ProfileSelection> = withContext(Dispatchers.IO) {
        try {
            Result.success(
                withTimeout(settings.refreshTimeoutMillis) {
                    val state = storage.snapshot()
                    val profiles = when (state.profileSourceMode) {
                        ProfileSourceMode.SUBSCRIPTION -> {
                            require(state.profileUrl.isNotBlank()) { "Profile URL is empty" }
                            storage.updateStatus("Downloading subscription")
                            val body = downloadSubscription(state.profileUrl)
                            val parsed = VlessParser.parseSubscription(body)
                            storage.updateCurrentLocations(parsed.map { it.rawLink })
                            parsed
                        }
                        ProfileSourceMode.CURRENT_LOCATIONS -> {
                            storage.updateStatus("Loading current locations")
                            state.currentLocations.mapIndexed { index, stored ->
                                runCatching { LocationConfigs.decodeStoredLocation(stored) }
                                    .getOrElse { error("Invalid saved location #${index + 1}: ${it.message}") }
                            }
                        }
                    }
                    require(profiles.isNotEmpty()) {
                        if (state.profileSourceMode == ProfileSourceMode.SUBSCRIPTION) {
                            "No profiles parsed from subscription"
                        } else {
                            "No saved locations available"
                        }
                    }

                    val dnsSettings = DnsSettings(
                        enabled = state.useCustomDns,
                        value = state.customDns,
                    )

                    storage.updateStatus(
                        "Prefiltering ${profiles.size} " +
                            if (state.profileSourceMode == ProfileSourceMode.SUBSCRIPTION) "subscription profiles" else "saved locations",
                    )
                    val preflightResults = preflightProfiles(profiles)
                    val reachableProfiles = preflightResults
                        .filter { it.connectMillis != null }
                        .sortedBy { it.connectMillis }

                    require(reachableProfiles.isNotEmpty()) {
                        val bestAttempt = preflightResults.minByOrNull { it.sortScore }
                        "No reachable profile found; best attempt: ${bestAttempt?.detail ?: "no benchmark results"}"
                    }

                    val candidates = reachableProfiles.take(settings.validationTopN)
                    storage.updateStatus(
                        "Validating ${candidates.size} fastest profiles with sing-box",
                    )
                    val candidateBenchmarks = validateCandidates(candidates, dnsSettings)
                    val winner = candidateBenchmarks
                        .filter { it.googleStatus == "ok" && it.chatgptStatus == "ok" }
                        .minByOrNull { it.score }
                        ?: run {
                            val bestAttempt = candidateBenchmarks.minByOrNull { it.score }
                            val detail = bestAttempt?.detail ?: "no benchmark results"
                            error(
                                "No compatible profile found after validating ${candidates.size} " +
                                    "of ${profiles.size} profiles; best attempt: $detail",
                            )
                        }

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
            Result.failure(IOException("Refresh timed out after ${settings.refreshTimeoutMillis / 1000}s"))
        } catch (error: Throwable) {
            Result.failure(error)
        }
    }

    suspend fun syncSubscriptionLocations(): Result<Int> = withContext(Dispatchers.IO) {
        runCatching {
            val state = storage.snapshot()
            require(state.profileUrl.isNotBlank()) { "Profile URL is empty" }
            val body = downloadSubscription(state.profileUrl)
            val parsed = VlessParser.parseSubscription(body)
            require(parsed.isNotEmpty()) { "No profiles parsed from subscription" }
            storage.updateCurrentLocations(parsed.map { it.rawLink })
            parsed.size
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
                    googleStatus = "cached",
                    chatgptStatus = "cached",
                    googleTotal = null,
                    chatgptTotal = null,
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
                    googleStatus = "manual",
                    chatgptStatus = "manual",
                    googleTotal = null,
                    chatgptTotal = null,
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

    private suspend fun validateCandidates(
        candidates: List<PreflightResult>,
        dnsSettings: DnsSettings,
    ): List<ProfileBenchmark> = coroutineScope {
        val semaphore = Semaphore(settings.validationConcurrency)
        candidates.mapIndexed { idx, candidate ->
            async(Dispatchers.IO) {
                semaphore.withPermit {
                    validateProfile(candidate, idx, dnsSettings)
                }
            }
        }.awaitAll()
    }

    private suspend fun validateProfile(
        candidate: PreflightResult,
        idx: Int,
        dnsSettings: DnsSettings,
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

                val googleResult = runProxyRuns(httpPort, httpUrls.google, settings.googleRuns)
                val chatgptResult = runProxyRuns(httpPort, httpUrls.chatgpt, settings.chatgptRuns)

                val googleMedian = medianOrNull(googleResult.totals)
                val chatgptMedian = medianOrNull(chatgptResult.totals)
                val googleStatus = classifyCodes(googleResult.codes, false)
                val chatgptStatus = classifyCodes(chatgptResult.codes, true)
                val statusPenalty = when (googleStatus to chatgptStatus) {
                    "ok" to "ok" -> 0.0
                    "ok" to "partial" -> 100.0
                    "ok" to "blocked" -> 200.0
                    else -> 1_000_000.0
                }
                val score = statusPenalty +
                    (googleMedian ?: 999_999.0) +
                    (chatgptMedian ?: 999_999.0)

                ProfileBenchmark(
                    profile = profile,
                    googleStatus = googleStatus,
                    chatgptStatus = chatgptStatus,
                    googleTotal = googleMedian,
                    chatgptTotal = chatgptMedian,
                    score = score,
                    detail = buildString {
                        append(profile.remarks)
                        append(": tcp=")
                        append(candidate.connectMillis?.let(::formatMillis) ?: "unreachable")
                        append(" google=")
                        append(googleStatus)
                        append(" codes=")
                        append(googleResult.codes.joinToString(","))
                        append(" chatgpt=")
                        append(chatgptStatus)
                        append(" codes=")
                        append(chatgptResult.codes.joinToString(","))
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
            return ProxyCallResult(response.code.toString(), duration)
        }
    }

    private fun classifyCodes(codes: List<String>, treat403AsPartial: Boolean): String {
        val ok = codes.any { it.startsWith("2") || it.startsWith("3") }
        val has403 = codes.any { it == "403" }
        return when {
            ok && treat403AsPartial && has403 -> "partial"
            ok -> "ok"
            treat403AsPartial && has403 -> "blocked"
            else -> "bad"
        }
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
            googleStatus = "error",
            chatgptStatus = "error",
            googleTotal = null,
            chatgptTotal = null,
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
        val google: String = "https://www.google.com/generate_204",
        val chatgpt: String = "https://chatgpt.com/",
    )

    private data class ValidationSettings(
        val baseHttpPort: Int = 24080,
        val subscriptionMaxTime: Int = 20,
        val prefilterConcurrency: Int = 8,
        val prefilterConnectTimeoutMillis: Int = 1_500,
        val prefilterTimeoutMillis: Long = 2_000L,
        val validationTopN: Int = 5,
        val validationConcurrency: Int = 3,
        val googleRuns: Int = 1,
        val chatgptRuns: Int = 1,
        val connectTimeout: Int = 5,
        val maxTime: Int = 8,
        val portWaitMillis: Long = 4_000L,
        val profileTimeoutMillis: Long = 18_000L,
        val refreshTimeoutMillis: Long = 60_000L,
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
