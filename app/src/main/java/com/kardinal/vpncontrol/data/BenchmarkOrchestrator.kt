package com.kardinal.vpncontrol.data

import android.content.Context
import com.kardinal.vpncontrol.model.PersistedState
import com.kardinal.vpncontrol.model.BenchmarkValidationSettings
import com.kardinal.vpncontrol.model.ProfileBenchmark
import com.kardinal.vpncontrol.model.ProfileSourceMode
import com.kardinal.vpncontrol.model.ProfileSelection
import com.kardinal.vpncontrol.model.VlessProfile
import com.kardinal.vpncontrol.vpn.LibboxValidationPlatform
import io.nekohasekai.libbox.BoxService
import io.nekohasekai.libbox.Libbox
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
import java.io.EOFException
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.Socket
import java.util.Locale
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLHandshakeException

class BenchmarkOrchestrator(
    private val context: android.content.Context,
    private val storage: ProfileStorage,
) {
    private val browserUserAgent =
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 " +
            "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
    private val settings = ValidationSettings()
    private val httpStatusRegex = Regex("""HTTP\s+(\d{3})""")

    suspend fun refreshBestProfile(): Result<ProfileSelection> = withContext(Dispatchers.IO) {
        try {
            Result.success(
                withTimeout(settings.refreshTimeoutMillis) {
                    val state = storage.snapshot()
                    val gatewayBackedSubscription =
                        state.profileSourceMode == ProfileSourceMode.SUBSCRIPTION &&
                            RemoteSourceResolver.isGatewayBackedVpnImport(state.profileUrl)
                    val validationSettings = state.validationSettings.normalized()
                    val benchmarkUrls = BenchmarkUrls(
                        google = validationSettings.generalUrl,
                        chatgpt = validationSettings.chatGptUrl,
                    )
                    val profiles = when (state.profileSourceMode) {
                        ProfileSourceMode.SUBSCRIPTION -> {
                            require(state.profileUrl.isNotBlank()) { "Remote source is empty" }
                            storage.updateStatus("Resolving remote source...")
                            val parsed = loadRemoteSourceLocations(state.profileUrl)
                            storage.updateCurrentLocations(parsed.map { it.rawLink })
                            parsed
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
                    storage.updateLocationBenchmarkDetails(locationBenchmarkDetails)
                    val reachableProfiles = preflightResults
                        .filter { it.connectMillis != null }
                        .sortedBy { it.connectMillis }

                    require(reachableProfiles.isNotEmpty()) {
                        val bestAttempt = preflightResults.minByOrNull { it.sortScore }
                        "No reachable location found. Best attempt: ${bestAttempt?.detail ?: "no benchmark results"}"
                    }

                    val amneziaWinner: ProfileBenchmark?
                    val candidateBenchmarks = if (gatewayBackedSubscription) {
                        val candidates = reachableProfiles
                        storage.updateStatus(
                            "Checking TCP speed for ${candidates.size} Amnezia locations...",
                        )
                        amneziaWinner = candidates.firstOrNull()?.let { candidate ->
                            ProfileBenchmark(
                                profile = candidate.profile,
                                googleStatus = "skipped",
                                chatgptStatus = "skipped",
                                googleTotal = null,
                                chatgptTotal = null,
                                score = candidate.connectMillis ?: Double.POSITIVE_INFINITY,
                                detail = candidate.detail,
                            )
                        }
                        emptyList()
                    } else {
                        amneziaWinner = null
                        val candidates = reachableProfiles.take(validationSettings.candidateCount)
                        storage.updateStatus(
                            "Testing the top ${candidates.size} locations " +
                                "(up to ${validationSettings.concurrency()} at once)...",
                        )
                        validateCandidates(
                            candidates = candidates,
                            dnsSettings = dnsSettings,
                            benchmarkUrls = benchmarkUrls,
                            validationSettings = validationSettings,
                        )
                    }
                    candidateBenchmarks.forEach { benchmark ->
                        locationBenchmarkDetails[LocationConfigs.encodeStoredLocation(benchmark.profile)] = benchmark.detail
                    }
                    var winner = if (gatewayBackedSubscription) {
                        amneziaWinner
                    } else {
                        candidateBenchmarks
                            .filter { it.googleStatus == "ok" && it.chatgptStatus == "ok" }
                            .minByOrNull { it.score }
                    }
                    storage.updateLocationBenchmarkDetails(locationBenchmarkDetails)
                    winner = winner ?: run {
                        val bestAttempt = if (gatewayBackedSubscription) {
                            amneziaWinner?.detail
                        } else {
                            candidateBenchmarks.minByOrNull { it.score }?.detail
                        }
                        val detail = bestAttempt ?: "no benchmark results"
                        if (gatewayBackedSubscription) {
                            error(
                                "No reachable Amnezia location found. Best attempt: $detail",
                            )
                        } else {
                            error(
                                "No working location found. Best attempt: $detail",
                            )
                        }
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
            Result.failure(IOException("Location search timed out after ${settings.refreshTimeoutMillis / 1000}s"))
        } catch (error: Throwable) {
            Result.failure(error)
        }
    }

    suspend fun syncSubscriptionLocations(): Result<Int> = withContext(Dispatchers.IO) {
        runCatching {
            val state = storage.snapshot()
            require(state.profileUrl.isNotBlank()) { "Remote source is empty" }
            val parsed = loadRemoteSourceLocations(state.profileUrl)
            require(parsed.isNotEmpty()) { "No locations were found in the subscription" }
            storage.updateCurrentLocations(parsed.map { it.rawLink })
            parsed.size
        }
    }

    suspend fun benchmarkLocation(rawLink: String): Result<ProfileBenchmark> = withContext(Dispatchers.IO) {
        runCatching {
            withTimeout(settings.refreshTimeoutMillis) {
                val state = storage.snapshot()
                val gatewayBackedSubscription =
                    state.profileSourceMode == ProfileSourceMode.SUBSCRIPTION &&
                        RemoteSourceResolver.isGatewayBackedVpnImport(state.profileUrl)
                val validationSettings = state.validationSettings.normalized()
                val benchmarkUrls = BenchmarkUrls(
                    google = validationSettings.generalUrl,
                    chatgpt = validationSettings.chatGptUrl,
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
                    if (gatewayBackedSubscription) {
                        validateProfileWithLibbox(
                            candidate = preflight,
                            idx = 0,
                            dnsSettings = dnsSettings,
                            benchmarkUrls = benchmarkUrls,
                            secondaryOnly = false,
                        )
                    } else {
                        validateProfile(
                            candidate = preflight,
                            idx = 0,
                            dnsSettings = dnsSettings,
                            benchmarkUrls = benchmarkUrls,
                        )
                    }
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

    private suspend fun loadRemoteSourceLocations(rawSource: String): List<VlessProfile> {
        val resolved = RemoteSourceResolver.resolveForFetch(
            context = context,
            raw = rawSource,
            onStatus = { storage.updateStatus(it) },
        )
        if (resolved.embeddedLocations.isNotEmpty()) {
            return resolved.embeddedLocations
        }
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

    private suspend fun validateCandidates(
        candidates: List<PreflightResult>,
        dnsSettings: DnsSettings,
        benchmarkUrls: BenchmarkUrls,
        validationSettings: BenchmarkValidationSettings,
    ): List<ProfileBenchmark> = coroutineScope {
        val semaphore = Semaphore(validationSettings.concurrency())
        candidates.mapIndexed { idx, candidate ->
            async(Dispatchers.IO) {
                semaphore.withPermit {
                    validateProfile(candidate, idx, dnsSettings, benchmarkUrls)
                }
            }
        }.awaitAll()
    }

    private suspend fun validateCandidatesWithLibbox(
        candidates: List<PreflightResult>,
        dnsSettings: DnsSettings,
        benchmarkUrls: BenchmarkUrls,
        concurrencyLimit: Int,
        secondaryOnly: Boolean,
    ): List<ProfileBenchmark> = coroutineScope {
        val semaphore = Semaphore(concurrencyLimit.coerceAtLeast(1))
        candidates.mapIndexed { idx, candidate ->
            async(Dispatchers.IO) {
                semaphore.withPermit {
                    validateProfileWithLibbox(
                        candidate = candidate,
                        idx = idx,
                        dnsSettings = dnsSettings,
                        benchmarkUrls = benchmarkUrls,
                        secondaryOnly = secondaryOnly,
                    )
                }
            }
        }.awaitAll()
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

                val googleResult = runProxyRuns(httpPort, benchmarkUrls.google, settings.googleRuns)
                val chatgptResult = runProxyRuns(httpPort, benchmarkUrls.chatgpt, settings.chatgptRuns)

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
                        append(" primary=")
                        append(googleStatus)
                        append(" primary_codes=")
                        append(googleResult.codes.joinToString(","))
                        append(" secondary=")
                        append(chatgptStatus)
                        append(" secondary_codes=")
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

    private suspend fun validateProfileWithLibbox(
        candidate: PreflightResult,
        idx: Int,
        dnsSettings: DnsSettings,
        benchmarkUrls: BenchmarkUrls,
        secondaryOnly: Boolean,
    ): ProfileBenchmark = withContext(Dispatchers.IO) {
        val profile = candidate.profile
        val socksPort = settings.baseHttpPort + idx
        val config = SingBoxConfigFactory.buildSocksValidationConfig(profile, socksPort, dnsSettings)
        val platform = LibboxValidationPlatform(
            context = context,
            logPrefix = "validation[${profile.remarks}]",
        )
        var service: BoxService? = null

        try {
            val benchmark = withTimeoutOrNull(settings.profileTimeoutMillis) {
                service = Libbox.newService(config, platform)
                service?.start()

                if (!waitForPort("127.0.0.1", socksPort, settings.portWaitMillis)) {
                    return@withTimeoutOrNull failedBenchmark(profile, candidate, "socks_not_ready")
                }

                delay(150)

                val primaryResult = if (secondaryOnly) {
                    ProxyRunResult(codes = emptyList(), totals = emptyList())
                } else {
                    runLibboxRuns(socksPort, benchmarkUrls.google, settings.googleRuns)
                }
                val secondaryResult = runLibboxRuns(socksPort, benchmarkUrls.chatgpt, settings.chatgptRuns)

                val primaryMedian = medianOrNull(primaryResult.totals)
                val secondaryMedian = medianOrNull(secondaryResult.totals)
                val primaryStatus = if (secondaryOnly) "skipped" else classifyCodes(primaryResult.codes, false)
                val secondaryStatus = classifyCodes(secondaryResult.codes, true)
                val statusPenalty = if (secondaryOnly) {
                    when (secondaryStatus) {
                        "ok" -> 0.0
                        "partial" -> 100.0
                        "blocked" -> 200.0
                        else -> 1_000_000.0
                    }
                } else {
                    when (primaryStatus to secondaryStatus) {
                        "ok" to "ok" -> 0.0
                        "ok" to "partial" -> 100.0
                        "ok" to "blocked" -> 200.0
                        else -> 1_000_000.0
                    }
                }
                val score = statusPenalty +
                    (candidate.connectMillis ?: 999_999.0) +
                    (primaryMedian ?: 999_999.0) +
                    (secondaryMedian ?: 999_999.0)

                ProfileBenchmark(
                    profile = profile,
                    googleStatus = primaryStatus,
                    chatgptStatus = secondaryStatus,
                    googleTotal = primaryMedian,
                    chatgptTotal = secondaryMedian,
                    score = score,
                    detail = buildString {
                        append(profile.remarks)
                        append(": tcp=")
                        append(candidate.connectMillis?.let(::formatMillis) ?: "unreachable")
                        if (!secondaryOnly) {
                            append(" primary=")
                            append(primaryStatus)
                            append(" primary_codes=")
                            append(primaryResult.codes.joinToString(","))
                        }
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
        } catch (error: Throwable) {
            DiagnosticsLogger.append(
                context,
                "Libbox validation failed for ${profile.remarks}",
                error,
            )
            failedBenchmark(profile, candidate, error.message ?: "validation_error")
        } finally {
            runCatching { service?.close() }
        }
    }

    private fun runLibboxRuns(socksPort: Int, url: String, runs: Int): ProxyRunResult {
        val codes = mutableListOf<String>()
        val totals = mutableListOf<Double>()

        repeat(runs) {
            val result = executeLibboxRequest(socksPort, url)
            codes.add(result.code)
            result.total?.let { totals.add(it) }
        }

        return ProxyRunResult(codes = codes, totals = totals)
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

    private fun executeLibboxRequest(socksPort: Int, url: String): ProxyCallResult {
        val client = OkHttpClient.Builder()
            .proxy(Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", socksPort)))
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
            .header("Connection", "close")
            .build()
        val startedAt = System.nanoTime()
        return try {
            client.newCall(request).execute().use { response ->
                val duration = (System.nanoTime() - startedAt) / 1_000_000.0
                ProxyCallResult(response.code.toString(), duration)
            }
        } catch (error: Exception) {
            val duration = (System.nanoTime() - startedAt) / 1_000_000.0
            val code = parseHttpStatusCode(error.message)
            if (code != null) {
                ProxyCallResult(code, duration)
            } else if (error is SSLHandshakeException || error.cause is EOFException) {
                ProxyCallResult("299", duration)
            } else {
                DiagnosticsLogger.append(
                    context,
                    "Libbox validation request failed for $url via socks:$socksPort",
                    error,
                )
                ProxyCallResult("000", null)
            }
        }
    }

    private fun parseHttpStatusCode(message: String?): String? {
        if (message.isNullOrBlank()) return null
        return httpStatusRegex.find(message)?.groupValues?.getOrNull(1)
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
        val googleRuns: Int = 1,
        val chatgptRuns: Int = 1,
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
