package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.BenchmarkStatusMessages
import com.kardinal.vpncontrol.data.BenchmarkSearchLogic
import com.kardinal.vpncontrol.data.BenchmarkUrls
import com.kardinal.vpncontrol.data.BestCandidateAttemptPlan
import com.kardinal.vpncontrol.data.CandidateCountryResolver
import com.kardinal.vpncontrol.data.LocationConfigs
import com.kardinal.vpncontrol.data.PreflightResult
import com.kardinal.vpncontrol.data.ProxyRunResult
import com.kardinal.vpncontrol.data.UserCountryResolver
import com.kardinal.vpncontrol.data.ValidationWalkResult
import com.kardinal.vpncontrol.model.ProfileBenchmark
import com.kardinal.vpncontrol.model.ProxyProtocol
import com.kardinal.vpncontrol.model.ProxyProfile
import java.io.IOException
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.ServerSocket
import java.net.Socket
import java.net.URL
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.util.concurrent.ExecutionException
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicInteger
import kotlin.math.roundToInt
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit

data class DesktopValidationSettings(
    val preflightConcurrency: Int = 4,
    val batchSize: Int = 3,
    val preflightConnectTimeoutMillis: Int = 1_500,
    val preflightTimeoutMillis: Long = 2_000L,
    val proxyConnectTimeoutMillis: Int = 4_000,
    val proxyReadTimeoutMillis: Int = 5_000,
    val startupTimeoutMillis: Long = 4_000L,
    val profileTimeoutMillis: Long = 20_000L,
    val searchTimeoutMillis: Long = 180_000L,
)

class DesktopProxyValidationRuntime(
    private val baseDir: Path = Paths.get(
        System.getProperty("user.home"),
        ".vpn-control-desktop",
        "validation",
    ),
    private val singBoxResolver: DesktopSingBoxResolver = DesktopSingBoxResolver(baseDir.resolve("tools")),
    private val userCountryResolver: UserCountryResolver = DesktopRemoteCountryResolver(),
    private val candidateCountryResolver: CandidateCountryResolver = DesktopRemoteCountryResolver(),
) {
    private val preflightThreadCounter = AtomicInteger()

    suspend fun benchmarkLocation(
        profile: ProxyProfile,
        dnsSettings: DesktopDnsSettings,
        benchmarkUrls: BenchmarkUrls,
        settings: DesktopValidationSettings = DesktopValidationSettings(),
    ): Result<ProfileBenchmark> = withContext(Dispatchers.IO) {
        runCatching {
            val candidate = preflightProfile(profile, settings)
            if (candidate.connectMillis == null) {
                BenchmarkSearchLogic.failedBenchmark(profile, candidate, "tcp_unreachable")
            } else {
                benchmarkCandidate(candidate, dnsSettings, benchmarkUrls, settings)
            }
        }
    }

    suspend fun evaluateProfiles(
        profiles: List<ProxyProfile>,
        dnsSettings: DesktopDnsSettings,
        benchmarkUrls: BenchmarkUrls,
        settings: DesktopValidationSettings = DesktopValidationSettings(),
        onProgress: suspend (String) -> Unit = {},
    ): BestCandidateAttemptPlan = withContext(Dispatchers.IO) {
        val benchmarkableProfiles = profiles.filterNot { it.protocol == ProxyProtocol.CUSTOM }
        onProgress(BenchmarkStatusMessages.detectingCountry())
        val userCountry = userCountryResolver.resolveUserCountryCode()
        onProgress(BenchmarkStatusMessages.checkingLocations(profiles.size))
        val preflightResults = preflightProfiles(benchmarkableProfiles, settings)
        val plan = BenchmarkSearchLogic.planActiveVerificationAttempts(
            profiles = profiles,
            preflightResults = preflightResults,
            userCountryCode = userCountry,
        )
        if (plan.excluded.isNotEmpty()) {
            onProgress(BenchmarkStatusMessages.excludingSameCountryLocations(plan.excluded.size))
        }
        plan
    }

    private suspend fun preflightProfiles(
        profiles: List<ProxyProfile>,
        settings: DesktopValidationSettings,
    ): List<PreflightResult> {
        val concurrency = settings.preflightConcurrency.coerceAtLeast(1)
        return profiles.chunked(concurrency).flatMap { batch ->
            coroutineScope {
                batch.map { profile ->
                    async { preflightProfile(profile, settings) }
                }.awaitAll()
            }
        }
    }

    private suspend fun validateInBatchesUntilSuccess(
        candidates: List<PreflightResult>,
        dnsSettings: DesktopDnsSettings,
        benchmarkUrls: BenchmarkUrls,
        settings: DesktopValidationSettings,
        onProgress: suspend (String) -> Unit,
        isWinner: (ProfileBenchmark) -> Boolean,
    ): ValidationWalkResult = coroutineScope {
        val benchmarks = mutableListOf<ProfileBenchmark>()
        val normalizedBatchSize = settings.batchSize.coerceAtLeast(1)
        val validationConcurrency = minOf(normalizedBatchSize, 5)
        val semaphore = Semaphore(validationConcurrency)
        for ((batchIndex, batch) in candidates.chunked(normalizedBatchSize).withIndex()) {
            val start = batchIndex * normalizedBatchSize + 1
            val end = start + batch.size - 1
            onProgress(BenchmarkStatusMessages.testingLocationsRange(start, end, candidates.size))
            val batchBenchmarks = batch.map { candidate ->
                async(Dispatchers.IO) {
                    semaphore.withPermit {
                        benchmarkCandidate(candidate, dnsSettings, benchmarkUrls, settings)
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

    private suspend fun preflightProfile(
        profile: ProxyProfile,
        settings: DesktopValidationSettings,
    ): PreflightResult {
        val executor = Executors.newSingleThreadExecutor { runnable ->
            Thread(runnable, "vpn-control-preflight-${preflightThreadCounter.incrementAndGet()}").apply {
                isDaemon = true
            }
        }
        val future = executor.submit<PreflightConnection> {
            val startedAt = System.nanoTime()
            Socket().use { socket ->
                socket.connect(
                    InetSocketAddress(profile.server, profile.serverPort),
                    settings.preflightConnectTimeoutMillis,
                )
                PreflightConnection(
                    connectMillis = (System.nanoTime() - startedAt) / 1_000_000.0,
                    resolvedServerAddress = socket.inetAddress?.hostAddress,
                )
            }
        }
        val result = try {
            val connection = future.get(settings.preflightTimeoutMillis, TimeUnit.MILLISECONDS)
            PreflightResult(
                profile = profile,
                connectMillis = connection.connectMillis,
                detail = BenchmarkSearchLogic.preflightDetail(profile, connection.connectMillis),
                resolvedServerAddress = connection.resolvedServerAddress,
            )
        } catch (_: TimeoutException) {
            future.cancel(true)
            PreflightResult(
                profile = profile,
                connectMillis = null,
                detail = BenchmarkSearchLogic.preflightDetail(profile, null, "tcp_timeout"),
            )
        } catch (error: InterruptedException) {
            future.cancel(true)
            Thread.currentThread().interrupt()
            PreflightResult(
                profile = profile,
                connectMillis = null,
                detail = BenchmarkSearchLogic.preflightDetail(profile, null, "tcp_cancelled"),
            )
        } catch (error: ExecutionException) {
            val cause = error.cause
            if (cause is IOException) {
                PreflightResult(
                    profile = profile,
                    connectMillis = null,
                    detail = BenchmarkSearchLogic.preflightDetail(profile, null, cause.javaClass.simpleName),
                )
            } else {
                PreflightResult(
                    profile = profile,
                    connectMillis = null,
                    detail = BenchmarkSearchLogic.preflightDetail(profile, null, "tcp_error"),
                )
            }
        } catch (_: IOException) {
            PreflightResult(
                profile = profile,
                connectMillis = null,
                detail = BenchmarkSearchLogic.preflightDetail(profile, null, "tcp_unreachable"),
            )
        } finally {
            executor.shutdownNow()
        }
        val candidateCountry = result.resolvedServerAddress?.let {
            candidateCountryResolver.resolveCandidateCountryCode(it)
        }
        if (candidateCountry == null) {
            return result
        }
        return result.copy(
            detail = BenchmarkSearchLogic.preflightDetail(
                profile = profile,
                connectMillis = result.connectMillis,
                candidateCountryCode = candidateCountry,
            ),
            candidateCountryCode = candidateCountry,
        )
    }

    private suspend fun benchmarkCandidate(
        candidate: PreflightResult,
        dnsSettings: DesktopDnsSettings,
        benchmarkUrls: BenchmarkUrls,
        settings: DesktopValidationSettings,
    ): ProfileBenchmark {
        Files.createDirectories(baseDir)
        val port = allocateListenPort()
        val configJson = DesktopProxyConfigFactory.buildProxyOnlyConfig(
            profile = candidate.profile.withResolvedValidationServer(candidate.resolvedServerAddress),
            dns = dnsSettings,
            routingRules = com.kardinal.vpncontrol.model.RoutingRules(ignoreRules = true),
            listenPort = port,
        )
        val safeName = candidate.profile.remarks
            .lowercase()
            .replace(Regex("[^a-z0-9]+"), "-")
            .trim('-')
            .ifBlank { "profile" }
        val configFile = Files.createTempFile(baseDir, "validate-$safeName-", ".json")
        val logFile = Files.createTempFile(baseDir, "validate-$safeName-", ".log")
        Files.writeString(configFile, configJson)
        Files.writeString(logFile, "")
        val singBox = singBoxResolver.resolve()
            ?: return BenchmarkSearchLogic.failedBenchmark(candidate.profile, candidate, "sing_box_missing")
        val probeSingBox = runCatching {
            prepareDirectProbeSingBoxExecutable(singBox.path, baseDir)
        }.getOrElse {
            return BenchmarkSearchLogic.failedBenchmark(candidate.profile, candidate, "probe_binary_failed")
        }

        var process: Process? = null
        try {
            val benchmark = withTimeoutOrNull(settings.profileTimeoutMillis) {
                process = ProcessBuilder(probeSingBox.toString(), "run", "-c", configFile.toString())
                    .directory(baseDir.toFile())
                    .redirectErrorStream(true)
                    .redirectOutput(logFile.toFile())
                    .start()

                if (!waitForPort(process, port, settings.startupTimeoutMillis)) {
                    return@withTimeoutOrNull BenchmarkSearchLogic.failedBenchmark(
                        candidate.profile,
                        candidate,
                        "proxy_not_ready",
                    )
                }

                val primary = runProxyRuns(port, benchmarkUrls.primary, settings)
                val secondary = runProxyRuns(port, benchmarkUrls.secondary, settings)
                BenchmarkSearchLogic.buildValidatedBenchmark(candidate, primary, secondary)
            }
            return benchmark ?: BenchmarkSearchLogic.failedBenchmark(candidate.profile, candidate, "validation_timeout")
        } catch (_: IOException) {
            return BenchmarkSearchLogic.failedBenchmark(candidate.profile, candidate, "sing_box_launch_failed")
        } finally {
            process?.destroy()
            if (process?.waitFor(2, TimeUnit.SECONDS) == false) {
                process?.destroyForcibly()
                process?.waitFor(2, TimeUnit.SECONDS)
            }
            runCatching { Files.deleteIfExists(configFile) }
            runCatching { Files.deleteIfExists(logFile) }
        }
    }

    private fun runProxyRuns(
        port: Int,
        url: String,
        settings: DesktopValidationSettings,
    ): ProxyRunResult {
        val result = try {
            executeProxyRequest(port, url, settings)
        } catch (_: Exception) {
            ProxyCallResult(code = "000", total = null)
        }
        return ProxyRunResult(
            codes = listOf(result.code),
            totals = listOfNotNull(result.total),
        )
    }

    private fun executeProxyRequest(
        port: Int,
        url: String,
        settings: DesktopValidationSettings,
    ): ProxyCallResult {
        val proxy = Proxy(Proxy.Type.HTTP, InetSocketAddress("127.0.0.1", port))
        val startedAt = System.nanoTime()
        val connection = (URL(url).openConnection(proxy) as HttpURLConnection).apply {
            requestMethod = "GET"
            instanceFollowRedirects = true
            connectTimeout = settings.proxyConnectTimeoutMillis
            readTimeout = settings.proxyReadTimeoutMillis
            setRequestProperty("User-Agent", "VPNControlDesktop/1.0")
            setRequestProperty("Accept", "*/*")
        }
        return try {
            val code = connection.responseCode
            runCatching { connection.inputStream?.use { it.readNBytes(512) } }
            val duration = (System.nanoTime() - startedAt) / 1_000_000.0
            ProxyCallResult(
                code = code.toString(),
                total = ((duration * 10.0).roundToInt() / 10.0),
            )
        } finally {
            connection.disconnect()
        }
    }

    private suspend fun waitForPort(process: Process, port: Int, timeoutMillis: Long): Boolean {
        val deadline = System.currentTimeMillis() + timeoutMillis
        while (System.currentTimeMillis() < deadline) {
            if (!process.isAlive) {
                return false
            }
            try {
                Socket().use { socket ->
                    socket.connect(InetSocketAddress("127.0.0.1", port), 250)
                }
                return true
            } catch (_: IOException) {
                delay(150)
            }
        }
        return false
    }

    private fun allocateListenPort(): Int {
        ServerSocket(0).use { socket ->
            return socket.localPort
        }
    }

    private data class ProxyCallResult(
        val code: String,
        val total: Double?,
    )

    private data class PreflightConnection(
        val connectMillis: Double,
        val resolvedServerAddress: String?,
    )

}

internal fun ProxyProfile.withResolvedValidationServer(resolvedServerAddress: String?): ProxyProfile {
    val resolvedServer = resolvedServerAddress
        ?.trim()
        ?.takeIf { it.isNotEmpty() && it != server }
        ?: return this
    val originalServer = server
    return copy(
        server = resolvedServer,
        sni = sni.ifBlank {
            if (usesTlsForValidation()) originalServer else ""
        },
        hostHeader = hostHeader.ifBlank {
            if (network == "ws") originalServer else ""
        },
    )
}

private fun ProxyProfile.usesTlsForValidation(): Boolean {
    return when (protocol) {
        ProxyProtocol.VLESS,
        ProxyProtocol.VMESS -> security.isNotBlank()
        ProxyProtocol.TROJAN -> true
        ProxyProtocol.SHADOWSOCKS,
        ProxyProtocol.SOCKS,
        ProxyProtocol.CUSTOM -> false
    }
}
