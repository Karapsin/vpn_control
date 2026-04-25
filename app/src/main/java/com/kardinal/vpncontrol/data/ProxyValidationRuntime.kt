package com.kardinal.vpncontrol.data

import android.content.Context
import com.kardinal.vpncontrol.model.ProfileBenchmark
import com.kardinal.vpncontrol.model.VlessProfile
import java.io.File
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.Socket
import java.net.URI
import java.util.concurrent.TimeUnit
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

data class ValidationRuntimeSettings(
    val baseHttpPort: Int = 24080,
    val subscriptionMaxTimeSeconds: Int = 20,
    val prefilterConcurrency: Int = 8,
    val prefilterConnectTimeoutMillis: Int = 1_500,
    val prefilterTimeoutMillis: Long = 2_000L,
    val primaryRuns: Int = 1,
    val secondaryRuns: Int = 1,
    val connectTimeoutSeconds: Int = 5,
    val maxTimeSeconds: Int = 5,
    val portWaitMillis: Long = 2_000L,
    val profileTimeoutMillis: Long = 10_000L,
    val refreshTimeoutMillis: Long = 240_000L,
)

class ProxyValidationRuntime(
    private val context: Context,
    private val browserUserAgent: String,
    private val genericSecondaryBlockedMarkers: List<String>,
    private val chatGptBlockedMarkers: List<String>,
) {
    suspend fun preflightProfiles(
        profiles: List<VlessProfile>,
        settings: ValidationRuntimeSettings,
    ): List<PreflightResult> = coroutineScope {
        val semaphore = Semaphore(settings.prefilterConcurrency)
        profiles.map { profile ->
            async(Dispatchers.IO) {
                semaphore.withPermit {
                    preflightProfile(profile, settings)
                }
            }
        }.awaitAll()
    }

    suspend fun preflightProfile(
        profile: VlessProfile,
        settings: ValidationRuntimeSettings,
    ): PreflightResult = withContext(Dispatchers.IO) {
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
                detail = "${profile.remarks}: tcp=${BenchmarkSearchLogic.formatMillis(connectMillis)}",
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

    suspend fun benchmarkCandidate(
        candidate: PreflightResult,
        idx: Int,
        dnsSettings: DnsSettings,
        benchmarkUrls: BenchmarkUrls,
        settings: ValidationRuntimeSettings,
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
                    return@withTimeoutOrNull BenchmarkSearchLogic.failedBenchmark(profile, candidate, "proxy_not_ready")
                }

                val primaryResult = runProxyRuns(httpPort, benchmarkUrls.primary, settings.primaryRuns, settings)
                val secondaryResult = runProxyRuns(httpPort, benchmarkUrls.secondary, settings.secondaryRuns, settings)
                BenchmarkSearchLogic.buildValidatedBenchmark(candidate, primaryResult, secondaryResult)
            }

            benchmark ?: BenchmarkSearchLogic.failedBenchmark(profile, candidate, "validation_timeout")
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

    private fun runProxyRuns(
        httpPort: Int,
        url: String,
        runs: Int,
        settings: ValidationRuntimeSettings,
    ): ProxyRunResult {
        val codes = mutableListOf<String>()
        val totals = mutableListOf<Double>()

        repeat(runs) {
            val result = try {
                executeProxyRequest(httpPort, url, settings)
            } catch (_: Exception) {
                ProxyCallResult(code = "000", total = null)
            }
            codes.add(result.code)
            result.total?.let { totals.add(it) }
        }

        return ProxyRunResult(codes = codes, totals = totals)
    }

    private fun executeProxyRequest(
        httpPort: Int,
        url: String,
        settings: ValidationRuntimeSettings,
    ): ProxyCallResult {
        val client = OkHttpClient.Builder()
            .proxy(Proxy(Proxy.Type.HTTP, InetSocketAddress("127.0.0.1", httpPort)))
            .connectTimeout(settings.connectTimeoutSeconds.toLong(), TimeUnit.SECONDS)
            .readTimeout(settings.maxTimeSeconds.toLong(), TimeUnit.SECONDS)
            .callTimeout(settings.maxTimeSeconds.toLong(), TimeUnit.SECONDS)
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
            .lowercase()
        val blockedMarkers = buildList {
            addAll(genericSecondaryBlockedMarkers)
            if (looksLikeChatGptHost(url)) {
                addAll(chatGptBlockedMarkers)
            }
        }
        val geoBlocked = blockedMarkers.any { marker -> marker in bodyPreview }
        return if (geoBlocked) "451" else responseCode
    }

    private fun looksLikeChatGptHost(url: String): Boolean {
        val host = runCatching { URI(url).host.orEmpty().lowercase() }
            .getOrDefault("")
        return host == "chatgpt.com" ||
            host.endsWith(".chatgpt.com") ||
            host == "chat.openai.com"
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

    private data class ProxyCallResult(
        val code: String,
        val total: Double?,
    )
}
