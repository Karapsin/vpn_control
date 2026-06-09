package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.model.ProfileBenchmark
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.URI
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response

class AndroidActiveConnectionVerifier(
    private val browserUserAgent: String,
    private val genericSecondaryBlockedMarkers: List<String>,
    private val chatGptBlockedMarkers: List<String>,
) {
    suspend fun verify(
        attempt: ProfileSelectionAttempt,
        url: String,
        settings: ValidationRuntimeSettings,
    ): Result<ProfileBenchmark> = withContext(Dispatchers.IO) {
        runCatching {
            val port = attempt.activeVerificationPort
                ?: error("Active verifier port is not available")
            val result = try {
                executeProxyRequest(port, url, settings)
            } catch (_: java.net.SocketTimeoutException) {
                return@runCatching BenchmarkSearchLogic.failedActiveVerificationBenchmark(
                    candidate = attempt.preflight,
                    reason = "active_verification_timeout",
                    secondaryStatus = "timeout",
                )
            } catch (_: Exception) {
                return@runCatching BenchmarkSearchLogic.failedActiveVerificationBenchmark(
                    candidate = attempt.preflight,
                    reason = "active_verification_failed",
                    secondaryStatus = "error",
                )
            }
            BenchmarkSearchLogic.buildActiveVerificationBenchmark(
                candidate = attempt.preflight,
                secondaryResult = ProxyRunResult(
                    codes = listOf(result.code),
                    totals = listOfNotNull(result.total),
                ),
            )
        }
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

    private data class ProxyCallResult(
        val code: String,
        val total: Double?,
    )
}
