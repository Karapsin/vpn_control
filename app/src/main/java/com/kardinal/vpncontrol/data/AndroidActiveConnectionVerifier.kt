package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.model.ProfileBenchmark
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.URI
import java.util.concurrent.TimeUnit
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import okhttp3.Call
import okhttp3.Callback
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response

class AndroidActiveConnectionVerifier(
    private val browserUserAgent: String,
    private val genericSecondaryBlockedMarkers: List<String>,
    private val chatGptBlockedMarkers: List<String>,
    private val diagnosticsLogger: (String) -> Unit = {},
) {
    suspend fun verify(
        attempt: ProfileSelectionAttempt,
        url: String,
        settings: ValidationRuntimeSettings,
    ): Result<ProfileBenchmark> = withContext(Dispatchers.IO) {
        runCatching {
            val port = attempt.activeVerificationPort
                ?: error("Active verifier port is not available")
            val targetHost = sanitizedTargetHost(url)
            val profileName = attempt.selection.profile.remarks
            val startedAt = System.nanoTime()
            diagnosticsLogger(
                "Active verification started: profile=$profileName targetHost=$targetHost activePort=$port " +
                    "profileTimeoutMs=${settings.profileTimeoutMillis} callTimeoutMs=${settings.maxTimeSeconds * 1000L}",
            )
            val result = try {
                withTimeoutOrNull(settings.profileTimeoutMillis) {
                    executeProxyRequest(port, url, settings)
                } ?: run {
                    diagnosticsLogger(
                        "Active verification timed out: profile=$profileName targetHost=$targetHost " +
                            "elapsedMs=${elapsedMillis(startedAt)} timeoutMs=${settings.profileTimeoutMillis}",
                    )
                    return@runCatching BenchmarkSearchLogic.failedActiveVerificationBenchmark(
                        candidate = attempt.preflight,
                        reason = "active_verification_timeout",
                        secondaryStatus = "timeout",
                    )
                }
            } catch (_: java.net.SocketTimeoutException) {
                diagnosticsLogger(
                    "Active verification socket timeout: profile=$profileName targetHost=$targetHost " +
                        "elapsedMs=${elapsedMillis(startedAt)} timeoutMs=${settings.maxTimeSeconds * 1000L}",
                )
                return@runCatching BenchmarkSearchLogic.failedActiveVerificationBenchmark(
                    candidate = attempt.preflight,
                    reason = "active_verification_timeout",
                    secondaryStatus = "timeout",
                )
            } catch (error: Exception) {
                diagnosticsLogger(
                    "Active verification failed: profile=$profileName targetHost=$targetHost " +
                        "elapsedMs=${elapsedMillis(startedAt)} error=${error.javaClass.simpleName}${safeMessage(error)}",
                )
                return@runCatching BenchmarkSearchLogic.failedActiveVerificationBenchmark(
                    candidate = attempt.preflight,
                    reason = "active_verification_failed",
                    secondaryStatus = "error",
                )
            }
            val benchmark = BenchmarkSearchLogic.buildActiveVerificationBenchmark(
                candidate = attempt.preflight,
                testResult = ProxyRunResult(
                    codes = listOf(result.code),
                    totals = listOfNotNull(result.total),
                ),
            )
            diagnosticsLogger(
                "Active verification completed: profile=$profileName targetHost=$targetHost " +
                    "code=${result.code} status=${benchmark.testStatus} elapsedMs=${elapsedMillis(startedAt)}",
            )
            benchmark
        }
    }

    private suspend fun executeProxyRequest(
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
        val call = client.newCall(request)
        return suspendCancellableCoroutine { continuation ->
            continuation.invokeOnCancellation {
                call.cancel()
            }
            call.enqueue(
                object : Callback {
                    override fun onFailure(call: Call, e: IOException) {
                        if (continuation.isActive) {
                            continuation.resumeWithException(e)
                        }
                    }

                    override fun onResponse(call: Call, response: Response) {
                        try {
                            response.use {
                                val duration = (System.nanoTime() - startedAt) / 1_000_000.0
                                val result = ProxyCallResult(inspectResponseCode(url, it), duration)
                                if (continuation.isActive) {
                                    continuation.resume(result)
                                }
                            }
                        } catch (error: Throwable) {
                            if (continuation.isActive) {
                                continuation.resumeWithException(error)
                            }
                        }
                    }
                },
            )
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

    private fun sanitizedTargetHost(url: String): String {
        return runCatching { URI(url).host.orEmpty().lowercase() }
            .getOrDefault("")
            .ifBlank { "unknown" }
    }

    private fun elapsedMillis(startedAt: Long): Long {
        return (System.nanoTime() - startedAt) / 1_000_000L
    }

    private fun safeMessage(error: Exception): String {
        val message = error.message
            ?.replace(Regex("[\\r\\n]+"), " ")
            ?.take(180)
            ?.takeIf { it.isNotBlank() }
            ?: return ""
        return ": $message"
    }

    private data class ProxyCallResult(
        val code: String,
        val total: Double?,
    )
}
