package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.data.BenchmarkSearchLogic
import com.kardinal.vpncontrol.data.PreflightResult
import com.kardinal.vpncontrol.data.ProxyRunResult
import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.ProfileBenchmark
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.ServerSocket
import java.net.URI
import java.net.URL
import kotlin.math.roundToInt
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

internal class DesktopActiveConnectionVerifier(
    private val genericBlockedMarkers: List<String> = defaultGenericBlockedMarkers,
    private val chatGptBlockedMarkers: List<String> = defaultChatGptBlockedMarkers,
) {
    fun allocateListenPort(): Int {
        ServerSocket(0).use { socket ->
            return socket.localPort
        }
    }

    suspend fun verify(
        candidate: PreflightResult,
        appMode: AppMode,
        proxyPort: Int?,
        url: String,
        settings: DesktopValidationSettings,
    ): Result<ProfileBenchmark> = withContext(Dispatchers.IO) {
        runCatching {
            val port = proxyPort ?: error("Active verifier port is not available for $appMode")
            val call = try {
                executeRequest(
                    proxyPort = port,
                    url = url,
                    settings = settings,
                )
            } catch (_: java.net.SocketTimeoutException) {
                return@runCatching BenchmarkSearchLogic.failedActiveVerificationBenchmark(
                    candidate = candidate,
                    reason = "active_verification_timeout",
                    secondaryStatus = "timeout",
                )
            } catch (_: Exception) {
                return@runCatching BenchmarkSearchLogic.failedActiveVerificationBenchmark(
                    candidate = candidate,
                    reason = "active_verification_failed",
                    secondaryStatus = "error",
                )
            }
            BenchmarkSearchLogic.buildActiveVerificationBenchmark(
                candidate = candidate,
                secondaryResult = ProxyRunResult(
                    codes = listOf(call.code),
                    totals = listOfNotNull(call.total),
                ),
            )
        }
    }

    private fun executeRequest(
        proxyPort: Int,
        url: String,
        settings: DesktopValidationSettings,
    ): ProxyCallResult {
        val proxy = Proxy(Proxy.Type.HTTP, InetSocketAddress("127.0.0.1", proxyPort))
        val startedAt = System.nanoTime()
        val connection = (URL(url).openConnection(proxy) as HttpURLConnection).apply {
            requestMethod = "GET"
            instanceFollowRedirects = true
            connectTimeout = settings.proxyConnectTimeoutMillis
            readTimeout = settings.proxyReadTimeoutMillis
            setRequestProperty("User-Agent", "VPNControlDesktop/1.0")
            setRequestProperty("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
            setRequestProperty("Accept-Language", "en-US,en;q=0.9")
            setRequestProperty("Cache-Control", "no-cache")
        }
        return try {
            val responseCode = connection.responseCode
            val bodyPreview = runCatching {
                (connection.inputStream ?: connection.errorStream)
                    ?.bufferedReader()
                    ?.use { it.readText().take(64 * 1024) }
            }.getOrNull().orEmpty()
            val duration = (System.nanoTime() - startedAt) / 1_000_000.0
            ProxyCallResult(
                code = inspectResponseCode(url, responseCode, bodyPreview),
                total = ((duration * 10.0).roundToInt() / 10.0),
            )
        } finally {
            connection.disconnect()
        }
    }

    private fun inspectResponseCode(url: String, responseCode: Int, bodyPreview: String): String {
        val code = responseCode.toString()
        if (responseCode !in 200..399) {
            return code
        }
        val lowered = bodyPreview.lowercase()
        val blockedMarkers = buildList {
            addAll(genericBlockedMarkers)
            if (looksLikeChatGptHost(url)) {
                addAll(chatGptBlockedMarkers)
            }
        }
        return if (blockedMarkers.any { marker -> marker in lowered }) "451" else code
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

    private companion object {
        val defaultGenericBlockedMarkers = listOf(
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
        val defaultChatGptBlockedMarkers = listOf(
            "openai's services are not available in your country",
            "you do not have access to chat.openai.com",
        )
    }
}
