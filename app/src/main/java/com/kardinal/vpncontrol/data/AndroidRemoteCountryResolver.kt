package com.kardinal.vpncontrol.data

import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request

class AndroidRemoteCountryResolver(
    private val baseUrl: String = "https://ipapi.co",
    timeoutMillis: Long = 1_500L,
) : UserCountryResolver, CandidateCountryResolver {
    private val client = OkHttpClient.Builder()
        .connectTimeout(timeoutMillis, TimeUnit.MILLISECONDS)
        .readTimeout(timeoutMillis, TimeUnit.MILLISECONDS)
        .callTimeout(timeoutMillis, TimeUnit.MILLISECONDS)
        .build()

    override suspend fun resolveUserCountryCode(): String? = withContext(Dispatchers.IO) {
        readCountryCode("$baseUrl/country/")
    }

    override suspend fun resolveCandidateCountryCode(ipAddress: String): String? = withContext(Dispatchers.IO) {
        val encodedIp = URLEncoder.encode(ipAddress, StandardCharsets.UTF_8.name())
        readCountryCode("$baseUrl/$encodedIp/country/")
    }

    private fun readCountryCode(url: String): String? {
        return runCatching {
            val request = Request.Builder()
                .url(url)
                .header("User-Agent", "VPNControl/1.0 (Android)")
                .header("Accept", "text/plain")
                .build()
            client.newCall(request).execute().use { response ->
                if (!response.isSuccessful) {
                    return null
                }
                BenchmarkSearchLogic.normalizeCountryCode(response.body?.string().orEmpty())
            }
        }.getOrNull()
    }
}
