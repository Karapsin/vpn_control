package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.data.BenchmarkSearchLogic
import com.kardinal.vpncontrol.data.CandidateCountryResolver
import com.kardinal.vpncontrol.data.UserCountryResolver
import java.net.HttpURLConnection
import java.net.URLEncoder
import java.net.URL
import java.nio.charset.StandardCharsets
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

internal class DesktopRemoteCountryResolver(
    private val baseUrl: String = "https://ipapi.co",
    private val connectTimeoutMillis: Int = 1_500,
    private val readTimeoutMillis: Int = 1_500,
) : UserCountryResolver, CandidateCountryResolver {
    override suspend fun resolveUserCountryCode(): String? = withContext(Dispatchers.IO) {
        readCountryCode("$baseUrl/country/")
    }

    override suspend fun resolveCandidateCountryCode(ipAddress: String): String? = withContext(Dispatchers.IO) {
        val encodedIp = URLEncoder.encode(ipAddress, StandardCharsets.UTF_8)
        readCountryCode("$baseUrl/$encodedIp/country/")
    }

    private fun readCountryCode(url: String): String? {
        return runCatching {
            val connection = (URL(url).openConnection() as HttpURLConnection).apply {
                requestMethod = "GET"
                connectTimeout = connectTimeoutMillis
                readTimeout = readTimeoutMillis
                setRequestProperty("User-Agent", "VPNControlDesktop/1.0")
                setRequestProperty("Accept", "text/plain")
            }
            try {
                if (connection.responseCode !in 200..299) {
                    return null
                }
                BenchmarkSearchLogic.normalizeCountryCode(
                    connection.inputStream.bufferedReader().use { it.readText() },
                )
            } finally {
                connection.disconnect()
            }
        }.getOrNull()
    }
}
