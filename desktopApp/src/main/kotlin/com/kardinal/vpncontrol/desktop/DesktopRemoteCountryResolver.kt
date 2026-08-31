package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.data.BenchmarkSearchLogic
import com.kardinal.vpncontrol.data.CandidateCountryResolver
import com.kardinal.vpncontrol.data.UserCountryResolver
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Proxy
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
        readCountryCode("$baseUrl/country/", proxyPort = null)
    }

    override suspend fun resolveCandidateCountryCode(ipAddress: String): String? = withContext(Dispatchers.IO) {
        val encodedIp = URLEncoder.encode(ipAddress, StandardCharsets.UTF_8)
        readCountryCode("$baseUrl/$encodedIp/country/", proxyPort = null)
    }

    suspend fun resolveUserCountryCode(proxyPort: Int): String? = withContext(Dispatchers.IO) {
        readCountryCode("$baseUrl/country/", proxyPort)
    }

    suspend fun resolveCandidateCountryCode(ipAddress: String, proxyPort: Int): String? = withContext(Dispatchers.IO) {
        val encodedIp = URLEncoder.encode(ipAddress, StandardCharsets.UTF_8)
        readCountryCode("$baseUrl/$encodedIp/country/", proxyPort)
    }

    private fun readCountryCode(url: String, proxyPort: Int?): String? {
        return runCatching {
            val rawConnection = if (proxyPort == null) {
                URL(url).openConnection()
            } else {
                URL(url).openConnection(
                    Proxy(Proxy.Type.HTTP, InetSocketAddress("127.0.0.1", proxyPort)),
                )
            }
            val connection = (rawConnection as HttpURLConnection).apply {
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
