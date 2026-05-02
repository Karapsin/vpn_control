package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.shared.storageapi.FetchedSubscriptionContent
import com.kardinal.vpncontrol.shared.storageapi.SubscriptionContentFetcher
import com.kardinal.vpncontrol.shared.storageapi.SubscriptionRequestHeaders
import java.net.HttpURLConnection
import java.net.URL
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

class DesktopSubscriptionDownloadClient : SubscriptionContentFetcher {
    override suspend fun fetch(
        url: String,
        subscriptionHwid: String,
    ): FetchedSubscriptionContent = withContext(Dispatchers.IO) {
        val connection = (URL(url).openConnection() as HttpURLConnection).apply {
            instanceFollowRedirects = true
            requestMethod = "GET"
            connectTimeout = 10_000
            readTimeout = 15_000
            SubscriptionRequestHeaders.build(
                userAgent = "VPNControlDesktop/1.0",
                accept = "*/*",
                subscriptionHwid = subscriptionHwid,
            ).forEach { (name, value) ->
                setRequestProperty(name, value)
            }
        }
        try {
            val statusCode = connection.responseCode
            val stream = if (statusCode in 200..299) {
                connection.inputStream
            } else {
                connection.errorStream
            }
            val body = stream?.bufferedReader()?.use { it.readText() }.orEmpty()
            require(statusCode in 200..299) {
                if (body.isBlank()) {
                    "HTTP $statusCode while fetching subscription"
                } else {
                    "HTTP $statusCode while fetching subscription: ${body.lineSequence().first().trim()}"
                }
            }
            FetchedSubscriptionContent(
                body = body,
                contentType = connection.contentType,
                headers = connection.headerFields
                    .filterKeys { it != null }
                    .mapKeys { it.key.orEmpty() }
                    .mapValues { (_, values) -> values.joinToString(",") },
            )
        } finally {
            connection.disconnect()
        }
    }
}
