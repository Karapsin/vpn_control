package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.shared.storageapi.FetchedSubscriptionContent
import com.kardinal.vpncontrol.shared.storageapi.SubscriptionContentFetcher
import com.kardinal.vpncontrol.shared.storageapi.SubscriptionRequestHeaders
import java.io.IOException
import java.util.concurrent.TimeUnit
import okhttp3.OkHttpClient
import okhttp3.Request

class SubscriptionDownloadClient(
    private val userAgent: String,
) : SubscriptionContentFetcher {
    override suspend fun fetch(url: String, subscriptionHwid: String): FetchedSubscriptionContent {
        return fetch(url, timeoutSeconds = 20, subscriptionHwid = subscriptionHwid)
    }

    suspend fun fetch(
        url: String,
        timeoutSeconds: Int,
        subscriptionHwid: String = "",
    ): FetchedSubscriptionContent {
        val requestBuilder = Request.Builder().url(url)
        SubscriptionRequestHeaders.build(
            userAgent = userAgent,
            accept = "text/plain, application/octet-stream, */*",
            subscriptionHwid = subscriptionHwid,
        ).forEach { (name, value) ->
            requestBuilder.header(name, value)
        }
        val request = requestBuilder.build()
        OkHttpClient.Builder()
            .callTimeout(timeoutSeconds.toLong(), TimeUnit.SECONDS)
            .build()
            .newCall(request)
            .execute()
            .use { response ->
                if (!response.isSuccessful) {
                    throw IOException("Subscription fetch failed: HTTP ${response.code}")
                }
                return FetchedSubscriptionContent(
                    body = response.body?.string().orEmpty(),
                    contentType = response.header("Content-Type"),
                    headers = response.headers.names().associateWith { name ->
                        response.header(name).orEmpty()
                    },
                )
            }
    }
}
