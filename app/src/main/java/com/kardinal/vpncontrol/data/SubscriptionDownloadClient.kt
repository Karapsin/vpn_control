package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.shared.storageapi.FetchedSubscriptionContent
import com.kardinal.vpncontrol.shared.storageapi.SubscriptionContentFetcher
import java.io.IOException
import java.util.concurrent.TimeUnit
import okhttp3.OkHttpClient
import okhttp3.Request

class SubscriptionDownloadClient(
    private val userAgent: String,
) : SubscriptionContentFetcher {
    override suspend fun fetch(url: String): FetchedSubscriptionContent {
        return fetch(url, timeoutSeconds = 20)
    }

    suspend fun fetch(url: String, timeoutSeconds: Int): FetchedSubscriptionContent {
        val request = Request.Builder()
            .url(url)
            .header("User-Agent", userAgent)
            .header("Accept", "text/plain, application/octet-stream, */*")
            .build()
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
                )
            }
    }
}
