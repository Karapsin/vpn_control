package com.kardinal.vpncontrol.data

import android.content.Context
import com.kardinal.vpncontrol.SubscriptionDownloadRoute
import com.kardinal.vpncontrol.SubscriptionDownloadRouteLogic
import com.kardinal.vpncontrol.model.PersistedState
import com.kardinal.vpncontrol.shared.storageapi.FetchedSubscriptionContent
import com.kardinal.vpncontrol.shared.storageapi.SubscriptionContentFetcher
import com.kardinal.vpncontrol.shared.storageapi.SubscriptionRequestHeaders
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.Socket
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request

class SubscriptionDownloadClient(
    private val userAgent: String,
    private val context: Context? = null,
    private val stateProvider: (suspend () -> PersistedState)? = null,
) : SubscriptionContentFetcher {
    override suspend fun fetch(url: String, subscriptionHwid: String): FetchedSubscriptionContent {
        return fetch(url, timeoutSeconds = 20, subscriptionHwid = subscriptionHwid)
    }

    suspend fun fetch(
        url: String,
        timeoutSeconds: Int,
        subscriptionHwid: String = "",
    ): FetchedSubscriptionContent {
        val state = stateProvider?.invoke()
        val routePlan = SubscriptionDownloadRouteLogic.plan(
            runtimeIsActive = state?.isVpnRunning == true,
            homeRouteEnabled = state?.homeSshRouteSettings?.enabled == true,
        )
        return try {
            fetchUsingRoute(url, timeoutSeconds, subscriptionHwid, routePlan.primary, state)
        } catch (error: IOException) {
            val fallback = routePlan.transportFailureFallback ?: throw error
            fetchUsingRoute(url, timeoutSeconds, subscriptionHwid, fallback, state)
        }
    }

    private suspend fun fetchUsingRoute(
        url: String,
        timeoutSeconds: Int,
        subscriptionHwid: String,
        route: SubscriptionDownloadRoute,
        state: PersistedState?,
    ): FetchedSubscriptionContent {
        return when (route) {
            SubscriptionDownloadRoute.DIRECT -> execute(url, timeoutSeconds, subscriptionHwid, proxyPort = null)
            SubscriptionDownloadRoute.ACTIVE_SESSION -> execute(
                url,
                timeoutSeconds,
                subscriptionHwid,
                proxyPort = state?.managementProxyPort?.takeIf { it in 1..65535 }
                    ?: throw IOException("Active VPN management proxy is unavailable"),
            )
            SubscriptionDownloadRoute.HOME_RELAY -> {
                val appContext = context ?: error("Home SSH routing is unavailable")
                val settings = state?.homeSshRouteSettings ?: error("Home SSH routing is not configured")
                val keyPath = AndroidHomeSshCredentialStore(appContext).privateKeyPathOrNull()
                    ?: error("Home SSH private key is missing")
                AndroidHomeSshBootstrapProxy(appContext).useProxy(
                    HomeSshRouteRuntimeOptions(settings, keyPath),
                ) { port ->
                    execute(url, timeoutSeconds, subscriptionHwid, proxyPort = port)
                }
            }
        }
    }

    private fun execute(
        url: String,
        timeoutSeconds: Int,
        subscriptionHwid: String,
        proxyPort: Int?,
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
        val clientBuilder = OkHttpClient.Builder()
            .callTimeout(timeoutSeconds.toLong(), TimeUnit.SECONDS)
        if (proxyPort != null) {
            clientBuilder.proxy(Proxy(Proxy.Type.HTTP, InetSocketAddress("127.0.0.1", proxyPort)))
        }
        clientBuilder
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

private class AndroidHomeSshBootstrapProxy(
    private val context: Context,
) {
    suspend fun <T> useProxy(
        options: HomeSshRouteRuntimeOptions,
        block: (Int) -> T,
    ): T = withContext(Dispatchers.IO) {
        val port = java.net.ServerSocket(0).use { it.localPort }
        val configFile = java.io.File.createTempFile("home-ssh-bootstrap-", ".json", context.cacheDir)
        val binary = SingBoxInstaller.resolveBinary(context)
        var process: Process? = null
        try {
            configFile.writeText(HomeSshRouteConfigBuilder.buildBootstrapProxyConfig(options, port).toString())
            process = ProcessBuilder(binary.absolutePath, "run", "-c", configFile.absolutePath)
                .redirectOutput(java.io.File("/dev/null"))
                .redirectError(java.io.File("/dev/null"))
                .start()
            require(waitForPort(port)) { "Home SSH relay did not become ready" }
            block(port)
        } finally {
            process?.destroy()
            if (process?.waitFor(2, TimeUnit.SECONDS) == false) {
                process?.destroyForcibly()
            }
            configFile.delete()
        }
    }

    private suspend fun waitForPort(port: Int): Boolean {
        repeat(20) {
            try {
                Socket().use { socket ->
                    socket.connect(InetSocketAddress("127.0.0.1", port), 300)
                }
                return true
            } catch (_: IOException) {
                delay(100)
            }
        }
        return false
    }
}
