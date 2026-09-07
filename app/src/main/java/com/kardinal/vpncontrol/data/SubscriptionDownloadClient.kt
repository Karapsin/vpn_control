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
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlinx.coroutines.suspendCancellableCoroutine

class SubscriptionDownloadClient(
    private val userAgent: String,
    private val context: Context? = null,
    private val stateProvider: (suspend () -> PersistedState)? = null,
    private val callFactory: (OkHttpClient, Request) -> okhttp3.Call = { client, request -> client.newCall(request) },
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
                val appContext = context ?: error("SSH Routing is unavailable")
                val settings = state?.homeSshRouteSettings ?: error("SSH Routing is not configured")
                val keyPath = AndroidHomeSshCredentialStore(appContext).privateKeyPathOrNull(settings.credentialVersion)
                    ?: error("SSH Routing private key is missing")
                AndroidHomeSshBootstrapProxy(appContext).useProxy(
                    HomeSshRouteRuntimeOptions(settings, keyPath),
                ) { port ->
                    execute(url, timeoutSeconds, subscriptionHwid, proxyPort = port)
                }
            }
        }
    }

    private suspend fun execute(
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
        return suspendCancellableCoroutine { continuation ->
            val call = callFactory(clientBuilder.build(), request)
            continuation.invokeOnCancellation { call.cancel() }
            call.enqueue(object : okhttp3.Callback {
                override fun onFailure(call: okhttp3.Call, error: IOException) {
                    if (continuation.isActive) continuation.resumeWithException(error)
                }
                override fun onResponse(call: okhttp3.Call, response: okhttp3.Response) {
                    val result = runCatching { response.use {
                        if (!it.isSuccessful) throw IOException("Subscription fetch failed: HTTP ${it.code}")
                        FetchedSubscriptionContent(it.body?.string().orEmpty(), it.header("Content-Type"),
                            it.headers.names().associateWith { name -> it.header(name).orEmpty() })
                    } }
                    if (continuation.isActive) result.fold(continuation::resume, continuation::resumeWithException)
                }
            })
        }
    }
}

private class AndroidHomeSshBootstrapProxy(
    private val context: Context,
) {
    suspend fun <T> useProxy(
        options: HomeSshRouteRuntimeOptions,
        block: suspend (Int) -> T,
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
            require(waitForPort(port)) { "SSH relay did not become ready" }
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
