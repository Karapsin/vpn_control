package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.SubscriptionDownloadRoute
import com.kardinal.vpncontrol.SubscriptionDownloadRouteLogic
import com.kardinal.vpncontrol.data.HomeSshRouteConfigBuilder
import com.kardinal.vpncontrol.data.HomeSshRouteRuntimeOptions
import com.kardinal.vpncontrol.model.PersistedState
import com.kardinal.vpncontrol.shared.storageapi.FetchedSubscriptionContent
import com.kardinal.vpncontrol.shared.storageapi.SubscriptionContentFetcher
import com.kardinal.vpncontrol.shared.storageapi.SubscriptionRequestHeaders
import java.io.IOException
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.ServerSocket
import java.net.Socket
import java.net.URL
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.delay
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

class DesktopSubscriptionDownloadClient(
    private val stateProvider: (suspend () -> PersistedState)? = null,
    private val runtimeIsActive: () -> Boolean = { false },
    private val runtimeProxyPort: () -> Int? = { null },
    private val credentialStore: DesktopHomeSshCredentialStore? = null,
    private val bootstrapBaseDir: Path? = null,
    private val singBoxResolver: DesktopSingBoxResolver? = null,
) : SubscriptionContentFetcher {
    override suspend fun fetch(
        url: String,
        subscriptionHwid: String,
    ): FetchedSubscriptionContent = withContext(Dispatchers.IO) {
        val state = stateProvider?.invoke()
        val activePort = runtimeProxyPort()
        val plan = SubscriptionDownloadRouteLogic.plan(
            runtimeIsActive = runtimeIsActive(),
            homeRouteEnabled = state?.homeSshRouteSettings?.enabled == true,
        )
        try {
            fetchUsingRoute(url, subscriptionHwid, plan.primary, state, activePort)
        } catch (error: java.io.IOException) {
            val fallback = plan.transportFailureFallback ?: throw error
            fetchUsingRoute(url, subscriptionHwid, fallback, state, activePort)
        }
    }

    private suspend fun fetchUsingRoute(
        url: String,
        subscriptionHwid: String,
        route: SubscriptionDownloadRoute,
        state: PersistedState?,
        activePort: Int?,
    ): FetchedSubscriptionContent {
        return when (route) {
            SubscriptionDownloadRoute.DIRECT -> execute(url, subscriptionHwid, proxyPort = null)
            SubscriptionDownloadRoute.ACTIVE_SESSION -> execute(
                url,
                subscriptionHwid,
                proxyPort = activePort?.takeIf { it in 1..65535 }
                    ?: throw IOException("Active VPN management proxy is unavailable"),
            )
            SubscriptionDownloadRoute.HOME_RELAY -> {
                val settings = state?.homeSshRouteSettings ?: error("SSH Routing is not configured")
                val keyPath = credentialStore?.privateKeyPathOrNull()
                    ?: error("SSH Routing private key is missing")
                val baseDir = bootstrapBaseDir ?: error("SSH Routing bootstrap runtime is unavailable")
                val resolver = singBoxResolver ?: error("SSH Routing bootstrap runtime is unavailable")
                DesktopHomeSshBootstrapProxy(baseDir, resolver).useProxy(
                    HomeSshRouteRuntimeOptions(settings, keyPath),
                ) { port -> execute(url, subscriptionHwid, proxyPort = port) }
            }
        }
    }

    private fun execute(
        url: String,
        subscriptionHwid: String,
        proxyPort: Int?,
    ): FetchedSubscriptionContent {
        val connection = (if (proxyPort == null) {
            URL(url).openConnection()
        } else {
            URL(url).openConnection(Proxy(Proxy.Type.HTTP, InetSocketAddress("127.0.0.1", proxyPort)))
        } as HttpURLConnection).apply {
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
        return try {
            val statusCode = connection.responseCode
            val stream = if (statusCode in 200..299) {
                connection.inputStream
            } else {
                connection.errorStream
            }
            val body = stream?.bufferedReader()?.use { it.readText() }.orEmpty()
            if (statusCode !in 200..299) {
                val detail = if (body.isBlank()) {
                    "HTTP $statusCode while fetching subscription"
                } else {
                    "HTTP $statusCode while fetching subscription: ${body.lineSequence().first().trim()}"
                }
                throw IOException(detail)
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

private class DesktopHomeSshBootstrapProxy(
    private val baseDir: Path,
    private val singBoxResolver: DesktopSingBoxResolver,
) {
    suspend fun <T> useProxy(
        options: HomeSshRouteRuntimeOptions,
        block: (Int) -> T,
    ): T {
        Files.createDirectories(baseDir)
        val port = ServerSocket(0).use { it.localPort }
        val config = Files.createTempFile(baseDir, "home-ssh-bootstrap-", ".json")
        val log = Files.createTempFile(baseDir, "home-ssh-bootstrap-", ".log")
        val binary = singBoxResolver.resolve() ?: error(singBoxResolver.missingMessage())
        var process: Process? = null
        try {
            Files.writeString(config, HomeSshRouteConfigBuilder.buildBootstrapProxyConfig(options, port).toString())
            process = ProcessBuilder(binary.path.toString(), "run", "-c", config.toString())
                .directory(baseDir.toFile())
                .redirectErrorStream(true)
                .redirectOutput(log.toFile())
                .start()
            require(waitForPort(process, port)) { "SSH relay did not become ready" }
            return block(port)
        } finally {
            process?.destroy()
            if (process?.waitFor(2, TimeUnit.SECONDS) == false) process?.destroyForcibly()
            runCatching { Files.deleteIfExists(config) }
            runCatching { Files.deleteIfExists(log) }
        }
    }

    private suspend fun waitForPort(process: Process?, port: Int): Boolean {
        repeat(30) {
            if (process?.isAlive != true) return false
            try {
                Socket().use { it.connect(InetSocketAddress("127.0.0.1", port), 300) }
                return true
            } catch (_: java.io.IOException) {
                delay(100)
            }
        }
        return false
    }
}
