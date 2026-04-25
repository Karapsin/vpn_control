package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.data.BenchmarkSearchLogic
import com.kardinal.vpncontrol.data.BenchmarkUrls
import com.kardinal.vpncontrol.data.LocationConfigs
import com.kardinal.vpncontrol.data.PreflightResult
import com.kardinal.vpncontrol.data.ProxyRunResult
import com.kardinal.vpncontrol.data.SearchEvaluation
import com.kardinal.vpncontrol.model.ProfileBenchmark
import com.kardinal.vpncontrol.model.VlessProfile
import java.io.IOException
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.ServerSocket
import java.net.Socket
import java.net.URL
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.util.concurrent.TimeUnit
import kotlin.math.roundToInt
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext

data class DesktopValidationSettings(
    val preflightConcurrency: Int = 4,
    val preflightConnectTimeoutMillis: Int = 1_500,
    val proxyConnectTimeoutMillis: Int = 4_000,
    val proxyReadTimeoutMillis: Int = 5_000,
    val startupTimeoutMillis: Long = 4_000L,
)

class DesktopProxyValidationRuntime(
    private val baseDir: Path = Paths.get(
        System.getProperty("user.home"),
        ".vpn-control-desktop",
        "validation",
    ),
) {
    suspend fun benchmarkLocation(
        profile: VlessProfile,
        dnsSettings: DesktopDnsSettings,
        benchmarkUrls: BenchmarkUrls,
        settings: DesktopValidationSettings = DesktopValidationSettings(),
    ): Result<ProfileBenchmark> = withContext(Dispatchers.IO) {
        runCatching {
            val candidate = preflightProfile(profile, settings)
            if (candidate.connectMillis == null) {
                BenchmarkSearchLogic.failedBenchmark(profile, candidate, "tcp_unreachable")
            } else {
                benchmarkCandidate(candidate, dnsSettings, benchmarkUrls, settings)
            }
        }
    }

    suspend fun evaluateProfiles(
        profiles: List<VlessProfile>,
        dnsSettings: DesktopDnsSettings,
        benchmarkUrls: BenchmarkUrls,
        settings: DesktopValidationSettings = DesktopValidationSettings(),
    ): SearchEvaluation = withContext(Dispatchers.IO) {
        val preflightResults = preflightProfiles(profiles, settings)
        val benchmarks = mutableListOf<ProfileBenchmark>()
        preflightResults
            .filter { it.connectMillis != null }
            .sortedBy { it.connectMillis }
            .forEach { candidate ->
                benchmarks += benchmarkCandidate(candidate, dnsSettings, benchmarkUrls, settings)
            }
        val winner = benchmarks
            .filter { it.primaryStatus == "ok" && it.secondaryStatus == "ok" }
            .minByOrNull(ProfileBenchmark::score)
        BenchmarkSearchLogic.evaluateProfilesForSelection(
            profiles = profiles,
            preflightResults = preflightResults,
            candidateBenchmarks = benchmarks,
            winner = winner,
        )
    }

    private suspend fun preflightProfiles(
        profiles: List<VlessProfile>,
        settings: DesktopValidationSettings,
    ): List<PreflightResult> = coroutineScope {
        profiles.map { profile ->
            async { preflightProfile(profile, settings) }
        }.awaitAll()
    }

    private fun preflightProfile(
        profile: VlessProfile,
        settings: DesktopValidationSettings,
    ): PreflightResult {
        return try {
            val startedAt = System.nanoTime()
            Socket().use { socket ->
                socket.connect(
                    InetSocketAddress(profile.server, profile.serverPort),
                    settings.preflightConnectTimeoutMillis,
                )
            }
            val connectMillis = (System.nanoTime() - startedAt) / 1_000_000.0
            PreflightResult(
                profile = profile,
                connectMillis = connectMillis,
                detail = "${profile.remarks}: tcp=${BenchmarkSearchLogic.formatMillis(connectMillis)}",
            )
        } catch (_: IOException) {
            PreflightResult(
                profile = profile,
                connectMillis = null,
                detail = "${profile.remarks}: tcp_unreachable",
            )
        }
    }

    private suspend fun benchmarkCandidate(
        candidate: PreflightResult,
        dnsSettings: DesktopDnsSettings,
        benchmarkUrls: BenchmarkUrls,
        settings: DesktopValidationSettings,
    ): ProfileBenchmark {
        Files.createDirectories(baseDir)
        val port = allocateListenPort()
        val configJson = DesktopProxyConfigFactory.buildProxyOnlyConfig(
            profile = candidate.profile,
            dns = dnsSettings,
            routingRules = com.kardinal.vpncontrol.model.RoutingRules(ignoreRules = true),
            listenPort = port,
        )
        val safeName = candidate.profile.remarks
            .lowercase()
            .replace(Regex("[^a-z0-9]+"), "-")
            .trim('-')
            .ifBlank { "profile" }
        val configFile = Files.createTempFile(baseDir, "validate-$safeName-", ".json")
        val logFile = Files.createTempFile(baseDir, "validate-$safeName-", ".log")
        Files.writeString(configFile, configJson)
        Files.writeString(logFile, "")

        var process: Process? = null
        try {
            process = ProcessBuilder("sing-box", "run", "-c", configFile.toString())
                .directory(baseDir.toFile())
                .redirectErrorStream(true)
                .redirectOutput(logFile.toFile())
                .start()

            if (!waitForPort(process, port, settings.startupTimeoutMillis)) {
                return BenchmarkSearchLogic.failedBenchmark(
                    candidate.profile,
                    candidate,
                    "proxy_not_ready",
                )
            }

            val primary = runProxyRuns(port, benchmarkUrls.primary, settings)
            val secondary = runProxyRuns(port, benchmarkUrls.secondary, settings)
            return BenchmarkSearchLogic.buildValidatedBenchmark(candidate, primary, secondary)
        } catch (_: IOException) {
            return BenchmarkSearchLogic.failedBenchmark(candidate.profile, candidate, "sing_box_launch_failed")
        } finally {
            process?.destroy()
            if (process?.waitFor(2, TimeUnit.SECONDS) == false) {
                process?.destroyForcibly()
                process?.waitFor(2, TimeUnit.SECONDS)
            }
            runCatching { Files.deleteIfExists(configFile) }
            runCatching { Files.deleteIfExists(logFile) }
        }
    }

    private fun runProxyRuns(
        port: Int,
        url: String,
        settings: DesktopValidationSettings,
    ): ProxyRunResult {
        val result = try {
            executeProxyRequest(port, url, settings)
        } catch (_: Exception) {
            ProxyCallResult(code = "000", total = null)
        }
        return ProxyRunResult(
            codes = listOf(result.code),
            totals = listOfNotNull(result.total),
        )
    }

    private fun executeProxyRequest(
        port: Int,
        url: String,
        settings: DesktopValidationSettings,
    ): ProxyCallResult {
        val proxy = Proxy(Proxy.Type.HTTP, InetSocketAddress("127.0.0.1", port))
        val startedAt = System.nanoTime()
        val connection = (URL(url).openConnection(proxy) as HttpURLConnection).apply {
            requestMethod = "GET"
            instanceFollowRedirects = true
            connectTimeout = settings.proxyConnectTimeoutMillis
            readTimeout = settings.proxyReadTimeoutMillis
            setRequestProperty("User-Agent", "VPNControlDesktop/1.0")
            setRequestProperty("Accept", "*/*")
        }
        return try {
            val code = connection.responseCode
            runCatching { connection.inputStream?.use { it.readNBytes(512) } }
            val duration = (System.nanoTime() - startedAt) / 1_000_000.0
            ProxyCallResult(
                code = code.toString(),
                total = ((duration * 10.0).roundToInt() / 10.0),
            )
        } finally {
            connection.disconnect()
        }
    }

    private suspend fun waitForPort(process: Process, port: Int, timeoutMillis: Long): Boolean {
        val deadline = System.currentTimeMillis() + timeoutMillis
        while (System.currentTimeMillis() < deadline) {
            if (!process.isAlive) {
                return false
            }
            try {
                Socket().use { socket ->
                    socket.connect(InetSocketAddress("127.0.0.1", port), 250)
                }
                return true
            } catch (_: IOException) {
                delay(150)
            }
        }
        return false
    }

    private fun allocateListenPort(): Int {
        ServerSocket(0).use { socket ->
            return socket.localPort
        }
    }

    private data class ProxyCallResult(
        val code: String,
        val total: Double?,
    )
}
