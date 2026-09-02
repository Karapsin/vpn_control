package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.DnsSettings
import com.kardinal.vpncontrol.model.ProxyProfile
import com.kardinal.vpncontrol.model.ProxyProtocol
import com.kardinal.vpncontrol.model.RoutingRules
import java.net.HttpURLConnection
import java.net.URI
import java.nio.file.Files
import java.nio.file.Path
import kotlinx.coroutines.runBlocking

internal data class DesktopVpnIntegrationRequest(
    val socksPort: Int,
    val targetUrl: String,
    val expectedBody: String,
    val stateDir: Path,
)

/**
 * Destructive-to-network disposable-runner probe. It is deliberately unavailable unless the
 * caller opts in through [ALLOW_ENV], so package smoke tests and developer launches cannot alter
 * host routes accidentally.
 */
internal object DesktopVpnIntegrationTest {
    const val ARG = "--vpn-integration-test"
    const val ALLOW_ENV = "VPN_CONTROL_ALLOW_DISPOSABLE_INTEGRATION"

    fun handleArgs(
        args: Array<String>,
        getenv: (String) -> String? = System::getenv,
        execute: (DesktopVpnIntegrationRequest) -> Result<String> = ::execute,
        printLine: (String) -> Unit = ::println,
    ): Int? {
        if (!args.contains(ARG)) return null
        if (getenv(ALLOW_ENV) != "1") {
            printLine("VPN integration test refused: set $ALLOW_ENV=1 only on a disposable runner.")
            return 2
        }
        val request = parseRequest(args).getOrElse { error ->
            printLine("VPN integration test configuration failed: ${error.message}")
            return 2
        }
        return execute(request).fold(
            onSuccess = { message ->
                printLine(message)
                0
            },
            onFailure = { error ->
                printLine("VPN integration test failed: ${error.message ?: error::class.simpleName}")
                1
            },
        )
    }

    internal fun parseRequest(args: Array<String>): Result<DesktopVpnIntegrationRequest> = runCatching {
        fun required(name: String): String = args.valueFor(name)
            ?.takeIf(String::isNotBlank)
            ?: error("missing $name")

        val socksPort = required("--integration-socks-port").toIntOrNull()
            ?.takeIf { it in 1..65535 }
            ?: error("--integration-socks-port must be between 1 and 65535")
        val targetUrl = required("--integration-target-url")
        require(URI(targetUrl).scheme == "http") { "--integration-target-url must use http" }
        val expectedBody = required("--integration-expected-body")
        val stateDir = args.valueFor("--integration-state-dir")
            ?.takeIf(String::isNotBlank)
            ?.let(Path::of)
            ?: Files.createTempDirectory("vpn-control-full-vpn-integration")
        DesktopVpnIntegrationRequest(socksPort, targetUrl, expectedBody, stateDir)
    }

    fun execute(request: DesktopVpnIntegrationRequest): Result<String> = runCatching {
        Files.createDirectories(request.stateDir)
        val store = DesktopStateStore(request.stateDir)
        val manager = DesktopProxyRuntimeManager(
            runtimeConfigStore = store,
            baseDir = request.stateDir.resolve("runtime"),
            singBoxResolver = DesktopSingBoxResolver(request.stateDir.resolve("runtime/tools")),
        )
        var runtimeStarted = false
        try {
            runBlocking {
                manager.start(
                    profile = socksProfile(request.socksPort),
                    routingRules = RoutingRules(ignoreRules = true),
                    dnsSettings = DnsSettings(),
                    appMode = AppMode.VPN,
                    activeVerificationPort = null,
                ).getOrThrow()
            }
            runtimeStarted = true
            val connection = URI(request.targetUrl).toURL().openConnection() as HttpURLConnection
            connection.connectTimeout = 10_000
            connection.readTimeout = 10_000
            connection.instanceFollowRedirects = false
            val status = connection.responseCode
            val body = connection.inputStream.bufferedReader().use { it.readText() }
            check(status == 200) { "fixture returned HTTP $status" }
            check(body == request.expectedBody) {
                "traffic did not return the expected fixture token"
            }
        } finally {
            if (runtimeStarted || manager.isRunning()) {
                runBlocking { manager.stop().getOrThrow() }
            }
        }
        "full VPN integration test passed: TUN traffic reached the SOCKS fixture"
    }

    private fun socksProfile(port: Int): ProxyProfile = ProxyProfile(
        protocol = ProxyProtocol.SOCKS,
        remarks = "Disposable integration fixture",
        server = "127.0.0.1",
        serverPort = port,
        network = "tcp",
        flow = "",
        security = "",
        sni = "",
        fingerprint = "",
        publicKey = "",
        shortId = "",
        path = "",
        hostHeader = "",
        serviceName = "",
        headerType = "",
        rawLink = "socks://127.0.0.1:$port#DisposableIntegrationFixture",
    )

    private fun Array<String>.valueFor(name: String): String? {
        forEachIndexed { index, argument ->
            if (argument == name) return getOrNull(index + 1)
            if (argument.startsWith("$name=")) return argument.substringAfter('=')
        }
        return null
    }
}
