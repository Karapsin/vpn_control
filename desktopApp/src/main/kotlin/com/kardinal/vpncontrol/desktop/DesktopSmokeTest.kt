package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.DnsSettings
import com.kardinal.vpncontrol.model.DnsMode
import com.kardinal.vpncontrol.data.ProxyParser
import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.PersistedState
import com.kardinal.vpncontrol.model.ProxyProtocol
import com.kardinal.vpncontrol.model.RoutingRules
import com.kardinal.vpncontrol.model.ProxyProfile
import java.nio.file.Files
import java.nio.file.Path
import kotlinx.coroutines.runBlocking

internal object DesktopSmokeTest {
    fun handleArgs(
        args: Array<String>,
        classLoader: ClassLoader = DesktopSmokeTest::class.java.classLoader,
        printLine: (String) -> Unit = ::println,
    ): Int? {
        if (!args.contains("--smoke-test")) {
            return null
        }
        val stateDir = stateDirFromArgs(args)
            ?: Files.createTempDirectory("vpn-control-desktop-smoke")
        return execute(stateDir, classLoader)
            .fold(
                onSuccess = { message ->
                    printLine(message)
                    0
                },
                onFailure = { error ->
                    printLine("desktop smoke test failed: ${error.message ?: error::class.simpleName}")
                    1
                },
            )
    }

    fun execute(
        stateDir: Path,
        classLoader: ClassLoader = DesktopSmokeTest::class.java.classLoader,
    ): Result<String> = runCatching {
        Files.createDirectories(stateDir)

        val store = DesktopStateStore(stateDir)
        val workspace = DesktopWorkspace(
            persistedState = PersistedState(statusMessage = "Desktop smoke test"),
            locations = emptyList(),
        )
        store.writeWorkspace(workspace)
        val loaded = store.loadWorkspace(workspace)
        check(loaded.persistedState.statusMessage == "Desktop smoke test") {
            "workspace persistence failed"
        }

        val singBox = DesktopSingBoxResolver(
            toolsDir = stateDir.resolve("runtime").resolve("tools"),
            classLoader = classLoader,
        ).resolve() ?: error("bundled sing-box was not resolved")

        val profile = smokeProfile()
        val proxyConfig = DesktopProxyConfigFactory.buildProxyOnlyConfig(
            profile = profile,
            dns = DnsSettings(mode = DnsMode.CUSTOM_DOH, endpoint = "https://1.1.1.1/dns-query"),
            routingRules = RoutingRules(),
            listenPort = 2080,
        )
        check(proxyConfig.contains("\"mixed\"")) { "proxy config was not generated" }

        val vpnConfig = DesktopProxyConfigFactory.buildVpnConfig(
            profile = profile,
            dns = DnsSettings(mode = DnsMode.CUSTOM_DOH, endpoint = "https://1.1.1.1/dns-query"),
            routingRules = RoutingRules(),
            interfaceName = DesktopProxyConfigFactory.DEFAULT_VPN_INTERFACE_NAME,
        )
        check(vpnConfig.contains("\"tun\"")) { "VPN config was not generated" }

        val parsedSubscription = ProxyParser.parseSubscription(smokeSubscription())
        check(parsedSubscription.size == 2) { "subscription parser smoke failed" }

        if (!isPlaceholderTestBinary(singBox.path)) {
            val runtimeManager = DesktopProxyRuntimeManager(
                runtimeConfigStore = store,
                baseDir = stateDir.resolve("runtime").resolve("session"),
                singBoxResolver = DesktopSingBoxResolver(
                    toolsDir = stateDir.resolve("runtime").resolve("tools"),
                    classLoader = classLoader,
                ),
            )
            runBlocking {
                val session = runtimeManager.start(
                    profile = profile,
                    routingRules = RoutingRules(ignoreRules = true),
                    dnsSettings = DnsSettings(
                        mode = DnsMode.CUSTOM_DOH,
                        endpoint = "https://1.1.1.1/dns-query",
                    ),
                    appMode = AppMode.PROXY_ONLY,
                    activeVerificationPort = null,
                ).getOrThrow()
                check(session.listenPort != null) { "proxy smoke did not allocate a listen port" }
                runtimeManager.stop().getOrThrow()
            }
        }

        "desktop smoke test passed: ${singBox.source}; parser/runtime ok"
    }

    private fun stateDirFromArgs(args: Array<String>): Path? {
        args.forEachIndexed { index, value ->
            if (value == "--smoke-test-state-dir") {
                return args.getOrNull(index + 1)?.takeIf(String::isNotBlank)?.let(Path::of)
            }
            if (value.startsWith("--smoke-test-state-dir=")) {
                return value.substringAfter('=').takeIf(String::isNotBlank)?.let(Path::of)
            }
        }
        return null
    }

    private fun smokeProfile(): ProxyProfile = ProxyProfile(
        protocol = ProxyProtocol.VLESS,
        remarks = "Smoke",
        server = "example.com",
        serverPort = 443,
        uuid = "00000000-0000-4000-8000-000000000000",
        network = "tcp",
        flow = "",
        security = "tls",
        sni = "example.com",
        fingerprint = "chrome",
        publicKey = "",
        shortId = "",
        path = "",
        hostHeader = "",
        serviceName = "",
        headerType = "",
        rawLink = "vless://00000000-0000-4000-8000-000000000000@example.com:443?security=tls#Smoke",
    )

    private fun smokeSubscription(): String = """
        vless://00000000-0000-4000-8000-000000000000@example.com:443?security=tls#Smoke
        trojan://secret@example.com:443?security=tls#TrojanSmoke
    """.trimIndent()

    private fun isPlaceholderTestBinary(path: Path): Boolean {
        return runCatching {
            Files.size(path) < 1024L && Files.readString(path).contains("test sing-box binary placeholder")
        }.getOrDefault(false)
    }
}
