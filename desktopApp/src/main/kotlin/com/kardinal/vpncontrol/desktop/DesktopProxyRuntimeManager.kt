package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.RuntimeStatusMessages
import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.RoutingRules
import com.kardinal.vpncontrol.model.ProxyProfile
import com.kardinal.vpncontrol.shared.storageapi.RuntimeConfigStore
import java.io.IOException
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext

data class DesktopRuntimeSession(
    val appMode: AppMode,
    val listenPort: Int?,
    val interfaceName: String?,
    val configJson: String,
    val logFile: Path,
    val processId: Long,
)

class DesktopProxyRuntimeManager(
    private val runtimeConfigStore: RuntimeConfigStore,
    private val baseDir: Path = Paths.get(
        System.getProperty("user.home"),
        ".vpn-control-desktop",
        "runtime",
    ),
    private val singBoxResolver: DesktopSingBoxResolver = DesktopSingBoxResolver(baseDir.resolve("tools")),
    private val directProbeRouting: DesktopDirectProbeRouting = DesktopDirectProbeRouting(),
    private val runtimeOsNameOverride: String? = null,
    private val windowsAdministratorOverride: Boolean? = null,
) : DesktopRuntimeController {
    @Volatile
    private var process: Process? = null

    @Volatile
    private var listenPort: Int? = null

    @Volatile
    private var logFile: Path? = null

    @Volatile
    private var activeMode: AppMode? = null

    @Volatile
    private var lastPreflightReport: DesktopPreflightReport? = null

    @Volatile
    private var lastAttemptedConfigJson: String? = null

    override suspend fun start(
        profile: ProxyProfile,
        routingRules: RoutingRules,
        dnsSettings: DesktopDnsSettings,
        appMode: AppMode,
    ): Result<DesktopRuntimeSession> = withContext(Dispatchers.IO) {
        runCatching {
            stopActiveProcess()
            runtimeConfigStore.clearRuntimeConfig()

            Files.createDirectories(baseDir)
            val port = if (appMode == AppMode.PROXY_ONLY) allocateListenPort() else null
            val interfaceName = if (appMode == AppMode.VPN) {
                DesktopProxyConfigFactory.DEFAULT_VPN_INTERFACE_NAME
            } else {
                null
            }
            val configJson = when (appMode) {
                AppMode.PROXY_ONLY -> DesktopProxyConfigFactory.buildProxyOnlyConfig(
                    profile = profile,
                    dns = dnsSettings,
                    routingRules = routingRules,
                    listenPort = checkNotNull(port),
                )
                AppMode.VPN ->
                    DesktopProxyConfigFactory.buildVpnConfig(
                        profile = profile,
                        dns = dnsSettings,
                        routingRules = routingRules,
                        interfaceName = checkNotNull(interfaceName),
                        directProbeRouting = directProbeRouting,
                    )
            }
            val configPath = baseDir.resolve("runtime-sing-box-${appMode.name.lowercase()}.json")
            val runtimeLogFile = baseDir.resolve("runtime-sing-box.log")
            Files.writeString(configPath, configJson)
            lastAttemptedConfigJson = configJson

            val preflight = runPreflight(
                appMode = appMode,
                configPath = configPath,
                listenPort = port,
            )
            lastPreflightReport = preflight
            if (!preflight.isReady) {
                runtimeConfigStore.clearRuntimeConfig()
                error(preflight.failureMessage())
            }
            val singBox = singBoxResolver.resolve() ?: error(singBoxResolver.missingMessage())

            val started = try {
                Files.writeString(runtimeLogFile, "")
                runtimeConfigStore.writeRuntimeConfig(configJson)
                ProcessBuilder(singBox.path.toString(), "run", "-c", configPath.toString())
                    .directory(baseDir.toFile())
                    .redirectErrorStream(true)
                    .redirectOutput(runtimeLogFile.toFile())
                    .start()
            } catch (error: IOException) {
                runtimeConfigStore.clearRuntimeConfig()
                throw IllegalStateException(
                    "Failed to launch sing-box at ${singBox.path}. ${singBoxResolver.missingMessage()}",
                    error,
                )
            }

            process = started
            listenPort = port
            logFile = runtimeLogFile
            activeMode = appMode

            val startedSuccessfully = when (appMode) {
                AppMode.PROXY_ONLY -> waitForPort(checkNotNull(port))
                AppMode.VPN -> waitForVpnProcess()
            }
            if (!startedSuccessfully) {
                val failureMessage = buildStartupFailureMessage(runtimeLogFile)
                stopActiveProcess()
                runtimeConfigStore.clearRuntimeConfig()
                error(failureMessage)
            }

            DesktopRuntimeSession(
                appMode = appMode,
                listenPort = port,
                interfaceName = interfaceName,
                configJson = configJson,
                logFile = runtimeLogFile,
                processId = started.pid(),
            )
        }
    }

    override suspend fun stop(): Result<Unit> = withContext(Dispatchers.IO) {
        runCatching {
            stopActiveProcess()
            runtimeConfigStore.clearRuntimeConfig()
        }
    }

    fun stopBlocking(): Result<Unit> = runCatching {
        stopActiveProcess()
        runBlocking {
            runtimeConfigStore.clearRuntimeConfig()
        }
    }

    override fun isRunning(): Boolean = process?.isAlive == true

    fun currentPort(): Int? = if (isRunning()) listenPort else null

    override fun currentMode(): AppMode? = if (isRunning()) activeMode else null

    fun currentProcessId(): Long? = process?.takeIf { it.isAlive }?.pid()

    fun currentLogFile(): Path? = logFile

    fun defaultLogFile(): Path = baseDir.resolve("runtime-sing-box.log")

    fun lastPreflightReport(): DesktopPreflightReport? = lastPreflightReport

    fun lastAttemptedConfigJson(): String? = lastAttemptedConfigJson

    fun desktopVpnCapabilityStatus(): String {
        return runCatching {
            ensureDesktopVpnSupported()
            RuntimeStatusMessages.desktopVpnCapabilityReady()
        }.getOrElse { error ->
            RuntimeStatusMessages.desktopVpnCapabilityError(error.message ?: "not ready")
        }
    }

    private fun allocateListenPort(): Int {
        ServerSocket(0).use { socket ->
            return socket.localPort
        }
    }

    private suspend fun waitForPort(port: Int): Boolean {
        repeat(20) {
            if (process?.isAlive != true) {
                return false
            }
            try {
                Socket().use { socket ->
                    socket.connect(InetSocketAddress("127.0.0.1", port), 300)
                }
                return true
            } catch (_: IOException) {
                delay(200)
            }
        }
        return false
    }

    private fun runPreflight(
        appMode: AppMode,
        configPath: Path,
        listenPort: Int?,
    ): DesktopPreflightReport {
        val checks = buildList {
            val binary = singBoxResolver.resolve()
            add(
                if (binary == null) {
                    DesktopPreflightCheck(
                        name = "sing-box binary",
                        status = DesktopPreflightStatus.FAIL,
                        detail = singBoxResolver.missingMessage(),
                    )
                } else {
                    val version = runCommand(listOf(binary.path.toString(), "version"), timeoutSeconds = 3)
                    DesktopPreflightCheck(
                        name = "sing-box binary",
                        status = if (version.exitCode == 0) DesktopPreflightStatus.PASS else DesktopPreflightStatus.FAIL,
                        detail = if (version.exitCode == 0) {
                            val versionLine = version.output.lineSequence().firstOrNull { it.isNotBlank() }
                                ?: binary.path.toString()
                            "$versionLine (${binary.source})"
                        } else {
                            version.output.ifBlank { "sing-box version command failed" }
                        },
                    )
                },
            )

            add(runtimeDirectoryCheck())

            if (appMode == AppMode.VPN) {
                val os = currentRuntimeOs()
                add(vpnOperatingSystemCheck(os))
                add(vpnTunBackendCheck(os))
                add(vpnPrivilegesCheck(os))
                add(vpnRouteDnsToolingCheck(os))
                add(
                    DesktopPreflightCheck(
                        name = "local ports",
                        status = DesktopPreflightStatus.SKIP,
                        detail = "VPN mode does not open a local proxy port",
                    ),
                )
            } else {
                val port = checkNotNull(listenPort)
                add(
                    if (isPortAvailable(port)) {
                        DesktopPreflightCheck("local proxy port", DesktopPreflightStatus.PASS, "127.0.0.1:$port is available")
                    } else {
                        DesktopPreflightCheck(
                            name = "local proxy port",
                            status = DesktopPreflightStatus.FAIL,
                            detail = "Port $port is already in use. Stop the other process or retry.",
                        )
                    },
                )
            }

            if (binary != null) {
                val validation = runCommand(
                    command = listOf(binary.path.toString(), "check", "-c", configPath.toString()),
                    timeoutSeconds = 5,
                )
                add(
                    DesktopPreflightCheck(
                        name = "config validation",
                        status = if (validation.exitCode == 0) DesktopPreflightStatus.PASS else DesktopPreflightStatus.FAIL,
                        detail = if (validation.exitCode == 0) {
                            "sing-box check passed for $configPath"
                        } else {
                            validation.output.ifBlank { "sing-box config validation failed" }
                        },
                    ),
                )
            } else {
                add(
                    DesktopPreflightCheck(
                        name = "config validation",
                        status = DesktopPreflightStatus.SKIP,
                        detail = "Skipped because sing-box is missing",
                    ),
                )
            }
        }
        return DesktopPreflightReport(appMode = appMode, checks = checks)
    }

    private fun runtimeDirectoryCheck(): DesktopPreflightCheck {
        return runCatching {
            Files.createDirectories(baseDir)
            val probe = Files.createTempFile(baseDir, "preflight-", ".tmp")
            Files.writeString(probe, "ok")
            Files.deleteIfExists(probe)
            DesktopPreflightCheck(
                name = "runtime directory",
                status = DesktopPreflightStatus.PASS,
                detail = "$baseDir is writable",
            )
        }.getOrElse { error ->
            DesktopPreflightCheck(
                name = "runtime directory",
                status = DesktopPreflightStatus.FAIL,
                detail = error.message ?: "$baseDir is not writable",
            )
        }
    }

    private fun isPortAvailable(port: Int): Boolean {
        return runCatching {
            ServerSocket().use { socket ->
                socket.reuseAddress = false
                socket.bind(InetSocketAddress("127.0.0.1", port))
            }
            true
        }.getOrDefault(false)
    }

    private data class CommandResult(
        val exitCode: Int,
        val output: String,
    )

    private fun runCommand(
        command: List<String>,
        timeoutSeconds: Long,
    ): CommandResult {
        return runCatching {
            val process = ProcessBuilder(command)
                .directory(baseDir.toFile())
                .redirectErrorStream(true)
                .start()
            val finished = process.waitFor(timeoutSeconds, TimeUnit.SECONDS)
            if (!finished) {
                process.destroyForcibly()
                process.waitFor(1, TimeUnit.SECONDS)
                return@runCatching CommandResult(
                    exitCode = -1,
                    output = "${command.joinToString(" ")} timed out after ${timeoutSeconds}s",
                )
            }
            val output = process.inputStream.bufferedReader().use { it.readText() }
                .trim()
                .take(2_000)
            CommandResult(process.exitValue(), output)
        }.getOrElse { error ->
            CommandResult(-1, error.message ?: "${command.joinToString(" ")} failed")
        }
    }

    private suspend fun waitForVpnProcess(): Boolean {
        repeat(10) {
            if (process?.isAlive != true) {
                return false
            }
            delay(200)
        }
        return process?.isAlive == true
    }

    private fun ensureDesktopVpnSupported() {
        val os = currentRuntimeOs()
        val checks = listOf(
            vpnOperatingSystemCheck(os),
            vpnTunBackendCheck(os),
            vpnPrivilegesCheck(os),
        )
        val failed = checks.firstOrNull { it.status == DesktopPreflightStatus.FAIL }
        if (failed != null) {
            error(failed.detail)
        }
    }

    private fun hasNetworkPrivileges(): Boolean {
        if (System.getProperty("user.name") == "root") {
            return true
        }
        val binary = singBoxResolver.resolve()?.path ?: return false
        val output = runCatching {
            val process = ProcessBuilder("getcap", binary.toString())
                .redirectErrorStream(true)
                .start()
            val text = process.inputStream.bufferedReader().use { it.readText() }
            process.waitFor(1, TimeUnit.SECONDS)
            text
        }.getOrDefault("")
        return output.contains("cap_net_admin")
    }

    private fun hasWindowsAdministratorPrivileges(): Boolean {
        windowsAdministratorOverride?.let { return it }
        val principalCheck = runCommand(
            command = listOf(
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)",
            ),
            timeoutSeconds = 3,
        )
        if (principalCheck.exitCode == 0 && principalCheck.output.trim().equals("true", ignoreCase = true)) {
            return true
        }
        val netSessionCheck = runCommand(
            command = listOf("cmd.exe", "/c", "net session >nul 2>nul"),
            timeoutSeconds = 3,
        )
        return netSessionCheck.exitCode == 0
    }

    private fun vpnOperatingSystemCheck(os: DesktopRuntimeOs): DesktopPreflightCheck {
        return when (os) {
            DesktopRuntimeOs.LINUX ->
                DesktopPreflightCheck("operating system", DesktopPreflightStatus.PASS, "Linux detected")
            DesktopRuntimeOs.WINDOWS ->
                DesktopPreflightCheck("operating system", DesktopPreflightStatus.PASS, "Windows detected")
            DesktopRuntimeOs.MACOS ->
                DesktopPreflightCheck(
                    name = "operating system",
                    status = DesktopPreflightStatus.FAIL,
                    detail = "macOS VPN mode needs a privileged Network Extension helper and is not implemented yet. Use Proxy-only mode on macOS.",
                )
            DesktopRuntimeOs.OTHER ->
                DesktopPreflightCheck(
                    name = "operating system",
                    status = DesktopPreflightStatus.FAIL,
                    detail = "Desktop VPN mode is currently implemented for Linux and Windows.",
                )
        }
    }

    private fun vpnTunBackendCheck(os: DesktopRuntimeOs): DesktopPreflightCheck {
        return when (os) {
            DesktopRuntimeOs.LINUX -> {
                if (Files.exists(Path.of("/dev/net/tun"))) {
                    DesktopPreflightCheck("TUN device", DesktopPreflightStatus.PASS, "/dev/net/tun exists")
                } else {
                    DesktopPreflightCheck(
                        name = "TUN device",
                        status = DesktopPreflightStatus.FAIL,
                        detail = "Linux TUN device is missing at /dev/net/tun. Try: sudo modprobe tun",
                    )
                }
            }
            DesktopRuntimeOs.WINDOWS ->
                DesktopPreflightCheck(
                    name = "TUN device",
                    status = DesktopPreflightStatus.PASS,
                    detail = "Windows Wintun backend is created by sing-box when running as Administrator",
                )
            DesktopRuntimeOs.MACOS ->
                DesktopPreflightCheck(
                    name = "TUN device",
                    status = DesktopPreflightStatus.SKIP,
                    detail = "macOS TUN setup is skipped until a privileged helper is implemented",
                )
            DesktopRuntimeOs.OTHER ->
                DesktopPreflightCheck(
                    name = "TUN device",
                    status = DesktopPreflightStatus.SKIP,
                    detail = "No desktop TUN backend check for this operating system",
                )
        }
    }

    private fun vpnPrivilegesCheck(os: DesktopRuntimeOs): DesktopPreflightCheck {
        return when (os) {
            DesktopRuntimeOs.LINUX -> {
                if (hasNetworkPrivileges()) {
                    DesktopPreflightCheck("network privileges", DesktopPreflightStatus.PASS, "CAP_NET_ADMIN available")
                } else {
                    DesktopPreflightCheck(
                        name = "network privileges",
                        status = DesktopPreflightStatus.FAIL,
                        detail = "Desktop VPN mode needs CAP_NET_ADMIN. Run as root or grant sing-box capabilities: sudo setcap cap_net_admin,cap_net_raw+ep \$(command -v sing-box)",
                    )
                }
            }
            DesktopRuntimeOs.WINDOWS -> {
                if (hasWindowsAdministratorPrivileges()) {
                    DesktopPreflightCheck("network privileges", DesktopPreflightStatus.PASS, "Windows Administrator token available")
                } else {
                    DesktopPreflightCheck(
                        name = "network privileges",
                        status = DesktopPreflightStatus.FAIL,
                        detail = "Windows VPN mode needs Administrator privileges. Relaunch VPN Control and accept the UAC prompt.",
                    )
                }
            }
            DesktopRuntimeOs.MACOS ->
                DesktopPreflightCheck(
                    name = "network privileges",
                    status = DesktopPreflightStatus.SKIP,
                    detail = "macOS privilege checks are skipped until a privileged helper is implemented",
                )
            DesktopRuntimeOs.OTHER ->
                DesktopPreflightCheck(
                    name = "network privileges",
                    status = DesktopPreflightStatus.SKIP,
                    detail = "No privilege check for this operating system",
                )
        }
    }

    private fun vpnRouteDnsToolingCheck(os: DesktopRuntimeOs): DesktopPreflightCheck {
        return when (os) {
            DesktopRuntimeOs.LINUX -> {
                val ip = runCommand(listOf("sh", "-c", "command -v ip"), timeoutSeconds = 3)
                if (ip.exitCode == 0) {
                    DesktopPreflightCheck("route/DNS tooling", DesktopPreflightStatus.PASS, "iproute2 is available")
                } else {
                    DesktopPreflightCheck(
                        name = "route/DNS tooling",
                        status = DesktopPreflightStatus.FAIL,
                        detail = "Linux route tooling is missing. Install iproute2.",
                    )
                }
            }
            DesktopRuntimeOs.WINDOWS -> {
                val netsh = runCommand(listOf("cmd.exe", "/c", "where netsh.exe"), timeoutSeconds = 3)
                val dns = runCommand(
                    listOf(
                        "powershell.exe",
                        "-NoProfile",
                        "-NonInteractive",
                        "-Command",
                        "Get-Command Get-DnsClientServerAddress -ErrorAction Stop | Out-Null; 'ok'",
                    ),
                    timeoutSeconds = 3,
                )
                if (netsh.exitCode == 0 && dns.exitCode == 0) {
                    DesktopPreflightCheck(
                        name = "route/DNS tooling",
                        status = DesktopPreflightStatus.PASS,
                        detail = "Windows netsh and DNS client cmdlets are available",
                    )
                } else {
                    DesktopPreflightCheck(
                        name = "route/DNS tooling",
                        status = DesktopPreflightStatus.FAIL,
                        detail = "Windows route/DNS tooling is unavailable. VPN mode needs netsh.exe and DNS client PowerShell cmdlets.",
                    )
                }
            }
            DesktopRuntimeOs.MACOS ->
                DesktopPreflightCheck(
                    name = "route/DNS tooling",
                    status = DesktopPreflightStatus.SKIP,
                    detail = "macOS route/DNS tooling is skipped until a privileged helper is implemented",
                )
            DesktopRuntimeOs.OTHER ->
                DesktopPreflightCheck(
                    name = "route/DNS tooling",
                    status = DesktopPreflightStatus.SKIP,
                    detail = "No route/DNS tooling check for this operating system",
                )
        }
    }

    private fun currentRuntimeOs(): DesktopRuntimeOs {
        val name = (runtimeOsNameOverride ?: System.getProperty("os.name")).lowercase()
        return when {
            name.contains("linux") -> DesktopRuntimeOs.LINUX
            name.contains("windows") -> DesktopRuntimeOs.WINDOWS
            name.contains("mac") || name.contains("darwin") -> DesktopRuntimeOs.MACOS
            else -> DesktopRuntimeOs.OTHER
        }
    }

    private fun buildStartupFailureMessage(runtimeLogFile: Path): String {
        val tail = runCatching {
            Files.readAllLines(runtimeLogFile)
                .asReversed()
                .firstOrNull { it.isNotBlank() }
                .orEmpty()
        }.getOrDefault("")
        return if (tail.isBlank()) {
            when (activeMode) {
                AppMode.VPN -> "sing-box did not stay running for desktop VPN mode"
                else -> "sing-box did not open the local proxy port"
            }
        } else {
            "sing-box failed to start: $tail"
        }
    }

    private fun stopActiveProcess() {
        val active = process
        if (active?.isAlive == true) {
            active.destroy()
            if (!active.waitFor(2, TimeUnit.SECONDS)) {
                active.destroyForcibly()
                active.waitFor(2, TimeUnit.SECONDS)
            }
        }
        stopOrphanRuntimeProcesses(excludedPid = active?.pid())
        process = null
        listenPort = null
        logFile = null
        activeMode = null
    }

    private fun stopOrphanRuntimeProcesses(excludedPid: Long?) {
        val runtimeConfigPaths = listOf(
            baseDir.resolve("runtime-sing-box-vpn.json"),
            baseDir.resolve("runtime-sing-box-proxy_only.json"),
        ).map { it.toAbsolutePath().normalize().toString() }
        val currentPid = ProcessHandle.current().pid()
        ProcessHandle.allProcesses().forEach { handle ->
            if (handle.pid() == currentPid || handle.pid() == excludedPid) return@forEach
            val info = handle.info()
            val command = info.command().orElse("")
            val commandLine = info.commandLine().orElse("")
            val arguments = info.arguments().orElse(emptyArray()).toList()
            val commandName = command.substringAfterLast('/').substringAfterLast('\\')
            val isSingBox = commandName.contains("sing-box", ignoreCase = true) ||
                commandLine.contains("sing-box", ignoreCase = true)
            val usesRuntimeConfig = runtimeConfigPaths.any { path ->
                path in arguments || commandLine.contains(path)
            }
            if (isSingBox && usesRuntimeConfig) {
                stopProcessHandle(handle)
            }
        }
    }

    private fun stopProcessHandle(handle: ProcessHandle) {
        if (!handle.isAlive) return
        handle.destroy()
        val stopped = runCatching {
            handle.onExit().get(2, TimeUnit.SECONDS)
        }.isSuccess
        if (!stopped && handle.isAlive) {
            handle.destroyForcibly()
            runCatching { handle.onExit().get(2, TimeUnit.SECONDS) }
        }
    }
}

private enum class DesktopRuntimeOs {
    LINUX,
    WINDOWS,
    MACOS,
    OTHER,
}
