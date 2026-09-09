package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.DnsSettings
import com.kardinal.vpncontrol.model.RuntimeStatusMessages
import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.RoutingRules
import com.kardinal.vpncontrol.model.ProxyProfile
import com.kardinal.vpncontrol.model.HomeSshRouteSettings
import com.kardinal.vpncontrol.data.HomeSshRouteRuntimeOptions
import com.kardinal.vpncontrol.data.SingBoxCustomConfigTransformer
import com.kardinal.vpncontrol.model.ProxyProtocol
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
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext

data class DesktopRuntimeSession(
    val appMode: AppMode,
    val listenPort: Int?,
    val managementProxyPort: Int? = listenPort,
    val interfaceName: String?,
    val configJson: String,
    val logFile: Path,
    val processId: Long,
    val resourceWarnings: List<DesktopRuntimeResourceWarning> = emptyList(),
)

internal const val WINDOWS_ROUTE_DNS_TOOLING_TIMEOUT_SECONDS = 15L

internal data class DesktopCommandResult(
    val exitCode: Int,
    val output: String,
)

internal fun windowsRouteDnsToolingCheck(
    commandRunner: (List<String>, Long) -> DesktopCommandResult,
): DesktopPreflightCheck {
    val netsh = commandRunner(
        listOf("cmd.exe", "/c", "where netsh.exe"),
        WINDOWS_ROUTE_DNS_TOOLING_TIMEOUT_SECONDS,
    )
    val dns = commandRunner(
        listOf(
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Get-Command Get-DnsClientServerAddress -ErrorAction Stop | Out-Null; 'ok'",
        ),
        WINDOWS_ROUTE_DNS_TOOLING_TIMEOUT_SECONDS,
    )
    return if (netsh.exitCode == 0 && dns.exitCode == 0) {
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

class DesktopProxyRuntimeManager(
    private val runtimeConfigStore: RuntimeConfigStore,
    private val baseDir: Path = DesktopWorkspacePaths.root().resolve("runtime"),
    private val singBoxResolver: DesktopSingBoxResolver = DesktopSingBoxResolver(baseDir.resolve("tools")),
    private val directProbeRouting: DesktopDirectProbeRouting = DesktopDirectProbeRouting(),
    private val runtimeOsNameOverride: String? = null,
    private val windowsAdministratorOverride: Boolean? = null,
    private val homeSshCredentialStore: DesktopHomeSshCredentialStore = DesktopHomeSshCredentialStore(
        baseDir.parent ?: baseDir,
    ),
    private val windowsScopedRuntimeEnabled: Boolean = false,
) : DesktopRuntimeController {
    internal constructor(runtimeConfigStore: RuntimeConfigStore, baseDir: Path,
                         nativeOperations: DesktopRuntimeManagerNative) : this(runtimeConfigStore, baseDir) {
        this.nativeOperations = nativeOperations
    }

    private var nativeOperations: DesktopRuntimeManagerNative? = null
    private var resourceScopeProvider: DesktopWindowsRuntimeResourceScopeProvider? = null

    @Synchronized internal fun bindRuntimeResourceScopeProvider(provider: DesktopWindowsRuntimeResourceScopeProvider) {
        check(resourceScopeProvider == null || resourceScopeProvider === provider) { "CONFLICT" }
        resourceScopeProvider = provider
    }

    @Synchronized internal fun requireRuntimeResourceScope(): DesktopWindowsRuntimeResourceScope =
        resourceScopeProvider?.current() ?: throw DesktopWindowsRuntimeFailure("UNAVAILABLE",
            stage = DesktopWindowsRuntimePreparationStage.CAPTURED_INPUTS)

    @Synchronized internal fun requireRuntimeResourceScopeProvider(): DesktopWindowsRuntimeResourceScopeProvider =
        resourceScopeProvider ?: throw DesktopWindowsRuntimeFailure("UNAVAILABLE",
            stage = DesktopWindowsRuntimePreparationStage.CAPTURED_INPUTS)

    @Volatile
    private var process: DesktopRuntimeProcess? = null

    @Volatile
    private var listenPort: Int? = null

    @Volatile
    private var managementProxyPort: Int? = null

    @Volatile
    private var logFile: Path? = null

    @Volatile
    private var activeMode: AppMode? = null

    @Volatile
    private var lastPreflightReport: DesktopPreflightReport? = null

    @Volatile
    private var lastAttemptedConfigJson: String? = null

    private val transition = DesktopRuntimeTransition(
        runtimeConfigStore, ::prepareLaunch, ::awaitLaunch,
        publish = { launch, child ->
            process = child
            listenPort = launch?.listenPort
            managementProxyPort = launch?.managementPort
            activeMode = launch?.appMode
            if (launch != null) logFile = launch.logFile
        },
        retire = ::retireLaunch,
    )

    override suspend fun start(
        profile: ProxyProfile,
        routingRules: RoutingRules,
        dnsSettings: DnsSettings,
        appMode: AppMode,
        activeVerificationPort: Int?,
        homeSshRouteSettings: HomeSshRouteSettings,
    ): Result<DesktopRuntimeSession> {
        val caller = kotlinx.coroutines.currentCoroutineContext()
        // Keep established recovery metadata available to lifecycle bookkeeping after cancellation.
        return withContext(kotlinx.coroutines.NonCancellable) {
            withContext(Dispatchers.IO) {
                transition.start(caller) {
                    buildLaunch(profile, routingRules, dnsSettings, appMode,
                        activeVerificationPort, homeSshRouteSettings)
                }
            }
        }
    }

    /** Pins the currently published immutable launch without reading staged settings. */
    override fun captureRuntimeRestoreLease(): DesktopRuntimeRestoreLease? =
        transition.captureRestoreLease() ?: object : DesktopRuntimeRestoreLease {
            override suspend fun restore(): Result<DesktopRuntimeSession> =
                Result.failure(IllegalStateException("ROLLBACK_FAILED"))

            override fun close() = Unit
        }

    private fun buildLaunch(
        profile: ProxyProfile,
        routingRules: RoutingRules,
        dnsSettings: DnsSettings,
        appMode: AppMode,
        activeVerificationPort: Int?,
        homeSshRouteSettings: HomeSshRouteSettings,
    ): DesktopRuntimeLaunch {
        DesktopWorkspacePaths.createDirectories(baseDir)
        val directory = Files.createTempDirectory(baseDir, "candidate-")
        try {
            return buildLaunchInDirectory(profile, routingRules, dnsSettings, appMode,
                activeVerificationPort, homeSshRouteSettings, directory)
        } catch (failure: Throwable) {
            // Preparation can fail before a launch descriptor exists. Remove only its known inputs.
            for (path in listOf(directory.resolve("home-ssh-private-key"), directory.resolve("config.json"),
                directory.resolve("runtime.log"), directory)) {
                try { Files.deleteIfExists(path) } catch (cleanup: Exception) { failure.addSuppressed(cleanup) }
            }
            throw failure
        }
    }

    private fun buildLaunchInDirectory(
        profile: ProxyProfile,
        routingRules: RoutingRules,
        dnsSettings: DnsSettings,
        appMode: AppMode,
        activeVerificationPort: Int?,
        homeSshRouteSettings: HomeSshRouteSettings,
        directory: Path,
    ): DesktopRuntimeLaunch {
        DesktopWorkspacePaths.createDirectories(baseDir)
        val managementPort = activeVerificationPort?.takeIf { it in 1..65535 } ?: allocateListenPort()
        val userProxyPort = when {
            appMode != AppMode.PROXY_ONLY -> managementPort
            profile.protocol == ProxyProtocol.CUSTOM -> managementPort
            else -> allocateListenPort(excluding = managementPort)
        }
        val homeRoute = homeSshRouteSettings.takeIf { it.enabled }?.let { settings ->
            HomeSshRouteRuntimeOptions(
                settings = settings,
                privateKeyPath = homeSshCredentialStore.capturePrivateKey(
                    directory.resolve("home-ssh-private-key"),
                ).toAbsolutePath().toString(),
            ).validated()
        }
        val interfaceName = if (appMode == AppMode.VPN) {
            DesktopProxyConfigFactory.DEFAULT_VPN_INTERFACE_NAME
        } else {
            null
        }
        val configJson = if (profile.protocol == ProxyProtocol.CUSTOM) {
            SingBoxCustomConfigTransformer.transform(
                rawConfig = profile.customConfigJson,
                managementProxyPort = managementPort,
                homeRoute = homeRoute,
                trustedDirectBypassRules = DesktopProxyConfigFactory.buildDirectProbeRouteRules(
                    routing = directProbeRouting,
                    outboundTag = SingBoxCustomConfigTransformer.TRUSTED_DIRECT_BYPASS_OUTBOUND_TAG,
                ),
            )
        } else when (appMode) {
            AppMode.PROXY_ONLY -> DesktopProxyConfigFactory.buildProxyOnlyConfig(
                profile = profile,
                dns = dnsSettings,
                routingRules = routingRules,
                listenPort = userProxyPort,
                managementProxyPort = managementPort,
                homeRoute = homeRoute,
            )
            AppMode.VPN ->
                DesktopProxyConfigFactory.buildVpnConfig(
                    profile = profile,
                    dns = dnsSettings,
                    routingRules = routingRules,
                    interfaceName = checkNotNull(interfaceName),
                    directProbeRouting = directProbeRouting,
                    activeVerificationPort = managementPort,
                    homeRoute = homeRoute,
                )
        }
        val configPath = directory.resolve("config.json")
        val runtimeLogFile = directory.resolve("runtime.log")
        val launch = DesktopRuntimeLaunch(appMode, userProxyPort, managementPort, interfaceName,
            configJson, configPath, runtimeLogFile, homeRoute?.privateKeyPath?.let(Path::of))
        try {
            Files.writeString(configPath, configJson, java.nio.file.StandardOpenOption.CREATE_NEW)
            Files.createFile(runtimeLogFile)
            lastAttemptedConfigJson = configJson
            val preflight = nativeOperations?.preflight(launch) ?: runPreflight(
                appMode, configPath, userProxyPort, managementPort,
            )
            lastPreflightReport = preflight
            check(preflight.isReady) { preflight.failureMessage() }
            if (scopedWindows(launch)) launch.captured = DesktopWindowsVpnConfigCapture.capture(
                configJson, baseDir, launch.privateKeyPath,
            )
            return launch
        } catch (failure: Throwable) {
            try { retireLaunch(launch) } catch (cleanup: Exception) { failure.addSuppressed(cleanup) }
            throw failure
        }
    }

    private fun scopedWindows(launch: DesktopRuntimeLaunch) = windowsScopedRuntimeEnabled &&
        launch.appMode == AppMode.VPN && currentRuntimeOs() == DesktopRuntimeOs.WINDOWS

    private suspend fun prepareLaunch(launch: DesktopRuntimeLaunch,
                                      caller: kotlin.coroutines.CoroutineContext): DesktopPreparedRuntimeProcess {
        nativeOperations?.let { return it.prepare(launch) }
        if (scopedWindows(launch)) {
            val captured = checkNotNull(launch.captured)
            return if (captured.mutableResources.isEmpty()) DesktopWindowsVpnBroker.prepareRetained(captured, launch.logFile) {
                caller.ensureActive()
            } else DesktopWindowsVpnBroker.prepareRetained(captured, launch.logFile, requireRuntimeResourceScopeProvider()) {
                caller.ensureActive()
            }
        }
        val executable = singBoxResolver.resolve() ?: error(singBoxResolver.missingMessage())
        return object : DesktopPreparedRuntimeProcess {
            private var consumed = false
            override fun commit(): DesktopRuntimeProcess {
                check(!consumed) { "Prepared runtime has already been consumed" }
                consumed = true
                return DesktopLocalRuntimeProcess(ProcessBuilder(executable.path.toString(), "run", "-c", launch.configPath.toString())
                    .directory(baseDir.toFile()).redirectErrorStream(true)
                    .redirectOutput(ProcessBuilder.Redirect.appendTo(launch.logFile.toFile())).start())
            }
            override fun close() { consumed = true }
        }
    }

    private suspend fun awaitLaunch(child: DesktopRuntimeProcess, launch: DesktopRuntimeLaunch): Boolean = try {
        nativeOperations?.awaitReady(child, launch) ?: when (launch.appMode) {
            AppMode.PROXY_ONLY -> waitForPort(child, launch.listenPort) &&
                (launch.managementPort == launch.listenPort || waitForPort(child, launch.managementPort))
            AppMode.VPN -> waitForVpnProcess(child) && waitForPort(child, launch.managementPort)
        }
    } catch (_: OutOfMemoryError) {
        // This boundary already has the exact accepted child. Let the transition establish its
        // exit and recover A; neither a resource failure nor a failed recovery may discard it.
        // Other VM errors are not converted to ordinary application failures.
        throw DesktopWindowsRuntimeFailure("RUNTIME_FAILED")
    }

    private fun retireLaunch(launch: DesktopRuntimeLaunch) {
        launch.captured?.close()
        if (Files.exists(launch.logFile) && Files.size(launch.logFile) > 0)
            Files.copy(launch.logFile, defaultLogFile(), java.nio.file.StandardCopyOption.REPLACE_EXISTING)
        Files.deleteIfExists(launch.configPath.parent.resolve("home-ssh-private-key"))
        Files.deleteIfExists(launch.configPath)
        Files.deleteIfExists(launch.logFile)
        Files.deleteIfExists(launch.configPath.parent) // Never recursively remove unexpected files.
        if (logFile == launch.logFile) logFile = null
    }

    override suspend fun stop(): Result<Unit> = withContext(kotlinx.coroutines.NonCancellable) {
        withContext(Dispatchers.IO) { transition.stop() }
    }

    fun stopBlocking(): Result<Unit> = runBlocking { stop() }

    override fun isRunning(): Boolean = process?.isAlive == true

    override fun currentPort(): Int? = if (isRunning()) listenPort else null

    override fun currentManagementProxyPort(): Int? = if (isRunning()) managementProxyPort else null

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

    private fun allocateListenPort(excluding: Int? = null): Int {
        while (true) {
            val candidate = ServerSocket(0).use { socket -> socket.localPort }
            if (candidate != excluding) return candidate
        }
    }

    private suspend fun waitForPort(child: DesktopRuntimeProcess, port: Int): Boolean {
        repeat(20) {
            if (child.isAlive != true) {
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
        activeVerificationPort: Int?,
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
                add(vpnLocalPortCheck(activeVerificationPort))
            } else {
                val port = checkNotNull(listenPort)
                add(localProxyPortCheck("local proxy port", port))
                activeVerificationPort
                    ?.takeIf { it != port }
                    ?.let { add(localProxyPortCheck("management proxy port", it)) }
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

    private fun vpnLocalPortCheck(activeVerificationPort: Int?): DesktopPreflightCheck {
        val port = activeVerificationPort ?: return DesktopPreflightCheck(
            name = "local ports",
            status = DesktopPreflightStatus.SKIP,
            detail = "VPN mode does not open a local proxy port",
        )
        return if (isPortAvailable(port)) {
            DesktopPreflightCheck(
                name = "active verification port",
                status = DesktopPreflightStatus.PASS,
                detail = "127.0.0.1:$port is available",
            )
        } else {
            DesktopPreflightCheck(
                name = "active verification port",
                status = DesktopPreflightStatus.FAIL,
                detail = "Port $port is already in use. Retry Find Best or stop the other process.",
            )
        }
    }

    private fun localProxyPortCheck(name: String, port: Int): DesktopPreflightCheck {
        return if (isPortAvailable(port)) {
            DesktopPreflightCheck(name, DesktopPreflightStatus.PASS, "127.0.0.1:$port is available")
        } else {
            DesktopPreflightCheck(
                name = name,
                status = DesktopPreflightStatus.FAIL,
                detail = "Port $port is already in use. Stop the other process or retry.",
            )
        }
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

    private fun runCommand(
        command: List<String>,
        timeoutSeconds: Long,
    ): DesktopCommandResult {
        return runCatching {
            val process = ProcessBuilder(command)
                .directory(baseDir.toFile())
                .redirectErrorStream(true)
                .start()
            val finished = process.waitFor(timeoutSeconds, TimeUnit.SECONDS)
            if (!finished) {
                process.destroyForcibly()
                process.waitFor(1, TimeUnit.SECONDS)
                return@runCatching DesktopCommandResult(
                    exitCode = -1,
                    output = "${command.joinToString(" ")} timed out after ${timeoutSeconds}s",
                )
            }
            val output = process.inputStream.bufferedReader().use { it.readText() }
                .trim()
                .take(2_000)
            DesktopCommandResult(process.exitValue(), output)
        }.getOrElse { error ->
            DesktopCommandResult(-1, error.message ?: "${command.joinToString(" ")} failed")
        }
    }

    private suspend fun waitForVpnProcess(child: DesktopRuntimeProcess): Boolean {
        repeat(10) {
            if (child.isAlive != true) {
                return false
            }
            delay(200)
        }
        return child.isAlive == true
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

    private data class LinuxNetworkPrivilegeResult(
        val hasPrivileges: Boolean,
        val binary: DesktopSingBoxExecutable?,
    )

    private fun linuxNetworkPrivilegeResult(): LinuxNetworkPrivilegeResult {
        val binary = singBoxResolver.resolve()
        if (System.getProperty("user.name") == "root") {
            return LinuxNetworkPrivilegeResult(hasPrivileges = true, binary = binary)
        }
        val executable = binary?.path ?: return LinuxNetworkPrivilegeResult(hasPrivileges = false, binary = null)
        val output = runCatching {
            val process = ProcessBuilder("getcap", executable.toString())
                .redirectErrorStream(true)
                .start()
            val text = process.inputStream.bufferedReader().use { it.readText() }
            process.waitFor(1, TimeUnit.SECONDS)
            text
        }.getOrDefault("")
        return LinuxNetworkPrivilegeResult(
            hasPrivileges = linuxNetworkCapabilitiesAvailable(output),
            binary = binary,
        )
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
                        detail = linuxTunBackendMissingDetail(),
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
                val privileges = linuxNetworkPrivilegeResult()
                if (privileges.hasPrivileges) {
                    DesktopPreflightCheck("network privileges", DesktopPreflightStatus.PASS, "CAP_NET_ADMIN/CAP_NET_RAW available")
                } else {
                    DesktopPreflightCheck(
                        name = "network privileges",
                        status = DesktopPreflightStatus.FAIL,
                        detail = linuxNetworkPrivilegesMissingDetail(privileges.binary),
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
            DesktopRuntimeOs.WINDOWS -> windowsRouteDnsToolingCheck(::runCommand)
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


}

internal fun linuxNetworkCapabilitiesAvailable(getcapOutput: String): Boolean {
    return getcapOutput.contains("cap_net_admin") && getcapOutput.contains("cap_net_raw")
}

internal fun linuxTunBackendMissingDetail(
    currentKernel: String? = currentLinuxKernelRelease(),
    modulesRoot: Path = Path.of("/lib/modules"),
): String {
    val baseMessage = "Linux TUN device is missing at /dev/net/tun."
    val kernel = currentKernel?.takeIf(String::isNotBlank) ?: return "$baseMessage Try: sudo modprobe tun"
    val expectedModulesDir = modulesRoot.resolve(kernel)
    if (Files.isDirectory(expectedModulesDir)) {
        return "$baseMessage Try: sudo modprobe tun"
    }
    val installedKernels = runCatching {
        Files.list(modulesRoot).use { stream ->
            stream
                .filter { Files.isDirectory(it) }
                .map { it.fileName.toString() }
                .sorted()
                .toList()
        }
    }.getOrDefault(emptyList())
    val installedText = installedKernels.takeIf { it.isNotEmpty() }
        ?.joinToString(", ", prefix = " Installed module directories: ")
        .orEmpty()
    return "$baseMessage Kernel modules for the running kernel are missing at $expectedModulesDir." +
        installedText +
        " Reboot into an installed kernel or install the matching Arch kernel/modules package, then run: sudo modprobe tun"
}

private fun currentLinuxKernelRelease(): String? {
    return runCatching {
        val process = ProcessBuilder("uname", "-r")
            .redirectErrorStream(true)
            .start()
        val output = process.inputStream.bufferedReader().use { it.readText() }.trim()
        if (process.waitFor(1, TimeUnit.SECONDS) && process.exitValue() == 0) {
            output
        } else {
            null
        }
    }.getOrNull()
}

internal fun linuxNetworkPrivilegesMissingDetail(binary: DesktopSingBoxExecutable?): String {
    if (binary == null) {
        return "Desktop VPN mode needs CAP_NET_ADMIN/CAP_NET_RAW, but sing-box is not available. " +
            "Rebuild the desktop package with bundled sing-box, set VPN_CONTROL_SING_BOX, or add sing-box to PATH."
    }
    val path = binary.path.toAbsolutePath().normalize().toString()
    return "Desktop VPN mode needs CAP_NET_ADMIN/CAP_NET_RAW. VPN Control is using sing-box at $path (${binary.source}). " +
        "Grant that binary capabilities: sudo setcap cap_net_admin,cap_net_raw+ep ${shellQuote(path)}"
}

private fun shellQuote(value: String): String {
    return "'${value.replace("'", "'\"'\"'")}'"
}

private enum class DesktopRuntimeOs {
    LINUX,
    WINDOWS,
    MACOS,
    OTHER,
}
