package com.kardinal.vpncontrol.desktop

import java.nio.file.Files
import java.nio.file.Path
import kotlin.concurrent.withLock
import kotlinx.coroutines.runBlocking

internal enum class HeadlessControllerMode {
    TRANSIENT,
    SERVICE,
}

internal object DesktopHeadlessController {
    const val ARG = "--headless-controller"
    const val SERVE_COMMAND = "serve"

    private const val STARTUP_IDLE_TIMEOUT_MILLIS = 30_000L
    private const val START_RESPONSE_TIMEOUT_MILLIS = 10_000L
    private const val RETRY_DELAY_MILLIS = 100L

    fun handleArgs(
        args: Array<String>,
        printLine: (String) -> Unit = ::println,
    ): Int? {
        return when (modeForArgs(args)) {
            HeadlessControllerMode.TRANSIENT -> runController(printLine = printLine, persistent = false)
            HeadlessControllerMode.SERVICE -> runController(printLine = printLine, persistent = true)
            null -> null
        }
    }

    fun modeForArgs(args: Array<String>): HeadlessControllerMode? = when (args.toList()) {
        listOf(ARG) -> HeadlessControllerMode.TRANSIENT
        listOf(SERVE_COMMAND) -> HeadlessControllerMode.SERVICE
        else -> null
    }

    fun startForCliCommand(
        command: DesktopCliCommand,
        osName: String = System.getProperty("os.name"),
        currentCommand: String? = ProcessHandle.current().info().command().orElse(null),
        requestCommand: (DesktopCliCommand) -> DesktopCliResponse = DesktopActivationServer::requestCliCommand,
        startProcess: (String, Path) -> Result<Process> = ::startHeadlessProcess,
        clockMillis: () -> Long = System::currentTimeMillis,
        sleepMillis: (Long) -> Unit = { Thread.sleep(it) },
    ): DesktopCliResponse {
        if (!isLinux(osName)) {
            return DesktopCliResponse.failure(
                "Headless CLI is currently supported on Linux only. Start the desktop app first.",
                exitCode = DesktopCliResponse.UNAVAILABLE_EXIT_CODE,
            )
        }
        val executable = currentCommand?.takeIf(String::isNotBlank)
            ?: return DesktopCliResponse.failure(
                "VPN Control could not determine its launcher path for headless CLI.",
                exitCode = DesktopCliResponse.UNAVAILABLE_EXIT_CODE,
            )
        val process = startProcess(executable, defaultLogFile()).getOrElse { error ->
            return DesktopCliResponse.failure(
                error.message ?: "Failed to start VPN Control headless controller.",
                exitCode = DesktopCliResponse.UNAVAILABLE_EXIT_CODE,
            )
        }
        val deadline = clockMillis() + START_RESPONSE_TIMEOUT_MILLIS
        while (clockMillis() < deadline) {
            val response = requestCommand(command)
            if (!response.isDesktopAppNotRunning) {
                return response
            }
            if (!process.isAlive) {
                return DesktopCliResponse.failure(
                    "VPN Control headless controller exited before responding.",
                    exitCode = DesktopCliResponse.UNAVAILABLE_EXIT_CODE,
                )
            }
            sleepMillis(RETRY_DELAY_MILLIS)
        }
        return DesktopCliResponse.failure(
            "Timed out waiting for VPN Control headless controller.",
            exitCode = DesktopCliResponse.UNAVAILABLE_EXIT_CODE,
        )
    }

    private fun runController(
        osName: String = System.getProperty("os.name"),
        printLine: (String) -> Unit,
        persistent: Boolean,
        acquireLock: () -> AutoCloseable? = { DesktopSingleInstanceLock.acquire() },
        serviceFactory: () -> DesktopAppService = { DesktopAppServiceFactory.default() },
        startServer: (
            onShowWindow: () -> DesktopActivationShowResult,
            onCliCommand: (DesktopCliCommand) -> DesktopCliResponse,
        ) -> AutoCloseable? = { onShowWindow, onCliCommand ->
            DesktopActivationServer.start(
                onShowWindow = onShowWindow,
                onCliCommand = onCliCommand,
            )
        },
        clockMillis: () -> Long = System::currentTimeMillis,
    ): Int {
        if (!isLinux(osName)) {
            printLine("Headless CLI is currently supported on Linux only.")
            return 1
        }
        val lock = acquireLock()
        if (lock == null) {
            printLine("VPN Control is already running.")
            return DesktopCliResponse.UNAVAILABLE_EXIT_CODE
        }
        lock.use {
            val service = serviceFactory()
            val lifecycle = HeadlessLifecycle(clockMillis, persistent)
            val server = startServer(
                { DesktopActivationShowResult.HEADLESS },
                { command ->
                    val response = runBlocking { service.executeCliCommand(command) }
                    lifecycle.markCommandHandled(keepAlive = persistent || service.state.isVpnRunning)
                    response
                },
            )
            if (server == null) {
                printLine("Failed to start VPN Control headless controller.")
                return DesktopCliResponse.UNAVAILABLE_EXIT_CODE
            }
            server.use {
                if (persistent) {
                    runBlocking { service.resumePreviousConnectionIfNeeded() }
                    printLine("VPN Control headless service is ready.")
                }
                lifecycle.awaitExit()
            }
        }
        return 0
    }

    private fun isLinux(osName: String): Boolean =
        osName.contains("linux", ignoreCase = true)

    private fun defaultLogFile(): Path = Path.of(
        System.getProperty("user.home"),
        ".vpn-control-desktop",
        "headless.log",
    )

    private fun startHeadlessProcess(executable: String, logFile: Path): Result<Process> = runCatching {
        Files.createDirectories(logFile.parent)
        ProcessBuilder(executable, ARG)
            .redirectErrorStream(true)
            .redirectOutput(ProcessBuilder.Redirect.appendTo(logFile.toFile()))
            .start()
    }

    private class HeadlessLifecycle(
        private val clockMillis: () -> Long,
        private val persistent: Boolean,
    ) {
        private val monitor = java.util.concurrent.locks.ReentrantLock()
        private val changed = monitor.newCondition()
        private var commandHandled = false
        private var keepAlive = false

        fun markCommandHandled(keepAlive: Boolean) {
            monitor.withLock {
                commandHandled = true
                this.keepAlive = keepAlive
                changed.signalAll()
            }
        }

        fun awaitExit() {
            val startupDeadline = clockMillis() + STARTUP_IDLE_TIMEOUT_MILLIS
            monitor.withLock {
                while (true) {
                    if (persistent) {
                        changed.awaitNanos(1_000_000_000L)
                        continue
                    }
                    if (commandHandled && !keepAlive) return
                    if (!commandHandled) {
                        val remainingMillis = startupDeadline - clockMillis()
                        if (remainingMillis <= 0L) return
                        changed.awaitNanos(remainingMillis.coerceAtMost(1_000L) * 1_000_000L)
                    } else {
                        changed.awaitNanos(1_000_000_000L)
                    }
                }
            }
        }
    }
}
