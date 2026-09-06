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
        packagedLauncher: String? = System.getProperty("jpackage.app-path"),
        classPath: String = System.getProperty("java.class.path"),
        workspaceDirectory: Path? = DesktopWorkspacePaths.overrideDirectory(),
        requestCommand: (DesktopCliCommand) -> DesktopCliResponse = DesktopActivationServer::requestCliCommand,
        startProcess: (List<String>, Path) -> Result<Process> = ::startHeadlessProcess,
        clockMillis: () -> Long = headlessMonotonicClock(),
        sleepMillis: (Long) -> Unit = { Thread.sleep(it) },
    ): DesktopCliResponse {
        if (!isSupportedPlatform(osName)) {
            return DesktopCliResponse.failure(
                "UNSUPPORTED",
                exitCode = DesktopCliResponse.UNAVAILABLE_EXIT_CODE,
            )
        }
        val launchCommand = launchCommand(currentCommand, packagedLauncher, classPath)
            ?: return DesktopCliResponse.failure(
                "VPN Control could not determine its launcher path for headless CLI.",
                exitCode = DesktopCliResponse.UNAVAILABLE_EXIT_CODE,
            )
        val ownerCommand = launchCommand + workspaceDirectory?.let { listOf("--state-dir", it.toString()) }.orEmpty()
        val process = startProcess(ownerCommand, (workspaceDirectory ?: DesktopWorkspacePaths.root()).resolve("headless.log")).getOrElse {
            return DesktopCliResponse.failure(
                "Failed to start VPN Control headless controller.",
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
        controllerId: String = java.util.UUID.randomUUID().toString(),
        startServer: (
            onShowWindow: () -> DesktopActivationShowResult,
            onCliCommand: (DesktopCliCommand) -> DesktopCliResponse,
            onCliCommandFinished: () -> Unit,
            onCliResponseFlushed: (DesktopCliCommand, DesktopCliResponse) -> Unit,
        ) -> AutoCloseable? = { onShowWindow, onCliCommand, onCliCommandFinished, onCliResponseFlushed ->
            DesktopActivationServer.start(
                onShowWindow = onShowWindow,
                onCliCommand = onCliCommand,
                onCliCommandFinished = onCliCommandFinished,
                controllerId = controllerId,
                onCliResponseFlushed = onCliResponseFlushed,
            )
        },
        clockMillis: () -> Long = headlessMonotonicClock(),
    ): Int {
        if (!isSupportedPlatform(osName)) {
            printLine("UNSUPPORTED")
            return 1
        }
        System.setProperty("java.awt.headless", "true")
        val lock = acquireLock()
        if (lock == null) {
            printLine("VPN Control is already running.")
            return DesktopCliResponse.UNAVAILABLE_EXIT_CODE
        }
        lock.use {
            val service = serviceFactory()
            val owner = DesktopControllerOwner(service, controllerId)
            val session = owner.session
            val lifecycle = HeadlessLifecycle(clockMillis, persistent, { owner.exitRequested }) {
                service.state.isVpnRunning || session.hasBackgroundWork() || owner.frontends.hasOwnedWork()
            }
            try {
                val server = startServer(
                    { DesktopActivationShowResult.HEADLESS },
                    { command ->
                        lifecycle.commandStarted()
                        runBlocking { owner.execute(command) }
                    },
                    { lifecycle.markCommandHandled() },
                    { command, response -> owner.responseFlushed(command, response) },
                )
                if (server == null) {
                    printLine("Failed to start VPN Control headless controller.")
                    return DesktopCliResponse.UNAVAILABLE_EXIT_CODE
                }
                server.use {
                    if (persistent) {
                        runBlocking { owner.resumePreviousConnection() }
                        printLine("VPN Control headless service is ready.")
                    }
                    session.start()
                    lifecycle.awaitExit()
                }
            } finally {
                owner.close()
            }
        }
        return 0
    }

    internal fun isSupportedPlatform(osName: String): Boolean {
        val name = osName.lowercase()
        return name.contains("linux") || name.contains("windows") || name.contains("mac") || name == "darwin"
    }

    /** Preserve each argument verbatim: no shell quoting or command-string reparsing. */
    internal fun launchCommand(currentCommand: String?, packagedLauncher: String?, classPath: String): List<String>? {
        packagedLauncher?.takeIf(String::isNotBlank)?.let { return listOf(windowlessOwnerLauncher(it), ARG) }
        val executable = currentCommand?.takeIf(String::isNotBlank) ?: return null
        val name = executable.replace('\\', '/').substringAfterLast('/').lowercase()
        return if (name in setOf("java", "java.exe", "javaw.exe")) {
            if (classPath.isBlank()) return null
            listOf(executable, "-Djava.awt.headless=true", "-cp", classPath,
                "com.kardinal.vpncontrol.desktop.MainKt", ARG)
        } else {
            listOf(windowlessOwnerLauncher(executable), ARG)
        }
    }

    private fun windowlessOwnerLauncher(path: String): String {
        val name = path.replace('\\', '/').substringAfterLast('/')
        return if (name.equals("vpn-control-cli.exe", ignoreCase = true))
            path.dropLast(name.length) + "vpn-control.exe" else path
    }

    private fun startHeadlessProcess(command: List<String>, logFile: Path): Result<Process> = runCatching {
        Files.createDirectories(logFile.parent)
        ProcessBuilder(command)
            .redirectErrorStream(true)
            .redirectOutput(ProcessBuilder.Redirect.appendTo(logFile.toFile()))
            .start()
    }

    private class HeadlessLifecycle(
        private val clockMillis: () -> Long,
        private val persistent: Boolean,
        private val exitRequested: () -> Boolean,
        private val hasBackgroundWork: () -> Boolean,
    ) {
        private val monitor = java.util.concurrent.locks.ReentrantLock()
        private val changed = monitor.newCondition()
        private val idle = DesktopOwnerIdlePolicy(persistent, clockMillis)
        private var activeCommands = 0

        fun commandStarted() = monitor.withLock {
            activeCommands++
            idle.activity()
        }

        fun markCommandHandled() {
            monitor.withLock {
                activeCommands--
                idle.activity()
                changed.signalAll()
            }
        }

        fun awaitExit() {
            monitor.withLock {
                while (true) {
                    if (exitRequested()) return
                    if (idle.shouldExit(activeCommands > 0 || hasBackgroundWork())) return
                    changed.awaitNanos(1_000_000_000L)
                }
            }
        }
    }
}

private fun headlessMonotonicClock(): () -> Long {
    val origin = System.nanoTime()
    return { (System.nanoTime() - origin) / 1_000_000 }
}
