package com.kardinal.vpncontrol.desktop

import kotlinx.coroutines.delay
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.util.concurrent.CompletableFuture
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/** Native ticks, not epoch milliseconds. The control client must verify its owner endpoint first. */
internal data class DesktopLinuxAuthorizationOwner(val pid: Long, val startTicks: Long, val uid: Long) {
    init { require(pid in 1..Int.MAX_VALUE && startTicks > 0 && uid in 1..4_294_967_294L) }
    override fun toString() = "DesktopLinuxAuthorizationOwner(<redacted>)"
}

/** Client-side only. This lease neither grants privilege nor proves installer authorization. */
internal class DesktopLinuxTerminalAuthorization private constructor(
    private val process: DesktopLinuxTerminalAgentProcess,
) : AutoCloseable {
    override fun close() = process.close()

    companion object {
        suspend fun start(owner: DesktopLinuxAuthorizationOwner): DesktopLinuxTerminalAuthorization {
            check(System.getProperty("os.name").startsWith("Linux", true)) { "UNSUPPORTED" }
            val selfUid = (Files.getAttribute(Path.of("/proc/self"), "unix:uid") as Number).toLong()
            check(selfUid == owner.uid) { "PRIVILEGE_REQUIRED" }
            verifyLinuxTerminalAgentExecutable()
            return start(owner, ::linuxAuthorizationOwnerMatches, ::launchLinuxTerminalAgent)
        }

        internal suspend fun start(
            owner: DesktopLinuxAuthorizationOwner,
            sameOwner: (DesktopLinuxAuthorizationOwner) -> Boolean,
            launch: (DesktopLinuxAuthorizationOwner) -> DesktopLinuxTerminalAgentProcess,
            timeoutMillis: Long = 15_000,
        ): DesktopLinuxTerminalAuthorization {
            require(timeoutMillis in 1..60_000)
            check(sameOwner(owner)) { "CONFLICT" }
            val process = launch(owner)
            var retained = false
            try {
                val deadline = System.nanoTime() + timeoutMillis * 1_000_000
                while (true) {
                    check(sameOwner(owner)) { "CONFLICT" }
                    check(process.isAlive()) { "INTERACTION_REQUIRED" }
                    if (process.registrationReady()) {
                        check(sameOwner(owner) && process.isAlive()) { "CONFLICT" }
                        retained = true
                        return DesktopLinuxTerminalAuthorization(process)
                    }
                    check(System.nanoTime() < deadline) { "INTERACTION_REQUIRED" }
                    delay(25)
                }
            } finally {
                if (!retained) process.close()
            }
        }
    }
}

internal interface DesktopLinuxTerminalAgentProcess : AutoCloseable {
    fun isAlive(): Boolean
    fun registrationReady(): Boolean
}

/**
 * Only fd 3 is the registration pipe. Authentication cannot reach CLI JSON stdout/stderr.
 * This explicit terminal lease registers an exact-process agent, not a session agent. Do not use
 * --fallback: polkit's lookup drops a process fallback when no logind session exists (e.g. daemon
 * owner/remote terminal). GUI authorization never creates this lease and keeps its session agent.
 */
internal fun linuxTerminalAgentArguments(owner: DesktopLinuxAuthorizationOwner): List<String> = listOf(
    "/bin/sh", "-c", """
        unset ENV BASH_ENV CDPATH
        exec 3>&1
        exec </dev/tty >/dev/tty 2>/dev/tty
        [ -t 0 ] || exit 126
        exec /usr/bin/pkttyagent --process "${'$'}1" --notify-fd 3
    """.trimIndent(), "vpn-control-terminal-auth", "${owner.pid},${owner.startTicks}",
)

private fun launchLinuxTerminalAgent(owner: DesktopLinuxAuthorizationOwner): DesktopLinuxTerminalAgentProcess {
    val process = ProcessBuilder(linuxTerminalAgentArguments(owner))
        .redirectError(ProcessBuilder.Redirect.DISCARD).start()
    process.outputStream.close()
    val executor = Executors.newSingleThreadExecutor { Thread(it, "linux-auth-registration").also { thread -> thread.isDaemon = true } }
    // pkttyagent's documented readiness notification is closing notify-fd, not writing a marker.
    val notification = CompletableFuture.supplyAsync({ process.inputStream.read() }, executor)
    return object : DesktopLinuxTerminalAgentProcess {
        private var closed = false
        override fun isAlive() = process.isAlive
        override fun registrationReady(): Boolean {
            if (!notification.isDone) return false
            check(notification.join() == -1) { "INVALID_ARGUMENT" }
            return true
        }
        override fun close() {
            if (closed) return
            closed = true
            try {
                // This is only the exact unprivileged agent we created, never an installer child.
                process.destroy()
                if (!process.waitFor(1, TimeUnit.SECONDS)) {
                    process.destroyForcibly()
                    process.waitFor(1, TimeUnit.SECONDS)
                }
            } finally {
                process.inputStream.close()
                executor.shutdownNow()
            }
        }
    }
}

private fun linuxAuthorizationOwnerMatches(owner: DesktopLinuxAuthorizationOwner): Boolean = runCatching {
    val uid = (Files.getAttribute(Path.of("/proc/${owner.pid}"), "unix:uid") as Number).toLong()
    uid == owner.uid && linuxInstallProcessStart(owner.pid) == owner.startTicks
}.getOrDefault(false)

private fun verifyLinuxTerminalAgentExecutable() {
    val executable = Path.of("/usr/bin/pkttyagent").toRealPath()
    var current = executable.root
    for (part in executable) {
        current = current.resolve(part)
        val uid = (Files.getAttribute(current, "unix:uid", LinkOption.NOFOLLOW_LINKS) as Number).toLong()
        val mode = (Files.getAttribute(current, "unix:mode", LinkOption.NOFOLLOW_LINKS) as Number).toInt()
        check(uid == 0L && mode and 0x12 == 0 && !Files.isSymbolicLink(current)) { "PRIVILEGE_REQUIRED" }
    }
    check(Files.isRegularFile(executable, LinkOption.NOFOLLOW_LINKS) && Files.isExecutable(executable)) { "INTERACTION_REQUIRED" }
}
