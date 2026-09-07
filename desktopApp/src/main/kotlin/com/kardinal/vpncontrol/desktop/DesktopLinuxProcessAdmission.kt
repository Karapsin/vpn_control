package com.kardinal.vpncontrol.desktop

import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.atomic.AtomicBoolean

internal object DesktopLinuxProcessAdmission {
    fun install(
        linux: Boolean = System.getProperty("os.name").startsWith("Linux", true),
        executable: () -> String? = { Files.readSymbolicLink(Path.of("/proc/self/exe")).toString() },
        enter: () -> AutoCloseable = { DesktopLinuxInstallAdmission.enter() },
        retainUntilExit: (() -> Unit) -> Unit = { release ->
            Runtime.getRuntime().addShutdownHook(Thread({ release() }, "linux-install-admission-release"))
        },
        allowPendingControl: Boolean = false,
        onPendingControl: () -> Unit = {},
        enterControl: () -> AutoCloseable = { DesktopLinuxInstallAdmission.enter(
            allowPendingControl = true, onPendingControl = onPendingControl) },
    ) {
        if (!linux) return
        val name = requireNotNull(executable()) { "Process identity unavailable" }.substringAfterLast('/')
        if (name == "java") return // IDE/Gradle execution is not an installed launcher.
        require(name == "vpn-control") { "Unapproved process image" }
        val lease = if (allowPendingControl) enterControl() else enter()
        val closed = AtomicBoolean()
        val release = { if (closed.compareAndSet(false, true)) lease.close() }
        try { retainUntilExit(release) }
        catch (failure: Throwable) { runCatching { release() }; throw failure }
    }
}
