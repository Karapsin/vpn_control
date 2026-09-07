package com.kardinal.vpncontrol.desktop

import com.sun.jna.Platform
import java.nio.file.Path
import java.util.Locale
import java.util.concurrent.atomic.AtomicBoolean

/** The shutdown hook, not a frontend or main-stack frame, owns the process admission lease. */
internal object DesktopWindowsProcessAdmission {
    fun install(
        windows: Boolean = Platform.isWindows(),
        executable: () -> String? = { ProcessHandle.current().info().command().orElse(null) },
        enter: (Path) -> AutoCloseable = { DesktopWindowsInstallAdmission.enter(it) },
        retainUntilExit: (() -> Unit) -> Unit = { release ->
            Runtime.getRuntime().addShutdownHook(Thread({ release() }, "windows-install-admission-release"))
        },
        allowPendingControl: Boolean = false,
        onPendingControl: () -> Unit = {},
        enterControl: (Path) -> AutoCloseable = { DesktopWindowsInstallAdmission.enter(it,
            allowPendingControl = true, onPendingControl = onPendingControl) },
    ) {
        if (!windows) return
        val actual = requireNotNull(executable()) { "Process identity unavailable" }
        val name = actual.substringAfterLast('\\').substringAfterLast('/').lowercase(Locale.ROOT)
        // IDE/Gradle JVM execution has no installed launcher to replace.
        if (name == "java.exe" || name == "javaw.exe") return
        require(name == "vpn-control.exe" || name == "vpn-control-cli.exe") { "Unapproved process image" }
        val lease = if (allowPendingControl) enterControl(Path.of(actual)) else enter(Path.of(actual))
        val closed = AtomicBoolean()
        val release = { if (closed.compareAndSet(false, true)) lease.close() }
        try { retainUntilExit(release) }
        catch (failure: Throwable) { runCatching { release() }; throw failure }
    }
}
