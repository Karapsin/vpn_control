package com.kardinal.vpncontrol.desktop

import java.nio.file.Path
import java.util.concurrent.atomic.AtomicBoolean

/** Packaged Darwin admission; lifetime is the process, not main or a client request. */
internal object DesktopMacProcessAdmission {
    fun install(mac: Boolean = System.getProperty("os.name").startsWith("Mac", true),
        executable: () -> String = { JnaMacInstallAdmission().currentExecutable() },
        enter: (Path, Boolean, () -> Unit) -> AutoCloseable = { path, allow, pending ->
            DesktopMacInstallAdmission.enter(path, allowPendingControl = allow, onPendingControl = pending)
        },
        allowPendingControl: Boolean = false, onPendingControl: () -> Unit = {},
        retainUntilExit: (() -> Unit) -> Unit = { release ->
            Runtime.getRuntime().addShutdownHook(Thread({ release() }, "mac-install-admission-release"))
        }) {
        if (!mac) return
        val path = Path.of(executable())
        if (path.fileName.toString() == "java") return
        require(path.fileName.toString() == "vpn-control") { "Unapproved process image" }
        val lease = enter(path, allowPendingControl, onPendingControl)
        val closed = AtomicBoolean()
        val release = { if (closed.compareAndSet(false, true)) lease.close() }
        try { retainUntilExit(release) }
        catch (failure: Throwable) { runCatching { release() }; throw failure }
    }
}
