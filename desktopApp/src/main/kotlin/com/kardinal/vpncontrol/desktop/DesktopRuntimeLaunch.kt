package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.ControlCode
import java.nio.file.Path

/** Immutable actual inputs remain available until replacement and any recovery have completed. */
internal class DesktopRuntimeLaunch(
    val appMode: AppMode,
    val listenPort: Int,
    val managementPort: Int,
    val interfaceName: String?,
    val configJson: String,
    val configPath: Path,
    val logFile: Path,
    val privateKeyPath: Path?,
) {
    internal var captured: DesktopWindowsCapturedConfiguration? = null
    fun session(process: DesktopRuntimeProcess) = DesktopRuntimeSession(
        appMode, listenPort, managementPort, interfaceName, configJson, logFile, process.pid(),
        resourceWarnings = process.resourceWarnings.toList(),
    )
    override fun toString() = "DesktopRuntimeLaunch(<redacted>)"
}

/** Native boundaries are injectable so manager transitions never need a host runtime in tests. */
internal interface DesktopRuntimeManagerNative {
    fun preflight(launch: DesktopRuntimeLaunch): DesktopPreflightReport
    fun prepare(launch: DesktopRuntimeLaunch): DesktopPreparedRuntimeProcess
    suspend fun awaitReady(process: DesktopRuntimeProcess, launch: DesktopRuntimeLaunch): Boolean
}

/** A new recovered child must produce a new public runtime identity, even with the same settings. */
internal class DesktopRuntimeTransitionFailure(
    val originalCode: ControlCode,
    val recoveredSession: DesktopRuntimeSession? = null,
    val recoveryFailed: Boolean = false,
    val resourceWarnings: List<DesktopRuntimeResourceWarning> = emptyList(),
) : java.io.IOException(if (recoveryFailed) "ROLLBACK_FAILED" else originalCode.name)
