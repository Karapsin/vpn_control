package com.kardinal.vpncontrol.desktop

/** Retains immutable inputs for one known runtime generation until rollback is no longer possible. */
interface DesktopRuntimeRestoreLease : AutoCloseable {
    /** Starts a fresh child from retained immutable inputs, never pending settings. */
    suspend fun restore(): Result<DesktopRuntimeSession>
}
