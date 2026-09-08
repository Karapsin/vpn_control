package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.ControlCode

/**
 * The adapter's authorization lifetime. It keeps the immediate receipt wait and exact child
 * collector together so both immediate and owner-maintenance observation share one reader.
 */
internal class DesktopMacAuthorizationLifetime(
    private val awaitAuthorization: suspend () -> Result<Unit>,
    private val collector: DesktopMacAuthorizationCollector,
) {
    suspend fun awaitInitial(): Result<Unit> = awaitAuthorization()

    /** The same bounded collector serves immediate and maintenance-time observation. */
    fun lateAuthorization(): ControlCode? = collector.poll()
}
