package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.control.ControlCommitted
import com.kardinal.vpncontrol.model.*
import java.util.UUID
import kotlinx.coroutines.CancellationException

/** The frontend owns the gesture; the typed owner owns admission and runtime work. */
internal class AndroidConnectionActionsService(
    private val controller: MainController,
    private val observation: () -> AndroidRuntimeObservation,
    private val launch: (suspend () -> Unit) -> Unit,
    private val snapshot: suspend () -> ControlCommitted<PersistedState>,
    private val execute: suspend (ControlRequest) -> ControlResult,
    private val updateStatus: suspend (String) -> Unit,
) {
    private var inFlight = false
    private data class Pending(val request: ControlRequest, val mode: AppMode)
    private var pending: Pending? = null

    fun onVpnPermissionGranted() = controller.onVpnPermissionGranted()

    fun toggleVpn() {
        if (inFlight) return
        inFlight = true
        launch {
            var mode = pending?.mode ?: controller.currentState().appMode
            var operation = pending?.request?.command?.operation ?: ControlOperationId.ON
            try {
                val request = pending?.request ?: snapshot().let { captured ->
                    val observed = observation()
                    mode = observed.activeMode ?: captured.value.appMode
                    operation = if (observed.knowledge == AndroidRuntimeKnowledge.RUNNING)
                        ControlOperationId.OFF else ControlOperationId.ON
                    // MainActivity performs VPN consent before this callback. Do not
                    // bypass it or launch a second interactive surface from this adapter.
                    ControlRequest(UUID.randomUUID().toString(), ControlCommand(operation),
                        controllerId = captured.controllerId, ifRevision = captured.revision)
                        .also { pending = Pending(it, mode) }
                }
                val result = execute(request)
                if (!result.final) return@launch // Acceptance is not a successful connection.
                if ("RUNTIME_OUTCOME_UNKNOWN" !in result.warnings) pending = null
                updateStatus(when {
                    result.code == ControlCode.OK && operation == ControlOperationId.OFF -> MainCommandLogic.stoppedConnectionStatus(mode)
                    result.code == ControlCode.OK -> MainCommandLogic.startedConnectionStatus(mode)
                    result.code == ControlCode.CANCELLED && operation == ControlOperationId.OFF -> ConnectionStatusMessages.connectionStopCancelled(mode)
                    result.code == ControlCode.CANCELLED -> ConnectionStatusMessages.connectionStartCancelled(mode)
                    operation == ControlOperationId.OFF -> ConnectionStatusMessages.connectionStopFailed(mode)
                    else -> ConnectionStatusMessages.connectionStartFailed(mode)
                })
            } catch (error: CancellationException) {
                // Keep the exact request: cancelling this wait does not cancel the owner.
                throw error
            } catch (_: Exception) {
                // An exception may follow dispatch. A later click retries the identity,
                // never a fresh toggle against a potentially changed running state.
                updateStatus(if (operation == ControlOperationId.OFF)
                    ConnectionStatusMessages.connectionStopFailed(mode)
                else ConnectionStatusMessages.connectionStartFailed(mode))
            } finally {
                inFlight = false
            }
        }
    }
}
