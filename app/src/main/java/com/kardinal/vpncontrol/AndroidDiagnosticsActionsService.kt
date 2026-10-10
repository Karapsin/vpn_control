package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.control.ControlCommitted
import com.kardinal.vpncontrol.model.*
import java.util.UUID
import kotlinx.coroutines.CancellationException

internal class AndroidDiagnosticsActionsService(
    private val launch: (suspend () -> Unit) -> Unit,
    private val setBusy: (Boolean) -> Unit,
    private val updateStatus: suspend (String) -> Unit,
    private val snapshot: suspend () -> ControlCommitted<PersistedState>,
    private val execute: suspend (ControlRequest) -> ControlResult,
    private val shareReport: suspend (String) -> Result<*>,
) {
    private var inFlight = false
    private var pendingRequest: ControlRequest? = null

    fun exportDiagnostics() {
        if (inFlight) return
        inFlight = true
        launch {
            setBusy(true)
            try {
                val request = pendingRequest ?: snapshot().let { captured ->
                    ControlRequest(UUID.randomUUID().toString(), ControlCommand(ControlOperationId.DIAGNOSTICS_EXPORT),
                        controllerId = captured.controllerId).also { pendingRequest = it }
                }
                val result = execute(request)
                if (!result.final) return@launch
                if (result.code != ControlCode.OK) {
                    pendingRequest = null
                    updateStatus(DiagnosticsStatusMessages.diagnosticsExportFailed())
                    return@launch
                }
                val content = (result.data["content"] as? ControlValue.Text)?.value
                if (content == null) {
                    updateStatus(DiagnosticsStatusMessages.diagnosticsExportFailed())
                    return@launch
                }
                // Sharing is presentation. It consumes the exact retained report and
                // cannot recollect diagnostics or replay the accepted owner operation.
                val shared = shareReport(content)
                if (shared.isSuccess) pendingRequest = null
                updateStatus(if (shared.isSuccess) DiagnosticsStatusMessages.diagnosticsExportOpened()
                    else DiagnosticsStatusMessages.diagnosticsDestinationOpenFailed())
            } catch (error: CancellationException) {
                throw error // The exact request remains recoverable after a lost wait.
            } catch (_: Exception) {
                updateStatus(DiagnosticsStatusMessages.diagnosticsExportFailed())
            } finally {
                setBusy(false)
                inFlight = false
            }
        }
    }
}
