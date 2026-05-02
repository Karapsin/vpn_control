package com.kardinal.vpncontrol

internal class AndroidDiagnosticsActionsService(
    private val launch: (suspend () -> Unit) -> Unit,
    private val setBusy: (Boolean) -> Unit,
    private val updateStatus: suspend (String) -> Unit,
    private val exportAndShare: suspend () -> Result<*>,
) {
    fun exportDiagnostics() {
        launch {
            setBusy(true)
            val result = exportAndShare()
            updateStatus(
                result.fold(
                    onSuccess = { "Diagnostics export opened" },
                    onFailure = { it.message ?: "Diagnostics export failed" },
                ),
            )
            setBusy(false)
        }
    }
}
