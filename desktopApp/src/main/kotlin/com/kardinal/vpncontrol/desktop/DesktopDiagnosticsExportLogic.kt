package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.DiagnosticsStatusMessages
import java.nio.file.Path

internal object DesktopDiagnosticsExportLogic {
    fun destinationSelectionFailureMessage(error: Throwable?): String {
        return error?.message ?: DiagnosticsStatusMessages.diagnosticsDestinationOpenFailed()
    }

    fun exportResultMessage(result: Result<Path>): String {
        return result.fold(
            onSuccess = { path -> DiagnosticsStatusMessages.diagnosticsExportedTo(path.toString()) },
            onFailure = { error -> error.message ?: DiagnosticsStatusMessages.diagnosticsExportFailed() },
        )
    }
}
