package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.StatusMessages
import java.nio.file.Path

internal object DesktopDiagnosticsExportLogic {
    fun destinationSelectionFailureMessage(error: Throwable?): String {
        return error?.message ?: StatusMessages.diagnosticsDestinationOpenFailed()
    }

    fun exportResultMessage(result: Result<Path>): String {
        return result.fold(
            onSuccess = { path -> StatusMessages.diagnosticsExportedTo(path.toString()) },
            onFailure = { error -> error.message ?: StatusMessages.diagnosticsExportFailed() },
        )
    }
}
