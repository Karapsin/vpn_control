package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.DiagnosticsStatusMessages
import java.nio.file.Paths
import kotlin.test.Test
import kotlin.test.assertEquals

class DesktopDiagnosticsExportLogicTest {
    @Test
    fun destinationSelectionFailureFallsBackToStructuredStatus() {
        val message = DesktopDiagnosticsExportLogic.destinationSelectionFailureMessage(null)

        assertEquals(DiagnosticsStatusMessages.diagnosticsDestinationOpenFailed(), message)
    }

    @Test
    fun destinationSelectionFailurePreservesDialogError() {
        val message = DesktopDiagnosticsExportLogic.destinationSelectionFailureMessage(
            IllegalStateException("dialog failed"),
        )

        assertEquals("dialog failed", message)
    }

    @Test
    fun exportResultSuccessUsesStructuredStatus() {
        val target = Paths.get("/tmp/vpn-control-diagnostics.txt")
        val message = DesktopDiagnosticsExportLogic.exportResultMessage(Result.success(target))

        assertEquals(DiagnosticsStatusMessages.diagnosticsExportedTo(target.toString()), message)
    }

    @Test
    fun exportResultFailureFallsBackToStructuredStatus() {
        val message = DesktopDiagnosticsExportLogic.exportResultMessage(Result.failure(IllegalStateException()))

        assertEquals(DiagnosticsStatusMessages.diagnosticsExportFailed(), message)
    }
}
