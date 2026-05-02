package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.StatusMessageKey
import com.kardinal.vpncontrol.model.StatusMessages
import java.nio.file.Paths
import kotlin.test.Test
import kotlin.test.assertEquals

class DesktopDiagnosticsExportLogicTest {
    @Test
    fun destinationSelectionFailureFallsBackToStructuredStatus() {
        val message = DesktopDiagnosticsExportLogic.destinationSelectionFailureMessage(null)

        assertEquals(StatusMessageKey.DIAGNOSTICS_DESTINATION_OPEN_FAILED, StatusMessages.decode(message)?.key)
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
        val decoded = StatusMessages.decode(message)

        assertEquals(StatusMessageKey.DIAGNOSTICS_EXPORTED_TO, decoded?.key)
        assertEquals(listOf(target.toString()), decoded?.args)
    }

    @Test
    fun exportResultFailureFallsBackToStructuredStatus() {
        val message = DesktopDiagnosticsExportLogic.exportResultMessage(Result.failure(IllegalStateException()))

        assertEquals(StatusMessageKey.DIAGNOSTICS_EXPORT_FAILED, StatusMessages.decode(message)?.key)
    }
}
