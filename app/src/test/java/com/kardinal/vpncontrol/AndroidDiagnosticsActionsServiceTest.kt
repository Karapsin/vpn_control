package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.model.StatusMessages
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

class AndroidDiagnosticsActionsServiceTest {
    @Test
    fun exportDiagnosticsReportsSuccessAndClearsBusy() {
        var busy = false
        val statuses = mutableListOf<String>()
        val service = service(
            setBusy = { busy = it },
            updateStatus = { statuses += it },
            exportAndShare = { Result.success("file") },
        )

        service.exportDiagnostics()

        assertFalse(busy)
        assertEquals(listOf(StatusMessages.diagnosticsExportOpened()), statuses)
    }

    @Test
    fun exportDiagnosticsReportsFailureAndClearsBusy() {
        var busy = false
        val statuses = mutableListOf<String>()
        val service = service(
            setBusy = { busy = it },
            updateStatus = { statuses += it },
            exportAndShare = { Result.failure<String>(IllegalStateException("share failed")) },
        )

        service.exportDiagnostics()

        assertFalse(busy)
        assertEquals(listOf("share failed"), statuses)
    }

    private fun service(
        setBusy: (Boolean) -> Unit,
        updateStatus: suspend (String) -> Unit,
        exportAndShare: suspend () -> Result<*>,
    ): AndroidDiagnosticsActionsService {
        return AndroidDiagnosticsActionsService(
            launch = { block -> runBlocking { block() } },
            setBusy = setBusy,
            updateStatus = updateStatus,
            exportAndShare = exportAndShare,
        )
    }
}
