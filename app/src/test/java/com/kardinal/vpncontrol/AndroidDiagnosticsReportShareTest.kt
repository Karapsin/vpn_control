package com.kardinal.vpncontrol

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test

class AndroidDiagnosticsReportShareTest {
    @Test fun cancellationDuringWriterIsPropagatedBeforeChooser() = runBlocking {
        var opened = false
        var propagated = false
        try {
            shareCompletedAndroidDiagnosticsReport("completed owner report",
                { throw CancellationException("OWN writer cancellation") }, { opened = true })
        } catch (_: CancellationException) { propagated = true }
        assertTrue("Writer cancellation must propagate out of presentation boundary", propagated)
        assertFalse(opened)
    }
    @Test fun cancellationDuringChooserIsPropagatedAfterExactUtf8Write() = runBlocking {
        val directory = java.nio.file.Files.createTempDirectory("diagnostics-share-cancel-").toFile()
        val report = "OWNER-REPORT-✓\n"
        var propagated = false
        try {
            try {
                shareCompletedAndroidDiagnosticsReport(report,
                    { writeAndroidDiagnosticsReport(directory, it).also { file ->
                        assertArrayEquals(report.toByteArray(Charsets.UTF_8), file.readBytes())
                    } }, { throw CancellationException("OWN chooser cancellation") })
            } catch (_: CancellationException) { propagated = true }
            assertTrue("Chooser cancellation must propagate out of presentation boundary", propagated)
        } finally { check(directory.deleteRecursively()) }
    }
}
