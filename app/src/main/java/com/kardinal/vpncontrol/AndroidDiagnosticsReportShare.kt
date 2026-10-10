package com.kardinal.vpncontrol

import java.io.File
import kotlinx.coroutines.CancellationException
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter

/** The existing GUI filename/writer, now accepting completed owner content only. */
internal fun writeAndroidDiagnosticsReport(directory: File, report: String): File {
    directory.mkdirs()
    val timestamp = DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss")
        .withZone(ZoneId.systemDefault()).format(Instant.now())
    return File(directory, "vpn-control-diagnostics-$timestamp.txt").also { it.writeText(report, Charsets.UTF_8) }
}

/** The OS writer/chooser are seams; this boundary must retain cancellation. */
internal suspend fun shareCompletedAndroidDiagnosticsReport(
    report: String,
    writeReport: suspend (String) -> File,
    openShare: suspend (File) -> Unit,
): Result<File> = try {
    val file = writeReport(report)
    openShare(file)
    Result.success(file)
} catch (error: CancellationException) {
    throw error
} catch (error: Exception) {
    Result.failure(error)
}
