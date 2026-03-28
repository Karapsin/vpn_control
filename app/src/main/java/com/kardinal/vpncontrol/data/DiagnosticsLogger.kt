package com.kardinal.vpncontrol.data

import android.content.Context
import java.io.File
import java.time.Instant

object DiagnosticsLogger {
    private const val maxBytes = 512 * 1024L
    private const val trimTargetBytes = 256 * 1024
    private val lock = Any()

    fun append(context: Context, message: String) {
        synchronized(lock) {
            val file = RuntimeFiles.diagnosticsLogFile(context)
            file.parentFile?.mkdirs()
            trimIfNeeded(file)
            file.appendText("${Instant.now()} $message\n")
        }
    }

    fun append(context: Context, message: String, error: Throwable) {
        val summary = buildString {
            append(message)
            append(": ")
            append(error.javaClass.simpleName)
            error.message?.takeIf { it.isNotBlank() }?.let {
                append(": ")
                append(it)
            }
            append('\n')
            append(error.stackTraceToString())
        }
        append(context, summary.trimEnd())
    }

    private fun trimIfNeeded(file: File) {
        if (!file.exists() || file.length() < maxBytes) {
            return
        }
        val bytes = file.readBytes()
        val start = (bytes.size - trimTargetBytes).coerceAtLeast(0)
        file.writeBytes(bytes.copyOfRange(start, bytes.size))
    }
}
