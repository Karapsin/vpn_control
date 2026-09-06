package com.kardinal.vpncontrol.desktop

import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

internal class DesktopAdbProcessResult(val exitCode: Int, val stdout: ByteArray, val stderr: ByteArray) {
    override fun toString() = "DesktopAdbProcessResult(exitCode=$exitCode, output=<redacted>)"
}

/** No host shell, temporary request files, inherited stdin, or unbounded output buffers. */
internal class DesktopAdbProcess(private val commandPrefix: List<String> = listOf("adb")) {
    fun execute(arguments: List<String>, input: ByteArray, timeoutMillis: Long): DesktopAdbProcessResult {
        val process = ProcessBuilder(commandPrefix + arguments).start()
        val workers = Executors.newFixedThreadPool(3) { task -> Thread(task, "adb-client-io").apply { isDaemon = true } }
        try {
            fun read(stream: java.io.InputStream, limit: Int): ByteArray = stream.use {
                val bytes = it.readNBytes(limit + 1)
                if (bytes.size > limit) {
                    process.destroyForcibly()
                    throw IllegalArgumentException("INCOMPATIBLE_PROTOCOL")
                }
                bytes
            }
            val stdout = workers.submit(Callable { read(process.inputStream, 1_048_576) })
            val stderr = workers.submit(Callable { read(process.errorStream, 16_384) })
            val writer = workers.submit(Callable { process.outputStream.use { it.write(input) } })
            if (!process.waitFor(timeoutMillis.coerceAtLeast(1), TimeUnit.MILLISECONDS)) {
                throw java.util.concurrent.TimeoutException("TIMEOUT")
            }
            writer.get(1, TimeUnit.SECONDS)
            return DesktopAdbProcessResult(process.exitValue(), stdout.get(1, TimeUnit.SECONDS), stderr.get(1, TimeUnit.SECONDS))
        } finally {
            if (process.isAlive) {
                process.destroyForcibly()
                process.waitFor(2, TimeUnit.SECONDS)
            }
            runCatching { process.outputStream.close() }
            runCatching { process.inputStream.close() }
            runCatching { process.errorStream.close() }
            workers.shutdownNow()
        }
    }
}
