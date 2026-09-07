package com.kardinal.vpncontrol.desktop

import org.junit.Assume.assumeTrue
import java.nio.file.Files
import java.util.concurrent.TimeUnit
import kotlin.test.*

/** Native coreutils coverage of the real pre-install receiver, isolated from privileged worker entry. */
class DesktopLinuxInstallPipeTest {
    private val job = "00000000-0000-0000-0000-000000000001"
    private fun functions(): String {
        val source = DesktopLinuxCapturedInstallWorker.arguments(job, 123)[4]
        return listOf("require_uint", "read_request", "receive_bytes", "receive_request").joinToString("\n") { name ->
            "$name() {" + source.substringAfter("$name() {").substringBefore("\n}") + "\n}\n"
        }
    }
    private fun request() = DesktopLinuxInstallRequest(job, 123, 456, 1000, "deb", "a".repeat(64), 12,
        "/unused/package.deb", "/opt/vpn-control/bin/vpn-control", "/unused/state").encode()

    @Test fun framedRequestRejectsTruncationAndByteCountMismatch() {
        assumeTrue(System.getProperty("os.name").startsWith("Linux", true))
        val record = request()
        fun frame(size: Int) = "%06d\n".format(java.util.Locale.ROOT, size).encodeToByteArray()
        for ((input, accepted) in listOf((frame(record.size) + record) to true,
            (frame(record.size) + record.dropLast(1)) to false,
            (frame(record.size + 1) + record) to false,
            (frame(record.size - 1) + record) to false,
            ("999999\n".encodeToByteArray()) to false)) {
            val directory = Files.createTempDirectory("vpn-install-frame-")
            try {
                val script = "set -eu\n" + functions() + """
                    exec 6<&0
                    job_path=${'$'}1
                    owner_pid=123; owner_start=456; reader_pid=
                    is_cancelled() { return 1; }
                    same_process() { return 0; }
                    publish_receipt() { printf 'UNEXPECTED'; }
                    receive_request
                    printf 'PARSED'
                """.trimIndent()
                val process = ProcessBuilder("/bin/sh", "-c", script, "pipe-test", directory.toString()).redirectErrorStream(true).start()
                process.outputStream.use { it.write(input) }
                assertTrue(process.waitFor(5, TimeUnit.SECONDS))
                val output = process.inputStream.bufferedReader().readText()
                if (accepted) { assertEquals(0, process.exitValue(), output); assertEquals("PARSED", output) }
                else assertNotEquals(0, process.exitValue(), output)
            } finally {
                Files.deleteIfExists(directory.resolve("frame")); Files.deleteIfExists(directory.resolve("request")); Files.delete(directory)
            }
        }
    }

    @Test fun cancellationStopsOnlyThePendingInputReaderWithoutWaitingForPipeEof() {
        assumeTrue(System.getProperty("os.name").startsWith("Linux", true))
        val directory = Files.createTempDirectory("vpn-install-cancel-reader-")
        try {
            val script = "set -eu\n" + functions() + """
                exec 6<&0
                owner_pid=123; owner_start=456; reader_pid=
                is_cancelled() { return 0; }
                same_process() { return 0; }
                publish_receipt() { printf '%s' "${'$'}1"; }
                receive_bytes 37 "${'$'}1/commit"
                printf 'UNEXPECTED_SUCCESS'
            """.trimIndent()
            val process = ProcessBuilder("/bin/sh", "-c", script, "pipe-test", directory.toString()).redirectErrorStream(true).start()
            try {
                // Keep the producer open and silent. Cancellation must terminate the receiver anyway.
                assertTrue(process.waitFor(5, TimeUnit.SECONDS))
                assertEquals(0, process.exitValue())
                assertEquals("CANCELLED", process.inputStream.bufferedReader().readText())
            } finally { process.outputStream.close() }
        } finally { Files.deleteIfExists(directory.resolve("commit")); Files.delete(directory) }
    }
}
