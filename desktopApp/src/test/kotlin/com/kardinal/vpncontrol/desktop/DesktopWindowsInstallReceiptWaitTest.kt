package com.kardinal.vpncontrol.desktop

import java.io.ByteArrayOutputStream
import java.util.Base64
import java.util.concurrent.TimeUnit
import java.util.zip.GZIPOutputStream
import org.junit.Assume.assumeTrue
import kotlin.test.*

class DesktopWindowsInstallReceiptWaitTest {
    @Test fun originalWorkerWaitsForFirstPublicationButRejectsLaterLossAndCorruption() {
        assumeTrue(System.getProperty("os.name").startsWith("Windows", true))
        val worker = javaClass.getResourceAsStream("/windows-install-user.ps1")!!.use { it.readBytes() }
        val compressed = ByteArrayOutputStream()
        GZIPOutputStream(compressed).use { it.write(worker) }
        val template = javaClass.getResourceAsStream("/windows-install-receipt-wait.ps1")!!.bufferedReader().use { it.readText() }
        val script = template.replace("__CAPTURED_WORKER_GZIP__", Base64.getEncoder().encodeToString(compressed.toByteArray()))
        assertTrue(script.length < 30000 && script.all { it.code < 128 })
        val process = ProcessBuilder("powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script)
            .redirectErrorStream(true).start()
        try {
            assertTrue(process.waitFor(15, TimeUnit.SECONDS), "Fixed receipt wait fixture timed out")
            val output = process.inputStream.bufferedReader().readText()
            assertEquals(0, process.exitValue(), output)
            assertContains(output, "FIXED_RECEIPT_WAIT_OK")
        } finally { if (process.isAlive) process.destroyForcibly() }
    }
}
