package com.kardinal.vpncontrol.desktop

import java.io.ByteArrayOutputStream
import java.util.Base64
import java.util.concurrent.TimeUnit
import java.util.zip.GZIPOutputStream
import org.junit.Assume.assumeTrue
import kotlin.test.*

/** Ordinary-user Windows CI exercises the captured helper's real IO with a scoped test SID policy. */
class DesktopWindowsInstallReceiptNativeTest {
    @Test fun fixedPublisherKeepsDirectoryPinsAndRetainedReadersAcrossAtomicReplacement() {
        assumeTrue(System.getProperty("os.name").startsWith("Windows", true))
        val native = javaClass.getResourceAsStream("/windows-install-native.cs")!!.use { it.readBytes() }
        val compressed = ByteArrayOutputStream()
        GZIPOutputStream(compressed).use { it.write(native) }
        val template = javaClass.getResourceAsStream("/windows-install-receipt-native.ps1")!!.bufferedReader().use { it.readText() }
        val script = template.replace("__CAPTURED_NATIVE_GZIP__", Base64.getEncoder().encodeToString(compressed.toByteArray()))
        assertTrue(script.length < 30000 && script.all { it.code < 128 })
        val process = ProcessBuilder("powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script)
            .redirectErrorStream(true).start()
        try {
            assertTrue(process.waitFor(30, TimeUnit.SECONDS), "Fixed native receipt fixture timed out")
            val output = process.inputStream.bufferedReader().readText()
            assertEquals(0, process.exitValue(), output)
            assertContains(output, "FIXED_NATIVE_RECEIPT_OK")
        } finally { if (process.isAlive) process.destroyForcibly() }
    }
}
