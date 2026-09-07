package com.kardinal.vpncontrol.desktop

import org.junit.Assume.assumeTrue
import java.io.ByteArrayOutputStream
import java.util.Base64
import java.util.concurrent.TimeUnit
import java.util.zip.GZIPOutputStream
import kotlin.test.*

class DesktopWindowsReparseWitnessNativeTest {
    @Test fun actualAttributesOnlyAttackerCannotEmptyAndRedirectPinnedAncestor() {
        assumeTrue(System.getProperty("os.name").startsWith("Windows", true))
        fun resource(name: String): String {
            val bytes = javaClass.getResourceAsStream("/$name")!!.use { it.readBytes() }
            val output = ByteArrayOutputStream()
            GZIPOutputStream(output).use { it.write(bytes) }
            return Base64.getEncoder().encodeToString(output.toByteArray())
        }
        val native = resource("windows-install-native.cs")
        val probe = resource("windows-reparse-witness-probe.ps1")
        val script = """
            ${'$'}ErrorActionPreference='Stop'
            function Expand-Fixed([string]${'$'}s) {
                ${'$'}gzip=[IO.Compression.GZipStream]::new([IO.MemoryStream]::new([Convert]::FromBase64String(${'$'}s)),[IO.Compression.CompressionMode]::Decompress)
                ${'$'}reader=[IO.StreamReader]::new(${'$'}gzip,[Text.Encoding]::UTF8)
                try { ${'$'}reader.ReadToEnd() } finally { ${'$'}reader.Dispose() }
            }
            Add-Type -TypeDefinition (Expand-Fixed '$native')
            & ([ScriptBlock]::Create((Expand-Fixed '$probe')))
        """.trimIndent()
        assertTrue(script.length < 30000 && script.all { it.code < 128 })
        val process = ProcessBuilder("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
            .redirectErrorStream(true).start()
        try {
            assertTrue(process.waitFor(30, TimeUnit.SECONDS), "Native witness test timed out")
            val bytes = process.inputStream.readNBytes(65537)
            assertTrue(bytes.size <= 65536)
            val output = bytes.toString(Charsets.UTF_8)
            assertEquals(0, process.exitValue(), output)
            assertContains(output, "REPARSE_WITNESS_OK")
        } finally { if (process.isAlive) process.destroyForcibly() }
    }
}
