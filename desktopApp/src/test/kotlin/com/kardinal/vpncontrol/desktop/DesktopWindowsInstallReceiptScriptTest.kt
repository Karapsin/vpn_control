package com.kardinal.vpncontrol.desktop

import org.junit.Assume.assumeTrue
import java.util.Base64
import java.util.concurrent.TimeUnit
import kotlin.test.*

/** Exercises the actual fixed publisher function with memory-only native IO, without elevation. */
class DesktopWindowsInstallReceiptScriptTest {
    @Test fun fixedPublisherRejectsPhaseRegressionAndTerminalRewrite() {
        assumeTrue(System.getProperty("os.name").startsWith("Windows", true))
        val source = javaClass.getResourceAsStream("/windows-install-coordinator.ps1")!!.use { it.readBytes() }
        val encoded = Base64.getEncoder().encodeToString(source)
        val script = """
            ${'$'}ErrorActionPreference='Stop'
            Add-Type -TypeDefinition 'public static class VpnInstallNative { public static System.IO.MemoryStream CreateFile(string p,string s,byte[] b) { return new System.IO.MemoryStream(b); } public static void ReplaceReceipt(object h,string n) {} }'
            ${'$'}tokens=${'$'}null; ${'$'}errors=${'$'}null
            ${'$'}ast=[Management.Automation.Language.Parser]::ParseInput([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('$encoded')),[ref]${'$'}tokens,[ref]${'$'}errors)
            if (${'$'}errors.Count) { throw 'Invalid coordinator syntax' }
            ${'$'}functions=@(${'$'}ast.FindAll({param(${'$'}n) ${'$'}n -is [Management.Automation.Language.FunctionDefinitionAst] -and ${'$'}n.Name -ceq 'Publish-Receipt'},${'$'}false))
            if (${'$'}functions.Count -ne 1) { throw 'Missing fixed publisher' }
            . ([ScriptBlock]::Create(${'$'}functions[0].Extent.Text))
            ${'$'}JobId='00000000-0000-0000-0000-000000000001'; ${'$'}script:jobPath='C:\unused-fixture'; ${'$'}script:jobHandle=${'$'}null
            ${'$'}script:sequence=-1L; ${'$'}script:phase=${'$'}null
            Publish-Receipt 'PREPARING'
            Publish-Receipt 'AUTHORIZED'
            ${'$'}rejected=${'$'}false
            try { Publish-Receipt 'PREPARING' } catch { ${'$'}rejected=${'$'}true }
            if (-not ${'$'}rejected) { throw 'Publisher accepted phase regression' }
            if (${'$'}script:sequence -ne 1) { throw 'Rejected receipt changed sequence' }
            Publish-Receipt 'CANCELLED' 'CANCELLED'
            ${'$'}rejected=${'$'}false
            try { Publish-Receipt 'AUTHORIZED' } catch { ${'$'}rejected=${'$'}true }
            if (-not ${'$'}rejected) { throw 'Publisher rewrote terminal receipt' }
            if (${'$'}script:sequence -ne 2) { throw 'Terminal rewrite changed sequence' }
            'FIXED_RECEIPT_STATE_OK'
        """.trimIndent()
        val process = ProcessBuilder("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
            .redirectErrorStream(true).start()
        try {
            assertTrue(process.waitFor(30, TimeUnit.SECONDS), "Fixed receipt test timed out")
            val output = process.inputStream.bufferedReader().readText()
            assertEquals(0, process.exitValue(), output)
            assertContains(output, "FIXED_RECEIPT_STATE_OK")
        } finally { if (process.isAlive) process.destroyForcibly() }
    }
}
