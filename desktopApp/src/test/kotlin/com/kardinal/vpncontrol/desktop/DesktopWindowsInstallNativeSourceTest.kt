package com.kardinal.vpncontrol.desktop

import java.util.Base64
import java.util.concurrent.TimeUnit
import kotlin.test.*
import org.junit.Assume.assumeTrue

class DesktopWindowsInstallNativeSourceTest {
    @Test fun actualFixedPowerShellNativeSourceCompilesAndRejectsUnsafeAclFixtures() {
        assumeTrue(System.getProperty("os.name").startsWith("Windows", true))
        val source = javaClass.getResourceAsStream("/windows-install-native.cs")!!.use { it.readBytes() }
        val compressed = java.io.ByteArrayOutputStream()
        java.util.zip.GZIPOutputStream(compressed).use { it.write(source) }
        val encodedSource = Base64.getEncoder().encodeToString(compressed.toByteArray())
        val unicodeSuffix = Base64.getEncoder().encodeToString("Юникод 空間".toByteArray(Charsets.UTF_8))
        fun fixture(value: String) = Base64.getEncoder().encodeToString(value.toByteArray(Charsets.UTF_8))
        val validRecord = fixture("""{"a":1,"b":"test"}""")
        val invalidRecords = listOf("""{"a":1,"a":2}""", """{"a":01}""", """{"a":"\uD800"}""", """{"a":{}}""")
            .joinToString(", ") { "'${fixture(it)}'" }
        val script = """
            ${'$'}ErrorActionPreference='Stop'
            ${'$'}gzip=[IO.Compression.GZipStream]::new([IO.MemoryStream]::new([Convert]::FromBase64String('$encodedSource')), [IO.Compression.CompressionMode]::Decompress)
            ${'$'}reader=[IO.StreamReader]::new(${'$'}gzip, [Text.Encoding]::UTF8)
            try { Add-Type -TypeDefinition (${'$'}reader.ReadToEnd()) } finally { ${'$'}reader.Dispose() }
            [VpnInstallNative]::ValidateSecurity('O:BAG:BAD:P(A;;FA;;;BA)(A;;GR;;;BU)', ${'$'}false, ${'$'}null)
            ${'$'}record=[VpnInstallNative]::ParseFlatRecord([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('$validRecord')))
            if (${'$'}record.Count -ne 2 -or ${'$'}record['a'] -ne 1) { throw 'Strict input parser failed' }
            foreach (${'$'}invalid in @($invalidRecords)) {
                ${'$'}rejected=${'$'}false
                try { [VpnInstallNative]::ParseFlatRecord([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(${'$'}invalid))) | Out-Null } catch { ${'$'}rejected=${'$'}true }
                if (-not ${'$'}rejected) { throw 'Invalid private input accepted' }
            }
            foreach (${ '$' }sddl in @('O:BAG:BAD:P(A;;FA;;;WD)', 'O:BAG:BAD:P(A;;WD;;;BU)', 'O:BAG:BAD:P(A;;DC;;;BU)')) {
                ${'$'}rejected=${'$'}false
                try { [VpnInstallNative]::ValidateSecurity(${ '$' }sddl, ${'$'}false, ${'$'}null) } catch { ${'$'}rejected=${'$'}true }
                if (-not ${'$'}rejected) { throw 'Unsafe ACL accepted' }
            }
            ${'$'}sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
            ${'$'}processPin=[VpnInstallNative+ProcessPin]::new([uint32]${'$'}PID)
            try {
                if (${'$'}processPin.Exited -or ${'$'}processPin.Principal -ne ${'$'}sid -or ${'$'}processPin.Pid -ne ${'$'}PID) { throw 'Process identity mismatch' }
                ${'$'}started=([DateTimeOffset]([Diagnostics.Process]::GetCurrentProcess().StartTime.ToUniversalTime())).ToUnixTimeMilliseconds()
                if (${'$'}processPin.StartedAtEpochMillis -ne ${'$'}started) { throw 'Process start mismatch' }
                if (-not ${'$'}processPin.LocalAppData()) { throw 'Native user folder unavailable' }
            } finally { ${'$'}processPin.Dispose() }
            if (-not [VpnInstallNative]::ProgramData()) { throw 'Native machine folder unavailable' }
            ${'$'}fixture=Join-Path ([IO.Path]::GetTempPath()) ('vpn-install-native-'+[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('$unicodeSuffix'))+'-'+[Guid]::NewGuid().ToString())
            [VpnInstallNative]::CreateDirectory(${'$'}fixture, ('O:'+${'$'}sid+'G:'+${'$'}sid+'D:P(A;OICI;FA;;;'+${'$'}sid+')'))
            ${'$'}directory=${'$'}null; ${'$'}file=${'$'}null
            try {
                ${'$'}directory=[VpnInstallNative]::OpenDirectory(${'$'}fixture)
                [VpnInstallNative]::Inspect(${'$'}directory, ${'$'}true, ${'$'}false, ${'$'}sid)
                ${'$'}readyRecord=Join-Path ${'$'}fixture 'worker-ready.json'
                [VpnInstallNative]::PublishPrivateRecord(${'$'}readyRecord, ${'$'}sid, [Text.Encoding]::UTF8.GetBytes('complete-original'))
                if ([IO.File]::ReadAllText(${'$'}readyRecord) -cne 'complete-original') { throw 'Private record was not published under parent pin' }
                ${'$'}rejected=${'$'}false
                try { [VpnInstallNative]::PublishPrivateRecord(${'$'}readyRecord, ${'$'}sid, [Text.Encoding]::UTF8.GetBytes('replacement')) }
                catch { ${'$'}rejected=${'$'}true }
                if (-not ${'$'}rejected -or [IO.File]::ReadAllText(${'$'}readyRecord) -cne 'complete-original') { throw 'Private record replaced prior acknowledgment' }
                ${'$'}resultRecord=Join-Path ${'$'}fixture 'worker-result.json'
                [VpnInstallNative]::PublishPrivateRecord(${'$'}resultRecord, ${'$'}sid, [Text.Encoding]::UTF8.GetBytes('complete-result'))
                if ([IO.File]::ReadAllText(${'$'}resultRecord) -cne 'complete-result') { throw 'Private result was not published' }
                ${'$'}installationId=[VpnInstallNative]::InstallationId(${'$'}directory)
                if (${'$'}installationId -notmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}${'$'}') { throw 'Invalid install identity' }
                ${'$'}alias=[VpnInstallNative]::OpenDirectory(${'$'}fixture.ToUpperInvariant())
                try {
                    if ([VpnInstallNative]::InstallationId(${'$'}alias) -ne ${'$'}installationId) { throw 'Case alias changed installation gate' }
                } finally { ${'$'}alias.Dispose() }
                ${'$'}rejected=${'$'}false
                try { [VpnInstallNative]::Inspect(${'$'}directory, ${'$'}true, ${'$'}false, ${'$'}null) } catch { ${'$'}rejected=${'$'}true }
                if (-not ${'$'}rejected) { throw 'User-owned protected output accepted' }
                ${'$'}payload=Join-Path ${'$'}fixture 'payload.msi'
                [IO.File]::WriteAllText(${'$'}payload, 'fixture')
                ${'$'}file=[VpnInstallNative]::OpenRead(${'$'}payload, ${'$'}false)
                [VpnInstallNative]::Inspect(${'$'}file, ${'$'}false, ${'$'}false, ${'$'}sid)
                ${'$'}rejected=${'$'}false
                try { [IO.File]::WriteAllText(${'$'}payload, 'changed') } catch { ${'$'}rejected=${'$'}true }
                if (-not ${'$'}rejected) { throw 'Pinned payload remained writable' }
                ${'$'}gate=Join-Path ${'$'}fixture 'gate'
                ${'$'}writer=[VpnInstallNative]::CreateFile(${'$'}gate, ('O:'+${'$'}sid+'G:'+${'$'}sid+'D:P(A;;FA;;;'+${'$'}sid+')'), [byte[]]::new(17))
                ${'$'}shared=${'$'}null
                try {
                    ${'$'}shared=[VpnInstallNative]::OpenGate(${'$'}gate, ${'$'}false)
                    if (-not [VpnInstallNative]::TryLock(${'$'}shared.SafeFileHandle, 0, ${'$'}false)) { throw 'Shared admission unavailable' }
                    if (-not [VpnInstallNative]::TryLock(${'$'}writer.SafeFileHandle, 16, ${'$'}true)) { throw 'Reservation unavailable' }
                    if ([VpnInstallNative]::TryLock(${'$'}writer.SafeFileHandle, 0, ${'$'}true)) { throw 'Exclusive bypassed shared admission' }
                    [VpnInstallNative]::Unlock(${'$'}shared.SafeFileHandle, 0)
                    if (-not [VpnInstallNative]::TryLock(${'$'}writer.SafeFileHandle, 0, ${'$'}true)) { throw 'Exclusive unavailable after release' }
                    [VpnInstallNative]::Unlock(${'$'}writer.SafeFileHandle, 0)
                    [VpnInstallNative]::Unlock(${'$'}writer.SafeFileHandle, 16)
                } finally {
                    if (${'$'}shared) { ${'$'}shared.Dispose() }
                    ${'$'}writer.Dispose()
                }
            } finally {
                if (${'$'}file) { ${'$'}file.Dispose() }
                if (${'$'}directory) { ${'$'}directory.Dispose() }
                [IO.Directory]::Delete(${'$'}fixture, ${'$'}true)
            }
            Write-Output 'NATIVE_POLICY_OK'
        """.trimIndent()
        assertTrue(script.length < 30000 && script.all { it.code < 128 }, "Captured bootstrap must fit Windows command line")
        val process = ProcessBuilder("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
            .redirectErrorStream(true).start()
        try {
            assertTrue(process.waitFor(30, TimeUnit.SECONDS), "Native policy compile timed out")
            val output = process.inputStream.bufferedReader().readText()
            assertEquals(0, process.exitValue(), output)
            assertTrue(output.contains("NATIVE_POLICY_OK"), output)
        } finally { if (process.isAlive) process.destroyForcibly() }
    }
}
