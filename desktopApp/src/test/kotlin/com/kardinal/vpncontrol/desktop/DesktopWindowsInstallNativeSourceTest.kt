package com.kardinal.vpncontrol.desktop

import java.util.Base64
import java.util.concurrent.TimeUnit
import kotlin.test.*
import org.junit.Assume.assumeTrue

class DesktopWindowsInstallNativeSourceTest {
    @Test fun physicalImageAliasesAndUnknownReadersCannotReachReplacement() {
        assumeTrue(System.getProperty("os.name").startsWith("Windows", true))
        val common = javaClass.getResourceAsStream("/windows-install-common.ps1")!!.use { it.readBytes() }
        val encoded = Base64.getEncoder().encodeToString(common)
        val script = """
            ${'$'}ErrorActionPreference='Stop'
            . ([ScriptBlock]::Create([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('$encoded'))))
            function New-TestCopy {
                ${'$'}copy=[pscustomobject]@{Id=100;HasExited=${'$'}false}
                ${'$'}copy|Add-Member ScriptMethod Dispose { ${'$'}script:disposed++ }
                return ${'$'}copy
            }
            ${'$'}cases=@(
                @{image='X:\ALIAS\VPN-CO~1.EXE';same=${'$'}true;unknown=${'$'}false;blocked=${'$'}true},
                @{image='C:\OTHER\VPN-CO~2.EXE';same=${'$'}true;unknown=${'$'}false;blocked=${'$'}true},
                @{image='C:\other-app\vpn-control.exe';same=${'$'}false;unknown=${'$'}false;blocked=${'$'}false},
                @{image='C:\unknown\vpn-control-cli.exe';same=${'$'}false;unknown=${'$'}true;blocked=${'$'}true}
            )
            foreach (${'$'}case in ${'$'}cases) {
                ${'$'}script:case=${'$'}case; ${'$'}script:disposed=0; ${'$'}caught=${'$'}null
                try {
                    Assert-NoInstallationCopies @((New-TestCopy)) 'C:\installed\vpn-control.exe' @() ${'$'}null `
                        -ReadImage { param(${'$'}Id) return ${'$'}script:case.image } `
                        -SameImage { param(${'$'}Image,${'$'}Captured) if (${'$'}script:case.unknown) { throw 'native identity unavailable' }; return ${'$'}script:case.same }
                } catch { ${'$'}caught=${'$'}_.Exception.Message }
                if (${'$'}case.blocked -and ${'$'}caught -cne 'BUSY') { throw 'Aliased or unknown live copy reached replacement' }
                if (-not ${'$'}case.blocked -and ${'$'}null -ne ${'$'}caught) { throw 'Unrelated physical installation was blocked' }
                if (${'$'}script:disposed -ne 1) { throw 'Process snapshot ownership lost' }
            }
            Write-Output 'PHYSICAL_COPIES_OK'
        """.trimIndent()
        assertTrue(script.length < 30000 && script.all { it.code < 128 })
        val process = ProcessBuilder("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
            .redirectErrorStream(true).start()
        try {
            assertTrue(process.waitFor(30, TimeUnit.SECONDS), "Copy admission regression timed out")
            val output = process.inputStream.bufferedReader().readText()
            assertEquals(0, process.exitValue(), output)
            assertTrue(output.contains("PHYSICAL_COPIES_OK"), output)
        } finally { if (process.isAlive) process.destroyForcibly() }
    }

    @Test fun actualFixedPowerShellNativeSourceCompilesAndRejectsUnsafeAclFixtures() {
        assumeTrue(System.getProperty("os.name").startsWith("Windows", true))
        val source = javaClass.getResourceAsStream("/windows-install-native.cs")!!.use { it.readBytes() }
        val compressed = java.io.ByteArrayOutputStream()
        java.util.zip.GZIPOutputStream(compressed).use { it.write(source) }
        val encodedSource = Base64.getEncoder().encodeToString(compressed.toByteArray())
        // The test-only NT rename mutates the fixture while its real parent pin stays held.
        // Capture C# bytes so Java/PowerShell command-line parsing cannot consume its quotes.
        val mutationSource = """
            using System; using System.Text; using System.Runtime.InteropServices; using Microsoft.Win32.SafeHandles;
            public static class NativeCopyMutationFixture {
              [StructLayout(LayoutKind.Sequential)] struct IoStatus { public IntPtr Status; public UIntPtr Information; }
              [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern SafeFileHandle CreateFileW(string path,uint access,uint share,IntPtr security,uint creation,uint flags,IntPtr template);
              [DllImport("ntdll.dll")] static extern int NtSetInformationFile(SafeFileHandle file,out IoStatus status,IntPtr info,uint size,int kind);
              [DllImport("ntdll.dll")] static extern uint RtlNtStatusToDosError(int status);
              public static void Replace(string source) {
                using (SafeFileHandle file=CreateFileW(source,0x30080,7,IntPtr.Zero,3,0x00200000,IntPtr.Zero)) {
                  if(file.IsInvalid)throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
                  byte[] name=Encoding.Unicode.GetBytes("vpn-control.exe");int lengthOffset=(IntPtr.Size==8?8:4)+IntPtr.Size;int nameOffset=lengthOffset+4;
                  byte[] packet=new byte[nameOffset+name.Length];Array.Copy(BitConverter.GetBytes(3u),packet,4);Array.Copy(BitConverter.GetBytes(name.Length),0,packet,lengthOffset,4);Array.Copy(name,0,packet,nameOffset,name.Length);
                  IntPtr data=Marshal.AllocHGlobal(packet.Length);try { Marshal.Copy(packet,0,data,packet.Length);IoStatus status;int result=NtSetInformationFile(file,out status,data,(uint)packet.Length,65);if(result<0)throw new System.ComponentModel.Win32Exception((int)RtlNtStatusToDosError(result)); } finally { Marshal.FreeHGlobal(data); }
                }
              }
            }
        """.trimIndent()
        val encodedMutation = Base64.getEncoder().encodeToString(mutationSource.toByteArray(Charsets.UTF_8))
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
            Add-Type -TypeDefinition ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('$encodedMutation')))
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
            ${'$'}directory=${'$'}null; ${'$'}file=${'$'}null; ${'$'}replacement=${'$'}null
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
                ${'$'}gui=Join-Path ${'$'}fixture 'vpn-control.exe'
                ${'$'}cli=Join-Path ${'$'}fixture 'vpn-control-cli.exe'
                [IO.File]::WriteAllBytes(${'$'}gui,[byte[]]@(1,2,3))
                [IO.File]::WriteAllBytes(${'$'}cli,[byte[]]@(4,5,6))
                ${'$'}replacement=[VpnInstallNative+ExecutableReplacementSet]::new(${'$'}directory,${'$'}sid)
                foreach (${'$'}sibling in @(${'$'}gui,${'$'}cli)) {
                    ${'$'}normal=[VpnInstallNative]::OpenRead(${'$'}sibling,${'$'}false)
                    try {
                        if (-not ${'$'}replacement.ContainsImage(${'$'}sibling.ToUpperInvariant())) { throw 'Native image alias was lost' }
                        if (${'$'}replacement.TryReady()) { throw 'Running sibling did not fence first installation' }
                    } finally { ${'$'}normal.Dispose() }
                }
                if (-not ${'$'}replacement.TryReady()) { throw 'Closed siblings remained busy' }
                ${'$'}after=[VpnInstallNative]::OpenRead(${'$'}cli,${'$'}false)
                ${'$'}after.Dispose() # Readiness handles must close before replacement.
                ${'$'}rejected=${'$'}false
                try { ${'$'}replacement.ContainsImage((Join-Path ${'$'}fixture 'missing.exe')) | Out-Null }
                catch { ${'$'}rejected=${'$'}true }
                if (-not ${'$'}rejected) { throw 'Unknown native identity was treated as unrelated' }
                ${'$'}newGui=Join-Path ${'$'}fixture 'next-inert.bin'
                [IO.File]::WriteAllBytes(${'$'}newGui,[byte[]]@(7,8,9))
                [NativeCopyMutationFixture]::Replace(${'$'}newGui)
                if (${'$'}replacement.ContainsImage(${'$'}gui)) { throw 'Mutation fixture retained the original image identity' }
                ${'$'}rejected=${'$'}false
                try { ${'$'}replacement.TryReady() | Out-Null }
                catch { ${'$'}rejected=${'$'}_.Exception.InnerException.Message -ceq 'CONFLICT' }
                if (-not ${'$'}rejected) { throw 'Replaced sibling identity reached installation' }
                ${'$'}replacement.Dispose(); ${'$'}replacement=${'$'}null
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
                if (${'$'}replacement) { ${'$'}replacement.Dispose() }
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
