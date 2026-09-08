package com.kardinal.vpncontrol.desktop

import java.util.Base64
import java.util.concurrent.TimeUnit
import kotlin.test.*
import org.junit.Assume.assumeTrue

class DesktopWindowsInstallNativeSourceTest {
    @Test fun physicalImageAliasesAndUnknownReadersCannotReachReplacement() = runInventoryFixture(
        """
            function New-TestCopy {
                ${'$'}copy=[pscustomobject]@{Id=912;HasExited=${'$'}false}
                ${'$'}copy|Add-Member ScriptMethod Dispose { ${'$'}script:disposed++ }
                return ${'$'}copy
            }
            ${'$'}cases=@(
                @{image='X:\ALIAS\VPN-CO~1.EXE';same=${'$'}true;unknown=${'$'}false;blocked=${'$'}true},
                @{image='C:\OTHER\VPN-CO~2.EXE';same=${'$'}true;unknown=${'$'}false;blocked=${'$'}true},
                @{image='C:\other-app\vpn-control.exe';same=${'$'}false;unknown=${'$'}false;blocked=${'$'}false},
                @{image='C:\unknown\vpn-control-cli.exe';same=${'$'}false;unknown=${'$'}true;blocked=${'$'}true}
            )
            foreach(${'$'}case in ${'$'}cases) {
                [NativeInventoryFixture]::Reset()
                ${'$'}script:case=${'$'}case; ${'$'}script:disposed=0; ${'$'}caught=${'$'}null
                try {
                    Assert-NoInstallationCopies @((New-TestCopy)) 'C:\installed\vpn-control.exe' @() ${'$'}null `
                        -ReadImage { param(${'$'}Id) return [NativeInventoryFixture]::PinWithImage(${'$'}script:case.image) } `
                        -SameImage { param(${'$'}Image,${'$'}Captured)
                            if (${'$'}Image -isnot [string] -or ${'$'}Image -cne ${'$'}script:case.image) { throw 'Native image observation lost' }
                            if (${'$'}script:case.unknown) { throw 'Native identity unavailable' }; return ${'$'}script:case.same
                        }
                } catch { ${'$'}caught=${'$'}_.Exception.Message }
                if (${'$'}case.blocked -and ${'$'}caught -cne 'BUSY') { throw 'Aliased or unknown live copy reached replacement' }
                if (-not ${'$'}case.blocked -and ${'$'}null -ne ${'$'}caught) { throw 'Unrelated physical installation was blocked' }
                if (${'$'}script:disposed -ne 1 -or ${'$'}script:pins.Count -ne 0) { throw 'Process snapshot ownership lost' }
            }
            Write-Output 'PHYSICAL_COPIES_OK'
        """.trimIndent(),
        "PHYSICAL_COPIES_OK",
    )

    @Test fun nativeInventoryClassificationRequiresExactLiveHandleAndKnownLayout() = runInventoryFixture(
        """
            ${'$'}passed=@([NativeInventoryFixture]::RunNativeCases())
            if (${'$'}passed.Count -ne 28) { throw 'Native inventory fixture cases were not all executed' }
            Write-Output ('NATIVE_INVENTORY_FIXTURES_OK:'+ ${'$'}passed.Count)
        """.trimIndent(),
        "NATIVE_INVENTORY_FIXTURES_OK:28",
    )

    @Test fun verifiedKernelOnlyRecordsDoNotRequireAnExecutableImage() = runInventoryFixture(
        """
            ${'$'}ErrorActionPreference='Stop'
            function New-TestCopy {
                ${'$'}copy=[pscustomobject]@{Id=912;HasExited=${'$'}false}
                ${'$'}copy|Add-Member ScriptMethod Dispose { ${'$'}script:disposed++ }
                return ${'$'}copy
            }
            foreach(${'$'}scenario in @('kernel3','kernel4')) {
                [NativeInventoryFixture]::Reset()
                ${'$'}script:pin=[NativeInventoryFixture]::Pin(${'$'}scenario)
                ${'$'}script:disposed=0; ${'$'}script:compared=0; ${'$'}caught=${'$'}null
                try {
                    try {
                        Assert-NoInstallationCopies @((New-TestCopy)) 'C:\installed\vpn-control.exe' @() ${'$'}null `
                            -ReadImage { param(${'$'}Id) return ${'$'}script:pin } `
                            -SameImage { param(${'$'}Image,${'$'}Captured) ${'$'}script:compared++; throw 'Kernel-only process required executable image' }
                    } catch { ${'$'}caught=${'$'}_.Exception.Message }
                    if (${'$'}null -ne ${'$'}caught) { throw ('Verified '+${'$'}scenario+' should reach readiness; actual='+${'$'}caught) }
                    if (${'$'}script:compared -ne 0 -or ${'$'}script:disposed -ne 1) { throw 'Kernel classification lost exact observation ownership' }
                    if ([string]::Join(',', [NativeInventoryFixture]::Trace) -cne 'open,stamp1,image,snapshot,stamp2,close') { throw 'Kernel classification did not use the same retained handle' }
                    if (${'$'}script:pins.Count -ne 0) { throw 'Confirmed closed inventory pin retained' }
                } finally { ${'$'}script:pin.Dispose() }
            }
            Write-Output 'KERNEL_INVENTORY_CONSUMER_OK'
        """.trimIndent(),
        "KERNEL_INVENTORY_CONSUMER_OK",
    )

    @Test fun unknownInventoryCannotReachReadinessFromManagedExitOrCallerFlags() = runInventoryFixture(
        """
            ${'$'}ErrorActionPreference='Stop'
            function New-TestCopy {
                # A managed HasExited claim must never suppress unknown native classification.
                ${'$'}copy=[pscustomobject]@{Id=912;HasExited=${'$'}script:claimsExit}
                ${'$'}copy|Add-Member ScriptMethod Dispose { ${'$'}script:disposed++ }
                return ${'$'}copy
            }
            foreach(${'$'}scenario in @('normal0','normal1','normal2','unknown-class','foreign-pid','reused-pid','pid-before','pid-after','creation-after','exit-before','exit-after','unknown-flags','thread-overflow','truncated','bad-next','duplicate','snapshot-failure','image-query-failure','query-before-failure','query-after-failure','empty-image','open-failure','caller-classification')) {
                foreach(${'$'}claimsExit in @(${'$'}false,${'$'}true)) {
                    [NativeInventoryFixture]::Reset()
                    ${'$'}script:scenario=${'$'}scenario; ${'$'}script:claimsExit=${'$'}claimsExit; ${'$'}script:disposed=0; ${'$'}script:compared=0; ${'$'}caught=${'$'}null; ${'$'}script:pin=${'$'}null
                    try {
                        try {
                            Assert-NoInstallationCopies @((New-TestCopy)) 'C:\installed\vpn-control.exe' @() ${'$'}null `
                                -ReadImage { param(${'$'}Id)
                                    if (${'$'}script:scenario -eq 'caller-classification') { return [pscustomobject]@{KernelOnly=${'$'}true;Image=${'$'}null} }
                                    ${'$'}script:pin=[NativeInventoryFixture]::Pin(${'$'}script:scenario); return ${'$'}script:pin
                                } `
                                -SameImage { param(${'$'}Image,${'$'}Captured) ${'$'}script:compared++; return ${'$'}false }
                        } catch { ${'$'}caught=${'$'}_.Exception.Message }
                        if (${'$'}caught -cne 'BUSY') { throw ('Unknown native process reached readiness: '+${'$'}scenario+' exit='+${'$'}claimsExit+' result='+${'$'}caught) }
                        if (${'$'}script:disposed -ne 1 -or ${'$'}script:compared -ne 0) { throw 'Unknown process comparison or ownership changed' }
                        if (${'$'}script:pins.Count -ne 0) { throw 'Confirmed closed unknown pin retained' }
                    } finally { if (${'$'}null -ne ${'$'}script:pin) { ${'$'}script:pin.Dispose() } }
                }
            }
            Write-Output 'UNKNOWN_INVENTORY_BUSY_OK'
        """.trimIndent(),
        "UNKNOWN_INVENTORY_BUSY_OK",
    )

    @Test fun unclosedInventoryPinsBlockReadinessUntilTheExactHandleCloses() = runInventoryFixture(
        """
            ${'$'}ErrorActionPreference='Stop'
            function New-TestCopy {
                ${'$'}copy=[pscustomobject]@{Id=912;HasExited=${'$'}false}
                ${'$'}copy|Add-Member ScriptMethod Dispose { ${'$'}script:disposed++ }
                return ${'$'}copy
            }
            foreach(${'$'}scenario in @('image-close-once','close-once-and-read-failure')) {
                [NativeInventoryFixture]::Reset()
                ${'$'}script:pin=[NativeInventoryFixture]::Pin(${'$'}scenario)
                ${'$'}script:disposed=0; ${'$'}caught=${'$'}null
                try {
                    try {
                        Assert-NoInstallationCopies @((New-TestCopy)) 'C:\installed\vpn-control.exe' @() ${'$'}null `
                            -ReadImage { param(${'$'}Id) return ${'$'}script:pin } `
                            -SameImage { param(${'$'}Image,${'$'}Captured) return ${'$'}false }
                    } catch { ${'$'}caught=${'$'}_.Exception.Message }
                    if (${'$'}caught -cne 'BUSY') { throw 'Native close failure reached readiness' }
                    if (${'$'}script:disposed -ne 1 -or -not ${'$'}script:pins.Contains(${'$'}script:pin)) { throw 'Unclosed exact native handle ownership was discarded' }
                    Assert-NoInstallationCopies @() 'C:\installed\vpn-control.exe' @() ${'$'}null
                    if (${'$'}script:pins.Count -ne 0) { throw 'Retry did not close retained inventory handle' }
                    ${'$'}closes=@([NativeInventoryFixture]::Trace | Where-Object { ${'$'}_ -eq 'close' })
                    if (${'$'}closes.Count -ne 2) { throw 'Native handle was not retried exactly once' }
                } finally { ${'$'}script:pin.Dispose(); ${'$'}null=${'$'}script:pins.Remove(${'$'}script:pin) }
            }
            Write-Output 'INVENTORY_CLOSE_RETRY_OK'
        """.trimIndent(),
        "INVENTORY_CLOSE_RETRY_OK",
    )

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

    private fun runInventoryFixture(body: String, marker: String) {
        assumeTrue(System.getProperty("os.name").startsWith("Windows", true))
        val native = javaClass.getResourceAsStream("/windows-install-native.cs")!!.use { it.reader().readText() }
        val common = javaClass.getResourceAsStream("/windows-install-common.ps1")!!.use { it.readBytes() }
        // These fakes drive the same retained-handle observation and native-byte parser
        // as the coordinator. They compile only into this test's captured assembly.
        val fixtures = """
            // Compiled only by the test, in the same assembly as the captured production source.
            public static class NativeInventoryFixture {
                const uint Pid=912;
                const long Created=132000000000000001L;
                public static readonly List<string> Trace=new List<string>();
                static Reader latest;
                public static void Reset() { Trace.Clear(); latest=null; }
                public static VpnInstallNative.ProcessImagePin Pin(string scenario) {
                    latest=new Reader(scenario,@"X:\ALIAS\VPN-CO~1.EXE");
                    return new VpnInstallNative.ProcessImagePin(Pid,latest);
                }
                public static VpnInstallNative.ProcessImagePin PinWithImage(string image) {
                    latest=new Reader("image",image);
                    return new VpnInstallNative.ProcessImagePin(Pid,latest);
                }
                public static bool SnapshotCleared() {
                    if (latest==null || latest.Captured==null) return false;
                    foreach(byte value in latest.Captured) if(value!=0) return false;
                    return true;
                }
                static byte[] Record(uint id,long created,int classification) {
                    byte[] bytes=new byte[312];
                    Array.Copy(BitConverter.GetBytes((ulong)id),0,bytes,80,8);
                    Array.Copy(BitConverter.GetBytes(created),0,bytes,32,8);
                    Array.Copy(BitConverter.GetBytes((uint)(classification<<1)),0,bytes,304,4);
                    return bytes;
                }
                sealed class Reader : VpnInstallNative.IProcessImageNative {
                    readonly string scenario, image;
                    int stamps, closes;
                    bool opened, closed;
                    internal byte[] Captured;
                    internal Reader(string value,string inputImage) { scenario=value; image=inputImage; }
                    void Exact(IntPtr handle) {
                        if (!opened || closed || handle!=new IntPtr(71)) throw new IOException("Wrong retained handle");
                    }
                    public IntPtr Open(uint pid) {
                        Trace.Add("open");
                        if (pid!=Pid || opened) throw new IOException("Wrong requested identity");
                        if (scenario=="open-failure") throw new IOException("Native open failure");
                        opened=true; return new IntPtr(71);
                    }
                    public VpnInstallNative.ProcessImageStamp Stamp(IntPtr handle) {
                        Exact(handle); stamps++; Trace.Add("stamp"+stamps);
                        if (scenario==(stamps==1 ? "query-before-failure" : "query-after-failure")) throw new IOException("Native stamp failure");
                        uint pid=Pid; long created=Created, exited=0;
                        if (scenario==(stamps==1 ? "pid-before" : "pid-after")) pid++;
                        if (stamps>1 && scenario=="creation-after") created++;
                        if (stamps==1 && scenario=="zero-creation") created=0;
                        if (scenario==(stamps==1 ? "exit-before" : "exit-after")) exited=Created+1;
                        return new VpnInstallNative.ProcessImageStamp(pid,created,exited);
                    }
                    public string Image(IntPtr handle) {
                        Exact(handle); Trace.Add("image");
                        if (scenario=="image-query-failure") throw new IOException("Native query failure");
                        if (scenario=="empty-image") return "";
                        if (scenario=="image" || scenario=="image-close-once") return image;
                        return null;
                    }
                    public byte[] Snapshot() {
                        Exact(new IntPtr(71)); Trace.Add("snapshot");
                        if (scenario=="snapshot-failure") throw new IOException("Native snapshot failure");
                        int classification=scenario=="kernel4" ? 4 : 3;
                        if (scenario.StartsWith("normal")) classification=int.Parse(scenario.Substring(6));
                        if (scenario=="unknown-class") classification=5;
                        Captured=Record(scenario=="foreign-pid" ? Pid+1 : Pid,scenario=="reused-pid" ? Created+1 : Created,classification);
                        if (scenario=="unknown-flags") Captured[304]|=64;
                        if (scenario=="thread-overflow") Array.Copy(BitConverter.GetBytes(uint.MaxValue),0,Captured,4,4);
                        if (scenario=="bad-next") Captured[0]=1;
                        if (scenario=="truncated") Captured=new byte[307];
                        if (scenario=="next-outside") Array.Copy(BitConverter.GetBytes(313U),0,Captured,0,4);
                        if (scenario=="duplicate" || scenario=="variable-record") {
                            int next=scenario=="variable-record" ? 314 : 312;
                            byte[] pair=new byte[next+312]; Array.Copy(Captured,pair,312);
                            Array.Copy(BitConverter.GetBytes((uint)next),0,pair,0,4);
                            Array.Copy(Record(scenario=="duplicate" ? Pid : Pid+1,Created+1,4),0,pair,next,312);
                            Captured=pair;
                        }
                        if (scenario=="close-once-and-read-failure") Captured[304]|=64;
                        return Captured;
                    }
                    public void Close(IntPtr handle) {
                        Exact(handle); Trace.Add("close"); closes++;
                        if (scenario.Contains("close-once") && closes==1) throw new IOException("Transient native close failure");
                        closed=true;
                    }
                }
                static void Check(bool condition,string name) { if (!condition) throw new IOException("Native fixture failed: "+name); }
                public static string[] RunNativeCases() {
                    List<string> passed=new List<string>();
                    foreach(string scenario in new string[]{"kernel3","kernel4","variable-record","image"}) {
                        Reset(); VpnInstallNative.ProcessImagePin pin=Pin(scenario);
                        try {
                            VpnInstallNative.ProcessImageObservation observation=pin.Observe();
                            Check(observation.Pid==Pid && observation.CreationFileTime==Created,"tuple");
                            Check(observation.KernelOnly==(scenario!="image"),scenario);
                            Check((observation.Image!=null)==(scenario=="image"),"image alternative");
                            Check(!Trace.Contains("close"),"ownership must outlive observation");
                            if (scenario!="image") Check(SnapshotCleared(),"native snapshot retention");
                            Check(String.Join(",",Trace)==(scenario=="image" ? "open,stamp1,image,stamp2" : "open,stamp1,image,snapshot,stamp2"),"same retained handle ordering");
                            passed.Add(scenario);
                        } finally { pin.Dispose(); }
                        Check(Trace[Trace.Count-1]=="close","exact closure");
                    }
                    foreach(string scenario in new string[]{"normal0","normal1","normal2","unknown-class","foreign-pid","reused-pid", "pid-before","pid-after","zero-creation","creation-after","exit-before","exit-after","unknown-flags","thread-overflow","truncated","bad-next","next-outside","duplicate","snapshot-failure","image-query-failure","query-before-failure","query-after-failure","empty-image"}) {
                        Reset(); VpnInstallNative.ProcessImagePin pin=Pin(scenario); bool rejected=false;
                        try { pin.Observe(); } catch(IOException) { rejected=true; }
                        finally { pin.Dispose(); }
                        Check(rejected,"unknown admitted: "+scenario);
                        Check(Trace[Trace.Count-1]=="close","failed observation lost handle");
                        if (scenario=="pid-before" || scenario=="query-before-failure" || scenario=="zero-creation" || scenario=="exit-before")
                            Check(!Trace.Contains("image") && !Trace.Contains("snapshot"),"identity checked too late");
                        if (latest.Captured!=null) Check(SnapshotCleared(),"failed snapshot retained");
                        passed.Add(scenario);
                    }
                    Reset(); VpnInstallNative.ProcessImagePin retained=Pin("image-close-once");
                    retained.Observe(); bool closeFailed=false;
                    try { retained.Dispose(); } catch(IOException) { closeFailed=true; }
                    Check(closeFailed,"native close failure hidden");
                    retained.Dispose(); retained.Dispose();
                    Check(String.Join(",",Trace)=="open,stamp1,image,stamp2,close,close","exact close was not retried");
                    bool disposed=false; try { retained.Observe(); } catch(ObjectDisposedException) { disposed=true; }
                    Check(disposed,"disposed pin reused"); passed.Add("native-close-retry");
                    return passed.ToArray();
                }
            }
        """.trimIndent()
        fun capture(bytes: ByteArray): String {
            val output = java.io.ByteArrayOutputStream()
            java.util.zip.GZIPOutputStream(output).use { it.write(bytes) }
            return Base64.getEncoder().encodeToString(output.toByteArray())
        }
        val source = capture((native + "\n" + fixtures).toByteArray(Charsets.UTF_8))
        val encodedCommon = capture(common)
        val script = """
            ${'$'}ErrorActionPreference='Stop'
            function Read-CapturedSource([string]${'$'}Encoded) {
                ${'$'}gzip=[IO.Compression.GZipStream]::new([IO.MemoryStream]::new([Convert]::FromBase64String(${'$'}Encoded)),[IO.Compression.CompressionMode]::Decompress)
                ${'$'}reader=[IO.StreamReader]::new(${'$'}gzip,[Text.Encoding]::UTF8)
                try { return ${'$'}reader.ReadToEnd() } finally { ${'$'}reader.Dispose() }
            }
            Add-Type -TypeDefinition (Read-CapturedSource '$source')
            . ([ScriptBlock]::Create((Read-CapturedSource '$encodedCommon')))
            $body
        """.trimIndent()
        assertTrue(script.length < 30000 && script.all { it.code < 128 }, "Captured inventory fixture must fit Windows command line")
        val process = ProcessBuilder("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
            .redirectErrorStream(true).start()
        try {
            assertTrue(process.waitFor(30, TimeUnit.SECONDS), "Native inventory regression timed out")
            val output = process.inputStream.bufferedReader().readText()
            assertEquals(0, process.exitValue(), output)
            assertTrue(output.contains(marker), output)
        } finally { if (process.isAlive) process.destroyForcibly() }
    }
}
