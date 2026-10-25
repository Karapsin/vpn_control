"""Complete idle programs classify only positively bound background OS roles."""
import hashlib,json,os,shutil,subprocess,tempfile,types,unittest
from pathlib import Path
from agent_tools import readiness_windows_idle as idle,readiness_windows_processes as processes
from agent_tools.tests.test_readiness_windows_processes import native_boundary
FIXTURE=Path(__file__).parent/'fixtures/windows_desktop_background_roles'

def before():
    provenance=json.loads((FIXTURE/'provenance.json').read_text());modules=[]
    for filename in ('processes.before.source','idle.before.source'):
        raw=(FIXTURE/filename).read_bytes()
        if hashlib.sha256(raw).hexdigest()!=provenance['sourceSha256'][filename]:raise ValueError('background_before_changed')
        module=types.ModuleType('agent_tools._background_before');module.__package__='agent_tools';module.__file__=str(FIXTURE/filename)
        exec(compile(raw,module.__file__,'exec'),module.__dict__);modules.append(module)
    return modules

def harness(kind,observer,roles,negative=''):
    native=native_boundary()
    native=native.replace('return new IntPtr(1);','return new IntPtr(pid);')
    child=(r'C:\Users\recovery\AppData\Local\Microsoft\OneDrive\OneDrive.exe' if kind=='onedrive' else r'C:\Program Files (x86)\Microsoft\EdgeWebView\Application\155.0.4283.62\msedgewebview2.exe')
    parent=r'C:\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\SearchHost.exe'
    native=native.replace('if(flags==0){return false;}name.Append("Registry");','name.Append(h.ToInt32()==201 ? @"'+parent+'" : @"'+child+'");')
    native=native.replace('protection=5;','protection=0xfffffffe;')
    old='[DllImport("kernel32.dll",CharSet=CharSet.Unicode)]static extern int GetPackageFullName(IntPtr h,ref uint length,StringBuilder name);'
    new='static int GetPackageFullName(IntPtr h,ref uint length,StringBuilder name){if(name==null){length=128;return 122;}name.Append("MicrosoftWindows.Client.CBS_1000.26100.234.0_x64__cw5n1h2txyewy");return 0;}'
    if native.count(old)!=1:raise ValueError('native_package_boundary_changed')
    native=native.replace(old,new)
    name='OneDrive.exe'if kind=='onedrive'else'msedgewebview2.exe'
    source=r'''
$ErrorActionPreference='Stop'
$Machine='machine';$Boot='boot';$Account='account'
$sessionFacts=@{machine='machine';boot='boot';expectedSid='account';ordinary=$true;console=1}
$leaseFacts=@{};$jobFacts=@{}
function Get-ItemProperty { @{SystemSetupInProgress=0;OOBEInProgress=0} }
function Get-ScheduledTask { @{State='Disabled'} }
function Test-Path { $false }
function Get-AuthenticodeSignature { @{Status='Valid';SignerCertificate=@{Subject='CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US'}} }
'''
    source+="function Get-CimInstance { [pscustomobject]@{ProcessId=200;Name='"+name+"';ParentProcessId=201;SessionId=1;ExecutablePath='"+child+"';CreationDate=[DateTime]::FromFileTimeUtc(134369743096527020)};[pscustomobject]@{ProcessId=201;Name='SearchHost.exe';ParentProcessId=4;SessionId=1;ExecutablePath='"+parent+"';CreationDate=[DateTime]::FromFileTimeUtc(134369743096527020)} }\n"
    source+=native+roles+r'''
$RecoveryMetadata=@{ownerSid='account';profileRoot='C:\Users\recovery';hiveLoaded=$true;accountsKnown=$true;configuredFieldsAbsent=$true}
function Get-RecoveryOneDriveMetadata { return $RecoveryMetadata }
'''
    source+=negative+'\n'
    output='[Console]::WriteLine(($result|ConvertTo-Json -Depth 10 -Compress))'
    if observer.count(output)!=1:raise ValueError('idle_output_changed')
    return source+observer.replace(output,"if(-not $rows[0].knownSystem){throw 'DESKTOP_BACKGROUND_CAUSAL_RED'}\n[Console]::WriteLine('BACKGROUND_GREEN')")

class DesktopBackgroundSourceTests(unittest.TestCase):
    def test_whole_beforeimages_native_evidence_and_fixed_harness_are_bound(self):
        old_process,old_idle=before()
        for kind in ('onedrive','webview'):
            self.assertIn('DESKTOP_BACKGROUND_CAUSAL_RED',harness(kind,old_idle._OBSERVE,old_process._ROLES))
            self.assertIn('Test-RecoveryWebView',harness(kind,idle._OBSERVE,processes._ROLES))
        provenance=json.loads((FIXTURE/'provenance.json').read_text())
        self.assertEqual(provenance['sourceSha256']['native-before.json'],hashlib.sha256((FIXTURE/'native-before.json').read_bytes()).hexdigest())

@unittest.skipUnless(os.name=='nt'and shutil.which('powershell.exe'),'actual Windows PowerShell/C# ABI')
class NativeWindowsDesktopBackgroundTests(unittest.TestCase):
    def run_ps(self,source):
        with tempfile.TemporaryDirectory()as directory:
            path=Path(directory)/'roles.ps1';path.write_text(source,encoding='utf-8')
            return subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',str(path)],capture_output=True,timeout=45)
    def test_complete_before_RED_fixed_desktop_roles_GREEN(self):
        old_process,old_idle=before()
        for kind in ('onedrive','webview'):
            for observer,roles,expected in [(old_idle._OBSERVE,old_process._ROLES,1),(idle._OBSERVE,processes._ROLES,0)]:
                with self.subTest(kind=kind,fixed=expected==0):
                    result=self.run_ps(harness(kind,observer,roles));self.assertEqual(expected,result.returncode,(result.stdout+result.stderr).decode(errors='replace'))
    def test_target_parent_package_account_and_configured_mismatches_block(self):
        cases=[('onedrive',"$RecoveryMetadata.ownerSid='foreign'"),('onedrive',"$RecoveryMetadata.profileRoot='C:\\Users\\foreign'"),('onedrive',"$RecoveryMetadata.hiveLoaded=$false"),('onedrive',"$RecoveryMetadata.accountsKnown=$false"),('onedrive',"$RecoveryMetadata.configuredFieldsAbsent=$false"),('webview',"function Get-CimInstance { [pscustomobject]@{ProcessId=200;Name='msedgewebview2.exe';ParentProcessId=202;SessionId=1;ExecutablePath='C:\\invalid';CreationDate=[DateTime]::FromFileTimeUtc(134369743096527020)} }")]
        for kind,negative in cases:
            with self.subTest(kind=kind,negative=negative):
                result=self.run_ps(harness(kind,idle._OBSERVE,processes._ROLES,negative));self.assertEqual(1,result.returncode,(result.stdout+result.stderr).decode(errors='replace'));self.assertIn(b'DESKTOP_BACKGROUND_CAUSAL_RED',result.stderr)

if __name__=='__main__':unittest.main()
