"""Native limited-query facts close WMI visibility gaps without name waivers."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import types
import unittest

from agent_tools import readiness_windows_idle as idle
from agent_tools import readiness_windows_processes as processes

FIXTURE=Path(__file__).parent/'fixtures/windows_idle_visibility'


def before_observer(directory=FIXTURE):
    raw=(directory/'idle.before.source').read_bytes()
    if hashlib.sha256(raw).hexdigest()!=json.loads((directory/'provenance.json').read_text())['sourceSha256']:
        raise ValueError('windows_idle_beforeimage_changed')
    module=types.ModuleType('agent_tools._idle_visibility_before');module.__package__='agent_tools'
    exec(compile(raw,str(directory/'idle.before.source'),'exec'),module.__dict__)
    return module._OBSERVE


def native_boundary():
    source=processes.NATIVE
    replacements={
      '[DllImport("kernel32.dll",SetLastError=true)]static extern IntPtr OpenProcess(uint access,bool inherit,uint pid);':
      'static IntPtr OpenProcess(uint access,bool inherit,uint pid){return new IntPtr(1);}',
      '[DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern bool QueryFullProcessImageName(IntPtr h,uint flags,StringBuilder name,ref uint count);':
      'static bool QueryFullProcessImageName(IntPtr h,uint flags,StringBuilder name,ref uint count){if(flags==0){return false;}name.Append("Registry");return true;}',
      '[DllImport("kernel32.dll",SetLastError=true)]static extern bool GetProcessTimes(IntPtr h,out long creation,out long exit,out long kernel,out long user);':
      'static bool GetProcessTimes(IntPtr h,out long creation,out long exit,out long kernel,out long user){creation=134369743096527024;exit=kernel=user=0;return true;}',
      '[DllImport("kernel32.dll",SetLastError=true)]static extern bool GetProcessInformation(IntPtr h,int kind,out uint protection,uint size);':
      'static bool GetProcessInformation(IntPtr h,int kind,out uint protection,uint size){protection=5;return true;}',
      '[DllImport("kernel32.dll")]static extern bool CloseHandle(IntPtr h);':
      'static bool CloseHandle(IntPtr h){return true;}',
    }
    for old,new in replacements.items():
        if source.count(old)!=1:raise ValueError('windows_process_boundary_changed')
        source=source.replace(old,new)
    return "Add-Type -TypeDefinition @'\n"+source+"\n'@\n"


def causal_harness(observer):
    # Only the OS APIs are controlled. Both complete captured/current census
    # programs and the complete current native Read/Kernel implementations run.
    prefix=r'''
$ErrorActionPreference='Stop'
$Machine='machine';$Boot='boot';$Account='account'
$sessionFacts=@{machine='machine';boot='boot';expectedSid='account';ordinary=$true}
$leaseFacts=@{}
function Get-CimInstance { [pscustomobject]@{ProcessId=124;Name='Registry';ParentProcessId=4;SessionId=0;ExecutablePath=$null;CreationDate=[DateTime]::FromFileTimeUtc(134369743096527020)} }
function Get-ItemProperty { @{SystemSetupInProgress=0;OOBEInProgress=0} }
function Get-ScheduledTask { @{State='Disabled'} }
function Test-Path { $false }
'''
    output='[Console]::WriteLine(($result|ConvertTo-Json -Depth 10 -Compress))'
    if observer.count(output)!=1:raise ValueError('windows_idle_output_changed')
    return prefix+native_boundary()+observer.replace(output,"if(-not $rows[0].knownSystem){throw 'WMI_MISSING_IMAGE_CAUSAL_RED'}\n[Console]::WriteLine('NATIVE_VISIBILITY_GREEN')")


def role_harness(observer):
    prefix=causal_harness(observer).split(native_boundary())[0]
    prefix=prefix.replace("ordinary=$true}","ordinary=$true;console=1}")
    prefix=prefix.replace("Name='Registry';ParentProcessId=4;SessionId=0;ExecutablePath=$null;", "Name='CrossDeviceResume.exe';ParentProcessId=4;SessionId=1;ExecutablePath=($env:SystemRoot+'\\SystemApps\\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\\CrossDeviceResume.exe');")
    boundary=native_boundary().replace('if(flags==0){return false;}name.Append("Registry");', 'name.Append(@"C:\\Windows\\SystemApps\\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\\CrossDeviceResume.exe");')
    boundary=boundary.replace('protection=5;','protection=0xfffffffe;')
    signature="function Get-AuthenticodeSignature { @{Status='Valid';SignerCertificate=@{Subject='CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US'}} }\n"
    output='[Console]::WriteLine(($result|ConvertTo-Json -Depth 10 -Compress))'
    return prefix+boundary+processes._ROLES+signature+observer.replace(output,"if(-not $rows[0].knownSystem){throw 'BACKGROUND_ROLE_CAUSAL_RED'}\n[Console]::WriteLine('BACKGROUND_ROLE_GREEN')")


class WindowsProcessSourceTests(unittest.TestCase):
    def test_actual_before_and_current_whole_observers_are_captured(self):
        self.assertIn('WMI_MISSING_IMAGE_CAUSAL_RED',causal_harness(before_observer()))
        self.assertIn('RecoveryProcessIdentity',causal_harness(idle._OBSERVE))
        for forbidden in ['PROCESS_TERMINATE','TerminateProcess','SeDebugPrivilege','AdjustTokenPrivileges']:
            self.assertNotIn(forbidden,processes.NATIVE)
        self.assertIn('BACKGROUND_ROLE_CAUSAL_RED',role_harness(before_observer(Path(__file__).parent/'fixtures/windows_background_roles')))


@unittest.skipUnless(os.name=='nt'and shutil.which('powershell.exe'),'Windows native C# process query execution')
class NativeWindowsProcessTests(unittest.TestCase):
    def run_ps(self,source):
        with tempfile.TemporaryDirectory()as directory:
            path=Path(directory)/'process.ps1';path.write_text(source,encoding='utf-8')
            return subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',str(path)],capture_output=True,timeout=45)

    def test_actual_complete_census_before_RED_fixed_native_identity_GREEN(self):
        for name,observer,code in [('before',before_observer(),1),('fixed',idle._OBSERVE,0)]:
            with self.subTest(name=name):
                result=self.run_ps(causal_harness(observer))
                self.assertEqual(code,result.returncode,(result.stdout+result.stderr).decode(errors='replace'))

    def test_actual_native_process_handle_birth_and_image(self):
        result=self.run_ps("$ErrorActionPreference='Stop'\n"+processes.powershell_source()+r'''
$p=Get-CimInstance Win32_Process -Filter "ProcessId=$PID"
$f=[RecoveryProcessIdentity]::Read([UInt32]$PID)
$birth=$p.CreationDate.ToUniversalTime().ToFileTimeUtc().ToString()
if(-not [RecoveryProcessIdentity]::Image($f,[string]$p.Name,$birth)){throw 'PROCESS_NATIVE_IDENTITY'}
if([RecoveryProcessIdentity]::Image($f,'unrelated.exe',$birth)){throw 'PROCESS_WRONG_IMAGE'}
if([RecoveryProcessIdentity]::Image($f,[string]$p.Name,'134369743096527020')){throw 'PROCESS_STALE_BIRTH'}
$f.protectionError=5
if([RecoveryProcessIdentity]::Image($f,[string]$p.Name,$birth)){throw 'PROCESS_MISSING_PROTECTION'}
[Console]::WriteLine('PROCESS_NATIVE_GREEN')
''')
        self.assertEqual(0,result.returncode,(result.stdout+result.stderr).decode(errors='replace'))

    def test_complete_background_before_RED_verified_role_GREEN(self):
        before=before_observer(Path(__file__).parent/'fixtures/windows_background_roles')
        for name,observer,code in [('before',before,1),('fixed',idle._OBSERVE,0)]:
            with self.subTest(name=name):
                result=self.run_ps(role_harness(observer))
                self.assertEqual(code,result.returncode,(result.stdout+result.stderr).decode(errors='replace'))

    def test_signature_account_session_and_path_mismatches_remain_blocked(self):
        result=self.run_ps("$ErrorActionPreference='Stop'\n"+processes._ROLES+r'''
$p=@{Name='CrossDeviceResume.exe';SessionId=1}
$native=@{image=($env:SystemRoot+'\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\CrossDeviceResume.exe')}
function Get-AuthenticodeSignature { @{Status='Valid';SignerCertificate=@{Subject='CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US'}} }
if(-not (Test-RecoveryExtraRole $p $native 'account' 1)){throw 'VALID_ROLE_REFUSED'}
if(Test-RecoveryExtraRole $p $native 'account' 2){throw 'WRONG_SESSION_ALLOWED'}
$native.image='C:\Temp\CrossDeviceResume.exe'
if(Test-RecoveryExtraRole $p $native 'account' 1){throw 'WRONG_PATH_ALLOWED'}
$native.image=$env:SystemRoot+'\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\CrossDeviceResume.exe'
$RecoveryRoleSignatures.Clear()
function Get-AuthenticodeSignature { @{Status='NotSigned';SignerCertificate=$null} }
if(Test-RecoveryExtraRole $p $native 'account' 1){throw 'UNSIGNED_ALLOWED'}
$RecoveryRoleSignatures.Clear()
function Get-AuthenticodeSignature { @{Status='Valid';SignerCertificate=@{Subject='CN=Other publisher'}} }
if(Test-RecoveryExtraRole $p $native 'account' 1){throw 'WRONG_PUBLISHER_ALLOWED'}
[Console]::WriteLine('ROLE_NEGATIVES_GREEN')
''')
        self.assertEqual(0,result.returncode,(result.stdout+result.stderr).decode(errors='replace'))


if __name__=='__main__':unittest.main()
