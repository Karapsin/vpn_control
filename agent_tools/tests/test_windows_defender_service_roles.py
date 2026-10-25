"""Execute the complete original/current census at controlled OS boundaries."""
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

FIXTURE = Path(__file__).parent / 'fixtures/windows_defender_installed_service'


def original():
    provenance = json.loads((FIXTURE / 'provenance.json').read_bytes())
    modules = []
    for name in ('processes.before.source', 'idle.before.source'):
        raw = (FIXTURE / name).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == provenance['files'][name]['sha256']
        module = types.ModuleType('agent_tools._defender_before')
        module.__package__ = 'agent_tools'
        exec(compile(raw, str(FIXTURE / name), 'exec'), module.__dict__)
        modules.append(module)
    return modules


def controlled_native():
    source = processes.NATIVE
    replacements = {
        '[DllImport("kernel32.dll",SetLastError=true)]static extern IntPtr OpenProcess(uint access,bool inherit,uint pid);':
        'public static string Case="healthy";static IntPtr OpenProcess(uint access,bool inherit,uint pid){return new IntPtr(pid);}',
        '[DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern bool QueryFullProcessImageName(IntPtr h,uint flags,StringBuilder name,ref uint count);':
        'static bool QueryFullProcessImageName(IntPtr h,uint flags,StringBuilder name,ref uint count){long p=h.ToInt64();string root=Environment.GetEnvironmentVariable("SystemRoot"),program=Environment.GetEnvironmentVariable("ProgramFiles");name.Append(p==7?root+@"\\System32\\services.exe":(Case=="path"?@"C:\\Temp":program+@"\\Windows Defender")+(p==8?@"\\MsMpEng.exe":@"\\NisSrv.exe"));return true;}',
        '[DllImport("kernel32.dll",SetLastError=true)]static extern bool GetProcessTimes(IntPtr h,out long creation,out long exit,out long kernel,out long user);':
        'static bool GetProcessTimes(IntPtr h,out long creation,out long exit,out long kernel,out long user){creation=h.ToInt64()==7?134369743086527024:134369743096527024;if(Case=="birth"&&h.ToInt64()!=7)creation+=10;exit=kernel=user=0;return true;}',
        '[DllImport("kernel32.dll",SetLastError=true)]static extern bool GetProcessInformation(IntPtr h,int kind,out uint protection,uint size);':
        'static bool GetProcessInformation(IntPtr h,int kind,out uint protection,uint size){protection=h.ToInt64()==7?0u:(Case=="protection"?0xfffffffeu:3u);return true;}',
        '[DllImport("kernel32.dll",CharSet=CharSet.Unicode)]static extern int GetPackageFullName(IntPtr h,ref uint length,StringBuilder name);':
        'static int GetPackageFullName(IntPtr h,ref uint length,StringBuilder name){return 15700;}',
        '[DllImport("kernel32.dll")]static extern bool CloseHandle(IntPtr h);':
        'static bool CloseHandle(IntPtr h){return true;}',
    }
    for old, new in replacements.items():
        assert source.count(old) == 1
        source = source.replace(old, new)
    return "Add-Type -TypeDefinition @'\n" + source + "\n'@\n"


def harness():
    before_processes, before_idle = original()
    output = '[Console]::WriteLine(($result|ConvertTo-Json -Depth 10 -Compress))'
    assert before_idle._OBSERVE.count(output) == idle._OBSERVE.count(output) == 1
    prefix = r'''
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$Machine='machine';$Boot='boot';$Account='account'
$sessionFacts=@{machine='machine';boot='boot';expectedSid='account';ordinary=$true;console=1}
$leaseFacts=@{};$jobFacts=@{};$script:TestCase='healthy'
function Get-CimInstance([string]$ClassName,[string]$Filter) {
 if($ClassName -eq 'Win32_Service'){
  $candidate=if($Filter -match '8$'){8}else{9}
  $name=if($candidate -eq 8){'WinDefend'}else{'WdNisSvc'}
  if($script:TestCase -eq 'service'){$name='Unrelated'}
  $state=if($script:TestCase -eq 'stopped'){'Stopped'}else{'Running'}
  if($script:TestCase -eq 'service-pid'){$candidate=10}
  $row=[pscustomobject]@{Name=$name;State=$state;ProcessId=$candidate}
  if($script:TestCase -eq 'multiple-services'){$row;$row}else{$row};return
 }
 foreach($candidate in @(7,8,9)){
  $name=if($candidate -eq 7){'services.exe'}elseif($candidate -eq 8){'MsMpEng.exe'}else{'NisSrv.exe'}
  if($candidate -eq 7 -and $script:TestCase -eq 'parent'){$name='other.exe'}
  $birth=if($candidate -eq 7){134369743086527020}else{134369743096527020}
  $session=if($script:TestCase -eq 'session' -and $candidate -ne 7){1}else{0}
  [pscustomobject]@{ProcessId=$candidate;Name=$name;ParentProcessId=7;SessionId=$session;CreationDate=[DateTime]::FromFileTimeUtc($birth)}
 }
}
function Invoke-CimMethod($InputObject,[string]$MethodName) {
 $sid=if($InputObject.ProcessId -eq 9){'S-1-5-19'}else{'S-1-5-18'}
 if($script:TestCase -eq 'owner' -or ($script:TestCase -eq 'parent-owner' -and $InputObject.ProcessId -eq 7)){$sid='S-1-5-21-1-2-3-1000'}
 @{ReturnValue=0;Sid=$sid}
}
function Get-AuthenticodeSignature($LiteralPath){
 if($script:TestCase -eq 'signature'){@{Status='NotSigned';SignerCertificate=$null}}
 else{@{Status='Valid';SignerCertificate=@{Subject='CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US'}}}
}
function Get-ItemProperty { @{SystemSetupInProgress=0;OOBEInProgress=0} }
function Get-ScheduledTask { @{State='Disabled'} }
function Test-Path { $false }
'''
    source = prefix + controlled_native() + before_processes._ROLES
    source += '\nfunction Invoke-Census {\n' + before_idle._OBSERVE.replace(output, 'return $result') + '\n}\n'
    source += "$before=Invoke-Census;if(@($before.processes|Where-Object {$_.name -in @('MsMpEng.exe','NisSrv.exe') -and -not $_.knownSystem}).Count -ne 2){throw 'ORIGINAL_NOT_RED'}\n"
    source += processes._ROLES
    source += '\nfunction Invoke-Census {\n' + idle._OBSERVE.replace(output, 'return $result') + '\n}\n'
    source += r'''
$fixed=Invoke-Census
if(@($fixed.processes|Where-Object {$_.name -in @('MsMpEng.exe','NisSrv.exe') -and $_.knownSystem}).Count -ne 2){throw 'FIXED_NOT_GREEN'}
$cases=@('path','birth','protection','session','owner','service','stopped','service-pid','multiple-services','parent','parent-owner','signature')
foreach($case in $cases){
 $script:TestCase=$case;[RecoveryProcessIdentity]::Case=$case;$RecoveryRoleSignatures.Clear()
 $result=Invoke-Census
 if(@($result.processes|Where-Object {$_.name -in @('MsMpEng.exe','NisSrv.exe') -and $_.knownSystem}).Count -ne 0){throw ('NEGATIVE_ALLOWED_'+$case)}
}
[Console]::WriteLine((@{schemaVersion=1;beforeBlocked=$true;fixedKnown=$true;negativeCount=$cases.Count}|ConvertTo-Json -Compress))
'''
    return source


class DefenderServiceEvidenceTests(unittest.TestCase):
    def test_actual_unknown_service_identities_and_whole_beforeimages(self):
        original()
        raw = (FIXTURE / 'native-before.json').read_bytes()
        provenance = json.loads((FIXTURE / 'provenance.json').read_bytes())
        self.assertEqual(provenance['files']['native-before.json']['sha256'], hashlib.sha256(raw).hexdigest())
        rows = json.loads(raw)['rows']
        self.assertEqual({'MsMpEng.exe', 'NisSrv.exe'}, {row['expectedName'] for row in rows})
        self.assertTrue(all(row['imageValid'] and row['microsoftSignature'] and not row['knownSystem'] for row in rows))
        self.assertIn('ORIGINAL_NOT_RED', harness())


@unittest.skipUnless(os.name == 'nt' and shutil.which('powershell.exe'), 'actual Windows C# and PowerShell execution')
class NativeWindowsDefenderServiceTests(unittest.TestCase):
    def test_complete_before_census_RED_fixed_service_GREEN_and_twelve_negatives(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'defender.ps1'
            path.write_text(harness(), encoding='utf-8')
            result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', str(path)], capture_output=True, timeout=60)
        self.assertEqual(0, result.returncode, (result.stdout + result.stderr).decode(errors='replace'))
        self.assertEqual(12, json.loads(result.stdout.decode('utf-8-sig'))['negativeCount'])


if __name__ == '__main__':
    unittest.main()
