"""New idle roles need their whole positive identity; wrong facts stay unknown.

The PowerShell runs on Windows CI and was also run natively on clone 246a3304 against
the whole preserved roles (RED, the original unknown census) and the current ones.
"""
import ast,hashlib,json,os,re,shutil,subprocess,tempfile,unittest
from pathlib import Path
from agent_tools import readiness_windows_idle as idle,readiness_windows_processes as processes

FIXTURE=Path(__file__).parent/'fixtures/windows_native_tools_20261106'


def before_roles(filename='processes.before.source'):
    raw=(FIXTURE/filename).read_bytes()
    if hashlib.sha256(raw).hexdigest()!=json.loads((FIXTURE/'provenance.json').read_bytes())['sha256'][filename]:raise AssertionError('processes beforeimage changed')
    tree=ast.parse(raw)
    return next(ast.literal_eval(n.value) for n in tree.body if isinstance(n,ast.Assign) and getattr(n.targets[0],'id','')=='_ROLES')


HARNESS=r'''
$ErrorActionPreference='Stop'
$script:SignatureStatus='Valid'
function Get-AuthenticodeSignature { @{Status=$script:SignatureStatus;SignerCertificate=@{Subject='CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US'}} }
$script:OwnerSid='account';$script:Services=@()
function Invoke-CimMethod { @{ReturnValue=0;Sid=$script:OwnerSid} }
function Get-CimInstance { @($script:Services) }
Add-Type -TypeDefinition @'
using System;using System.Collections.Generic;
public sealed class RecoveryStubFacts {public UInt32 pid;public string image="";public string package="";public int packageError=15700;public UInt32 protection=0xfffffffe;public UInt64 birth=1;}
public static class RecoveryProcessIdentity {
 public static Dictionary<UInt32,RecoveryStubFacts> Rows=new Dictionary<UInt32,RecoveryStubFacts>();
 public static RecoveryStubFacts Read(UInt32 id){return Rows[id];}
 public static bool Image(RecoveryStubFacts facts,string name,string birth){return facts.image.EndsWith("\\"+name,StringComparison.OrdinalIgnoreCase);}
}
'@
function Facts([UInt32]$id,[string]$image,[string]$package,[int]$packageError,[UInt32]$protection,[UInt64]$birth) {
 $row=New-Object RecoveryStubFacts;$row.pid=$id;$row.image=$image;$row.package=$package;$row.packageError=$packageError;$row.protection=$protection;$row.birth=$birth
 [RecoveryProcessIdentity]::Rows[$id]=$row;return $row
}
$RecoveryRoleProcessMap=@{}
$script:Failed=New-Object 'System.Collections.Generic.List[string]'
function Expect([bool]$actual,[bool]$wanted,[string]$label){if($actual -ne $wanted){$script:Failed.Add($label)}}
function Unsigned([scriptblock]$check){$RecoveryRoleSignatures.Clear();$script:SignatureStatus='NotSigned';$value=[bool](& $check);$script:SignatureStatus='Valid';$RecoveryRoleSignatures.Clear();return $value}
# Store app in the ordinary session
$hub='Microsoft.MicrosoftOfficeHub_19.2610.37021.0_x64__8wekyb3d8bbwe'
$hubImage=$env:ProgramFiles+'\WindowsApps\'+$hub+'\M365Copilot.exe'
$p=@{Name='M365Copilot.exe';SessionId=1;ProcessId=50};$native=@{image=$hubImage;package=$hub;packageError=0;protection=[UInt32]4294967294}
Expect (Test-RecoveryExtraRole $p $native 'account' 1) $true 'OFFICE_REFUSED'
Expect (Test-RecoveryExtraRole $p $native 'account' 2) $false 'OFFICE_WRONG_SESSION'
Expect (Test-RecoveryExtraRole $p $native 'other' 1) $false 'OFFICE_WRONG_OWNER'
Expect (Unsigned {Test-RecoveryExtraRole $p $native 'account' 1}) $false 'OFFICE_UNSIGNED'
$native.image='C:\Temp\M365Copilot.exe';Expect (Test-RecoveryExtraRole $p $native 'account' 1) $false 'OFFICE_WRONG_PATH';$native.image=$hubImage
$native.package='Contoso.App_1.0.0.0_x64__8wekyb3d8bbwe';Expect (Test-RecoveryExtraRole $p $native 'account' 1) $false 'OFFICE_WRONG_PACKAGE';$native.package=$hub
$native.packageError=15700;Expect (Test-RecoveryExtraRole $p $native 'account' 1) $false 'OFFICE_NO_PACKAGE';$native.packageError=0
# WebView child of the Office hub
$webview=${env:ProgramFiles(x86)}+'\Microsoft\EdgeWebView\Application\141.0.3537.71\msedgewebview2.exe'
$RecoveryRoleProcessMap.Clear();$RecoveryRoleProcessMap[[UInt32]91]=@{Name='M365Copilot.exe';SessionId=1;ProcessId=91;ParentProcessId=1;CreationDate=$null}
$null=Facts 91 $hubImage $hub 0 ([UInt32]4294967294) 1
$p=@{Name='msedgewebview2.exe';SessionId=1;ProcessId=90;ParentProcessId=91};$native=Facts 90 $webview $hub 0 ([UInt32]4294967294) 2
Expect (Test-RecoveryExtraRole $p $native 'account' 1) $true 'WEBVIEW_REFUSED'
Expect (Test-RecoveryExtraRole $p $native 'other' 1) $false 'WEBVIEW_WRONG_OWNER'
$RecoveryRoleProcessMap[[UInt32]91].Name='Contoso.exe';Expect (Test-RecoveryExtraRole $p $native 'account' 1) $false 'WEBVIEW_WRONG_PARENT';$RecoveryRoleProcessMap[[UInt32]91].Name='M365Copilot.exe'
$native.birth=[UInt64]0;Expect (Test-RecoveryExtraRole $p $native 'account' 1) $false 'WEBVIEW_OLDER_THAN_PARENT';$native.birth=[UInt64]2
$RecoveryRoleSignatures[$webview]=$false;Expect (Test-RecoveryExtraRole $p $native 'account' 1) $false 'WEBVIEW_UNSIGNED';$RecoveryRoleSignatures.Clear()
$RecoveryRoleProcessMap.Clear()
# Lock screen app
$lock=$env:SystemRoot+'\SystemApps\Microsoft.LockApp_cw5n1h2txyewy\LockApp.exe'
$p=@{Name='LockApp.exe';SessionId=1};$native=@{image=$lock}
Expect (Test-RecoveryExtraRole $p $native 'account' 1) $true 'LOCK_REFUSED'
Expect (Test-RecoveryExtraRole $p $native 'account' 2) $false 'LOCK_WRONG_SESSION'
Expect (Unsigned {Test-RecoveryExtraRole $p $native 'account' 1}) $false 'LOCK_UNSIGNED'
$native.image='C:\Temp\LockApp.exe';Expect (Test-RecoveryExtraRole $p $native 'account' 1) $false 'LOCK_WRONG_PATH'
# SmartScreen, briefly after a sign-in
$smart=$env:SystemRoot+'\System32\smartscreen.exe'
$p=@{Name='smartscreen.exe';SessionId=1};$native=@{image=$smart}
Expect (Test-RecoveryExtraRole $p $native 'account' 1) $true 'SMARTSCREEN_REFUSED'
Expect (Test-RecoveryExtraRole $p $native 'account' 2) $false 'SMARTSCREEN_WRONG_SESSION'
Expect (Unsigned {Test-RecoveryExtraRole $p $native 'account' 1}) $false 'SMARTSCREEN_UNSIGNED'
$native.image=$env:SystemRoot+'\Temp\smartscreen.exe';Expect (Test-RecoveryExtraRole $p $native 'account' 1) $false 'SMARTSCREEN_WRONG_PATH'
# Helper of the unconfigured per-user OneDrive
function Get-RecoveryOneDriveMetadata { $script:OneDriveMetadata }
$script:OneDriveMetadata=@{ownerSid='account';profileRoot='C:\Users\fixtureuser';hiveLoaded=$true;accountsKnown=$true;configuredFieldsAbsent=$true}
$sync='C:\Users\fixtureuser\AppData\Local\Microsoft\OneDrive\26.198.1011.0006\OneDrive.Sync.Service.exe'
$p=@{Name='OneDrive.Sync.Service.exe';SessionId=1;CommandLine=('"'+$sync+'" /silentConfig')};$native=@{image=$sync}
Expect (Test-RecoveryExtraRole $p $native 'account' 1) $true 'SYNC_REFUSED'
Expect (Test-RecoveryExtraRole $p $native 'account' 2) $false 'SYNC_WRONG_SESSION'
Expect (Unsigned {Test-RecoveryExtraRole $p $native 'account' 1}) $false 'SYNC_UNSIGNED'
$p.CommandLine=('"'+$sync+'" /sync');Expect (Test-RecoveryExtraRole $p $native 'account' 1) $false 'SYNC_WRONG_ARGUMENT';$p.CommandLine=('"'+$sync+'" /silentConfig')
$elsewhere='C:\Temp\OneDrive.Sync.Service.exe';$native.image=$elsewhere;$p.CommandLine=('"'+$elsewhere+'" /silentConfig');Expect (Test-RecoveryExtraRole $p $native 'account' 1) $false 'SYNC_WRONG_PATH';$native.image=$sync;$p.CommandLine=('"'+$sync+'" /silentConfig')
$script:OneDriveMetadata=$null;Expect (Test-RecoveryExtraRole $p $native 'account' 1) $false 'SYNC_CONFIGURED_ACCOUNT'
$script:OneDriveMetadata=@{ownerSid='other';profileRoot='C:\Users\fixtureuser';hiveLoaded=$true;accountsKnown=$true;configuredFieldsAbsent=$true};Expect (Test-RecoveryExtraRole $p $native 'account' 1) $false 'SYNC_WRONG_OWNER'
# Defender AI host: one accepted identity, then each case differs by one fact
$platform=$env:ProgramData+'\Microsoft\Windows Defender\Platform\4.18.26100.4-0\'
function Reset-Defender {
 $script:OwnerSid='S-1-5-19';$script:Services=@();$script:SignatureStatus='Valid';$RecoveryRoleSignatures.Clear();$RecoveryRoleProcessMap.Clear()
 $RecoveryRoleProcessMap[[UInt32]61]=@{Name='MsMpEng.exe';SessionId=0;ProcessId=61;CreationDate=$null}
 $script:ParentNative=Facts 61 ($platform+'MsMpEng.exe') '' 15700 3 1
 $script:AiHost=@{Name='DefenderAiPlatformHost.exe';SessionId=0;ProcessId=60;ParentProcessId=61}
 $script:AiHostNative=Facts 60 ($platform+'DefenderAiPlatformHost.exe') '' 15700 3 2
}
function Defender {[bool](Test-RecoveryExtraRole $script:AiHost $script:AiHostNative 'account' 1)}
Reset-Defender;Expect (Defender) $true 'DEFENDER_REFUSED'
Reset-Defender;$script:AiHostNative.image='C:\Temp\DefenderAiPlatformHost.exe';Expect (Defender) $false 'DEFENDER_WRONG_PATH'
Reset-Defender;$script:AiHostNative.protection=[UInt32]0;Expect (Defender) $false 'DEFENDER_UNPROTECTED'
Reset-Defender;$script:AiHost.SessionId=1;Expect (Defender) $false 'DEFENDER_WRONG_SESSION'
Reset-Defender;$script:OwnerSid='S-1-5-18';Expect (Defender) $false 'DEFENDER_WRONG_OWNER'
Reset-Defender;$script:Services=@(@{Name='service'});Expect (Defender) $false 'DEFENDER_OWN_SERVICE'
Reset-Defender;$RecoveryRoleProcessMap.Clear();Expect (Defender) $false 'DEFENDER_NO_PARENT'
Reset-Defender;$RecoveryRoleProcessMap[[UInt32]61].Name='Contoso.exe';Expect (Defender) $false 'DEFENDER_WRONG_PARENT'
Reset-Defender;$script:ParentNative.protection=[UInt32]0;Expect (Defender) $false 'DEFENDER_PARENT_UNPROTECTED'
Reset-Defender;$script:ParentNative.birth=[UInt64]3;Expect (Defender) $false 'DEFENDER_PARENT_YOUNGER'
Reset-Defender;$RecoveryRoleSignatures[$script:AiHostNative.image]=$false;Expect (Defender) $false 'DEFENDER_UNSIGNED'
Reset-Defender;$RecoveryRoleSignatures[$script:ParentNative.image]=$false;Expect (Defender) $false 'DEFENDER_PARENT_UNSIGNED'
Reset-Defender
$script:OwnerSid='account';$script:Services=@();$RecoveryRoleProcessMap.Clear()
# Store desktop extension: wrong package facts refuse before any package lookup
$store='Microsoft.WindowsStore_22609.1401.12.0_x64__8wekyb3d8bbwe'
$storeImage=$env:ProgramFiles+'\WindowsApps\'+$store+'\StoreDesktopExtension.exe'
if(Get-Command Test-RecoveryPublishedPackage -ErrorAction SilentlyContinue){
 Expect (Test-RecoveryPublishedPackage @{image=($env:ProgramFiles+'\WindowsApps\Contoso.App_1.0.0.0_x64__8wekyb3d8bbwe\StoreDesktopExtension.exe');package='Contoso.App_1.0.0.0_x64__8wekyb3d8bbwe';packageError=0} 'account' 'Microsoft.WindowsStore' 'StoreDesktopExtension.exe') $false 'STORE_WRONG_PACKAGE'
 Expect (Test-RecoveryPublishedPackage @{image='C:\Temp\StoreDesktopExtension.exe';package=$store;packageError=0} 'account' 'Microsoft.WindowsStore' 'StoreDesktopExtension.exe') $false 'STORE_WRONG_PATH'
 Expect (Test-RecoveryPublishedPackage @{image=$storeImage;package=$store;packageError=15700} 'account' 'Microsoft.WindowsStore' 'StoreDesktopExtension.exe') $false 'STORE_NO_PACKAGE'
 Expect ($RecoveryRolePackages.Count -eq 0) $true 'STORE_LOOKUP_REACHED'
}
function Test-RecoveryPublishedPackage([object]$native,[string]$ordinary,[string]$identity,[string]$relative) { $identity -eq 'Microsoft.WindowsStore' -and $relative -eq 'StoreDesktopExtension.exe' }
$p=@{Name='StoreDesktopExtension.exe';SessionId=1;ProcessId=80};$native=@{image=$storeImage;package=$store;packageError=0}
Expect (Test-RecoveryExtraRole $p $native 'account' 1) $true 'STORE_REFUSED'
Expect (Test-RecoveryExtraRole $p $native 'other' 1) $false 'STORE_WRONG_OWNER'
Expect (Test-RecoveryExtraRole $p $native 'account' 2) $false 'STORE_WRONG_SESSION'
# A running Edge updater has no role at all
$p=@{Name='MicrosoftEdgeUpdate.exe';SessionId=0;ProcessId=70};$native=@{pid=[UInt32]70;image=(${env:ProgramFiles(x86)}+'\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe');protection=[UInt32]4294967294}
Expect (Test-RecoveryExtraRole $p $native 'account' 1) $false 'EDGE_UPDATER_ALLOWED'
[Console]::WriteLine((@{failed=@($script:Failed)}|ConvertTo-Json -Compress))
'''


def script(roles=None):return "Set-StrictMode -Off\n"+(processes._ROLES if roles is None else roles)+HARNESS


POSITIVE=('OFFICE_REFUSED','WEBVIEW_REFUSED','LOCK_REFUSED','SMARTSCREEN_REFUSED','SYNC_REFUSED','DEFENDER_REFUSED','STORE_REFUSED')


class RoleSourceTests(unittest.TestCase):
    def test_each_new_name_is_absent_before_and_dispatched_now(self):
        before=before_roles()
        for name in ('M365Copilot.exe','DefenderAiPlatformHost.exe','LockApp.exe','OneDrive.Sync.Service.exe','smartscreen.exe','StoreDesktopExtension.exe'):
            self.assertNotIn(name,before);self.assertIn("'"+name+"'",processes._ROLES)
        store=before_roles('processes-store.before.source')
        self.assertNotIn('StoreDesktopExtension.exe',store);self.assertNotIn('smartscreen.exe',store)
        self.assertNotIn('MicrosoftEdgeUpdate',processes._ROLES)
    def test_smartscreen_is_not_on_the_wide_baseline(self):
        baseline=re.search(r"\$baseline=@\([^\n]*\)",idle._OBSERVE).group(0)
        self.assertNotIn('smartscreen',baseline)
    def test_harness_ends_with_one_output_line(self):
        lines=script().rstrip().splitlines();self.assertEqual(1,sum(line.lstrip().startswith('[Console]::WriteLine(')for line in lines));self.assertTrue(lines[-1].startswith('[Console]::WriteLine('))


@unittest.skipUnless(os.name=='nt' and shutil.which('powershell.exe'),'Actual Windows PowerShell role decisions')
class NativeRoleTests(unittest.TestCase):
    def failed(self,source):
        with tempfile.TemporaryDirectory()as directory:
            path=Path(directory)/'roles.ps1';path.write_text(source,encoding='utf-8')
            result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',str(path)],capture_output=True,timeout=120)
        self.assertEqual(0,result.returncode,(result.stdout+result.stderr).decode(errors='replace'))
        value=json.loads(result.stdout)['failed'];return [] if value is None else [value] if type(value) is str else value
    def test_before_refuses_each_real_role_and_current_decides_every_control(self):
        failed=self.failed(script(before_roles()))
        for label in POSITIVE:self.assertIn(label,failed)
        failed=self.failed(script(before_roles('processes-store.before.source')))
        self.assertIn('STORE_REFUSED',failed);self.assertIn('SMARTSCREEN_REFUSED',failed)
        self.assertEqual([],self.failed(script()))


if __name__=='__main__':unittest.main()
