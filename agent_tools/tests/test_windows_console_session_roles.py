"""Image 637199a5's Microsoft console-session roles are known only by their whole identity.

Native contacts of 2026-11-09: the full idle census refused with unknown_jobs on two
clones of the image, and later on the never-signed-in one for the Windows Defender
Firewall prompt alone. The fixture keeps the unfixed roles of both contacts and their
census byte for byte, and a synthetic projection of the native facts. On Windows the
whole census, composed as production composes it (the module's own native reader with
only its OS calls answered, the roles, ALLOWANCE and _OBSERVE), runs in Windows
PowerShell: each unfixed program reproduces its native unknown set (RED), the fixed one
knows every role (GREEN), and each control that differs from the native facts by one
fact stays unknown.
"""
import hashlib,json,os,re,shutil,subprocess,tempfile,types,unittest
from pathlib import Path
from agent_tools import readiness_windows_idle as idle,readiness_windows_processes as processes

FIXTURE=Path(__file__).parent/'fixtures/windows_console_session_roles'
OUTPUT='[Console]::WriteLine(($result|ConvertTo-Json -Depth 10 -Compress))'
WINDOWS='CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US'
MICROSOFT='CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US'
OTHER_SID='S-1-5-21-1-2-3-1001'


def before():
    """The roles that refused first, the roles the firewall census ran, and their census."""
    provenance=json.loads((FIXTURE/'provenance.json').read_bytes());modules=[]
    for filename in ('processes.before.source','processes-firewall.before.source','idle.before.source'):
        raw=(FIXTURE/filename).read_bytes()
        if hashlib.sha256(raw).hexdigest()!=provenance['sources'][filename]['sha256']:raise ValueError('console_roles_before_changed')
        module=types.ModuleType('agent_tools._console_roles_before');module.__package__='agent_tools';module.__file__=str(FIXTURE/filename)
        exec(compile(raw,module.__file__,'exec'),module.__dict__);modules.append(module)
    return modules


def facts():
    raw=(FIXTURE/'native-facts.json').read_bytes()
    if hashlib.sha256(raw).hexdigest()!=json.loads((FIXTURE/'provenance.json').read_bytes())['sources']['native-facts.json']['sha256']:
        raise ValueError('console_roles_facts_changed')
    return json.loads(raw)


def literal(value):
    return "'"+str(value).replace("'","''")+"'"


def boundary(native):
    """The module's own native reader; only its six OS calls answer from a per-pid table."""
    replacements={
      '[DllImport("kernel32.dll",SetLastError=true)]static extern IntPtr OpenProcess(uint access,bool inherit,uint pid);':
      'public static System.Collections.Generic.Dictionary<uint,string[]> Rows=new System.Collections.Generic.Dictionary<uint,string[]>();static IntPtr OpenProcess(uint access,bool inherit,uint pid){return Rows.ContainsKey(pid)?new IntPtr((long)pid):IntPtr.Zero;}',
      '[DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern bool QueryFullProcessImageName(IntPtr h,uint flags,StringBuilder name,ref uint count);':
      'static bool QueryFullProcessImageName(IntPtr h,uint flags,StringBuilder name,ref uint count){name.Append(flags==0?Rows[(uint)h.ToInt64()][0]:"");return true;}',
      '[DllImport("kernel32.dll",SetLastError=true)]static extern bool GetProcessTimes(IntPtr h,out long creation,out long exit,out long kernel,out long user);':
      'static bool GetProcessTimes(IntPtr h,out long creation,out long exit,out long kernel,out long user){creation=long.Parse(Rows[(uint)h.ToInt64()][1]);exit=kernel=user=0;return true;}',
      '[DllImport("kernel32.dll",SetLastError=true)]static extern bool GetProcessInformation(IntPtr h,int kind,out uint protection,uint size);':
      'static bool GetProcessInformation(IntPtr h,int kind,out uint protection,uint size){protection=uint.Parse(Rows[(uint)h.ToInt64()][2]);return true;}',
      '[DllImport("kernel32.dll",CharSet=CharSet.Unicode)]static extern int GetPackageFullName(IntPtr h,ref uint length,StringBuilder name);':
      'static int GetPackageFullName(IntPtr h,ref uint length,StringBuilder name){string p=Rows[(uint)h.ToInt64()][3];if(p.Length==0)return 15700;if(name==null){length=(uint)p.Length+1;return 122;}name.Append(p);return 0;}',
      '[DllImport("kernel32.dll")]static extern bool CloseHandle(IntPtr h);':
      'static bool CloseHandle(IntPtr h){return true;}',
    }
    for old,new in replacements.items():
        if native.count(old)!=1:raise ValueError('console_roles_native_boundary_changed')
        native=native.replace(old,new)
    return "Add-Type -TypeDefinition @'\n"+native+"\n'@\n"


PRELUDE=r'''
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$Machine='machine';$Boot='boot'
$leaseFacts=@{};$jobFacts=@{}
function Get-CimInstance([string]$ClassName,[string]$Filter){if($ClassName -eq 'Win32_Process'){return $script:Census};return @()}
function Invoke-CimMethod($InputObject,[string]$MethodName){@{ReturnValue=0;Sid=$script:Owners[[UInt32]$InputObject.ProcessId]}}
function Get-AuthenticodeSignature($LiteralPath){if($script:Signers.ContainsKey([string]$LiteralPath)){@{Status='Valid';SignerCertificate=@{Subject=$script:Signers[[string]$LiteralPath]}}}else{@{Status='NotSigned';SignerCertificate=$null}}}
function Get-ItemProperty { @{SystemSetupInProgress=0;OOBEInProgress=0} }
function Get-ScheduledTask { @{State='Disabled'} }
function Test-Path { $false }
'''

WORLD=r'''
function Add-Process([UInt32]$id,[string]$name,[UInt32]$parent,[UInt32]$session,[string]$image,[string]$birth,[UInt32]$protection,[string]$package,[string]$owner,[string]$commandLine){
 [RecoveryProcessIdentity]::Rows[$id]=[string[]]@($image,$birth,[string]$protection,$package);$script:Owners[$id]=$owner
 $script:Census+=,([pscustomobject]@{ProcessId=$id;Name=$name;ParentProcessId=$parent;SessionId=$session;CreationDate=[DateTime]::FromFileTimeUtc([Int64]($birth.Substring(0,$birth.Length-1)+'0'));CommandLine=$commandLine;ExecutablePath=$image})
}
function Get-Row([UInt32]$id){foreach($row in $script:Census){if([UInt32]$row.ProcessId -eq $id){return $row}}}
function Set-Birth([UInt32]$id,[string]$birth){[RecoveryProcessIdentity]::Rows[$id][1]=$birth;(Get-Row $id).CreationDate=[DateTime]::FromFileTimeUtc([Int64]($birth.Substring(0,$birth.Length-1)+'0'))}
function Get-Unknown($census){@($census.processes|Where-Object {-not $_.knownSystem}|ForEach-Object {[string]$_.name}|Sort-Object)}
function Test-Known($census,[string]$name){$rows=@($census.processes|Where-Object {$_.name -eq $name});return [bool]($rows.Count -eq 1 -and $rows[0].knownSystem)}
'''


def add_process(variable,name,row):
    return (' Add-Process $'+variable+' '+literal(name)+' '+str(row['parent']['pid'])+' $Console $'+variable+'Image '+literal(row['birth'])+' '+str(row['protection'])
            +' '+literal(row['packageFullName'])+' $Account '+literal(row['commandLine'])+'\n $script:Signers[$'+variable+'Image]=$Microsoft')


def world(value):
    """The never-signed-in clone's console session as its two native role probes read it:
    Reset-World is the session of census 45f127d9; Add-FirewallPrompt adds the prompt that
    census d82d82a4 found beside the same four roles."""
    roles={row['name']:row for row in value['freshClone']['roles']}
    prompt=value['firewallPrompt']['roles'][0]
    host=roles['AppActions.exe']['parent']
    if roles['WidgetService.exe']['parent']!=host or prompt['parent']!=host or host['name']!='svchost.exe' or host['session']!=0 or not host['identityValid']:
        raise ValueError('console_roles_parent_changed')
    names={'AppActions.exe':'AppActions','WidgetService.exe':'WidgetService','OneDrive.exe':'OneDrive','OneDrive.Sync.Service.exe':'Sync'}
    lines=['$Account='+literal(value['ordinarySid'])+';$ProfileRoot='+literal(value['profileRoot'])+';$Console=[UInt32]'+str(value['consoleSession']),
           "$sessionFacts=@{machine='machine';boot='boot';expectedSid=$Account;ordinary=$true;console=$Console}",
           '$Q=[string][char]34;$Microsoft='+literal(MICROSOFT)+';$Contoso='+literal('CN=Contoso, O=Contoso, C=US')+';$OtherSid='+literal(OTHER_SID),
           # The session's shell, by the census's explorer pid, is a parent the user could start from.
           '$ServiceHost=[UInt32]'+str(host['pid'])+';$ServiceHostImage='+literal(host['image'])+';$Shell=[UInt32]'+str(value['freshClone']['shellPid']),
           '$Picker=[UInt32]'+str(prompt['pid'])+';$PickerImage='+literal(prompt['image'])]
    for name,variable in names.items():lines.append('$'+variable+'=[UInt32]'+str(roles[name]['pid'])+';$'+variable+'Image='+literal(roles[name]['image']))
    lines.append('function Reset-World {')
    lines.append(' $script:Census=@();$script:Owners=@{};$script:Signers=@{};[RecoveryProcessIdentity]::Rows.Clear()')
    lines.append(' $script:OneDriveMetadata=@{ownerSid=$Account;profileRoot=$ProfileRoot;hiveLoaded=$true;accountsKnown=$true;configuredFieldsAbsent=$true}')
    lines.append(" Add-Process $ServiceHost 'svchost.exe' 0 0 $ServiceHostImage "+literal(host['birth'])+" 0 '' 'S-1-5-18' ''")
    lines.append(" Add-Process $Shell 'explorer.exe' 0 $Console ($env:SystemRoot+'\\explorer.exe') '134386587900000000' 0 '' $Account ''")
    lines.append(" $script:Signers[$ServiceHostImage]="+literal(WINDOWS))
    for row in [*roles.values(),prompt]:
        if row['ownerSid']!=value['ordinarySid'] or row['session']!=value['consoleSession'] or not(row['signatureValid'] and row['microsoftPublisher']):
            raise ValueError('console_roles_fact_changed')
    for name,variable in names.items():lines.append(add_process(variable,name,roles[name]))
    lines.append('}')
    lines.append('function Add-FirewallPrompt {')
    lines.append(add_process('Picker','PickerHost.exe',prompt))
    lines.append('}')
    return '\n'.join(lines)+'\n'


# Each control differs from the native facts by one fact; True means it must stay known.
# Every control runs in the later session, with the firewall prompt beside the four roles.
# $Q is a double quote, $Contoso a foreign signer and $OtherSid another account.
MOVE_PACKAGE=r";$row=[RecoveryProcessIdentity]::Rows[$WidgetService];$row[0]=$row[0].Replace($from,$to);$row[3]=$row[3].Replace($from,$to);(Get-Row $WidgetService).CommandLine=(Get-Row $WidgetService).CommandLine.Replace($from,$to);$script:Signers[$row[0]]=$Microsoft"
CONTROLS=(
  ('APPACTIONS_IMAGE_ELSEWHERE','AppActions.exe',r"[RecoveryProcessIdentity]::Rows[$AppActions][0]='C:\Windows\Temp\AppActions.exe'",False),
  ('APPACTIONS_FOREIGN_PACKAGE','AppActions.exe',r"[RecoveryProcessIdentity]::Rows[$AppActions][3]='Contoso.Actions_1000.26100.234.0_x64__cw5n1h2txyewy'",False),
  ('APPACTIONS_OTHER_WINDOWS_PACKAGE','AppActions.exe',r"[RecoveryProcessIdentity]::Rows[$AppActions][3]='MicrosoftWindows.Client.Core_1000.26100.234.0_x64__cw5n1h2txyewy'",False),
  ('APPACTIONS_STORE_PUBLISHER','AppActions.exe',r"[RecoveryProcessIdentity]::Rows[$AppActions][3]='MicrosoftWindows.Client.CBS_1000.26100.234.0_x64__8wekyb3d8bbwe'",False),
  ('APPACTIONS_NO_PACKAGE','AppActions.exe',r"[RecoveryProcessIdentity]::Rows[$AppActions][3]=''",False),
  ('APPACTIONS_UNSIGNED','AppActions.exe',r"$script:Signers.Remove($AppActionsImage)",False),
  ('APPACTIONS_OTHER_PUBLISHER','AppActions.exe',r"$script:Signers[$AppActionsImage]=$Contoso",False),
  ('APPACTIONS_OTHER_OWNER','AppActions.exe',r"$script:Owners[$AppActions]=$OtherSid",False),
  ('APPACTIONS_OTHER_SESSION','AppActions.exe',r"(Get-Row $AppActions).SessionId=3",False),
  ('APPACTIONS_SHELL_PARENT','AppActions.exe',r"(Get-Row $AppActions).ParentProcessId=$Shell",False),
  ('APPACTIONS_PARENT_GONE','AppActions.exe',r"(Get-Row $AppActions).ParentProcessId=1452",False),
  ('APPACTIONS_PARENT_YOUNGER','AppActions.exe',r"Set-Birth $ServiceHost '134386589364213040'",False),
  ('APPACTIONS_ARGUMENTS','AppActions.exe',r"(Get-Row $AppActions).CommandLine=($Q+$AppActionsImage+$Q+' -Embedding -ServerName:Other')",False),
  ('WIDGET_IMAGE_ELSEWHERE','WidgetService.exe',r"[RecoveryProcessIdentity]::Rows[$WidgetService][0]=$WidgetServiceImage.Replace('\Dashboard\','\WidgetService\')",False),
  ('WIDGET_FOREIGN_PACKAGE','WidgetService.exe',r"$from='MicrosoftWindows.Client.WebExperience_';$to='Contoso.WebExperience_'"+MOVE_PACKAGE,False),
  ('WIDGET_STORE_PUBLISHER','WidgetService.exe',r"$from='_cw5n1h2txyewy';$to='_8wekyb3d8bbwe'"+MOVE_PACKAGE,False),
  ('WIDGET_NO_PACKAGE','WidgetService.exe',r"[RecoveryProcessIdentity]::Rows[$WidgetService][3]=''",False),
  ('WIDGET_UNSIGNED','WidgetService.exe',r"$script:Signers.Remove($WidgetServiceImage)",False),
  ('WIDGET_OTHER_PUBLISHER','WidgetService.exe',r"$script:Signers[$WidgetServiceImage]=$Contoso",False),
  ('WIDGET_OTHER_OWNER','WidgetService.exe',r"$script:Owners[$WidgetService]=$OtherSid",False),
  ('WIDGET_OTHER_SESSION','WidgetService.exe',r"(Get-Row $WidgetService).SessionId=3",False),
  ('WIDGET_SHELL_PARENT','WidgetService.exe',r"(Get-Row $WidgetService).ParentProcessId=$Shell",False),
  ('WIDGET_PARENT_IN_SESSION','WidgetService.exe',r"(Get-Row $ServiceHost).SessionId=$Console",False),
  ('WIDGET_PARENT_IMAGE','WidgetService.exe',r"[RecoveryProcessIdentity]::Rows[$ServiceHost][0]=$ServiceHostImage.Replace('\System32\','\SysWOW64\')",False),
  ('WIDGET_PARENT_UNSIGNED','WidgetService.exe',r"$script:Signers.Remove($ServiceHostImage)",False),
  ('WIDGET_ARGUMENTS','WidgetService.exe',r"(Get-Row $WidgetService).CommandLine=($Q+$WidgetServiceImage+$Q+' -Embedding')",False),
  ('SYNC_IMAGE_ELSEWHERE','OneDrive.Sync.Service.exe',r"[RecoveryProcessIdentity]::Rows[$Sync][0]=$SyncImage.Replace('\Microsoft\OneDrive\','\Temp\')",False),
  ('SYNC_OTHER_ARGUMENT','OneDrive.Sync.Service.exe',r"(Get-Row $Sync).CommandLine='/silentConfig /sync'",False),
  ('SYNC_QUOTED_OTHER_ARGUMENT','OneDrive.Sync.Service.exe',r"(Get-Row $Sync).CommandLine=($Q+$SyncImage+$Q+' /sync')",False),
  ('SYNC_UNSIGNED','OneDrive.Sync.Service.exe',r"$script:Signers.Remove($SyncImage)",False),
  ('SYNC_OTHER_PUBLISHER','OneDrive.Sync.Service.exe',r"$script:Signers[$SyncImage]=$Contoso",False),
  ('SYNC_OTHER_OWNER','OneDrive.Sync.Service.exe',r"$script:OneDriveMetadata.ownerSid=$OtherSid",False),
  ('SYNC_OTHER_SESSION','OneDrive.Sync.Service.exe',r"(Get-Row $Sync).SessionId=3",False),
  ('SYNC_CONFIGURED_ACCOUNT','OneDrive.Sync.Service.exe',r"$script:OneDriveMetadata=$null",False),
  ('ONEDRIVE_CONFIGURED_ACCOUNT','OneDrive.exe',r"$script:OneDriveMetadata=$null",False),
  ('ONEDRIVE_VERSIONED_IMAGE','OneDrive.exe',r"$image=$OneDriveImage.Replace('\OneDrive\OneDrive.exe','\OneDrive\26.198.1011.0006\OneDrive.exe');[RecoveryProcessIdentity]::Rows[$OneDrive][0]=$image;$script:Signers[$image]=$Microsoft",False),
  ('PICKER_IMAGE_ELSEWHERE','PickerHost.exe',r"[RecoveryProcessIdentity]::Rows[$Picker][0]=$PickerImage.Replace('\System32\','\SysWOW64\')",False),
  ('PICKER_QUOTED_IMAGE','PickerHost.exe',r"(Get-Row $Picker).CommandLine=($Q+$PickerImage+$Q+' FirewallNotificationDialogServer -Embedding')",False),
  ('PICKER_PACKAGED','PickerHost.exe',r"[RecoveryProcessIdentity]::Rows[$Picker][3]='MicrosoftWindows.Client.CBS_1000.26100.234.0_x64__cw5n1h2txyewy'",False),
  ('PICKER_UNSIGNED','PickerHost.exe',r"$script:Signers.Remove($PickerImage)",False),
  ('PICKER_OTHER_PUBLISHER','PickerHost.exe',r"$script:Signers[$PickerImage]=$Contoso",False),
  ('PICKER_OTHER_OWNER','PickerHost.exe',r"$script:Owners[$Picker]=$OtherSid",False),
  ('PICKER_OTHER_SESSION','PickerHost.exe',r"(Get-Row $Picker).SessionId=3",False),
  ('PICKER_SHELL_PARENT','PickerHost.exe',r"(Get-Row $Picker).ParentProcessId=$Shell",False),
  ('PICKER_PARENT_GONE','PickerHost.exe',r"(Get-Row $Picker).ParentProcessId=1452",False),
  ('PICKER_PARENT_YOUNGER','PickerHost.exe',r"Set-Birth $ServiceHost '134386655186715986'",False),
  ('PICKER_OTHER_SERVER','PickerHost.exe',r"(Get-Row $Picker).CommandLine=($PickerImage+' OtherPickerServer -Embedding')",False),
  ('PICKER_NO_SERVER','PickerHost.exe',r"(Get-Row $Picker).CommandLine=($PickerImage+' -Embedding')",False),
  ('PICKER_MISSING_ARGUMENT','PickerHost.exe',r"(Get-Row $Picker).CommandLine=($PickerImage+' FirewallNotificationDialogServer')",False),
  ('PICKER_EXTRA_ARGUMENT','PickerHost.exe',r"(Get-Row $Picker).CommandLine=($PickerImage+' FirewallNotificationDialogServer -Embedding /extra')",False),
  # The forms the 2026-11-06 probe read on an earlier clone of the image stay known.
  ('SYNC_QUOTED_FORM','OneDrive.Sync.Service.exe',r"(Get-Row $Sync).CommandLine=($Q+$SyncImage+$Q+' /silentConfig')",True),
  ('ONEDRIVE_LOGON_FORM','OneDrive.exe',r"(Get-Row $OneDrive).CommandLine=($Q+$OneDriveImage+$Q+' /background');(Get-Row $OneDrive).ParentProcessId=$Shell",True),
)


def census_function(observe):
    if observe.count(OUTPUT)!=1:raise ValueError('console_roles_output_changed')
    return 'function Invoke-Census {\n'+observe.replace(OUTPUT,'return $result')+'\n}\n'


def phase(roles,census):
    return roles+'\nfunction Get-RecoveryOneDriveMetadata { return $script:OneDriveMetadata }\n'+census.ALLOWANCE+census_function(census._OBSERVE)


def program(value=None):
    """One ASCII program: each unfixed census in its own native session, then the fixed
    census in both sessions, then every control."""
    value=facts() if value is None else value
    old_processes,firewall_processes,old_idle=before()
    if not old_processes.NATIVE==firewall_processes.NATIVE==processes.NATIVE:raise ValueError('console_roles_native_changed')
    source=PRELUDE+boundary(processes.NATIVE)+WORLD+world(value)
    source+="foreach($id in @($ServiceHost,$Shell,$AppActions,$WidgetService,$OneDrive,$Sync,$Picker)){if($id -eq [UInt32]$PID){throw 'HARNESS_PID_COLLISION'}}\n"
    source+=phase(old_processes._ROLES,old_idle)+'Reset-World;$before=Invoke-Census\n'
    source+=phase(firewall_processes._ROLES,old_idle)+'Reset-World;Add-FirewallPrompt;$firewallBefore=Invoke-Census\n'
    source+=phase(processes._ROLES,idle)+'Reset-World;$fixed=Invoke-Census\nReset-World;Add-FirewallPrompt;$firewallFixed=Invoke-Census\n$controls=[ordered]@{}\n'
    for label,target,change,_ in CONTROLS:
        source+='Reset-World;Add-FirewallPrompt;$RecoveryRoleSignatures.Clear();'+change+';$controls['+literal(label)+']=Test-Known (Invoke-Census) '+literal(target)+'\n'
    source+=("[Console]::WriteLine((@{beforeUnknown=@(Get-Unknown $before);beforeBlockers=@($before.blockers);"
             "firewallBeforeUnknown=@(Get-Unknown $firewallBefore);firewallBeforeBlockers=@($firewallBefore.blockers);"
             "fixedUnknown=@(Get-Unknown $fixed);fixedBlockers=@($fixed.blockers);"
             "firewallFixedUnknown=@(Get-Unknown $firewallFixed);firewallFixedBlockers=@($firewallFixed.blockers);"
             "controls=$controls}|ConvertTo-Json -Depth 4 -Compress))\n")
    source.encode('ascii')
    return source


def listed(value):
    return [] if value is None else [value] if type(value)is str else list(value)


def observed_rule_gaps(roles):
    """Static oracle of the four identities the native censuses could not place."""
    gaps=[]
    if re.search(r"\$name -eq 'AppActions\.exe'",roles)is None:gaps.append('AppActions.exe')
    if "'MicrosoftWindows.Client.WebExperience'" not in roles or "'\\Dashboard\\WidgetService.exe'" not in roles:gaps.append('WidgetService.exe')
    if "[string]::Equals($commandLine,'/silentConfig'," not in roles:gaps.append('OneDrive.Sync.Service.exe')
    if re.search(r"\$name -eq 'PickerHost\.exe'",roles)is None or "' FirewallNotificationDialogServer -Embedding'" not in roles:gaps.append('PickerHost.exe')
    return gaps


class ConsoleSessionRoleSourceTests(unittest.TestCase):
    def test_the_fixture_binds_the_whole_unfixed_sources_and_a_synthetic_native_projection(self):
        old_processes,firewall_processes,old_idle=before()
        provenance=json.loads((FIXTURE/'provenance.json').read_bytes())
        for name in ('processes.before.source','processes-firewall.before.source'):
            self.assertEqual('agent_tools/readiness_windows_processes.py',provenance['sources'][name]['origin'].split(' ')[0])
        # Only the roles changed: the native reader and the census are those that ran.
        self.assertEqual(old_processes.NATIVE,processes.NATIVE);self.assertEqual(firewall_processes.NATIVE,processes.NATIVE)
        self.assertEqual((old_idle.ALLOWANCE,old_idle._OBSERVE),(idle.ALLOWANCE,idle._OBSERVE))
        raw=(FIXTURE/'native-facts.json').read_text(encoding='ascii')
        self.assertEqual({'S-1-5-21-1-2-3-1000','S-1-5-21-1-2-3-500'},set(re.findall(r'S-1-5-21-[0-9-]+[0-9]',raw)))
        for forbidden in (r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',r'DESKTOP-',r'/home/'):
            self.assertIsNone(re.search(forbidden,raw,re.I),forbidden)

    def test_the_native_censuses_are_the_recorded_failure(self):
        value=facts()
        self.assertEqual([['AppActions.exe',2],['OneDrive.Sync.Service.exe',2],['WidgetService.exe',2]],value['freshClone']['unknown'])
        self.assertIn(['OneDrive.exe',2],value['freshClone']['knownControls'])
        signed=value['signedInClone']
        self.assertTrue(all(census['unknown']==[['OneDrive.exe',2],['WidgetService.exe',2]]and census['blockers']==['unknown_jobs']for census in signed['censuses']))
        # OneDrive.exe was already unknown in the census before the first sign-in.
        self.assertLess(signed['censuses'][0]['observedUtc'],signed['firstSignIn']['lockedObservedUtc'])
        self.assertTrue(signed['firstSignIn']['sameLogon'])
        # The firewall census ran exactly the preserved roles, which knew the four earlier roles.
        prompt=value['firewallPrompt']
        self.assertEqual(([['PickerHost.exe',2]],['unknown_jobs']),(prompt['unknown'],prompt['blockers']))
        self.assertEqual([['AppActions.exe',2],['OneDrive.Sync.Service.exe',2],['OneDrive.exe',2],['WidgetService.exe',2]],prompt['knownControls'])
        self.assertEqual(json.loads((FIXTURE/'provenance.json').read_bytes())['sources']['processes-firewall.before.source']['sha256'],prompt['rolesSourceSha256'])

    def test_the_unfixed_rules_lack_each_observed_identity_and_the_current_rules_name_it(self):
        old_processes,firewall_processes,_=before()
        self.assertEqual(['AppActions.exe','WidgetService.exe','OneDrive.Sync.Service.exe','PickerHost.exe'],observed_rule_gaps(old_processes._ROLES))
        self.assertEqual(['PickerHost.exe'],observed_rule_gaps(firewall_processes._ROLES))
        self.assertEqual([],observed_rule_gaps(processes._ROLES))

    def test_the_harness_runs_every_whole_census_program_over_the_native_facts(self):
        old_processes,firewall_processes,old_idle=before();source=program()
        for roles in (old_processes._ROLES,firewall_processes._ROLES,processes._ROLES):self.assertEqual(1,source.count(roles))
        self.assertEqual(3,source.count(idle.ALLOWANCE));self.assertEqual(3,source.count(idle._OBSERVE.replace(OUTPUT,'return $result')))
        self.assertEqual(1,source.count('[Console]::WriteLine('))
        self.assertLess(source.index(old_processes._ROLES),source.index('$before=Invoke-Census'))
        self.assertLess(source.index('$before=Invoke-Census'),source.index(firewall_processes._ROLES))
        self.assertLess(source.index(firewall_processes._ROLES),source.index('$firewallBefore=Invoke-Census'))
        self.assertLess(source.index('$firewallBefore=Invoke-Census'),source.index(processes._ROLES))
        value=facts()
        for row in value['freshClone']['roles']+value['firewallPrompt']['roles']:
            for fact in (row['image'],row['birth'],row['packageFullName'],row['commandLine']):self.assertIn(literal(fact),source)
        kinds={'IMAGE','PACKAGE','PUBLISHER','UNSIGNED','OWNER','SESSION','PARENT','ARGUMENT'}
        for prefix in ('APPACTIONS','WIDGET','SYNC','PICKER'):
            covered={kind for kind in kinds for label,_,_,known in CONTROLS if label.startswith(prefix+'_')and kind in label and not known}
            self.assertEqual(kinds-({'PACKAGE','PARENT'}if prefix=='SYNC'else set()),covered,prefix)


@unittest.skipUnless(os.name=='nt' and shutil.which('powershell.exe'),'Actual Windows PowerShell census decisions')
class NativeConsoleSessionCensusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with tempfile.TemporaryDirectory()as directory:
            path=Path(directory)/'census.ps1';path.write_bytes(program().encode('ascii'))
            cls.result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',str(path)],capture_output=True,timeout=300)

    def value(self):
        self.assertEqual(0,self.result.returncode,(self.result.stdout+self.result.stderr).decode(errors='replace'))
        return json.loads(self.result.stdout.decode('utf-8-sig'))

    def test_unfixed_census_reproduces_the_native_unknowns_RED_and_the_fixed_census_knows_them_GREEN(self):
        value=self.value()
        self.assertEqual(sorted(name for name,_ in facts()['freshClone']['unknown']),listed(value['beforeUnknown']))
        self.assertIn('unknown_jobs',listed(value['beforeBlockers']))
        self.assertEqual([],listed(value['fixedUnknown']));self.assertNotIn('unknown_jobs',listed(value['fixedBlockers']))

    def test_first_fix_census_leaves_the_firewall_prompt_unknown_RED_and_the_fixed_census_knows_it_GREEN(self):
        value=self.value()
        self.assertEqual(sorted(name for name,_ in facts()['firewallPrompt']['unknown']),listed(value['firewallBeforeUnknown']))
        self.assertIn('unknown_jobs',listed(value['firewallBeforeBlockers']))
        self.assertEqual([],listed(value['firewallFixedUnknown']));self.assertNotIn('unknown_jobs',listed(value['firewallFixedBlockers']))

    def test_each_control_one_fact_from_the_native_identity_stays_unknown(self):
        self.assertEqual({label:known for label,_,_,known in CONTROLS},self.value()['controls'])


if __name__=='__main__':unittest.main()
