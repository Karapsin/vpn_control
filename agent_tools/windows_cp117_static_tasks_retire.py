"""Fixed five-task retirement; original outcomes remain historical and unknown.

No caller-supplied task, path, source or command is accepted. A consumed intent
is status-only, including partial deletion without the batch terminal.
"""
from __future__ import annotations
import base64
import gzip
import hashlib
import io
import json
import os
import re
import stat
import xml.etree.ElementTree as ET
from contextlib import contextmanager, nullcontext
from pathlib import Path
from typing import Any, Mapping
from . import windows_cp117_e848_http_task_retire as wire
from . import windows_cp117_protected_journal as journal
history=wire.observer.history
base=wire.base
# Fixed static batch has five snapshots; keep the shared transport unchanged.
assert wire._REMOTE_BODY.count('for _ in range(40):')==1
_REMOTE_BODY=wire._REMOTE_BODY.replace('for _ in range(40):','for _ in range(200):')
_REMOTE=(base._QGA if base is not None else '')+_REMOTE_BODY
_RETIREMENT='dd76ca4e-b958-4a92-9487-89a92eaa499d'
_DIR='.rag_index/windows-cp117-static-tasks-retirement'
_ROOT=r'C:\ProgramData\VpnControlCp117-retirement-'+_RETIREMENT
_NAMES=('VpnControlCp117_BaseInstall','VpnControlCp117OwnerQuitPhaseDiagnosticC32',
        'VpnControlCp117OwnerRelaunchC32','VpnControlCp117OwnerRelaunchQuitV3C32',
        'VpnControlCp117OwnerRelaunchQuitV4C32')
_LEAVES=('binding.json','archive.json','terminal.json',*(f'removed-{i}.json' for i in range(5)))
_PHASES=frozenset({'platform','history','generation','active-lease','parser','snapshot','task','action','principal','settings','process','installer','xml','archive','race','intent','dispatch','journal','terminal','absence','complete','base-lock','base-route'} | {'transport-'+p for p in wire._PROBE_PHASES})
# Dispatch source embeds this set: never extend it for an already consumed intent.
_ACTION_PHASES=_PHASES
_DIAGNOSTIC_PHASES=frozenset({'diagnostic-root-absence','diagnostic-root-metadata','diagnostic-root-acl','diagnostic-leaf-metadata','diagnostic-leaf-acl','diagnostic-encoding','diagnostic-schema','diagnostic-hash','diagnostic-state','diagnostic-complete','diagnostic-stage-binding','diagnostic-stage-archive','diagnostic-stage-progress','diagnostic-stage-terminal','diagnostic-terminal-absent-verified'})
_PHASES=_PHASES | _DIAGNOSTIC_PHASES
_FLAGS={'replayAllowed':False,'nativeActionAllowed':False,'productAction':False}
_SOURCE='19be9df22cbab8086c26e5ca907d9569a5a28a08'
_CLI='ca95b4e671c3effe05eb8f888a4260dedb6ff22363fe347383290240801dd2b1'
# Exact admitted records; request/product SHA is distinct from task-tool bytes.
_RECORDS={
 '.rag_index/windows-msi-base-prepare/c32cb108-4d48-407e-9153-40774559ba50.json':'99c296318904ba426128322675cf350c7de2b9d5d403814ddb7db42c17721d69',
 '.rag_index/windows-msi-owner-relaunch/c32cb108-4d48-407e-9153-40774559ba50.json':'78b53e48d2de145741bb846b13886190488574bd58413475f71467cf2bb9506d',
 '.rag_index/windows-msi-owner-relaunch-quit/44ac1ea9-b18b-4203-9cef-9e38c5d45970.json':'a2a88e39c8050fd613399f9e7c06b068792a47a11a2ab858a8504b50c514db29',
 '.rag_index/windows-msi-owner-relaunch-quit-v3/38daf3a3-a661-495e-a001-b2b0bdaa9a66.json':'184b00fea595169067b87dfd35280cd05e98c5648d82e65298fa92ee0fc609c7',
 '.rag_index/windows-msi-owner-relaunch-quit-v4/bf8c6d40-1021-4f8e-b2e3-73cdad967788.json':'8af0e49e90666f80b582d0b59843ccd1c2eff5f496ae82f8dcff05647cbfa59e',
 '.rag_index/windows-msi-owner-quit-phase-diagnostic/7c35c962-3fd3-42ce-914f-05f6e4a48a42.json':'1b5aa77dc24c4a64c3999dc688f6d7937be8ae30696854a06947e7eaa89479cc',
}
_ARGUMENT_HASHES=('9b22eff9a3ce8fab00c0c3aad52d823aab10284dd79e2a081f252ff1a331f2f7',
 'e69419401efd515b63253170b10ff135106125363fb158e254ef9b914ed7f979',
 '1d7aed326ac44b0a2e0e705c539ce6de9e3a2363971fbc1af30843235649421f',
 '98b920289e4aab44d0c908cbe402ea6035820e9d2379df59b4c455844fad8c56',
 '87b227bd0f2b0ca9b608fa4aa76ad3b40ca71cef58e859e9169146093f1ff3b5')
# Historical native capture SHA25645959195d706080c977003fe0e0e87b5e69799c6864b9ef95a2f2b22cdaf3d79.
# These bytes are only regenerated for comparison; never executed by this adapter.
_BASE_TASK_PS='$ErrorActionPreference=\'Stop\';$expectedSid=\'S-1-5-21-2404255130-2183793310-3766671872-1002\';$expectedProfile=\'C:\\Users\\vpncp117\';$msi=\'C:\\ProgramData\\VpnControlCp117\\msi-stage\\packages\\base\\vpn-control-2.1.13.msi\';$receiptDir=Join-Path $env:LOCALAPPDATA \'VpnControlCp117\';$receipt=Join-Path $receiptDir \'base-install-receipt.json\';if([IO.File]::Exists($receipt)){throw \'ordinary receipt exists\'};[IO.Directory]::CreateDirectory($receiptDir)|Out-Null;$id=[Security.Principal.WindowsIdentity]::GetCurrent();$principal=[Security.Principal.WindowsPrincipal]::new($id);$groups=(& "$env:SystemRoot\\System32\\whoami.exe" /groups /fo csv /nh 2>$null|Out-String);$integrity=if($groups -match \'High Mandatory Level\'){\'High\'}elseif($groups -match \'Medium Mandatory Level\'){\'Medium\'}elseif($groups -match \'Low Mandatory Level\'){\'Low\'}elseif($groups -match \'Untrusted Mandatory Level\'){\'Untrusted\'}else{\'Unknown\'};$proof=[ordered]@{sid=$id.User.Value;name=$id.Name;elevated=$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);integrity=$integrity;userProfile=$env:USERPROFILE;localAppData=$env:LOCALAPPDATA};if(-not ($proof.sid -eq $expectedSid -and -not $proof.elevated -and $proof.integrity -in @(\'Medium\',\'Low\',\'Untrusted\') -and $proof.userProfile -ieq $expectedProfile)){([ordered]@{phase=\'identity-gate\';terminal=\'failed\';proof=$proof}|ConvertTo-Json -Compress -Depth 4)|Set-Content -LiteralPath $receipt -Encoding utf8;exit 87};$p=$null;try{$i=[Diagnostics.ProcessStartInfo]::new();$i.FileName="$env:SystemRoot\\System32\\msiexec.exe";$i.UseShellExecute=$false;$i.Arguments=\'/i "\'+$msi+\'" /qn /norestart ALLUSERS=2 MSIINSTALLPERUSER=1 REBOOT=ReallySuppress MSIRESTARTMANAGERCONTROL=Disable\';$p=[Diagnostics.Process]::Start($i);([ordered]@{phase=\'installer-started\';terminal=$false;proof=$proof;installerPid=$p.Id;installerCreationFileTime=$p.StartTime.ToUniversalTime().ToFileTimeUtc();msiPath=$msi}|ConvertTo-Json -Compress -Depth 5)|Set-Content -LiteralPath $receipt -Encoding utf8;$p.WaitForExit();([ordered]@{phase=\'installer-exited\';terminal=\'complete\';proof=$proof;installerPid=$p.Id;installerCreationFileTime=$p.StartTime.ToUniversalTime().ToFileTimeUtc();exitCode=$p.ExitCode;msiPath=$msi;completedUtc=[DateTime]::UtcNow.ToString(\'o\')}|ConvertTo-Json -Compress -Depth 5)|Set-Content -LiteralPath $receipt -Encoding utf8;exit $p.ExitCode}catch{([ordered]@{phase=\'installer-exception\';terminal=\'failed\';proof=$proof;error=$_.Exception.GetType().FullName;message=$_.Exception.Message}|ConvertTo-Json -Compress -Depth 5)|Set-Content -LiteralPath $receipt -Encoding utf8;exit 1}finally{if($null -ne $p){$p.Dispose()}}'

class Blocked(ValueError):
    def __init__(self,phase):
        if phase not in _PHASES:phase='journal'
        self.phase=phase

def _result(state,phase):
    assert phase in _PHASES
    return {'state':state,'phase':phase,'retirementCorrelationId':_RETIREMENT,**_FLAGS}

def _sha(value):return hashlib.sha256(value).hexdigest()
def _digest(value):return history._digest(value)

def _expected():
    from . import windows_msi_owner_quit_phase_diagnostic as diag
    from . import windows_msi_owner_relaunch_quit_v3 as v3
    from . import windows_msi_owner_relaunch_quit_v4 as v4
    sid=wire.observer._GENERATION[4]
    ps=r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
    def arguments(body):return '-NoProfile -NonInteractive -EncodedCommand '+base64.b64encode(body.replace('__SID__',sid).replace('__CLI_HASH__',_CLI).encode('utf-16le')).decode()
    args=['-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand '+base64.b64encode(_BASE_TASK_PS.encode('utf-16le')).decode(),
          arguments(diag._TASK_PS),'--state-dir "C:\\Users\\vpncp117\\AppData\\Local\\VpnControl\\cp166\\state" serve',arguments(v3._TASK_PS),arguments(v4._TASK_PS)]
    exes=[r'C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe',ps,r'C:\Users\vpncp117\AppData\Local\vpn-control\vpn-control-cli.exe',ps,ps]
    if tuple(_sha(a.encode()) for a in args)!=_ARGUMENT_HASHES:raise Blocked('history')
    return [{'task':name,'execute':exe,'arguments':arg,'argumentsSha256':digest,
             'logonType':'Password' if i==0 else 'Interactive','enabled':i!=0,
             'taskState':'Disabled' if i==0 else 'Ready','executionTimeLimit':'PT72H' if i==0 else ('PT0S' if i==2 else 'PT1M'),
             'lastTaskResult':(1601,14,0,1,0)[i],'allowStartOnBattery':i!=0,'dontStopOnBattery':i!=0,'runOnlyIfIdle':False,
             'toolSourceSha256':_sha((base64.b64decode(arg.rsplit(' ',1)[1]) if i!=2 else arg.encode()))}
            for i,(name,exe,arg,digest) in enumerate(zip(_NAMES,exes,args,_ARGUMENT_HASHES))]

def _admit_local(root):
    descriptor=base._descriptor(root)[2]
    if descriptor!=wire.observer._GENERATION:raise Blocked('generation')
    for relative,digest in _RECORDS.items():
        path=root/relative;value=history._read(path)
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
        with os.fdopen(fd,'rb') as stream:
            info=os.fstat(stream.fileno());raw=stream.read(16385)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600
                    or not 0<len(raw)<=16384 or len(raw)!=info.st_size
                    or (info.st_dev,info.st_ino)!=(path.lstat().st_dev,path.lstat().st_ino) or _sha(raw)!=digest):raise Blocked('history')
        if value is None:raise Blocked('history')
    _record,closed=wire.observer._admit(root,descriptor)
    return descriptor,closed,_expected()

def _archive(value,expected):
    fields={'task','taskState','enabled','argumentsSha256','lastRunTicks','lastTaskResult','executionTimeLimit','multipleInstances','restartCount','startWhenAvailable','allowStartOnBattery','dontStopOnBattery','runOnlyIfIdle','xmlSha256','xmlLength','xmlGzip'}
    if not isinstance(value,dict) or set(value)!=fields:raise Blocked('archive')
    if value['task']!=expected['task'] or value['taskState']!=expected['taskState'] or value['enabled'] is not expected['enabled']:raise Blocked('task')
    if value['argumentsSha256']!=expected['argumentsSha256']:raise Blocked('action')
    if (type(value['lastRunTicks']) is not int or not 630822816000000000<=value['lastRunTicks']<=3155378975999999999
            or type(value['lastTaskResult']) is not int or value['lastTaskResult']!=expected['lastTaskResult']):raise Blocked('task')
    if (type(value['restartCount']) is not int or value['restartCount']!=0 or value['startWhenAvailable'] is not False
            or any(value[key] is not expected[key] for key in ('allowStartOnBattery','dontStopOnBattery','runOnlyIfIdle'))
            or value['multipleInstances']!='IgnoreNew' or not isinstance(value['executionTimeLimit'],str)
            or not re.fullmatch(r'PT(?:[0-9]{1,6}[HMS])+',value['executionTimeLimit'])
            or (expected['executionTimeLimit'] is not None and value['executionTimeLimit']!=expected['executionTimeLimit'])):raise Blocked('settings')
    if (type(value['xmlLength']) is not int or not 1<=value['xmlLength']<=131072 or not isinstance(value['xmlGzip'],str)
            or not 1<=len(value['xmlGzip'])<=15000 or not isinstance(value['xmlSha256'],str) or not re.fullmatch('[0-9a-f]{64}',value['xmlSha256'])
            or len(json.dumps(value,separators=(',',':')).encode())>16384):raise Blocked('archive')
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(base64.b64decode(value['xmlGzip'],validate=True))) as stream:
            raw=stream.read(131073)
            if len(raw)>131072 or stream.read(1):raise Blocked('archive')
        if len(raw)!=value['xmlLength'] or _sha(raw)!=value['xmlSha256']:raise Blocked('archive')
        text=raw.decode('utf-8');ns='{http://schemas.microsoft.com/windows/2004/02/mit/task}'
        if '<!DOCTYPE' in text or '<!ENTITY' in text:raise Blocked('xml')
        tree=ET.fromstring(text)
        if tree.attrib!={'version':'1.2' if expected['task']==_NAMES[0] else '1.3'} or any(node.tag not in {ns+key for key in ('RegistrationInfo','Triggers','Principals','Settings','Actions')} for node in tree):raise Blocked('xml')
        if len(tree.findall(ns+'RegistrationInfo'))>1:raise Blocked('xml')
        registration=tree.find(ns+'RegistrationInfo')
        if registration is not None and (registration.attrib or len({node.tag for node in registration})!=len(registration) or any(node.tag not in {ns+key for key in ('Date','Author','Description','URI')} or node.attrib or len(node) for node in registration)):raise Blocked('xml')
        if any(not isinstance(node.tag,str) or not node.tag.startswith(ns) for node in tree.iter()):raise Blocked('xml')
        if any(len(tree.findall(ns+key))!=1 for key in ('Actions','Principals','Settings')) or len(tree.findall(ns+'Triggers'))>1:raise Blocked('xml')
        actions=tree.find(ns+'Actions');principals=tree.find(ns+'Principals')
        triggers=tree.find(ns+'Triggers');settings=tree.find(ns+'Settings')
        if (tree.tag!=ns+'Task' or actions is None or len(actions)!=1 or actions[0].tag!=ns+'Exec'
                or principals is None or len(principals)!=1 or principals[0].tag!=ns+'Principal'
                or (triggers is not None and len(triggers)) or (settings is not None and settings.find(ns+'RestartOnFailure') is not None)):raise Blocked('xml')
        execnode=actions[0];principal=principals[0]
        if actions.attrib!={'Context':'Author'} or principals.attrib or execnode.attrib or principal.attrib!={'id':'Author'} or (triggers is not None and triggers.attrib):raise Blocked('xml')
        if any(node.tag not in {ns+'Command',ns+'Arguments',ns+'WorkingDirectory'} for node in execnode):raise Blocked('xml')
        if any(node.tag not in {ns+'UserId',ns+'LogonType'} for node in principal):raise Blocked('principal')
        childset={'DisallowStartIfOnBatteries','IdleSettings','MultipleInstancesPolicy','StopIfGoingOnBatteries'}
        childset|={'Enabled'} if expected['task']==_NAMES[0] else {'ExecutionTimeLimit','UseUnifiedSchedulingEngine'}
        if settings is None or settings.attrib or len(settings)!=len(childset) or {node.tag for node in settings}!={ns+key for key in childset}:raise Blocked('settings')
        idle=settings.find(ns+'IdleSettings')
        if idle is None or idle.attrib or len(idle)!=4 or {node.tag for node in idle}!={ns+key for key in ('Duration','RestartOnIdle','StopOnIdleEnd','WaitTimeout')}:raise Blocked('settings')
        def exact(node,key,wanted,optional=False):
            rows=node.findall(ns+key)
            if not rows and optional:return
            if len(rows)!=1 or rows[0].attrib or len(rows[0]) or rows[0].text!=wanted:raise Blocked('xml')
        exact(execnode,'Command',expected['execute']);exact(execnode,'Arguments',expected['arguments'])
        rows=execnode.findall(ns+'WorkingDirectory')
        if len(rows)>1 or (rows and (rows[0].attrib or len(rows[0]) or rows[0].text not in (None,''))):raise Blocked('xml')
        users=principal.findall(ns+'UserId')
        if len(users)!=1 or users[0].attrib or len(users[0]) or users[0].text not in {wire.observer._GENERATION[4],r'VPNMSIX64\vpncp117','vpncp117'}:raise Blocked('principal')
        exact(principal,'LogonType','Password' if expected['logonType']=='Password' else 'InteractiveToken')
        for key,wanted in (('Duration','PT10M'),('RestartOnIdle','false'),('StopOnIdleEnd','true'),('WaitTimeout','PT1H')):exact(idle,key,wanted)
        if settings is None:raise Blocked('settings')
        def setting(key,wanted,default):
            rows=settings.findall(ns+key)
            if not rows:
                if wanted!=default:raise Blocked('settings')
                return
            if len(rows)!=1 or rows[0].attrib or len(rows[0]) or rows[0].text!=wanted:raise Blocked('settings')
        setting('Enabled',str(value['enabled']).lower(),'true')
        setting('ExecutionTimeLimit',value['executionTimeLimit'],'PT72H')
        setting('MultipleInstancesPolicy','IgnoreNew','IgnoreNew')
        setting('StartWhenAvailable','false','false')
        setting('DisallowStartIfOnBatteries',str(not value['allowStartOnBattery']).lower(),'true')
        setting('StopIfGoingOnBatteries',str(not value['dontStopOnBattery']).lower(),'true')
        setting('RunOnlyIfIdle','false','false')
        if expected['task']!=_NAMES[0]:exact(settings,'UseUnifiedSchedulingEngine','true')
    except (OSError,ValueError,UnicodeError,EOFError,ET.ParseError) as error:
        if isinstance(error,Blocked):raise
        raise Blocked('xml') from error
    return {key:item for key,item in value.items() if key!='xmlGzip'}

def _unpack_archives(value):
    if (not isinstance(value,dict) or set(value)!={'length','sha256','gzip'} or type(value['length']) is not int
            or not 1<=value['length']<=52000 or not isinstance(value['gzip'],str) or not 1<=len(value['gzip'])<=15000
            or not isinstance(value['sha256'],str) or not re.fullmatch('[0-9a-f]{64}',value['sha256'])):raise Blocked('archive')
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(base64.b64decode(value['gzip'],validate=True))) as stream:
            raw=stream.read(52001)
            if len(raw)>52000 or stream.read(1):raise Blocked('archive')
        if len(raw)!=value['length'] or _sha(raw)!=value['sha256']:raise Blocked('archive')
        result=json.loads(raw,object_pairs_hook=history._unique)
        if not isinstance(result,dict) or set(result)!={'archives'} or not isinstance(result['archives'],list) or len(result['archives'])!=5:raise Blocked('archive')
        rows=[]
        for entry in result['archives']:
            if not isinstance(entry,dict) or 'xmlGzip' in entry or not isinstance(entry.get('xml'),str):raise Blocked('archive')
            row=dict(entry);xml=row.pop('xml').encode('utf-8')
            if not 1<=len(xml)<=131072 or len(xml)!=row.get('xmlLength') or _sha(xml)!=row.get('xmlSha256'):raise Blocked('archive')
            row['xmlGzip']=base64.b64encode(gzip.compress(xml,mtime=0)).decode();rows.append(row)
        return rows
    except (ValueError,OSError,EOFError,UnicodeError) as error:
        if isinstance(error,Blocked):raise
        raise Blocked('archive') from error

def _common(expected):
    data=json.dumps(expected,separators=(',',':')).replace("'","''")
    return r'''$ErrorActionPreference='Stop'
$expected=ConvertFrom-Json '@EXPECTED@';$sid='@SID@'
function Hash([byte[]]$bytes){$h=[Security.Cryptography.SHA256]::Create();try{return ([BitConverter]::ToString($h.ComputeHash($bytes))).Replace('-','').ToLowerInvariant()}finally{$h.Dispose()}}
function Idle {
 $resolved=([Security.Principal.NTAccount]::new('VPNMSIX64\vpncp117')).Translate([Security.Principal.SecurityIdentifier]).Value
 if($resolved -cne $sid -or [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne 'S-1-5-18'){throw 'principal'}
 $all=@(Get-CimInstance Win32_Process -ErrorAction Stop)
 if(@($all|Where-Object {$_.ProcessId -ne $PID -and $_.Name -match '^(powershell|pwsh|vpn-control|vpn-control-cli|sing-box)\.exe$'}).Count -ne 0){throw 'process'}
 if(@($all|Where-Object {$_.Name -match '^(msiexec|consent)\.exe$'}).Count -ne 0){throw 'installer'}
 $tasks=@(Get-ScheduledTask -ErrorAction Stop|Where-Object {$_.TaskName -match '^VpnControl(Mcp|Cp117)'})
 $allowed=@($expected.task)+@('VpnControlMcpBase-c32cb108-4d48-407e-9153-40774559ba50','VpnControlCp117GuestAgentRecovery-c2c0e5c9-77aa-4bd2-91a1-fb7540aa9f58')
 if(@($tasks|Where-Object {$_.TaskPath -cne '\' -or $_.TaskName -cnotin $allowed -or $_.State.ToString() -notin @('Ready','Disabled')}).Count -ne 0){throw 'task'}
}
function Snapshot($e) {
 Idle;$rows=@(Get-ScheduledTask -TaskPath '\' -ErrorAction Stop|Where-Object {$_.TaskName -ceq $e.task})
 if($rows.Count -ne 1){throw 'task'};$t=$rows[0];$a=@($t.Actions);$p=$t.Principal
 $s=if($p.UserId -match '^S-1-'){$p.UserId}else{([Security.Principal.NTAccount]::new($p.UserId)).Translate([Security.Principal.SecurityIdentifier]).Value}
 $tr=@($t.Triggers);if($tr.Count -eq 1 -and $null -eq $tr[0]){$tr=@()}
 if($a.Count -ne 1 -or $a[0].Execute -cne $e.execute -or $a[0].Arguments -cne $e.arguments -or [string]$a[0].WorkingDirectory -cne ''){throw 'action'}
 if($s -cne $sid -or $p.LogonType.ToString() -cne $e.logonType -or $p.RunLevel.ToString() -cne 'Limited'){throw 'principal'}
 if($tr.Count -ne 0 -or $t.Settings.RestartCount -ne 0 -or $t.Settings.StartWhenAvailable -ne $false -or $t.Settings.MultipleInstances.ToString() -cne 'IgnoreNew' -or (-not $t.Settings.DisallowStartIfOnBatteries) -ne $e.allowStartOnBattery -or (-not $t.Settings.StopIfGoingOnBatteries) -ne $e.dontStopOnBattery -or $t.Settings.RunOnlyIfIdle -ne $false -or ($null -ne $e.executionTimeLimit -and $t.Settings.ExecutionTimeLimit -cne $e.executionTimeLimit)){throw 'settings'}
 $info=Get-ScheduledTaskInfo -TaskPath '\' -TaskName $e.task -ErrorAction Stop
 $run=$info.LastRunTime.ToUniversalTime().Ticks
 if($t.State.ToString() -cne $e.taskState -or $t.Settings.Enabled -ne $e.enabled -or $run -lt 630822816000000000 -or $run -gt [datetime]::UtcNow.Ticks -or $info.LastTaskResult -ne $e.lastTaskResult){throw 'task'}
 $xml=[Text.Encoding]::UTF8.GetBytes((Export-ScheduledTask -TaskPath '\' -TaskName $e.task -ErrorAction Stop));if($xml.Length -lt 1 -or $xml.Length -gt 131072){throw 'archive'}
 $out=[IO.MemoryStream]::new();$zip=[IO.Compression.GzipStream]::new($out,[IO.Compression.CompressionMode]::Compress,$true);$zip.Write($xml,0,$xml.Length);$zip.Dispose();$packed=[Convert]::ToBase64String($out.ToArray());$out.Dispose()
 if($packed.Length -gt 15000){throw 'archive'}
 $result=[ordered]@{task=$e.task;taskState=$t.State.ToString();enabled=[bool]$t.Settings.Enabled;argumentsSha256=(Hash ([Text.Encoding]::UTF8.GetBytes($a[0].Arguments)));lastRunTicks=[int64]$run;lastTaskResult=[int64]$info.LastTaskResult;executionTimeLimit=[string]$t.Settings.ExecutionTimeLimit;multipleInstances=$t.Settings.MultipleInstances.ToString();restartCount=[int]$t.Settings.RestartCount;startWhenAvailable=[bool]$t.Settings.StartWhenAvailable;allowStartOnBattery=(-not [bool]$t.Settings.DisallowStartIfOnBatteries);dontStopOnBattery=(-not [bool]$t.Settings.StopIfGoingOnBatteries);runOnlyIfIdle=[bool]$t.Settings.RunOnlyIfIdle;xmlSha256=(Hash $xml);xmlLength=$xml.Length;xmlGzip=$packed}
 Idle;return $result
}
function Same($a,$b){foreach($key in @('task','taskState','enabled','argumentsSha256','lastRunTicks','lastTaskResult','executionTimeLimit','multipleInstances','restartCount','startWhenAvailable','allowStartOnBattery','dontStopOnBattery','runOnlyIfIdle','xmlSha256','xmlLength')){if($a.$key -cne $b.$key){throw 'race'}}}
function Absent($e){if(@(Get-ScheduledTask -ErrorAction Stop|Where-Object {$_.TaskName -ceq $e.task}).Count -ne 0){throw 'absence'}}
function PackArchives($all) {
 $saved=@();foreach($a in $all){$row=[ordered]@{};foreach($key in @('task','taskState','enabled','argumentsSha256','lastRunTicks','lastTaskResult','executionTimeLimit','multipleInstances','restartCount','startWhenAvailable','allowStartOnBattery','dontStopOnBattery','runOnlyIfIdle','xmlSha256','xmlLength')){$row[$key]=$a.$key};$bytes=[Convert]::FromBase64String($a.xmlGzip);$input=[IO.MemoryStream]::new([byte[]]$bytes);$zip=[IO.Compression.GzipStream]::new($input,[IO.Compression.CompressionMode]::Decompress);$out=[IO.MemoryStream]::new();try{$buf=New-Object byte[] 4096;while(($n=$zip.Read($buf,0,$buf.Length)) -gt 0){if($out.Length+$n -gt 131072){throw 'archive'};$out.Write($buf,0,$n)};$xml=$out.ToArray()}finally{$zip.Dispose();$input.Dispose();$out.Dispose()};if($xml.Length -ne $a.xmlLength -or (Hash $xml) -cne $a.xmlSha256){throw 'archive'};$row['xml']=[Text.UTF8Encoding]::new($false,$true).GetString($xml);$saved+=$row}
 $raw=[Text.Encoding]::UTF8.GetBytes((@{archives=$saved}|ConvertTo-Json -Depth 6 -Compress));if($raw.Length -lt 1 -or $raw.Length -gt 52000){throw 'archive'}
 $out=[IO.MemoryStream]::new();$zip=[IO.Compression.GzipStream]::new($out,[IO.Compression.CompressionMode]::Compress,$true);$zip.Write($raw,0,$raw.Length);$zip.Dispose();$packed=[Convert]::ToBase64String($out.ToArray());$out.Dispose();if($packed.Length -gt 15000){throw 'archive'}
 return @{length=$raw.Length;sha256=(Hash $raw);gzip=$packed}
}
function ReadArchives {
 $envelope=Read-SecureJson 'archive.json'
 if((($envelope.PSObject.Properties.Name|Sort-Object)-join ',') -cne 'gzip,length,sha256' -or $envelope.length -lt 1 -or $envelope.length -gt 52000 -or $envelope.gzip.Length -gt 15000){throw 'archive'}
 $packed=[Convert]::FromBase64String($envelope.gzip);$input=[IO.MemoryStream]::new([byte[]]$packed);$zip=[IO.Compression.GzipStream]::new($input,[IO.Compression.CompressionMode]::Decompress);$out=[IO.MemoryStream]::new()
 try{$buf=New-Object byte[] 4096;while(($n=$zip.Read($buf,0,$buf.Length)) -gt 0){if($out.Length+$n -gt 52000){throw 'archive'};$out.Write($buf,0,$n)};$raw=$out.ToArray()}finally{$zip.Dispose();$input.Dispose();$out.Dispose()}
 if($raw.Length -ne $envelope.length -or (Hash $raw) -cne $envelope.sha256){throw 'archive'}
 $value=[Text.UTF8Encoding]::new($false,$true).GetString($raw)|ConvertFrom-Json -ErrorAction Stop
 if((($value.PSObject.Properties.Name)-join ',') -cne 'archives' -or @($value.archives).Count -ne 5){throw 'archive'}
 $all=@();foreach($a in $value.archives){if($a.xml -isnot [string]){throw 'archive'};$xml=[Text.Encoding]::UTF8.GetBytes($a.xml);if($xml.Length -lt 1 -or $xml.Length -gt 131072 -or $xml.Length -ne $a.xmlLength -or (Hash $xml) -cne $a.xmlSha256){throw 'archive'};$row=[ordered]@{};foreach($p in $a.PSObject.Properties){if($p.Name -cne 'xml'){$row[$p.Name]=$p.Value}};$out=[IO.MemoryStream]::new();$zip=[IO.Compression.GzipStream]::new($out,[IO.Compression.CompressionMode]::Compress,$true);$zip.Write($xml,0,$xml.Length);$zip.Dispose();$row['xmlGzip']=[Convert]::ToBase64String($out.ToArray());$out.Dispose();if($row.xmlGzip.Length -gt 15000){throw 'archive'};$all+=$row};return $all
}
'''.replace('@EXPECTED@',data).replace('@SID@',wire.observer._GENERATION[4])

def _guest(source,phases=_ACTION_PHASES):
    codes=','.join("'"+phase+"'" for phase in sorted(phases))
    return "$ErrorActionPreference='Stop';try{\n"+source+"\n}catch{$phase=$_.Exception.Message;if($phase -cnotin @("+codes+")){$phase='journal'};[Console]::Out.WriteLine((@{state='blocked';phase=$phase}|ConvertTo-Json -Compress))}"

def _checked(value):
    if isinstance(value,dict) and set(value)=={'state','phase'}:
        if value['state']=='probe-failed' and value['phase'] in wire._PROBE_PHASES:raise Blocked('transport-'+value['phase'])
        if value['state']=='blocked' and value['phase'] in _PHASES:raise Blocked(value['phase'])
    return value

def _snapshot_script(expected):
    return _guest(_common(expected)+"\nif(Test-Path -LiteralPath '"+_ROOT+"'){throw 'journal'};$all=@();foreach($e in $expected){$all+=Snapshot $e};Idle;[Console]::Out.WriteLine((@{archivesPacket=(PackArchives $all)}|ConvertTo-Json -Depth 6 -Compress))")

def _plan(binding,expected):
    digest=_digest(binding);data=json.dumps(binding,separators=(',',':'),sort_keys=True).replace("'","''")
    body=_common(expected)+journal.powershell(_ROOT,_LEAVES)+r'''
$b=ConvertFrom-Json '@BINDING@';$bindingSha='@BINDING_SHA@';$actionSha='@ACTION_SHA@'
if(Test-Path -LiteralPath $JournalRoot){throw 'journal'}
$all=@();for($i=0;$i -lt 5;$i++){$a=Snapshot $expected[$i];Same $a $b.snapshots[$i];$all+=$a};Idle
Initialize-SecureJournal
Write-SecureJsonCreate 'binding.json' ((@{binding=$b;bindingSha256=$bindingSha;actionSha256=$actionSha})|ConvertTo-Json -Depth 10 -Compress)
Write-SecureJsonCreate 'archive.json' ((PackArchives $all)|ConvertTo-Json -Compress)
$saved=Read-SecureJson 'binding.json';if(($saved|ConvertTo-Json -Depth 10 -Compress) -cne ((@{binding=$b;bindingSha256=$bindingSha;actionSha256=$actionSha})|ConvertTo-Json -Depth 10 -Compress)){throw 'journal'}
$savedArchives=@(ReadArchives);for($i=0;$i -lt 5;$i++){$a=$savedArchives[$i];Same $a $all[$i];Same (Snapshot $expected[$i]) $a}
for($i=0;$i -lt 5;$i++){
 Idle;$savedArchives=@(ReadArchives);$a=$savedArchives[$i];Same (Snapshot $expected[$i]) $a
 Unregister-ScheduledTask -TaskPath '\' -TaskName $expected[$i].task -Confirm:$false -ErrorAction Stop
 Absent $expected[$i];Idle
 Write-SecureJsonCreate ('removed-'+$i+'.json') ((@{retirementCorrelationId='@RETIRE@';index=$i;bindingSha256=$bindingSha;xmlSha256=$a.xmlSha256;state='removed'})|ConvertTo-Json -Compress)
}
foreach($e in $expected){Absent $e};Idle
Write-SecureJsonCreate 'terminal.json' ((@{retirementCorrelationId='@RETIRE@';bindingSha256=$bindingSha;actionSha256=$actionSha;state='retired'})|ConvertTo-Json -Compress)
[Console]::Out.WriteLine('{"submitted":true}')
'''.replace('@BINDING@',data).replace('@BINDING_SHA@',digest).replace('@RETIRE@',_RETIREMENT)
    body=_guest(body)
    action=_sha(body.replace('@ACTION_SHA@','').encode('utf-16le'))
    return body.replace('@ACTION_SHA@',action),{'binding':binding,'bindingSha256':digest,'actionSha256':action}

def _reader(expected):
    return _guest(_common(expected)+journal.powershell(_ROOT,_LEAVES)+r'''
Idle;$binding=Read-SecureJson 'binding.json';$terminal=Read-SecureJson 'terminal.json';$archives=@(ReadArchives);$progress=@()
if(@(Get-ChildItem -LiteralPath $JournalRoot -Force -ErrorAction Stop).Count -ne 8){throw 'journal'}
for($i=0;$i -lt 5;$i++){$progress+=Read-SecureJson ('removed-'+$i+'.json');Absent $expected[$i]};Idle
[Console]::Out.WriteLine((@{binding=$binding;terminal=$terminal;archivesPacket=(Read-SecureJson 'archive.json');progress=$progress;absent=$true}|ConvertTo-Json -Depth 12 -Compress))
''')

def _diagnostic_reader(expected):
    """Fixed protected reader only; no create, task change, or outcome promotion."""
    protected=journal.powershell(_ROOT,_LEAVES)
    # Remove writer definitions, including the multiline ACL construction.
    begin=protected.index('function Initialize-SecureJournal ')
    end=protected.index('function Read-SecureJson(',begin)
    protected=protected[:begin]+protected[end:]
    protected=protected[:protected.index('function Write-SecureJsonCreate(')]
    protected=protected.replace("return ([Text.Encoding]::UTF8.GetString($bytes)|ConvertFrom-Json -ErrorAction Stop)","try{$text=[Text.UTF8Encoding]::new($false,$true).GetString($bytes)}catch{throw 'diagnostic-encoding'};if($text.Length -eq 0 -or [int]$text[0] -eq 65279){throw 'diagnostic-encoding'};try{return ($text|ConvertFrom-Json -ErrorAction Stop)}catch{throw 'diagnostic-schema'}")
    body=_common(expected)+protected+r'''
Idle
if(-not (Test-Path -LiteralPath $JournalRoot)){throw 'diagnostic-root-absence'}
[void](Assert-Root $JournalRoot)
$present=@(Get-ChildItem -LiteralPath $JournalRoot -Force -ErrorAction Stop|ForEach-Object {$_.Name})
if('binding.json' -cnotin $present){throw 'diagnostic-stage-binding'}
$binding=Read-SecureJson 'binding.json'
if('archive.json' -cnotin $present){throw 'diagnostic-stage-archive'}
$archives=@(ReadArchives)
$progress=@()
for($i=0;$i -lt 5;$i++){$name='removed-'+$i+'.json';if($name -cnotin $present){throw 'diagnostic-stage-progress'};$progress+=Read-SecureJson $name}
$terminal=$null;$terminalAbsent=$false
if('terminal.json' -cin $present){$terminal=Read-SecureJson 'terminal.json';if($present.Count -ne 8){throw 'diagnostic-leaf-metadata'}}else{$terminalAbsent=$true;if($present.Count -ne 7){throw 'diagnostic-leaf-metadata'}}
for($i=0;$i -lt 5;$i++){Absent $expected[$i]};Idle
[Console]::Out.WriteLine((@{binding=$binding;terminal=$terminal;archivesPacket=(Read-SecureJson 'archive.json');progress=$progress;absent=$true;terminalAbsent=$terminalAbsent}|ConvertTo-Json -Depth 12 -Compress))
'''
    source=_guest(body,_PHASES)
    # Keep detailed journal exceptions private: publish only finite categories.
    mapping={
        'ROOT_TYPE':'diagnostic-root-metadata','ROOT_REPARSE':'diagnostic-root-metadata','ANCESTOR_REPARSE':'diagnostic-root-metadata',
        **{p:'diagnostic-root-acl' for p in ('ROOT_ACL_PROTECTED','ROOT_OWNER','ROOT_ACL_COUNT','ROOT_ACL')},
        **{p:'diagnostic-leaf-acl' for p in ('LEAF_ACL_PROTECTED','LEAF_OWNER','LEAF_ACL_COUNT','LEAF_ACL')},
        **{p:'diagnostic-leaf-metadata' for p in ('LEAF','LEAF_TYPE','LEAF_REPARSE','LEAF_SIZE','HANDLE_SIZE','HANDLE_READ','HANDLE_CHANGED')},
    }
    cases=';'.join("'"+key+"'{$phase='"+value+"'}" for key,value in mapping.items())
    return source.replace("$phase=$_.Exception.Message;","$phase=$_.Exception.Message;switch -CaseSensitive ($phase){"+cases+"};",1)

def _run(root,descriptor,closed,source):
    config,target,current=base._descriptor(root)
    if current!=descriptor or descriptor!=wire.observer._GENERATION:return wire._probe_failure('descriptor')
    raw=base._remote(config,_REMOTE,(str(target.fixture_transfer_root),*wire.observer._remote_arguments(descriptor,closed),wire._command(source)),None,90)
    if raw is None:return wire._probe_failure('transport')
    if not isinstance(raw,(bytes,str)) or not 0<len(raw)<=16384:return wire._probe_failure('envelope')
    try:value=json.loads(raw,object_pairs_hook=history._unique)
    except (ValueError,TypeError):return wire._probe_failure('json')
    value=wire._unpack(value)
    if isinstance(value,dict) and set(value)=={'state','phase'} and value['state']=='probe-failed' and value['phase'] in wire._PROBE_PHASES:return value
    if isinstance(value,dict) and set(value)=={'state','phase'} and value['state']=='unknown' and value['phase'] in wire._PROBE_PHASES:return wire._probe_failure(value['phase'])
    if isinstance(value,dict) and set(value)=={'state','receipt'} and value['state']=='observed':return value['receipt']
    return wire._probe_failure('shape')

def _parse(root,descriptor,closed,source):
    packed=base64.b64encode(gzip.compress(source.encode('utf-16le'),mtime=0)).decode()
    parser=history._PARSER.replace('@PACKED@',packed)
    return _run(root,descriptor,closed,parser)=={'version':1,'code':'OK'}

def _steady(root,descriptor):
    if (not base._fixed_c32_task_terminal(root,descriptor,_RETIREMENT)
            or not base._fixed_recovery_task_terminal(root,descriptor)):
        raise Blocked('history')

def _proof(root):
    descriptor,closed,expected=_admit_local(root)
    _steady(root,descriptor)
    source=_snapshot_script(expected)
    if not _parse(root,descriptor,closed,source):raise Blocked('parser')
    observations=[]
    for _ in range(2):
        value=_checked(_run(root,descriptor,closed,source))
        if not isinstance(value,dict) or set(value)!={'archivesPacket'}:raise Blocked('snapshot')
        observations.append([_archive(a,e) for a,e in zip(_unpack_archives(value['archivesPacket']),expected)])
    if observations[0]!=observations[1]:raise Blocked('race')
    binding={'retirementCorrelationId':_RETIREMENT,'generation':list(descriptor),'originalProductSourceSha':_SOURCE,
             'historicalRecordSha256':dict(_RECORDS),'taskArgumentSha256':list(_ARGUMENT_HASHES),'taskToolSourceSha256':[e['toolSourceSha256'] for e in expected],'snapshots':observations[0]}
    source,intent=_plan(binding,expected)
    for prospective in (source,_reader(expected)):
        if not _parse(root,descriptor,closed,prospective):raise Blocked('parser')
    _steady(root,descriptor)
    if _admit_local(root)!=(descriptor,closed,expected):raise Blocked('generation')
    return descriptor,closed,expected,source,intent

def _status(root,diagnostic=False):
    intent=wire._read(root/_DIR/'intent.json')
    if intent is None:return _result('not-started','intent')
    descriptor,closed,expected=_admit_local(root)
    _steady(root,descriptor)
    if not isinstance(intent,dict) or set(intent)!={'binding','bindingSha256','actionSha256'} or not isinstance(intent['binding'],dict):raise Blocked('intent')
    b=intent['binding'];fields={'retirementCorrelationId','generation','originalProductSourceSha','historicalRecordSha256','taskArgumentSha256','taskToolSourceSha256','snapshots'}
    if (set(b)!=fields or b['retirementCorrelationId']!=_RETIREMENT or b['generation']!=list(descriptor) or b['originalProductSourceSha']!=_SOURCE or b['historicalRecordSha256']!=_RECORDS or b['taskArgumentSha256']!=list(_ARGUMENT_HASHES) or b['taskToolSourceSha256']!=[e['toolSourceSha256'] for e in expected]
            or not isinstance(b['snapshots'],list) or len(b['snapshots'])!=5 or _plan(b,expected)[1]!=intent):raise Blocked('intent')
    source=_diagnostic_reader(expected) if diagnostic else _reader(expected)
    if not _parse(root,descriptor,closed,source):raise Blocked('parser')
    value=_checked(_run(root,descriptor,closed,source))
    fields={'binding','terminal','archivesPacket','progress','absent'} | ({'terminalAbsent'} if diagnostic else set())
    if (not isinstance(value,dict) or set(value)!=fields or value['binding']!=intent
            or not isinstance(value['progress'],list) or len(value['progress'])!=5):raise Blocked('journal')
    if value['absent'] is not True:raise Blocked('absence')
    snapshots=[_archive(a,e) for a,e in zip(_unpack_archives(value['archivesPacket']),expected)]
    if snapshots!=b['snapshots']:raise Blocked('archive')
    for i,(p,snapshot) in enumerate(zip(value['progress'],snapshots)):
        if p!={'retirementCorrelationId':_RETIREMENT,'index':i,'bindingSha256':intent['bindingSha256'],'xmlSha256':snapshot['xmlSha256'],'state':'removed'} or type(p.get('index')) is not int:raise Blocked('terminal')
    if diagnostic and (type(value['terminalAbsent']) is not bool or value['terminalAbsent'] != (value['terminal'] is None)):raise Blocked('terminal')
    missing_terminal=diagnostic and value['terminalAbsent'] is True
    if not missing_terminal and value['terminal']!={'retirementCorrelationId':_RETIREMENT,'bindingSha256':intent['bindingSha256'],'actionSha256':intent['actionSha256'],'state':'retired'}:raise Blocked('terminal')
    _steady(root,descriptor)
    if _admit_local(root)!=(descriptor,closed,expected):raise Blocked('generation')
    return _result('unknown','diagnostic-terminal-absent-verified' if missing_terminal else 'diagnostic-complete') if diagnostic else _result('retired','complete')

@contextmanager
def _start_admission(root):
    """Order: base journal EX, then campaign SH; status only takes campaign SH.

    The shared base lock prevents a base reservation from racing static intent
    publication. After a deadline the consumed intent continues to exclude it.
    Existing lock/parents are read-only; this helper never initializes them.
    """
    directory=root/base._LOCAL;lockpath=directory/'.environment.lock'
    try:
        parents=[(path,history._directory(path)) for path in (directory.parent,directory)]
        fd=os.open(lockpath,os.O_RDONLY|os.O_NOFOLLOW)
    except (OSError,ValueError) as error:raise Blocked('base-lock') from error
    try:
        info=os.fstat(fd);current=lockpath.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600 or (info.st_dev,info.st_ino)!=(current.st_dev,current.st_ino):raise Blocked('base-lock')
        history.fcntl.flock(fd,history.fcntl.LOCK_EX)
        def recheck():
            current=lockpath.lstat()
            if (info.st_dev,info.st_ino)!=(current.st_dev,current.st_ino):raise Blocked('base-lock')
            for path,old in parents:
                current=history._directory(path)
                if (old.st_dev,old.st_ino)!=(current.st_dev,current.st_ino):raise Blocked('base-lock')
        recheck()
        if not os.path.lexists(root/_DIR/'intent.json'):
            config,target,descriptor=base._descriptor(root)
            try:base._require_base_route_free(root,config,target,descriptor)
            except (ValueError,OSError) as error:raise Blocked('base-route') from error
        yield
        recheck()
    finally:os.close(fd)

def workflow(root:Path|str,action:str,inputs:Mapping[str,Any]):
    if not isinstance(inputs,Mapping) or dict(inputs)!={} or action not in {'preflight','diagnose','start','status'}:raise ValueError('Fixed static retirement takes no inputs.')
    if not history._supported() or base is None:return _result('blocked','platform')
    consumed=False
    try:
        root=Path(root).resolve(strict=True)
        with (_start_admission(root) if action=='start' and not os.path.lexists(root/_DIR/'intent.json') else nullcontext()):
            with history._history_lock(root):
                if os.path.lexists(root/base.campaign_lease._DIR/'active.json'):raise Blocked('active-lease')
                consumed=os.path.lexists(root/_DIR/'intent.json')
                if consumed or action=='status':
                    result=_status(root,diagnostic=action=='diagnose')
                    if action=='diagnose' and result['phase']=='diagnostic-terminal-absent-verified':
                        if _status(root,diagnostic=True)!=result:raise Blocked('race')
                    return result
                descriptor,closed,expected,source,intent=_proof(root)
                if action in {'preflight','diagnose'}:return _result('ready','snapshot')
                if not (root/_DIR).exists():
                    os.mkdir(root/_DIR,0o700)
                    fd=os.open(root/'.rag_index',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
                    try:os.fsync(fd)
                    finally:os.close(fd)
                history._directory(root/_DIR)
                wire.guards.secure_write_create(root/_DIR/'intent.json',intent);consumed=True
                _steady(root,descriptor)
                if _admit_local(root)!=(descriptor,closed,expected):raise Blocked('generation')
                _run(root,descriptor,closed,source)
                return _status(root)
    except Blocked as error:
        phase=error.phase
        if action=='diagnose' and consumed:phase={'journal':'diagnostic-schema','intent':'diagnostic-hash','archive':'diagnostic-hash','terminal':'diagnostic-state'}.get(phase,phase)
        return _result('unknown' if consumed else 'blocked',phase)
    except (OSError,ValueError,TypeError,KeyError,IndexError,EOFError):return _result('unknown','journal')

def preflight(root,value):return workflow(root,'preflight',value)
def diagnose(root,value):return workflow(root,'diagnose',value)
def start(root,value):return workflow(root,'start',value)
def status(root,value):return workflow(root,'status',value)
