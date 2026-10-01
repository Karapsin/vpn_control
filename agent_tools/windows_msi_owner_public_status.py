"""One-shot original-user public status proof for the armed CP117 owner launch.

QGA/SYSTEM never reads ``activation.port``.  The scheduled task runs as the
fixed interactive user, validates that private endpoint in-process, invokes the
installed public CLI, and exits zero only for the bounded runtime-off result.
"""
from __future__ import annotations

import base64, fcntl, hashlib, json, os, stat
from pathlib import Path
from typing import Any, Mapping

from . import windows_msi_base_prepare as base
from . import windows_msi_owner_relaunch as relaunch

class WindowsMsiOwnerPublicStatusError(ValueError): pass

_CORRELATION = "d19d1c94-28d9-48cc-a4be-8e12ab9d02db"
_GROUP = ".rag_index/windows-msi-owner-public-status"
_TASK = "VpnControlCp117OwnerPublicStatusC32"
_RETRY_TASK = "VpnControlCp117OwnerPublicStatusRetryC32"
_THIRD_TASK = "VpnControlCp117OwnerPublicStatusThirdC32"
_ALLOWED_TASKS = {_TASK, _RETRY_TASK, _THIRD_TASK}
_UNKNOWN = {"state":"unknown","replayAllowed":False,"nativeActionAllowed":False}
_APP_CENSUS_PS = r'''$ErrorActionPreference='Stop'
try{$all=@(Get-CimInstance Win32_Process -ErrorAction Stop);$gui=@($all|Where-Object {$_.Name -ceq 'vpn-control.exe'}).Count;$cli=@($all|Where-Object {$_.Name -ceq 'vpn-control-cli.exe'}).Count;$g=if($gui -eq 0){'none'}elseif($gui -eq 1){'one'}elseif($gui -le 16){'many'}else{'ambiguous'};$c=if($cli -eq 2){'two'}elseif($cli -le 16){'other'}else{'ambiguous'};[Console]::Out.WriteLine((@{version=1;gui=$g;cli=$c}|ConvertTo-Json -Compress))}catch{[Console]::Out.WriteLine('{"version":1,"gui":"ambiguous","cli":"ambiguous"}')}
'''
_DIAGNOSE_PS = r'''$ErrorActionPreference='Stop';$phase='system-identity';$task='absent'
try{
 $sid='__SID__';$hash='__CLI_HASH__';$name='VpnControlCp117OwnerPublicStatusC32';$install='C:\Users\vpncp117\AppData\Local\vpn-control';$cli=Join-Path $install 'vpn-control-cli.exe';$state='C:\Users\vpncp117\AppData\Local\VpnControl\cp166\state';$endpoint=Join-Path $state 'activation.port'
 function D([string]$x){$i=Get-Item -LiteralPath $x -Force -ErrorAction Stop;if(-not $i.PSIsContainer -or (($i.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)){throw 'ANCESTOR'}}
 function A([string]$x){$a=Get-Acl -LiteralPath $x -ErrorAction Stop;if($a.GetOwner([Security.Principal.SecurityIdentifier]).Value -cne $sid){throw 'ACL'};$r=$false;foreach($z in @($a.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))){if($z.AccessControlType -eq [Security.AccessControl.AccessControlType]::Deny -and [int]$z.FileSystemRights -ne 0){throw 'ACL'};if($z.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and [int]$z.FileSystemRights -ne 0){if($z.IdentityReference.Value -notin @($sid,'S-1-5-18','S-1-5-32-544')){throw 'ACL'};if($z.IdentityReference.Value -ceq $sid -and ($z.FileSystemRights -band [Security.AccessControl.FileSystemRights]::ReadData) -ne 0){$r=$true}}};if(-not $r){throw 'ACL'}}
 if([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne 'S-1-5-18'){throw 'SYSTEM'}
 $phase='ancestors';foreach($x in @('C:\Users','C:\Users\vpncp117','C:\Users\vpncp117\AppData','C:\Users\vpncp117\AppData\Local',$install,'C:\Users\vpncp117\AppData\Local\VpnControl','C:\Users\vpncp117\AppData\Local\VpnControl\cp166',$state)){D $x}
 $phase='acl';A $install;A $state
 $phase='cli';$f=Get-Item -LiteralPath $cli -Force -ErrorAction Stop;if($f.PSIsContainer -or (($f.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or (Get-FileHash -LiteralPath $cli -Algorithm SHA256).Hash.ToLowerInvariant() -cne $hash){throw 'CLI'}
 $phase='endpoint';$e=Get-Item -LiteralPath $endpoint -Force -ErrorAction Stop;if($e.PSIsContainer -or (($e.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or $e.Length -lt 2 -or $e.Length -gt 4096){throw 'ENDPOINT'};A $endpoint
 $phase='task';$t=Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue;if($null -eq $t){$task='absent'}else{$u=[string]$t.Principal.UserId;if($u -match '^S-1-'){$p=([Security.Principal.SecurityIdentifier]::new($u)).Value}else{$p=([Security.Principal.NTAccount]::new($u)).Translate([Security.Principal.SecurityIdentifier]).Value};$a=@($t.Actions);$digest=if($a.Count -eq 1){([BitConverter]::ToString(([Security.Cryptography.SHA256]::Create()).ComputeHash([Text.Encoding]::UTF8.GetBytes([string]$a[0].Arguments)))).Replace('-','').ToLowerInvariant()}else{''};if($p -cne $sid -or $t.Principal.LogonType.ToString() -cne 'Interactive' -or $t.Principal.RunLevel.ToString() -cne 'Limited'){$task='principal-mismatch'}elseif($a.Count -ne 1 -or $a[0].Execute -cne 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -or $digest -cne '__ARGS_SHA__'){$task='action-mismatch'}else{$i=Get-ScheduledTaskInfo -TaskName $name -ErrorAction Stop;if($t.State -eq 'Running' -or $i.LastRunTime -eq [datetime]::MinValue){$task='pending'}elseif($i.LastTaskResult -eq 0){$task='proved'}else{$task='failed'}}}
 [Console]::Out.WriteLine((@{version=1;phase='task';task=$task}|ConvertTo-Json -Compress))
}catch{[Console]::Out.WriteLine((@{version=1;phase=$phase;task='unknown'}|ConvertTo-Json -Compress))}'''

_TASK_PS = r'''$ErrorActionPreference='Stop'
try {
 $sid='__SID__';$install='C:\Users\vpncp117\AppData\Local\vpn-control';$cli=Join-Path $install 'vpn-control-cli.exe';$state='C:\Users\vpncp117\AppData\Local\VpnControl\cp166\state';$endpoint=Join-Path $state 'activation.port';$expected='__CLI_HASH__'
 $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
 $limited=-not ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
 if($identity.User.Value -cne $sid -or (Get-Process -Id $PID).SessionId -ne 1 -or -not $limited){throw 'IDENTITY'}
 function SafeDirectory([string]$path){$item=Get-Item -LiteralPath $path -Force -ErrorAction Stop;if(-not $item.PSIsContainer -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)){throw 'ANCESTOR'}}
 function OwnerReadAcl([string]$path){$acl=Get-Acl -LiteralPath $path -ErrorAction Stop;if($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -cne $sid){throw 'ACL'};$read=$false;foreach($rule in @($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))){if($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Deny -and [int]$rule.FileSystemRights -ne 0){throw 'ACL'};if($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and [int]$rule.FileSystemRights -ne 0){if($rule.IdentityReference.Value -notin @($sid,'S-1-5-18','S-1-5-32-544')){throw 'ACL'};if($rule.IdentityReference.Value -ceq $sid -and ($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::ReadData) -ne 0){$read=$true}}};if(-not $read){throw 'ACL'}}
 foreach($path in @('C:\Users','C:\Users\vpncp117','C:\Users\vpncp117\AppData','C:\Users\vpncp117\AppData\Local',$install,'C:\Users\vpncp117\AppData\Local\VpnControl','C:\Users\vpncp117\AppData\Local\VpnControl\cp166',$state)){SafeDirectory $path};OwnerReadAcl $install;OwnerReadAcl $state
 $argument='--state-dir "'+$state+'" serve';$unquoted=$cli+' '+$argument;$quoted='"'+$cli+'" '+$argument
 function VerifyOwners {$all=@(Get-CimInstance Win32_Process -ErrorAction Stop);if(@($all|Where-Object {$_.Name -ceq 'vpn-control.exe'}).Count -ne 0){throw 'OWNER'};$apps=@($all|Where-Object {$_.Name -ceq 'vpn-control-cli.exe'});if($apps.Count -ne 2){throw 'OWNER'};$q=0;$u=0;foreach($app in $apps){$owner=Invoke-CimMethod -InputObject $app -MethodName GetOwnerSid -ErrorAction Stop;if($owner.ReturnValue -ne 0 -or $owner.Sid -cne $sid -or $app.SessionId -ne 1 -or $app.ExecutablePath -cne $cli){throw 'OWNER'};if($app.CommandLine -ceq $quoted){$q++}elseif($app.CommandLine -ceq $unquoted){$u++}else{throw 'OWNER'}};if($q -ne 1 -or $u -ne 1){throw 'OWNER'}}
 VerifyOwners
 $file=Get-Item -LiteralPath $cli -Force -ErrorAction Stop;if($file.PSIsContainer -or (($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or (Get-FileHash -LiteralPath $cli -Algorithm SHA256).Hash.ToLowerInvariant() -cne $expected){throw 'CLI'}
 $leaf=Get-Item -LiteralPath $endpoint -Force -ErrorAction Stop;if($leaf.PSIsContainer -or (($leaf.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or $leaf.Length -lt 2 -or $leaf.Length -gt 4096){throw 'ENDPOINT'};OwnerReadAcl $endpoint
 $value=Get-Content -LiteralPath $endpoint -Raw -ErrorAction Stop|ConvertFrom-Json -ErrorAction Stop
 $controller=[string]$value.controllerId
 if($value.schemaVersion -ne 1 -or $controller -notmatch '^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$' -or [guid]::Parse($controller).ToString() -cne $controller -or $value.port -lt 1 -or $value.port -gt 65535 -or ([string]$value.token) -notmatch '^[A-Za-z0-9_-]{43}$'){throw 'ENDPOINT'}
 $raw=@(& $cli --state-dir $state --json --controller-id $controller --timeout-seconds 15 status 2>$null)
 if($LASTEXITCODE -ne 0 -or $raw.Count -ne 1 -or $raw[0] -isnot [string] -or $raw[0].Length -lt 2 -or $raw[0].Length -gt 8192){throw 'PUBLIC'}
 $public=ConvertFrom-Json -InputObject $raw[0] -ErrorAction Stop
 if($public.schemaVersion -ne 1 -or $public.ok -ne $true -or $public.final -ne $true -or $public.code -cne 'OK' -or $public.controllerId -cne $controller -or $public.data.runtimeRunning -ne $false){throw 'RESULT'}
 VerifyOwners
 exit 0
}catch{exit 1}'''

_REMOTE = base._QGA + r'''import time,hashlib
sock,pid,ticks,sid,cli_hash,mode=sys.argv[1:]
TASK_NAME='VpnControlCp117OwnerPublicStatusC32'
def out(v):print(json.dumps(v,separators=(',',':'),sort_keys=True))
def ps(script):return base64.b64encode(script.encode('utf-16le')).decode()
try:
 if mode not in ('start','status','census','diagnose') or not live(sock,pid,ticks):raise ValueError()
 if mode=='diagnose':
  task_body=TASK_PS.replace('__CLI_HASH__',cli_hash).replace('__SID__',sid); args='-NoProfile -NonInteractive -EncodedCommand '+ps(task_body); digest=hashlib.sha256(args.encode()).hexdigest()
  program=DIAGNOSE_PS.replace('__SID__',sid).replace('__CLI_HASH__',cli_hash).replace('__ARGS_SHA__',digest)
  child=call(sock,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',ps(program)],'capture-output':True}).get('pid')
  if type(child) is not int or child<=0:raise ValueError()
  for _ in range(160):
   seen=call(sock,'guest-exec-status',{'pid':child})
   if seen.get('exited') is True:break
   if seen.get('exited') is not False:raise ValueError()
   time.sleep(.25)
  else:raise ValueError()
  if seen.get('exitcode')!=0 or seen.get('out-truncated') is True:raise ValueError()
  raw=base64.b64decode(seen.get('out-data',''),validate=True);lines=[x for x in decode(raw).splitlines() if x.startswith('{') and x.endswith('}')]
  if len(lines)!=1:raise ValueError()
  value=json.loads(lines[0])
  if not isinstance(value,dict) or set(value)!={'version','phase','task'} or value.get('version')!=1 or value.get('phase') not in {'system-identity','ancestors','acl','cli','endpoint','task'} or value.get('task') not in {'absent','principal-mismatch','action-mismatch','pending','proved','failed','unknown'}:raise ValueError()
  out(value);raise SystemExit
 if mode=='census':
  child=call(sock,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',ps(APP_CENSUS_PS)],'capture-output':True}).get('pid')
  if type(child) is not int or child<=0:raise ValueError()
  for _ in range(160):
   seen=call(sock,'guest-exec-status',{'pid':child})
   if seen.get('exited') is True:break
   if seen.get('exited') is not False:raise ValueError()
   time.sleep(.25)
  else:raise ValueError()
  if seen.get('exitcode')!=0 or seen.get('out-truncated') is True:raise ValueError()
  raw=base64.b64decode(seen.get('out-data',''),validate=True);lines=[x for x in decode(raw).splitlines() if x.startswith('{') and x.endswith('}')]
  if len(lines)!=1:raise ValueError()
  value=json.loads(lines[0])
  if not isinstance(value,dict) or set(value)!={'version','gui','cli'} or value.get('version')!=1 or value.get('gui') not in {'none','one','many','ambiguous'} or value.get('cli') not in {'two','other','ambiguous'}:raise ValueError()
  out(value);raise SystemExit
 if mode=='start':
  body=TASK_PS.replace('__CLI_HASH__',cli_hash).replace('__SID__',sid); encoded=ps(body); arg='-NoProfile -NonInteractive -EncodedCommand '+encoded
  boot="$ErrorActionPreference='Stop';$n='"+TASK_NAME+"';$sid='"+sid+"';if([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne 'S-1-5-18'){throw 'SYSTEM'};$install='C:\\Users\\vpncp117\\AppData\\Local\\vpn-control';$cli=Join-Path $install 'vpn-control-cli.exe';$state='C:\\Users\\vpncp117\\AppData\\Local\\VpnControl\\cp166\\state';$e=Join-Path $state 'activation.port';function D($x){$i=Get-Item -LiteralPath $x -Force -ErrorAction Stop;if(-not $i.PSIsContainer -or (($i.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)){throw 'ANCESTOR'}};function A($x){$a=Get-Acl -LiteralPath $x -ErrorAction Stop;if($a.GetOwner([Security.Principal.SecurityIdentifier]).Value -cne $sid){throw 'ACL'};$r=$false;foreach($z in @($a.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))){if($z.AccessControlType -eq [Security.AccessControl.AccessControlType]::Deny -and [int]$z.FileSystemRights -ne 0){throw 'ACL'};if($z.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and [int]$z.FileSystemRights -ne 0){if($z.IdentityReference.Value -notin @($sid,'S-1-5-18','S-1-5-32-544')){throw 'ACL'};if($z.IdentityReference.Value -ceq $sid -and ($z.FileSystemRights -band [Security.AccessControl.FileSystemRights]::ReadData) -ne 0){$r=$true}}};if(-not $r){throw 'ACL'}};foreach($x in @('C:\\Users','C:\\Users\\vpncp117','C:\\Users\\vpncp117\\AppData','C:\\Users\\vpncp117\\AppData\\Local',$install,'C:\\Users\\vpncp117\\AppData\\Local\\VpnControl','C:\\Users\\vpncp117\\AppData\\Local\\VpnControl\\cp166',$state)){D $x};A $install;A $state;if(Get-ScheduledTask -TaskName $n -ErrorAction SilentlyContinue){throw 'TASK'};$f=Get-Item -LiteralPath $cli -Force -ErrorAction Stop;if($f.PSIsContainer -or (($f.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or (Get-FileHash -LiteralPath $cli -Algorithm SHA256).Hash.ToLowerInvariant() -cne '"+cli_hash+"'){throw 'CLI'};$l=Get-Item -LiteralPath $e -Force -ErrorAction Stop;if($l.PSIsContainer -or (($l.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or $l.Length -lt 2 -or $l.Length -gt 4096){throw 'ENDPOINT'};A $e;$a=New-ScheduledTaskAction -Execute 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe' -Argument '"+arg.replace("'","''")+"';$p=New-ScheduledTaskPrincipal -UserId $sid -LogonType Interactive -RunLevel Limited;$s=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 1) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries;Register-ScheduledTask -TaskName $n -Action $a -Principal $p -Settings $s|Out-Null;Start-ScheduledTask -TaskName $n;[Console]::Out.WriteLine('{\"version\":1,\"state\":\"submitted\"}')"
 else:
  # The task action itself contains the private controller/token.  We compare
  # only its SHA-256 in SYSTEM, then project task completion as a finite state.
  body=TASK_PS.replace('__CLI_HASH__',cli_hash).replace('__SID__',sid); arg='-NoProfile -NonInteractive -EncodedCommand '+ps(body); digest=hashlib.sha256(arg.encode()).hexdigest()
  boot="$ErrorActionPreference='Stop';$n='"+TASK_NAME+"';$sid='"+sid+"';$h='"+digest+"';$t=Get-ScheduledTask -TaskName $n -ErrorAction Stop;$u=[string]$t.Principal.UserId;if($u -match '^S-1-'){$p=([Security.Principal.SecurityIdentifier]::new($u)).Value}else{$p=([Security.Principal.NTAccount]::new($u)).Translate([Security.Principal.SecurityIdentifier]).Value};$a=@($t.Actions);if($p -cne $sid -or $t.Principal.LogonType.ToString() -cne 'Interactive' -or $t.Principal.RunLevel.ToString() -cne 'Limited' -or $a.Count -ne 1 -or $a[0].Execute -cne 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe' -or ([BitConverter]::ToString(([Security.Cryptography.SHA256]::Create()).ComputeHash([Text.Encoding]::UTF8.GetBytes([string]$a[0].Arguments)))).Replace('-','').ToLowerInvariant() -cne $h){throw 'TASK'};$i=Get-ScheduledTaskInfo -TaskName $n -ErrorAction Stop;if($i.LastRunTime -eq [datetime]::MinValue){$r='pending'}elseif($t.State -eq 'Running'){$r='pending'}elseif($i.LastTaskResult -eq 0){$r='proved'}else{$r='failed'};[Console]::Out.WriteLine((@{version=1;state=$r}|ConvertTo-Json -Compress))"
 child=call(sock,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',ps(boot)],'capture-output':True}).get('pid')
 if type(child) is not int or child<=0:raise ValueError()
 for _ in range(160):
  seen=call(sock,'guest-exec-status',{'pid':child})
  if seen.get('exited') is True:break
  if seen.get('exited') is not False:raise ValueError()
  time.sleep(.25)
 else:raise ValueError()
 if seen.get('exitcode')!=0 or seen.get('out-truncated') is True:raise ValueError()
 raw=base64.b64decode(seen.get('out-data',''),validate=True);lines=[x for x in decode(raw).splitlines() if x.startswith('{') and x.endswith('}')]
 if len(lines)!=1:raise ValueError()
 value=json.loads(lines[0]);allowed={'submitted'} if mode=='start' else {'pending','proved','failed'}
 if not isinstance(value,dict) or set(value)!={'version','state'} or value.get('version')!=1 or value.get('state') not in allowed:raise ValueError()
 out(value)
except SystemExit:pass
except Exception:out({'version':1,'state':'unknown'})
'''.replace('TASK_PS',repr(_TASK_PS)).replace('APP_CENSUS_PS',repr(_APP_CENSUS_PS)).replace('DIAGNOSE_PS',repr(_DIAGNOSE_PS))


def _remote_for(task_name: str) -> str:
    """Return a fixed reviewed program for one of the two CP117 task names."""
    if task_name not in _ALLOWED_TASKS:
        raise WindowsMsiOwnerPublicStatusError("Unrecognized public-status task.")
    if task_name == _TASK:
        return _REMOTE
    account = r"VPNMSIX64\vpncp117"
    # This text is injected into a Python string literal in _REMOTE. Escape
    # the account separator there so Python does not decode \v to vertical tab.
    account_for_remote = account.replace("\\", "\\\\")
    replacement = ("$account='" + account_for_remote + "';$resolved=([Security.Principal.NTAccount]::new($account))."
                   "Translate([Security.Principal.SecurityIdentifier]).Value;if($resolved -cne $sid){throw 'SID_MISMATCH'};"
                   "$p=New-ScheduledTaskPrincipal -UserId $account")
    # A preflight is only an admission fact.  Recheck volatile scheduler and
    # owner facts, plus every earlier fixed task, before registration.
    prior_tasks = [_TASK] if task_name == _RETRY_TASK else [_TASK, _RETRY_TASK]
    prior_absence = "".join("if(Get-ScheduledTask -TaskName '" + name + "' -ErrorAction SilentlyContinue){throw 'PRIOR_TASK'};"
                           for name in prior_tasks)
    process_guard = ""
    if task_name == _THIRD_TASK:
        process_guard = ("$active=0;foreach($x in @(Get-CimInstance Win32_Process -Filter \\\"Name='powershell.exe'\\\" -ErrorAction Stop)){"
                         "if($x.SessionId -eq 1 -and $x.CommandLine -like '*-NoProfile -NonInteractive -EncodedCommand*'){"
                         "$o=Invoke-CimMethod -InputObject $x -MethodName GetOwnerSid -ErrorAction Stop;"
                         "if($o.ReturnValue -eq 0 -and $o.Sid -ceq $sid){$active++}}};if($active -ne 0){throw 'ACTIVE_TASK'};")
    guard = ("if((Get-Service -Name Schedule -ErrorAction Stop).Status.ToString() -cne 'Running'){throw 'SCHEDULER'};"
             "$account='" + account_for_remote + "';$resolved=([Security.Principal.NTAccount]::new($account))."
             "Translate([Security.Principal.SecurityIdentifier]).Value;if($resolved -cne $sid){throw 'SID_MISMATCH'};"
             "$owners=0;foreach($x in @(Get-CimInstance Win32_Process -Filter \\\"Name='explorer.exe'\\\" -ErrorAction Stop)){"
             "if($x.SessionId -eq 1){$o=Invoke-CimMethod -InputObject $x -MethodName GetOwnerSid -ErrorAction Stop;"
             "if($o.ReturnValue -eq 0 -and $o.Sid -ceq $sid){$owners++}}};if($owners -ne 1){throw 'SESSION'};"
             + prior_absence + process_guard)
    marker = "A $install;A $state;if(Get-ScheduledTask -TaskName $n"
    return _REMOTE.replace(_TASK, task_name).replace(marker, "A $install;A $state;" + guard + "if(Get-ScheduledTask -TaskName $n").replace("$p=New-ScheduledTaskPrincipal -UserId $sid", replacement)


def _run_named(config: Any, desc: tuple[str, str, int, int, str], hash_: str, mode: str, task_name: str) -> str:
    raw = base._remote(config, _remote_for(task_name), (desc[1], str(desc[2]), str(desc[3]), desc[4], hash_, mode), None, 90)
    try: value = json.loads(raw) if raw else {}
    except (ValueError, TypeError): return "unknown"
    return value.get("state") if isinstance(value, dict) and set(value) == {"version", "state"} and value.get("version") == 1 else "unknown"

def _dir(root:Path,create:bool)->Path:
 p=root/_GROUP
 if create:p.mkdir(mode=0o700,parents=True,exist_ok=True)
 i=p.lstat()
 if not stat.S_ISDIR(i.st_mode) or p.is_symlink() or i.st_uid!=os.getuid() or stat.S_IMODE(i.st_mode)!=0o700:raise WindowsMsiOwnerPublicStatusError('Unsafe journal.')
 return p
def _path(root:Path,create:bool)->Path:return _dir(root,create)/(_CORRELATION+'.json')
def _read(root:Path)->dict|None:
 try:p=_path(root,False)
 except FileNotFoundError:return None
 try:fd=os.open(p,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
 except FileNotFoundError:return None
 with os.fdopen(fd,'rb') as stream:
  info=os.fstat(stream.fileno())
  if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_size>4096:raise WindowsMsiOwnerPublicStatusError('Unsafe journal.')
  raw=stream.read()
 try:v=json.loads(raw)
 except (ValueError,TypeError):raise WindowsMsiOwnerPublicStatusError('Invalid journal.')
 if not isinstance(v,dict) or set(v)!={'version','correlationId','sourceSha','guestGeneration','evidenceSha256','state'} or v.get('version')!=1 or v.get('correlationId')!=_CORRELATION or v.get('sourceSha')!=relaunch._SOURCE or v.get('state') not in {'intent','proved'}:raise WindowsMsiOwnerPublicStatusError('Invalid journal.')
 return v
def _write(root:Path,v:dict,replace:bool=False)->None:
 d=_dir(root,True);p=_path(root,True);lock=os.open(d/'.lock',os.O_RDWR|os.O_CREAT,0o600)
 try:
  fcntl.flock(lock,fcntl.LOCK_EX);cur=_read(root)
  if (cur is not None)!=replace or (replace and cur.get('state')!='intent'):raise WindowsMsiOwnerPublicStatusError('Journal changed.')
  t=p.with_suffix('.tmp');data=(json.dumps(v,sort_keys=True,separators=(',',':'))+'\n').encode();fd=os.open(t,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
  with os.fdopen(fd,'wb') as stream:stream.write(data);stream.flush();os.fsync(stream.fileno())
  os.replace(t,p);parent=os.open(d,os.O_RDONLY|getattr(os,'O_DIRECTORY',0));os.fsync(parent);os.close(parent)
 finally:os.close(lock)
def _admit(root:Path):
 a=relaunch._admit(root);launch=relaunch._read_intent(root)
 if a is None or not isinstance(launch,dict) or launch.get('state') not in {'intent','launched'}:return None
 config,desc,hash_,evidence=a
 gen={'socketPath':desc[1],'qemuPid':desc[2],'startTicks':desc[3]}
 if launch.get('guestGeneration')!=gen or launch.get('staleRecoveryEvidenceSha256')!=evidence:return None
 detail=relaunch.detail(root,{'host':'archlinux'})
 exact={'state':'detailed','baseOwners':'none','quotedStateServe':'one','unquotedStateServe':'one','otherSubcommand':'none','unrelated':'none','ownerIdentity':'exact','replayAllowed':False,'nativeActionAllowed':False}
 if not isinstance(detail,dict) or any(detail.get(key)!=value for key,value in exact.items()):return None
 if detail.get('endpoint') not in relaunch._DETAIL_LEAF or any(detail.get(key) not in relaunch._DETAIL_FIELD for key in ('schemaVersion','controllerId','port','token')):return None
 live=relaunch.liveness.observe(root,{'host':'archlinux'})
 required={'state':'blocked','sourceSha':relaunch._SOURCE,'correlationId':relaunch.stale_lock._CORRELATION,'ownerProcesses':'many','installerProcesses':'none','consentProcesses':'none','runtimeProcesses':'none','stateLeaves':'both','runtimeOff':True,'replayAllowed':False,'nativeActionAllowed':False}
 if live!=required:return None
 if _app_census(config,desc,hash_)!={'gui':'none','cli':'two'}:return None
 return config,desc,hash_,gen,evidence
def _run(config,desc,hash_,mode):
 return _run_named(config,desc,hash_,mode,_TASK)
def _app_census(config,desc,hash_):
 raw=base._remote(config,_REMOTE,(desc[1],str(desc[2]),str(desc[3]),desc[4],hash_,'census'),None,60)
 try:v=json.loads(raw) if raw else {}
 except (ValueError,TypeError):return None
 return {'gui':v.get('gui'),'cli':v.get('cli')} if isinstance(v,dict) and set(v)=={'version','gui','cli'} and v.get('version')==1 and v.get('gui') in {'none','one','many','ambiguous'} and v.get('cli') in {'two','other','ambiguous'} else None
def _diagnostic_named(config,desc,hash_,task_name):
 if task_name not in _ALLOWED_TASKS:raise WindowsMsiOwnerPublicStatusError('Unrecognized public-status task.')
 raw=base._remote(config,_remote_for(task_name),(desc[1],str(desc[2]),str(desc[3]),desc[4],hash_,'diagnose'),None,60)
 try:v=json.loads(raw) if raw else {}
 except (ValueError,TypeError):return None
 return {'phase':v.get('phase'),'task':v.get('task')} if isinstance(v,dict) and set(v)=={'version','phase','task'} and v.get('version')==1 and v.get('phase') in {'system-identity','ancestors','acl','cli','endpoint','task'} and v.get('task') in {'absent','principal-mismatch','action-mismatch','pending','proved','failed','unknown'} else None
def _diagnostic(config,desc,hash_):
 return _diagnostic_named(config,desc,hash_,_TASK)
def start(root:Path|str,inputs:Mapping[str,Any])->dict:
 if not isinstance(inputs,Mapping) or dict(inputs)!={'host':'archlinux'}:raise WindowsMsiOwnerPublicStatusError('Exact CP117 host required.')
 try:
  root=Path(root).resolve();a=_admit(root)
  if a is None:return dict(_UNKNOWN)
  current=_read(root)
  if current is not None:return status(root,inputs)
  config,desc,hash_,gen,evidence=a;_write(root,{'version':1,'correlationId':_CORRELATION,'sourceSha':relaunch._SOURCE,'guestGeneration':gen,'evidenceSha256':evidence,'state':'intent'})
  return status(root,inputs) if _run(config,desc,hash_,'start')=='submitted' else dict(_UNKNOWN)
 except (OSError,ValueError,TypeError,KeyError,WindowsMsiOwnerPublicStatusError):return dict(_UNKNOWN)
def status(root:Path|str,inputs:Mapping[str,Any])->dict:
 if not isinstance(inputs,Mapping) or dict(inputs)!={'host':'archlinux'}:raise WindowsMsiOwnerPublicStatusError('Exact CP117 host required.')
 try:
  root=Path(root).resolve();a=_admit(root);record=_read(root)
  if a is None or record is None:return dict(_UNKNOWN)
  config,desc,hash_,gen,evidence=a
  if record.get('guestGeneration')!=gen or record.get('evidenceSha256')!=evidence:return dict(_UNKNOWN)
  observed=_run(config,desc,hash_,'status')
  if observed=='proved':
   return {'state':'proved','runtimeRunning':False,'replayAllowed':False,'nativeActionAllowed':False}
  return {'state':'pending','replayAllowed':False,'nativeActionAllowed':False} if observed=='pending' else dict(_UNKNOWN)
 except (OSError,ValueError,TypeError,KeyError,WindowsMsiOwnerPublicStatusError):return dict(_UNKNOWN)
def collect(root:Path|str,inputs:Mapping[str,Any])->dict:return status(root,inputs)
def diagnose(root:Path|str,inputs:Mapping[str,Any])->dict:
 if not isinstance(inputs,Mapping) or dict(inputs)!={'host':'archlinux'}:raise WindowsMsiOwnerPublicStatusError('Exact CP117 host required.')
 try:
  root=Path(root).resolve();a=_admit(root);record=_read(root)
  if a is None or record is None or record.get('state')!='intent':return dict(_UNKNOWN)
  config,desc,hash_,gen,evidence=a
  if record.get('guestGeneration')!=gen or record.get('evidenceSha256')!=evidence:return dict(_UNKNOWN)
  found=_diagnostic(config,desc,hash_)
  return {'state':'diagnosed',**found,'replayAllowed':False,'nativeActionAllowed':False} if found is not None else dict(_UNKNOWN)
 except (OSError,ValueError,TypeError,KeyError,WindowsMsiOwnerPublicStatusError):return dict(_UNKNOWN)
def workflow(root:Path|str,action:str,inputs:Mapping[str,Any])->dict:
 if action=='start':return start(root,inputs)
 if action in {'status','collect'}:return status(root,inputs)
 if action=='diagnose':return diagnose(root,inputs)
 raise WindowsMsiOwnerPublicStatusError('Unsupported action.')
