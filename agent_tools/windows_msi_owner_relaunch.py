"""One-shot, source-bound relaunch of CP117's original-user CLI owner.

The only mutation is a scheduled task created inside the disposable CP117
guest.  A durable host intent is written before QGA is asked to create that
task.  Consequently a lost QGA response is an unknown result, never a reason
to submit a second launch request.
"""
from __future__ import annotations

import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Any, Mapping

from . import windows_msi_base_prepare as base
from . import windows_msi_owner_liveness as liveness
from . import windows_msi_stale_lock_recovery as stale_lock
from . import windows_msi_stale_lock_reconcile as stale_reconcile


class WindowsMsiOwnerRelaunchError(ValueError):
    pass


_CORRELATION = "c32cb108-4d48-407e-9153-40774559ba50"
_SOURCE = "19be9df22cbab8086c26e5ca907d9569a5a28a08"
_GROUP = ".rag_index/windows-msi-owner-relaunch"
_TASK = "VpnControlCp117OwnerRelaunchC32"
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_UNKNOWN = {"state": "unknown", "replayAllowed": False, "nativeActionAllowed": False}
_TASK_STATES = {"absent", "principal-mismatch", "action-mismatch", "exact", "ambiguous"}
_OWNER_STATES = {"none", "one", "two", "many", "sid-mismatch", "session-mismatch", "command-mismatch", "ambiguous"}
_ENDPOINT_STATES = {"absent", "reparse", "invalid", "controller-invalid", "valid", "ambiguous"}
_DIAGNOSTIC_PHASES = {"task-absent", "task-principal-mismatch", "task-action-mismatch", "task-ambiguous",
                      "owner-process-count-none", "owner-process-count-one", "owner-process-count-two",
                      "owner-process-count-many", "owner-sid-mismatch", "owner-session-mismatch",
                      "owner-command-mismatch", "owner-ambiguous", "endpoint-absent", "endpoint-reparse",
                      "endpoint-invalid", "endpoint-controller-invalid", "endpoint-ambiguous", "owner-multiple-with-endpoint",
                      "diagnostic-ancestors", "diagnostic-cli", "diagnostic-task-query", "diagnostic-process-query",
                      "diagnostic-endpoint", "diagnostic-phase-eval"}
_DETAIL_COUNTS = {"none", "one", "many", "ambiguous"}
_DETAIL_IDENTITY = {"exact", "sid-mismatch", "session-mismatch", "path-mismatch", "ambiguous"}
_DETAIL_FIELD = {"valid", "missing", "invalid", "ambiguous"}
_DETAIL_LEAF = {"absent", "reparse", "invalid", "valid", "ambiguous"}
_ENDPOINT_ACCESS = {"absent", "access-denied", "read-error", "reparse", "present-invalid", "parse-invalid", "schema-invalid", "schema-valid", "ambiguous"}


# The script executes under QGA's privileged context but starts exactly one
# limited interactive-token task for the original user.  It refuses to replace
# any pre-existing task and repeats all state checks immediately before task
# creation.  It never starts or stops sing-box.
_LAUNCH_PS = r'''$ErrorActionPreference='Stop'
$sid='__SID__';$expectedHash='__CLI_HASH__';$taskName='__TASK__'
$install='C:\Users\vpncp117\AppData\Local\vpn-control';$cli=Join-Path $install 'vpn-control-cli.exe'
$state='C:\Users\vpncp117\AppData\Local\VpnControl\cp166\state';$lock=Join-Path $state 'vpn-control.lock';$endpoint=Join-Path $state 'activation.port'
$argument='--state-dir "'+$state+'" serve';$expectedCommandLines=@($cli+' '+$argument,'"'+$cli+'" '+$argument)
function Fail { throw 'UNSAFE' }
function Missing([string]$path) { try { Get-Item -LiteralPath $path -Force -ErrorAction Stop|Out-Null;Fail } catch { if($_.CategoryInfo.Category -ne [System.Management.Automation.ErrorCategory]::ObjectNotFound){Fail} } }
function SafeDirectory([string]$path) {$item=Get-Item -LiteralPath $path -Force -ErrorAction Stop;if(-not $item.PSIsContainer -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)){Fail}}
function SafeAncestors { foreach($path in @('C:\Users','C:\Users\vpncp117','C:\Users\vpncp117\AppData','C:\Users\vpncp117\AppData\Local',$install,'C:\Users\vpncp117\AppData\Local\VpnControl','C:\Users\vpncp117\AppData\Local\VpnControl\cp166',$state)){SafeDirectory $path} }
function Probe {
 SafeAncestors
 $item=Get-Item -LiteralPath $cli -Force -ErrorAction Stop
 if($item.PSIsContainer -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or (Get-FileHash -LiteralPath $cli -Algorithm SHA256).Hash.ToLowerInvariant() -cne $expectedHash){Fail}
 $products=@(Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',('Registry::HKEY_USERS\'+$sid+'\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'),('Registry::HKEY_USERS\'+$sid+'\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*') -ErrorAction SilentlyContinue|Where-Object {$_.DisplayName -eq 'vpn-control'})
 if($products.Count -ne 1 -or $products[0].DisplayVersion -cne '2.1.19' -or $products[0].InstallLocation.TrimEnd('\\') -cne $install){Fail}
 $stateItem=Get-Item -LiteralPath $state -Force -ErrorAction Stop
 if(-not $stateItem.PSIsContainer -or (($stateItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)){Fail}
 Missing $lock;Missing $endpoint
 if(Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue){Fail}
 $all=@(Get-CimInstance Win32_Process -ErrorAction Stop)
 if(@($all|Where-Object {$_.Name -in @('vpn-control.exe','vpn-control-cli.exe','msiexec.exe','consent.exe','sing-box.exe')}).Count -ne 0){Fail}
}
function OwnedOwner([object]$process) {
 $owner=Invoke-CimMethod -InputObject $process -MethodName GetOwnerSid -ErrorAction Stop
 return $owner.ReturnValue -eq 0 -and $owner.Sid -ceq $sid -and $process.SessionId -eq 1 -and $process.Name -ceq 'vpn-control-cli.exe' -and $process.ExecutablePath -ceq $cli -and $process.CommandLine -in $expectedCommandLines
}
try {
 Probe
 $action=New-ScheduledTaskAction -Execute $cli -Argument $argument
 $principal=New-ScheduledTaskPrincipal -UserId $sid -LogonType Interactive -RunLevel Limited
 $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
 Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $settings -Force:$false|Out-Null
 Start-ScheduledTask -TaskName $taskName
 $observed=$null
 for($i=0;$i -lt 80;$i++){
  Start-Sleep -Milliseconds 250
  try {
   $port=Get-Item -LiteralPath $endpoint -Force -ErrorAction Stop
   if($port.PSIsContainer -or (($port.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or $port.Length -lt 1 -or $port.Length -gt 4096){Fail}
   $apps=@(Get-CimInstance Win32_Process -ErrorAction Stop|Where-Object {$_.Name -ceq 'vpn-control-cli.exe'})
   if($apps.Count -ge 2){Fail}
   if($apps.Count -eq 1 -and (OwnedOwner $apps[0])){$observed=$apps[0];break}
  }catch{if($_.Exception.Message -eq 'UNSAFE'){throw}}
 }
 if($null -eq $observed){Fail}
 [Console]::Out.WriteLine(([pscustomobject]@{version=1;state='launched';cliSha256=$expectedHash;ownerPid=[int]$observed.ProcessId;sessionId=[int]$observed.SessionId;runtimeRunning=$false}|ConvertTo-Json -Compress))
}catch{[Console]::Out.WriteLine('{"version":1,"state":"unknown"}')}
'''


# Status is deliberately read-only.  It proves the same original-user owner
# and endpoint leaf, but never invokes Start-ScheduledTask or changes the task.
_STATUS_PS = r'''$ErrorActionPreference='Stop'
try {
 $sid='__SID__';$expectedHash='__CLI_HASH__';$taskName='__TASK__'
 $cli='C:\Users\vpncp117\AppData\Local\vpn-control\vpn-control-cli.exe';$state='C:\Users\vpncp117\AppData\Local\VpnControl\cp166\state';$endpoint=Join-Path $state 'activation.port'
 $argument='--state-dir "'+$state+'" serve';$expectedCommandLines=@($cli+' '+$argument,'"'+$cli+'" '+$argument)
 function SafeDirectory([string]$path) {$item=Get-Item -LiteralPath $path -Force -ErrorAction Stop;if(-not $item.PSIsContainer -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)){throw 'ANCESTOR'}}
 function SafeAncestors { foreach($path in @('C:\Users','C:\Users\vpncp117','C:\Users\vpncp117\AppData','C:\Users\vpncp117\AppData\Local','C:\Users\vpncp117\AppData\Local\vpn-control','C:\Users\vpncp117\AppData\Local\VpnControl','C:\Users\vpncp117\AppData\Local\VpnControl\cp166',$state)){SafeDirectory $path} }
 function PrincipalSid([string]$userId) { if($userId -match '^S-1-'){return ([Security.Principal.SecurityIdentifier]::new($userId)).Value};return ([Security.Principal.NTAccount]::new($userId)).Translate([Security.Principal.SecurityIdentifier]).Value }
 SafeAncestors
 $item=Get-Item -LiteralPath $cli -Force -ErrorAction Stop
 if($item.PSIsContainer -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or (Get-FileHash -LiteralPath $cli -Algorithm SHA256).Hash.ToLowerInvariant() -cne $expectedHash){throw 'CLI'}
 $port=Get-Item -LiteralPath $endpoint -Force -ErrorAction Stop
 if($port.PSIsContainer -or (($port.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or $port.Length -lt 1 -or $port.Length -gt 4096){throw 'ENDPOINT'}
 $task=Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
 $principalSid=PrincipalSid ([string]$task.Principal.UserId)
 if($principalSid -cne $sid -or $task.Principal.LogonType.ToString() -cne 'Interactive' -or $task.Principal.RunLevel.ToString() -cne 'Limited'){throw 'TASK'}
 $actions=@($task.Actions)
 if($actions.Count -ne 1 -or $actions[0].Execute -cne $cli -or $actions[0].Arguments -cne $argument){throw 'TASK_ACTION'}
 $apps=@(Get-CimInstance Win32_Process -ErrorAction Stop|Where-Object {$_.Name -ceq 'vpn-control-cli.exe'})
 if($apps.Count -ne 2){throw 'OWNER'}
 $quoted=0;$unquoted=0
 foreach($app in $apps){$owner=Invoke-CimMethod -InputObject $app -MethodName GetOwnerSid -ErrorAction Stop;if($owner.ReturnValue -ne 0 -or $owner.Sid -cne $sid -or $app.SessionId -ne 1 -or $app.ExecutablePath -cne $cli){throw 'OWNER'};if($app.CommandLine -ceq $expectedCommandLines[0]){$unquoted++}elseif($app.CommandLine -ceq $expectedCommandLines[1]){$quoted++}else{throw 'OWNER'}}
 if($quoted -ne 1 -or $unquoted -ne 1){throw 'OWNER'}
 if(@(Get-CimInstance Win32_Process -ErrorAction Stop|Where-Object {$_.Name -in @('msiexec.exe','consent.exe','sing-box.exe')}).Count -ne 0){throw 'RUNTIME'}
 [Console]::Out.WriteLine(([pscustomobject]@{version=1;state='launched';cliSha256=$expectedHash;ownerPid=[int]$apps[0].ProcessId;sessionId=1;runtimeRunning=$false}|ConvertTo-Json -Compress))
}catch{[Console]::Out.WriteLine('{"version":1,"state":"unknown"}')}
'''


_ENDPOINT_ACCESS_PS = r'''$ErrorActionPreference='Stop'
$state='C:\Users\vpncp117\AppData\Local\VpnControl\cp166\state';$endpoint=Join-Path $state 'activation.port'
function SafeDirectory([string]$path){$item=Get-Item -LiteralPath $path -Force -ErrorAction Stop;if(-not $item.PSIsContainer -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)){throw 'DIR'}}
function AccessCategory([object]$errorRecord) { if($errorRecord.CategoryInfo.Category -eq [System.Management.Automation.ErrorCategory]::PermissionDenied){'access-denied'}else{'read-error'} }
try {
 foreach($path in @('C:\Users','C:\Users\vpncp117','C:\Users\vpncp117\AppData','C:\Users\vpncp117\AppData\Local','C:\Users\vpncp117\AppData\Local\VpnControl','C:\Users\vpncp117\AppData\Local\VpnControl\cp166',$state)){SafeDirectory $path}
 $result='absent'
 try{$item=Get-Item -LiteralPath $endpoint -Force -ErrorAction Stop;if($item.PSIsContainer -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)){$result='reparse'}elseif($item.Length -lt 2 -or $item.Length -gt 4096){$result='present-invalid'}else{try{$value=Get-Content -LiteralPath $endpoint -Raw -ErrorAction Stop|ConvertFrom-Json -ErrorAction Stop;if($value.schemaVersion -ne 1 -or ([string]$value.controllerId) -notmatch '^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$' -or [guid]::Parse([string]$value.controllerId).ToString() -cne [string]$value.controllerId -or $value.port -lt 1 -or $value.port -gt 65535 -or ([string]$value.token) -notmatch '^[A-Za-z0-9_-]{43}$'){$result='schema-invalid'}else{$result='schema-valid'}}catch{$result=AccessCategory $_}}}catch{if($_.CategoryInfo.Category -ne [System.Management.Automation.ErrorCategory]::ObjectNotFound){$result=AccessCategory $_}}
 [Console]::Out.WriteLine((@{version=1;endpoint=$result}|ConvertTo-Json -Compress))
}catch{[Console]::Out.WriteLine('{"version":1,"endpoint":"ambiguous"}')}
'''


# This is diagnosis only.  It does not call Start-ScheduledTask, write a task,
# stop an owner, or open the public endpoint.  Fields are closed finite sets so
# the raw task account, command line, process IDs, and endpoint token never
# leave the guest.
_DIAGNOSE_PS = r'''$ErrorActionPreference='Stop';$stage='ancestors'
try {
 $sid='__SID__';$expectedHash='__CLI_HASH__';$taskName='__TASK__'
 $cli='C:\Users\vpncp117\AppData\Local\vpn-control\vpn-control-cli.exe';$state='C:\Users\vpncp117\AppData\Local\VpnControl\cp166\state';$endpoint=Join-Path $state 'activation.port'
 $argument='--state-dir "'+$state+'" serve';$expectedCommandLines=@($cli+' '+$argument,'"'+$cli+'" '+$argument)
 function SafeDirectory([string]$path) {$item=Get-Item -LiteralPath $path -Force -ErrorAction Stop;if(-not $item.PSIsContainer -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)){throw 'DIR'}}
 function SafeAncestors { foreach($path in @('C:\Users','C:\Users\vpncp117','C:\Users\vpncp117\AppData','C:\Users\vpncp117\AppData\Local','C:\Users\vpncp117\AppData\Local\vpn-control','C:\Users\vpncp117\AppData\Local\VpnControl','C:\Users\vpncp117\AppData\Local\VpnControl\cp166',$state)){SafeDirectory $path} }
 function PrincipalSid([string]$userId) { if($userId -match '^S-1-'){return ([Security.Principal.SecurityIdentifier]::new($userId)).Value};return ([Security.Principal.NTAccount]::new($userId)).Translate([Security.Principal.SecurityIdentifier]).Value }
 SafeAncestors
 $stage='cli'
 $file=Get-Item -LiteralPath $cli -Force -ErrorAction Stop
 if($file.PSIsContainer -or (($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or (Get-FileHash -LiteralPath $cli -Algorithm SHA256).Hash.ToLowerInvariant() -cne $expectedHash){throw 'CLI'}
 $stage='task-query'
 $taskState='absent';$task=Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
 if($null -ne $task){
  try {$principalSid=PrincipalSid ([string]$task.Principal.UserId);if($principalSid -ne $sid -or $task.Principal.LogonType.ToString() -ne 'Interactive' -or $task.Principal.RunLevel.ToString() -ne 'Limited'){$taskState='principal-mismatch'}else{$actions=@($task.Actions);$taskState=if($actions.Count -eq 1 -and $actions[0].Execute -ceq $cli -and $actions[0].Arguments -ceq $argument){'exact'}else{'action-mismatch'}}}catch{$taskState='ambiguous'}
 }
 $stage='process-query'
 $all=@(Get-CimInstance Win32_Process -ErrorAction Stop);$apps=@($all|Where-Object {$_.Name -ceq 'vpn-control-cli.exe'})
 $owners=if($apps.Count -eq 0){'none'}elseif($apps.Count -eq 1){'one'}elseif($apps.Count -eq 2){'two'}elseif($apps.Count -le 16){'many'}else{'ambiguous'}
 if($owners -notin @('none','ambiguous')){foreach($app in $apps){try{$owner=Invoke-CimMethod -InputObject $app -MethodName GetOwnerSid -ErrorAction Stop;if($owner.ReturnValue -ne 0 -or $owner.Sid -cne $sid){$owners='sid-mismatch';break};if($app.SessionId -ne 1){$owners='session-mismatch';break};if($app.ExecutablePath -cne $cli -or $app.CommandLine -notin $expectedCommandLines){$owners='command-mismatch';break}}catch{$owners='ambiguous';break}}}
 $stage='endpoint';$endpointState='absent'
 try{$leaf=Get-Item -LiteralPath $endpoint -Force -ErrorAction Stop;if($leaf.PSIsContainer -or (($leaf.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)){$endpointState='reparse'}elseif($leaf.Length -lt 2 -or $leaf.Length -gt 4096){$endpointState='invalid'}else{try{$value=Get-Content -LiteralPath $endpoint -Raw -ErrorAction Stop|ConvertFrom-Json -ErrorAction Stop;if($value.schemaVersion -ne 1 -or $value.port -lt 1 -or $value.port -gt 65535 -or $value.token -notmatch '^[A-Za-z0-9_-]{43}$'){$endpointState='invalid'}elseif(([string]$value.controllerId) -notmatch '^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$' -or [guid]::Parse([string]$value.controllerId).ToString() -cne [string]$value.controllerId){$endpointState='controller-invalid'}else{$endpointState='valid'}}catch{$endpointState='invalid'}}}catch{if($_.CategoryInfo.Category -ne [System.Management.Automation.ErrorCategory]::ObjectNotFound){$endpointState='ambiguous'}}
 $stage='phase-eval'
 if($taskState -ne 'exact'){$phase='task-'+$taskState}
 elseif($owners -ne 'two'){
  if($owners -in @('none','one','many')){$phase='owner-process-count-'+$owners}
  else{$phase='owner-'+$owners}
 }
 elseif($endpointState -ne 'valid'){$phase='endpoint-'+$endpointState}
 else{$phase='owner-multiple-with-endpoint'}
 [Console]::Out.WriteLine(([pscustomobject]@{version=1;phase=$phase;task=$taskState;owners=$owners;endpoint=$endpointState}|ConvertTo-Json -Compress))
}catch{[Console]::Out.WriteLine((@{version=1;phase=('diagnostic-'+$stage);task='ambiguous';owners='ambiguous';endpoint='ambiguous'}|ConvertTo-Json -Compress))}
'''


_DETAIL_PS = r'''$ErrorActionPreference='Stop'
try {
 $sid='__SID__';$expectedHash='__CLI_HASH__'
 $cli='C:\Users\vpncp117\AppData\Local\vpn-control\vpn-control-cli.exe';$state='C:\Users\vpncp117\AppData\Local\VpnControl\cp166\state';$endpoint=Join-Path $state 'activation.port'
 function SafeDirectory([string]$path) {$item=Get-Item -LiteralPath $path -Force -ErrorAction Stop;if(-not $item.PSIsContainer -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)){throw 'DIR'}}
 function Count([int]$value){if($value -eq 0){'none'}elseif($value -eq 1){'one'}elseif($value -le 16){'many'}else{'ambiguous'}}
 function Field([object]$value,[string]$name){if($null -eq $value.PSObject.Properties[$name]){'missing'}else{'valid'}}
 foreach($path in @('C:\Users','C:\Users\vpncp117','C:\Users\vpncp117\AppData','C:\Users\vpncp117\AppData\Local','C:\Users\vpncp117\AppData\Local\vpn-control','C:\Users\vpncp117\AppData\Local\VpnControl','C:\Users\vpncp117\AppData\Local\VpnControl\cp166',$state)){SafeDirectory $path}
 $file=Get-Item -LiteralPath $cli -Force -ErrorAction Stop
 if($file.PSIsContainer -or (($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or (Get-FileHash -LiteralPath $cli -Algorithm SHA256).Hash.ToLowerInvariant() -cne $expectedHash){throw 'CLI'}
 $base=0;$quoted=0;$unquoted=0;$subcommand=0;$unrelated=0;$identity='exact'
 $quotedCommand='"'+$cli+'" --state-dir "'+$state+'" serve';$unquotedCommand=$cli+' --state-dir '+$state+' serve';$baseCommands=@($cli,'"'+$cli+'"')
 $apps=@(Get-CimInstance Win32_Process -ErrorAction Stop|Where-Object {$_.Name -ceq 'vpn-control-cli.exe'})
 foreach($app in $apps){
  try{$owner=Invoke-CimMethod -InputObject $app -MethodName GetOwnerSid -ErrorAction Stop;if($owner.ReturnValue -ne 0 -or $owner.Sid -cne $sid){$identity='sid-mismatch';continue};if($app.SessionId -ne 1){$identity='session-mismatch';continue};if($app.ExecutablePath -cne $cli){$identity='path-mismatch';continue};$command=[string]$app.CommandLine;if($command -in $baseCommands){$base++}elseif($command -ceq $quotedCommand){$quoted++}elseif($command -ceq $unquotedCommand){$unquoted++}elseif($command -like ($cli+' --state-dir *')){$subcommand++}else{$unrelated++}}catch{$identity='ambiguous'}
 }
 $leaf='absent';$schema='missing';$controller='missing';$port='missing';$token='missing'
 try{$item=Get-Item -LiteralPath $endpoint -Force -ErrorAction Stop;if($item.PSIsContainer -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)){$leaf='reparse'}elseif($item.Length -lt 2 -or $item.Length -gt 4096){$leaf='invalid'}else{try{$value=Get-Content -LiteralPath $endpoint -Raw -ErrorAction Stop|ConvertFrom-Json -ErrorAction Stop;$leaf='valid';$schema=Field $value 'schemaVersion';if($schema -eq 'valid' -and (($value.schemaVersion -isnot [int] -and $value.schemaVersion -isnot [long]) -or $value.schemaVersion -ne 1)){$schema='invalid'};$controller=Field $value 'controllerId';if($controller -eq 'valid' -and (([string]$value.controllerId) -notmatch '^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$' -or [guid]::Parse([string]$value.controllerId).ToString() -cne [string]$value.controllerId)){$controller='invalid'};$port=Field $value 'port';if($port -eq 'valid' -and (($value.port -isnot [int] -and $value.port -isnot [long]) -or $value.port -lt 1 -or $value.port -gt 65535)){$port='invalid'};$token=Field $value 'token';if($token -eq 'valid' -and ([string]$value.token) -notmatch '^[A-Za-z0-9_-]{43}$'){$token='invalid'}}catch{$leaf='invalid';$schema='ambiguous';$controller='ambiguous';$port='ambiguous';$token='ambiguous'}}}catch{if($_.CategoryInfo.Category -ne [System.Management.Automation.ErrorCategory]::ObjectNotFound){$leaf='ambiguous';$schema='ambiguous';$controller='ambiguous';$port='ambiguous';$token='ambiguous'}}
 [Console]::Out.WriteLine(([pscustomobject]@{version=1;baseOwners=(Count $base);quotedStateServe=(Count $quoted);unquotedStateServe=(Count $unquoted);otherSubcommand=(Count $subcommand);unrelated=(Count $unrelated);ownerIdentity=$identity;endpoint=$leaf;schemaVersion=$schema;controllerId=$controller;port=$port;token=$token}|ConvertTo-Json -Compress))
}catch{[Console]::Out.WriteLine('{"version":1,"baseOwners":"ambiguous","quotedStateServe":"ambiguous","unquotedStateServe":"ambiguous","otherSubcommand":"ambiguous","unrelated":"ambiguous","ownerIdentity":"ambiguous","endpoint":"ambiguous","schemaVersion":"ambiguous","controllerId":"ambiguous","port":"ambiguous","token":"ambiguous"}')}
'''


_REMOTE = base._QGA + r'''import time
sock,pid,ticks,sid,cli_hash,mode=sys.argv[1:]
TASK_NAME=__TASK_NAME_LITERAL__
def out(value):print(json.dumps(value,separators=(',',':'),sort_keys=True))
try:
 if mode not in ('launch','status','diagnose','detail','endpoint-access') or not live(sock,pid,ticks):raise ValueError()
 template=LAUNCH_PS if mode=='launch' else (STATUS_PS if mode=='status' else (DIAGNOSE_PS if mode=='diagnose' else (DETAIL_PS if mode=='detail' else ENDPOINT_ACCESS_PS)))
 script=template.replace('__SID__',sid).replace('__CLI_HASH__',cli_hash).replace('__TASK__',TASK_NAME)
 child=call(sock,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',base64.b64encode(script.encode('utf-16le')).decode()],'capture-output':True}).get('pid')
 if type(child) is not int or child<=0:raise ValueError()
 for _ in range(160):
  observed=call(sock,'guest-exec-status',{'pid':child})
  if observed.get('exited') is True:break
  if observed.get('exited') is not False:raise ValueError()
  time.sleep(.25)
 else:raise ValueError()
 if type(observed.get('exitcode')) is not int or observed['exitcode']!=0 or observed.get('out-truncated') is True or observed.get('err-truncated') is True:raise ValueError()
 raw=base64.b64decode(observed.get('out-data',''),validate=True)
 if not 0<len(raw)<=1024:raise ValueError()
 lines=[line for line in decode(raw).splitlines() if line.startswith('{') and line.endswith('}')]
 if len(lines)!=1:raise ValueError()
 value=json.loads(lines[0])
 if mode=='endpoint-access':
  if not isinstance(value,dict) or set(value)!={'version','endpoint'} or value.get('version')!=1 or value.get('endpoint') not in ACCESS:raise ValueError()
 elif mode=='detail':
  fields={'version','baseOwners','quotedStateServe','unquotedStateServe','otherSubcommand','unrelated','ownerIdentity','endpoint','schemaVersion','controllerId','port','token'}
  if not isinstance(value,dict) or set(value)!=fields or value.get('version')!=1 or any(value.get(key) not in COUNTS for key in ('baseOwners','quotedStateServe','unquotedStateServe','otherSubcommand','unrelated')) or value.get('ownerIdentity') not in IDENTITIES or value.get('endpoint') not in LEAVES or any(value.get(key) not in FIELDS for key in ('schemaVersion','controllerId','port','token')):raise ValueError()
 elif mode=='diagnose':
  if not isinstance(value,dict) or set(value)!={'version','phase','task','owners','endpoint'} or value.get('version')!=1 or value.get('phase') not in PHASES or value.get('task') not in TASKS or value.get('owners') not in OWNERS or value.get('endpoint') not in ENDPOINTS:raise ValueError()
 else:
  fields={'version','state'} if value.get('state')=='unknown' else {'version','state','cliSha256','ownerPid','sessionId','runtimeRunning'}
  if not isinstance(value,dict) or set(value)!=fields or value.get('version')!=1 or value.get('state') not in ('launched','unknown'):raise ValueError()
  if value['state']=='launched' and (value.get('cliSha256')!=cli_hash or type(value.get('ownerPid')) is not int or value['ownerPid']<=0 or value.get('sessionId')!=1 or value.get('runtimeRunning') is not False):raise ValueError()
 out(value)
except Exception:
 if mode=='endpoint-access':out({'version':1,'endpoint':'ambiguous'})
 elif mode=='detail':out({'version':1,'baseOwners':'ambiguous','quotedStateServe':'ambiguous','unquotedStateServe':'ambiguous','otherSubcommand':'ambiguous','unrelated':'ambiguous','ownerIdentity':'ambiguous','endpoint':'ambiguous','schemaVersion':'ambiguous','controllerId':'ambiguous','port':'ambiguous','token':'ambiguous'})
 elif mode=='diagnose':out({'version':1,'phase':'diagnostic-phase-eval','task':'ambiguous','owners':'ambiguous','endpoint':'ambiguous'})
 else:out({'version':1,'state':'unknown'})
'''.replace('LAUNCH_PS', repr(_LAUNCH_PS)).replace('STATUS_PS', repr(_STATUS_PS)).replace('DIAGNOSE_PS', repr(_DIAGNOSE_PS)).replace('DETAIL_PS', repr(_DETAIL_PS)).replace('ENDPOINT_ACCESS_PS', repr(_ENDPOINT_ACCESS_PS)).replace('PHASES', repr(_DIAGNOSTIC_PHASES)).replace('TASKS', repr(_TASK_STATES)).replace('OWNERS', repr(_OWNER_STATES)).replace('ENDPOINTS', repr(_ENDPOINT_STATES)).replace('ACCESS', repr(_ENDPOINT_ACCESS)).replace('COUNTS', repr(_DETAIL_COUNTS)).replace('IDENTITIES', repr(_DETAIL_IDENTITY)).replace('LEAVES', repr(_DETAIL_LEAF)).replace('FIELDS', repr(_DETAIL_FIELD)).replace('__TASK_NAME_LITERAL__', repr(_TASK))


def _directory(root: Path, *, create: bool) -> Path:
    path = root / _GROUP
    if create:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
    elif not path.exists():
        raise FileNotFoundError(path)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or path.is_symlink() or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise WindowsMsiOwnerRelaunchError("Owner-relaunch journal is unsafe.")
    return path


def _intent_path(root: Path, *, create: bool) -> Path:
    return _directory(root, create=create) / (_CORRELATION + ".json")


def _read_intent(root: Path) -> dict[str, Any] | None:
    try:
        path = _intent_path(root, create=False)
    except FileNotFoundError:
        return None
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 4096:
            raise WindowsMsiOwnerRelaunchError("Owner-relaunch intent is unsafe.")
        raw = stream.read()
    try:
        value = json.loads(raw)
    except (TypeError, ValueError) as error:
        raise WindowsMsiOwnerRelaunchError("Owner-relaunch intent is invalid.") from error
    required = {"version", "correlationId", "sourceSha", "guestGeneration", "staleRecoveryEvidenceSha256", "state"}
    if (not isinstance(value, dict) or set(value) != required or value.get("version") != 1
            or value.get("correlationId") != _CORRELATION or value.get("sourceSha") != _SOURCE
            or value.get("state") not in {"intent", "launched"} or not _SHA256.fullmatch(str(value.get("staleRecoveryEvidenceSha256", "")))):
        raise WindowsMsiOwnerRelaunchError("Owner-relaunch intent is invalid.")
    return value


def _write_intent(root: Path, value: Mapping[str, Any]) -> None:
    directory = _directory(root, create=True)
    path = _intent_path(root, create=True)
    lock = os.open(directory / ".environment.lock", os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if _read_intent(root) is not None:
            raise WindowsMsiOwnerRelaunchError("Owner-relaunch intent already exists.")
        data = (json.dumps(dict(value), sort_keys=True, separators=(",", ":")) + "\n").encode()
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data); stream.flush(); os.fsync(stream.fileno())
        parent = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)); os.fsync(parent); os.close(parent)
    finally:
        os.close(lock)


def _finish_intent(root: Path, value: Mapping[str, Any]) -> None:
    directory = _directory(root, create=True); path = _intent_path(root, create=True); temporary: Path | None = None
    lock = os.open(directory / ".environment.lock", os.O_RDWR | getattr(os, "O_NOFOLLOW", 0))
    try:
        fcntl.flock(lock, fcntl.LOCK_EX)
        current = _read_intent(root)
        if current is None or current.get("state") != "intent":
            raise WindowsMsiOwnerRelaunchError("Owner-relaunch intent changed.")
        temporary = path.with_suffix(".tmp")
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write((json.dumps(dict(value), sort_keys=True, separators=(",", ":")) + "\n").encode())
            stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, path)
        parent = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)); os.fsync(parent); os.close(parent)
    finally:
        if temporary is not None:
            try: temporary.unlink()
            except FileNotFoundError: pass
        os.close(lock)


def _admit(root: Path) -> tuple[Any, tuple[str, str, int, int, str], str, str] | None:
    """Bind relaunch to armed c32 history and the separate recovered receipt."""
    admitted = liveness._admit(root)
    if admitted is None:
        return None
    config, descriptor, source, cli_hash = admitted
    if source != _SOURCE or not _SHA256.fullmatch(cli_hash):
        return None
    old = stale_lock._read_intent(root)
    if not isinstance(old, dict) or old.get("state") != "intent" or old.get("sourceSha") != _SOURCE:
        return None
    recovery = stale_reconcile._read(root)
    if not isinstance(recovery, dict) or recovery.get("state") != "recovered" or recovery.get("sourceSha") != _SOURCE:
        return None
    _env, socket, pid, ticks, _sid = descriptor
    expected_generation = {"socketPath": socket, "qemuPid": pid, "startTicks": ticks}
    expected_evidence = hashlib.sha256(json.dumps(expected_generation, sort_keys=True).encode()).hexdigest()
    if (not stale_lock._matches_current(old, descriptor)
            or not stale_reconcile._matches(recovery, descriptor)
            or recovery.get("guestGeneration") != expected_generation
            or recovery.get("evidenceSha256") != expected_evidence):
        return None
    return config, descriptor, cli_hash, expected_evidence


def _run(config: Any, descriptor: tuple[str, str, int, int, str], cli_hash: str, mode: str) -> dict[str, Any]:
    _env, socket, pid, ticks, sid = descriptor
    raw = base._remote(config, _REMOTE, (socket, str(pid), str(ticks), sid, cli_hash, mode), None, 90)
    try:
        value = json.loads(raw) if raw is not None else {}
    except (TypeError, ValueError):
        return {"state": "unknown"}
    if not isinstance(value, dict) or value.get("version") != 1 or value.get("state") not in {"launched", "unknown"}:
        return {"state": "unknown"}
    return value


def _diagnostic(config: Any, descriptor: tuple[str, str, int, int, str], cli_hash: str) -> dict[str, Any] | None:
    """Read the bounded guest diagnosis without starting or stopping anything."""
    _env, socket, pid, ticks, sid = descriptor
    raw = base._remote(config, _REMOTE, (socket, str(pid), str(ticks), sid, cli_hash, "diagnose"), None, 90)
    try:
        value = json.loads(raw) if raw is not None else {}
    except (TypeError, ValueError):
        return None
    fields = {"version", "phase", "task", "owners", "endpoint"}
    if (not isinstance(value, dict) or set(value) != fields or value.get("version") != 1
            or value.get("phase") not in _DIAGNOSTIC_PHASES or value.get("task") not in _TASK_STATES
            or value.get("owners") not in _OWNER_STATES or value.get("endpoint") not in _ENDPOINT_STATES):
        return None
    return {key: value[key] for key in ("phase", "task", "owners", "endpoint")}


def _detail(config: Any, descriptor: tuple[str, str, int, int, str], cli_hash: str) -> dict[str, Any] | None:
    _env, socket, pid, ticks, sid = descriptor
    raw = base._remote(config, _REMOTE, (socket, str(pid), str(ticks), sid, cli_hash, "detail"), None, 90)
    try:
        value = json.loads(raw) if raw is not None else {}
    except (TypeError, ValueError):
        return None
    fields = {"version", "baseOwners", "quotedStateServe", "unquotedStateServe", "otherSubcommand", "unrelated",
              "ownerIdentity", "endpoint", "schemaVersion", "controllerId", "port", "token"}
    count_keys = ("baseOwners", "quotedStateServe", "unquotedStateServe", "otherSubcommand", "unrelated")
    field_keys = ("schemaVersion", "controllerId", "port", "token")
    if (not isinstance(value, dict) or set(value) != fields or value.get("version") != 1
            or any(value.get(key) not in _DETAIL_COUNTS for key in count_keys)
            or value.get("ownerIdentity") not in _DETAIL_IDENTITY or value.get("endpoint") not in _DETAIL_LEAF
            or any(value.get(key) not in _DETAIL_FIELD for key in field_keys)):
        return None
    return {key: value[key] for key in fields - {"version"}}


def _endpoint_access(config: Any, descriptor: tuple[str, str, int, int, str], cli_hash: str) -> str | None:
    _env, socket, pid, ticks, sid = descriptor
    raw = base._remote(config, _REMOTE, (socket, str(pid), str(ticks), sid, cli_hash, "endpoint-access"), None, 90)
    try:
        value = json.loads(raw) if raw is not None else {}
    except (TypeError, ValueError):
        return None
    if not isinstance(value, dict) or set(value) != {"version", "endpoint"} or value.get("version") != 1:
        return None
    return value["endpoint"] if value.get("endpoint") in _ENDPOINT_ACCESS else None


def _result(value: Mapping[str, Any], state: str) -> dict[str, Any]:
    if (state != "launched" or set(value) != {"version", "state", "cliSha256", "ownerPid", "sessionId", "runtimeRunning"}
            or value.get("version") != 1 or value.get("state") != "launched"
            or not _SHA256.fullmatch(str(value.get("cliSha256", "")))
            or type(value.get("ownerPid")) is not int or value["ownerPid"] <= 0
            or value.get("sessionId") != 1 or value.get("runtimeRunning") is not False):
        return dict(_UNKNOWN)
    return {"state": "launched", "sourceSha": _SOURCE, "correlationId": _CORRELATION,
            "installedCliSha256": value["cliSha256"], "ownerPid": value["ownerPid"],
            "sessionId": 1, "runtimeRunning": False,
            "replayAllowed": False, "nativeActionAllowed": False}


def launch(root: Path | str, inputs: Mapping[str, Any]) -> dict[str, Any]:
    """Launch exactly once after fresh absence evidence; unknown effects stay armed."""
    if not isinstance(inputs, Mapping) or dict(inputs) != {"host": "archlinux"}:
        raise WindowsMsiOwnerRelaunchError("Exact CP117 host is required.")
    try:
        root = Path(root).resolve(strict=True); admitted = _admit(root)
        terminal = {"state": "terminal-proven", "replayAllowed": False, "nativeActionAllowed": False}
        if (admitted is None or stale_reconcile.status(root, {"host": "archlinux"}) != terminal
                or liveness.observe(root, {"host": "archlinux"}).get("state") != "absent"):
            return dict(_UNKNOWN)
        current = _read_intent(root)
        if current is not None:
            return dict(_UNKNOWN) if current["state"] == "intent" else status(root, inputs)
        config, descriptor, cli_hash, stale_evidence = admitted
        _env, socket, pid, ticks, _sid = descriptor
        record = {"version": 1, "correlationId": _CORRELATION, "sourceSha": _SOURCE,
                  "guestGeneration": {"socketPath": socket, "qemuPid": pid, "startTicks": ticks},
                  "staleRecoveryEvidenceSha256": stale_evidence, "state": "intent"}
        _write_intent(root, record)
        result = _run(config, descriptor, cli_hash, "launch")
        if result.get("state") != "launched":
            return dict(_UNKNOWN)
        record["state"] = "launched"; _finish_intent(root, record)
        return _result(result, "launched")
    except (OSError, ValueError, TypeError, KeyError, base.WindowsMsiBasePrepareError,
            WindowsMsiOwnerRelaunchError, stale_lock.WindowsMsiStaleLockRecoveryError,
            stale_reconcile.WindowsMsiStaleLockReconcileError):
        return dict(_UNKNOWN)


def status(root: Path | str, inputs: Mapping[str, Any]) -> dict[str, Any]:
    """Read-only proof for a completed or response-lost owner relaunch."""
    if not isinstance(inputs, Mapping) or dict(inputs) != {"host": "archlinux"}:
        raise WindowsMsiOwnerRelaunchError("Exact CP117 host is required.")
    try:
        root = Path(root).resolve(strict=True); admitted = _admit(root); current = _read_intent(root)
        if admitted is None or current is None:
            return dict(_UNKNOWN)
        config, descriptor, cli_hash, evidence = admitted
        _env, socket, pid, ticks, _sid = descriptor
        generation = {"socketPath": socket, "qemuPid": pid, "startTicks": ticks}
        if current.get("guestGeneration") != generation or current.get("staleRecoveryEvidenceSha256") != evidence:
            return dict(_UNKNOWN)
        return _result(_run(config, descriptor, cli_hash, "status"), "launched")
    except (OSError, ValueError, TypeError, KeyError, base.WindowsMsiBasePrepareError,
            WindowsMsiOwnerRelaunchError, stale_lock.WindowsMsiStaleLockRecoveryError,
            stale_reconcile.WindowsMsiStaleLockReconcileError):
        return dict(_UNKNOWN)


def collect(root: Path | str, inputs: Mapping[str, Any]) -> dict[str, Any]:
    """Alias for the read-only status collector used after a lost response."""
    return status(root, inputs)


def diagnose(root: Path | str, inputs: Mapping[str, Any]) -> dict[str, Any]:
    """Bounded read-only diagnosis for the non-replayable armed launch intent."""
    if not isinstance(inputs, Mapping) or dict(inputs) != {"host": "archlinux"}:
        raise WindowsMsiOwnerRelaunchError("Exact CP117 host is required.")
    try:
        root = Path(root).resolve(strict=True); admitted = _admit(root); current = _read_intent(root)
        if admitted is None or current is None or current.get("state") != "intent":
            return dict(_UNKNOWN)
        config, descriptor, cli_hash, evidence = admitted
        _env, socket, pid, ticks, _sid = descriptor
        if (current.get("guestGeneration") != {"socketPath": socket, "qemuPid": pid, "startTicks": ticks}
                or current.get("staleRecoveryEvidenceSha256") != evidence):
            return dict(_UNKNOWN)
        diagnostic = _diagnostic(config, descriptor, cli_hash)
        if diagnostic is None:
            return dict(_UNKNOWN)
        return {"state": "diagnosed", **diagnostic, "replayAllowed": False, "nativeActionAllowed": False}
    except (OSError, ValueError, TypeError, KeyError, base.WindowsMsiBasePrepareError,
            WindowsMsiOwnerRelaunchError, stale_lock.WindowsMsiStaleLockRecoveryError,
            stale_reconcile.WindowsMsiStaleLockReconcileError):
        return dict(_UNKNOWN)


def detail(root: Path | str, inputs: Mapping[str, Any]) -> dict[str, Any]:
    """Read only fixed command-shape and endpoint-schema categories."""
    if not isinstance(inputs, Mapping) or dict(inputs) != {"host": "archlinux"}:
        raise WindowsMsiOwnerRelaunchError("Exact CP117 host is required.")
    try:
        root = Path(root).resolve(strict=True); admitted = _admit(root); current = _read_intent(root)
        if admitted is None or current is None or current.get("state") != "intent":
            return dict(_UNKNOWN)
        config, descriptor, cli_hash, evidence = admitted
        _env, socket, pid, ticks, _sid = descriptor
        if (current.get("guestGeneration") != {"socketPath": socket, "qemuPid": pid, "startTicks": ticks}
                or current.get("staleRecoveryEvidenceSha256") != evidence):
            return dict(_UNKNOWN)
        observed = _detail(config, descriptor, cli_hash)
        if observed is None:
            return dict(_UNKNOWN)
        return {"state": "detailed", **observed, "replayAllowed": False, "nativeActionAllowed": False}
    except (OSError, ValueError, TypeError, KeyError, base.WindowsMsiBasePrepareError,
            WindowsMsiOwnerRelaunchError, stale_lock.WindowsMsiStaleLockRecoveryError,
            stale_reconcile.WindowsMsiStaleLockReconcileError):
        return dict(_UNKNOWN)


def endpoint_access(root: Path | str, inputs: Mapping[str, Any]) -> dict[str, Any]:
    """Distinguish private-endpoint ACL denial from bounded content failures."""
    if not isinstance(inputs, Mapping) or dict(inputs) != {"host": "archlinux"}:
        raise WindowsMsiOwnerRelaunchError("Exact CP117 host is required.")
    try:
        root = Path(root).resolve(strict=True); admitted = _admit(root); current = _read_intent(root)
        if admitted is None or current is None or current.get("state") != "intent":
            return dict(_UNKNOWN)
        config, descriptor, cli_hash, evidence = admitted
        _env, socket, pid, ticks, _sid = descriptor
        if (current.get("guestGeneration") != {"socketPath": socket, "qemuPid": pid, "startTicks": ticks}
                or current.get("staleRecoveryEvidenceSha256") != evidence):
            return dict(_UNKNOWN)
        observed = _endpoint_access(config, descriptor, cli_hash)
        if observed is None:
            return dict(_UNKNOWN)
        return {"state": "endpoint-access", "endpoint": observed, "replayAllowed": False, "nativeActionAllowed": False}
    except (OSError, ValueError, TypeError, KeyError, base.WindowsMsiBasePrepareError,
            WindowsMsiOwnerRelaunchError, stale_lock.WindowsMsiStaleLockRecoveryError,
            stale_reconcile.WindowsMsiStaleLockReconcileError):
        return dict(_UNKNOWN)


def workflow(root: Path | str, action: str, inputs: Mapping[str, Any]) -> dict[str, Any]:
    if action == "launch": return launch(root, inputs)
    if action == "status": return status(root, inputs)
    if action == "collect": return collect(root, inputs)
    if action == "diagnose": return diagnose(root, inputs)
    if action == "detail": return detail(root, inputs)
    if action == "endpoint-access": return endpoint_access(root, inputs)
    raise WindowsMsiOwnerRelaunchError("Unsupported owner-relaunch action.")
