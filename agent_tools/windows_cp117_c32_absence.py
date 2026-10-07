"""Fresh, read-only absence census for CP117's completed historical c32 base."""
from __future__ import annotations

import base64
import gzip
import json
from pathlib import Path
from typing import Any, Mapping

from . import windows_msi_base_prepare as base
from . import windows_msi_http_transfer as transfer


_C32 = "c32cb108-4d48-407e-9153-40774559ba50"
_UNKNOWN = {"state": "unknown", "replayAllowed": False,
            "nativeActionAllowed": False, "productAction": False}
_FIELDS = {"baseTask", "transferTask", "guestLeaf", "baseMsi", "correlationProcess"}
_VALUES = {"absent", "present", "ambiguous"}
_RESULT_FIELDS = {"version", "correlationId", "stage", "result", "exitCode", "originalSid",
                  "sessionId", "limited", "msiSha256", "installedVersion", "cliSha256",
                  "jarSha256", "helperSha256", "priorProducts", "installedProducts"}
_RETAINED_GUARDS = {"ready", "TASK", "TASK_COUNT", "TASK_STATE", "TASK_ACTION_COUNT", "TASK_EXEC",
                    "TASK_TRIGGER_NULL", "TASK_TRIGGER_COUNT", "TASK_INFO", "PRINCIPAL", "ACTION", "ROOT", "OWNER",
                    "TREE", "FILE", "RESULT_SIZE", "RESULT_READ", "RESULT_UTF8_BOM", "RESULT_UTF16_LE",
                    "RESULT_UTF16_BE", "RESULT_JSON", "runtime-error"}
_RETAINED_PHASES = {"binding", "script", "transport", "guest-exec", "guest-status", "running",
                    "terminal", "json-shape", "task", "task-info", "principal", "action", "root",
                    "owner", "tree", "file", "result"}


_REMOTE = base._QGA + r'''import base64,json,sys,time
sock,pid,ticks,encoded=sys.argv[1:]
def out(v):print(json.dumps(v,separators=(',',':'),sort_keys=True))
try:
 if not live(sock,pid,ticks):raise ValueError()
 child=call(sock,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',encoded],'capture-output':True})['pid']
 if type(child)is not int or child<=0:raise ValueError()
 for _ in range(80):
  item=call(sock,'guest-exec-status',{'pid':child})
  if item.get('exited') is True:break
  if item.get('exited') is not False:raise ValueError()
  time.sleep(.25)
 else:raise ValueError()
 if (set(item)-{'exited','exitcode','out-data','err-data','out-truncated','err-truncated'}
  or type(item.get('exitcode')) is not int or item['exitcode']!=0
  or item.get('out-truncated',False) is not False or item.get('err-truncated',False) is not False):raise ValueError()
 raw=base64.b64decode(item.get('out-data',''),validate=True)
 if not 0<len(raw)<=1024:raise ValueError()
 value=json.loads(decode(raw))
 if not isinstance(value,dict) or set(value)!={'baseTask','transferTask','guestLeaf','baseMsi','correlationProcess'} or any(v not in {'absent','present','ambiguous'} for v in value.values()):raise ValueError()
 out({'state':'observed','receipt':value})
except Exception:out({'state':'unknown'})
'''

_RETAINED_REMOTE = base._QGA + r'''import base64,json,sys,time
sock,pid,ticks,encoded=sys.argv[1:]
def out(v):print(json.dumps(v,separators=(',',':'),sort_keys=True))
try:
 if not live(sock,pid,ticks):raise ValueError()
 child=call(sock,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',encoded],'capture-output':True})['pid']
 if type(child)is not int or child<=0:raise ValueError()
 for _ in range(80):
  item=call(sock,'guest-exec-status',{'pid':child})
  if item.get('exited') is True:break
  if item.get('exited') is not False:raise ValueError()
  time.sleep(.25)
 else:raise ValueError()
 if (set(item)-{'exited','exitcode','out-data','err-data','out-truncated','err-truncated'} or type(item.get('exitcode')) is not int or item['exitcode']!=0 or item.get('out-truncated',False) is not False or item.get('err-truncated',False) is not False):raise ValueError()
 raw=base64.b64decode(item.get('out-data',''),validate=True)
 if not 0<len(raw)<=8192:raise ValueError()
 value=json.loads(decode(raw))
 if not isinstance(value,dict) or set(value)!={'result'} or not isinstance(value['result'],dict):raise ValueError()
 out({'state':'observed','receipt':value['result']})
except Exception:out({'state':'unknown'})
'''

_RETAINED_DIAG_REMOTE = base._QGA + r'''import base64,json,sys,time
sock,pid,ticks,encoded=sys.argv[1:]
def out(v):print(json.dumps(v,separators=(',',':'),sort_keys=True))
phase='guest-exec'
try:
 if not live(sock,pid,ticks):raise ValueError()
 child=call(sock,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',encoded],'capture-output':True})['pid']
 if type(child)is not int or child<=0:raise ValueError()
 phase='guest-status'
 for _ in range(80):
  item=call(sock,'guest-exec-status',{'pid':child})
  if item.get('exited') is True:break
  if item.get('exited') is not False:raise ValueError()
  time.sleep(.25)
 else:phase='running';raise ValueError()
 phase='terminal'
 if (set(item)-{'exited','exitcode','out-data','err-data','out-truncated','err-truncated'} or type(item.get('exitcode')) is not int or item['exitcode']!=0 or item.get('out-truncated',False) is not False or item.get('err-truncated',False) is not False):raise ValueError()
 raw=base64.b64decode(item.get('out-data',''),validate=True)
 if not 0<len(raw)<=256:raise ValueError()
 phase='json-shape'
 value=json.loads(decode(raw))
 if not isinstance(value,dict) or set(value)!={'guard','phase'} or value['guard'] not in {'ready','TASK','TASK_COUNT','TASK_STATE','TASK_ACTION_COUNT','TASK_EXEC','TASK_TRIGGER_NULL','TASK_TRIGGER_COUNT','TASK_INFO','PRINCIPAL','ACTION','ROOT','OWNER','TREE','FILE','RESULT_SIZE','RESULT_READ','RESULT_UTF8_BOM','RESULT_UTF16_LE','RESULT_UTF16_BE','RESULT_JSON','runtime-error'} or value['phase'] not in {'task','task-info','principal','action','root','owner','tree','file','result'}:raise ValueError()
 out({'state':'observed','guard':value['guard'],'phase':value['phase']})
except Exception:out({'state':'unknown','phase':phase})
'''

_RETAINED_PARSE_REMOTE = base._QGA + r'''import base64,json,sys,time
sock,pid,ticks,command=sys.argv[1:]
def out(v):print(json.dumps(v,separators=(',',':'),sort_keys=True))
try:
 if not live(sock,pid,ticks):raise ValueError()
 child=call(sock,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-Command',command],'capture-output':True})['pid']
 if type(child)is not int or child<=0:raise ValueError()
 for _ in range(80):
  item=call(sock,'guest-exec-status',{'pid':child})
  if item.get('exited') is True:break
  if item.get('exited') is not False:raise ValueError()
  time.sleep(.25)
 else:raise ValueError()
 if (set(item)-{'exited','exitcode','out-data','err-data','out-truncated','err-truncated'} or type(item.get('exitcode')) is not int or item['exitcode']!=0 or item.get('out-truncated',False) is not False or item.get('err-truncated',False) is not False):raise ValueError()
 raw=base64.b64decode(item.get('out-data',''),validate=True)
 if not 0<len(raw)<=128:raise ValueError()
 value=json.loads(decode(raw))
 if not isinstance(value,dict) or set(value)!={'strict','diagnostic'} or any(v not in {'passed','failed'} for v in value.values()):raise ValueError()
 out({'state':'observed','phase':'ast','strict':value['strict'],'diagnostic':value['diagnostic']})
except Exception:out({'state':'unknown','phase':'transport','strict':'failed','diagnostic':'failed'})
'''


def _admit(root: Path, target: Any, descriptor: tuple[Any, ...]) -> tuple[dict[str, Any], str] | None:
    """Bind only the fixed historical local intent, transfer record, and generation."""
    if (not isinstance(descriptor, tuple) or len(descriptor) != 5
            or descriptor[0] != "windows-cp117" or not all(isinstance(x, str) for x in (descriptor[1], descriptor[4]))
            or type(descriptor[2]) is not int or descriptor[2] <= 0
            or type(descriptor[3]) is not int or descriptor[3] <= 0
            or getattr(target, "fixture_transfer_root", None) is None):
        return None
    try:
        intent = base._private_intent(root, _C32)
        record = transfer._intent(root, _C32)
        if not isinstance(intent, Mapping) or not isinstance(record, Mapping):
            return None
        request = intent.get("request")
        if (not isinstance(request, Mapping) or intent.get("leaseId") != _C32
                or request.get("correlationId") != _C32
                or request.get("sourceSha") != record.get("sourceSha")
                or request.get("baseMsiArtifactId") != record.get("baseMsiArtifactId")
                or (intent.get("environment"), intent.get("socketPath"), intent.get("pid"), intent.get("startTicks"), intent.get("expectedSid")) != descriptor
                or (record.get("environment"), record.get("socketPath"), record.get("qemuPid"), record.get("startTicks"), record.get("expectedSid")) != descriptor):
            return None
        path = "/" + record["routeNonce"]
        marker = transfer._guest_dispatch_marker(root, record, path)
        if not isinstance(marker, Mapping):
            return None
        return dict(record), path
    except (OSError, ValueError, KeyError, TypeError, base.WindowsMsiBasePrepareError,
            transfer.WindowsMsiHttpTransferError):
        return None


def _script(correlation: str) -> str:
    """Emit a bounded absence-only census; all queried identifiers are fixed."""
    if correlation != _C32:
        raise ValueError("only the fixed c32 correlation may be observed")
    return r'''$ErrorActionPreference='Stop'
$corr='@CORR@';$base='VpnControlMcpBase-'+$corr;$transfer='VpnControlMcpTransfer-'+$corr
$leaf='C:\Users\vpncp117\AppData\Local\VpnControl\mcp-base-'+$corr;$msi=Join-Path $leaf 'base.msi'
function Classify([int]$count){if($count -eq 0){'absent'}elseif($count -eq 1){'present'}else{'ambiguous'}}
$all=@(Get-ScheduledTask -TaskPath '\' -ErrorAction Stop)
$baseTasks=@($all|Where-Object {$_.TaskName -ceq $base});$transferTasks=@($all|Where-Object {$_.TaskName -ceq $transfer})
$allProcesses=@(Get-CimInstance Win32_Process -ErrorAction Stop)
$processes=@($allProcesses|Where-Object {$null -ne $_.CommandLine -and $_.CommandLine -match [regex]::Escape($corr)})
$opaque=@($allProcesses|Where-Object {$_.Name -in @('powershell.exe','pwsh.exe','msiexec.exe') -and $null -eq $_.CommandLine})
$leafState=$(if(Test-Path -LiteralPath $leaf){'present'}else{'absent'});$msiState=$(if(Test-Path -LiteralPath $msi){'present'}else{'absent'})
$processState=$(if($processes.Count -gt 0){'present'}elseif($opaque.Count -gt 0){'ambiguous'}else{'absent'})
[Console]::Out.WriteLine(([ordered]@{baseTask=(Classify $baseTasks.Count);transferTask=(Classify $transferTasks.Count);guestLeaf=$leafState;baseMsi=$msiState;correlationProcess=$processState}|ConvertTo-Json -Compress))
'''.replace("@CORR@", correlation)


def observe(root: Path | str, config: Any, target: Any, descriptor: tuple[Any, ...]) -> dict[str, Any]:
    """Observe c32 only.  This never writes, unregisters, or starts guest work."""
    path = Path(root).resolve(strict=True)
    admitted = _admit(path, target, descriptor)
    if admitted is None:
        return dict(_UNKNOWN)
    record, _route_path = admitted
    try:
        encoded = base64.b64encode(_script(_C32).encode("utf-16le")).decode("ascii")
        raw = base._remote(config, _REMOTE, (record["socketPath"], str(record["qemuPid"]),
                                             str(record["startTicks"]), encoded), None, 30)
        value = json.loads(raw) if isinstance(raw, (str, bytes, bytearray)) else None
        receipt = value.get("receipt") if (isinstance(value, Mapping) and set(value) == {"state", "receipt"}
                                           and value.get("state") == "observed") else None
        if not isinstance(receipt, Mapping) or set(receipt) != _FIELDS or any(receipt.get(key) not in _VALUES for key in _FIELDS):
            return dict(_UNKNOWN)
        return {"state": "observed", **dict(receipt), "replayAllowed": False,
                "nativeActionAllowed": False, "productAction": False}
    except (OSError, ValueError, TypeError, KeyError, base.WindowsMsiBasePrepareError):
        return dict(_UNKNOWN)


def _ps(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _trigger_guard_powershell() -> str:
    """Accept only Scheduler's empty or single-null trigger representations."""
    return ("if($triggers.Count -ne 0 -and -not ($triggers.Count -eq 1 -and $null -eq $triggers[0]))"
            + "{throw 'TASK_TRIGGER_COUNT'}")


def _result_decode_powershell() -> str:
    """Decode JSON as strict UTF-8, accepting only the proven UTF-8 BOM prefix."""
    return ("$offset=0;if($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF)"
            + "{$offset=3};$utf8=[Text.UTF8Encoding]::new($false,$true);"
            + "$result=$utf8.GetString($bytes,$offset,$bytes.Length-$offset)|ConvertFrom-Json -ErrorAction Stop")


def _retained_script(intent: Mapping[str, Any], *, diagnostic: bool = False) -> str:
    """Read c32's preserved terminal receipt after exact task/leaf checks."""
    pair, request = intent["pair"], intent["request"]
    action = base._terminal_task_arguments_sha(_C32, intent)
    source = r'''$ErrorActionPreference='Stop'
$corr='@CORR@';$sid=@SID@;$expectedAction=@ACTION@;$root='C:\Users\vpncp117\AppData\Local\VpnControl\mcp-base-'+$corr;$taskName='VpnControlMcpBase-'+$corr
$phase='task';$tasks=@(Get-ScheduledTask -TaskPath '\' -TaskName $taskName -ErrorAction Stop);if($tasks.Count -ne 1){throw 'TASK_COUNT'};$task=$tasks[0];if($task.State.ToString() -cne 'Ready'){throw 'TASK_STATE'};$actions=@($task.Actions);if($actions.Count -ne 1){throw 'TASK_ACTION_COUNT'};if($actions[0].Execute -cne 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'){throw 'TASK_EXEC'};$triggers=@($task.Triggers);@TRIGGER_GUARD@
$phase='task-info';$info=Get-ScheduledTaskInfo -TaskPath '\' -TaskName $taskName -ErrorAction Stop;if($info.LastTaskResult -ne 0 -or $info.LastRunTime.Year -lt 2020){throw 'TASK_INFO'}
$phase='principal';$principal=$tasks[0].Principal;$principalSid=if($principal.UserId -match '^S-1-'){$principal.UserId}else{([Security.Principal.NTAccount]::new($principal.UserId)).Translate([Security.Principal.SecurityIdentifier]).Value};if($principalSid -cne $sid -or $principal.LogonType.ToString() -cne 'Interactive' -or $principal.RunLevel.ToString() -cne 'Limited'){throw 'PRINCIPAL'}
$phase='action';$hash=([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($actions[0].Arguments)))).Replace('-','').ToLowerInvariant();if($hash -cne $expectedAction){throw 'ACTION'}
$phase='root';foreach($node in @((Get-Item -LiteralPath $root -Force -ErrorAction Stop),((Get-Item -LiteralPath $root -Force -ErrorAction Stop).Parent),((Get-Item -LiteralPath $root -Force -ErrorAction Stop).Parent.Parent))){if(-not ($node -is [IO.DirectoryInfo]) -or ($node.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'ROOT'}}
$phase='owner';$rootOwner=([Security.Principal.NTAccount]::new((Get-Acl -LiteralPath $root).Owner)).Translate([Security.Principal.SecurityIdentifier]).Value;if($rootOwner -cne $sid){throw 'OWNER'}
$phase='tree';$nodes=@(Get-ChildItem -LiteralPath $root -Force -ErrorAction Stop);$names=@($nodes|ForEach-Object {$_.Name}|Sort-Object);if(($names -join "`n") -notin @('result.json',"base-msi.log`nresult.json")){throw 'TREE'}
$phase='file';foreach($node in $nodes){if($node.PSIsContainer -or ($node.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'FILE'};$owner=([Security.Principal.NTAccount]::new((Get-Acl -LiteralPath $node.FullName).Owner)).Translate([Security.Principal.SecurityIdentifier]).Value;if($owner -cne $sid){$phase='owner';throw 'OWNER'}}
$phase='result';$file=Join-Path $root 'result.json';$stream=[IO.File]::Open($file,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::None);try{if($stream.Length -lt 1 -or $stream.Length -gt 8192){throw 'RESULT_SIZE'};$bytes=New-Object byte[] ([int]$stream.Length);$offset=0;while($offset -lt $bytes.Length){$n=$stream.Read($bytes,$offset,$bytes.Length-$offset);if($n -le 0){throw 'RESULT_READ'};$offset+=$n};try{@RESULT_DECODE@}catch{throw 'RESULT_JSON'}}finally{$stream.Dispose()}
@OUTPUT@
'''.replace("@CORR@", _C32).replace("@SID@", _ps(intent["expectedSid"])).replace("@ACTION@", _ps(action)).replace("@TRIGGER_GUARD@", _trigger_guard_powershell()).replace("@RESULT_DECODE@", _result_decode_powershell())
    if not diagnostic:
        return source.replace("@OUTPUT@", "[Console]::Out.WriteLine((@{result=$result}|ConvertTo-Json -Depth 6 -Compress))")
    body = source.removeprefix("$ErrorActionPreference='Stop'\n").replace("@OUTPUT@", "[Console]::Out.WriteLine((@{guard='ready';phase=$phase}|ConvertTo-Json -Compress))")
    guards = ",".join(_ps(guard) for guard in sorted(_RETAINED_GUARDS - {"ready", "runtime-error"}))
    return ("$ErrorActionPreference='Stop';try{" + body
            + "}catch{$code=if($_.Exception.Message -cin @(" + guards
            + ")){$_.Exception.Message}else{'runtime-error'};[Console]::Out.WriteLine((@{guard=$code;phase=$phase}|ConvertTo-Json -Compress));exit 0}")


def _retained_parse_script(strict: str, diagnostic: str) -> str:
    """Parse prospective retained scripts only; neither script is invoked."""
    if not isinstance(strict, str) or not isinstance(diagnostic, str):
        raise ValueError("retained parser inputs must be source strings")
    pair = json.dumps({"strict": strict, "diagnostic": diagnostic}, separators=(",", ":")).encode("utf-8")
    packed = base64.b64encode(gzip.compress(pair, mtime=0)).decode("ascii")
    return ("$ErrorActionPreference='Stop';$z=[Convert]::FromBase64String('" + packed
            + "');$i=[IO.MemoryStream]::new([byte[]]$z);$g=[IO.Compression.GzipStream]::new($i,[IO.Compression.CompressionMode]::Decompress);"
            + "$o=[IO.MemoryStream]::new();try{$g.CopyTo($o);$pair=[Text.Encoding]::UTF8.GetString($o.ToArray())|ConvertFrom-Json -ErrorAction Stop}finally{$g.Dispose();$i.Dispose();$o.Dispose()};"
            + "if(@($pair.PSObject.Properties.Name).Count -ne 2 -or $null -eq $pair.strict -or $null -eq $pair.diagnostic){throw 'PAIR'};"
            + "$strict=[string]$pair.strict;$diagnostic=[string]$pair.diagnostic;function Parse-Only([string]$source){$tokens=$null;$errors=$null;"
            + "[System.Management.Automation.Language.Parser]::ParseInput($source,[ref]$tokens,[ref]$errors)|Out-Null;"
            + "if(@($errors).Count -eq 0){'passed'}else{'failed'}};[Console]::Out.WriteLine((@{strict=(Parse-Only $strict);"
            + "diagnostic=(Parse-Only $diagnostic)}|ConvertTo-Json -Compress))")


def parse_retained(root: Path | str, config: Any, target: Any, descriptor: tuple[Any, ...]) -> dict[str, Any]:
    """Parse both prospective c32 retained scripts in guest PowerShell without invoking them."""
    path = Path(root).resolve(strict=True)
    if _admit(path, target, descriptor) is None:
        return {"state": "unknown", "phase": "binding", "strict": "failed", "diagnostic": "failed"}
    try:
        intent = base._private_intent(path, _C32)
        if not isinstance(intent, Mapping):
            raise ValueError()
        script = _retained_parse_script(_retained_script(intent), _retained_script(intent, diagnostic=True))
        raw = base._remote(config, _RETAINED_PARSE_REMOTE,
                           (descriptor[1], str(descriptor[2]), str(descriptor[3]), script), None, 60)
        value = json.loads(raw) if isinstance(raw, (str, bytes, bytearray)) else None
        if (isinstance(value, Mapping) and set(value) == {"state", "phase", "strict", "diagnostic"}
                and value.get("state") == "observed" and value.get("phase") == "ast"
                and all(value.get(key) in {"passed", "failed"} for key in ("strict", "diagnostic"))):
            return dict(value)
    except (OSError, ValueError, TypeError, KeyError, base.WindowsMsiBasePrepareError):
        pass
    return {"state": "unknown", "phase": "transport", "strict": "failed", "diagnostic": "failed"}


def _valid_retained_payload(payload: Any, intent: Mapping[str, Any]) -> bool:
    """Validate the private receipt with the same exact product semantics as base."""
    try:
        request, pair = intent["request"], intent["pair"]
        return (isinstance(payload, Mapping) and set(payload) == _RESULT_FIELDS
                and payload.get("version") == 1 and payload.get("correlationId") == _C32
                and payload.get("stage") == "READBACK" and payload.get("result") == "PASSED"
                and type(payload.get("exitCode")) is int and payload["exitCode"] == 0
                and payload.get("originalSid") == intent["expectedSid"] and payload.get("sessionId") == 1
                and payload.get("limited") is True
                and payload.get("msiSha256") == request["baseMsiArtifactId"].removeprefix("sha256-")
                and payload.get("installedVersion") == pair["baseVersion"]
                and payload.get("cliSha256") == pair["baseCliSha256"]
                and payload.get("jarSha256") == pair["baseAppJarSha256"]
                and payload.get("helperSha256") == pair["baseHelperSha256"]
                and base._unique_product(payload.get("priorProducts"), request["expectedCurrentVersion"])
                and base._unique_product(payload.get("installedProducts"), pair["baseVersion"]))
    except (KeyError, TypeError, ValueError, base.WindowsMsiBasePrepareError):
        return False


def _retained_parse_passed(root: Path, config: Any, target: Any, descriptor: tuple[Any, ...]) -> bool:
    result = parse_retained(root, config, target, descriptor)
    return (result.get("state") == "observed" and result.get("phase") == "ast"
            and result.get("strict") == "passed" and result.get("diagnostic") == "passed")


def retained_terminal(root: Path | str, config: Any, target: Any, descriptor: tuple[Any, ...]) -> dict[str, Any]:
    """Confirm retained c32 terminal evidence without checking current package artifacts."""
    path = Path(root).resolve(strict=True)
    if not _retained_parse_passed(path, config, target, descriptor):
        return dict(_UNKNOWN)
    try:
        intent = base._private_intent(path, _C32)
        if not isinstance(intent, Mapping):
            return dict(_UNKNOWN)
        encoded = base64.b64encode(_retained_script(intent).encode("utf-16le")).decode("ascii")
        raw = base._remote(config, _RETAINED_REMOTE, (descriptor[1], str(descriptor[2]), str(descriptor[3]), encoded), None, 60)
        value = json.loads(raw) if isinstance(raw, (str, bytes, bytearray)) else None
        payload = value.get("receipt") if isinstance(value, Mapping) and set(value) == {"state", "receipt"} and value.get("state") == "observed" else None
        if not _valid_retained_payload(payload, intent):
            return dict(_UNKNOWN)
        return {"state": "retained-terminal", "replayAllowed": False,
                "nativeActionAllowed": False, "productAction": False}
    except (OSError, ValueError, TypeError, KeyError, base.WindowsMsiBasePrepareError):
        return dict(_UNKNOWN)


def diagnose_retained(root: Path | str, config: Any, target: Any, descriptor: tuple[Any, ...]) -> dict[str, Any]:
    """Classify retained c32 verifier failure without exposing task or receipt data."""
    path = Path(root).resolve(strict=True)
    if _admit(path, target, descriptor) is None:
        return {**_UNKNOWN, "state": "diagnosed", "guard": "runtime-error", "phase": "binding"}
    if not _retained_parse_passed(path, config, target, descriptor):
        return {**_UNKNOWN, "state": "diagnosed", "guard": "runtime-error", "phase": "script"}
    try:
        intent = base._private_intent(path, _C32)
        if not isinstance(intent, Mapping):
            raise ValueError()
        try:
            script = _retained_script(intent, diagnostic=True)
        except (KeyError, TypeError, ValueError, base.WindowsMsiBasePrepareError):
            return {**_UNKNOWN, "state": "diagnosed", "guard": "runtime-error", "phase": "script"}
        encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
        raw = base._remote(config, _RETAINED_DIAG_REMOTE, (descriptor[1], str(descriptor[2]), str(descriptor[3]), encoded), None, 60)
        value = json.loads(raw) if isinstance(raw, (str, bytes, bytearray)) else None
        if (isinstance(value, Mapping) and set(value) == {"state", "guard", "phase"} and value.get("state") == "observed"
                and value.get("guard") in _RETAINED_GUARDS and value.get("phase") in _RETAINED_PHASES):
            return {**_UNKNOWN, "state": "diagnosed", "guard": value["guard"], "phase": value["phase"]}
        if (isinstance(value, Mapping) and set(value) == {"state", "phase"} and value.get("state") == "unknown"
                and value.get("phase") in _RETAINED_PHASES):
            return {**_UNKNOWN, "state": "diagnosed", "guard": "runtime-error", "phase": value["phase"]}
    except (OSError, ValueError, TypeError, KeyError, base.WindowsMsiBasePrepareError):
        pass
    return {**_UNKNOWN, "state": "diagnosed", "guard": "runtime-error", "phase": "transport"}


def _post_retirement_leaf_script(intent: Mapping[str, Any]) -> str:
    """Reuse the retained receipt verifier after the task has been retired.

    The prefix is intentionally rebuilt without a scheduled-task query.  The
    tail begins with the original exact ACL/tree/result verifier, so this does
    not turn task absence into a receipt claim.
    """
    strict = _retained_script(intent)
    marker = "$phase='root';"
    try:
        tail = strict[strict.index(marker):]
    except ValueError as error:  # source construction drift must fail closed
        raise ValueError("retained receipt verifier has no root guard") from error
    return ("$ErrorActionPreference='Stop'\n$corr=" + _ps(_C32)
            + ";$sid=" + _ps(intent["expectedSid"])
            + ";$root='C:\\Users\\vpncp117\\AppData\\Local\\VpnControl\\mcp-base-'+$corr\n" + tail)


def post_retirement_terminal(root: Path | str, config: Any, target: Any,
                              descriptor: tuple[Any, ...]) -> dict[str, Any]:
    """Require the fixed retirement terminal and the original protected leaf.

    This is deliberately a separate proof from ``retained_terminal``: it only
    applies when the exact c32 task is absent and its original result leaf is
    still present.  It never treats absence alone as completion.
    """
    path = Path(root).resolve(strict=True)
    admitted = _admit(path, target, descriptor)
    if admitted is None:
        return dict(_UNKNOWN)
    census = observe(path, config, target, descriptor)
    if not (census.get("state") == "observed" and census.get("baseTask") == "absent"
            and census.get("guestLeaf") == "present"
            and all(census.get(key) == "absent" for key in ("transferTask", "baseMsi", "correlationProcess"))):
        return dict(_UNKNOWN)
    # Import here to avoid a module cycle; retirement remains the authoritative
    # protected journal, task-absence, generation and lease observer.
    try:
        from . import windows_cp117_c32_retained_task_retire as retire
        retired = retire.status(path, {})
        if (retired.get("state") != "terminal" or retired.get("retirementCorrelationId") != retire._RETIREMENT
                or retired.get("task") != "VpnControlMcpBase-" + _C32):
            return dict(_UNKNOWN)
        intent = base._private_intent(path, _C32)
        if not isinstance(intent, Mapping):
            return dict(_UNKNOWN)
        source = _post_retirement_leaf_script(intent)
        parsed = _retained_parse_script(source, source)
        raw = base._remote(config, _RETAINED_PARSE_REMOTE,
                           (descriptor[1], str(descriptor[2]), str(descriptor[3]), parsed), None, 60)
        parsed_value = json.loads(raw) if isinstance(raw, (str, bytes, bytearray)) else None
        if not (isinstance(parsed_value, Mapping) and set(parsed_value) == {"state", "phase", "strict", "diagnostic"}
                and parsed_value.get("state") == "observed" and parsed_value.get("phase") == "ast"
                and parsed_value.get("strict") == "passed" and parsed_value.get("diagnostic") == "passed"):
            return dict(_UNKNOWN)
        encoded = base64.b64encode(source.encode("utf-16le")).decode("ascii")
        if len(encoded) >= 30000:
            return dict(_UNKNOWN)
        raw = base._remote(config, _RETAINED_REMOTE,
                           (descriptor[1], str(descriptor[2]), str(descriptor[3]), encoded), None, 60)
        value = json.loads(raw) if isinstance(raw, (str, bytes, bytearray)) else None
        payload = value.get("receipt") if isinstance(value, Mapping) and set(value) == {"state", "receipt"} and value.get("state") == "observed" else None
        if not _valid_retained_payload(payload, intent):
            return dict(_UNKNOWN)
        # The c32 retirement observer itself rechecks generation and lease. A
        # second call makes a later changed terminal journal fail closed.
        if retire.status(path, {}) != retired:
            return dict(_UNKNOWN)
        return {"state": "post-retirement-terminal", "replayAllowed": False,
                "nativeActionAllowed": False, "productAction": False}
    except (OSError, ValueError, TypeError, KeyError, base.WindowsMsiBasePrepareError):
        return dict(_UNKNOWN)
