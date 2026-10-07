"""One-shot retirement of five fixed, terminal CP95 tasks; no product actions.

Original journals and installers are never modified. An intent is consumed before
submission, and only a protected terminal plus fresh absence can prove retirement.
"""
from __future__ import annotations

import base64
import gzip
import hashlib
import io
import json
import os
import stat
import zlib
from pathlib import Path
from typing import Any, Mapping

from . import windows_cp117_cp95_retained_tasks as retained
from . import windows_cp117_guest_agent_recovery as transport
from . import windows_cp117_lease as lease
from . import windows_cp117_protected_journal as journal
from . import windows_cp117_retirement_guards as guards
from . import windows_msi_base_prepare as base


class WindowsCp117Cp95TaskRetireError(ValueError):
    pass


_RETIREMENT = "9a5d3d6a-5f43-4a3f-9e4e-f90b9cc86e86"
_TAIL = "60c5d5da-1d80-492b-90b5-7a4a9ad48b34"
_SUCCESSOR = "7cc61627-2881-4cc3-887d-a5bf545ed2ca"
_FRESH = "f31ec89e-bbf2-4c13-b277-23c21b794a31"
_DIR = ".rag_index/windows-cp117-cp95-task-retirement"
_TAIL_DIR = ".rag_index/windows-cp117-cp95-task-retirement-tail"
_SUCCESSOR_DIR = ".rag_index/windows-cp117-cp95-task-retirement-successor"
_CLOSURE_DIR = ".rag_index/windows-cp117-cp95-task-retirement-tail-closure"
_SUCCESSOR_CLOSURE_DIR = ".rag_index/windows-cp117-cp95-task-retirement-successor-closure"
_FRESH_DIR = ".rag_index/windows-cp117-cp95-task-retirement-fresh"
_ROOT = r"C:\ProgramData\VpnControlCp117-retirement-" + _RETIREMENT
_TAIL_ROOT = r"C:\ProgramData\VpnControlCp117-retirement-" + _TAIL
_SUCCESSOR_ROOT = r"C:\ProgramData\VpnControlCp117-retirement-" + _SUCCESSOR
_FRESH_ROOT = r"C:\ProgramData\VpnControlCp117-retirement-" + _FRESH
_LEAVES = ("binding.json",) + tuple("archive-" + p + ".json" for p in retained._PROFILE_NAMES) + ("terminal.json",)
_TAIL_LEAVES = ("binding.json", "terminal.json")
_RESULTS = ("succeeded", "failed", "failed", "succeeded", "succeeded")
_DIAGNOSTIC_PHASES = {"lease", "generation", "guest-exit", "guest-truncated", "guest-output-encoding", "guest-output-size", "guest-output-json", "wire-size", "wire-envelope", "archive-fields", "task", "action", "triggers", "task-binding", "terminal", "running", "xml-size", "process", "exists", "unrecognized-guard"}
_PHASES = {"input", "platform", "intent", "active-lease", "descriptor", "proof", "snapshot", "generation", "parser", "dispatch", "journal", "terminal", "absence", "complete", "configured-specs", "retained-proof", "snapshot-parser", "snapshot-output", "mutation-parser", "reader-parser", "finish-parser", "finish-proof", "finish-dispatch"} | {"snapshot-output-" + p for p in _DIAGNOSTIC_PHASES}
_JOURNAL_DIAGNOSTIC_PHASES = frozenset({"intent", "descriptor", "generation", "remote-stage", "remote-file", "remote-encoding", "remote-decoder", "archive", "terminal", "complete"})
_JOURNAL_FILE_PHASES = frozenset({"root-absent", "root-unsafe", "binding-absent", "archive-absent", "terminal-absent", "file-unsafe", "access", "readable"})
_FINISH_DIAGNOSTIC_PHASES = frozenset({"process", "binding", "archive", "task-query", "task-present-1", "task-present-2", "task-present-3", "task-present-4", "task-present-5", "root", "terminal", "ready", "unknown"})
_PHASES |= {"parent-intent", "child-intent-absent", "child-intent", "remote-file", "unknown", "tail-local-intent"}
_PHASES |= {"tail-closure-parser", "tail-closure-proof", "tail-closure-marker", "tail-closure-complete"}
_PHASES |= {"successor-closure-parser", "successor-closure-proof", "successor-closure-marker", "successor-closure-complete"}
_SUCCESSOR_DIAG_STAGES = {"parent", "descriptor", "specs", "closure", "old-child", "successor-child", "lease", "tailplan", "intentfs", "parser", "fresh", "ready"}
_PHASES |= _SUCCESSOR_DIAG_STAGES | {stage + "-" + kind for stage in _SUCCESSOR_DIAG_STAGES for kind in {"oserror", "valueerror", "typeerror", "keyerror", "indexerror"}}
_PHASES |= {"remote-file-" + phase for phase in _JOURNAL_FILE_PHASES}


def _result(state: str, phase: str) -> dict[str, Any]:
    assert phase in _PHASES
    return {"state": state, "phase": phase, "retirementCorrelationId": _RETIREMENT,
            "replayAllowed": False, "nativeActionAllowed": False, "productAction": False}


def _tail_result(state: str, phase: str) -> dict[str, Any]:
    value = _result(state, phase)
    value["tailCorrelationId"] = _TAIL
    return value


def _successor_result(state: str, phase: str) -> dict[str, Any]:
    value = _result(state, phase)
    value["tailCorrelationId"] = _SUCCESSOR
    return value


def _fresh_result(state: str, phase: str) -> dict[str, Any]:
    value = _result(state, phase)
    value["tailCorrelationId"] = _FRESH
    return value


def _digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _binding(descriptor: tuple[Any, ...], snapshots: list[dict[str, Any]]) -> dict[str, Any]:
    return {"retirementCorrelationId": _RETIREMENT, "environment": descriptor[0],
            "socketPath": descriptor[1], "qemuPid": descriptor[2], "startTicks": descriptor[3],
            "sid": descriptor[4], "snapshots": snapshots}


def _validate_archive(item: Any, spec: Mapping[str, str], binding_sha: str | None = None) -> dict[str, Any]:
    fields = {"profile", "task", "actionSha256", "result", "taskResult", "lastRunTicks", "xmlSha256", "xmlLength", "xmlGzip"}
    if binding_sha is not None:
        fields.add("bindingSha256")
    if (not isinstance(item, Mapping) or set(item) != fields
            or any(item.get(k) != spec[k] for k in ("profile", "task", "actionSha256"))
            or item.get("result") != _RESULTS[retained._PROFILE_NAMES.index(spec["profile"])]
            or type(item.get("taskResult")) is not int or not 0 <= item["taskResult"] <= 4294967295
            or (item["taskResult"] == 0) != (item["result"] == "succeeded") or item["taskResult"] == 267009
            or type(item.get("lastRunTicks")) is not int or item["lastRunTicks"] <= 0
            or type(item.get("xmlLength")) is not int or not 1 <= item["xmlLength"] <= 131072
            or not isinstance(item.get("xmlSha256"), str) or not retained._HASH.fullmatch(item["xmlSha256"])
            or not isinstance(item.get("xmlGzip"), str) or len(item["xmlGzip"]) > 15000
            or (binding_sha is not None and item.get("bindingSha256") != binding_sha)
            or len(json.dumps(item, separators=(",", ":")).encode()) > 16384):
        raise WindowsCp117Cp95TaskRetireError("Archive binding is invalid.")
    try:
        packed = base64.b64decode(item["xmlGzip"], validate=True)
        with gzip.GzipFile(fileobj=io.BytesIO(packed)) as stream:
            raw = stream.read(131073)
            if len(raw) > 131072 or stream.read(1):
                raise ValueError()
        if len(raw) != item["xmlLength"] or hashlib.sha256(raw).hexdigest() != item["xmlSha256"]:
            raise ValueError()
        raw.decode("utf-8", errors="strict")
    except (OSError, ValueError, EOFError, UnicodeError) as error:
        raise WindowsCp117Cp95TaskRetireError("Archive XML is invalid.") from error
    return {k: item[k] for k in fields - {"xmlGzip", "bindingSha256"}}


# The coordinator lease lock is held throughout the guest operation. No remote
# directory/lock is created, and an active/opaque record blocks submission.
_REMOTE = base._QGA + r'''import fcntl,json,os,stat,sys,time,base64
root,env,sock,pid,ticks,encoded=sys.argv[1:]
def out(v):print(json.dumps(v,separators=(',',':')))
try:
 if env!='windows-cp117' or not live(sock,pid,ticks):raise ValueError()
 group=os.path.join(root,env,'windows-cp117-campaign')
 for p in (root,os.path.join(root,env),group):
  i=os.lstat(p)
  if not stat.S_ISDIR(i.st_mode) or stat.S_ISLNK(i.st_mode) or i.st_uid!=os.geteuid() or stat.S_IMODE(i.st_mode)!=0o700:raise ValueError()
 fd=os.open(os.path.join(group,'.environment.lock'),os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
 try:
  i=os.fstat(fd)
  if not stat.S_ISREG(i.st_mode) or i.st_uid!=os.geteuid() or stat.S_IMODE(i.st_mode)!=0o600:raise ValueError()
  fcntl.flock(fd,fcntl.LOCK_SH)
  if os.path.lexists(os.path.join(group,'active.json')):out({'state':'blocked','phase':'active-lease'});raise SystemExit()
  if not live(sock,pid,ticks):raise ValueError()
  child=call(sock,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',encoded],'capture-output':True})['pid']
  for _ in range(160):
   v=call(sock,'guest-exec-status',{'pid':child})
   if v.get('exited') is True:break
   if v.get('exited') is not False:raise ValueError()
   time.sleep(.25)
  else:raise ValueError()
  if not live(sock,pid,ticks):out({'state':'diagnostic','phase':'generation'});raise SystemExit()
  if os.path.lexists(os.path.join(group,'active.json')):out({'state':'diagnostic','phase':'lease'});raise SystemExit()
  if v.get('exitcode')!=0:out({'state':'diagnostic','phase':'guest-exit'});raise SystemExit()
  if v.get('out-truncated',False) or v.get('err-truncated',False):out({'state':'diagnostic','phase':'guest-truncated'});raise SystemExit()
  try:raw=base64.b64decode(v.get('out-data',''),validate=True)
  except Exception:out({'state':'diagnostic','phase':'guest-output-encoding'});raise SystemExit()
  if len(raw)>100000:out({'state':'diagnostic','phase':'guest-output-size','rawBytes':min(len(raw),100001)});raise SystemExit()
  try:receipt=json.loads(decode(raw))
  except Exception:out({'state':'diagnostic','phase':'guest-output-json'});raise SystemExit()
  import gzip,hashlib,zlib
  canonical=json.dumps(receipt,separators=(',',':'),sort_keys=True).encode()
  if len(canonical)>100000:out({'state':'diagnostic','phase':'guest-output-size','rawBytes':100001});raise SystemExit()
  # The five archive rows repeat nine field names.  Preserve the canonical
  # receipt hash, but carry a reversible column form over QGA so a complete
  # snapshot stays below the fixed 16 KiB stdout bound.
  fields=('profile','task','actionSha256','result','taskResult','lastRunTicks','xmlSha256','xmlLength','xmlGzip')
  compact=None;encoding='gzip-base64'
  if set(receipt)=={'archives'} and isinstance(receipt['archives'],list) and 1<=len(receipt['archives'])<=5 and all(isinstance(row,dict) and set(row)==set(fields) for row in receipt['archives']):
   compact={'v':1,'a':[[row[key] for key in fields] for row in receipt['archives']]}
   encoding='gzip-base85-archive-columns-v1'
  elif set(receipt)=={'binding','archives','terminal','absent'} and isinstance(receipt['binding'],dict) and isinstance(receipt['archives'],list):
   outer=receipt['binding'];inner=outer.get('binding');snapshot_fields=fields[:-1];archive_fields=fields+('bindingSha256',);binding_fields=('retirementCorrelationId','environment','socketPath','qemuPid','startTicks','sid');terminal_fields=('retirementCorrelationId','state','bindingSha256','actionSha256')
   if (set(outer)=={'binding','bindingSha256','actionSha256'} and isinstance(inner,dict) and set(inner)==set(binding_fields+('snapshots',)) and isinstance(inner['snapshots'],list) and len(inner['snapshots'])==5 and len(receipt['archives'])==5 and isinstance(receipt['terminal'],dict) and set(receipt['terminal'])==set(terminal_fields) and receipt['absent'] is True and all(isinstance(row,dict) and set(row)==set(snapshot_fields) for row in inner['snapshots']) and all(isinstance(row,dict) and set(row)==set(archive_fields) for row in receipt['archives'])):
    if not all(all(row[key]==inner['snapshots'][index][key] for key in snapshot_fields) and row['bindingSha256']==outer['bindingSha256'] for index,row in enumerate(receipt['archives'])):raise ValueError()
    compact={'v':4,'b':[inner[key] for key in binding_fields],'s':[[row[key] for key in snapshot_fields] for row in inner['snapshots']],'x':[row['xmlGzip'] for row in receipt['archives']],'i':[outer['bindingSha256'],outer['actionSha256']]}
    encoding='z85r4'
  wire_raw=json.dumps(compact if compact is not None else receipt,separators=(',',':'),sort_keys=True).encode()
  packed=(base64.b85encode(zlib.compress(wire_raw,9)).decode() if encoding=='z85r4' else (base64.b85encode(gzip.compress(wire_raw,mtime=0)).decode() if compact is not None else base64.b64encode(gzip.compress(wire_raw,mtime=0)).decode()))
  envelope={'state':'observed','encoding':encoding,'rawBytes':len(canonical),'rawSha256':hashlib.sha256(canonical).hexdigest(),'receiptGzip':packed}
  wire=json.dumps(envelope,separators=(',',':'))
  if len(wire.encode())+1>16384:out({'state':'diagnostic','phase':'wire-size','rawBytes':len(canonical),'wireBytes':min(len(wire.encode())+1,150000)});raise SystemExit()
  print(wire)
 finally:os.close(fd)
except Exception:out({'state':'unknown'})
'''


def _decode_observation(value: Any) -> Any:
    """Unpack a bounded response without changing the generic SSH stdout cap."""
    if not isinstance(value, dict):
        return {"_diagnostic": {"phase": "wire-envelope"}}
    if value == {"state": "blocked", "phase": "active-lease"}:
        return {"_diagnostic": {"phase": "lease"}}
    if value.get("state") == "diagnostic":
        if (set(value) <= {"state", "phase", "rawBytes", "wireBytes"}
                and isinstance(value.get("phase"), str) and value["phase"] in _DIAGNOSTIC_PHASES
                and all(type(value[k]) is int and 0 <= value[k] <= 150000 for k in ("rawBytes", "wireBytes") if k in value)):
            return {"_diagnostic": {k: v for k, v in value.items() if k != "state"}}
        return {"_diagnostic": {"phase": "wire-envelope"}}
    if (set(value) != {"state", "encoding", "rawBytes", "rawSha256", "receiptGzip"}
            or value.get("state") != "observed" or not isinstance(value.get("encoding"), str)
            or value["encoding"] not in {"gzip-base64", "gzip-base85-archive-columns-v1", "gzip-base85-reader-columns-v1", "gzip-base85-reader-columns-v2", "gzip-base85-reader-columns-v3", "z85r4"}
            or type(value.get("rawBytes")) is not int or not 1 <= value["rawBytes"] <= 100000
            or not isinstance(value.get("receiptGzip"), str)
            or not isinstance(value.get("rawSha256"), str) or not retained._HASH.fullmatch(value["rawSha256"])):
        return {"_diagnostic": {"phase": "wire-envelope"}}
    if len(value["receiptGzip"]) > 16384:
        return {"_diagnostic": {"phase": "wire-envelope"}}
    # Authoritative bound mirrors the remote writer.  The envelope shape, not
    # a stale per-codec payload estimate, controls accepted reader bytes.
    if len(json.dumps(value, separators=(",", ":")).encode()) + 1 > 16384:
        return {"_diagnostic": {"phase": "wire-envelope"}}
    try:
        packed = (base64.b85decode(value["receiptGzip"]) if value["encoding"] in {"gzip-base85-archive-columns-v1", "gzip-base85-reader-columns-v1", "gzip-base85-reader-columns-v2", "gzip-base85-reader-columns-v3", "z85r4"}
                  else base64.b64decode(value["receiptGzip"], validate=True))
        if value["encoding"] == "z85r4":
            inflater = zlib.decompressobj()
            raw = inflater.decompress(packed, 100001)
            if len(raw) > 100000 or inflater.unconsumed_tail or not inflater.eof or inflater.unused_data:
                raise ValueError()
        else:
            with gzip.GzipFile(fileobj=io.BytesIO(packed)) as stream:
                raw = stream.read(100001)
                if len(raw) > 100000 or stream.read(1):
                    raise ValueError()
        if value["encoding"] == "gzip-base85-archive-columns-v1":
            fields = ("profile", "task", "actionSha256", "result", "taskResult", "lastRunTicks", "xmlSha256", "xmlLength", "xmlGzip")
            compact = json.loads(raw)
            if (not isinstance(compact, dict) or set(compact) != {"v", "a"} or type(compact.get("v")) is not int or compact["v"] != 1
                    or not isinstance(compact.get("a"), list) or not 1 <= len(compact["a"]) <= 5
                    or any(not isinstance(row, list) or len(row) != len(fields) for row in compact["a"])):
                raise ValueError()
            receipt = {"archives": [dict(zip(fields, row)) for row in compact["a"]]}
            canonical = json.dumps(receipt, separators=(",", ":"), sort_keys=True).encode()
        elif value["encoding"] == "gzip-base85-reader-columns-v1":
            snapshot_fields = ("profile", "task", "actionSha256", "result", "taskResult", "lastRunTicks", "xmlSha256", "xmlLength")
            archive_fields = snapshot_fields + ("xmlGzip", "bindingSha256")
            binding_fields = ("retirementCorrelationId", "environment", "socketPath", "qemuPid", "startTicks", "sid")
            terminal_fields = ("retirementCorrelationId", "state", "bindingSha256", "actionSha256")
            compact = json.loads(raw)
            if (not isinstance(compact, dict) or set(compact) != {"v", "b", "s", "a", "i", "t", "z"}
                    or type(compact.get("v")) is not int or compact["v"] != 1 or compact.get("z") is not True
                    or not all(isinstance(compact.get(key), list) for key in ("b", "s", "a", "i", "t"))
                    or len(compact["b"]) != len(binding_fields) or len(compact["s"]) != 5 or len(compact["a"]) != 5
                    or len(compact["i"]) != 2 or len(compact["t"]) != len(terminal_fields)
                    or any(not isinstance(row, list) or len(row) != len(snapshot_fields) for row in compact["s"])
                    or any(not isinstance(row, list) or len(row) != len(archive_fields) for row in compact["a"])):
                raise ValueError()
            inner = {**dict(zip(binding_fields, compact["b"])), "snapshots": [dict(zip(snapshot_fields, row)) for row in compact["s"]]}
            receipt = {"binding": {"binding": inner, "bindingSha256": compact["i"][0], "actionSha256": compact["i"][1]},
                       "archives": [dict(zip(archive_fields, row)) for row in compact["a"]],
                       "terminal": dict(zip(terminal_fields, compact["t"])), "absent": True}
            canonical = json.dumps(receipt, separators=(",", ":"), sort_keys=True).encode()
        elif value["encoding"] == "gzip-base85-reader-columns-v2":
            snapshot_fields = ("profile", "task", "actionSha256", "result", "taskResult", "lastRunTicks", "xmlSha256", "xmlLength")
            binding_fields = ("retirementCorrelationId", "environment", "socketPath", "qemuPid", "startTicks", "sid")
            terminal_fields = ("retirementCorrelationId", "state", "bindingSha256", "actionSha256")
            compact = json.loads(raw)
            if (not isinstance(compact, dict) or set(compact) != {"v", "b", "s", "x", "i", "t", "z"}
                    or type(compact.get("v")) is not int or compact["v"] != 2 or compact.get("z") is not True
                    or not all(isinstance(compact.get(key), list) for key in ("b", "s", "x", "i", "t"))
                    or len(compact["b"]) != len(binding_fields) or len(compact["s"]) != 5 or len(compact["x"]) != 5
                    or len(compact["i"]) != 2 or len(compact["t"]) != len(terminal_fields)
                    or any(not isinstance(row, list) or len(row) != len(snapshot_fields) for row in compact["s"])):
                raise ValueError()
            inner = {**dict(zip(binding_fields, compact["b"])), "snapshots": [dict(zip(snapshot_fields, row)) for row in compact["s"]]}
            archives = [{**dict(zip(snapshot_fields, row)), "xmlGzip": compact["x"][index], "bindingSha256": compact["i"][0]}
                        for index, row in enumerate(compact["s"])]
            receipt = {"binding": {"binding": inner, "bindingSha256": compact["i"][0], "actionSha256": compact["i"][1]},
                       "archives": archives, "terminal": dict(zip(terminal_fields, compact["t"])), "absent": True}
            canonical = json.dumps(receipt, separators=(",", ":"), sort_keys=True).encode()
        elif value["encoding"] in {"gzip-base85-reader-columns-v3", "z85r4"}:
            snapshot_fields = ("profile", "task", "actionSha256", "result", "taskResult", "lastRunTicks", "xmlSha256", "xmlLength")
            binding_fields = ("retirementCorrelationId", "environment", "socketPath", "qemuPid", "startTicks", "sid")
            compact = json.loads(raw)
            version = 4 if value["encoding"] == "z85r4" else 3
            if (not isinstance(compact, dict) or set(compact) != {"v", "b", "s", "x", "i"}
                    or type(compact.get("v")) is not int or compact["v"] != version
                    or not all(isinstance(compact.get(key), list) for key in ("b", "s", "x", "i"))
                    or len(compact["b"]) != len(binding_fields) or len(compact["s"]) != 5 or len(compact["x"]) != 5
                    or len(compact["i"]) != 2
                    or any(not isinstance(row, list) or len(row) != len(snapshot_fields) for row in compact["s"])):
                raise ValueError()
            inner = {**dict(zip(binding_fields, compact["b"])), "snapshots": [dict(zip(snapshot_fields, row)) for row in compact["s"]]}
            archives = [{**dict(zip(snapshot_fields, row)), "xmlGzip": compact["x"][index], "bindingSha256": compact["i"][0]}
                        for index, row in enumerate(compact["s"])]
            terminal = {"retirementCorrelationId": compact["b"][0], "state": "retired",
                        "bindingSha256": compact["i"][0], "actionSha256": compact["i"][1]}
            receipt = {"binding": {"binding": inner, "bindingSha256": compact["i"][0], "actionSha256": compact["i"][1]},
                       "archives": archives, "terminal": terminal, "absent": True}
            canonical = json.dumps(receipt, separators=(",", ":"), sort_keys=True).encode()
        else:
            receipt = json.loads(raw)
            canonical = raw
        if len(canonical) != value["rawBytes"] or hashlib.sha256(canonical).hexdigest() != value["rawSha256"]:
            raise ValueError()
        return receipt
    except (ValueError, OSError, EOFError, UnicodeError):
        return {"_diagnostic": {"phase": "wire-envelope"}}


def _run(root: Path, descriptor: tuple[Any, ...], source: str) -> Any:
    config, target, current = base._descriptor(root)
    if current != descriptor:
        return None
    encoded = transport._encode_ps(source)
    raw = base._remote(config, _REMOTE, (str(target.fixture_transfer_root), descriptor[0], descriptor[1],
                                       str(descriptor[2]), str(descriptor[3]), encoded), None, 60)
    value = json.loads(raw) if raw else {}
    return _decode_observation(value)


def _task_functions(specs: list[dict[str, str]]) -> str:
    entries = json.dumps(specs, separators=(",", ":"))
    return r'''$ErrorActionPreference='Stop'
$specs=ConvertFrom-Json '@SPECS@'
function Hash([byte[]]$b){$h=[Security.Cryptography.SHA256]::Create();try{return ([BitConverter]::ToString($h.ComputeHash($b))).Replace('-','').ToLowerInvariant()}finally{$h.Dispose()}}
function Idle {if(@(Get-CimInstance Win32_Process -ErrorAction Stop|Where-Object {($_.Name -match '^(powershell|pwsh)\.exe$' -and $_.ProcessId -ne $PID) -or $_.Name -match '^(msiexec|consent)\.exe$'}).Count -ne 0){throw 'PROCESS'}}
function TaskSnapshot($s){
 Idle
 $ts=@(Get-ScheduledTask -TaskPath '\' -TaskName $s.task -ErrorAction Stop);if($ts.Count -ne 1){throw 'TASK'};$t=$ts[0];$a=@($t.Actions);$p=$t.Principal
 if($a.Count -ne 1){throw 'ACTION'};$action=Hash ([Text.Encoding]::UTF8.GetBytes($a[0].Execute+[char]0+$a[0].Arguments))
 $triggers=@($t.Triggers);if(-not ($triggers.Count -eq 0 -or ($triggers.Count -eq 1 -and $null -eq $triggers[0]))){throw 'TRIGGERS'}
 $sid=if($p.UserId -match '^S-1-'){([Security.Principal.SecurityIdentifier]::new($p.UserId)).Value}else{([Security.Principal.NTAccount]::new($p.UserId)).Translate([Security.Principal.SecurityIdentifier]).Value}
 if($t.TaskPath -cne '\' -or $t.State.ToString() -cne 'Ready' -or $action -cne $s.actionSha256 -or $sid -cne $s.sid -or $p.LogonType.ToString() -cne 'Interactive' -or $p.RunLevel.ToString() -cne 'Limited' -or $t.Settings.RestartCount -ne 0){throw 'TASK_BINDING'}
 $i=Get-ScheduledTaskInfo -TaskPath '\' -TaskName $s.task -ErrorAction Stop;$raw=$i.LastTaskResult
 if($null -eq $raw -or [Convert]::GetTypeCode($raw) -notin @([TypeCode]::SByte,[TypeCode]::Int16,[TypeCode]::Int32,[TypeCode]::Int64,[TypeCode]::Byte,[TypeCode]::UInt16,[TypeCode]::UInt32,[TypeCode]::UInt64) -or $i.LastRunTime -eq [datetime]::MinValue){throw 'TERMINAL'}
 $code=[int64]$raw;if($code -lt 0){$code+=4294967296};if($code -eq 267009){throw 'RUNNING'};$result=if($code -eq 0){'succeeded'}else{'failed'}
 $b=[Text.Encoding]::UTF8.GetBytes((Export-ScheduledTask -TaskPath '\' -TaskName $s.task -ErrorAction Stop));if($b.Length -lt 1 -or $b.Length -gt 131072){throw 'XML_SIZE'}
 $o=[IO.MemoryStream]::new();$z=[IO.Compression.GzipStream]::new($o,[IO.Compression.CompressionMode]::Compress,$true);$z.Write($b,0,$b.Length);$z.Dispose();$packed=[Convert]::ToBase64String($o.ToArray());$o.Dispose()
 return [ordered]@{profile=$s.profile;task=$s.task;actionSha256=$action;result=$result;taskResult=$code;lastRunTicks=$i.LastRunTime.Ticks;xmlSha256=(Hash $b);xmlLength=$b.Length;xmlGzip=$packed}
}
function VerifyArchive($a){$b=[Convert]::FromBase64String($a.xmlGzip);$i=[IO.MemoryStream]::new([byte[]]$b);$z=[IO.Compression.GzipStream]::new($i,[IO.Compression.CompressionMode]::Decompress);$o=[IO.MemoryStream]::new();try{$buf=New-Object byte[] 4096;while(($n=$z.Read($buf,0,$buf.Length)) -gt 0){if($o.Length+$n -gt 131072){throw 'XML_SIZE'};$o.Write($buf,0,$n)};$raw=$o.ToArray();if($raw.Length -ne $a.xmlLength -or (Hash $raw) -cne $a.xmlSha256){throw 'XML_HASH'}}finally{$z.Dispose();$i.Dispose();$o.Dispose()}}
'''.replace("@SPECS@", entries.replace("'", "''"))


def _snapshot_script(specs: list[dict[str, str]]) -> str:
    return _task_functions(specs) + ";try{if(Test-Path -LiteralPath '" + _ROOT + "'){throw 'EXISTS'};$all=@();foreach($s in $specs){$all+=,(TaskSnapshot $s)};[Console]::Out.WriteLine((@{archives=$all}|ConvertTo-Json -Depth 5 -Compress))}catch{$guard=$_.Exception.Message;$allowed=@('TASK','ACTION','TRIGGERS','TASK_BINDING','TERMINAL','RUNNING','XML_SIZE','PROCESS','EXISTS');$phase=if($guard -cin $allowed){$guard.ToLowerInvariant().Replace('_','-')}else{'unrecognized-guard'};[Console]::Out.WriteLine((@{_diagnostic=@{phase=$phase}}|ConvertTo-Json -Depth 3 -Compress))}"


def _plan(binding: dict[str, Any], specs: list[dict[str, str]]) -> tuple[str, dict[str, Any]]:
    binding_sha = _digest(binding)
    text = json.dumps(binding, sort_keys=True, separators=(",", ":")).replace("'", "''")
    source = _task_functions(specs) + journal.powershell(_ROOT, _LEAVES) + r'''
$b=ConvertFrom-Json '@BINDING@';$bindingSha='@SHA@';$action='@ACTION@'
if(Test-Path -LiteralPath $JournalRoot){throw 'EXISTS'}
# Capture and validate every original XML before creating the guest journal.
$all=@();foreach($s in $specs){$a=TaskSnapshot $s;$expected=@($b.snapshots|Where-Object {$_.profile -ceq $s.profile});if($expected.Count -ne 1){throw 'PROFILE'};foreach($key in @('task','actionSha256','result','taskResult','lastRunTicks','xmlSha256','xmlLength')){if($a[$key] -cne $expected[0].$key){throw 'CHANGED'}};$a.bindingSha256=$bindingSha;if([Text.Encoding]::UTF8.GetByteCount(($a|ConvertTo-Json -Depth 4 -Compress)) -gt 16384){throw 'LEAF_SIZE'};$all+=,$a}
Idle;Initialize-SecureJournal
Write-SecureJsonCreate 'binding.json' ((@{binding=$b;bindingSha256=$bindingSha;actionSha256=$action})|ConvertTo-Json -Depth 8 -Compress)
foreach($a in $all){Write-SecureJsonCreate ('archive-'+$a.profile+'.json') ($a|ConvertTo-Json -Depth 4 -Compress)}
# Read back and decompress ALL durable archives before the first unregister.
foreach($a in $all){$saved=Read-SecureJson ('archive-'+$a.profile+'.json');VerifyArchive $saved;foreach($key in @('profile','task','actionSha256','result','taskResult','lastRunTicks','xmlSha256','xmlLength','xmlGzip','bindingSha256')){if($saved.$key -cne $a[$key]){throw 'ARCHIVE_CHANGED'}}}
foreach($s in $specs){$fresh=TaskSnapshot $s;$a=@($all|Where-Object {$_.profile -ceq $s.profile})[0];foreach($key in @('task','actionSha256','result','taskResult','lastRunTicks','xmlSha256','xmlLength')){if($fresh[$key] -cne $a[$key]){throw 'CHANGED'}};Idle;Unregister-ScheduledTask -TaskPath '\' -TaskName $s.task -Confirm:$false -ErrorAction Stop}
Idle;foreach($s in $specs){if(@(Get-ScheduledTask -TaskPath '\' -ErrorAction Stop|Where-Object {$_.TaskName -ceq $s.task}).Count -ne 0){throw 'PRESENT'}}
Write-SecureJsonCreate 'terminal.json' ((@{retirementCorrelationId=$b.retirementCorrelationId;state='retired';bindingSha256=$bindingSha;actionSha256=$action})|ConvertTo-Json -Compress)
[Console]::Out.WriteLine('{"submitted":true}')
'''.replace("@BINDING@", text).replace("@SHA@", binding_sha)
    action = hashlib.sha256(source.replace("@ACTION@", "").encode("utf-16le")).hexdigest()
    return source.replace("@ACTION@", action), {"binding": binding, "bindingSha256": binding_sha, "actionSha256": action}


def _reader(specs: list[dict[str, str]]) -> str:
    return _task_functions(specs) + journal.powershell(_ROOT, _LEAVES) + r'''
Idle;$b=Read-SecureJson 'binding.json';$all=@();foreach($s in $specs){$a=Read-SecureJson ('archive-'+$s.profile+'.json');VerifyArchive $a;$all+=,$a};$t=Read-SecureJson 'terminal.json'
if(@(Get-ChildItem -LiteralPath $JournalRoot -Force -ErrorAction Stop).Count -ne 7){throw 'LEAVES'}
foreach($s in $specs){if(@(Get-ScheduledTask -TaskPath '\' -ErrorAction Stop|Where-Object {$_.TaskName -ceq $s.task}).Count -ne 0){throw 'PRESENT'}}
[Console]::Out.WriteLine((@{binding=$b;archives=$all;terminal=$t;absent=$true}|ConvertTo-Json -Depth 10 -Compress))
'''


def _finish_script(specs: list[dict[str, str]], local: Mapping[str, Any]) -> str:
    """Only complete a proven post-unregister crash window; never unregister."""
    text = json.dumps(local, sort_keys=True, separators=(",", ":")).replace("'", "''")
    return _task_functions(specs) + journal.powershell(_ROOT, _LEAVES) + r'''
$expected=ConvertFrom-Json '@LOCAL@';Idle;$binding=Read-SecureJson 'binding.json'
if($binding.bindingSha256 -cne $expected.bindingSha256 -or $binding.actionSha256 -cne $expected.actionSha256 -or (($binding.binding|ConvertTo-Json -Depth 12 -Compress)) -cne (($expected.binding|ConvertTo-Json -Depth 12 -Compress))){throw 'BINDING'}
foreach($s in $specs){$a=Read-SecureJson ('archive-'+$s.profile+'.json');VerifyArchive $a;$snapshot=@($expected.binding.snapshots|Where-Object {$_.profile -ceq $s.profile});if($snapshot.Count -ne 1 -or $a.bindingSha256 -cne $expected.bindingSha256){throw 'ARCHIVE'};foreach($key in @('profile','task','actionSha256','result','taskResult','lastRunTicks','xmlSha256','xmlLength')){if($a.$key -cne $snapshot[0].$key){throw 'ARCHIVE'}}}
Idle;foreach($s in $specs){if(@(Get-ScheduledTask -TaskPath '\' -ErrorAction Stop|Where-Object {$_.TaskName -ceq $s.task}).Count -ne 0){throw 'PRESENT'}}
[void](Assert-Root $JournalRoot);$children=@(Get-ChildItem -LiteralPath $JournalRoot -Force -ErrorAction Stop);if($children.Count -ne 6){throw 'LEAVES'};if(Test-Path -LiteralPath (Join-Path $JournalRoot 'terminal.json')){throw 'TERMINAL_PRESENT'}
Idle;Write-SecureJsonCreate 'terminal.json' ((@{retirementCorrelationId='@RETIREMENT@';state='retired';bindingSha256=$expected.bindingSha256;actionSha256=$expected.actionSha256}|ConvertTo-Json -Compress));$t=Read-SecureJson 'terminal.json';if($t.retirementCorrelationId -cne '@RETIREMENT@' -or $t.state -cne 'retired' -or $t.bindingSha256 -cne $expected.bindingSha256 -or $t.actionSha256 -cne $expected.actionSha256){throw 'TERMINAL'};[Console]::Out.WriteLine('{"finished":true}')
'''.replace('@LOCAL@', text).replace('@RETIREMENT@', _RETIREMENT)


def _finish_diagnostic_script(specs: list[dict[str, str]], local: Mapping[str, Any]) -> str:
    """Read-only first-failure classifier for the exact pre-terminal proof."""
    text = json.dumps(local, sort_keys=True, separators=(',', ':')).replace("'", "''")
    return _task_functions(specs) + journal.powershell(_ROOT, _LEAVES) + r'''
$expected=ConvertFrom-Json '@LOCAL@';$phase='process'
try{
 Idle;$phase='binding';$binding=Read-SecureJson 'binding.json'
 if($binding.bindingSha256 -cne $expected.bindingSha256 -or $binding.actionSha256 -cne $expected.actionSha256 -or (($binding.binding|ConvertTo-Json -Depth 12 -Compress)) -cne (($expected.binding|ConvertTo-Json -Depth 12 -Compress))){throw 'BINDING'}
 $phase='archive';foreach($s in $specs){$a=Read-SecureJson ('archive-'+$s.profile+'.json');VerifyArchive $a;$snapshot=@($expected.binding.snapshots|Where-Object {$_.profile -ceq $s.profile});if($snapshot.Count -ne 1 -or $a.bindingSha256 -cne $expected.bindingSha256){throw 'ARCHIVE'};foreach($key in @('profile','task','actionSha256','result','taskResult','lastRunTicks','xmlSha256','xmlLength')){if($a.$key -cne $snapshot[0].$key){throw 'ARCHIVE'}}}
 $phase='task-query';Idle;$index=0;foreach($s in $specs){$index++;if(@(Get-ScheduledTask -TaskPath '\' -ErrorAction Stop|Where-Object {$_.TaskName -ceq $s.task}).Count -ne 0){$phase='task-present-'+$index;throw 'PRESENT'}}
 $phase='root';[void](Assert-Root $JournalRoot);$children=@(Get-ChildItem -LiteralPath $JournalRoot -Force -ErrorAction Stop);if($children.Count -ne 6){throw 'LEAVES'}
 $phase='terminal';if(Test-Path -LiteralPath (Join-Path $JournalRoot 'terminal.json')){throw 'TERMINAL_PRESENT'}
 [Console]::Out.WriteLine('{"phase":"ready"}')
}catch{if($phase -notmatch '^(process|binding|archive|task-query|task-present-[1-5]|root|terminal)$'){$phase='unknown'};[Console]::Out.WriteLine((@{phase=$phase}|ConvertTo-Json -Compress))}
'''.replace('@LOCAL@', text)


def _tail_plan(specs: list[dict[str, str]], parent: Mapping[str, Any], *, correlation: str = _TAIL, rootpath: str = _TAIL_ROOT) -> tuple[str, dict[str, Any]]:
    """Build the fixed successor for the observed first-four-task prefix only."""
    fifth = specs[4]
    tail_binding = {
        "tailCorrelationId": correlation,
        "parentRetirementCorrelationId": _RETIREMENT,
        "parentBindingSha256": parent["bindingSha256"],
        "parentActionSha256": parent["actionSha256"],
        "profile": fifth["profile"], "task": fifth["task"],
    }
    parent_text = json.dumps(parent, sort_keys=True, separators=(",", ":")).replace("'", "''")
    tail_text = json.dumps(tail_binding, sort_keys=True, separators=(",", ":")).replace("'", "''")
    parent_leaves = "@(" + ",".join("'" + x + "'" for x in _LEAVES) + ")"
    source = _task_functions(specs) + journal.powershell(_ROOT, _LEAVES) + r'''
$expected=ConvertFrom-Json '@PARENT@';$tail=ConvertFrom-Json '@TAIL@';$action='@ACTION@';$tail|Add-Member -NotePropertyName actionSha256 -NotePropertyValue $action
Idle;$binding=Read-SecureJson 'binding.json';if($binding.bindingSha256 -cne $expected.bindingSha256 -or $binding.actionSha256 -cne $expected.actionSha256 -or (($binding.binding|ConvertTo-Json -Depth 12 -Compress)) -cne (($expected.binding|ConvertTo-Json -Depth 12 -Compress))){throw 'BINDING'}
foreach($s in $specs){$a=Read-SecureJson ('archive-'+$s.profile+'.json');VerifyArchive $a;$snapshot=@($expected.binding.snapshots|Where-Object {$_.profile -ceq $s.profile});if($snapshot.Count -ne 1 -or $a.bindingSha256 -cne $expected.bindingSha256){throw 'ARCHIVE'};foreach($key in @('profile','task','actionSha256','result','taskResult','lastRunTicks','xmlSha256','xmlLength')){if($a.$key -cne $snapshot[0].$key){throw 'ARCHIVE'}}}
for($index=0;$index -lt 4;$index++){if(@(Get-ScheduledTask -TaskPath '\' -ErrorAction Stop|Where-Object {$_.TaskName -ceq $specs[$index].task}).Count -ne 0){throw 'PREFIX_PRESENT'}}
$last=$specs[4];$archive=Read-SecureJson ('archive-'+$last.profile+'.json');$fresh=TaskSnapshot $last;foreach($key in @('profile','task','actionSha256','result','taskResult','lastRunTicks','xmlSha256','xmlLength')){if($fresh[$key] -cne $archive.$key){throw 'TAIL_CHANGED'}};Idle
[void](Assert-Root $JournalRoot);$parentChildren=@(Get-ChildItem -LiteralPath $JournalRoot -Force -ErrorAction Stop);if($parentChildren.Count -ne 6){throw 'PARENT_LEAVES'};$parentTerminal=Join-Path $JournalRoot 'terminal.json';if(Test-Path -LiteralPath $parentTerminal){throw 'PARENT_TERMINAL'}
'''.replace('@PARENT@', parent_text).replace('@TAIL@', tail_text) + journal.powershell(rootpath, _TAIL_LEAVES) + r'''
if(Test-Path -LiteralPath $JournalRoot){throw 'TAIL_EXISTS'};Write-SecureJsonCreate 'binding.json' ($tail|ConvertTo-Json -Depth 4 -Compress);$saved=Read-SecureJson 'binding.json';if(($saved|ConvertTo-Json -Depth 4 -Compress) -cne ($tail|ConvertTo-Json -Depth 4 -Compress)){throw 'TAIL_BINDING'}
$fresh=TaskSnapshot $last;foreach($key in @('profile','task','actionSha256','result','taskResult','lastRunTicks','xmlSha256','xmlLength')){if($fresh[$key] -cne $archive.$key){throw 'TAIL_CHANGED'}};Idle;Unregister-ScheduledTask -TaskPath '\' -TaskName $last.task -Confirm:$false -ErrorAction Stop
Idle;foreach($s in $specs){if(@(Get-ScheduledTask -TaskPath '\' -ErrorAction Stop|Where-Object {$_.TaskName -ceq $s.task}).Count -ne 0){throw 'PRESENT'}}
$JournalRoot='@PARENT_ROOT@';$AllowedLeaves=@PARENT_LEAVES@;Write-SecureJsonCreate 'terminal.json' ((@{retirementCorrelationId='@RETIREMENT@';state='retired';bindingSha256=$expected.bindingSha256;actionSha256=$expected.actionSha256}|ConvertTo-Json -Compress))
$JournalRoot='@TAIL_ROOT@';$AllowedLeaves=@('binding.json','terminal.json');Write-SecureJsonCreate 'terminal.json' ((@{tailCorrelationId='@TAIL_CORRELATION@';state='completed';parentRetirementCorrelationId='@RETIREMENT@';parentBindingSha256=$expected.bindingSha256;parentActionSha256=$expected.actionSha256;actionSha256=$action}|ConvertTo-Json -Compress));[Console]::Out.WriteLine('{"submitted":true}')
'''.replace('@PARENT_ROOT@', _ROOT).replace('@PARENT_LEAVES@', parent_leaves).replace('@TAIL_ROOT@', rootpath).replace('@RETIREMENT@', _RETIREMENT).replace('@TAIL_CORRELATION@', correlation)
    action = hashlib.sha256(source.replace("@ACTION@", "").encode("utf-16le")).hexdigest()
    source = source.replace("@ACTION@", action)
    return source, {"binding": {**tail_binding, "actionSha256": action}, "actionSha256": action}


def _tail_reader(rootpath: str = _TAIL_ROOT) -> str:
    return r'''$ErrorActionPreference='Stop'
function Idle {if(@(Get-CimInstance Win32_Process -ErrorAction Stop|Where-Object {($_.Name -match '^(powershell|pwsh)\.exe$' -and $_.ProcessId -ne $PID) -or $_.Name -match '^(msiexec|consent)\.exe$'}).Count -ne 0){throw 'PROCESS'}}
''' + journal.powershell(rootpath, _TAIL_LEAVES) + r'''
Idle;$binding=Read-SecureJson 'binding.json';$terminal=Read-SecureJson 'terminal.json'
if(@(Get-ChildItem -LiteralPath $JournalRoot -Force -ErrorAction Stop).Count -ne 2){throw 'LEAVES'}
[Console]::Out.WriteLine((@{binding=$binding;terminal=$terminal}|ConvertTo-Json -Depth 5 -Compress))
'''


def _pre_effect_closure_script(specs: list[dict[str, str]], parent: Mapping[str, Any], *, proof_correlation: str,
                               proof_root: str, absent_root: str) -> str:
    """Derive the non-mutating task-prefix proof, then require one absent child root."""
    source, _child = _tail_plan(specs, parent, correlation=proof_correlation, rootpath=proof_root)
    child_preamble = journal.powershell(proof_root, _TAIL_LEAVES)
    if source.count(child_preamble) != 1:
        raise WindowsCp117Cp95TaskRetireError("fixed tail proof construction failed")
    prefix = source.split(child_preamble, 1)[0]
    return prefix + r'''
if(Test-Path -LiteralPath '@ABSENT_ROOT@'){throw 'CHILD_ROOT_PRESENT'};[Console]::Out.WriteLine('{"verified":true}')
'''.replace('@ABSENT_ROOT@', absent_root)


def _tail_closure_script(specs: list[dict[str, str]], parent: Mapping[str, Any]) -> str:
    """The exact non-mutating prefix proof for the consumed old tail."""
    # This source is hashed in an already-durable historical marker.  Keep its
    # bytes stable; new closures use the parameterized builder below.
    source, _child = _tail_plan(specs, parent, correlation=_SUCCESSOR, rootpath=_SUCCESSOR_ROOT)
    child_preamble = journal.powershell(_SUCCESSOR_ROOT, _TAIL_LEAVES)
    if source.count(child_preamble) != 1:
        raise WindowsCp117Cp95TaskRetireError("fixed successor proof construction failed")
    prefix = source.split(child_preamble, 1)[0]
    return prefix + r'''
if(Test-Path -LiteralPath '@OLD_ROOT@'){throw 'OLD_ROOT_PRESENT'};[Console]::Out.WriteLine('{"verified":true}')
'''.replace('@OLD_ROOT@', _TAIL_ROOT)


def _successor_closure_script(specs: list[dict[str, str]], parent: Mapping[str, Any]) -> str:
    """The exact non-mutating prefix proof for the consumed 7cc successor."""
    return _pre_effect_closure_script(specs, parent, proof_correlation=_FRESH,
                                      proof_root=_FRESH_ROOT, absent_root=_SUCCESSOR_ROOT)


def _closure_marker(parent: Mapping[str, Any], descriptor: tuple[Any, ...], source: str) -> dict[str, Any]:
    return {"oldTailCorrelationId": _TAIL, "successorCorrelationId": _SUCCESSOR,
            "parentRetirementCorrelationId": _RETIREMENT,
            "parentBindingSha256": parent["bindingSha256"], "parentActionSha256": parent["actionSha256"],
            "environment": descriptor[0], "socketPath": descriptor[1], "qemuPid": descriptor[2],
            "startTicks": descriptor[3], "sid": descriptor[4],
            "proofSha256": hashlib.sha256(source.encode("utf-16le")).hexdigest()}


def _successor_closure_marker(parent: Mapping[str, Any], descriptor: tuple[Any, ...], source: str) -> dict[str, Any]:
    return {"closedTailCorrelationId": _SUCCESSOR, "freshTailCorrelationId": _FRESH,
            "parentRetirementCorrelationId": _RETIREMENT,
            "parentBindingSha256": parent["bindingSha256"], "parentActionSha256": parent["actionSha256"],
            "environment": descriptor[0], "socketPath": descriptor[1], "qemuPid": descriptor[2],
            "startTicks": descriptor[3], "sid": descriptor[4],
            "proofSha256": hashlib.sha256(source.encode("utf-16le")).hexdigest()}


def tail_close_pre_effect(root: Path | str, inputs: Mapping[str, Any]) -> dict[str, Any]:
    """Close only the proven no-effect old tail; never touches a guest task."""
    if inputs != {}:
        raise WindowsCp117Cp95TaskRetireError("Fixed tail closure takes no inputs.")
    path = Path(root).resolve(strict=True)
    marker_path = path / _CLOSURE_DIR / "marker.json"
    try:
        with retained._lease_read_lock(path) as directory:
            parent = guards.secure_read(path / _DIR / "intent.json")
            if parent is None or set(parent) != {"binding", "bindingSha256", "actionSha256"} or guards.secure_read(path / _TAIL_DIR / "intent.json") is not None:
                return _tail_result("blocked", "intent")
            descriptor = base._descriptor(path)[2]; specs = retained._configured_specs(path, descriptor)
            snapshots = parent.get("binding", {}).get("snapshots") if isinstance(parent.get("binding"), dict) else None
            if (specs is None or not isinstance(snapshots, list) or len(snapshots) != 5 or parent["binding"] != _binding(descriptor, snapshots)
                    or parent != _plan(parent["binding"], specs)[1] or lease._active(directory) is not None):
                return _tail_result("blocked", "generation")
            source = _tail_closure_script(specs, parent); marker = _closure_marker(parent, descriptor, source)
            existing = guards.secure_read(marker_path)
            if existing is not None:
                return _tail_result("closed" if existing == marker else "unknown", "tail-closure-complete" if existing == marker else "tail-closure-marker")
            if not _parse(path, descriptor, source):
                return _tail_result("blocked", "tail-closure-parser")
            if base._descriptor(path)[2] != descriptor or retained._configured_specs(path, descriptor) != specs or lease._active(directory) is not None:
                return _tail_result("blocked", "generation")
            if _run(path, descriptor, source) != {"verified": True}:
                return _tail_result("unknown", "tail-closure-proof")
            if (base._descriptor(path)[2] != descriptor or retained._configured_specs(path, descriptor) != specs
                    or lease._active(directory) is not None or guards.secure_read(path / _TAIL_DIR / "intent.json") is not None):
                return _tail_result("unknown", "generation")
            try:
                guards.secure_write_create(marker_path, marker)
            except (OSError, ValueError, TypeError, KeyError, IndexError):
                return _tail_result("unknown", "tail-closure-marker")
            return _tail_result("closed", "tail-closure-complete")
    except (OSError, ValueError, TypeError, KeyError, IndexError):
        return _tail_result("unknown", "tail-closure-proof")


def successor_close_pre_effect(root: Path | str, inputs: Mapping[str, Any]) -> dict[str, Any]:
    """Create evidence that consumed 7cc had no local or remote child effect."""
    if inputs != {}:
        raise WindowsCp117Cp95TaskRetireError("Fixed successor closure takes no inputs.")
    path = Path(root).resolve(strict=True)
    marker_path = path / _SUCCESSOR_CLOSURE_DIR / "marker.json"
    try:
        with retained._lease_read_lock(path) as directory:
            parent = guards.secure_read(path / _DIR / "intent.json")
            if parent is None or set(parent) != {"binding", "bindingSha256", "actionSha256"}:
                return _successor_result("blocked", "intent")
            descriptor = base._descriptor(path)[2]; specs = retained._configured_specs(path, descriptor)
            snapshots = parent.get("binding", {}).get("snapshots") if isinstance(parent.get("binding"), dict) else None
            if (specs is None or not isinstance(snapshots, list) or len(snapshots) != 5
                    or parent["binding"] != _binding(descriptor, snapshots)
                    or parent != _plan(parent["binding"], specs)[1] or lease._active(directory) is not None):
                return _successor_result("blocked", "generation")
            old_source = _tail_closure_script(specs, parent)
            if guards.secure_read(path / _CLOSURE_DIR / "marker.json") != _closure_marker(parent, descriptor, old_source):
                return _successor_result("blocked", "tail-closure-complete")
            if guards.secure_read(path / _SUCCESSOR_DIR / "intent.json") is not None:
                return _successor_result("blocked", "intent")
            source = _successor_closure_script(specs, parent)
            marker = _successor_closure_marker(parent, descriptor, source)
            existing = guards.secure_read(marker_path)
            if existing is not None:
                return _successor_result("closed" if existing == marker else "unknown",
                                         "successor-closure-complete" if existing == marker else "successor-closure-marker")
            if not _parse(path, descriptor, source):
                return _successor_result("blocked", "successor-closure-parser")
            if (base._descriptor(path)[2] != descriptor or retained._configured_specs(path, descriptor) != specs
                    or lease._active(directory) is not None
                    or guards.secure_read(path / _CLOSURE_DIR / "marker.json") != _closure_marker(parent, descriptor, old_source)
                    or guards.secure_read(path / _SUCCESSOR_DIR / "intent.json") is not None):
                return _successor_result("unknown", "generation")
            if _run(path, descriptor, source) != {"verified": True}:
                return _successor_result("unknown", "successor-closure-proof")
            if (base._descriptor(path)[2] != descriptor or retained._configured_specs(path, descriptor) != specs
                    or lease._active(directory) is not None
                    or guards.secure_read(path / _CLOSURE_DIR / "marker.json") != _closure_marker(parent, descriptor, old_source)
                    or guards.secure_read(path / _SUCCESSOR_DIR / "intent.json") is not None):
                return _successor_result("unknown", "generation")
            try:
                guards.secure_write_create(marker_path, marker)
            except (OSError, ValueError, TypeError, KeyError, IndexError):
                return _successor_result("unknown", "successor-closure-marker")
            return _successor_result("closed", "successor-closure-complete")
    except (OSError, ValueError, TypeError, KeyError, IndexError):
        return _successor_result("unknown", "successor-closure-proof")


def _journal_file_probe(rootpath: str = _ROOT, leaves_value: tuple[str, ...] = _LEAVES) -> str:
    leaves = "@("
    leaves += ",".join("'" + leaf + "'" for leaf in leaves_value)
    leaves += ")"
    return r'''$ErrorActionPreference='Stop';$root='@ROOT@';function O($p){[Console]::Out.WriteLine((@{phase=$p}|ConvertTo-Json -Compress))}
try{$item=Get-Item -LiteralPath $root -Force -ErrorAction Stop;if(-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){O 'root-unsafe';exit};$leaves=@LEAVES@;foreach($leaf in $leaves){$path=Join-Path $root $leaf;if(-not(Test-Path -LiteralPath $path)){if($leaf -eq 'binding.json'){O 'binding-absent'}elseif($leaf -eq 'terminal.json'){O 'terminal-absent'}else{O 'archive-absent'};exit};$file=Get-Item -LiteralPath $path -Force -ErrorAction Stop;if($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $file.Length -gt 16384){O 'file-unsafe';exit};[void][IO.File]::ReadAllBytes($path)};O 'readable'}catch [UnauthorizedAccessException]{O 'access'}catch{O 'root-absent'}'''.replace('@ROOT@', rootpath).replace('@LEAVES@', leaves)


def _parser_script(source: str) -> str:
    """Parse the exact fixed source in a compact, non-executing UTF-8 wrapper."""
    packed = base64.b64encode(gzip.compress(source.encode("utf-8"), mtime=0)).decode()
    return "$i=[IO.MemoryStream]::new([byte[]][Convert]::FromBase64String('" + packed + "'));$z=[IO.Compression.GzipStream]::new($i,[IO.Compression.CompressionMode]::Decompress);$o=[IO.MemoryStream]::new();$z.CopyTo($o);$z.Dispose();$i.Dispose();$s=[Text.Encoding]::UTF8.GetString($o.ToArray());$o.Dispose();$t=$null;$e=$null;[void][Management.Automation.Language.Parser]::ParseInput($s,[ref]$t,[ref]$e);[Console]::Out.WriteLine((@{valid=($e.Count -eq 0)}|ConvertTo-Json -Compress))"


def _parse(root: Path, descriptor: tuple[Any, ...], source: str) -> bool:
    # Parse the actual source, not merely its compressed launcher.
    return _run(root, descriptor, _parser_script(source)) == {"valid": True}


class _AdmissionBlocked(Exception):
    """Finite causal missing fact; never carries transport or exception text."""
    def __init__(self, phase: str, diagnostic: Mapping[str, Any] | None = None):
        self.phase = phase
        self.diagnostic = diagnostic


def _admission_fact(phase: str, read):
    try:
        return read()
    except (OSError, ValueError, TypeError, KeyError, IndexError):
        raise _AdmissionBlocked(phase) from None


def _admit(root: Path):
    _config, _target, descriptor = _admission_fact("descriptor", lambda: base._descriptor(root))
    specs = _admission_fact("configured-specs", lambda: retained._configured_specs(root, descriptor))
    if specs is None:
        raise _AdmissionBlocked("configured-specs")
    observed = _admission_fact("retained-proof", lambda: retained.status(root, {}))
    if not isinstance(observed, Mapping) or observed.get("state") != "ready":
        raise _AdmissionBlocked("retained-proof")
    snapshot_source = _admission_fact("snapshot-parser", lambda: _snapshot_script(specs))
    if not _admission_fact("snapshot-parser", lambda: _parse(root, descriptor, snapshot_source)):
        raise _AdmissionBlocked("snapshot-parser")
    value = _admission_fact("snapshot-output", lambda: _run(root, descriptor, snapshot_source))
    if isinstance(value, dict) and set(value) == {"_diagnostic"}:
        diagnostic = value["_diagnostic"]
        if isinstance(diagnostic, dict) and diagnostic.get("phase") in _DIAGNOSTIC_PHASES and set(diagnostic) <= {"phase", "rawBytes", "wireBytes"} and all(type(diagnostic[k]) is int and 0 <= diagnostic[k] <= 150000 for k in ("rawBytes", "wireBytes") if k in diagnostic):
            raise _AdmissionBlocked("snapshot-output-" + diagnostic["phase"], diagnostic)
    if not isinstance(value, dict) or set(value) != {"archives"} or not isinstance(value["archives"], list) or len(value["archives"]) != 5:
        raise _AdmissionBlocked("snapshot-output")
    snapshots = _admission_fact("snapshot-output-archive-fields", lambda: [_validate_archive(a, s) for a, s in zip(value["archives"], specs)])
    binding = _binding(descriptor, snapshots)
    script, intent = _admission_fact("mutation-parser", lambda: _plan(binding, specs))
    if not _admission_fact("mutation-parser", lambda: _parse(root, descriptor, script)):
        raise _AdmissionBlocked("mutation-parser")
    if not _admission_fact("reader-parser", lambda: _parse(root, descriptor, _reader(specs))):
        raise _AdmissionBlocked("reader-parser")
    current = _admission_fact("generation", lambda: base._descriptor(root)[2])
    current_specs = _admission_fact("generation", lambda: retained._configured_specs(root, descriptor))
    if current != descriptor or current_specs != specs:
        raise _AdmissionBlocked("generation")
    return descriptor, specs, script, intent


def _status_locked(root: Path, directory: Path) -> dict[str, Any]:
    local = guards.secure_read(root / _DIR / "intent.json")
    if local is None:
        return _result("not-started", "intent")
    if lease._active(directory) is not None:
        return _result("unknown", "active-lease")
    descriptor = base._descriptor(root)[2]
    specs = retained._configured_specs(root, descriptor)
    if specs is None or set(local) != {"binding", "bindingSha256", "actionSha256"} or not isinstance(local.get("binding"), dict):
        return _result("unknown", "intent")
    binding = local["binding"]
    if binding != _binding(descriptor, binding.get("snapshots")) or not isinstance(binding.get("snapshots"), list) or len(binding["snapshots"]) != 5:
        return _result("unknown", "generation")
    _script, expected = _plan(binding, specs)
    if local != expected:
        return _result("unknown", "intent")
    value = _run(root, descriptor, _reader(specs))
    if not isinstance(value, dict) or set(value) != {"binding", "archives", "terminal", "absent"} or value["binding"] != local or value["absent"] is not True or not isinstance(value["archives"], list) or len(value["archives"]) != 5:
        return _result("unknown", "journal")
    snapshots = [_validate_archive(a, s, local["bindingSha256"]) for a, s in zip(value["archives"], specs)]
    terminal = {"retirementCorrelationId": _RETIREMENT, "state": "retired", "bindingSha256": local["bindingSha256"], "actionSha256": local["actionSha256"]}
    if snapshots != binding["snapshots"] or value["terminal"] != terminal:
        return _result("unknown", "terminal")
    if base._descriptor(root)[2] != descriptor or retained._configured_specs(root, descriptor) != specs or lease._active(directory) is not None:
        return _result("unknown", "generation")
    return _result("retired", "complete")


def _finish_locked(root: Path, directory: Path) -> dict[str, Any]:
    """Create only the absent terminal after independently rechecking the crash window."""
    local = guards.secure_read(root / _DIR / "intent.json")
    if local is None:
        return _result("blocked", "intent")
    if lease._active(directory) is not None:
        return _result("blocked", "active-lease")
    descriptor = base._descriptor(root)[2]
    specs = retained._configured_specs(root, descriptor)
    if specs is None or set(local) != {"binding", "bindingSha256", "actionSha256"} or not isinstance(local.get("binding"), dict):
        return _result("blocked", "intent")
    binding = local["binding"]
    snapshots = binding.get("snapshots")
    if not isinstance(snapshots, list) or len(snapshots) != 5 or binding != _binding(descriptor, snapshots):
        return _result("blocked", "generation")
    _plan_source, expected = _plan(binding, specs)
    if local != expected:
        return _result("blocked", "intent")
    source = _finish_script(specs, local)
    if not _parse(root, descriptor, source):
        return _result("blocked", "finish-parser")
    # Reconstruct exact expected bindings after parsing, immediately before the
    # only remote mutation.  A changed generation, task inventory, or active
    # campaign can never be converted into terminal completion.
    if (base._descriptor(root)[2] != descriptor
            or retained._configured_specs(root, descriptor) != specs
            or lease._active(directory) is not None):
        return _result("blocked", "generation")
    value = _run(root, descriptor, source)
    if value != {"finished": True}:
        return _result("unknown", "finish-dispatch")
    # A fresh reader must verify the immutable terminal and all five task
    # absences.  The acknowledgement alone is never a retirement proof.
    return _status_locked(root, directory)


def _tail_status_locked(root: Path, directory: Path, parent: Mapping[str, Any], descriptor: tuple[Any, ...], specs: list[dict[str, str],], *, correlation: str = _TAIL, child_dir: str = _TAIL_DIR, child_root: str = _TAIL_ROOT, result_factory=_tail_result) -> dict[str, Any]:
    child = guards.secure_read(root / child_dir / "intent.json")
    _source, expected = _tail_plan(specs, parent, correlation=correlation, rootpath=child_root)
    if child != expected or lease._active(directory) is not None:
        return result_factory("unknown", "terminal")
    if not _parse(root, descriptor, _tail_reader(child_root)):
        return result_factory("unknown", "parser")
    value = _run(root, descriptor, _tail_reader(child_root))
    terminal = {"tailCorrelationId": correlation, "state": "completed", "parentRetirementCorrelationId": _RETIREMENT,
                "parentBindingSha256": parent["bindingSha256"], "parentActionSha256": parent["actionSha256"],
                "actionSha256": child["actionSha256"]}
    if not isinstance(value, dict) or set(value) != {"binding", "terminal"} or value.get("binding") != child["binding"] or value.get("terminal") != terminal:
        return result_factory("unknown", "terminal")
    parent_status = _status_locked(root, directory)
    if parent_status["state"] != "retired":
        return result_factory("unknown", "terminal")
    if base._descriptor(root)[2] != descriptor or retained._configured_specs(root, descriptor) != specs or lease._active(directory) is not None:
        return result_factory("unknown", "generation")
    return result_factory("retired", "complete")


def tail_start(root: Path | str, inputs: Mapping[str, Any]) -> dict[str, Any]:
    """Submit the fixed fifth-task successor once; never reuses the parent start."""
    if inputs != {}:
        raise WindowsCp117Cp95TaskRetireError("Fixed tail retirement takes no inputs.")
    path = Path(root).resolve(strict=True)
    try:
        with retained._lease_read_lock(path) as directory:
            parent = guards.secure_read(path / _DIR / "intent.json")
            child_path = path / _TAIL_DIR / "intent.json"
            if guards.secure_read(path / _CLOSURE_DIR / "marker.json") is not None:
                return _tail_result("blocked", "tail-closure-complete")
            if parent is None or set(parent) != {"binding", "bindingSha256", "actionSha256"} or not isinstance(parent.get("binding"), dict):
                return _tail_result("blocked", "intent")
            if guards.secure_read(child_path) is not None:
                return _tail_result("unknown", "terminal")
            if lease._active(directory) is not None:
                return _tail_result("blocked", "active-lease")
            descriptor = base._descriptor(path)[2]
            specs = retained._configured_specs(path, descriptor)
            snapshots = parent["binding"].get("snapshots")
            if (specs is None or not isinstance(snapshots, list) or len(snapshots) != 5
                    or parent["binding"] != _binding(descriptor, snapshots)
                    or parent != _plan(parent["binding"], specs)[1]):
                return _tail_result("blocked", "generation")
            source, child = _tail_plan(specs, parent)
            if not _parse(path, descriptor, source):
                return _tail_result("blocked", "parser")
            if (base._descriptor(path)[2] != descriptor
                    or retained._configured_specs(path, descriptor) != specs
                    or lease._active(directory) is not None):
                return _tail_result("blocked", "generation")
            try:
                guards.secure_write_create(child_path, child)
            except (OSError, ValueError, TypeError, KeyError, IndexError):
                return _tail_result("unknown", "tail-local-intent")
            # The child intent is consumed before its only task unregister.
            value = _run(path, descriptor, source)
            if value != {"submitted": True}:
                return _tail_result("unknown", "dispatch")
            return _tail_status_locked(path, directory, parent, descriptor, specs)
    except (OSError, ValueError, TypeError, KeyError, IndexError):
        return _tail_result("unknown", "journal")


def tail_status(root: Path | str, inputs: Mapping[str, Any]) -> dict[str, Any]:
    """Read the fixed tail terminal; this never reopens the parent start."""
    if inputs != {}:
        raise WindowsCp117Cp95TaskRetireError("Fixed tail status takes no inputs.")
    path = Path(root).resolve(strict=True)
    try:
        with retained._lease_read_lock(path) as directory:
            parent = guards.secure_read(path / _DIR / "intent.json")
            if parent is None or set(parent) != {"binding", "bindingSha256", "actionSha256"} or not isinstance(parent.get("binding"), dict):
                return _tail_result("not-started", "intent")
            descriptor = base._descriptor(path)[2]
            specs = retained._configured_specs(path, descriptor)
            snapshots = parent["binding"].get("snapshots")
            if (specs is None or not isinstance(snapshots, list) or len(snapshots) != 5
                    or parent["binding"] != _binding(descriptor, snapshots)
                    or parent != _plan(parent["binding"], specs)[1]):
                return _tail_result("unknown", "generation")
            return _tail_status_locked(path, directory, parent, descriptor, specs)
    except (OSError, ValueError, TypeError, KeyError, IndexError):
        return _tail_result("unknown", "journal")


def successor_start(root: Path | str, inputs: Mapping[str, Any]) -> dict[str, Any]:
    if inputs != {}:
        raise WindowsCp117Cp95TaskRetireError("Fixed successor takes no inputs.")
    path = Path(root).resolve(strict=True)
    try:
        with retained._lease_read_lock(path) as directory:
            parent = guards.secure_read(path / _DIR / "intent.json")
            descriptor = base._descriptor(path)[2]; specs = retained._configured_specs(path, descriptor)
            if parent is None or specs is None:
                return _successor_result("blocked", "intent")
            closure = guards.secure_read(path / _CLOSURE_DIR / "marker.json")
            closure_source = _tail_closure_script(specs, parent)
            if closure != _closure_marker(parent, descriptor, closure_source):
                return _successor_result("blocked", "tail-closure-complete")
            if guards.secure_read(path / _SUCCESSOR_CLOSURE_DIR / "marker.json") is not None:
                return _successor_result("blocked", "successor-closure-complete")
            child_path = path / _SUCCESSOR_DIR / "intent.json"
            if (guards.secure_read(child_path) is not None
                    or guards.secure_read(path / _TAIL_DIR / "intent.json") is not None
                    or lease._active(directory) is not None):
                return _successor_result("unknown", "terminal")
            source, child = _tail_plan(specs, parent, correlation=_SUCCESSOR, rootpath=_SUCCESSOR_ROOT)
            if not _parse(path, descriptor, source): return _successor_result("blocked", "parser")
            if (base._descriptor(path)[2] != descriptor or retained._configured_specs(path, descriptor) != specs
                    or guards.secure_read(path / _TAIL_DIR / "intent.json") is not None
                    or guards.secure_read(path / _SUCCESSOR_CLOSURE_DIR / "marker.json") is not None
                    or lease._active(directory) is not None):
                return _successor_result("blocked", "generation")
            guards.secure_write_create(child_path, child)
            if _run(path, descriptor, source) != {"submitted": True}: return _successor_result("unknown", "dispatch")
            return _tail_status_locked(path, directory, parent, descriptor, specs, correlation=_SUCCESSOR, child_dir=_SUCCESSOR_DIR, child_root=_SUCCESSOR_ROOT, result_factory=_successor_result)
    except (OSError, ValueError, TypeError, KeyError, IndexError):
        return _successor_result("unknown", "journal")


def successor_status(root: Path | str, inputs: Mapping[str, Any]) -> dict[str, Any]:
    if inputs != {}:
        raise WindowsCp117Cp95TaskRetireError("Fixed successor status takes no inputs.")
    path = Path(root).resolve(strict=True)
    try:
        with retained._lease_read_lock(path) as directory:
            parent = guards.secure_read(path / _DIR / "intent.json")
            if parent is None: return _successor_result("not-started", "intent")
            descriptor = base._descriptor(path)[2]; specs = retained._configured_specs(path, descriptor)
            if specs is None or guards.secure_read(path / _SUCCESSOR_DIR / "intent.json") is None:
                return _successor_result("not-started", "intent")
            marker = guards.secure_read(path / _CLOSURE_DIR / "marker.json")
            if marker != _closure_marker(parent, descriptor, _tail_closure_script(specs, parent)):
                return _successor_result("unknown", "tail-closure-complete")
            return _tail_status_locked(path, directory, parent, descriptor, specs, correlation=_SUCCESSOR, child_dir=_SUCCESSOR_DIR, child_root=_SUCCESSOR_ROOT, result_factory=_successor_result)
    except (OSError, ValueError, TypeError, KeyError, IndexError):
        return _successor_result("unknown", "journal")


def _fresh_markers(parent: Mapping[str, Any], descriptor: tuple[Any, ...], specs: list[dict[str, str]], path: Path) -> bool:
    """Require immutable closure evidence for both consumed predecessors."""
    old = guards.secure_read(path / _CLOSURE_DIR / "marker.json")
    if old != _closure_marker(parent, descriptor, _tail_closure_script(specs, parent)):
        return False
    closed = guards.secure_read(path / _SUCCESSOR_CLOSURE_DIR / "marker.json")
    return closed == _successor_closure_marker(parent, descriptor, _successor_closure_script(specs, parent))


def fresh_start(root: Path | str, inputs: Mapping[str, Any]) -> dict[str, Any]:
    """One new task-five continuation after both consumed attempts are proven no-effect."""
    if inputs != {}:
        raise WindowsCp117Cp95TaskRetireError("Fixed fresh continuation takes no inputs.")
    path = Path(root).resolve(strict=True)
    try:
        with retained._lease_read_lock(path) as directory:
            parent = guards.secure_read(path / _DIR / "intent.json")
            descriptor = base._descriptor(path)[2]; specs = retained._configured_specs(path, descriptor)
            if parent is None or specs is None:
                return _fresh_result("blocked", "intent")
            if not _fresh_markers(parent, descriptor, specs, path):
                return _fresh_result("blocked", "successor-closure-complete")
            child_path = path / _FRESH_DIR / "intent.json"
            if (guards.secure_read(child_path) is not None or guards.secure_read(path / _TAIL_DIR / "intent.json") is not None
                    or guards.secure_read(path / _SUCCESSOR_DIR / "intent.json") is not None or lease._active(directory) is not None):
                return _fresh_result("unknown", "terminal")
            source, child = _tail_plan(specs, parent, correlation=_FRESH, rootpath=_FRESH_ROOT)
            if not _parse(path, descriptor, source):
                return _fresh_result("blocked", "parser")
            if (base._descriptor(path)[2] != descriptor or retained._configured_specs(path, descriptor) != specs
                    or not _fresh_markers(parent, descriptor, specs, path)
                    or guards.secure_read(path / _TAIL_DIR / "intent.json") is not None
                    or guards.secure_read(path / _SUCCESSOR_DIR / "intent.json") is not None
                    or lease._active(directory) is not None):
                return _fresh_result("blocked", "generation")
            guards.secure_write_create(child_path, child)
            if _run(path, descriptor, source) != {"submitted": True}:
                return _fresh_result("unknown", "dispatch")
            return _tail_status_locked(path, directory, parent, descriptor, specs, correlation=_FRESH,
                                       child_dir=_FRESH_DIR, child_root=_FRESH_ROOT, result_factory=_fresh_result)
    except (OSError, ValueError, TypeError, KeyError, IndexError):
        return _fresh_result("unknown", "journal")


def fresh_status(root: Path | str, inputs: Mapping[str, Any]) -> dict[str, Any]:
    """Fresh linked child and original parent terminal proof; never retries submission."""
    if inputs != {}:
        raise WindowsCp117Cp95TaskRetireError("Fixed fresh continuation status takes no inputs.")
    path = Path(root).resolve(strict=True)
    try:
        with retained._lease_read_lock(path) as directory:
            parent = guards.secure_read(path / _DIR / "intent.json")
            if parent is None: return _fresh_result("not-started", "intent")
            descriptor = base._descriptor(path)[2]; specs = retained._configured_specs(path, descriptor)
            if specs is None or guards.secure_read(path / _FRESH_DIR / "intent.json") is None:
                return _fresh_result("not-started", "intent")
            if not _fresh_markers(parent, descriptor, specs, path):
                return _fresh_result("unknown", "successor-closure-complete")
            return _tail_status_locked(path, directory, parent, descriptor, specs, correlation=_FRESH,
                                       child_dir=_FRESH_DIR, child_root=_FRESH_ROOT, result_factory=_fresh_result)
    except (OSError, ValueError, TypeError, KeyError, IndexError):
        return _fresh_result("unknown", "journal")


def successor_admission_diagnose(root: Path | str, inputs: Mapping[str, Any]) -> dict[str, Any]:
    """Read-only bounded first-failure diagnosis for consumed 7cc pre-intent admission."""
    if inputs != {}: raise WindowsCp117Cp95TaskRetireError("Fixed successor diagnosis takes no inputs.")
    path = Path(root).resolve(strict=True); stage = "parent"
    def out(phase: str) -> dict[str, Any]: return _successor_result("diagnosed", phase)
    try:
        with retained._lease_read_lock(path) as directory:
            parent = guards.secure_read(path / _DIR / "intent.json")
            if parent is None: return out("parent")
            stage = "descriptor"; descriptor = base._descriptor(path)[2]
            stage = "specs"; specs = retained._configured_specs(path, descriptor)
            if specs is None: return out("specs")
            stage = "closure"; marker = guards.secure_read(path / _CLOSURE_DIR / "marker.json")
            if marker != _closure_marker(parent, descriptor, _tail_closure_script(specs, parent)): return out("closure")
            stage = "old-child"; old = guards.secure_read(path / _TAIL_DIR / "intent.json")
            if old is not None: return out("old-child")
            stage = "successor-child"; child = guards.secure_read(path / _SUCCESSOR_DIR / "intent.json")
            if child is not None: return out("successor-child")
            stage = "lease";
            if lease._active(directory) is not None: return out("lease")
            stage = "tailplan"; source, _child = _tail_plan(specs, parent, correlation=_SUCCESSOR, rootpath=_SUCCESSOR_ROOT)
            stage = "intentfs"; ancestor = path / ".rag_index"
            info = ancestor.lstat()
            if (not stat.S_ISDIR(info.st_mode) or ancestor.is_symlink() or info.st_uid != os.getuid()
                    or not os.access(ancestor, os.W_OK | os.X_OK)):
                return out("intentfs")
            stage = "parser"
            if not _parse(path, descriptor, source): return out("parser")
            stage = "fresh"; refreshed = base._descriptor(path)[2]; refreshed_specs = retained._configured_specs(path, descriptor)
            if refreshed != descriptor or refreshed_specs != specs: return out("fresh")
            return out("ready")
    except OSError: return out(stage + "-oserror")
    except ValueError: return out(stage + "-valueerror")
    except TypeError: return out(stage + "-typeerror")
    except KeyError: return out(stage + "-keyerror")
    except IndexError: return out(stage + "-indexerror")


def tail_diagnose(root: Path | str, inputs: Mapping[str, Any]) -> dict[str, Any]:
    """Read-only child-journal census after a consumed tail submission."""
    if inputs != {}:
        raise WindowsCp117Cp95TaskRetireError("Fixed tail diagnostic takes no inputs.")
    path = Path(root).resolve(strict=True)
    def out(phase: str) -> dict[str, Any]:
        value = _tail_result("diagnosed", phase)
        value["nativeActionAllowed"] = False
        return value
    try:
        with retained._lease_read_lock(path) as directory:
            parent = guards.secure_read(path / _DIR / "intent.json")
            if parent is None or set(parent) != {"binding", "bindingSha256", "actionSha256"} or not isinstance(parent.get("binding"), dict):
                return out("parent-intent")
            child = guards.secure_read(path / _TAIL_DIR / "intent.json")
            if child is None:
                return out("child-intent-absent")
            descriptor = base._descriptor(path)[2]
            specs = retained._configured_specs(path, descriptor)
            snapshots = parent["binding"].get("snapshots")
            if (specs is None or not isinstance(snapshots, list) or len(snapshots) != 5
                    or parent["binding"] != _binding(descriptor, snapshots)
                    or parent != _plan(parent["binding"], specs)[1]
                    or child != _tail_plan(specs, parent)[1]
                    or lease._active(directory) is not None):
                return out("child-intent")
            value = _run(path, descriptor, _journal_file_probe(_TAIL_ROOT, _TAIL_LEAVES))
            if isinstance(value, dict) and set(value) == {"phase"} and isinstance(value.get("phase"), str) and value["phase"] in _JOURNAL_FILE_PHASES:
                return out("remote-file-" + value["phase"])
            return out("remote-file")
    except (OSError, ValueError, TypeError, KeyError, IndexError):
        return out("unknown")


def diagnose(root: Path | str, inputs: Mapping[str, Any]) -> dict[str, Any]:
    """Read only classification for the consumed CP95 intent; no recovery path."""
    if inputs != {}:
        raise WindowsCp117Cp95TaskRetireError("Fixed task retirement diagnostic takes no inputs.")
    path = Path(root).resolve(strict=True)
    flags = {"replayAllowed": False, "nativeActionAllowed": False, "productAction": False}
    def out(phase: str) -> dict[str, Any]:
        return {"state": "diagnosed", "phase": phase, "retirementCorrelationId": _RETIREMENT, **flags}
    try:
        with retained._lease_read_lock(path) as directory:
            local = guards.secure_read(path / _DIR / "intent.json")
            if local is None or set(local) != {"binding", "bindingSha256", "actionSha256"} or not isinstance(local.get("binding"), dict):
                return out("intent")
            try:
                descriptor = base._descriptor(path)[2]; specs = retained._configured_specs(path, descriptor)
            except (OSError, ValueError, TypeError, KeyError, IndexError):
                return out("descriptor")
            if specs is None or local["binding"] != _binding(descriptor, local["binding"].get("snapshots")):
                return out("generation")
            try:
                value = _run(path, descriptor, _reader(specs))
            except (OSError, ValueError, TypeError, KeyError, IndexError):
                return out("remote-stage")
            if isinstance(value, dict) and set(value) == {"_diagnostic"}:
                item = value["_diagnostic"]
                if isinstance(item, dict) and isinstance(item.get("phase"), str):
                    if item["phase"] == "guest-exit":
                        probe = _run(path, descriptor, _journal_file_probe())
                        if isinstance(probe, dict) and set(probe) == {"phase"} and isinstance(probe.get("phase"), str) and probe["phase"] in _JOURNAL_FILE_PHASES:
                            return out("remote-file-" + probe["phase"])
                        return out("remote-file")
                    return out("remote-encoding" if item["phase"] in {"guest-output-encoding", "guest-output-json", "wire-envelope"} else "remote-decoder")
                return out("remote-decoder")
            if not isinstance(value, dict) or set(value) != {"binding", "archives", "terminal", "absent"}:
                return out("remote-decoder")
            try:
                snapshots = [_validate_archive(a, s, local["bindingSha256"]) for a, s in zip(value["archives"], specs)]
            except (OSError, ValueError, TypeError, KeyError, IndexError):
                return out("archive")
            terminal = {"retirementCorrelationId": _RETIREMENT, "state": "retired", "bindingSha256": local["bindingSha256"], "actionSha256": local["actionSha256"]}
            if value.get("binding") != local or value.get("absent") is not True or snapshots != local["binding"].get("snapshots") or value.get("terminal") != terminal:
                return out("terminal")
            return out("complete")
    except (OSError, ValueError, TypeError, KeyError, IndexError):
        return out("intent")


def finish_diagnose(root: Path | str, inputs: Mapping[str, Any]) -> dict[str, Any]:
    """Read only first-failure diagnosis for the consumed finish attempt."""
    if inputs != {}:
        raise WindowsCp117Cp95TaskRetireError("Fixed finish diagnostic takes no inputs.")
    path = Path(root).resolve(strict=True)
    def out(phase: str) -> dict[str, Any]:
        return {"state": "diagnosed", "phase": phase, "retirementCorrelationId": _RETIREMENT,
                "replayAllowed": False, "nativeActionAllowed": False, "productAction": False}
    try:
        with retained._lease_read_lock(path) as directory:
            local = guards.secure_read(path / _DIR / "intent.json")
            if local is None or set(local) != {"binding", "bindingSha256", "actionSha256"} or not isinstance(local.get("binding"), dict):
                return out("binding")
            descriptor = base._descriptor(path)[2]
            specs = retained._configured_specs(path, descriptor)
            snapshots = local["binding"].get("snapshots")
            if (specs is None or not isinstance(snapshots, list) or len(snapshots) != 5
                    or local["binding"] != _binding(descriptor, snapshots)
                    or local != _plan(local["binding"], specs)[1]
                    or lease._active(directory) is not None):
                return out("binding")
            source = _finish_diagnostic_script(specs, local)
            if not _parse(path, descriptor, source):
                return out("unknown")
            if base._descriptor(path)[2] != descriptor or retained._configured_specs(path, descriptor) != specs or lease._active(directory) is not None:
                return out("unknown")
            value = _run(path, descriptor, source)
            if isinstance(value, dict) and set(value) == {"phase"} and isinstance(value.get("phase"), str) and value["phase"] in _FINISH_DIAGNOSTIC_PHASES:
                return out(value["phase"])
            return out("unknown")
    except (OSError, ValueError, TypeError, KeyError, IndexError):
        return out("unknown")


def workflow(root: Path | str, action: str, inputs: Mapping[str, Any]) -> dict[str, Any]:
    if action == "diagnose":
        return diagnose(root, inputs)
    if inputs != {} or action not in {"preflight", "start", "status", "finish"}:
        raise WindowsCp117Cp95TaskRetireError("Fixed task retirement takes preflight/start/status/finish and no inputs.")
    path = Path(root).resolve(strict=True)
    try:
        with retained._lease_read_lock(path) as directory:
            local = guards.secure_read(path / _DIR / "intent.json")
            if action == "status" or local is not None:
                if action == "finish":
                    return _finish_locked(path, directory)
                return _status_locked(path, directory)
            if action == "finish":
                return _result("blocked", "intent")
            if lease._active(directory) is not None:
                return _result("blocked", "active-lease")
            admitted = _admit(path)
            descriptor, specs, script, intent = admitted
            if action == "preflight":
                return _result("ready", "proof")
            if base._descriptor(path)[2] != descriptor or retained._configured_specs(path, descriptor) != specs or lease._active(directory) is not None:
                return _result("blocked", "generation")
            guards.secure_write_create(path / _DIR / "intent.json", intent)
            # An uncertain submission consumes this intent forever.
            _run(path, descriptor, script)
            return _status_locked(path, directory)
    except _AdmissionBlocked as blocked:
        result = _result("blocked", blocked.phase)
        if blocked.diagnostic is not None:
            result["snapshotDiagnostic"] = blocked.diagnostic
        return result
    except (OSError, ValueError, TypeError, KeyError, IndexError):
        return _result("unknown", "journal")


def preflight(root: Path | str, inputs: Mapping[str, Any]) -> dict[str, Any]:
    return workflow(root, "preflight", inputs)


def start(root: Path | str, inputs: Mapping[str, Any]) -> dict[str, Any]:
    return workflow(root, "start", inputs)


def status(root: Path | str, inputs: Mapping[str, Any]) -> dict[str, Any]:
    return workflow(root, "status", inputs)
