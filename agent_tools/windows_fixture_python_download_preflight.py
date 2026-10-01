"""Read-only CP117 reachability preflight for the pinned Python installer.

The installer is intentionally fixed here.  This module only asks the exact
guest whether its normal TLS stack can issue a HEAD request; it never downloads,
writes, or executes the installer.
"""
from __future__ import annotations

import base64
import json
from pathlib import Path
import re
from typing import Any, Mapping

from . import windows_msi_base_prepare as base
from . import windows_update_fixture_server as server


class WindowsFixturePythonDownloadPreflightError(ValueError):
    pass


_URL = "https://www.python.org/ftp/python/3.13.15/python-3.13.15-amd64.exe"
_SHA256 = "edec09c4853aeae9ac36efb8c9f95b6b8e2fee65eee56d9767a8b7c69c574403"
_HASH = re.compile(r"[0-9a-f]{64}\Z")


# This is a constrained PS5-compatible request.  The certificate callback
# preserves normal platform validation while retaining only a public digest.
# Registry inspection prevents a new installer run from racing an already
# provisioned interpreter into this fixed fixture chain.
_POWERSHELL = r'''$ErrorActionPreference='Stop'
$url=@URL@
$sid=@SID@
$roots=@(('Registry::HKEY_USERS\'+$sid+'\Software\Python\PythonCore'),
         'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Python\PythonCore')
$candidateCount=0
foreach($root in $roots){
 if(-not (Test-Path -LiteralPath $root)){continue}
 $versions=@(Get-ChildItem -LiteralPath $root -ErrorAction Stop)
 if($versions.Count -gt 8){throw 'REGISTRY_COUNT'}
 foreach($version in $versions){
  $install=Join-Path $version.PSPath 'InstallPath'
  if(-not (Test-Path -LiteralPath $install)){continue}
  $directory=(Get-Item -LiteralPath $install -ErrorAction Stop).GetValue('')
  if([string]::IsNullOrWhiteSpace($directory)){continue}
  $path=[IO.Path]::GetFullPath((Join-Path $directory 'python.exe'))
  if(($path -like 'C:\Program Files\Python3*\python.exe') -or
     ($path -like 'C:\Users\vpncp117\AppData\Local\Programs\Python\Python3*\python.exe')){
   $item=Get-Item -LiteralPath $path -Force -ErrorAction Stop
   if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'INTERPRETER_REPARSE'}
   $candidateCount++
  }
 }
}
if($candidateCount -ne 0){throw 'PYTHON_CANDIDATE_PRESENT'}
$script:tls='unknown'
[Net.ServicePointManager]::ServerCertificateValidationCallback = {
 param($sender,$certificate,$chain,$errors)
 if($null -ne $certificate){
  $sha=[Security.Cryptography.SHA256]::Create()
  try{$script:tls=([BitConverter]::ToString($sha.ComputeHash($certificate.GetRawCertData()))).Replace('-','').ToLowerInvariant()}
  finally{$sha.Dispose()}
 }
 return $errors -eq [Net.Security.SslPolicyErrors]::None
}
$status='unknown';$length='unknown';$classification='unknown';$phase='network-failed'
try{
 $request=[Net.HttpWebRequest]::Create($url)
 $request.Method='HEAD';$request.AllowAutoRedirect=$false;$request.Timeout=30000;$request.ReadWriteTimeout=30000
 $response=$request.GetResponse()
 try{$status=[int]$response.StatusCode;$length=if($response.ContentLength -ge 0){[int64]$response.ContentLength}else{'unknown'};if($status -eq 200){$classification='reachable';$phase='reachable'}else{$classification='unreachable';$phase='http-status'}}
 finally{$response.Close()}
}catch [Net.WebException]{
 if($null -ne $_.Exception.Response){$status=[int]$_.Exception.Response.StatusCode;$length=if($_.Exception.Response.ContentLength -ge 0){[int64]$_.Exception.Response.ContentLength}else{'unknown'};$_.Exception.Response.Close();$classification='unreachable';$phase='http-status'}
 elseif($_.Exception.Status -eq [Net.WebExceptionStatus]::Timeout){$phase='network-timeout'}
 elseif($_.Exception.Status -in @([Net.WebExceptionStatus]::TrustFailure,[Net.WebExceptionStatus]::SecureChannelFailure)){$phase='tls-validation-failed'}
 else{$phase='network-failed'}
}
([pscustomobject]@{version=2;classification=$classification;phase=$phase;tlsSha256=$script:tls;statusCode=$status;contentLength=$length;candidateCount=$candidateCount}|ConvertTo-Json -Compress)
'''


_REMOTE = base._QGA + r'''import time
root,env,lease_id,stage_corr,server_corr,source,receipt_id,base_id,target_id,sock,pid,ticks,encoded=sys.argv[1:]
def out(value):print(json.dumps(value,separators=(',',':'),sort_keys=True))
phase='guest-binding-failed'
try:
 if env!='windows-cp117' or not live(sock,pid,ticks):raise ValueError()
 group=os.path.join(root,env,'windows-cp117-campaign')
 for path in (root,os.path.join(root,env),group):
  info=os.lstat(path)
  if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError()
 fd=os.open(os.path.join(group,'active.json'),os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
 with os.fdopen(fd,encoding='utf-8') as file:record=json.load(file)
 expected={'host':'archlinux','environment':'windows-cp117','leaseId':lease_id,'operator':'windows-base','sourceSha':source,'fixtureReceiptArtifactId':receipt_id,'baseMsiArtifactId':base_id,'targetMsiArtifactId':target_id,'socketPath':sock,'qemuPid':int(pid),'startTicks':int(ticks)}
 if set(record)!={'version','identity','sequence','state','role','correlationId','server','credentials','lastEvidenceSha256','lastOutcome'} or record.get('version')!=1 or record.get('state')!='active' or record.get('role') is not None or record.get('correlationId') is not None or record.get('server')!='stopped' or record.get('credentials')!='ready' or record.get('identity')!=expected:raise ValueError()
 phase='qga-submit-failed'
 submitted=call(sock,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',encoded],'capture-output':True})
 child=submitted.get('pid') if isinstance(submitted,dict) else None
 if type(child) is not int or child<=0:raise ValueError()
 phase='qga-status-failed'
 for _ in range(160):
  result=call(sock,'guest-exec-status',{'pid':child})
  if result.get('exited') is True:break
  time.sleep(.2)
 else:
  out({'state':'observed','endpoint':{'version':2,'classification':'unknown','phase':'qga-status-timeout','tlsSha256':'unknown','statusCode':'unknown','contentLength':'unknown','candidateCount':0}});raise SystemExit
 if result.get('exitcode')!=0 or result.get('out-truncated') is not False or result.get('err-truncated') is not False:
  out({'state':'observed','endpoint':{'version':2,'classification':'unknown','phase':'guest-script-exit','tlsSha256':'unknown','statusCode':'unknown','contentLength':'unknown','candidateCount':0}});raise SystemExit
 phase='response-invalid'
 raw=base64.b64decode(result.get('out-data',''),validate=True)
 if not 0<len(raw)<=4096:raise ValueError()
 out({'state':'observed','endpoint':json.loads(decode(raw))})
except SystemExit:pass
except Exception:
 out({'state':'observed','endpoint':{'version':2,'classification':'unknown','phase':phase,'tlsSha256':'unknown','statusCode':'unknown','contentLength':'unknown','candidateCount':0}})
'''


_PHASES = frozenset({"reachable", "http-status", "network-timeout", "tls-validation-failed",
                     "network-failed", "guest-script-exit", "guest-binding-failed", "qga-submit-failed",
                     "qga-status-failed", "qga-status-timeout", "response-invalid",
                     "remote-transport-unknown", "admission-failed", "descriptor-failed"})


def _endpoint(value: object) -> dict[str, object] | None:
    if not isinstance(value, Mapping) or set(value) != {"version", "classification", "phase", "tlsSha256", "statusCode", "contentLength", "candidateCount"}:
        return None
    classification = value.get("classification")
    phase = value.get("phase")
    tls = value.get("tlsSha256")
    status = value.get("statusCode")
    length = value.get("contentLength")
    if (value.get("version") != 2 or classification not in {"reachable", "unreachable", "unknown"}
            or phase not in _PHASES
            or not isinstance(tls, str) or (tls != "unknown" and not _HASH.fullmatch(tls))
            or (type(status) is not int and status != "unknown")
            or (type(status) is int and not 100 <= status <= 599)
            or (type(length) is not int and length != "unknown")
            or (type(length) is int and not 0 <= length <= 1_073_741_824)
            or value.get("candidateCount") != 0):
        return None
    if classification == "reachable" and (phase != "reachable" or status != 200 or tls == "unknown"):
        return None
    if classification == "unreachable" and phase != "http-status":
        return None
    if classification == "unknown" and (phase in {"reachable", "http-status"} or status != "unknown" or length != "unknown"):
        return None
    return {"classification": classification, "phase": phase, "tlsSha256": tls,
            "statusCode": status, "contentLength": length}


def preflight(root: Path | str, value: Mapping[str, Any]) -> dict[str, object]:
    """Return a finite, source-bound endpoint fact without downloading Python."""
    root = Path(root).resolve(strict=True)
    request = server._request(value)
    # Both observations are deliberately before the external HEAD.  The first
    # admission prevents even the inventory read until the credential/server
    # boundary is ready; the second binds the final request after that read.
    base_result = {"state": "observed", "leaseId": request["leaseId"],
                   "stageCorrelationId": request["stageCorrelationId"], "serverCorrelationId": request["serverCorrelationId"],
                   "candidateCount": 0, "serverReady": False, "installerSha256": _SHA256}
    try:
        server._admit_campaign(root, request, require_credentials=True)
        if server._python_candidates(root, request):
            raise WindowsFixturePythonDownloadPreflightError("CP117 Python candidate is already present.")
        server._admit_campaign(root, request, require_credentials=True)
    except (ValueError, OSError, KeyError, TypeError, AttributeError):
        return {**base_result, "classification": "unknown", "phase": "admission-failed",
                "tlsSha256": "unknown", "statusCode": "unknown", "contentLength": "unknown"}
    try:
        config, target, (environment, socket, pid, ticks, sid) = base._descriptor(root)
    except (ValueError, OSError, KeyError, TypeError, AttributeError):
        return {**base_result, "classification": "unknown", "phase": "descriptor-failed",
                "tlsSha256": "unknown", "statusCode": "unknown", "contentLength": "unknown"}
    if environment != "windows-cp117":
        return {**base_result, "classification": "unknown", "phase": "descriptor-failed",
                "tlsSha256": "unknown", "statusCode": "unknown", "contentLength": "unknown"}
    script = _POWERSHELL.replace("@URL@", server.public._ps_literal(_URL)).replace("@SID@", server.public._ps_literal(sid))
    encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
    raw = base._remote(config, _REMOTE, (str(target.fixture_transfer_root), environment, request["leaseId"],
                       request["stageCorrelationId"], request["serverCorrelationId"], request["sourceSha"],
                       request["fixtureReceiptArtifactId"], request["baseMsiArtifactId"],
                       request["targetMsiArtifactId"], socket, str(pid), str(ticks), encoded), None, 40)
    try:
        observed = json.loads(raw) if raw is not None else None
        endpoint = _endpoint(observed.get("endpoint")) if isinstance(observed, dict) and set(observed) == {"state", "endpoint"} and observed.get("state") == "observed" else None
    except (TypeError, ValueError):
        endpoint = None
    if endpoint is None:
        phase = "remote-transport-unknown" if raw is None else "response-invalid"
        endpoint = {"classification": "unknown", "phase": phase,
                    "tlsSha256": "unknown", "statusCode": "unknown", "contentLength": "unknown"}
    return {**base_result, **endpoint}
