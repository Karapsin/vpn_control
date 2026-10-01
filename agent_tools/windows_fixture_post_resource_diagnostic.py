"""Read-only CP117 diagnosis of the failed server's post-resource gates.

The sole admitted server attempt created its private ``probe-events`` directory
and then exited 1 before it could write ``ready.json``.  This module replays
only the remaining local reads from ``serve`` with the frozen signed Python:
process identity, TLS chain loading, certificate digest stability, and an
ephemeral loopback bind.  It neither starts a server nor writes guest state.
"""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from . import windows_msi_base_prepare as base
from . import windows_update_fixture_server as server
from . import windows_update_fixture_stage as stage


class WindowsFixturePostResourceDiagnosticError(ValueError):
    pass


_CORRELATION = "316e6189-5be0-4ea0-bca1-a3905816d815"
_EXPECTED_INPUT = {"serverCorrelationId": _CORRELATION}
_UNKNOWN = {"state": "unknown", "serverCorrelationId": _CORRELATION,
            "replayAllowed": False, "nativeActionAllowed": False,
            "productAction": False}
_GATES = ("serverProcessIdentity", "tlsLoadCertChain",
          "certificateDigestRecheck", "loopbackEphemeralBind")


# This runs under the exact interpreter already recorded in the immutable
# server intent.  Each exception is deliberately reduced to a finite gate
# result; exception text could expose private credential paths or contents.
_POST_RESOURCE_CODE = r'''import importlib.util,json,pathlib,socket,ssl,sys
stage=pathlib.Path(sys.argv[1]);certificate=pathlib.Path(sys.argv[2]);private_key=pathlib.Path(sys.argv[3]);entry=stage/'server'/'prepare_desktop_update_fixture.py'
out={'version':1,'serverProcessIdentity':'skipped','tlsLoadCertChain':'skipped','certificateDigestRecheck':'skipped','loopbackEphemeralBind':'skipped'}
try:
 sys.path.insert(0,str(entry.parent));spec=importlib.util.spec_from_file_location('fixture_post_resource_diagnostic',entry);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
except Exception:
 print(json.dumps(out,separators=(',',':')));raise SystemExit(0)
try:
 module.server_process_identity();out['serverProcessIdentity']='ok'
except Exception:
 print(json.dumps(out,separators=(',',':')));raise SystemExit(0)
try:
 digest=module.probe_certificate_sha256(certificate);tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);tls.minimum_version=ssl.TLSVersion.TLSv1_2;tls.load_cert_chain(certificate,private_key);out['tlsLoadCertChain']='ok'
except Exception:
 print(json.dumps(out,separators=(',',':')));raise SystemExit(0)
try:
 if module.probe_certificate_sha256(certificate)!=digest:raise ValueError()
 out['certificateDigestRecheck']='ok'
except Exception:
 print(json.dumps(out,separators=(',',':')));raise SystemExit(0)
try:
 listener=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
 try:listener.bind(('127.0.0.1',0))
 finally:listener.close()
 out['loopbackEphemeralBind']='ok'
except Exception:pass
print(json.dumps(out,separators=(',',':')))'''


_PROBE_EVENTS_ACL_CODE = r'''import base64,importlib.util,json,pathlib,subprocess,sys
stage=pathlib.Path(sys.argv[1]);entry=stage/'server'/'prepare_desktop_update_fixture.py'
out={'version':1,'probeEventsAcl':'unknown','aclShape':{'protected':'unknown','aceCount':'unknown','principals':'unknown','rights':'unknown','inheritance':'unknown','originalSid':'unknown','systemSid':'unknown','adminSid':'unknown','unexpectedPrincipal':'unknown'},'identity':{'originalSid':'unknown','stageRecipientSid':'unknown','stateRootThirdSid':'unknown','taskPrincipalSid':'unknown','thirdSidNamespace':'unknown','thirdSidAuthority':'unknown'}}
def recipient(receipt):
 rules=receipt.get('acl') if isinstance(receipt,dict) else None
 if not isinstance(rules,list) or len(rules)!=3:return None
 values=[v.get('sid') for v in rules if isinstance(v,dict) and isinstance(v.get('sid'),str) and v.get('sid') not in {'S-1-5-18','S-1-5-32-544'}]
 return values[0] if len(values)==1 else None
def namespace(value,original):
 if not isinstance(value,str):return 'unknown'
 if value=='S-1-1-0':return 'everyone'
 if value=='S-1-3-0':return 'creator-owner'
 if value=='S-1-3-1':return 'creator-group'
 if value=='S-1-3-4':return 'owner-rights'
 if value=='S-1-5-18':return 'system'
 if value=='S-1-5-19':return 'local-service'
 if value=='S-1-5-20':return 'network-service'
 if value=='S-1-5-4':return 'interactive'
 if value=='S-1-5-11':return 'authenticated-users'
 if value=='S-1-5-12':return 'restricted'
 if value.startswith('S-1-5-80-'):return 'service-sid'
 if value.startswith('S-1-5-5-'):return 'logon-sid'
 if value.startswith('S-1-5-32-'):return 'builtin'
 if value=='S-1-15-2-1':return 'all-application-packages'
 if value.startswith('S-1-15-2-'):return 'app-container'
 if value.startswith('S-1-5-21-'):return 'same-domain-user' if isinstance(original,str) and value.rsplit('-',1)[0]==original.rsplit('-',1)[0] else 'foreign-user'
 return 'other'
def authority(value):
 if not isinstance(value,str):return 'unknown'
 prefix='-'.join(value.split('-')[:3])
 return prefix if prefix in {'S-1-1','S-1-3','S-1-5','S-1-12','S-1-15'} else 'other'
def task_match(candidate):
 if not isinstance(candidate,str):return 'unknown'
 try:
  encoded=base64.b64encode(candidate.encode('utf-16le')).decode()
  script="$ErrorActionPreference='Stop';$candidate=[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('"+encoded+"'));$sid=([Security.Principal.NTAccount]::new('VPNMSIX64\\vpncp117')).Translate([Security.Principal.SecurityIdentifier]).Value;[Console]::Out.Write($(if($sid -ceq $candidate){'yes'}else{'no'}))"
  result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-EncodedCommand',base64.b64encode(script.encode('utf-16le')).decode()],capture_output=True,text=True,timeout=10,check=False)
  return result.stdout.strip() if result.returncode==0 and result.stdout.strip() in {'yes','no'} else 'unknown'
 except Exception:return 'unknown'
try:
 events=stage.parent/'server-state'/'probe-events'
 if not events.exists():out['probeEventsAcl']='absent'
 else:
  sys.path.insert(0,str(entry.parent));spec=importlib.util.spec_from_file_location('fixture_events_acl_diagnostic',entry);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
  receipt=module.windows_acl_receipt(events,private=True,establish=False)
  stage_receipt=module.windows_acl_receipt(stage,private=False,establish=False)
  state_receipt=module.windows_acl_receipt(stage.parent/'server-state',private=True,establish=False)
  rules=receipt['acl'];expected_ids={'S-1-5-18','S-1-5-32-544',@SID@}
  exact_principals=len(rules)==3 and {v.get('sid') for v in rules}==expected_ids
  exact_rights=all(v.get('type')=='Allow' and v.get('inherited') is False and v.get('propagation')==0 and v.get('rights')==0x1F01FF for v in rules)
  exact_inheritance=all(v.get('inheritance')==3 for v in rules)
  actual={v.get('sid') for v in rules}
  unexpected=actual-expected_ids
  category='none' if not unexpected else 'same-domain' if len(unexpected)==1 and next(iter(unexpected)).rsplit('-',1)[0]==@SID@.rsplit('-',1)[0] else 'local-service' if unexpected=={'S-1-5-19'} else 'network-service' if unexpected=={'S-1-5-20'} else 'interactive' if unexpected=={'S-1-5-4'} else 'authenticated-users' if unexpected=={'S-1-5-11'} else 'service-sid' if all(str(v).startswith('S-1-5-80-') for v in unexpected) else 'logon-sid' if all(str(v).startswith('S-1-5-5-') for v in unexpected) else 'builtin' if all(str(v).startswith('S-1-5-32-') for v in unexpected) else 'app-container' if all(str(v).startswith('S-1-15-2-') for v in unexpected) else 'foreign-user' if all(str(v).startswith('S-1-5-21-') for v in unexpected) else 'other'
  out['aclShape']={'protected':'yes' if receipt.get('protected') is True else 'no','aceCount':'three' if len(rules)==3 else 'other','principals':'exact' if exact_principals else 'other','rights':'exact' if exact_rights else 'other','inheritance':'exact' if exact_inheritance else 'other','originalSid':'yes' if @SID@ in actual else 'no','systemSid':'yes' if 'S-1-5-18' in actual else 'no','adminSid':'yes' if 'S-1-5-32-544' in actual else 'no','unexpectedPrincipal':category}
  events_third=recipient(receipt);stage_recipient=recipient(stage_receipt);state_third=recipient(state_receipt)
  out['identity']={'originalSid':'yes' if events_third==@SID@ else 'no' if events_third is not None else 'unknown','stageRecipientSid':'yes' if events_third==stage_recipient else 'no' if events_third is not None and stage_recipient is not None else 'unknown','stateRootThirdSid':'yes' if events_third==state_third else 'no' if events_third is not None and state_third is not None else 'unknown','taskPrincipalSid':task_match(events_third),'thirdSidNamespace':namespace(events_third,@SID@),'thirdSidAuthority':authority(events_third)}
  out['probeEventsAcl']='expected' if receipt.get('isDirectory') is True and out['aclShape']['protected']=='yes' and exact_principals and exact_rights and exact_inheritance else 'mismatch'
except Exception:pass
print(json.dumps(out,separators=(',',':')))'''


_REMOTE_POST_RESOURCE = base._QGA + r'''import time
sock,pid,ticks,python,expected_python_sha,stage,cert,key,code=sys.argv[1:]
def out(value):print(json.dumps(value,separators=(',',':'),sort_keys=True))
phase='binding'
try:
 if not live(sock,pid,ticks):raise ValueError()
 phase='python-digest'
 path64=base64.b64encode(python.encode('utf-16le')).decode()
 ps="$ErrorActionPreference='Stop';$p=[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('"+path64+"'));[Console]::Out.Write((Get-FileHash -LiteralPath $p -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant())"
 checker=call(sock,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',base64.b64encode(ps.encode('utf-16le')).decode()],'capture-output':True})['pid']
 if type(checker) is not int or checker<=0:raise ValueError()
 for _ in range(100):
  checked=call(sock,'guest-exec-status',{'pid':checker})
  if checked.get('exited') is True:break
  if checked.get('exited') is not False:raise ValueError()
  time.sleep(.2)
 else:raise ValueError()
 if checked.get('exitcode')!=0 or checked.get('out-truncated',False) is not False or checked.get('err-truncated',False) is not False:raise ValueError()
 if decode(base64.b64decode(checked.get('out-data',''),validate=True)).strip().lower()!=expected_python_sha:raise ValueError()
 phase='guest-launch'
 child=call(sock,'guest-exec',{'path':python,'arg':['-I','-B','-c',base64.b64decode(code,validate=True).decode(),stage,cert,key],'capture-output':True})['pid']
 if type(child) is not int or child<=0:raise ValueError()
 phase='guest-wait'
 for _ in range(100):
  result=call(sock,'guest-exec-status',{'pid':child})
  if result.get('exited') is True:break
  if result.get('exited') is not False:raise ValueError()
  time.sleep(.2)
 else:raise ValueError()
 phase='guest-exit'
 if result.get('exitcode')!=0:raise ValueError()
 phase='guest-output-truncated'
 if result.get('out-truncated',False) is not False or result.get('err-truncated',False) is not False:raise ValueError()
 phase='guest-output-bytes'
 raw=base64.b64decode(result.get('out-data',''),validate=True)
 if not 0<len(raw)<=1024:raise ValueError()
 phase='guest-parse'
 out({'state':'observed','result':json.loads(decode(raw))})
except Exception:out({'state':'diagnosed','phase':phase})'''


def _inputs(value: Mapping[str, Any]) -> None:
    if not isinstance(value, Mapping) or dict(value) != _EXPECTED_INPUT:
        raise WindowsFixturePostResourceDiagnosticError(
            "Only the fixed CP117 post-resource server attempt can be diagnosed.")


def _bound(root: Path) -> tuple[Any, tuple[Any, ...], Mapping[str, Any], str, str, str, str]:
    intent = server._read_intent(root, _CORRELATION)
    if intent is None:
        raise WindowsFixturePostResourceDiagnosticError("Server intent is absent.")
    request = server._request(intent.get("request", {}))
    config, _target, descriptor = base._descriptor(root)
    env, socket, pid, ticks, sid = descriptor
    if (env != "windows-cp117" or (socket, pid, ticks, sid) !=
            (intent.get("socketPath"), intent.get("qemuPid"), intent.get("startTicks"),
             intent.get("originalSid"))):
        raise WindowsFixturePostResourceDiagnosticError("Server guest generation changed.")
    if request["serverCorrelationId"] != _CORRELATION:
        raise WindowsFixturePostResourceDiagnosticError("Server correlation changed.")
    staged = stage.status(root, {"correlationId": request["stageCorrelationId"]})
    if staged.get("state") != "staged-not-server-ready":
        raise WindowsFixturePostResourceDiagnosticError("Server stage changed.")
    failure = server.diagnose_status(root, {"serverCorrelationId": _CORRELATION})
    if failure != {"state": "observed", "serverCorrelationId": _CORRELATION,
                   "task": "ready", "lastResult": 1, "ready": "absent",
                   "stateContent": "probe-events", "stageAcl": "expected",
                   "stateAcl": "expected", "replayAllowed": False}:
        raise WindowsFixturePostResourceDiagnosticError("Server is not the fixed post-resource failure.")
    python = intent.get("pythonPath")
    python_sha = intent.get("pythonExeSha256")
    if (not isinstance(python, str) or not server._PYTHON_PATH.fullmatch(python)
            or not isinstance(python_sha, str) or not server._HASH.fullmatch(python_sha)):
        raise WindowsFixturePostResourceDiagnosticError("Frozen signed Python changed.")
    content = (r"C:\Users\vpncp117\AppData\Local\VpnControl\mcp-update-fixture-"
               + request["stageCorrelationId"] + r"\content")
    credentials = (r"C:\Users\vpncp117\AppData\Local\VpnControl\mcp-update-credentials-"
                   + request["stageCorrelationId"] + r"\server-")
    return config, descriptor, intent, python, python_sha, content, credentials


def _project(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict) or set(raw) != {"state", "result"} or raw.get("state") != "observed":
        return dict(_UNKNOWN)
    result = raw["result"]
    if (not isinstance(result, dict) or set(result) != {"version", *_GATES}
            or result.get("version") != 1
            or any(result.get(gate) not in {"ok", "failed", "skipped"} for gate in _GATES)):
        return dict(_UNKNOWN)
    prior_ok = True
    for gate in _GATES:
        value = result[gate]
        if prior_ok:
            if value == "skipped":
                return dict(_UNKNOWN)
            prior_ok = value == "ok"
        elif value != "skipped":
            return dict(_UNKNOWN)
    return {"state": "diagnosed", "serverCorrelationId": _CORRELATION,
            **{gate: result[gate] for gate in _GATES}, "replayAllowed": False,
            "nativeActionAllowed": False, "productAction": False}


def diagnose(root: Path | str, inputs: Mapping[str, Any]) -> dict[str, Any]:
    """Observe the fixed failed run without task, file, or persistent-state writes."""
    _inputs(inputs)
    try:
        root_path = Path(root).resolve(strict=True)
        config, descriptor, _intent, python, python_sha, content, credentials = _bound(root_path)
        _env, socket, pid, ticks, _sid = descriptor
        raw = base._remote(config, _REMOTE_POST_RESOURCE,
                           (socket, str(pid), str(ticks), python, python_sha, content,
                            credentials + "cert.pem", credentials + "key.pem",
                            base64.b64encode(_POST_RESOURCE_CODE.encode()).decode()), None, 30)
        outer = json.loads(raw) if raw is not None else None
        if (isinstance(outer, dict) and set(outer) == {"state", "phase"}
                and outer.get("state") == "diagnosed"
                and outer.get("phase") in {"binding", "python-digest", "guest-launch",
                                             "guest-wait", "guest-exit", "guest-output-truncated",
                                             "guest-output-bytes", "guest-parse"}):
            return {"state": "diagnosed", "serverCorrelationId": _CORRELATION,
                    "phase": outer["phase"], "replayAllowed": False,
                    "nativeActionAllowed": False, "productAction": False}
        return _project(outer)
    except (OSError, ValueError, TypeError, KeyError, AttributeError,
            base.WindowsMsiBasePrepareError, server.WindowsUpdateFixtureServerError,
            WindowsFixturePostResourceDiagnosticError):
        return dict(_UNKNOWN)


def diagnose_events_acl(root: Path | str, inputs: Mapping[str, Any]) -> dict[str, Any]:
    """Classify the one failed run's probe-events DACL without changing it."""
    _inputs(inputs)
    try:
        root_path = Path(root).resolve(strict=True)
        config, descriptor, _intent, python, python_sha, content, credentials = _bound(root_path)
        _env, socket, pid, ticks, sid = descriptor
        code = _PROBE_EVENTS_ACL_CODE.replace("@SID@", json.dumps(sid))
        raw = base._remote(config, _REMOTE_POST_RESOURCE,
                           (socket, str(pid), str(ticks), python, python_sha, content,
                            credentials + "cert.pem", credentials + "key.pem",
                            base64.b64encode(code.encode()).decode()), None, 30)
        outer = json.loads(raw) if raw is not None else None
        result = outer.get("result") if isinstance(outer, dict) and outer.get("state") == "observed" else None
        shape = result.get("aclShape") if isinstance(result, dict) else None
        identity = result.get("identity") if isinstance(result, dict) else None
        if (isinstance(result, dict) and set(result) == {"version", "probeEventsAcl", "aclShape", "identity"}
                and result.get("version") == 1
                and result.get("probeEventsAcl") in {"expected", "mismatch", "absent", "unknown"}
                and isinstance(shape, dict)
                and set(shape) == {"protected", "aceCount", "principals", "rights", "inheritance", "originalSid", "systemSid", "adminSid", "unexpectedPrincipal"}
                and shape["protected"] in {"yes", "no", "unknown"}
                and shape["aceCount"] in {"three", "other", "unknown"}
                and all(shape[key] in {"exact", "other", "unknown"}
                        for key in ("principals", "rights", "inheritance"))
                and all(shape[key] in {"yes", "no", "unknown"}
                        for key in ("originalSid", "systemSid", "adminSid"))
                and shape["unexpectedPrincipal"] in {"none", "same-domain", "local-service", "network-service", "interactive", "authenticated-users", "service-sid", "logon-sid", "builtin", "app-container", "foreign-user", "other", "unknown"}
                and isinstance(identity, dict)
                and set(identity) == {"originalSid", "stageRecipientSid", "stateRootThirdSid", "taskPrincipalSid", "thirdSidNamespace", "thirdSidAuthority"}
                and all(identity[key] in {"yes", "no", "unknown"}
                        for key in ("originalSid", "stageRecipientSid", "stateRootThirdSid", "taskPrincipalSid"))
                and identity["thirdSidNamespace"] in {"everyone", "creator-owner", "creator-group", "owner-rights", "system", "local-service", "network-service", "interactive", "authenticated-users", "restricted", "service-sid", "logon-sid", "builtin", "all-application-packages", "app-container", "same-domain-user", "foreign-user", "other", "unknown"}
                and identity["thirdSidAuthority"] in {"S-1-1", "S-1-3", "S-1-5", "S-1-12", "S-1-15", "other", "unknown"}):
            return {"state": "observed", "serverCorrelationId": _CORRELATION,
                    "probeEventsAcl": result["probeEventsAcl"], "aclShape": shape,
                    "identity": identity,
                    "replayAllowed": False,
                    "nativeActionAllowed": False, "productAction": False}
    except (OSError, ValueError, TypeError, KeyError, AttributeError,
            base.WindowsMsiBasePrepareError, server.WindowsUpdateFixtureServerError,
            WindowsFixturePostResourceDiagnosticError):
        pass
    return dict(_UNKNOWN)


def workflow(root: Path | str, action: str, inputs: Mapping[str, Any]) -> dict[str, Any]:
    if action == "events-acl":
        return diagnose_events_acl(root, inputs)
    if action in {"diagnose", "status", "collect"}:
        return diagnose(root, inputs)
    raise WindowsFixturePostResourceDiagnosticError("Unsupported post-resource diagnostic action.")
