"""One-shot public Android runtime acceptance over an admitted endpoint fixture.

The adapter has no generic device command surface.  It binds its fixed SOCKS
location and fixed HTTPS validation URL to an endpoint admission already holding
the parent device lease.  An unknown child is deliberately retained: it cannot
be replayed and its activity receipt keeps endpoint cleanup blocked.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Any

from agent_tools import (android_cli_stage, android_document_acceptance,
                         android_endpoint_admission, android_native_fixture_lifecycle,
                         android_observation,
                         ssh_transport)

_UUID = re.compile(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_FIXED_LOCATION = "socks://127.0.0.1:18081#NativeFixture"
_FIXED_URL = "https://localhost:18080/traffic"
_DEVICE_APIS = {"api29": 29, "api35": 35}


def _directory(root: Path) -> Path:
    path = root / ".rag_index" / "android-runtime-acceptance"
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError("Android runtime journal directory is unsafe")
    return path


def _path(root: Path | str, correlation_id: str) -> Path:
    if not isinstance(correlation_id, str) or not _UUID.fullmatch(correlation_id):
        raise ValueError("Android runtime correlation must be a canonical UUID")
    return _directory(Path(root).resolve()) / (correlation_id + ".json")


def _status_path(root: Path | str, correlation_id: str) -> Path | None:
    """Locate an existing journal without creating status-side state."""
    if not isinstance(correlation_id, str) or not _UUID.fullmatch(correlation_id):
        raise ValueError("Android runtime correlation must be a canonical UUID")
    directory = Path(root).resolve() / ".rag_index" / "android-runtime-acceptance"
    try:
        info = directory.lstat()
    except FileNotFoundError:
        return None
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or
            info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700):
        raise ValueError("Android runtime journal directory is unsafe")
    return directory / (correlation_id + ".json")


def _save(root: Path | str, intent: dict[str, Any]) -> None:
    path = _path(root, intent["correlationId"])
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(json.dumps(intent, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n")
        output.flush(); os.fsync(output.fileno())
    directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try: os.fsync(directory)
    finally: os.close(directory)


def _claim_parent(root: Path | str, intent: dict[str, Any]) -> str:
    """Keep a second runtime correlation from submitting over unresolved work."""
    directory = _directory(Path(root).resolve())
    path = directory / ("parent-" + intent["parentCorrelationId"] + ".lease")
    record = {"parentCorrelationId": intent["parentCorrelationId"],
              "runtimeCorrelationId": intent["correlationId"]}
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600)
    raw = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
    with os.fdopen(fd, "wb") as output:
        output.write(raw)
        output.flush(); os.fsync(output.fileno())
    descriptor = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try: os.fsync(descriptor)
    finally: os.close(descriptor)
    return hashlib.sha256(raw).hexdigest()


def _load(root: Path | str, correlation_id: str) -> dict[str, Any] | None:
    try:
        path = _status_path(root, correlation_id)
    except ValueError:
        raise
    if path is None:
        return None
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as source:
            info = os.fstat(source.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or
                    stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
                return None
            raw = source.read(8193)
        if len(raw) > 8192:
            return None
        value = json.loads(raw)
        return value if isinstance(value, dict) and value.get("correlationId") == correlation_id else None
    except (OSError, ValueError, TypeError):
        return None


def _reply(state: str, correlation_id: str, reason: str | None = None, **extra: Any) -> dict[str, Any]:
    return {"ok": state in {"submitted", "running", "complete"}, "state": state,
            "reason": reason, "correlationId": correlation_id, "replayAllowed": False,
            "nativeMutationAllowed": False, **extra}


# This record is consumed by android_endpoint_admission before it may remove the
# fixture CA/reverses.  It is intentionally separate from the worker job so an
# uncertain submit remains visible to the parent cleanup guard.
_ACTIVITY_CREATE = r'''
import json,os,pathlib,stat,sys
root,encoded=sys.argv[1:]
base=pathlib.Path(root); value=json.loads(encoded); corr=value['runtimeCorrelationId']
def out(state,reason=None): print(json.dumps({'state':state,'reason':reason,'correlationId':corr},separators=(',',':')))
try:
 info=base.lstat()
 if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700: raise ValueError()
 path=base/('android-runtime-acceptance-'+corr+'.json')
 raw=(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
 with os.fdopen(fd,'wb') as output: output.write(raw); output.flush(); os.fsync(output.fileno())
 directory=os.open(base,os.O_RDONLY|getattr(os,'O_DIRECTORY',0)); os.fsync(directory); os.close(directory)
 out('created')
except (OSError,ValueError,KeyError,TypeError): out('unknown','activity_create_unknown')
'''

_REMOTE = "stage_status_source=" + repr(android_cli_stage._STATUS) + "\n" + android_observation._canonical_cli_environment_source() + r'''
import hashlib,json,os,pathlib,stat,subprocess,sys,uuid
adb,cli,serial,avd,device_alias,api,root,correlation,owner,opening_revision,package_hash,parent_correlation,campaign,parent_lease_sha256,stage_correlation,stage_manifest,stage_rpm,launcher_hash,desktop_jar_hash,https_port,socks_port=sys.argv[1:]
job=pathlib.Path(root)/('android-runtime-job-'+correlation)
def fail(reason): print(json.dumps({'state':'unknown','reason':reason},separators=(',',':'))); raise SystemExit(0)
def invoke(argv,timeout=120,limit=1048576,env=None):
 try: done=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=timeout,env=env,check=False)
 except (OSError,subprocess.TimeoutExpired): fail('command_unknown')
 if done.returncode or len(done.stdout)>limit: fail('command_failed')
 try: return done.stdout.decode('utf-8','strict').strip()
 except UnicodeError: fail('command_encoding')
def shell(*words): return invoke([adb,'-s',serial,'shell','-T',*words],timeout=30,limit=65536)
def guard_device():
 if shell('id','-u')!='2000' or shell('getprop','ro.build.version.sdk')!=api or {x for x in (shell('getprop','ro.kernel.qemu.avd_name'),shell('getprop','ro.boot.qemu.avd_name')) if x}!={avd}: fail('device_changed')
 paths=[x.removeprefix('package:') for x in shell('pm','path','com.kardinal.vpncontrol').splitlines() if x.startswith('package:') and x.endswith('/base.apk')]
 if len(paths)!=1 or not paths[0].startswith('/data/app/') or shell('sha256sum',paths[0]).split()!=[package_hash,paths[0]]: fail('package_changed')
 if hashlib.sha256(pathlib.Path(cli).read_bytes()).hexdigest()!=launcher_hash: fail('cli_stage_changed')
 try:
  stage_raw=invoke(['python3','-I','-B','-c','exec('+repr(stage_status_source)+')',root,stage_correlation,stage_manifest],timeout=120,limit=16384)
  stage=json.loads(stage_raw); receipt=stage.get('receipt') if isinstance(stage,dict) else None
 except (ValueError,TypeError): fail('cli_stage_changed')
 if not isinstance(receipt,dict) or stage.get('state')!='published' or stage.get('correlationId')!=stage_correlation or receipt.get('cliPath')!=cli or receipt.get('manifestSha256')!=stage_manifest or receipt.get('rpmSha256')!=stage_rpm or receipt.get('launcherSha256')!=launcher_hash or receipt.get('desktopJarSha256')!=desktop_jar_hash: fail('cli_stage_changed')
 routes={}
 for line in invoke([adb,'-s',serial,'reverse','--list'],timeout=30,limit=16384).splitlines():
  fields=line.split()
  if len(fields)!=3 or not fields[1].startswith('tcp:') or not fields[2].startswith('tcp:'): fail('reverse_shape_changed')
  try: port=int(fields[1][4:]); target=int(fields[2][4:])
  except ValueError: fail('reverse_shape_changed')
  if port in routes: fail('reverse_shape_changed')
  routes[port]=target
 if routes!={18080:int(https_port),18081:int(socks_port)}: fail('endpoint_routes_changed')
 lease=pathlib.Path(root)/('android-native-device-'+device_alias+'.lease')
 try:
  fd=os.open(lease,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
  with os.fdopen(fd,'rb') as source:
   info=os.fstat(source.fileno())
   if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1: fail('parent_lease_changed')
   raw=source.read(4097); after=os.fstat(source.fileno())
  if len(raw)>4096 or (info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns): fail('parent_lease_changed')
  lease_value=json.loads(raw)
 except (OSError,ValueError,UnicodeError): fail('parent_lease_changed')
 if lease_value!={'owner':'android-endpoint','correlationId':parent_correlation,'host':'archlinux','device':device_alias}: fail('parent_lease_changed')
if {'api29':'29','api35':'35'}.get(device_alias)!=api or not avd: fail('device_profile_invalid')
guard_device()
environment=public_cli_environment(adb,pathlib.Path(cli))
last_revision=None
def public(*words,mutation=False,timeout=180,limit=1048576):
 # Every mutation takes its owner/revision from a fresh public STATUS and repeats all external binding checks.
 global last_revision
 if mutation:
  guard_device()
  fresh=public('status')
  revision=fresh.get('configurationRevision')
  if type(revision) is not int or revision!=last_revision: fail('fresh_revision_changed')
  words=('--controller-id',owner,'--if-revision',str(revision),*words)
 raw=invoke([cli,'--json','--android','--serial',serial,'--timeout-seconds',str(timeout),*words],timeout=timeout+15,limit=limit,env=environment)
 try: value=json.loads(raw)
 except ValueError: fail('public_result_invalid')
 if not isinstance(value,dict) or value.get('ok') is not True or value.get('final') is not True or value.get('code')!='OK' or value.get('controllerId')!=owner or not isinstance(value.get('configurationRevision'),int) or not isinstance(value.get('data'),dict): fail('public_result_invalid')
 if mutation:
  if value['configurationRevision']<last_revision: fail('mutation_revision_invalid')
  last_revision=value['configurationRevision']
 return value
def data(*words,**kw): return public(*words,**kw)['data']
def routing_rules(value):
 # `routing show` contains generated export metadata (for example
 # `exported_at`), which must never be used as restore evidence.  Retain the
 # full canonical rules document and compare only that validated semantic part.
 # Public `routing show` returns its document under `data.routing`; do not
 # confuse that wrapper with an export document or accept a partial rules map.
 routing=value.get('routing') if isinstance(value,dict) else None
 if not isinstance(routing,dict) or routing.get('type')!='vpn_control_routing_rules' or routing.get('version')!=7: fail('routing_shape_invalid')
 rules=routing.get('rules')
 if (not isinstance(rules,dict) or set(rules)!={'ignore_rules','block_quic_udp_443','proxy_packages','direct_domain_suffixes'} or
     type(rules['ignore_rules']) is not bool or type(rules['block_quic_udp_443']) is not bool or
     not isinstance(rules['proxy_packages'],list) or not isinstance(rules['direct_domain_suffixes'],list) or
     any(not isinstance(item,str) for item in rules['proxy_packages']) or any(not isinstance(item,str) for item in rules['direct_domain_suffixes'])): fail('routing_shape_invalid')
 try: raw=json.dumps(rules,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode('utf-8')
 except (TypeError,ValueError,UnicodeError): fail('routing_shape_invalid')
 if not 0<len(raw)<=16777216: fail('routing_rules_oversized')
 return raw
def retain_opening_rules(raw):
 path=job/'opening-routing-rules.json'
 try:
  fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
  with os.fdopen(fd,'wb') as out: out.write(raw); out.flush(); os.fsync(out.fileno())
  d=os.open(job,os.O_RDONLY|getattr(os,'O_DIRECTORY',0)); os.fsync(d); os.close(d)
 except OSError: fail('opening_routing_backup_failed')
 return hashlib.sha256(raw).hexdigest()
def retained_opening_hash():
 path=job/'opening-routing-rules.json'
 try:
  fd=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
  with os.fdopen(fd,'rb') as source:
   info=os.fstat(source.fileno())
   if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1 or not 0<info.st_size<=16777216: fail('opening_routing_backup_invalid')
   raw=source.read(16777217); after=os.fstat(source.fileno())
  if len(raw)!=info.st_size or (info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns): fail('opening_routing_backup_invalid')
  value=json.loads(raw)
  if not isinstance(value,dict) or json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode('utf-8')!=raw: fail('opening_routing_backup_invalid')
  return hashlib.sha256(raw).hexdigest()
 except (OSError,ValueError,TypeError,UnicodeError): fail('opening_routing_backup_invalid')
def admitted_mode(configured):
 raw=invoke([cli,'--android','--serial',serial,'--timeout-seconds','90','diagnostics','export','--output','-'],timeout=105,limit=1048576,env=environment)
 fields={}; section=False
 for line in raw.splitlines():
  if line=='[runtime]':
   if section: fail('runtime_diagnostic_ambiguous')
   section=True; continue
  if section and line.startswith('[') and line.endswith(']'): section=False; continue
  if section and '=' in line:
   key,value=line.split('=',1)
   if key in ('mode','vpn_permission_granted','is_vpn_running'):
    if key in fields: fail('runtime_diagnostic_ambiguous')
    fields[key]=value
 if configured=='vpn' and fields=={'mode':'VPN','vpn_permission_granted':'true','is_vpn_running':'false'}: return 'vpn-authorized'
 if configured=='proxy-only' and fields=={'mode':'PROXY_ONLY','vpn_permission_granted':'false','is_vpn_running':'false'}: return 'proxy-only'
 fail('runtime_mode_unadmitted')
def phase(name):
 allowed={'opening','added','selected','on','find-best','stats','off','deleted','closing'}
 if name not in allowed: fail('phase_invalid')
 path=job/'phase.json'; temp=job/'phase.json.tmp'; raw=json.dumps({'phase':name},separators=(',',':')).encode()+b'\n'
 try:
  fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
  with os.fdopen(fd,'wb') as out: out.write(raw); out.flush(); os.fsync(out.fileno())
  os.replace(temp,path)
  d=os.open(job,os.O_RDONLY|getattr(os,'O_DIRECTORY',0)); os.fsync(d); os.close(d)
 except OSError: fail('phase_journal_failed')
opening=public('status'); opening_status=opening['data']; last_revision=opening.get('configurationRevision')
if last_revision!=int(opening_revision): fail('opening_revision_changed')
source=data('source','show'); settings=data('settings','show'); locations=data('locations','list'); routing=data('routing','show',limit=16777216)
if opening_status.get('runtimeRunning') is not False or opening_status.get('runtimeObservation')!='stopped' or opening_status.get('configuredMode') not in ('vpn','proxy-only') or source.get('mode')!='current-locations' or source.get('subscriptionId') is not None or locations.get('locations')!=[] or opening_status.get('selectedLocationId') is not None or opening_status.get('activeLocationId') is not None: fail('baseline_not_empty_off')
admission_mode=admitted_mode(opening_status['configuredMode'])
opening_routing_hash=retain_opening_rules(routing_rules(routing))
phase('opening')
location_file=job/'fixture-location.txt'; location_file.write_text('socks://127.0.0.1:18081#NativeFixture\n',encoding='utf-8')
public('locations','add','--input',str(location_file),mutation=True); phase('added')
public('source','set','current-locations',mutation=True)
public('locations','select','1',mutation=True); phase('selected')
original_url=settings.get('validation.test-url')
if not isinstance(original_url,str): fail('settings_shape_invalid')
public('settings','set','validation.test-url','https://localhost:18080/traffic',mutation=True)
public('on',mutation=True,timeout=180); active=data('status')
if active.get('runtimeRunning') is not True or not isinstance(active.get('runtimeId'),str) or active.get('activeLocationId') is None or active.get('activeMode')!=opening_status.get('configuredMode'): fail('runtime_not_active')
phase('on')
found=public('find-best',mutation=True,timeout=240); after=data('status')
if after.get('runtimeRunning') is not True or after.get('activeLocationId') is None or after.get('selectedLocationId') is None or after.get('activeMode')!=opening_status.get('configuredMode'): fail('find_best_not_active')
phase('find-best')
stats=data('stats')
if not isinstance(stats,dict) or stats.get('running') is not True or stats.get('runtimeId')!=after.get('runtimeId') or stats.get('activeMode')!=after.get('activeMode'): fail('stats_invalid')
phase('stats')
public('off',mutation=True,timeout=180); stopped=data('status')
if stopped.get('runtimeRunning') is not False or stopped.get('activeLocationId') is not None: fail('runtime_not_off')
phase('off')
public('settings','set','validation.test-url',original_url,mutation=True)
public('locations','delete','1',mutation=True,timeout=180); phase('deleted')
closing_status=data('status'); closing_source=data('source','show'); closing_settings=data('settings','show'); closing_locations=data('locations','list'); closing_routing=data('routing','show',limit=16777216)
if closing_status.get('runtimeRunning') is not False or closing_status.get('activeLocationId') is not None or closing_status.get('selectedLocationId') is not None or closing_source!=source or closing_settings!=settings or closing_locations.get('locations')!=[] or hashlib.sha256(routing_rules(closing_routing)).hexdigest()!=opening_routing_hash or retained_opening_hash()!=opening_routing_hash: fail('restoration_failed')
phase('closing')
closing=public('status')
if closing.get('configurationRevision')!=last_revision or closing.get('data')!=closing_status: fail('closing_owner_or_revision_changed')
result={'state':'complete','sourcePackageSha256':package_hash,'parentCorrelationId':parent_correlation,'campaignId':campaign,'opening':{'owner':owner,'revision':int(opening_revision)},'closingOwner':owner,'closingRevision':last_revision,'selectedProxy':True,'outboundEvidence':True,'statsObserved':True,'admittedMode':admission_mode,'restoration':{'settings':True,'source':True,'routing':True,'locationsEmpty':True,'selectedNull':True,'activeNull':True,'runtimeOff':True}}
terminal={'schema':1,'kind':'android-runtime-acceptance','state':'stopped','parentCorrelationId':parent_correlation,'runtimeCorrelationId':correlation,'campaignId':campaign,'sourcePackageSha256':package_hash,'expectedOwner':owner,'parentLeaseSha256':parent_lease_sha256,'closingOwner':owner,'closingRevision':last_revision,'admittedMode':admission_mode,'restoration':result['restoration'],'terminal':True}
try:
 path=pathlib.Path(root)/('android-runtime-acceptance-'+correlation+'.terminal.json')
 raw=(json.dumps(terminal,sort_keys=True,separators=(',',':'))+'\n').encode()
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
 with os.fdopen(fd,'wb') as output: output.write(raw); output.flush(); os.fsync(output.fileno())
 directory=os.open(root,os.O_RDONLY|getattr(os,'O_DIRECTORY',0)); os.fsync(directory); os.close(directory)
except OSError: fail('terminal_journal_failed')
print(json.dumps(result,separators=(',',':')))
'''


def _worker(args: list[str]) -> str:
    return android_document_acceptance._worker(_REMOTE, args).replace("android-document-job-", "android-runtime-job-")


_STATUS = r'''
import json,os,pathlib,stat,sys
root,correlation,expected_json=sys.argv[1:]
def emit(state,reason=None,**extra):
 print(json.dumps({'state':state,'reason':reason,'correlationId':correlation,**extra},separators=(',',':'))); raise SystemExit(0)
job=pathlib.Path(root)/('android-runtime-job-'+correlation)
try:
 info=job.lstat()
 if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700: emit('unknown','unsafe_job')
 def private(name,limit=16384):
  fd=os.open(job/name,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
  with os.fdopen(fd,'rb') as source:
   info=os.fstat(source.fileno())
   if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1: emit('unknown','unsafe_file')
   raw=source.read(limit+1)
  if len(raw)>limit: emit('unknown','oversized_file')
  return json.loads(raw)
 intent=private('intent.json')
 if intent!=json.loads(expected_json): emit('unknown','intent_mismatch')
 if type(intent.get('api')) is not int or {'api29':29,'api35':35}.get(intent.get('device'))!=intent.get('api'): emit('unknown','intent_profile_invalid')
 activity_path=pathlib.Path(root)/('android-runtime-acceptance-'+correlation+'.json')
 fd=os.open(activity_path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
 with os.fdopen(fd,'rb') as source:
  info=os.fstat(source.fileno()); raw=source.read(8193)
 expected_activity={'schema':1,'kind':'android-runtime-acceptance','state':'running','parentCorrelationId':intent.get('parentCorrelationId'),'runtimeCorrelationId':correlation,'campaignId':intent.get('campaignId'),'sourcePackageSha256':intent.get('packageSha256'),'expectedOwner':intent.get('expectedOwner'),'parentLeaseSha256':intent.get('parentLeaseSha256'),'endpoint':{'state':'ready','correlationId':intent.get('parentCorrelationId'),'sourcePackageSha256':intent.get('packageSha256'),'owner':intent.get('expectedOwner')},'fixture':{'campaignId':intent.get('campaignId'),'deviceUid':'2000','api':intent.get('api'),'avd':intent.get('expectedAvd')}}
 if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1 or len(raw)>8192 or json.loads(raw)!=expected_activity: emit('unknown','activity_binding_invalid')
 identity=private('identity.json'); pid=identity.get('pid'); ticks=identity.get('startTicks')
 if type(pid) is not int or type(ticks) is not int or pid<=0 or ticks<=0: emit('unknown','identity_invalid')
 try: receipt=private('result.json')
 except FileNotFoundError: receipt=None
 if receipt is not None:
  value=receipt.get('result') if receipt.get('state')=='complete' else None
  restore={'settings':True,'source':True,'routing':True,'locationsEmpty':True,'selectedNull':True,'activeNull':True,'runtimeOff':True}
  if not isinstance(value,dict) or value.get('state')!='complete' or value.get('sourcePackageSha256')!=intent.get('packageSha256') or value.get('parentCorrelationId')!=intent.get('parentCorrelationId') or value.get('campaignId')!=intent.get('campaignId') or value.get('opening')!={'owner':intent.get('expectedOwner'),'revision':intent.get('expectedRevision')} or value.get('admittedMode') not in {'vpn-authorized','proxy-only'} or value.get('closingOwner')!=intent.get('expectedOwner') or type(value.get('closingRevision')) is not int or value['closingRevision']<=intent.get('expectedRevision') or value.get('selectedProxy') is not True or value.get('outboundEvidence') is not True or value.get('statsObserved') is not True or value.get('restoration')!=restore: emit('unknown','terminal_binding_invalid',identity=identity)
  terminal=pathlib.Path(root)/('android-runtime-acceptance-'+correlation+'.terminal.json')
  fd=os.open(terminal,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
  with os.fdopen(fd,'rb') as source:
   info=os.fstat(source.fileno()); raw=source.read(4097)
  expected={'schema':1,'kind':'android-runtime-acceptance','state':'stopped','parentCorrelationId':intent.get('parentCorrelationId'),'runtimeCorrelationId':correlation,'campaignId':intent.get('campaignId'),'sourcePackageSha256':intent.get('packageSha256'),'expectedOwner':intent.get('expectedOwner'),'parentLeaseSha256':intent.get('parentLeaseSha256'),'closingOwner':intent.get('expectedOwner'),'closingRevision':value.get('closingRevision'),'admittedMode':value.get('admittedMode'),'restoration':restore,'terminal':True}
  if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1 or len(raw)>4096 or json.loads(raw)!=expected: emit('unknown','activity_terminal_invalid',identity=identity)
  emit('complete',None,identity=identity,receipt=receipt)
 try:
  fields=pathlib.Path('/proc/'+str(pid)+'/stat').read_text(encoding='ascii').rsplit(')',1)[1].split(); live=fields[0]!='Z' and int(fields[19])==ticks
 except (OSError,ValueError,IndexError): live=False
 emit('running' if live else 'unknown',None if live else 'missing_worker_receipt',identity=identity)
except FileNotFoundError: emit('unknown','missing_job_or_intent')
except (OSError,ValueError,TypeError,KeyError): emit('unknown','status_unavailable')
'''

def _endpoint_intent(root: Path, endpoint_correlation_id: str) -> dict[str, Any]:
    intent = android_endpoint_admission._status_intent(root, endpoint_correlation_id)
    if not isinstance(intent, dict) or not isinstance(intent.get("remote"), dict):
        raise ValueError("Android runtime endpoint intent is unavailable")
    ready = android_endpoint_admission.status(root, endpoint_correlation_id)
    remote = intent["remote"]
    campaign = android_native_fixture_lifecycle.status(root, remote.get("campaignId")) if isinstance(remote.get("campaignId"), str) else {}
    counts = campaign.get("eventCounts") if isinstance(campaign, dict) else None
    if (ready.get("state") != "ready" or campaign.get("state") != "running" or
            not isinstance(counts, dict) or
            set(counts) != {"socksConnected", "socksRejected", "health", "traffic", "subscription"} or
            any(type(value) is not int or value < 0 for value in counts.values()) or
            intent.get("host") != "archlinux" or not isinstance(intent.get("device"), str) or intent.get("device") not in _DEVICE_APIS or
            intent.get("correlationId") != endpoint_correlation_id or
            not isinstance(intent.get("sourceSha"), str) or not re.fullmatch(r"[0-9a-f]{40}", intent["sourceSha"]) or
            not isinstance(remote.get("packageSha256"), str) or not _SHA.fullmatch(remote["packageSha256"]) or
            not isinstance(remote.get("owner"), str) or not remote["owner"] or type(remote.get("revision")) is not int or
            not isinstance(remote.get("campaignId"), str) or not _UUID.fullmatch(remote["campaignId"])):
        raise ValueError("Android runtime endpoint is not exactly ready")
    bound = dict(intent)
    bound["fixtureEventCounts"] = counts
    return bound


def _configured_profile(config: Any, endpoint: dict[str, Any]) -> dict[str, Any]:
    """Bind the endpoint's immutable device identity to one configured emulator."""
    host, device = endpoint.get("host"), endpoint.get("device")
    remote = endpoint.get("remote")
    if (host != "archlinux" or not isinstance(device, str) or device not in _DEVICE_APIS or host not in config.hosts or
            device not in config.hosts[host].android_devices or
            config.hosts[host].fixture_transfer_root is None or
            endpoint.get("remoteRoot") != str(config.hosts[host].fixture_transfer_root) or
            ssh_transport.connection_host(config, host).password is not None or not isinstance(remote, dict)):
        raise ValueError("Android runtime route is unavailable")
    profile = android_observation._profile(config.hosts[host].android_devices[device])
    if (type(profile.get("api")) is not int or profile["api"] != _DEVICE_APIS[device] or
            remote.get("host") != host or
            any(remote.get(key) != profile.get(field) for key, field in
                (("api", "api"), ("avd", "expectedAvd"), ("serial", "serial"), ("adb", "adb"), ("cli", "cli")))):
        raise ValueError("Android runtime endpoint profile changed")
    return profile


def start(root: Path | str, correlation_id: str, endpoint_correlation_id: str,
          cli_stage_correlation_id: str) -> dict[str, Any]:
    """Submit exactly one fixed public runtime scenario from a ready endpoint."""
    root = Path(root).resolve()
    if not all(isinstance(v, str) and _UUID.fullmatch(v) for v in (correlation_id, endpoint_correlation_id, cli_stage_correlation_id)):
        raise ValueError("Android runtime requires exact correlation UUIDs")
    endpoint = _endpoint_intent(root, endpoint_correlation_id)
    remote = endpoint["remote"]
    stage = android_cli_stage.status(root, cli_stage_correlation_id)
    if (stage.get("ok") is not True or stage.get("state") != "published" or
            stage.get("sourceSha") != endpoint.get("sourceSha") or
            not isinstance(stage.get("receipt", {}).get("cliPath"), str) or
            not isinstance(stage.get("receipt", {}).get("launcherSha256"), str) or
            not _SHA.fullmatch(stage["receipt"]["launcherSha256"]) or
            not all(isinstance(stage.get("receipt", {}).get(k), str) and _SHA.fullmatch(stage["receipt"][k]) for k in ("manifestSha256", "rpmSha256", "desktopJarSha256"))):
        raise ValueError("Android runtime CLI stage is not exact-source published")
    config = ssh_transport.load_config(root)
    host, device = endpoint["host"], endpoint["device"]
    profile = _configured_profile(config, endpoint)
    remote_root = config.hosts[host].fixture_transfer_root
    intent = {"schema": 1, "kind": "android-runtime-acceptance", "correlationId": correlation_id,
              "parentCorrelationId": endpoint_correlation_id, "campaignId": remote["campaignId"],
              "sourceSha": endpoint["sourceSha"], "packageSha256": remote["packageSha256"],
              "expectedOwner": remote["owner"], "expectedRevision": remote["revision"],
              "host": host, "device": device, "api": profile["api"], "expectedAvd": profile["expectedAvd"],
              "remoteRoot": str(remote_root), "cliStageCorrelationId": cli_stage_correlation_id,
              "cliPath": stage["receipt"]["cliPath"], "cliManifestSha256": stage["receipt"]["manifestSha256"], "cliRpmSha256": stage["receipt"]["rpmSha256"], "cliLauncherSha256": stage["receipt"]["launcherSha256"], "cliDesktopJarSha256": stage["receipt"]["desktopJarSha256"], "location": _FIXED_LOCATION,
              "testUrl": _FIXED_URL, "fixtureEventCounts": endpoint["fixtureEventCounts"]}
    # Use the endpoint's lock only to make the child binding atomic with the
    # parent cleanup observer.  The endpoint lease itself is never touched.
    with android_endpoint_admission._shared_device_lease(root, host, device) as lease:
        if android_native_fixture_lifecycle._read_plan(lease) != {
                "owner": "android-endpoint", "correlationId": endpoint_correlation_id,
                "host": host, "device": device}:
            raise ValueError("Android runtime parent device lease changed")
        intent["parentLeaseSha256"] = _claim_parent(root, intent)
        _save(root, intent)
    activity = {"schema": 1, "kind": "android-runtime-acceptance", "state": "running",
                "parentCorrelationId": endpoint_correlation_id, "runtimeCorrelationId": correlation_id,
                "campaignId": remote["campaignId"], "sourcePackageSha256": remote["packageSha256"],
                "expectedOwner": remote["owner"], "parentLeaseSha256": intent["parentLeaseSha256"], "endpoint": {"state": "ready", "correlationId": endpoint_correlation_id,
                "sourcePackageSha256": remote["packageSha256"], "owner": remote["owner"]},
                "fixture": {"campaignId": remote["campaignId"], "deviceUid": "2000", "api": profile["api"], "avd": profile["expectedAvd"]}}
    create = ssh_transport.build_ssh_argv(config, host, 30, command=("python3", "-I", "-B", "-c", "exec(" + repr(_ACTIVITY_CREATE) + ")", str(remote_root), json.dumps(activity, sort_keys=True, separators=(",", ":"))))
    try:
        code, output = android_observation._run_probe(create, 30)
        created = json.loads(output.decode("utf-8", "strict")) if code == 0 else None
        if not isinstance(created, dict) or created.get("state") != "created" or created.get("correlationId") != correlation_id:
            return _reply("unknown", correlation_id, "activity_create_unknown")
    except (OSError, RuntimeError, TimeoutError, UnicodeError, ValueError):
        return _reply("unknown", correlation_id, "activity_create_unknown")
    args = [profile["adb"], stage["receipt"]["cliPath"], profile["serial"], profile["expectedAvd"], device, str(profile["api"]), str(remote_root),
            correlation_id, remote["owner"], str(remote["revision"]), remote["packageSha256"], endpoint_correlation_id, remote["campaignId"], intent["parentLeaseSha256"], cli_stage_correlation_id, stage["receipt"]["manifestSha256"], stage["receipt"]["rpmSha256"], stage["receipt"]["launcherSha256"], stage["receipt"]["desktopJarSha256"], str(remote["httpsHostPort"]), str(remote["socksHostPort"]) ]
    encoded = base64.urlsafe_b64encode(_worker(args).encode()).decode("ascii")
    submit = android_document_acceptance._SUBMIT.replace("android-document-job-", "android-runtime-job-")
    argv = ssh_transport.build_ssh_argv(config, host, 60, command=("python3", "-I", "-B", "-c", "exec(" + repr(submit) + ")", str(remote_root), correlation_id, json.dumps(intent, sort_keys=True, separators=(",", ":")), encoded))
    try:
        code, output = android_observation._run_probe(argv, 60)
        value = json.loads(output.decode("utf-8", "strict")) if code == 0 else None
        if isinstance(value, dict) and value.get("state") == "submitted" and value.get("correlationId") == correlation_id:
            return _reply("submitted", correlation_id, identity=value.get("identity"))
    except (OSError, RuntimeError, TimeoutError, UnicodeError, ValueError):
        pass
    return _reply("unknown", correlation_id, "submission_unknown")


def status(root: Path | str, correlation_id: str) -> dict[str, Any]:
    root = Path(root).resolve()
    if not isinstance(correlation_id, str) or not _UUID.fullmatch(correlation_id):
        raise ValueError("Android runtime correlation must be a canonical UUID")
    intent = _load(root, correlation_id)
    if intent is None:
        return _reply("unknown", correlation_id, "missing_local_intent")
    required = {"schema", "kind", "correlationId", "parentCorrelationId", "campaignId", "sourceSha",
                "packageSha256", "expectedOwner", "expectedRevision", "host", "device", "api", "expectedAvd",
                "remoteRoot", "parentLeaseSha256", "cliStageCorrelationId", "cliPath", "cliManifestSha256", "cliRpmSha256", "cliLauncherSha256", "cliDesktopJarSha256", "location", "testUrl", "fixtureEventCounts"}
    if (set(intent) != required or intent.get("schema") != 1 or intent.get("kind") != "android-runtime-acceptance" or
            intent.get("correlationId") != correlation_id or not all(isinstance(intent.get(key), str) and
            _UUID.fullmatch(intent[key]) for key in ("parentCorrelationId", "campaignId", "cliStageCorrelationId")) or
            not isinstance(intent.get("packageSha256"), str) or not _SHA.fullmatch(intent["packageSha256"]) or
            not isinstance(intent.get("parentLeaseSha256"), str) or not _SHA.fullmatch(intent["parentLeaseSha256"]) or
            type(intent.get("api")) is not int or not isinstance(intent.get("device"), str) or _DEVICE_APIS.get(intent.get("device")) != intent.get("api") or
            not isinstance(intent.get("sourceSha"), str) or not re.fullmatch(r"[0-9a-f]{40}", intent["sourceSha"]) or
            type(intent.get("expectedRevision")) is not int or intent.get("location") != _FIXED_LOCATION or
            intent.get("testUrl") != _FIXED_URL):
        return _reply("unknown", correlation_id, "local_intent_invalid")
    endpoint_intent = android_endpoint_admission._status_intent(root, intent.get("parentCorrelationId"))
    remote = endpoint_intent.get("remote") if isinstance(endpoint_intent, dict) else None
    if (not isinstance(remote, dict) or
            endpoint_intent.get("host") != intent.get("host") or endpoint_intent.get("device") != intent.get("device") or
            endpoint_intent.get("sourceSha") != intent.get("sourceSha") or endpoint_intent.get("correlationId") != intent.get("parentCorrelationId") or
            remote.get("api") != intent.get("api") or remote.get("avd") != intent.get("expectedAvd") or
            remote.get("campaignId") != intent.get("campaignId") or
            remote.get("packageSha256") != intent.get("packageSha256") or
            remote.get("owner") != intent.get("expectedOwner") or
            remote.get("revision") != intent.get("expectedRevision")):
        return _reply("unknown", correlation_id, "parent_endpoint_changed")
    config = ssh_transport.load_config(root)
    try:
        profile = _configured_profile(config, endpoint_intent)
    except (ValueError, KeyError, TypeError):
        return _reply("unknown", correlation_id, "route_changed")
    if (str(config.hosts[intent["host"]].fixture_transfer_root) != intent.get("remoteRoot") or
            profile["api"] != intent.get("api") or profile["expectedAvd"] != intent.get("expectedAvd")):
        return _reply("unknown", correlation_id, "route_changed")
    argv = ssh_transport.build_ssh_argv(config, intent["host"], 30, command=("python3", "-I", "-B", "-c", "exec(" + repr(_STATUS) + ")", intent["remoteRoot"], correlation_id, json.dumps(intent, sort_keys=True, separators=(",", ":"))))
    try:
        code, output = android_observation._run_probe(argv, 30)
        value = json.loads(output.decode("utf-8", "strict")) if code == 0 else None
        if isinstance(value, dict) and value.get("correlationId") == correlation_id and value.get("state") in {"running", "complete", "unknown"}:
            return _reply(value["state"], correlation_id, value.get("reason"), identity=value.get("identity"), receipt=value.get("receipt"))
    except (OSError, RuntimeError, TimeoutError, UnicodeError, ValueError):
        pass
    return _reply("unknown", correlation_id, "transport_or_receipt_unknown")


def collect(root: Path | str, correlation_id: str) -> dict[str, Any]:
    """Return a terminal only after the worker proved full empty-baseline restoration."""
    observed = status(root, correlation_id)
    if observed.get("state") != "complete":
        return observed
    value = observed.get("receipt", {}).get("result") if isinstance(observed.get("receipt"), dict) else None
    expected = {"settings": True, "source": True, "routing": True, "locationsEmpty": True,
                "selectedNull": True, "activeNull": True, "runtimeOff": True}
    intent = _load(root, correlation_id)
    if (not isinstance(intent, dict) or not isinstance(value, dict) or value.get("state") != "complete" or
            value.get("selectedProxy") is not True or value.get("outboundEvidence") is not True or
            value.get("statsObserved") is not True or value.get("restoration") != expected or
            any(value["restoration"][key] is not True for key in expected)):
        return _reply("unknown", correlation_id, "terminal_binding_invalid")
    campaign = android_native_fixture_lifecycle.status(root, intent["campaignId"])
    before, after = intent.get("fixtureEventCounts"), campaign.get("eventCounts") if isinstance(campaign, dict) else None
    keys = {"socksConnected", "socksRejected", "health", "traffic", "subscription"}
    if (campaign.get("state") != "running" or
            not isinstance(before, dict) or not isinstance(after, dict) or set(before) != keys or set(after) != keys or
            any(type(before[key]) is not int or type(after[key]) is not int or after[key] < before[key] for key in keys) or
            after["socksConnected"] <= before["socksConnected"] or after["traffic"] <= before["traffic"]):
        return _reply("unknown", correlation_id, "fixture_outbound_not_proved")
    return _reply("complete", correlation_id, result={"selectedProxy": True, "outboundEvidence": True,
                  "statsObserved": True, "fixtureSocksAndTrafficObserved": True,
                  "admittedMode": value.get("admittedMode"), "restoredEmptyBaseline": True})
