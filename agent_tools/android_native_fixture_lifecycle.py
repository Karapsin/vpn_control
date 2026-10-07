"""Durable host-only Android HTTPS/SOCKS campaign lifecycle over configured SSH.

This adapter never calls ADB, changes a VPN, installs an APK, or establishes
device trust. A native owner must separately admit and clean device reverses.
"""

from __future__ import annotations

import base64
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Any

from agent_tools import android_native_fixture, ssh_transfer, ssh_transport


_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")
_ALIAS = re.compile(r"[a-z0-9][a-z0-9-]{0,39}")
_SHA = re.compile(r"[0-9a-f]{64}")
_REMOTE = r'''
import base64,contextlib,fcntl,hashlib,json,os,pathlib,signal,stat,subprocess,sys,time
action,root_raw,device,campaign,source_hash,cert_hash,key_hash=sys.argv[1:]
root=pathlib.Path(root_raw); job=root/('android-native-fixture-'+campaign); lease=root/('android-native-fixture-'+device+'.lease')
def emit(state,reason=None,**extra):
 print(json.dumps({'state':state,'campaignId':campaign,'reason':reason,**extra},sort_keys=True,separators=(',',':')),flush=True)
def unknown(reason): emit('unknown',reason); raise SystemExit(0)
def info(path,mode):
 try: value=path.lstat()
 except OSError: unknown('private_path_missing')
 if not stat.S_ISREG(value.st_mode) or value.st_uid!=os.getuid() or stat.S_IMODE(value.st_mode)!=mode: unknown('private_file_unsafe')
 return value
def read(path,mode,max_bytes=1048576):
 item=info(path,mode)
 if item.st_size>max_bytes: unknown('private_file_too_large')
 try:
  descriptor=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
  with os.fdopen(descriptor,'rb') as source:
   opened=os.fstat(source.fileno())
   if (not stat.S_ISREG(opened.st_mode) or opened.st_uid!=os.getuid() or stat.S_IMODE(opened.st_mode)!=mode or opened.st_nlink!=1 or (opened.st_dev,opened.st_ino,opened.st_size)!=(item.st_dev,item.st_ino,item.st_size)): unknown('private_file_replaced')
   data=source.read(max_bytes+1)
   closing=os.fstat(source.fileno())
   if (closing.st_dev,closing.st_ino,closing.st_size)!=(item.st_dev,item.st_ino,item.st_size): unknown('private_file_changed')
 except OSError: unknown('private_file_unreadable')
 if len(data)!=item.st_size: unknown('private_file_changed')
 return data
def read_job(name,mode=0o600,max_bytes=1048576):
 try:
  directory=os.open(job,os.O_RDONLY|os.O_DIRECTORY|getattr(os,'O_NOFOLLOW',0))
  parent=os.fstat(directory)
  if not stat.S_ISDIR(parent.st_mode) or parent.st_uid!=os.getuid() or stat.S_IMODE(parent.st_mode)!=0o700: unknown('job_unsafe')
  descriptor=os.open(name,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0),dir_fd=directory)
  with os.fdopen(descriptor,'rb') as source:
   item=os.fstat(source.fileno())
   if not stat.S_ISREG(item.st_mode) or item.st_uid!=os.getuid() or stat.S_IMODE(item.st_mode)!=mode or item.st_size>max_bytes or item.st_nlink!=1: unknown('job_file_unsafe')
   data=source.read(max_bytes+1)
   after=os.fstat(source.fileno())
   if (after.st_dev,after.st_ino,after.st_size)!=(item.st_dev,item.st_ino,item.st_size): unknown('job_file_changed')
  if len(data)!=item.st_size: unknown('job_file_changed')
  return data
 except OSError: unknown('job_read_unavailable')
 finally:
  if 'directory' in locals(): os.close(directory)
def put(path,data):
 descriptor=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
 with os.fdopen(descriptor,'wb') as output: output.write(data); output.flush(); os.fsync(output.fileno())
def valid_root():
 try: value=root.lstat()
 except OSError: unknown('fixture_root_missing')
 if not stat.S_ISDIR(value.st_mode) or value.st_uid!=os.getuid() or stat.S_IMODE(value.st_mode)!=0o700: unknown('fixture_root_unsafe')
def ticks(pid):
 try: raw=pathlib.Path('/proc/'+str(pid)+'/stat').read_text()
 except FileNotFoundError:
  if not pathlib.Path('/proc').is_dir(): unknown('proc_unavailable')
  return None
 except OSError: unknown('process_identity_unreadable')
 try: return int(raw.split(') ',1)[1].split()[19])
 except (ValueError,IndexError): unknown('process_identity_malformed')
def signal_exact(pid,start):
 if not hasattr(os,'pidfd_open') or not hasattr(signal,'pidfd_send_signal'): unknown('pidfd_unavailable')
 try: descriptor=os.pidfd_open(pid,0)
 except OSError: unknown('pidfd_open_failed')
 try:
  if ticks(pid)!=start: unknown('worker_identity_changed_before_signal')
  try: signal.pidfd_send_signal(descriptor,signal.SIGTERM,None,0)
  except OSError: unknown('stop_submission_uncertain')
 finally: os.close(descriptor)
@contextlib.contextmanager
def device_lock():
 lock=root/('android-native-fixture-'+device+'.lock')
 try:
  descriptor=os.open(lock,os.O_RDWR|os.O_CREAT|getattr(os,'O_NOFOLLOW',0),0o600)
  item=os.fstat(descriptor)
  if not stat.S_ISREG(item.st_mode) or item.st_uid!=os.getuid() or stat.S_IMODE(item.st_mode)!=0o600: unknown('device_lock_unsafe')
  fcntl.flock(descriptor,fcntl.LOCK_EX)
  yield
 finally:
  if 'descriptor' in locals():
   fcntl.flock(descriptor,fcntl.LOCK_UN); os.close(descriptor)
def counts():
 result={'socksConnected':0,'socksRejected':0,'health':0,'traffic':0,'subscription':0}
 try: raw=read_job('events.jsonl',0o600,1048576).decode('utf-8','strict').splitlines()
 except (UnicodeError,ValueError): unknown('events_invalid')
 if not raw: unknown('events_missing_epoch')
 for index,line in enumerate(raw):
  try: event=json.loads(line)
  except ValueError: unknown('events_invalid')
  if event.get('campaignId')!=campaign: unknown('events_foreign_epoch')
  if index==0:
   if event.get('event')!='epoch-start': unknown('events_missing_epoch')
   continue
  if event.get('transport')=='socks' and event.get('event')=='connected': result['socksConnected']+=1
  elif event.get('transport')=='socks' and event.get('event')=='rejected': result['socksRejected']+=1
  elif event.get('transport')=='https' and (event.get('path'),event.get('status')) in (('/health',204),('/traffic',200),('/subscription',200)):
   result[event['path'][1:]]+=1
  else: unknown('events_unrecognized')
 return result
def observe():
 try: ident=json.loads(read_job('intent.json')); ready=json.loads(read_job('ready.json'))
 except (ValueError,UnicodeError): unknown('intent_or_ready_invalid')
 if ident!={'campaignId':campaign,'device':device,'sourceSha256':source_hash,'certificateSha256':cert_hash,'privateKeySha256':key_hash}: unknown('intent_changed')
 for name,expected in (('fixture.py',source_hash),('certificate.pem',cert_hash),('private-key.pem',key_hash)):
  if hashlib.sha256(read_job(name)).hexdigest()!=expected: unknown('staged_bytes_changed')
 if ready.get('campaignId')!=campaign or ready.get('state')!='running' or ready.get('certificateSha256')!=cert_hash: unknown('ready_changed')
 endpoint=ready.get('endpoint')
 if not isinstance(endpoint,dict) or any(type(endpoint.get(k)) is not int or not 1<=endpoint[k]<=65535 for k in ('hostHttpsPort','hostSocksPort')): unknown('endpoint_invalid')
 pid=ready.get('pid'); start=ready.get('startTicks')
 if type(pid) is not int or type(start) is not int: unknown('process_identity_invalid')
 stopped=job/'stopped.json'
 if stopped.exists():
  try: terminal=json.loads(read_job('stopped.json'))
  except (ValueError,UnicodeError): unknown('terminal_invalid')
  current=counts()
  if terminal.get('campaignId')!=campaign or terminal.get('state')!='stopped' or terminal.get('eventCounts',{}).get('campaignId')!=campaign or any(terminal['eventCounts'].get(k)!=v for k,v in current.items()): unknown('terminal_unbound')
  if ticks(pid)==start: unknown('stopped_process_still_running')
  return {'state':'stopped','endpoint':endpoint,'eventCounts':current}
 if ticks(pid)!=start: unknown('worker_identity_lost')
 if read(lease,0o600,128)!=(campaign+'\n').encode(): unknown('device_lease_changed')
 return {'state':'running','endpoint':endpoint,'eventCounts':counts()}
valid_root()
if action=='start':
 try: payload=json.load(sys.stdin)
 except (ValueError,UnicodeError): unknown('payload_invalid')
 try: source=base64.b64decode(payload['source'],validate=True); cert=base64.b64decode(payload['certificate'],validate=True); key=base64.b64decode(payload['privateKey'],validate=True)
 except (KeyError,ValueError): unknown('payload_invalid')
 if any(hashlib.sha256(data).hexdigest()!=expected for data,expected in ((source,source_hash),(cert,cert_hash),(key,key_hash))): unknown('payload_hash_mismatch')
 try:
  job.mkdir(mode=0o700)
  put(job/'fixture.py',source); put(job/'certificate.pem',cert); put(job/'private-key.pem',key)
  intent={'campaignId':campaign,'device':device,'sourceSha256':source_hash,'certificateSha256':cert_hash,'privateKeySha256':key_hash}
  put(job/'intent.json',(json.dumps(intent,sort_keys=True,separators=(',',':'))+'\n').encode())
  directory=os.open(job,os.O_RDONLY|os.O_DIRECTORY|getattr(os,'O_NOFOLLOW',0)); os.fsync(directory); os.close(directory)
  with device_lock(): put(lease,(campaign+'\n').encode())
  log=os.open(job/'worker.log',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
  with os.fdopen(log,'wb') as output:
   subprocess.Popen([sys.executable,str(job/'fixture.py'),'serve','--certificate',str(job/'certificate.pem'),'--private-key',str(job/'private-key.pem'),'--campaign-id',campaign,'--ready',str(job/'ready.json'),'--events',str(job/'events.jsonl'),'--stopped',str(job/'stopped.json')],stdin=subprocess.DEVNULL,stdout=output,stderr=output,start_new_session=True,close_fds=True)
 except (OSError,ValueError): unknown('submission_uncertain')
 for _ in range(30):
  if (job/'ready.json').exists():
   result=observe(); emit(result['state'],None,endpoint=result['endpoint'],eventCounts=result['eventCounts']); raise SystemExit(0)
  time.sleep(.2)
 unknown('worker_readiness_uncertain')
if action=='status':
 result=observe(); emit(result['state'],None,endpoint=result['endpoint'],eventCounts=result['eventCounts']); raise SystemExit(0)
if action=='stop':
 result=observe()
 if result['state']=='stopped': emit('stopped',None,endpoint=result['endpoint'],eventCounts=result['eventCounts']); raise SystemExit(0)
 ready=json.loads(read_job('ready.json')); pid=ready['pid']; start=ready['startTicks']
 if ticks(pid)!=start: unknown('worker_identity_lost')
 signal_exact(pid,start)
 for _ in range(50):
  if (job/'stopped.json').exists() and ticks(pid)!=start:
   result=observe(); emit(result['state'],None,endpoint=result['endpoint'],eventCounts=result['eventCounts']); raise SystemExit(0)
  time.sleep(.2)
 unknown('stop_outcome_uncertain')
if action=='collect':
 result=observe()
 if result['state']!='stopped': unknown('campaign_not_stopped')
 with device_lock():
  if lease.exists():
   if read(lease,0o600,128)!=(campaign+'\n').encode(): unknown('device_lease_changed')
   lease.unlink()
   directory=os.open(root,os.O_RDONLY|os.O_DIRECTORY|getattr(os,'O_NOFOLLOW',0)); os.fsync(directory); os.close(directory)
 emit('stopped',None,endpoint=result['endpoint'],eventCounts=result['eventCounts'],collected=True); raise SystemExit(0)
unknown('invalid_action')
'''


def _directory(root: Path) -> Path:
    directory = root / ".rag_index" / "android-native-fixture-campaigns"
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    if directory.is_symlink() or directory.stat().st_uid != os.getuid() or directory.stat().st_mode & 0o077:
        raise ValueError("Android fixture local journal directory is unsafe")
    return directory


@contextlib.contextmanager
def _device_lock(directory: Path, host: str, device: str):
    lock = directory / ("device-" + host + "-" + device + ".lock")
    descriptor = os.open(lock, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
            raise ValueError("Android fixture local device lock is unsafe")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _read_plan(path: Path) -> dict[str, Any]:
    if not path.is_absolute():
        raise ValueError("Android fixture private plan path must be absolute")
    for ancestor in (path.parent, *path.parent.parents):
        if stat.S_ISLNK(ancestor.lstat().st_mode):
            raise ValueError("Android fixture private plan has symlink ancestry")
    parent = path.parent.lstat()
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened_parent = os.fstat(directory)
        if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.getuid() or parent.st_mode & 0o077 or
                (opened_parent.st_dev, opened_parent.st_ino) != (parent.st_dev, parent.st_ino)):
            raise ValueError("Android fixture private plan directory is unsafe")
        descriptor = os.open(path.name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=directory)
        try:
            info = os.fstat(descriptor)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or
                    stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 8192 or info.st_nlink != 1):
                raise ValueError("Android fixture plan file is unsafe")
            raw = os.read(descriptor, 8193)
            after = os.fstat(descriptor)
            if (after.st_dev, after.st_ino, after.st_size) != (info.st_dev, info.st_ino, info.st_size) or len(raw) != info.st_size:
                raise ValueError("Android fixture plan changed while read")
        finally:
            os.close(descriptor)
    finally:
        os.close(directory)
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("Android fixture plan is invalid")
    return value


def _remote(root: Path, host: str, action: str, device: str, campaign_id: str,
            source_hash: str, cert_hash: str, key_hash: str, payload: bytes | None) -> dict[str, Any]:
    config = ssh_transport.load_config(root)
    if host not in config.hosts or device not in config.hosts[host].android_devices or config.hosts[host].fixture_transfer_root is None:
        raise ValueError("Android fixture host/device is not configured")
    if ssh_transport.connection_host(config, host).password is not None:
        raise ValueError("Android fixture requires private key SSH")
    remote_root = str(config.hosts[host].fixture_transfer_root)
    argv = ssh_transport.build_ssh_argv(config, host, 30,
        command=ssh_transfer._python_command(_REMOTE, action, remote_root, device, campaign_id,
                                             source_hash, cert_hash, key_hash))
    try:
        code, output = ssh_transfer._bounded_run(argv, payload, 30)
        result = json.loads(output.decode("utf-8", "strict"))
    except (OSError, ValueError, UnicodeError, ssh_transfer.SshTransferError):
        return {"state": "unknown", "reason": "transport_uncertain", "campaignId": campaign_id}
    if code != 0 or not isinstance(result, dict) or result.get("campaignId") != campaign_id or result.get("state") not in {"running", "stopped", "unknown"}:
        return {"state": "unknown", "reason": "remote_receipt_invalid", "campaignId": campaign_id}
    return result


def start(root: Path | str, host: str, device: str, campaign_id: str, plan_path: Path | str,
          certificate: Path | str, private_key: Path | str, *,
          source_root: Path | str | None = None) -> dict[str, Any]:
    """Journal before one remote host-only submission; never replay an unknown."""
    root = Path(root).resolve()
    if (not isinstance(campaign_id, str) or not _UUID.fullmatch(campaign_id) or
            not isinstance(device, str) or not _ALIAS.fullmatch(device) or
            not isinstance(host, str) or not _ALIAS.fullmatch(host)):
        raise ValueError("Android fixture requires exact campaign/device identity")
    config = ssh_transport.load_config(root)
    if host not in config.hosts or device not in config.hosts[host].android_devices or config.hosts[host].fixture_transfer_root is None:
        raise ValueError("Android fixture host/device is not configured")
    if ssh_transport.connection_host(config, host).password is not None:
        raise ValueError("Android fixture requires private key SSH")
    plan = _read_plan(Path(plan_path))
    source_sha = plan.get("sourceSha")
    source_checkout = android_native_fixture._source_root(root, source_root)
    if plan != android_native_fixture.prepare_requirements(root, source_sha, plan.get("baseArtifactId"),
                                                            source_root=source_checkout):
        raise ValueError("Android fixture plan no longer matches exact source")
    fixture_bytes = (Path(__file__).with_name("android_native_fixture.py")).read_bytes()
    cert, _ = android_native_fixture._stable_tls_bytes(Path(certificate), private=False)
    key, _ = android_native_fixture._stable_tls_bytes(Path(private_key), private=True)
    if (android_native_fixture._head(source_checkout) != source_sha or
            not android_native_fixture._clean(source_checkout)):
        raise ValueError("Android fixture source changed during preparation")
    source_hash = hashlib.sha256(fixture_bytes).hexdigest()
    cert_hash = hashlib.sha256(cert).hexdigest()
    key_hash = hashlib.sha256(key).hexdigest()
    directory = _directory(root)
    lease = directory / ("device-" + host + "-" + device + ".lease")
    intent = {"host": host, "device": device, "campaignId": campaign_id, "sourceSha": source_sha,
              "sourceSha256": source_hash, "certificateSha256": cert_hash, "privateKeySha256": key_hash,
              "planSha256": hashlib.sha256(json.dumps(plan, sort_keys=True, separators=(",", ":")).encode()).hexdigest()}
    android_native_fixture.write_private_plan(directory / (campaign_id + ".json"), intent)
    with _device_lock(directory, host, device):
        android_native_fixture.write_private_plan(lease, {"host": host, "device": device, "campaignId": campaign_id})
    payload = json.dumps({"source": base64.b64encode(fixture_bytes).decode(), "certificate": base64.b64encode(cert).decode(),
                          "privateKey": base64.b64encode(key).decode()}, separators=(",", ":")).encode()
    result = _remote(root, host, "start", device, campaign_id, source_hash, cert_hash, key_hash, payload)
    return {"ok": result.get("state") == "running", "state": result.get("state"), "campaignId": campaign_id,
            "reason": result.get("reason"), "endpoint": result.get("endpoint"), "replayAllowed": False,
            "deviceMutationAllowed": False, "installerTargetAdmitted": False}


def status(root: Path | str, campaign_id: str) -> dict[str, Any]:
    root = Path(root).resolve()
    if not isinstance(campaign_id, str) or not _UUID.fullmatch(campaign_id):
        raise ValueError("Android fixture requires exact campaign UUID")
    intent = _read_plan(_directory(root) / (campaign_id + ".json"))
    result = _remote(root, intent["host"], "status", intent["device"], campaign_id,
                     intent["sourceSha256"], intent["certificateSha256"], intent["privateKeySha256"], None)
    return {"ok": result.get("state") in {"running", "stopped"}, **result,
            "replayAllowed": False, "deviceMutationAllowed": False, "installerTargetAdmitted": False}


def stop(root: Path | str, campaign_id: str) -> dict[str, Any]:
    root = Path(root).resolve()
    intent = _read_plan(_directory(root) / (campaign_id + ".json"))
    result = _remote(root, intent["host"], "stop", intent["device"], campaign_id,
                     intent["sourceSha256"], intent["certificateSha256"], intent["privateKeySha256"], None)
    return {"ok": result.get("state") == "stopped", **result,
            "replayAllowed": False, "deviceMutationAllowed": False, "installerTargetAdmitted": False}


def collect(root: Path | str, campaign_id: str) -> dict[str, Any]:
    observed = status(root, campaign_id)
    if observed.get("state") != "stopped":
        return {**observed, "collected": False}
    root = Path(root).resolve()
    intent = _read_plan(_directory(root) / (campaign_id + ".json"))
    result = _remote(root, intent["host"], "collect", intent["device"], campaign_id,
                     intent["sourceSha256"], intent["certificateSha256"], intent["privateKeySha256"], None)
    if result.get("state") == "stopped" and result.get("collected") is True:
        directory = _directory(root)
        receipt = directory / (campaign_id + "-collected.json")
        expected = {"campaignId": campaign_id, "endpoint": result.get("endpoint"),
                    "eventCounts": result.get("eventCounts")}
        if receipt.exists():
            if _read_plan(receipt) != expected:
                raise ValueError("Android fixture collected receipt changed")
        else:
            android_native_fixture.write_private_plan(receipt, expected)
        lease = directory / ("device-" + intent["host"] + "-" + intent["device"] + ".lease")
        with _device_lock(directory, intent["host"], intent["device"]):
            if lease.exists():
                if _read_plan(lease).get("campaignId") != campaign_id:
                    raise ValueError("Android fixture local lease changed")
                lease.unlink()
        return {"ok": True, **result, "replayAllowed": False, "deviceMutationAllowed": False,
                "installerTargetAdmitted": False}
    return {"ok": False, **result, "collected": False, "replayAllowed": False,
            "deviceMutationAllowed": False, "installerTargetAdmitted": False}
