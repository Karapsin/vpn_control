"""One-shot fixed Arch dispatch of an admitted Android self-update fixture.

The local and remote journals precede leases and guest effects. Unknown transport
or worker results retain both leases and never authorize a second submission.
"""
from __future__ import annotations

from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
from typing import Any
from uuid import uuid4

from agent_tools import (android_admission_readback, android_cli_stage, android_installer_target,
                         android_observation, android_public_inspect, android_installer_tool_bundle, native_artifact_registry,
                         ssh_transfer, ssh_transport)

_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_BUNDLE = (
    "agent_tools/android_installer_target.py",
    "scripts/android_installer_lifecycle.py",
    "scripts/android_no_update_tls_preflight.py",
    "scripts/android_fixture_preflight.py",
    "scripts/android_fixture_transport.py",
    "scripts/android_fixture_trust.py",
    "scripts/integration/android_update_fixture.py",
)
_MAX_BYTES = 150_000_000


def _directory(root: Path) -> Path:
    path = root / ".rag_index" / "android-installer-dispatch"
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError("Android installer dispatch directory is unsafe")
    return path


def _shared_directory(root: Path) -> Path:
    path = root / ".rag_index" / "android-native-device-leases"
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError("Android shared device lease directory is unsafe")
    return path


@contextmanager
def _shared_lock(root: Path, host: str, device: str):
    if not re.fullmatch(r"[A-Za-z0-9_-]+", host) or not re.fullmatch(r"[A-Za-z0-9_-]+", device):
        raise ValueError("Android shared lease alias is invalid")
    directory = _shared_directory(root)
    lock = directory / ("lock-" + host + "-" + device + ".json")
    fd = os.open(lock, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
            raise ValueError("Android shared lease lock is unsafe")
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            yield directory / ("lease-" + host + "-" + device + ".json")
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def _lease_value(owner: str, host: str, device: str, correlation_id: str) -> dict[str, str]:
    if owner not in {"android-installer", "android-package-install", "android-endpoint", "android-document-retry"}:
        raise ValueError("Android shared lease owner is invalid")
    return {"owner": owner, "host": host, "device": device, "correlationId": correlation_id}


def _claim_local(root: Path, host: str, device: str, correlation_id: str,
                 owner: str = "android-installer") -> None:
    with _shared_lock(root, host, device) as path:
        android_installer_target._write_private(path, _lease_value(owner, host, device, correlation_id))


def _release_local(root: Path, host: str, device: str, correlation_id: str,
                   owner: str = "android-installer") -> bool:
    with _shared_lock(root, host, device) as path:
        try:
            value = json.loads(android_installer_target._private_file(path, 1024))
            before = path.lstat()
            if value != _lease_value(owner, host, device, correlation_id):
                return False
            after = path.lstat()
            if (before.st_dev, before.st_ino, before.st_size) != (after.st_dev, after.st_ino, after.st_size):
                return False
            path.unlink()
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try: os.fsync(directory)
            finally: os.close(directory)
            return True
        except (OSError, ValueError, TypeError):
            return False


_REMOTE_SHARED = r'''import fcntl,json,os,pathlib,stat,sys
action,root_raw,host,device,correlation,owner=sys.argv[1:]
root=pathlib.Path(root_raw); lease=root/('android-native-device-'+device+'.lease'); lock=root/('android-native-device-'+device+'.lock'); release_intent=root/('android-native-device-'+device+'-'+correlation+'.release-intent')
expected={'owner':owner,'host':host,'device':device,'correlationId':correlation}
def emit(state,reason=None): print(json.dumps({'state':state,'reason':reason,'correlationId':correlation,'replayAllowed':False},separators=(',',':'))); raise SystemExit(0)
def private():
 fd=os.open(lease,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
 with os.fdopen(fd,'rb') as source:
  info=os.fstat(source.fileno()); data=source.read(1025); after=os.fstat(source.fileno())
 if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1 or len(data)>1024 or (info.st_dev,info.st_ino,info.st_size)!=(after.st_dev,after.st_ino,after.st_size): emit('unknown','lease_unsafe')
 return json.loads(data)
def release_record():
 try:
  fd=os.open(release_intent,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
 except FileNotFoundError: return False
 with os.fdopen(fd,'rb') as source:
  info=os.fstat(source.fileno()); data=source.read(1025); after=os.fstat(source.fileno())
 if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1 or len(data)>1024 or (info.st_dev,info.st_ino,info.st_size)!=(after.st_dev,after.st_ino,after.st_size): emit('unknown','release_intent_unsafe')
 return json.loads(data)==expected
info=root.lstat()
if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700: emit('unknown','root_unsafe')
fd=os.open(lock,os.O_RDWR|os.O_CREAT|getattr(os,'O_NOFOLLOW',0),0o600)
try:
 item=os.fstat(fd)
 if not stat.S_ISREG(item.st_mode) or item.st_uid!=os.getuid() or stat.S_IMODE(item.st_mode)!=0o600: emit('unknown','lock_unsafe')
 fcntl.flock(fd,fcntl.LOCK_EX)
 if action=='claim':
  try:
   descriptor=os.open(lease,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
   with os.fdopen(descriptor,'wb') as output: output.write((json.dumps(expected,sort_keys=True,separators=(',',':'))+'\n').encode()); output.flush(); os.fsync(output.fileno())
   directory=os.open(root,os.O_RDONLY|os.O_DIRECTORY); os.fsync(directory); os.close(directory)
   emit('claimed')
  except FileExistsError: emit('unknown','foreign_or_prior_lease')
 if action=='status':
  if release_record():
   if lease.exists(): emit('unknown','release_incomplete')
   emit('released')
  try: value=private()
  except (OSError,ValueError): emit('unknown','lease_unavailable')
  emit('claimed' if value==expected else 'unknown',None if value==expected else 'lease_changed')
 if action=='release':
  if release_record():
   if lease.exists():
    try: value=private()
    except (OSError,ValueError): emit('unknown','lease_unavailable')
    if value!=expected: emit('unknown','lease_changed')
    lease.unlink(); directory=os.open(root,os.O_RDONLY|os.O_DIRECTORY); os.fsync(directory); os.close(directory)
   emit('released')
  try: value=private()
  except (OSError,ValueError): emit('unknown','lease_unavailable')
  if value!=expected: emit('unknown','lease_changed')
  before=lease.lstat(); after=lease.lstat()
  if (before.st_dev,before.st_ino,before.st_size)!=(after.st_dev,after.st_ino,after.st_size): emit('unknown','lease_replaced')
  descriptor=os.open(release_intent,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
  with os.fdopen(descriptor,'wb') as output: output.write((json.dumps(expected,sort_keys=True,separators=(',',':'))+'\n').encode()); output.flush(); os.fsync(output.fileno())
  directory=os.open(root,os.O_RDONLY|os.O_DIRECTORY); os.fsync(directory); os.close(directory)
  lease.unlink(); directory=os.open(root,os.O_RDONLY|os.O_DIRECTORY); os.fsync(directory); os.close(directory)
  emit('released')
 emit('unknown','invalid_action')
finally:
 fcntl.flock(fd,fcntl.LOCK_UN); os.close(fd)
'''


def remote_shared_lease(root: Path | str, host: str, device: str,
                        correlation_id: str, owner: str, action: str) -> dict[str, Any]:
    """Fixed remote shared lease mutation; callers journal before claim/release."""
    if action not in {"claim", "status", "release"} or not _UUID.fullmatch(correlation_id):
        raise ValueError("Android shared lease action or correlation is invalid")
    _lease_value(owner, host, device, correlation_id)
    config = ssh_transport.load_config(root)
    if host not in config.hosts or config.hosts[host].fixture_transfer_root is None or ssh_transport.connection_host(config, host).password is not None:
        raise ValueError("Android shared lease route is unavailable")
    argv = ssh_transport.build_ssh_argv(config, host, 30, command=("python3", "-I", "-B", "-c",
        "exec(" + repr(_REMOTE_SHARED) + ")", action,
        str(config.hosts[host].fixture_transfer_root), host, device, correlation_id, owner))
    try:
        code, output = android_observation._run_probe(argv, 30)
        value = json.loads(output.decode("utf-8", "strict")) if code == 0 else None
        if isinstance(value, dict) and value.get("correlationId") == correlation_id and value.get("state") in {"claimed", "released", "unknown"}:
            return value
    except (OSError, ValueError, UnicodeError, RuntimeError, TimeoutError):
        pass
    return {"state": "unknown", "reason": "transport_or_lease_unknown", "correlationId": correlation_id,
            "replayAllowed": False}


def _source_bytes(root: Path, source_sha: str, name: str) -> bytes:
    path = root / name
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 8_388_608:
        raise ValueError("Android installer source bundle file is unsafe")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(fd)
        if ((opened.st_dev, opened.st_ino, opened.st_size) !=
                (info.st_dev, info.st_ino, info.st_size)):
            raise ValueError("Android installer source bundle changed")
        with os.fdopen(fd, "rb", closefd=False) as source:
            data = source.read(8_388_609)
        closed = os.fstat(fd)
        if (closed.st_dev, closed.st_ino, closed.st_size) != (opened.st_dev, opened.st_ino, opened.st_size):
            raise ValueError("Android installer source bundle changed")
    finally:
        os.close(fd)
    frozen = subprocess.run(["git", "show", source_sha + ":" + name], cwd=root,
                            capture_output=True, timeout=10, check=True).stdout
    if data != frozen:
        raise ValueError("Android installer driver differs from frozen source")
    return data


def _fixture_bytes(root: Path, artifact_id: str, kind: str, source_sha: str) -> bytes:
    if not isinstance(artifact_id, str) or not re.fullmatch(r"sha256-[0-9a-f]{64}", artifact_id):
        raise ValueError("Android installer TLS fixture artifact ID is invalid")
    value = native_artifact_registry.verify_artifact(root, artifact_id)
    item, location = value.get("artifact", {}), value.get("location", {})
    if (value.get("verification") != "verified" or item.get("platform") != "android" or
            item.get("artifactKind") != kind or item.get("sourceSha") != source_sha or
            item.get("sha256") != artifact_id[7:] or not isinstance(location.get("localPath"), str)):
        raise ValueError("Android installer TLS fixture is not source-bound")
    path = Path(location["localPath"])
    data = android_installer_target._private_file(path, 65_536)
    if not data or hashlib.sha256(data).hexdigest() != item["sha256"]:
        raise ValueError("Android installer TLS fixture bytes changed")
    return data


def _snapshot_payload(output: Path, files: list[tuple[str, bytes | Path]]) -> list[dict[str, Any]]:
    """Make one fsynced stream snapshot so local source races cannot change upload."""
    manifest = []
    payload = output / "payload.bin"
    fd = os.open(payload, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as stream:
        for name, value in files:
            digest = hashlib.sha256(); size = 0
            if isinstance(value, bytes):
                pieces = (value[index:index + 65536] for index in range(0, len(value), 65536))
            else:
                source_fd = os.open(value, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
                source = os.fdopen(source_fd, "rb")
                opened = os.fstat(source_fd)
                if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1 or opened.st_size > _MAX_BYTES:
                    source.close()
                    raise ValueError("Android installer staged source is unsafe")
                pieces = iter(lambda: source.read(65536), b"")
            try:
                for piece in pieces:
                    stream.write(piece); digest.update(piece); size += len(piece)
                    if size > _MAX_BYTES:
                        raise ValueError("Android installer staged file is oversized")
            finally:
                if isinstance(value, Path):
                    closed = os.fstat(source.fileno())
                    source.close()
                    if ((closed.st_dev, closed.st_ino, closed.st_size) !=
                            (opened.st_dev, opened.st_ino, opened.st_size) or size != opened.st_size):
                        raise ValueError("Android installer staged source changed")
            manifest.append({"name": name, "size": size, "sha256": digest.hexdigest()})
        stream.flush(); os.fsync(stream.fileno())
    parent_fd = os.open(output, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
    try:
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)
    return manifest


_REMOTE = android_observation._canonical_cli_environment_source() + r'''import fcntl,hashlib,json,os,pathlib,re,socket,stat,subprocess,sys,time,xml.etree.ElementTree as ET
action,root_raw,host,device,correlation,expected_json=sys.argv[1:]
root=pathlib.Path(root_raw); expected=json.loads(expected_json)
job=root/('android-installer-'+correlation); lease=root/('android-native-device-'+device+'.lease'); lock=root/('android-native-device-'+device+'.lock')
def emit(state,reason=None,**extra):
 print(json.dumps({'state':state,'reason':reason,'correlationId':correlation,'replayAllowed':False,**extra},sort_keys=True,separators=(',',':')),flush=True); raise SystemExit(0)
def unknown(reason): emit('unknown',reason)
def parent_fd(path):
 try: parts=path.relative_to(root).parts
 except ValueError: unknown('path_outside_fixture')
 if not parts or any(part in ('','.','..') for part in parts): unknown('path_invalid')
 try: fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|getattr(os,'O_NOFOLLOW',0))
 except OSError: unknown('root_changed')
 try:
  root_info=os.fstat(fd)
  if (root_info.st_dev,root_info.st_ino)!=(info.st_dev,info.st_ino): unknown('root_changed')
  for part in parts[:-1]:
   child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|getattr(os,'O_NOFOLLOW',0),dir_fd=fd)
   child_info=os.fstat(child)
   if not stat.S_ISDIR(child_info.st_mode) or child_info.st_uid!=os.getuid() or stat.S_IMODE(child_info.st_mode)!=0o700: unknown('directory_unsafe')
   os.close(fd); fd=child
  return fd,parts[-1]
 except BaseException:
  os.close(fd); raise
def private(path,limit=1048576):
 directory,name=parent_fd(path)
 try: fd=os.open(name,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0),dir_fd=directory)
 finally: os.close(directory)
 before=os.fstat(fd)
 with os.fdopen(fd,'rb') as source: data=source.read(limit+1); after=os.fstat(source.fileno())
 if not stat.S_ISREG(before.st_mode) or before.st_uid!=os.getuid() or stat.S_IMODE(before.st_mode)!=0o600 or before.st_nlink!=1 or before.st_size>limit or len(data)!=before.st_size or (before.st_dev,before.st_ino,before.st_size)!=(after.st_dev,after.st_ino,after.st_size): unknown('private_file_changed')
 return data
def put(path,data):
 directory,name=parent_fd(path)
 try:
  fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600,dir_fd=directory)
  with os.fdopen(fd,'wb') as output: output.write(data); output.flush(); os.fsync(output.fileno())
  os.fsync(directory)
 finally: os.close(directory)
def device_lock():
 fd=os.open(lock,os.O_RDWR|os.O_CREAT|getattr(os,'O_NOFOLLOW',0),0o600); info=os.fstat(fd)
 if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600: unknown('shared_lock_unsafe')
 fcntl.flock(fd,fcntl.LOCK_EX); return fd
def unlock(fd): fcntl.flock(fd,fcntl.LOCK_UN); os.close(fd)
def ticks(pid):
 try: raw=pathlib.Path('/proc/'+str(pid)+'/stat').read_text(encoding='ascii')
 except FileNotFoundError: return None
 except OSError: unknown('worker_identity_unreadable')
 try: return int(raw.rsplit(')',1)[1].split()[19])
 except (ValueError,IndexError): unknown('worker_identity_invalid')
def fixture_stopped(output):
 try:
  identity=json.loads(private(output/'fixture-identity.json',1024))
  finished=json.loads(private(output/'worker-finished.json',1024))
  readiness=json.loads(private(output/'fixture-receipt.json',4096))
  ready=json.loads(private(output/'ready.json',4096))
 except (OSError,ValueError,TypeError): unknown('fixture_teardown_unproven')
 pid=identity.get('pid'); start=identity.get('startTicks'); port=identity.get('port')
 if (identity.get('correlationId')!=correlation or type(pid) is not int or pid<1 or
     type(start) is not int or start<1 or type(port) is not int or not 1<=port<=65535 or
     finished!={**identity,'state':'fixture_stopped'} or
     readiness.get('state')!='ready' or readiness.get('pid')!=pid or readiness.get('port')!=port or
     ready.get('port')!=port): unknown('fixture_identity_changed')
 if ticks(pid)==start: unknown('fixture_server_live')
 try:
  probe=socket.create_connection(('127.0.0.1',port),timeout=.5)
 except ConnectionRefusedError: return
 except OSError: unknown('fixture_port_unknown')
 else:
  probe.close(); unknown('fixture_listener_present')
def fixed_run(argv,timeout=30,limit=1048576,environment=None):
 try: done=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=timeout,env=environment,check=False)
 except (OSError,subprocess.TimeoutExpired): unknown('callback_observation_unavailable')
 if done.returncode!=0 or len(done.stdout)>limit: unknown('callback_observation_unavailable')
 return done.stdout.decode('utf-8','strict')
def public_cli(*words):
 env=public_cli_environment(expected['adb'],pathlib.Path(expected['cli']))
 value=json.loads(fixed_run([expected['cli'],'--json','--android','--serial',expected['serial'],'--timeout-seconds','30',*words],environment=env))
 if not isinstance(value,dict) or value.get('ok') is not True or value.get('final') is not True or value.get('code')!='OK': unknown('callback_public_unavailable')
 return value
def callback_snapshot(phase):
 adb=[expected['adb'],'-s',expected['serial'],'shell','-T']
 focus=fixed_run([*adb,'dumpsys','window'],limit=1048576)
 focus_lines=[line for line in focus.splitlines() if 'mCurrentFocus=' in line]
 if len(focus_lines)!=1: unknown('callback_focus_ambiguous')
 installer=('com.google.android.packageinstaller','com.android.packageinstaller')
 match=re.search(r'mCurrentFocus=Window\{[0-9a-fA-F]+\s+u\d+\s+([A-Za-z0-9_.]+)/([A-Za-z0-9_.$]+)\}',focus_lines[0])
 if match is None: unknown('callback_focus_ambiguous')
 focused=match.group(1) if match.group(1) in installer else None
 path='/sdcard/android-installer-'+correlation+'-'+phase+'.xml'
 fixed_run([*adb,'uiautomator','dump',path],timeout=45,limit=4096)
 try: xml=fixed_run([*adb,'cat',path],limit=1048576)
 finally: fixed_run([*adb,'rm',path],limit=4096)
 try: tree=ET.fromstring(xml)
 except ET.ParseError: unknown('callback_ui_invalid')
 if tree.tag!='hierarchy': unknown('callback_ui_invalid')
 nodes=list(tree.iter('node'))
 title=[node for node in nodes if node.attrib.get('package')==focused and node.attrib.get('text')=='VPN Control']
 buttons={node.attrib.get('text') for node in nodes if node.attrib.get('package')==focused and node.attrib.get('enabled')=='true'}
 if phase=='handoff-ready':
  if focused is None or len(title)!=1 or not {'Update','Cancel'}<=buttons: unknown('callback_dialog_not_owned')
 else:
  if focused is not None or any(node.attrib.get('package') in installer and node.attrib.get('text') in ('Update','Cancel') for node in nodes): unknown('callback_dialog_still_visible')
 put(job/'output'/('callback-'+phase+'-ui.xml'),xml.encode())
 return {'uiSha256':hashlib.sha256(xml.encode()).hexdigest(),'focusedInstaller':focused if phase=='handoff-ready' else None}
def safe_dir(path):
 try: before=path.lstat(); fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|getattr(os,'O_NOFOLLOW',0)); after=os.fstat(fd)
 except OSError: unknown('structure_unsafe')
 try:
  if not stat.S_ISDIR(before.st_mode) or before.st_uid!=os.getuid() or stat.S_IMODE(before.st_mode)!=0o700 or (before.st_dev,before.st_ino)!=(after.st_dev,after.st_ino): unknown('structure_unsafe')
 finally: os.close(fd)
def safe_structure():
 for path in (job,job/'output',job/'bundle',job/'bundle'/'agent_tools',job/'bundle'/'scripts',job/'bundle'/'scripts'/'integration'): safe_dir(path)
 if (set(os.listdir(job/'bundle'))!={'agent_tools','scripts'} or
     set(os.listdir(job/'bundle'/'agent_tools'))!={'android_installer_target.py'} or
     set(os.listdir(job/'bundle'/'scripts'))!={'android_installer_lifecycle.py','android_no_update_tls_preflight.py','android_fixture_preflight.py','android_fixture_transport.py','android_fixture_trust.py','integration'} or
     set(os.listdir(job/'bundle'/'scripts'/'integration'))!={'android_update_fixture.py'}): unknown('bundle_inventory_changed')
tool_stream_pins={}
def tool_file_pin(path):
 info=path.lstat()
 if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1:unknown('tool_bundle_generation_changed')
 return [info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns,stat.S_IMODE(info.st_mode),info.st_uid,info.st_nlink]
def verify_tool_bundle():
 bundle=expected.get('toolBundle')
 if bundle is None:return
 if not isinstance(bundle,dict) or set(bundle)!={'toolBundleId','reviewedTreeSha256','manifest'} or not isinstance(bundle['toolBundleId'],str) or not re.fullmatch(r'sha256-[0-9a-f]{64}',bundle['toolBundleId']):unknown('tool_bundle_invalid')
 manifest=bundle['manifest']
 names=['agent_tools/android_installer_target.py','scripts/android_installer_lifecycle.py','scripts/android_no_update_tls_preflight.py','scripts/android_fixture_preflight.py','scripts/android_fixture_transport.py','scripts/android_fixture_trust.py','scripts/integration/android_update_fixture.py']
 if not isinstance(manifest,dict) or set(manifest)!={'schema','kind','files'} or type(manifest['schema']) is not int or manifest['schema']!=1 or manifest['kind']!='android-installer-reviewed-tools' or not isinstance(manifest['files'],list) or len(manifest['files'])!=7:unknown('tool_bundle_invalid')
 canonical=(json.dumps(manifest,sort_keys=True,separators=(',',':'))+'\n').encode()
 if hashlib.sha256(canonical).hexdigest()!=bundle['reviewedTreeSha256']:unknown('tool_bundle_invalid')
 entries={entry['name']:entry for entry in expected['files']}
 for name,item in zip(names,manifest['files']):
  if not isinstance(item,dict) or set(item)!={'path','size','sha256'} or item['path']!=name or type(item['size']) is not int or not 0<=item['size']<=8388608 or not isinstance(item['sha256'],str) or not re.fullmatch(r'[0-9a-f]{64}',item['sha256']):unknown('tool_bundle_invalid')
  if entries.get('bundle/'+name)!={'name':'bundle/'+name,'size':item['size'],'sha256':item['sha256']}:unknown('tool_bundle_manifest_changed')
  path=job/'bundle'/name;pin=tool_file_pin(path)
  if hashlib.sha256(private(path,max(1,item['size']))).hexdigest()!=item['sha256']:unknown('tool_bundle_manifest_changed')
  if tool_file_pin(path)!=pin or tool_stream_pins and tool_stream_pins.get(name)!=pin:unknown('tool_bundle_generation_changed')
 pins={name:tool_file_pin(job/'bundle'/name) for name in names}
 marker=job/'tool-bundle-owned.json'
 owned={'schema':1,'toolBundleId':bundle['toolBundleId'],'reviewedTreeSha256':bundle['reviewedTreeSha256'],'files':pins}
 if action=='start' and not marker.exists():put(marker,json.dumps(owned,sort_keys=True,separators=(',',':')).encode()+b'\n')
 elif json.loads(private(marker,8192))!=owned:unknown('tool_bundle_generation_changed')
def verify_manifest():
 safe_structure()
 verify_tool_bundle()
 for entry in expected['files']:
  path=job/entry['name']; meta=path.lstat()
  if not stat.S_ISREG(meta.st_mode) or meta.st_size!=entry['size'] or hashlib.sha256(private(path,max(1,entry['size']))).hexdigest()!=entry['sha256']: unknown('staged_bytes_changed')
def observe():
 if not job.exists(): unknown('job_missing')
 info=job.lstat()
 if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700: unknown('job_unsafe')
 if json.loads(private(job/'dispatch.json'))!=expected: unknown('dispatch_changed')
 verify_manifest()
 try: identity=json.loads(private(job/'identity.json',4096))
 except FileNotFoundError: unknown('identity_missing')
 pid=identity.get('pid'); start=identity.get('startTicks')
 if type(pid) is not int or type(start) is not int or pid<1 or start<1: unknown('identity_invalid')
 expected_lease={'owner':'android-installer','host':host,'device':device,'correlationId':correlation}
 if lease.exists():
  if json.loads(private(lease,1024))!=expected_lease: unknown('shared_lease_changed')
 elif (job/'release-intent.json').exists():
  if json.loads(private(job/'release-intent.json',1024))!={'correlationId':correlation,'resultState':'complete'}: unknown('release_intent_changed')
 else: unknown('shared_lease_missing')
 output=job/'output'
 namespace={'__name__':'staged_android_installer_target'}
 exec(compile(private(job/'bundle'/'agent_tools'/'android_installer_target.py',8388608),str(job/'bundle'/'agent_tools'/'android_installer_target.py'),'exec'),namespace)
 result=namespace['status'](output,correlation)
 alive=ticks(pid)==start
 if result.get('state')=='complete' and not alive:
  fixture_stopped(output)
  return result
 if result.get('state') in ('prepared','submitted','complete') and alive and (job/'release').exists(): return {'state':'running','operationId':result.get('operationId')}
 unknown('worker_or_receipt_unknown')
info=root.lstat()
if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700: unknown('remote_root_unsafe')
if action=='start':
 try:
  job.mkdir(mode=0o700); put(job/'dispatch.json',json.dumps(expected,sort_keys=True,separators=(',',':')).encode()+b'\n')
  (job/'output').mkdir(mode=0o700); (job/'bundle').mkdir(mode=0o700); (job/'bundle'/'scripts').mkdir(mode=0o700); (job/'bundle'/'scripts'/'integration').mkdir(mode=0o700); (job/'bundle'/'agent_tools').mkdir(mode=0o700)
  stage_fd=os.open(job/'stage.lock',os.O_RDWR|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
  stage_dir=os.open(job,os.O_RDONLY|os.O_DIRECTORY|getattr(os,'O_NOFOLLOW',0)); os.fsync(stage_dir); os.close(stage_dir)
  fcntl.flock(stage_fd,fcntl.LOCK_EX)
  fd=device_lock()
  try: put(lease,json.dumps({'owner':'android-installer','host':host,'device':device,'correlationId':correlation},sort_keys=True,separators=(',',':')).encode()+b'\n')
  finally: unlock(fd)
 except (OSError,ValueError): unknown('submission_uncertain')
 for entry in expected['files']:
  path=job/entry['name']; size=entry['size']; digest=hashlib.sha256(); remaining=size
  fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
  with os.fdopen(fd,'wb') as output:
   while remaining:
    block=sys.stdin.buffer.read(min(65536,remaining))
    if not block: unknown('stream_truncated')
    output.write(block); digest.update(block); remaining-=len(block)
   output.flush(); os.fsync(output.fileno())
  if digest.hexdigest()!=entry['sha256']: unknown('stream_hash_changed')
  if expected.get('toolBundle') is not None and entry['name'].startswith('bundle/'):
   tool_stream_pins[entry['name'].removeprefix('bundle/')]=tool_file_pin(path)
 if sys.stdin.buffer.read(1): unknown('stream_extra_bytes')
 verify_manifest()
 intent=json.loads(private(job/'output'/'intent.json',8192))
 if intent.get('correlationId')!=correlation or intent.get('host')!=host or intent.get('device')!=device or intent.get('pair',{}).get('sourceSha')!=expected['sourceSha']: unknown('installer_intent_changed')
 command=['python3','-I','-B',str(job/'bundle'/'scripts'/'android_installer_lifecycle.py'),
  '--adb',expected['adb'],'--serial',expected['serial'],'--api',str(expected['api']),'--avd',expected['avd'],'--device-port',str(expected['devicePort']),
  '--cli',expected['cli'],'--ca-certificate',str(job/'ca.pem'),'--leaf-certificate',str(job/'leaf.pem'),'--private-key',str(job/'key.pem'),
  '--output',str(job/'output'),'--intent-file',str(job/'output'/'intent.json'),'--continue-file',str(job/'output'/'continue'),
  '--handoff-ready-file',str(job/'output'/'handoff-ready'),'--governed-callbacks','--expected-terminal',expected['terminal'],
  '--base-apk',str(job/'base.apk'),'--base-sha256',intent['pair']['baseSha256'],'--base-version',intent['pair']['baseVersion'],'--base-code',str(intent['pair']['baseCode']),
  '--target-apk',str(job/'target.apk'),'--target-sha256',intent['pair']['targetSha256'],'--target-version',intent['pair']['targetVersion'],'--target-code',str(intent['pair']['targetCode'])]
 verify_tool_bundle()
 put(job/'launch-intent.json',json.dumps({'correlationId':correlation,'argvSha256':hashlib.sha256(json.dumps(command,separators=(',',':')).encode()).hexdigest()},sort_keys=True,separators=(',',':')).encode()+b'\n')
 if not pathlib.Path('/proc').is_dir(): unknown('proc_unavailable')
 launcher='import os,pathlib,sys,time\nrelease=pathlib.Path(sys.argv[1]); argv=sys.argv[2:]\nwhile not release.exists(): time.sleep(.02)\nos.execvp(argv[0],argv)\n'
 child=subprocess.Popen(['python3','-I','-B','-c',launcher,str(job/'release'),*command],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True,close_fds=True)
 for _ in range(100):
  start=ticks(child.pid)
  if start is not None: break
  time.sleep(.01)
 if start is None:
  child.terminate()
  try: child.wait(timeout=5)
  except subprocess.TimeoutExpired: unknown('worker_identity_unknown')
  unknown('worker_identity_unknown')
 put(job/'identity.json',json.dumps({'pid':child.pid,'startTicks':start},sort_keys=True,separators=(',',':')).encode()+b'\n')
 put(job/'release',b'go\n')
 emit('submitted',None,identity={'pid':child.pid,'startTicks':start})
if action=='abort-prelaunch':
 if not job.exists(): unknown('job_missing')
 job_info=job.lstat()
 if not stat.S_ISDIR(job_info.st_mode) or job_info.st_uid!=os.getuid() or stat.S_IMODE(job_info.st_mode)!=0o700: unknown('job_unsafe')
 if json.loads(private(job/'dispatch.json'))!=expected: unknown('dispatch_changed')
 try: stage_fd=os.open(job/'stage.lock',os.O_RDWR|getattr(os,'O_NOFOLLOW',0))
 except OSError: unknown('stage_lock_missing')
 stage_info=os.fstat(stage_fd)
 if not stat.S_ISREG(stage_info.st_mode) or stage_info.st_uid!=os.getuid() or stat.S_IMODE(stage_info.st_mode)!=0o600: unknown('stage_lock_unsafe')
 try: fcntl.flock(stage_fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
 except BlockingIOError: unknown('stage_worker_still_running')
 if any((job/name).exists() for name in ('launch-intent.json','identity.json','release')): unknown('launch_may_have_started')
 abort=job/'prelaunch-abort-intent.json'
 receipt={'correlationId':correlation,'phase':'before-launch'}
 fd=device_lock()
 try:
  if abort.exists():
   if json.loads(private(abort,1024))!=receipt: unknown('abort_intent_changed')
  else:
   value=json.loads(private(lease,1024))
   if value!={'owner':'android-installer','host':host,'device':device,'correlationId':correlation}: unknown('shared_lease_changed')
   put(abort,json.dumps(receipt,sort_keys=True,separators=(',',':')).encode()+b'\n')
  if lease.exists():
   value=json.loads(private(lease,1024))
   if value!={'owner':'android-installer','host':host,'device':device,'correlationId':correlation}: unknown('shared_lease_changed')
   lease.unlink(); directory=os.open(root,os.O_RDONLY|os.O_DIRECTORY|getattr(os,'O_NOFOLLOW',0)); os.fsync(directory); os.close(directory)
 finally: unlock(fd)
 emit('complete',None,leaseReleased=True,prelaunchAborted=True)
if action in ('callback-handoff-ready','callback-continue','callback-status-handoff-ready','callback-status-continue'):
 phase='handoff-ready' if action.endswith('handoff-ready') else 'continue'
 output=job/'output'; evidence=output/('callback-'+phase+'-evidence.json'); marker=output/phase
 callback_intent=job/('callback-'+phase+'-intent.json')
 if action.startswith('callback-status-'):
  if not callback_intent.exists() or not evidence.exists() or not marker.exists(): unknown('callback_not_complete')
  submitted=json.loads(private(callback_intent,1024))
  value=json.loads(private(evidence,4096))
  if (submitted!={'correlationId':correlation,'phase':phase,'operationId':value.get('operationId'),
                 'sourceSha':expected['sourceSha'],'targetArtifactId':expected['targetArtifactId']} or
      value.get('correlationId')!=correlation or value.get('phase')!=phase or
      hashlib.sha256(private(output/('callback-'+phase+'-ui.xml'),1048576)).hexdigest()!=value.get('uiSha256') or
      private(marker,32)!=b'continue\n'): unknown('callback_evidence_changed')
  emit('complete',None,callback=value)
 current=observe()
 if current.get('state')!='running': unknown('installer_worker_not_waiting')
 if callback_intent.exists() or evidence.exists() or marker.exists(): unknown('callback_already_submitted')
 product=json.loads(private(output/'intent.json',8192))
 pair=product.get('pair',{})
 if (product.get('correlationId')!=correlation or product.get('host')!=host or product.get('device')!=device or
     pair.get('sourceSha')!=expected['sourceSha'] or pair.get('targetArtifactId')!=expected['targetArtifactId'] or
     product.get('expectedOwner')!=expected['owner'] or product.get('expectedRevision')!=expected['revision'] or
     product.get('expectedAvd')!=expected['avd'] or product.get('expectedApi')!=expected['api']): unknown('callback_intent_changed')
 if json.loads(private(output/'phase-interactive.json',1024))!={'correlationId':correlation,'phase':'interactive'}: unknown('interactive_phase_missing')
 probe=json.loads(private(output/'probe.json',1048576))
 accepted=probe.get('callbackReceipt',{}).get('installerLifecycle',{}).get('interactiveAccepted',{}).get('response',{})
 operation=accepted.get('operationId')
 if (accepted.get('ok') is not True or accepted.get('code')!='ACCEPTED' or accepted.get('final') is not False or
     accepted.get('controllerId')!=expected['owner'] or accepted.get('configurationRevision')!=expected['revision'] or
     not isinstance(operation,str) or not operation): unknown('callback_operation_changed')
 if phase=='continue':
  previous=json.loads(private(output/'callback-handoff-ready-evidence.json',4096))
  handoff=json.loads(private(output/'handoff.json',1048576))
  identity=handoff.get('identity',{})
  if (private(output/'handoff-ready',32)!=b'continue\n' or previous.get('operationId')!=operation or
      identity.get('operationId')!=operation or identity.get('receiptId')!=previous.get('receiptId') or
      identity.get('sessionId')!=previous.get('sessionId')): unknown('callback_handoff_changed')
 put(callback_intent,json.dumps({'correlationId':correlation,'phase':phase,'operationId':operation,'sourceSha':expected['sourceSha'],'targetArtifactId':expected['targetArtifactId']},sort_keys=True,separators=(',',':')).encode()+b'\n')
 if phase=='continue':
  receipt_id=previous['receiptId']; session_id=previous['sessionId']
  retained=public_cli('updates','status'); terminal=retained.get('data',{}).get('installReceipt',{})
  if (not isinstance(terminal,dict) or terminal.get('installReceiptId')!=receipt_id or
      terminal.get('installSessionId')!=session_id or terminal.get('installPhase')!=expected['terminal'] or
      terminal.get('installed') is not (expected['terminal']=='installed') or
      not isinstance(retained.get('controllerId'),str) or not retained['controllerId'] or
      type(retained.get('configurationRevision')) is not int): unknown('callback_terminal_session_changed')
  observed_owner=retained['controllerId']; observed_revision=retained['configurationRevision']
 else:
  historical=public_cli('operations','status',operation)
  data=historical.get('data',{})
  if (historical.get('operationId')!=operation or historical.get('controllerId')!=expected['owner'] or
      historical.get('configurationRevision')!=expected['revision'] or
      data.get('installerStarted') is not True or data.get('installPhase')!='handed_off' or
      not isinstance(data.get('installReceiptId'),str) or not data['installReceiptId'] or
      type(data.get('installSessionId')) is not int): unknown('callback_session_changed')
  receipt_id=data['installReceiptId']; session_id=data['installSessionId']
  observed_owner=expected['owner']; observed_revision=expected['revision']
 workspace=public_cli('status')
 workspace_data=workspace.get('data',{})
 if (workspace.get('controllerId')!=observed_owner or
     workspace.get('configurationRevision')!=observed_revision or
     not isinstance(workspace_data,dict) or workspace_data.get('runtimeRunning') is not False or
     workspace_data.get('runtimeObservation')!='stopped'): unknown('callback_workspace_changed')
 snapshot=callback_snapshot(phase)
 value={'correlationId':correlation,'phase':phase,'sourceSha':expected['sourceSha'],
        'targetArtifactId':expected['targetArtifactId'],'operationId':operation,
        'receiptId':receipt_id,'sessionId':session_id,'owner':observed_owner,
        'revision':observed_revision,**snapshot}
 put(evidence,json.dumps(value,sort_keys=True,separators=(',',':')).encode()+b'\n')
 put(marker,b'continue\n')
 emit('complete',None,callback=value)
if action=='status':
 result=observe(); emit(result['state'],None,result=result)
if action=='collect':
 result=observe()
 if result['state']!='complete': unknown('terminal_not_complete')
 emit('complete',None,result=result)
if action=='finalize':
 result=observe()
 if result['state']!='complete': unknown('terminal_not_complete')
 fd=device_lock()
 try:
  release_intent=job/'release-intent.json'
  if release_intent.exists():
   saved=json.loads(private(release_intent,1024))
   if saved!={'correlationId':correlation,'resultState':'complete'}: unknown('release_intent_changed')
   if lease.exists():
    value=json.loads(private(lease,1024))
    if value!={'owner':'android-installer','host':host,'device':device,'correlationId':correlation}: unknown('shared_lease_changed')
    lease.unlink()
    directory=os.open(root,os.O_RDONLY|os.O_DIRECTORY|getattr(os,'O_NOFOLLOW',0)); os.fsync(directory); os.close(directory)
   emit('complete',None,result=result,leaseReleased=True)
  value=json.loads(private(lease,1024))
  if value!={'owner':'android-installer','host':host,'device':device,'correlationId':correlation}: unknown('shared_lease_changed')
  put(release_intent,json.dumps({'correlationId':correlation,'resultState':'complete'},sort_keys=True,separators=(',',':')).encode()+b'\n')
  lease.unlink()
  directory=os.open(root,os.O_RDONLY|os.O_DIRECTORY|getattr(os,'O_NOFOLLOW',0)); os.fsync(directory); os.close(directory)
 finally: unlock(fd)
 emit('complete',None,result=result,leaseReleased=True)
unknown('invalid_action')
'''


def _local_intent(root: Path, correlation_id: str) -> dict[str, Any]:
    if not isinstance(correlation_id, str) or not _UUID.fullmatch(correlation_id):
        raise ValueError("Android installer dispatch requires canonical UUID")
    value = json.loads(android_installer_target._private_file(
        _directory(root) / correlation_id / "dispatch.json", 16_384))
    if not isinstance(value, dict) or value.get("correlationId") != correlation_id:
        raise ValueError("Android installer dispatch intent is unavailable")
    return value


def _remote(root: Path, intent: dict[str, Any], action: str,
            payload: Path | None = None) -> dict[str, Any]:
    if action not in {"start", "status", "collect", "finalize", "abort-prelaunch",
                      "callback-handoff-ready", "callback-continue",
                      "callback-status-handoff-ready", "callback-status-continue"}:
        raise ValueError("Android installer remote action is not fixed")
    if intent.get('toolBundleId') is not None:
        tools=android_installer_tool_bundle.load(root,intent['toolBundleId'])
        if intent['remote'].get('toolBundle')!={key:tools[key] for key in ('toolBundleId','reviewedTreeSha256','manifest')}:
            raise ValueError('Installer tool bundle binding changed')
    config = ssh_transport.load_config(root)
    host = intent["host"]
    if (host not in config.hosts or ssh_transport.connection_host(config, host).password is not None or
            str(config.hosts[host].fixture_transfer_root) != intent["fixtureRoot"]):
        return {"state": "unknown", "reason": "route_changed"}
    expected = intent["remote"]
    argv = ssh_transport.build_ssh_argv(config, host, 60, command=(
        "python3", "-I", "-B", "-c", "exec(" + repr(_REMOTE) + ")", action,
        intent["fixtureRoot"], host, intent["device"], intent["correlationId"],
        json.dumps(expected, sort_keys=True, separators=(",", ":"))))
    try:
        stream = ssh_transfer.StreamPayload(b"", payload) if payload is not None else None
        code, output = ssh_transfer._bounded_run(argv, stream, 300 if payload is not None else 60)
        value = json.loads(output.decode("utf-8", "strict")) if code == 0 else None
        if (isinstance(value, dict) and value.get("correlationId") == intent["correlationId"] and
                value.get("state") in {"submitted", "running", "complete", "unknown"}):
            return value
    except (OSError, ValueError, UnicodeError, ssh_transfer.SshTransferError):
        pass
    return {"state": "unknown", "reason": "transport_or_receipt_unknown"}


def _result(intent: dict[str, Any], remote: dict[str, Any]) -> dict[str, Any]:
    state = remote.get("state", "unknown")
    return {"ok": state in {"submitted", "running", "complete"}, "state": state,
            "reason": remote.get("reason"), "correlationId": intent["correlationId"],
            "result": remote.get("result"), "identity": remote.get("identity"),
            "leaseReleased": remote.get("leaseReleased") is True,
            "replayAllowed": False}


def start(root: Path | str, host: str, device: str, correlation_id: str,
          source_sha: str, base_artifact_id: str, target_artifact_id: str,
          backup_correlation_id: str, inspect_correlation_id: str,
          expected_owner: str, expected_revision: int, expected_backup_sha256: str,
          expected_terminal: str, cli_stage_correlation_id: str,
          ca_artifact_id: str, leaf_artifact_id: str, key_artifact_id: str, *, tool_bundle_id: str | None = None) -> dict[str, Any]:
    """Journal, lease, stage exact bytes, then release one fixed detached runner."""
    root = Path(root).resolve()
    if any(not isinstance(value, str) or not _UUID.fullmatch(value) for value in
           (correlation_id, backup_correlation_id, inspect_correlation_id, cli_stage_correlation_id)):
        raise ValueError("Android installer correlations must be canonical UUIDs")
    config = ssh_transport.load_config(root)
    if (host not in config.hosts or device not in config.hosts[host].android_devices or
            config.hosts[host].fixture_transfer_root is None or
            ssh_transport.connection_host(config, host).password is not None):
        raise ValueError("Android installer requires a configured key-only AVD")
    profile = android_observation._profile(config.hosts[host].android_devices[device])
    cli = android_cli_stage.collect(root, cli_stage_correlation_id)
    cli_intent = android_cli_stage._read_intent(root, cli_stage_correlation_id)
    if (cli.get("ok") is not True or cli.get("state") != "published" or
            cli.get("sourceSha") != source_sha or not isinstance(cli_intent, dict) or
            cli_intent.get("host") != host or cli.get("receipt", {}).get("cliPath") is None):
        raise ValueError("Android installer current-source public CLI is not staged")
    pair = android_installer_target.admit_pair(root, source_sha, base_artifact_id,
                                                target_artifact_id, base_artifact_id.removeprefix("sha256-"))
    fixture_root = config.hosts[host].fixture_transfer_root
    output = _directory(root) / correlation_id
    opening = android_admission_readback.async_collect(root, backup_correlation_id)
    backup_path = opening.get("result", {}).get("backup", {}).get("path")
    if not isinstance(backup_path, str):
        raise ValueError("Android installer remote backup path is unavailable")
    # Fixture tooling is independently reviewed; product/APK/CLI/TLS retain
    # their original source SHA. Reject tooling/TLS before consuming an intent.
    ca = _fixture_bytes(root, ca_artifact_id, "fixture-ca", source_sha)
    leaf = _fixture_bytes(root, leaf_artifact_id, "fixture-leaf", source_sha)
    key = _fixture_bytes(root, key_artifact_id, "fixture-private-key", source_sha)
    tools = android_installer_tool_bundle.load(root, tool_bundle_id) if tool_bundle_id is not None else None
    files: list[tuple[str, bytes | Path]] = [("bundle/" + name,
        tools['files'][name] if tools is not None else _source_bytes(root, source_sha, name)) for name in _BUNDLE]
    android_installer_target.create_intent(root, output, correlation_id, pair, host=host, device=device,
        backup_correlation_id=backup_correlation_id, inspect_correlation_id=inspect_correlation_id,
        expected_avd=profile["expectedAvd"], expected_api=profile["api"],
        expected_owner=expected_owner, expected_revision=expected_revision,
        backup_path=backup_path, backup_sha256=expected_backup_sha256,
        expected_terminal=expected_terminal)
    files += [("output/intent.json", output / "intent.json"), ("ca.pem", ca),
              ("leaf.pem", leaf), ("key.pem", key),
              ("base.apk", Path(pair["basePath"])), ("target.apk", Path(pair["targetPath"]))]
    manifest = _snapshot_payload(output, files)
    remote = {"sourceSha": source_sha, "files": manifest, "adb": profile["adb"],
              "cli": cli["receipt"]["cliPath"], "serial": profile["serial"],
              "avd": profile["expectedAvd"], "api": profile["api"],
              "devicePort": 45600 + profile["api"], "terminal": expected_terminal,
              "targetArtifactId": target_artifact_id, "owner": expected_owner,
              "revision": expected_revision}
    if tools is not None:
        remote['toolBundle'] = {key: tools[key] for key in ('toolBundleId','reviewedTreeSha256','manifest')}
    intent = {"schema": 1, "host": host, "device": device, "correlationId": correlation_id,
              "sourceSha": source_sha, "fixtureRoot": str(fixture_root),
              "cliStageCorrelationId": cli_stage_correlation_id,
              "baseArtifactId": base_artifact_id, "targetArtifactId": target_artifact_id,
              "backupCorrelationId": backup_correlation_id,
              "inspectCorrelationId": inspect_correlation_id,
              "caArtifactId": ca_artifact_id, "leafArtifactId": leaf_artifact_id,
              "keyArtifactId": key_artifact_id, "remote": remote}
    if tools is not None:
        intent['toolBundleId'] = tool_bundle_id
        if android_installer_tool_bundle.load(root, tool_bundle_id) != tools:
            raise ValueError('Installer tool bundle changed before dispatch')
    android_installer_target._write_private(output / "dispatch.json", intent)
    _claim_local(root, host, device, correlation_id)
    value = _remote(root, intent, "start", output / "payload.bin")
    return _result(intent, value)


def status(root: Path | str, correlation_id: str) -> dict[str, Any]:
    root = Path(root).resolve(); intent = _local_intent(root, correlation_id)
    value = _remote(root, intent, "status")
    return _result(intent, value)


def callback(root: Path | str, correlation_id: str, phase: str) -> dict[str, Any]:
    """Observe one exact OS dialog/session phase and signal only that phase once."""
    if phase not in {"handoff-ready", "continue"}:
        raise ValueError("Android installer callback phase is not fixed")
    root = Path(root).resolve(); intent = _local_intent(root, correlation_id)
    value = _remote(root, intent, "callback-" + phase)
    return _bounded_callback(intent, value, phase)


def callback_status(root: Path | str, correlation_id: str, phase: str) -> dict[str, Any]:
    if phase not in {"handoff-ready", "continue"}:
        raise ValueError("Android installer callback phase is not fixed")
    root = Path(root).resolve(); intent = _local_intent(root, correlation_id)
    value = _remote(root, intent, "callback-status-" + phase)
    return _bounded_callback(intent, value, phase)


def _bounded_callback(intent: dict[str, Any], value: dict[str, Any], phase: str) -> dict[str, Any]:
    callback_value = value.get("callback")
    if (value.get("state") != "complete" or not isinstance(callback_value, dict) or
            callback_value.get("correlationId") != intent["correlationId"] or
            callback_value.get("phase") != phase or
            callback_value.get("sourceSha") != intent["sourceSha"] or
            callback_value.get("targetArtifactId") != intent["targetArtifactId"] or
            not isinstance(callback_value.get("uiSha256"), str) or
            not _SHA.fullmatch(callback_value["uiSha256"])):
        return {"ok": False, "state": "unknown", "reason": value.get("reason") or "callback_unbound",
                "correlationId": intent["correlationId"], "phase": phase, "replayAllowed": False}
    return {"ok": True, "state": "complete", "correlationId": intent["correlationId"],
            "phase": phase, "uiSha256": callback_value["uiSha256"],
            "operationId": callback_value.get("operationId"),
            "receiptId": callback_value.get("receiptId"),
            "sessionId": callback_value.get("sessionId"), "replayAllowed": False}


def collect(root: Path | str, correlation_id: str) -> dict[str, Any]:
    root = Path(root).resolve(); intent = _local_intent(root, correlation_id)
    value = _remote(root, intent, "collect")
    bounded = _result(intent, value)
    if bounded["state"] != "complete":
        return {**bounded, "ok": False}
    result = bounded.get("result")
    if (not isinstance(result, dict) or result.get("state") != "complete" or
            result.get("correlationId") != correlation_id or result.get("replayAllowed") is not False):
        return {**bounded, "ok": False, "state": "unknown", "reason": "terminal_result_unbound"}
    return bounded


def abort_prelaunch(root: Path | str, correlation_id: str, closing_readback_correlation_id: str) -> dict[str, Any]:
    """Release an interrupted upload only after no-launch proof and fresh baseline."""
    root = Path(root).resolve(); intent = _local_intent(root, correlation_id)
    if not isinstance(closing_readback_correlation_id, str) or not _UUID.fullmatch(closing_readback_correlation_id):
        raise ValueError("Android installer prelaunch closing readback requires UUID")
    original = android_installer_target.load_intent(_directory(root) / correlation_id / "intent.json")
    config = ssh_transport.load_config(root)
    if intent["host"] not in config.hosts or intent["device"] not in config.hosts[intent["host"]].android_devices:
        return {"ok": False, "state": "unknown", "reason": "configured_device_changed",
                "correlationId": correlation_id, "replayAllowed": False}
    profile = android_observation._profile(config.hosts[intent["host"]].android_devices[intent["device"]])
    if any(profile.get(field) != intent["remote"].get(other) for field, other in (
            ("serial", "serial"), ("expectedAvd", "avd"), ("api", "api"), ("adb", "adb"))):
        return {"ok": False, "state": "unknown", "reason": "configured_device_changed",
                "correlationId": correlation_id, "replayAllowed": False}
    observed = android_admission_readback.readback_status(root, intent["host"], intent["device"],
                                                            closing_readback_correlation_id)
    collected = android_admission_readback.async_collect(root, closing_readback_correlation_id)
    state, result = observed.get("result", {}), collected.get("result", {})
    if (observed.get("ok") is not True or state.get("stage") != "backup_present" or
            state.get("deviceIdentity") is not True or
            state.get("controllerId") != original["expectedOwner"] or
            state.get("configurationRevision") != original["expectedRevision"] or
            state.get("backup", {}).get("sha256") != original["backupSha256"] or
            state.get("backup", {}).get("size") != original["backupSize"] or
            state.get("backup", {}).get("formatValid") is not True or
            collected.get("ok") is not True or collected.get("state") != "complete" or
            result.get("package", {}).get("baseSha256") != original["pair"]["baseSha256"] or
            result.get("device", {}).get("uid") != "2000" or
            result.get("device", {}).get("avd") != original["expectedAvd"] or
            result.get("device", {}).get("api") != original["expectedApi"] or
            result.get("guard", {}).get("controllerId") != original["expectedOwner"] or
            result.get("guard", {}).get("configurationRevision") != original["expectedRevision"] or
            result.get("backup", {}).get("sha256") != original["backupSha256"]):
        return {"ok": False, "state": "unknown", "reason": "closing_readback_changed",
                "correlationId": correlation_id, "replayAllowed": False}
    public = android_public_inspect.inspect(root, intent["host"], intent["device"], str(uuid4()),
            original["pair"]["baseSha256"], original["expectedOwner"], original["expectedRevision"])
    seen = public.get("result", {})
    if (public.get("ok") is not True or public.get("outcome") != "admitted" or
            seen.get("packageSha256") != original["pair"]["baseSha256"] or
            seen.get("controllerId") != original["expectedOwner"] or
            seen.get("configurationRevision") != original["expectedRevision"] or
            seen.get("device", {}).get("uid") != "2000" or
            seen.get("device", {}).get("avd") != original["expectedAvd"] or
            seen.get("device", {}).get("api") != original["expectedApi"] or
            seen.get("runtime", {}).get("running") is not False or
            seen.get("runtime", {}).get("observation") != "stopped"):
        return {"ok": False, "state": "unknown", "reason": "closing_public_state_changed",
                "correlationId": correlation_id, "replayAllowed": False}
    # The remote stage lock proves a lost SSH upload has exited; its durable
    # abort marker precedes unlink of the exact remote shared lease.
    remote = _remote(root, intent, "abort-prelaunch")
    if remote.get("state") != "complete" or remote.get("prelaunchAborted") is not True or remote.get("leaseReleased") is not True:
        return _result(intent, remote)
    released = _release_local(root, intent["host"], intent["device"], correlation_id)
    return {"ok": released, "state": "complete" if released else "unknown",
            "reason": None if released else "local_lease_not_released", "correlationId": correlation_id,
            "prelaunchAborted": True, "leaseReleased": released, "replayAllowed": False}


def reconcile(root: Path | str, correlation_id: str, closing_readback_correlation_id: str,
              expected_closing_owner: str, expected_closing_revision: int) -> dict[str, Any]:
    """Release both leases only after exact terminal and fresh detached readback."""
    root = Path(root).resolve(); intent = _local_intent(root, correlation_id)
    if not isinstance(closing_readback_correlation_id, str) or not _UUID.fullmatch(closing_readback_correlation_id):
        raise ValueError("Android installer closing readback requires UUID")
    if not isinstance(expected_closing_owner, str) or not expected_closing_owner or type(expected_closing_revision) is not int:
        raise ValueError("Android installer closing owner identity is invalid")
    terminal = collect(root, correlation_id)
    if terminal.get("ok") is not True:
        return {"ok": False, "state": "unknown", "reason": "installer_not_terminal",
                "correlationId": correlation_id, "replayAllowed": False}
    original = android_installer_target.load_intent(_directory(root) / correlation_id / "intent.json")
    terminal_result = terminal.get("result")
    if (not isinstance(terminal_result, dict) or
            terminal_result.get("terminal") != original["expectedTerminal"] or
            terminal_result.get("terminalOwner") != expected_closing_owner or
            terminal_result.get("terminalRevision") != expected_closing_revision or
            (original["expectedTerminal"] == "cancelled" and
             (expected_closing_owner != original["expectedOwner"] or
              expected_closing_revision != original["expectedRevision"]))):
        return {"ok": False, "state": "unknown", "reason": "closing_owner_changed",
                "correlationId": correlation_id, "replayAllowed": False}
    config = ssh_transport.load_config(root)
    if intent["host"] not in config.hosts or intent["device"] not in config.hosts[intent["host"]].android_devices:
        return {"ok": False, "state": "unknown", "reason": "configured_device_changed",
                "correlationId": correlation_id, "replayAllowed": False}
    profile = android_observation._profile(config.hosts[intent["host"]].android_devices[intent["device"]])
    if any(profile.get(field) != intent["remote"].get(other) for field, other in (
            ("serial", "serial"), ("expectedAvd", "avd"), ("api", "api"), ("adb", "adb"))):
        return {"ok": False, "state": "unknown", "reason": "configured_device_changed",
                "correlationId": correlation_id, "replayAllowed": False}
    expected_hash = (original["pair"]["targetSha256"] if original["expectedTerminal"] == "installed"
                     else original["pair"]["baseSha256"])
    observed = android_admission_readback.readback_status(root, intent["host"], intent["device"],
                                                            closing_readback_correlation_id)
    collected = android_admission_readback.async_collect(root, closing_readback_correlation_id)
    state, result = observed.get("result", {}), collected.get("result", {})
    if (observed.get("ok") is not True or state.get("stage") != "backup_present" or
            state.get("controllerId") != expected_closing_owner or
            state.get("configurationRevision") != expected_closing_revision or
            state.get("deviceIdentity") is not True or
            state.get("backup", {}).get("formatValid") is not True or
            state.get("backup", {}).get("sha256") != original["backupSha256"] or
            state.get("backup", {}).get("size") != original["backupSize"] or
            collected.get("ok") is not True or collected.get("state") != "complete" or
            result.get("package", {}).get("baseSha256") != expected_hash or
            result.get("device", {}).get("uid") != "2000" or
            result.get("device", {}).get("avd") != original["expectedAvd"] or
            result.get("device", {}).get("api") != original["expectedApi"] or
            result.get("guard", {}).get("controllerId") != expected_closing_owner or
            result.get("guard", {}).get("configurationRevision") != expected_closing_revision or
            result.get("backup", {}).get("sha256") != state.get("backup", {}).get("sha256")):
        return {"ok": False, "state": "unknown", "reason": "closing_readback_changed",
                "correlationId": correlation_id, "replayAllowed": False}
    public = android_public_inspect.inspect(root, intent["host"], intent["device"], str(uuid4()),
                                            expected_hash, expected_closing_owner, expected_closing_revision)
    seen = public.get("result", {})
    if (public.get("ok") is not True or public.get("outcome") != "admitted" or
            seen.get("packageSha256") != expected_hash or
            seen.get("controllerId") != expected_closing_owner or
            seen.get("configurationRevision") != expected_closing_revision or
            seen.get("device", {}).get("uid") != "2000" or
            seen.get("device", {}).get("avd") != original["expectedAvd"] or
            seen.get("device", {}).get("api") != original["expectedApi"] or
            seen.get("runtime", {}).get("running") is not False or
            seen.get("runtime", {}).get("observation") != "stopped"):
        return {"ok": False, "state": "unknown", "reason": "closing_public_state_changed",
                "correlationId": correlation_id, "replayAllowed": False}
    remote = _remote(root, intent, "finalize")
    if remote.get("state") != "complete" or remote.get("leaseReleased") is not True:
        return _result(intent, remote)
    released = _release_local(root, intent["host"], intent["device"], correlation_id)
    return {"ok": released, "state": "complete" if released else "unknown",
            "reason": None if released else "local_lease_not_released", "correlationId": correlation_id,
            "leaseReleased": released, "replayAllowed": False}
