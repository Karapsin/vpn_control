"""One-shot device admission for the source-bound Android HTTPS/SOCKS fixture.

Only an explicitly configured disposable emulator may receive the fixture CA and
two fixed ADB reverses.  Unknown submissions retain both leases for inspection.
This module has no public app mutation, package install, VPN, or force-stop path.
"""

from __future__ import annotations

import base64
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

from agent_tools import (android_admission_readback, android_native_fixture,
                         android_native_fixture_lifecycle, android_observation,
                         native_artifact_registry, ssh_transfer, ssh_transport)


_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_ARTIFACT = re.compile(r"sha256-[0-9a-f]{64}\Z")
_ALIAS = re.compile(r"[a-z0-9][a-z0-9-]{0,39}\Z")
_MAX_CA = 65_536


def _stable_ca(root: Path, artifact_id: str, source_sha: str) -> bytes:
    if not isinstance(artifact_id, str) or not _ARTIFACT.fullmatch(artifact_id):
        raise ValueError("Android endpoint requires exact CA artifact ID")
    verified = native_artifact_registry.verify_artifact(root, artifact_id)
    item, location = verified.get("artifact", {}), verified.get("location", {})
    if (verified.get("verification") != "verified" or item.get("platform") != "android" or
            item.get("artifactKind") != "fixture-ca" or item.get("sha256") != artifact_id[7:] or
            not isinstance(location.get("localPath"), str)):
        raise ValueError("Android endpoint CA artifact is unverified")
    if item.get("sourceSha") != source_sha:
        raise ValueError("Android endpoint CA artifact belongs to another source")
    path = Path(location["localPath"])
    if not path.is_absolute():
        raise ValueError("Android endpoint CA location is not absolute")
    if any(stat.S_ISLNK(parent.lstat().st_mode) for parent in (path.parent, *path.parent.parents)):
        raise ValueError("Android endpoint CA path has symlink ancestry")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or
                before.st_nlink != 1 or not 0 < before.st_size <= _MAX_CA):
            raise ValueError("Android endpoint CA file is unsafe")
        payload = os.read(descriptor, _MAX_CA + 1)
        after = os.fstat(descriptor)
        if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) !=
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) or
                len(payload) != before.st_size or hashlib.sha256(payload).hexdigest() != item["sha256"]):
            raise ValueError("Android endpoint CA bytes changed")
        return payload
    finally:
        os.close(descriptor)


def _local_directory(root: Path) -> Path:
    directory = root / ".rag_index" / "android-endpoint-admission"
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError("Android endpoint journal directory is unsafe")
    return directory


def _intent_path(root: Path, correlation_id: str) -> Path:
    if not isinstance(correlation_id, str) or not _UUID.fullmatch(correlation_id):
        raise ValueError("Android endpoint requires canonical correlation UUID")
    return _local_directory(root) / (correlation_id + ".json")


@contextmanager
def _shared_device_lease(root: Path, host: str, device: str):
    """Serialize endpoint and installer claims on the same exact AVD."""
    directory = root / ".rag_index" / "android-native-device-leases"
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError("Android shared device lease directory is unsafe")
    lease = directory / ("lease-" + host + "-" + device + ".json")
    lock = directory / ("lock-" + host + "-" + device + ".json")
    descriptor = os.open(lock, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        meta = os.fstat(descriptor)
        if not stat.S_ISREG(meta.st_mode) or meta.st_uid != os.getuid() or stat.S_IMODE(meta.st_mode) != 0o600:
            raise ValueError("Android shared device lock is unsafe")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield lease
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _read_intent(root: Path, correlation_id: str) -> dict[str, Any]:
    return android_native_fixture_lifecycle._read_plan(_intent_path(root, correlation_id))


def _response(state: str, correlation_id: str, reason: str | None = None, **extra: Any) -> dict[str, Any]:
    return {"ok": state in {"ready", "cleaned"}, "state": state, "reason": reason,
            "correlationId": correlation_id, "replayAllowed": False,
            "productMutationAllowed": False, "installerTargetAdmitted": False, **extra}


def _mount_proof(expected: dict[str, Any], observed: dict[str, Any], mountinfo: str) -> bool:
    """Require a unique bind in the same zygote generation and mount namespace."""
    if (not isinstance(expected, dict) or not isinstance(observed, dict) or
            observed != {key: expected.get(key) for key in ("pid", "startTicks", "namespace")} or
            not isinstance(mountinfo, str)):
        return False
    target, staging = expected.get("target"), expected.get("staging")
    if not isinstance(target, str) or not isinstance(staging, str):
        return False
    entries = []
    for line in mountinfo.splitlines():
        fields = line.split(" - ", 1)[0].split()
        if len(fields) >= 5 and fields[4] == target:
            entries.append(fields[3])
    return bool(entries) and entries[-1] == staging


_REMOTE = r'''
import base64,fcntl,hashlib,json,os,pathlib,re,stat,subprocess,sys
action,root_raw,device,correlation,expected_json=sys.argv[1:]
root=pathlib.Path(root_raw); expected=json.loads(expected_json)
job=root/('android-endpoint-'+correlation)
lease=root/('android-native-device-'+device+'.lease')
lock=root/('android-native-device-'+device+'.lock')
def emit(state,reason=None,**extra):
 print(json.dumps({'state':state,'reason':reason,'correlationId':correlation,**extra},sort_keys=True,separators=(',',':')),flush=True)
 raise SystemExit(0)
def unknown(reason): emit('unknown',reason)
def private(path,limit=67108864):
 try:
  parts=path.relative_to(root).parts
  if not parts or any(part in ('','.','..') for part in parts): unknown('private_path_invalid')
  parent=os.open(root,os.O_RDONLY|os.O_DIRECTORY|getattr(os,'O_NOFOLLOW',0))
  try:
   for part in parts[:-1]:
    child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|getattr(os,'O_NOFOLLOW',0),dir_fd=parent)
    os.close(parent); parent=child
    info=os.fstat(parent)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700: unknown('private_parent_unsafe')
   fd=os.open(parts[-1],os.O_RDONLY|getattr(os,'O_NOFOLLOW',0),dir_fd=parent)
   with os.fdopen(fd,'rb') as stream:
    info=os.fstat(stream.fileno())
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1 or info.st_size>limit: unknown('private_file_unsafe')
    raw=stream.read(limit+1); after=os.fstat(stream.fileno())
    if len(raw)!=info.st_size or (info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns): unknown('private_file_changed')
    return raw
  finally: os.close(parent)
 except (OSError,ValueError): unknown('private_file_unavailable')
def record(path,value):
 raw=(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
 with os.fdopen(fd,'wb') as output: output.write(raw); output.flush(); os.fsync(output.fileno())
 directory=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|getattr(os,'O_NOFOLLOW',0)); os.fsync(directory); os.close(directory)
def command(argv,timeout=30,max_bytes=1048576,env=None):
 try: result=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=timeout,check=False,env=env)
 except (OSError,subprocess.TimeoutExpired): unknown('command_outcome_unknown')
 if result.returncode or len(result.stdout)>max_bytes: unknown('command_failed')
 try: return result.stdout.decode('utf-8','strict').strip()
 except UnicodeError: unknown('command_encoding')
adb=expected['adb']; cli=expected['cli']; serial=expected['serial']; api=str(expected['api']); avd=expected['avd']
environment=public_cli_environment(adb,pathlib.Path(cli))
def adb_call(*args,timeout=30,max_bytes=1048576): return command([adb,'-s',serial,*args],timeout,max_bytes)
def shell(*args): return adb_call('shell','-T',*args)
def identity(uid='2000'):
 if shell('id','-u')!=uid or shell('getprop','ro.build.version.sdk')!=api or {x for x in (shell('getprop','ro.kernel.qemu.avd_name'),shell('getprop','ro.boot.qemu.avd_name')) if x}!={avd} or shell('getprop','ro.product.cpu.abi')!='x86_64': unknown('device_identity_changed')
def installed():
 paths=[x.removeprefix('package:') for x in shell('pm','path','com.kardinal.vpncontrol').splitlines() if x.startswith('package:') and x.endswith('/base.apk')]
 if len(paths)!=1 or not paths[0].startswith('/data/app/'): unknown('package_path_changed')
 parts=shell('sha256sum',paths[0]).split()
 if len(parts)!=2 or parts[1]!=paths[0] or parts[0]!=expected['packageSha256']: unknown('package_changed')
def public(*args):
 value=json.loads(command([cli,'--json','--android','--serial',serial,'--timeout-seconds','30',*args],max_bytes=65536,env=environment))
 if not isinstance(value,dict) or value.get('ok') is not True or value.get('final') is not True or value.get('code')!='OK' or value.get('controllerId')!=expected['owner'] or value.get('configurationRevision')!=expected['revision']: unknown('owner_changed')
 return value
def guard():
 identity(); installed()
 status=public('status'); data=status.get('data')
 if not isinstance(data,dict) or data.get('runtimeRunning') is not False or data.get('runtimeObservation')!='stopped': unknown('runtime_not_off')
 ops=public('operations','list').get('data',{}).get('operations')
 if not isinstance(ops,list) or any(not isinstance(x,dict) or x.get('final') is not True for x in ops): unknown('history_unknown')
 backup=pathlib.Path(expected['backupPath'])
 if not backup.is_relative_to(root) or hashlib.sha256(private(backup)).hexdigest()!=expected['backupSha256']: unknown('backup_changed')
 return status
def routes():
 raw=adb_call('reverse','--list',max_bytes=16384); result={}
 for line in raw.splitlines():
  fields=line.split()
  if len(fields)==3 and fields[0]==serial: fields=fields[1:]
  if len(fields)!=2 or any(not re.fullmatch(r'tcp:[0-9]+',x) for x in fields): unknown('reverse_inventory_invalid')
  port=int(fields[0][4:]); host=int(fields[1][4:])
  if not 1<=port<=65535 or not 1<=host<=65535 or port in result: unknown('reverse_inventory_invalid')
  result[port]=host
 return result
def fixture_routes():
 current=routes()
 if current!={18080:expected['httpsHostPort'],18081:expected['socksHostPort']}: unknown('fixture_reverse_changed_or_foreign')
 return current
def host_fixture_leaf():
 path=root/('android-native-fixture-'+expected['campaignId'])/'certificate.pem'
 raw=private(path,65536)
 if hashlib.sha256(raw).hexdigest()!=expected['leafSha256']: unknown('host_fixture_leaf_changed')
 return raw
def zygote_identity(pid):
 if not isinstance(pid,str) or not pid.isdecimal() or int(pid)<1: unknown('zygote_identity_invalid')
 raw=shell('cat','/proc/'+pid+'/stat')
 try: ticks=int(raw.rsplit(')',1)[1].split()[19])
 except (IndexError,ValueError): unknown('zygote_generation_invalid')
 namespace=shell('readlink','/proc/'+pid+'/ns/mnt')
 if ticks<1 or not re.fullmatch(r'mnt:\[[0-9]+\]',namespace): unknown('zygote_namespace_invalid')
 return {'pid':pid,'startTicks':ticks,'namespace':namespace}
def staging_identity(path):
 raw=shell('stat','-c','%u:%a:%d:%i',path)
 if not re.fullmatch(r'0:755:[0-9]+:[0-9]+',raw): unknown('staging_identity_invalid')
 return raw
def mount_observed(plan):
 if zygote_identity(plan['zygote']['pid'])!=plan['zygote']: unknown('zygote_reused')
 mountinfo=shell('cat','/proc/'+plan['zygote']['pid']+'/mountinfo')
 entries=[]
 for line in mountinfo.splitlines():
  fields=line.split(' - ',1)[0].split()
  if len(fields)>=5 and fields[4]==plan['target']: entries.append(fields[3])
 if not entries or entries[-1]!=plan['staging']: unknown('fixture_mount_missing_or_changed')
 return True
def mount_exact(plan):
 if zygote_identity(plan['zygote']['pid'])!=plan['zygote']: unknown('zygote_reused_before_mount')
 shell('nsenter','-t',plan['zygote']['pid'],'-m','--','mount','--bind',plan['staging'],plan['target'])
 if zygote_identity(plan['zygote']['pid'])!=plan['zygote']: unknown('zygote_reused_after_mount')
def unmount_exact(plan):
 if zygote_identity(plan['zygote']['pid'])!=plan['zygote']: unknown('zygote_reused_before_umount')
 shell('nsenter','-t',plan['zygote']['pid'],'-m','--','umount',plan['target'])
 if zygote_identity(plan['zygote']['pid'])!=plan['zygote']: unknown('zygote_reused_after_umount')
def lease_lock():
 fd=os.open(lock,os.O_RDWR|os.O_CREAT|getattr(os,'O_NOFOLLOW',0),0o600)
 info=os.fstat(fd)
 if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600: unknown('device_lock_unsafe')
 fcntl.flock(fd,fcntl.LOCK_EX)
 return fd
def release_lock(fd): fcntl.flock(fd,fcntl.LOCK_UN); os.close(fd)
def validate_mount(plan):
 target='/apex/com.android.conscrypt/cacerts' if api=='35' else '/system/etc/security/cacerts'
 staging='/data/local/tmp/vpn-control-endpoint-'+correlation
 zygote=plan.get('zygote') if isinstance(plan,dict) else None
 if (not isinstance(plan,dict) or plan.get('target')!=target or plan.get('staging')!=staging or
     not re.fullmatch(r'0:755:[0-9]+:[0-9]+',str(plan.get('stagingIdentity',''))) or
     not isinstance(zygote,dict) or not isinstance(zygote.get('pid'),str) or not zygote['pid'].isdecimal() or
     type(zygote.get('startTicks')) is not int or zygote['startTicks']<1 or
     not isinstance(zygote.get('namespace'),str) or not re.fullmatch(r'mnt:\[[0-9]+\]',zygote['namespace'])): unknown('mount_intent_invalid')
 return plan
def exact_lease_present():
 try: item=lease.lstat()
 except FileNotFoundError: return None
 if not stat.S_ISREG(item.st_mode) or item.st_uid!=os.getuid() or stat.S_IMODE(item.st_mode)!=0o600: unknown('lease_unsafe')
 if json.loads(private(lease,1024))!={'owner':'android-endpoint','correlationId':correlation,'device':device,'host':expected['host']}: unknown('lease_changed')
 after=lease.lstat()
 if (item.st_dev,item.st_ino,item.st_size)!=(after.st_dev,after.st_ino,after.st_size): unknown('lease_replaced')
 return item
def release_exact_lease():
 guard_fd=lease_lock()
 try:
  item=exact_lease_present()
  if item is not None:
   after=lease.lstat()
   if (item.st_dev,item.st_ino,item.st_size)!=(after.st_dev,after.st_ino,after.st_size): unknown('lease_replaced')
   lease.unlink()
 finally: release_lock(guard_fd)
def finish_cleaned():
 guard()
 if routes(): unknown('reverse_after_cleanup')
 record(job/'cleaned.json',{'correlationId':correlation,'caSha256':expected['caSha256']})
 release_exact_lease()
 emit('cleaned',None,device={'uid':'2000','api':int(api),'avd':avd},packageSha256=expected['packageSha256'],owner=expected['owner'],revision=expected['revision'],caSha256=expected['caSha256'],reversePorts=[])
def cleaned_terminal():
 if json.loads(private(job/'cleaned.json',8192))!={'correlationId':correlation,'caSha256':expected['caSha256']}: unknown('cleaned_changed')
 guard()
 if routes(): unknown('reverse_after_cleanup')
 if exact_lease_present() is not None:
  if action!='cleanup': emit('partial','remote_lease_release_pending',phase='terminal')
  release_exact_lease()
 emit('cleaned',None,device={'uid':'2000','api':int(api),'avd':avd},packageSha256=expected['packageSha256'],owner=expected['owner'],revision=expected['revision'],caSha256=expected['caSha256'],reversePorts=[])
def cleanup_before_mount():
 stage=json.loads(private(job/'stage.json',8192))
 target='/apex/com.android.conscrypt/cacerts' if api=='35' else '/system/etc/security/cacerts'
 staging='/data/local/tmp/vpn-control-endpoint-'+correlation
 if stage!={'phase':'before_root','target':target,'staging':staging}: unknown('stage_intent_changed')
 if routes(): unknown('foreign_reverse_before_premount_cleanup')
 uid=shell('id','-u')
 if uid=='0': identity('0')
 elif uid=='2000': guard()
 else: unknown('device_uid_changed')
 owned_path=job/'stage-owned.json'
 if owned_path.exists():
  owned=json.loads(private(owned_path,8192))
  if (owned.get('staging')!=staging or not re.fullmatch(r'0:755:[0-9]+:[0-9]+',str(owned.get('stagingIdentity',''))) or
      not isinstance(owned.get('zygote'),dict)): unknown('stage_ownership_changed')
  if uid=='2000':
   guard()
   if routes(): unknown('foreign_reverse_before_root')
   adb_call('root',timeout=30); adb_call('wait-for-device',timeout=30); identity('0')
  if zygote_identity(owned['zygote'].get('pid'))!=owned['zygote']: unknown('zygote_reused')
  if staging_identity(staging)!=owned['stagingIdentity']: unknown('staging_replaced')
  shell('rm','-r',staging)
  adb_call('unroot',timeout=30); adb_call('wait-for-device',timeout=30)
 else:
  # No staged inode was durably recorded. Never delete an unowned path.
  observed=shell('sh','-c','if [ -e '+staging+' ] || [ -L '+staging+' ]; then echo present; else echo absent; fi')
  if uid=='0': adb_call('unroot',timeout=30); adb_call('wait-for-device',timeout=30)
  if observed!='absent': unknown('unowned_stage_possible')
 finish_cleaned()
def cleanup_effects(plan):
 plan=validate_mount(plan)
 uid=shell('id','-u')
 if uid=='0':
  identity('0')
  if routes(): unknown('foreign_reverse_before_unroot')
  adb_call('unroot',timeout=30); adb_call('wait-for-device',timeout=30)
 elif uid!='2000': unknown('device_uid_changed')
 guard()
 current=routes()
 if any(port not in (18080,18081) or host!={18080:expected['httpsHostPort'],18081:expected['socksHostPort']}[port] for port,host in current.items()): unknown('foreign_reverse_before_cleanup')
 for port in (18081,18080):
  if current.get(port) is not None:
   adb_call('reverse','--remove','tcp:'+str(port))
   if routes().get(port) is not None: unknown('reverse_remove_uncertain')
 if routes(): unknown('foreign_reverse_before_unmount')
 guard()
 if not (job/'cleanup-intent.json').exists(): record(job/'cleanup-intent.json',{'correlationId':correlation,'mount':plan})
 elif json.loads(private(job/'cleanup-intent.json',8192))!={'correlationId':correlation,'mount':plan}: unknown('cleanup_intent_changed')
 if routes(): unknown('foreign_reverse_before_root')
 adb_call('root',timeout=30); adb_call('wait-for-device',timeout=30); identity('0')
 if zygote_identity(plan['zygote']['pid'])!=plan['zygote']: unknown('zygote_reused')
 if staging_identity(plan['staging'])!=plan['stagingIdentity']: unknown('staging_replaced')
 mounted=shell('cat','/proc/'+plan['zygote']['pid']+'/mountinfo')
 entries=[]
 for line in mounted.splitlines():
  fields=line.split(' - ',1)[0].split()
  if len(fields)>=5 and fields[4]==plan['target']: entries.append(fields[3])
 if entries and entries[-1]==plan['staging']:
  if shell('nsenter','-t',plan['zygote']['pid'],'-m','--','sha256sum',plan['target']+'/'+expected['caStoreName']).split()[0]!=expected['caSha256']: unknown('mounted_ca_changed')
  unmount_exact(plan)
 elif plan['staging'] in entries: unknown('foreign_overlay_above_fixture')
 if staging_identity(plan['staging'])!=plan['stagingIdentity']: unknown('staging_replaced')
 shell('rm','-r',plan['staging'])
 adb_call('unroot',timeout=30); adb_call('wait-for-device',timeout=30)
 finish_cleaned()
info=root.lstat()
if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700: unknown('remote_root_unsafe')
if action=='start':
 try: payload=json.load(sys.stdin); ca=base64.b64decode(payload['ca'],validate=True)
 except (ValueError,KeyError,UnicodeError): unknown('ca_payload_invalid')
 if not 0<len(ca)<=65536 or hashlib.sha256(ca).hexdigest()!=expected['caSha256']: unknown('ca_payload_changed')
 # A durable job and intent precede the exclusive lease and every guest command.
 try:
  job.mkdir(mode=0o700)
  record(job/'intent.json',expected)
  fd=os.open(job/'ca.pem',os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
  with os.fdopen(fd,'wb') as output: output.write(ca); output.flush(); os.fsync(output.fileno())
  guard_fd=lease_lock()
  try: record(lease,{'owner':'android-endpoint','correlationId':correlation,'device':device,'host':expected['host']})
  finally: release_lock(guard_fd)
 except (OSError,ValueError): unknown('submission_uncertain')
 leaf=host_fixture_leaf()
 leaf_fd=os.open(job/'leaf.pem',os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
 with os.fdopen(leaf_fd,'wb') as output: output.write(leaf); output.flush(); os.fsync(output.fileno())
 command(['openssl','verify','-CAfile',str(job/'ca.pem'),str(job/'leaf.pem')],max_bytes=2048)
 guard()
 if routes(): unknown('foreign_reverse_present')
 if shell('settings','get','global','http_proxy') not in ('null',':0'): unknown('proxy_not_disconnected')
 target='/apex/com.android.conscrypt/cacerts' if api=='35' else '/system/etc/security/cacerts'
 staging='/data/local/tmp/vpn-control-endpoint-'+correlation
 record(job/'stage.json',{'phase':'before_root','target':target,'staging':staging})
 if routes(): unknown('foreign_reverse_before_root')
 adb_call('root',timeout=30); adb_call('wait-for-device',timeout=30); identity('0')
 zygote=shell('pidof','zygote64').split()
 if len(zygote)!=1 or not zygote[0].isdecimal() or int(zygote[0])<1: unknown('zygote_identity')
 generation=zygote_identity(zygote[0])
 label=shell('ls','-Zd',target).split()[0]
 if not re.fullmatch(r'u:object_r:[a-z0-9_]+:s[0-9]+',label): unknown('ca_store_label')
 if shell('stat','-c','%a',target)!='755': unknown('ca_store_mode')
 shell('mkdir','-m','0755',staging)
 staged_inode=staging_identity(staging)
 record(job/'stage-owned.json',{'staging':staging,'stagingIdentity':staged_inode,'zygote':generation})
 shell('cp','-a',target+'/.',staging+'/')
 children=shell('find',staging,'-mindepth','1','-maxdepth','1','-print').splitlines()
 regular=shell('find',staging,'-mindepth','1','-maxdepth','1','-type','f','-print').splitlines()
 if not children or len(children)!=len(set(children)) or set(children)!=set(regular) or any(not re.fullmatch(re.escape(staging)+r'/[A-Za-z0-9._-]+',x) for x in children): unknown('ca_store_shape')
 staged=staging+'/'+expected['caStoreName']
 if staged in children: unknown('ca_entry_exists')
 adb_call('push',str(job/'ca.pem'),staged,timeout=30,max_bytes=4096)
 shell('chmod','0644',staged)
 for child in [staging,*children,staged]: shell('chcon',label,child)
 if shell('stat','-c','%a',staged)!='644' or shell('ls','-Zd',staged).split()[0]!=label or shell('sha256sum',staged).split()[0]!=expected['caSha256']: unknown('ca_stage_changed')
 mount_plan={'zygote':generation,'target':target,'staging':staging,'stagingIdentity':staged_inode}
 record(job/'mount-intent.json',mount_plan)
 mount_exact(mount_plan)
 if shell('nsenter','-t',zygote[0],'-m','--','sha256sum',target+'/'+expected['caStoreName']).split()[0]!=expected['caSha256']: unknown('ca_mount_unknown')
 adb_call('unroot',timeout=30); adb_call('wait-for-device',timeout=30)
 guard()
 if routes(): unknown('reverse_changed_after_unroot')
 record(job/'https-reverse-intent.json',{'devicePort':18080,'hostPort':expected['httpsHostPort']})
 adb_call('reverse','tcp:18080','tcp:'+str(expected['httpsHostPort']))
 if routes().get(18080)!=expected['httpsHostPort']: unknown('https_reverse_unknown')
 record(job/'socks-reverse-intent.json',{'devicePort':18081,'hostPort':expected['socksHostPort']})
 adb_call('reverse','tcp:18081','tcp:'+str(expected['socksHostPort']))
 fixture_routes(); guard()
 mount_observed(mount_plan)
 record(job/'ready.json',{'correlationId':correlation,'caSha256':expected['caSha256'],'leafSha256':expected['leafSha256'],'mount':mount_plan,'httpsHostPort':expected['httpsHostPort'],'socksHostPort':expected['socksHostPort']})
 emit('ready',None,device={'uid':'2000','api':int(api),'avd':avd},packageSha256=expected['packageSha256'],owner=expected['owner'],revision=expected['revision'],caSha256=expected['caSha256'],reversePorts=[18080,18081])
try:
 item=job.lstat()
 if not stat.S_ISDIR(item.st_mode) or item.st_uid!=os.getuid() or stat.S_IMODE(item.st_mode)!=0o700: unknown('job_unsafe')
 if json.loads(private(job/'intent.json',8192))!=expected: unknown('intent_changed')
 if (job/'cleaned.json').exists():
  cleaned_terminal()
 if json.loads(private(lease,1024))!={'owner':'android-endpoint','correlationId':correlation,'device':device,'host':expected['host']}: unknown('lease_changed')
 if not (job/'ready.json').exists():
  phase='mount-intent' if (job/'mount-intent.json').exists() else 'before-root' if (job/'stage.json').exists() else 'journaled'
  if action=='cleanup' and (job/'mount-intent.json').exists():
   cleanup_effects(json.loads(private(job/'mount-intent.json',8192)))
  if action=='cleanup' and (job/'stage.json').exists(): cleanup_before_mount()
  emit('partial','setup_incomplete',phase=phase)
 ready=json.loads(private(job/'ready.json',8192))
 mount=ready.get('mount')
 if (ready.get('correlationId')!=correlation or ready.get('caSha256')!=expected['caSha256'] or ready.get('leafSha256')!=expected['leafSha256'] or ready.get('httpsHostPort')!=expected['httpsHostPort'] or ready.get('socksHostPort')!=expected['socksHostPort'] or not isinstance(mount,dict) or mount.get('target')!=('/apex/com.android.conscrypt/cacerts' if api=='35' else '/system/etc/security/cacerts') or mount.get('staging')!='/data/local/tmp/vpn-control-endpoint-'+correlation or mount!=json.loads(private(job/'mount-intent.json',8192))): unknown('ready_changed')
 guard(); fixture_routes()
 if action=='status': host_fixture_leaf(); mount_observed(mount)
 if action=='status': emit('ready',None,device={'uid':'2000','api':int(api),'avd':avd},packageSha256=expected['packageSha256'],owner=expected['owner'],revision=expected['revision'],caSha256=expected['caSha256'],reversePorts=[18080,18081])
 if action!='cleanup': unknown('action_invalid')
 cleanup_effects(mount)
except (OSError,ValueError,KeyError,TypeError,IndexError): unknown('state_or_cleanup_uncertain')
'''


def _remote(root: Path, intent: dict[str, Any], action: str, payload: bytes | None = None) -> dict[str, Any]:
    host = intent["host"]
    config = ssh_transport.load_config(root)
    if host not in config.hosts or ssh_transport.connection_host(config, host).password is not None:
        raise ValueError("Android endpoint requires configured private-key host")
    remote_root = config.hosts[host].fixture_transfer_root
    if remote_root is None or str(remote_root) != intent["remoteRoot"]:
        raise ValueError("Android endpoint remote root changed")
    argv = ssh_transport.build_ssh_argv(config, host, 60,
        command=ssh_transfer._python_command(android_observation._canonical_cli_environment_source() + _REMOTE,
                                             action, str(remote_root), intent["device"],
                                             intent["correlationId"],
                                             json.dumps(intent["remote"], sort_keys=True, separators=(",", ":"))))
    try:
        code, output = ssh_transfer._bounded_run(argv, payload, 60)
        value = json.loads(output.decode("utf-8", "strict")) if code == 0 else None
        if isinstance(value, dict) and value.get("correlationId") == intent["correlationId"] and value.get("state") in {"ready", "cleaned", "partial", "unknown"}:
            return value
    except (OSError, ValueError, UnicodeError, ssh_transfer.SshTransferError):
        pass
    return {"state": "unknown", "reason": "transport_or_receipt_unknown", "correlationId": intent["correlationId"]}


def _bound_result(intent: dict[str, Any], value: dict[str, Any], action: str) -> dict[str, Any]:
    """Never turn a merely named terminal response into device admission."""
    state = value.get("state")
    if state in {"unknown", "partial"}:
        return _response(state, intent["correlationId"], value.get("reason") or "native_outcome_unknown",
                         phase=value.get("phase") if state == "partial" else None)
    remote = intent["remote"]
    expected_state = state if action == "status" and state in {"ready", "cleaned"} else "cleaned" if action == "cleanup" else "ready"
    ports = [] if expected_state == "cleaned" else [18080, 18081]
    if (state != expected_state or value.get("correlationId") != intent["correlationId"] or
            value.get("device") != {"uid": "2000", "api": remote["api"], "avd": remote["avd"]} or
            value.get("packageSha256") != remote["packageSha256"] or
            value.get("owner") != remote["owner"] or value.get("revision") != remote["revision"] or
            value.get("caSha256") != remote["caSha256"] or value.get("reversePorts") != ports):
        return _response("unknown", intent["correlationId"], "terminal_binding_invalid")
    return _response(state, intent["correlationId"], result=value)


def start(root: Path | str, host: str, device: str, correlation_id: str, campaign_id: str,
          source_sha: str, target_artifact_id: str, ca_artifact_id: str,
          backup_correlation_id: str, expected_owner: str, expected_revision: int,
          expected_backup_sha256: str) -> dict[str, Any]:
    """Submit one native setup after exact source, campaign, package and OFF admission."""
    root = Path(root).resolve()
    if (not all(isinstance(x, str) and _UUID.fullmatch(x) for x in (correlation_id, campaign_id, backup_correlation_id)) or
            not all(isinstance(x, str) and _ALIAS.fullmatch(x) for x in (host, device)) or
            not isinstance(source_sha, str) or not re.fullmatch(r"[0-9a-f]{40}", source_sha) or
            not isinstance(expected_owner, str) or not expected_owner or
            type(expected_revision) is not int or expected_revision < 0 or
            not isinstance(expected_backup_sha256, str) or not _SHA.fullmatch(expected_backup_sha256)):
        raise ValueError("Android endpoint identity is invalid")
    config = ssh_transport.load_config(root)
    if host not in config.hosts or device not in config.hosts[host].android_devices or config.hosts[host].fixture_transfer_root is None:
        raise ValueError("Android endpoint host/device is not configured")
    if ssh_transport.connection_host(config, host).password is not None:
        raise ValueError("Android endpoint requires private-key SSH")
    profile = android_observation._profile(config.hosts[host].android_devices[device])
    requirements = android_native_fixture.prepare_requirements(root, source_sha)
    target = android_native_fixture.verify_target(root, requirements, target_artifact_id)
    package_hash = target["targetSha256"]
    campaign = android_native_fixture_lifecycle.status(root, campaign_id)
    campaign_intent = android_native_fixture_lifecycle._read_plan(
        android_native_fixture_lifecycle._directory(root) / (campaign_id + ".json"))
    if (campaign.get("state") != "running" or campaign_intent.get("host") != host or
            campaign_intent.get("device") != device or campaign_intent.get("sourceSha") != source_sha or
            campaign.get("endpoint", {}).get("hostHttpsPort") is None or
            campaign.get("endpoint", {}).get("hostSocksPort") is None):
        raise ValueError("Android endpoint host fixture is not admitted")
    opening = android_admission_readback.async_collect(root, backup_correlation_id)
    result = opening.get("result", {})
    guard, backup = result.get("guard", {}), result.get("backup", {})
    if (opening.get("state") != "complete" or opening.get("ok") is not True or
            result.get("package", {}).get("baseSha256") != package_hash or
            result.get("device") != {"uid": "2000", "api": profile["api"], "avd": profile["expectedAvd"]} or
            guard.get("controllerId") != expected_owner or guard.get("configurationRevision") != expected_revision or
            backup.get("sha256") != expected_backup_sha256):
        raise ValueError("Android endpoint opening readback is not admitted")
    live = android_admission_readback.readback_status(root, host, device, backup_correlation_id)
    observed = live.get("result", {})
    if (live.get("ok") is not True or observed.get("deviceIdentity") is not True or
            observed.get("stage") != "backup_present" or observed.get("controllerId") != expected_owner or
            observed.get("configurationRevision") != expected_revision or
            observed.get("backup", {}).get("sha256") != expected_backup_sha256):
        raise ValueError("Android endpoint live owner or backup changed")
    ca = _stable_ca(root, ca_artifact_id, source_sha)
    if not ca.startswith(b"-----BEGIN CERTIFICATE-----") or b"-----END CERTIFICATE-----" not in ca:
        raise ValueError("Android endpoint CA artifact is not PEM")
    endpoint = campaign["endpoint"]
    ports = (endpoint["hostHttpsPort"], endpoint["hostSocksPort"])
    if any(type(port) is not int or not 1 <= port <= 65535 for port in ports):
        raise ValueError("Android endpoint host ports are invalid")
    import tempfile
    with tempfile.TemporaryDirectory() as temporary:
        cert_path = Path(temporary) / "ca.pem"
        cert_path.write_bytes(ca)
        subject = subprocess.run(["openssl", "x509", "-in", str(cert_path), "-noout", "-subject_hash_old"],
                                 check=True, capture_output=True, text=True, timeout=10).stdout.strip()
    if not re.fullmatch(r"[0-9a-fA-F]{8}", subject):
        raise ValueError("Android endpoint CA subject hash is invalid")
    remote = {"host": host, "adb": profile["adb"], "cli": profile["cli"], "serial": profile["serial"],
              "avd": profile["expectedAvd"], "api": profile["api"], "packageSha256": package_hash,
              "owner": expected_owner, "revision": expected_revision, "backupPath": backup["path"],
              "backupSha256": expected_backup_sha256, "campaignId": campaign_id,
              "leafSha256": campaign_intent["certificateSha256"], "caSha256": hashlib.sha256(ca).hexdigest(),
              "caStoreName": subject.lower() + ".0", "httpsHostPort": ports[0], "socksHostPort": ports[1]}
    intent = {"host": host, "device": device, "correlationId": correlation_id,
              "sourceSha": source_sha, "targetArtifactId": target_artifact_id,
              "caArtifactId": ca_artifact_id, "backupCorrelationId": backup_correlation_id,
              "remoteRoot": str(config.hosts[host].fixture_transfer_root), "remote": remote}
    path = _intent_path(root, correlation_id)
    android_native_fixture.write_private_plan(path, intent)
    with _shared_device_lease(root, host, device) as lease:
        android_native_fixture.write_private_plan(lease, {"owner": "android-endpoint", "correlationId": correlation_id,
                                                  "host": host, "device": device})
    payload = json.dumps({"ca": base64.b64encode(ca).decode("ascii")}, separators=(",", ":")).encode()
    value = _remote(root, intent, "start", payload)
    return _bound_result(intent, value, "start")


def status(root: Path | str, correlation_id: str) -> dict[str, Any]:
    """Read only the exact durable job; unknown results never authorize replay."""
    root = Path(root).resolve()
    intent = _read_intent(root, correlation_id)
    value = _remote(root, intent, "status")
    bounded = _bound_result(intent, value, "status")
    if bounded["state"] != "ready":
        return bounded
    campaign = android_native_fixture_lifecycle.status(root, intent["remote"]["campaignId"])
    endpoint = campaign.get("endpoint") if isinstance(campaign, dict) else None
    if (campaign.get("state") != "running" or not isinstance(endpoint, dict) or
            endpoint.get("hostHttpsPort") != intent["remote"]["httpsHostPort"] or
            endpoint.get("hostSocksPort") != intent["remote"]["socksHostPort"]):
        return _response("unknown", correlation_id, "host_fixture_changed")
    return bounded


def cleanup(root: Path | str, correlation_id: str) -> dict[str, Any]:
    """Remove only this campaign's two reverses and verified temporary CA mount."""
    root = Path(root).resolve()
    intent = _read_intent(root, correlation_id)
    value = _remote(root, intent, "cleanup")
    bounded = _bound_result(intent, value, "cleanup")
    if bounded["state"] == "cleaned":
        with _shared_device_lease(root, intent["host"], intent["device"]) as lease:
            before = lease.lstat()
            if android_native_fixture_lifecycle._read_plan(lease) != {"owner": "android-endpoint", "correlationId": correlation_id,
                                                                   "host": intent["host"], "device": intent["device"]}:
                return _response("unknown", correlation_id, "local_lease_changed")
            after = lease.lstat()
            if (not stat.S_ISREG(before.st_mode) or
                    (before.st_dev, before.st_ino, before.st_size) != (after.st_dev, after.st_ino, after.st_size)):
                return _response("unknown", correlation_id, "local_lease_replaced")
            lease.unlink()
    return bounded
