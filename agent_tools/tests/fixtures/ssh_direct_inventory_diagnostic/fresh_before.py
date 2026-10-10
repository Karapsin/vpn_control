"""Independent configured nested channel; canonical recovery state stays intact.

No arbitrary command API. Prepare is create-only; UNKNOWN is observation-only.
A reconnect never resubmits an existing remote job. Route options are internal
provider data, not a public MCP response.
"""
from __future__ import annotations
from contextlib import ExitStack
from dataclasses import asdict
import hashlib
import ast
import inspect
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import types
import uuid
from typing import Any
from . import ssh_transport as transport, ssh_connection_session as session
from . import ssh_connection_recovery as recovery
from . import private_inventory_lock as private
from . import ssh_channel_inventory_diagnostics as inventory_diagnostics
from . import ssh_nested_socket_owned_home_observation as owned_home

def validated_unknown(result):
    required={'state','nativeActionAllowed','replayAllowed','correlationId'}
    optional={'failurePhase','failureReason','exceptionClass','errno'}
    if not isinstance(result,dict) or not required<=set(result) or not set(result)<=required|optional or result['state']!='unknown' or result['nativeActionAllowed'] is not False or result['replayAllowed'] is not False or not isinstance(result['correlationId'],str) or re.fullmatch('[0-9a-f]{32}',result['correlationId']) is None:raise ValueError('unknown_dto')
    if 'failurePhase' in result and (not isinstance(result['failurePhase'],str) or result['failurePhase'] not in _PUBLIC_PHASES):raise ValueError('unknown_dto')
    fields=set(result)&{'failureReason','exceptionClass','errno'}
    if fields and (fields!={'failureReason','exceptionClass','errno'} or 'failurePhase' not in result or not isinstance(result['failureReason'],str) or result['failureReason'] not in _REMOTE_REASONS or not isinstance(result['exceptionClass'],str) or result['exceptionClass'] not in _EXCEPTION_CLASSES or (result['errno'] is not None and (type(result['errno'])is not int or not 0<=result['errno']<=255))):raise ValueError('unknown_dto')
    return dict(result)

class ChannelUnknown(ValueError):
    """Carry only a closed finite refusal; no exception text or authority."""
    def __init__(self,result):
        super().__init__('channel_unknown');self._result=types.MappingProxyType(validated_unknown(result))
    @property
    def result(self):return validated_unknown(dict(self._result))

HOST='archlinux'
EXPECTED_UID=1000
EXPECTED_BOOT='25515f23-b966-4c3a-ae63-d38452375578'
IDLE_SECONDS=60
_REVIEWED_ENDED_PREDECESSOR='9cc06c7e5e8d5f61815d8f28a955ff63e2452ef10534cbc013c3111db8d3384e'
_REVIEWED_ENDED_PREDECESSOR_9A='9a7abc8ab6a5c4595d3f0dc0bb8bda33d5a6b1928bf373651a57cfe4e904bfe7'
_REVIEWED_ENDED_PREDECESSOR_9527='9527a0163d0b532055a12e34c00dbf68c6435b03843b3caa5d334c90f15be33f'
_REVIEWED_ENDED_REMOTE_9527='f148a727ad94bfdd0d3fc083cd6379c2f6e65e617b50825d06787c04800b54a1'
_REVIEWED_ENDED_REMOTE_9A='13799269eccc0d6a9e0bd86ea5816129d7c5c7fce5553d65349d55072e8f4791'
# These exact source/program/handle tuples were independently reviewed and
# positively ended before the EOF-reader successor. They authorize only a new
# current handle after guarded terminal closure, never old READY adoption.
_REVIEWED_ENDED_PREDECESSOR_012='012061ebf05def240bf79005ca58f1913fb29736a4201cae56154dcc034183fd'
_REVIEWED_ENDED_REMOTE_012='e09d999c433654349c4e48d29947522e54f91ab69cc449050b59d9eba9684898'
_REVIEWED_ENDED_DIAGNOSTICS_012=types.MappingProxyType({
    'a10a21cfd20e4ddf9c32a1c74e393fa6':'f6efd83b9c2580876f7f8e38b7553346ce840c64ce9086ae8c50a23e3d6dea42',
    'e48177f1ee694cb69abacd96ffe8f1b8':'37b6c10baf4b5608e62278768380d12ac415e76759c2a28871bc7730f3b44991',
})
# The immediately preceding reviewed provider emitted the exact same rendered
# remote programme. Only positively ENDED protected receipts may transition;
# this pair never adopts old READY or authorizes an unrelated remote body.
_REVIEWED_ENDED_PREDECESSOR_0BE3='0be3a94c8e0e5763a70b396e22d068555e6a93697f614f12c03f09bf6610e1d6'
_REVIEWED_ENDED_REMOTE_0BE3='a0d5a30bbb83bea3ba4dd7fb3c5b1664e5be2dd90e1ade1e82c3fb6123d032fd'
_REMOTE_REASONS=frozenset(('actor', 'actor_uid', 'arch_identity', 'changed', 'closing', 'closing_master', 'config_dependencies', 'config_or_keys_changed', 'directory', 'directory_membership', 'duplicate', 'effective_home_changed', 'effective_home_foreign', 'effective_home_unknown', 'effective_key_not_literal', 'effective_key_unavailable', 'effective_key_unknown', 'effective_route_unknown', 'fd_cap', 'fd_changed', 'gateway_reboot', 'kernel_duplicate_inode', 'kernel_fields', 'kernel_header', 'kernel_row', 'launch_unknown', 'listener_owner', 'listener_present', 'master_check', 'process_cap', 'process_changed', 'process_disappeared_partial', 'publication_master_changed', 'publication_ready_changed', 'ready_changed', 'ready_private', 'ready_publication', 'remote_intent', 'remote_intent_changed', 'route_file_changed', 'route_file_unbounded', 'route_file_unsafe', 'route_parent_changed', 'route_parent_unsafe', 'route_unknown', 'saved_binding', 'secret', 'socket', 'stage_appeared', 'stage_parent', 'status_input', 'unclassified', 'unseen_unknown'))
_EXCEPTION_CLASSES=frozenset(('ValueError','FileNotFoundError','PermissionError','OSError','KeyError','TimeoutExpired','SubprocessError','other'))
_REMOTE_PHASES=frozenset(('prepare_stage','launch','remote_intent','master_snapshot','arch_identity','master_closing','publication'))
_PUBLIC_PHASES=_REMOTE_PHASES|frozenset(('input','inventory','route','channel_journal','outer_receipt','outer_reuse','intent','transport','capture_retention','closing','parser'))
_REMOTE=r'''import base64,hashlib,json,os,re,stat,subprocess,sys,tempfile,time
def reject_pairs(pairs):
 value={}
 for key,item in pairs:
  if key in value:raise ValueError('duplicate')
  value[key]=item
 return value
request=json.loads(sys.stdin.buffer.read(4097),object_pairs_hook=reject_pairs)
corr,action,config,profile,source_sha=sys.argv[1:]
if not re.fullmatch('[0-9a-f]{32}',corr) or action not in ('prepare','status') or not re.fullmatch('[0-9a-f]{64}',source_sha):raise SystemExit(2)
stage='/tmp/vpn-channel-'+corr
control=stage+'/m'
def gen(s):return [s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def pin(path):
 before=os.lstat(path)
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  if path=='/proc/net/unix':
   chunks=[];total=0;read_count=0;deadline=time.monotonic()+2
   while True:
    if time.monotonic()>deadline or read_count>=256:raise ValueError('changed')
    chunk=os.read(fd,65537-total);read_count+=1
    if not chunk:break
    total+=len(chunk)
    if total>65536:raise ValueError('changed')
    chunks.append(chunk)
   body=b''.join(chunks)
  else:body=os.read(fd,65537)
  # Only this fixed procfs seq-file has volatile lookup timestamps. Its
  # descriptor/name inode, type, ownership, links and size remain strict.
  fields=7 if path=='/proc/net/unix' else 9
  if len(body)>65536 or gen(before)[:fields]!=gen(os.fstat(fd))[:fields] or gen(before)[:fields]!=gen(os.lstat(path))[:fields]:raise ValueError('changed')
 finally:os.close(fd)
 return body,gen(before)
def launch_capture(value):
 if value is None:return None
 result={key:value.get(key) for key in ('pid','returnCode','complete','counts','eof','timeout','overflow','readError')}
 result['streams']={}
 for name in ('stdout','stderr'):
  raw=value[name];prefix=raw[:512]
  result['streams'][name]={'prefixBase64':base64.b64encode(prefix).decode(),'prefixBytes':len(prefix),'prefixSha256':hashlib.sha256(prefix).hexdigest(),'prefixComplete':len(prefix)==value['counts'][name],'retainedBytes':len(raw),'retainedSha256':hashlib.sha256(raw).hexdigest(),'retainedComplete':len(raw)==value['counts'][name]}
 return result
def save(name,value):
 fd=os.open(stage+'/'+name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'w') as f:json.dump(value,f,sort_keys=True);f.flush();os.fsync(f.fileno())
 fd=os.open(stage,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)
def directory():
 s=os.lstat(stage)
 if not stat.S_ISDIR(s.st_mode) or s.st_uid!=os.getuid() or stat.S_IMODE(s.st_mode)!=0o700:raise ValueError('directory')
 names=os.listdir(stage)
 if len(names)>3 or any(name not in ('m','intent.json','ready.json') for name in names):raise ValueError('directory_membership')
 return [s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid]
def actor(pid):
 body,_=pin('/proc/%d/stat'%pid);tail=body[body.rindex(b')')+2:].split()
 if len(tail)<20 or tail[0] in (b'Z',b'X'):raise ValueError('actor')
 info=os.stat('/proc/%d'%pid)
 if info.st_uid!=os.getuid():raise ValueError('actor_uid')
 return {'pid':pid,'startTicks':int(tail[19]),'uid':info.st_uid}
def table_rows(table):
 if not table.startswith(b'Num       RefCount Protocol Flags    Type St Inode Path\n') or not table.endswith(b'\n'):raise ValueError('kernel_header')
 rows=[];seen=set()
 for line in table.splitlines()[1:]:
  fields=line.split(maxsplit=7)
  if len(fields) not in (7,8) or not re.fullmatch(rb'[0-9a-fA-F]+:',fields[0]):raise ValueError('kernel_row')
  if any(re.fullmatch(rb'[0-9a-fA-F]+',item) is None for item in fields[1:6]) or re.fullmatch(rb'[0-9]+',fields[6]) is None:raise ValueError('kernel_fields')
  if fields[6] in seen:raise ValueError('kernel_duplicate_inode')
  seen.add(fields[6]);rows.append(fields)
 return rows
def control_row(row):
 # OpenSSH muxserver_listen binds m.<16 alphanumerics>, then links m and
 # unlinks its temporary pathname. Linux retains the original bind name.
 return len(row)==8 and (row[7]==os.fsencode(control) or re.fullmatch(re.escape(os.fsencode(control))+rb'\.[A-Za-z0-9]{16}',row[7]) is not None)
def pending_absent():
 if os.path.lexists(control):return False
 present=os.path.lexists(stage)
 parent=stage.rsplit('/',1)[0]
 def boundary():
  if present:return directory()
  if os.path.lexists(stage):raise ValueError('stage_appeared')
  info=os.lstat(parent)
  if not stat.S_ISDIR(info.st_mode):raise ValueError('stage_parent')
  return [info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid]
 initial=boundary()
 for _ in range(2):
  table,_=pin('/proc/net/unix')
  if any(control_row(row) for row in table_rows(table)):return False
  names=os.listdir('/proc')
  if len(names)>4096:raise ValueError('process_cap')
  for name in names:
   if not name.isdecimal() or int(name)==os.getpid():continue
   path='/proc/'+name
   try:
    info=os.stat(path)
    if info.st_uid!=os.getuid():continue
    command,_=pin(path+'/cmdline')
    if corr.encode() in command.split(b'\0') or control.encode() in command:return False
    closing=os.stat(path)
    if (info.st_dev,info.st_ino,info.st_uid)!=(closing.st_dev,closing.st_ino,closing.st_uid):raise ValueError('process_changed')
   except FileNotFoundError:
    if os.path.lexists(path):raise ValueError('process_disappeared_partial')
  if boundary()!=initial or os.path.lexists(control):return False
 return True
def snapshot():
 remote_guard();parent=directory();sock=os.lstat(control)
 if not stat.S_ISSOCK(sock.st_mode) or sock.st_uid!=os.getuid() or sock.st_nlink!=1 or sock.st_mode&0o077:raise ValueError('socket')
 result=subprocess.run(ssh+['-S',control,'-O','check',profile],capture_output=True,timeout=5)
 match=re.fullmatch(rb'Master running \(pid=([1-9][0-9]*)\)\r?\n',result.stderr)
 if result.returncode!=0 or result.stdout or not match:raise ValueError('master_check')
 identity=actor(int(match[1]));inodes=set()
 names=os.listdir('/proc/%d/fd'%identity['pid'])
 if len(names)>256:raise ValueError('fd_cap')
 for name in names:
  try:link=os.readlink('/proc/%d/fd/%s'%(identity['pid'],name))
  except FileNotFoundError:raise ValueError('fd_changed')
  match=re.fullmatch(r'socket:\[([0-9]+)\]',link)
  if match:inodes.add(match[1].encode())
 table,_=pin('/proc/net/unix');rows=[]
 for fields in table_rows(table):
  if control_row(fields) and fields[3]==b'00010000' and fields[4]==b'0001' and fields[5]==b'01':rows.append(fields)
 if len(rows)!=1 or rows[0][6] not in inodes:raise ValueError('listener_owner')
 if directory()!=parent or gen(os.lstat(control))!=gen(sock) or actor(identity['pid'])!=identity:raise ValueError('closing')
 remote_guard()
 return {'actor':identity,'socket':gen(sock),'directory':parent,'listenerInode':rows[0][6].decode(),'gatewayBoot':boot}
ssh=['ssh']+(['-F',config] if config else [])+['-o','PermitLocalCommand=no','-o','ClearAllForwardings=yes','-o','UpdateHostKeys=no']
config_file=config if config else str(Path.home()/'.ssh/config')
spec={'configFile':config_file,'controlPath':control,'remoteHostAlias':profile}
config_pin=file_pin(config_file,body=True)
if config_pin['unsupportedConfigDirectives']:raise ValueError('config_dependencies')
route_pin=effective_route(spec)
def remote_guard():
 if file_pin(config_file,body=True)!=config_pin or effective_route(spec)!=route_pin:raise ValueError('config_or_keys_changed')
remote_guard()
boot=pin('/proc/sys/kernel/random/boot_id')[0].decode().strip()
intent_value={'correlationId':corr,'gatewayBoot':boot,'gatewayUid':os.getuid(),'sourceSha256':source_sha,'configPin':config_pin,'effectiveRoute':route_pin}
_REFUSALS=('actor', 'actor_uid', 'arch_identity', 'changed', 'closing', 'closing_master', 'config_dependencies', 'config_or_keys_changed', 'directory', 'directory_membership', 'duplicate', 'effective_home_changed', 'effective_home_foreign', 'effective_home_unknown', 'effective_key_not_literal', 'effective_key_unavailable', 'effective_key_unknown', 'effective_route_unknown', 'fd_cap', 'fd_changed', 'gateway_reboot', 'kernel_duplicate_inode', 'kernel_fields', 'kernel_header', 'kernel_row', 'launch_unknown', 'listener_owner', 'listener_present', 'master_check', 'process_cap', 'process_changed', 'process_disappeared_partial', 'publication_master_changed', 'publication_ready_changed', 'ready_changed', 'ready_private', 'ready_publication', 'remote_intent', 'remote_intent_changed', 'route_file_changed', 'route_file_unbounded', 'route_file_unsafe', 'route_parent_changed', 'route_parent_unsafe', 'route_unknown', 'saved_binding', 'secret', 'socket', 'stage_appeared', 'stage_parent', 'status_input', 'unclassified', 'unseen_unknown')
phase='prepare_stage';launch=None
try:
 if action=='prepare':
  if set(request)!={'passphrase'} or not isinstance(request['passphrase'],str) or not 0<len(request['passphrase'])<=512:raise ValueError('secret')
  os.mkdir(stage,0o700);directory();save('intent.json',intent_value)
  with tempfile.TemporaryDirectory(prefix='askpass-',dir=stage) as secret_dir:
   password=secret_dir+'/password';helper=secret_dir+'/askpass'
   fd=os.open(password,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
   with os.fdopen(fd,'w') as f:f.write(request['passphrase'])
   fd=os.open(helper,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o700)
   with os.fdopen(fd,'w') as f:f.write('#!/bin/sh\ncat "$VPN_CONTROL_SSH_PASSWORD_FILE"\n')
   env=os.environ.copy();env.update(SSH_ASKPASS=helper,SSH_ASKPASS_REQUIRE='force',DISPLAY='vpn-channel',VPN_CONTROL_SSH_PASSWORD_FILE=password)
   phase='launch'
   launch=subprocess.run(ssh+['-M','-N','-f','-S',control,'-o','ControlMaster=yes','-o','ControlPersist=60','-o','StrictHostKeyChecking=yes','-o','IdentitiesOnly=yes','-o','BatchMode=no','-o','NumberOfPasswordPrompts=1','-o','ConnectTimeout=10',profile],stdin=subprocess.DEVNULL,capture_output=True,timeout=20,env=env)
   if launch.returncode!=0:raise ValueError('launch_unknown')
 elif request!={}:raise ValueError('status_input')
 phase='remote_intent'
 if action=='status':
  if not os.path.lexists(stage):
   if not pending_absent():raise ValueError('unseen_unknown')
   remote_guard();print(json.dumps({'state':'ended','correlationId':corr,'prior':None,'gatewayBoot':boot},sort_keys=True));raise SystemExit(0)
  directory();intent_info=os.lstat(stage+'/intent.json')
  if not stat.S_ISREG(intent_info.st_mode) or stat.S_IMODE(intent_info.st_mode)!=0o600 or intent_info.st_uid!=os.getuid() or intent_info.st_nlink!=1:raise ValueError('remote_intent')
  if json.loads(pin(stage+'/intent.json')[0],object_pairs_hook=reject_pairs)!=intent_value:raise ValueError('remote_intent_changed')
  saved=json.loads(pin(stage+'/ready.json')[0],object_pairs_hook=reject_pairs) if os.path.lexists(stage+'/ready.json') else None
  if saved is not None and (saved.get('state')!='ready' or saved.get('correlationId')!=corr or saved.get('controlPath')!=control):raise ValueError('saved_binding')
  if saved is None and pending_absent():
   remote_guard();print(json.dumps({'state':'ended','correlationId':corr,'prior':None,'gatewayBoot':boot},sort_keys=True));raise SystemExit(0)
  if saved is not None and not os.path.lexists(control) and not os.path.lexists('/proc/%d'%saved['master']['actor']['pid']):
   table,_=pin('/proc/net/unix')
   if any(control_row(f) for f in table_rows(table)):raise ValueError('listener_present')
   if saved['master']['gatewayBoot']!=boot:raise ValueError('gateway_reboot')
   directory()
   print(json.dumps({'state':'ended','correlationId':corr,'prior':saved,'gatewayBoot':boot},sort_keys=True));raise SystemExit(0)
 phase='master_snapshot'
 first=snapshot()
 phase='arch_identity'
 probe=subprocess.run(ssh+['-T','-S',control,'-o','ControlMaster=no','-o','ControlPersist=no','-o','ProxyCommand=false','-o','BatchMode=yes',profile,"python3 -I -B -c 'import json,os;from pathlib import Path;print(json.dumps({\"uid\":os.getuid(),\"boot\":Path(\"/proc/sys/kernel/random/boot_id\").read_text().strip()},sort_keys=True))'"],capture_output=True,timeout=10)
 if probe.returncode!=0 or probe.stderr or len(probe.stdout)>4096:raise ValueError('route_unknown')
 arch=json.loads(probe.stdout)
 if set(arch)!={'uid','boot'} or type(arch['uid'])is not int or arch['uid']!=1000 or arch['boot']!='25515f23-b966-4c3a-ae63-d38452375578':raise ValueError('arch_identity')
 phase='master_closing'
 if snapshot()!=first:raise ValueError('closing_master')
 result={'state':'ready','correlationId':corr,'master':first,'arch':arch,'controlPath':control}
 phase='publication'
 if action=='prepare' or not os.path.lexists(stage+'/ready.json'):save('ready.json',result)
 else:
  previous=json.loads(pin(stage+'/ready.json')[0])
  if previous!=result:raise ValueError('ready_changed')
 # Custody must close after readiness publication, not before it.
 saved_info=os.lstat(stage+'/ready.json')
 if not stat.S_ISREG(saved_info.st_mode) or stat.S_IMODE(saved_info.st_mode)!=0o600 or saved_info.st_uid!=os.getuid() or saved_info.st_nlink!=1:raise ValueError('ready_private')
 saved_bytes,saved_generation=pin(stage+'/ready.json')
 if json.loads(saved_bytes,object_pairs_hook=reject_pairs)!=result:raise ValueError('ready_publication')
 if snapshot()!=first:raise ValueError('publication_master_changed')
 if gen(os.lstat(stage+'/ready.json'))!=saved_generation:raise ValueError('publication_ready_changed')
 remote_guard()
 print(json.dumps(result,sort_keys=True))
except (OSError,ValueError,KeyError,subprocess.SubprocessError) as failure:
 label=str(failure) if isinstance(failure,ValueError) else 'unclassified'
 if label not in _REFUSALS:label='unclassified'
 kind=type(failure).__name__
 if kind not in ('ValueError','FileNotFoundError','PermissionError','OSError','KeyError','TimeoutExpired','SubprocessError'):kind='other'
 number=failure.errno if isinstance(failure,OSError) and type(failure.errno)is int and 0<=failure.errno<=255 else None
 print(json.dumps({'state':'unknown','correlationId':corr,'failurePhase':phase,'failureReason':label,'exceptionClass':kind,'errno':number,'launchCapture':launch_capture(launch)},sort_keys=True));raise SystemExit(3)
'''


# Reuse the independently reviewed binary collector on the gateway too. Both
# pipes and child termination are bounded before parsing any SSH output.
_inner_source=inspect.getsource(recovery._bounded_socket_query)
_inner_source=_inner_source.replace('def _bounded_socket_query(argv, timeout_seconds):','def inner(argv, timeout_seconds, environment=None):').replace('stderr=subprocess.PIPE,text=False)','stderr=subprocess.PIPE,text=False,env=environment)')
_trusted_guard_source=owned_home.remote_source()
if hashlib.sha256(_trusted_guard_source.encode()).hexdigest()!='fe13637a9a0386a4490dc96113670c378c10dc577bf5c0d62fe4299c394934fd':raise ValueError('guard_source_changed')
_guard_lines=_trusted_guard_source.splitlines(keepends=True)
_guard_names={'generation','parent_guard','file_pin','ssh_options','effective_route','owned_home_identity'}
_guard_nodes=[n for n in ast.parse(_trusted_guard_source).body if isinstance(n,ast.FunctionDef) and n.name in _guard_names]
if {n.name for n in _guard_nodes}!=_guard_names:raise ValueError('guard_factory_changed')
_guard_program=''.join(''.join(_guard_lines[n.lineno-1:n.end_lineno])+'\n' for n in _guard_nodes)
_REMOTE='import selectors,time,pwd\nfrom pathlib import Path\n_SOCKET_CAPTURE_BYTES=4096\n'+_guard_program+_inner_source+'\n'+_REMOTE
_REMOTE=_REMOTE.replace("result=subprocess.run(ssh+['-S',control,'-O','check',profile],capture_output=True,timeout=5)","result=inner(ssh+['-S',control,'-O','check',profile],5)")
_REMOTE=_REMOTE.replace("result.stderr)","result['stderr'])").replace("result.returncode!=0 or result.stdout or not match","not result['complete'] or result['returnCode']!=0 or result['stdout'] or not match")
_REMOTE=_REMOTE.replace("launch=subprocess.run(ssh+", "launch=inner(ssh+")
_REMOTE=_REMOTE.replace("stdin=subprocess.DEVNULL,capture_output=True,timeout=20,env=env)","20,env)")
_REMOTE=_REMOTE.replace("if launch.returncode!=0:","if not launch['complete'] or launch['returnCode']!=0:")
_REMOTE=_REMOTE.replace("probe=subprocess.run(ssh+","probe=inner(ssh+").replace("capture_output=True,timeout=10)","10)")
_REMOTE=_REMOTE.replace("probe.returncode!=0 or probe.stderr or len(probe.stdout)>4096","not probe['complete'] or probe['returnCode']!=0 or probe['stderr'] or len(probe['stdout'])>4096").replace("arch=json.loads(probe.stdout)","arch=json.loads(probe['stdout'])")


def _source():return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
def _public(state='unknown',**fields):
    return {'state':state,'nativeActionAllowed':False,'replayAllowed':False,**fields}
def _corr(value):
    if not isinstance(value,str) or re.fullmatch('[0-9a-f]{32}',value) is None:raise ValueError('correlation')
def _journal(root,create,direct=False):
    group=root/'.rag_index';session._directory(group)
    path=group/('ssh-direct-nested-channel' if direct else 'ssh-fresh-nested-channel')
    if create:
        try:path.mkdir(mode=0o700)
        except FileExistsError:pass
    session._directory(path);return path

def _collect(argv,payload,timeout):
    if not isinstance(payload,bytes) or not 0<len(payload)<=4096:raise ValueError('input_bound')
    real_popen=subprocess.Popen
    def popen(command,**kwargs):
        kwargs['stdin']=subprocess.PIPE
        child=real_popen(command,**kwargs)
        try:child.stdin.write(payload);child.stdin.close()
        except BaseException:
            if child.poll() is None:child.kill()
            child.wait(timeout=1);raise
        return child
    facade=types.SimpleNamespace(Popen=popen,DEVNULL=subprocess.DEVNULL,PIPE=subprocess.PIPE,
                                 SubprocessError=subprocess.SubprocessError,TimeoutExpired=subprocess.TimeoutExpired)
    namespace=dict(recovery._bounded_socket_query.__globals__);namespace['subprocess']=facade
    collector=types.FunctionType(recovery._bounded_socket_query.__code__,namespace)
    return collector(argv,timeout)


def _master_shape(value):
    if not isinstance(value,dict) or set(value)!={'actor','socket','directory','listenerInode','gatewayBoot'}:return False
    actor=value['actor'];sock=value['socket'];directory=value['directory']
    if not isinstance(actor,dict) or set(actor)!={'pid','startTicks','uid'}:return False
    if any(type(actor[k])is not int or actor[k]<=0 for k in ('pid','startTicks')) or type(actor['uid'])is not int or actor['uid']<0:return False
    if not isinstance(sock,list) or len(sock)!=9 or any(type(n)is not int for n in sock):return False
    if not isinstance(directory,list) or len(directory)!=5 or any(type(n)is not int for n in directory):return False
    if not stat.S_ISSOCK(sock[2]) or sock[2]&0o077 or sock[3]!=actor['uid'] or sock[5]!=1:return False
    if not stat.S_ISDIR(directory[2]) or stat.S_IMODE(directory[2])!=0o700 or directory[3]!=actor['uid']:return False
    if not isinstance(value['listenerInode'],str) or re.fullmatch('[1-9][0-9]*',value['listenerInode'])is None:return False
    return isinstance(value['gatewayBoot'],str) and re.fullmatch('[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}',value['gatewayBoot']) is not None


def _ended_012_intent(value,current,prior_id):
    if type(value)is not dict:return False
    remote=value.get('remoteSourceSha256')
    if not isinstance(remote,str) or re.fullmatch('[0-9a-f]{64}',remote) is None:return False
    if remote!=_REVIEWED_ENDED_REMOTE_012 and remote!=_REVIEWED_ENDED_DIAGNOSTICS_012.get(prior_id):return False
    outer=value.get('outerReceiptSha256')
    if not isinstance(outer,str) or re.fullmatch('[0-9a-f]{64}',outer) is None:return False
    expected={**current,'correlationId':prior_id,'sourceSha256':_REVIEWED_ENDED_PREDECESSOR_012,
              'remoteSourceSha256':remote,'outerReceiptSha256':outer}
    # Canonical JSON equality keeps every nested scalar type strict too; bool
    # or float substitutions must not compare equal to an integer pin field.
    return json.dumps(value,sort_keys=True)==json.dumps(expected,sort_keys=True)


def _ended_0be3_intent(value,current,prior_id):
    if type(value)is not dict:return False
    outer=value.get('outerReceiptSha256')
    if type(outer)is not str or re.fullmatch('[0-9a-f]{64}',outer) is None:return False
    expected={**current,'correlationId':prior_id,'sourceSha256':_REVIEWED_ENDED_PREDECESSOR_0BE3,
              'remoteSourceSha256':_REVIEWED_ENDED_REMOTE_0BE3,'outerReceiptSha256':outer}
    return json.dumps(value,sort_keys=True)==json.dumps(expected,sort_keys=True)


_REVIEWED_ENDED_DIRECT_PROVIDER='b957d4b6bf37ca0c603f09f7df757284a56f042706533159fb5427c1b89fdafc'

def _ended_direct_intent_matches(previous,current):
    """Strict finite v1 bridge; the caller retains terminal and ready custody."""
    if type(previous)is not dict or type(current)is not dict or set(previous)!=set(current):return False
    if json.dumps(previous,sort_keys=True)==json.dumps(current,sort_keys=True):return True
    from . import ssh_direct_nested_channel as direct_channel
    old=previous.get('directSourcePins');new=current.get('directSourcePins')
    if type(old)is not dict or type(new)is not dict or set(old)!=set(direct_channel._SOURCE_NAMES) or set(new)!=set(old):return False
    if any(type(x)is not str or re.fullmatch('[0-9a-f]{64}',x)is None for x in [*old.values(),*new.values()]):return False
    if current.get('sourceSha256')!=_source() or new.get('ssh_fresh_nested_channel.py')!=current['sourceSha256']:return False
    if previous.get('sourceSha256') not in (_source(),_REVIEWED_ENDED_DIRECT_PROVIDER) or old.get('ssh_fresh_nested_channel.py')!=previous['sourceSha256']:return False
    normalized=dict(old);normalized['ssh_fresh_nested_channel.py']=new['ssh_fresh_nested_channel.py']
    if old.get('mcp_server.py')!=new.get('mcp_server.py'):
        if old.get('mcp_server.py')!='6ca7b4050ee5ca6977ff3948ad22b78350d49007c557ba603b9ab2a6558dc014' or new.get('mcp_server.py')!='5707593229d5fa3c331998a0f6bbc2bae1ca4dff3a94fd4f5f5c8064e07a14d7':return False
        normalized['mcp_server.py']=new['mcp_server.py']
    if normalized!=new:return False
    return json.dumps({**previous,'sourceSha256':current['sourceSha256'],'directSourcePins':new},sort_keys=True)==json.dumps(current,sort_keys=True)

def _operate(root,host,correlation_id,prepare,_private_capture=None,_private_inventory_diagnostic=None,*,direct=False):
    phase='input'
    try:
        if host!=HOST:return _public()
        _corr(correlation_id);root=Path(root).resolve(strict=True)
        if _private_capture is not None and not callable(_private_capture):raise ValueError('private_capture')
        if _private_inventory_diagnostic is not None and not callable(_private_inventory_diagnostic):raise ValueError('private_inventory_diagnostic')
        phase='inventory'
        with private.ownership(root) as (presented,directory,ownership), ExitStack() as stack:
            config_source=stack.enter_context(private.Snapshot(directory,transport.CONFIG_FILENAME))
            phase='route'
            config=transport.load_config(root);target=config.hosts[host]
            if target.transport!='nested' or not target.gateway or len(transport._route_hosts(config.hosts,host))!=2:return _public()
            gateway=transport.connection_host(config,target.gateway)
            if gateway.password is not None:return _public(reason='outer_prompt_unavailable')
            phase='channel_journal'
            source_sha=_source();journal=_journal(root,prepare,direct)
            channel_dir=stack.enter_context(private.Directory(journal))
            path=journal/(correlation_id+'.intent.json')
            if direct:
                from . import ssh_direct_nested_channel as direct_channel
                direct_guard=stack.enter_context(direct_channel.Guard(root))
                outer_receipt=direct_guard.authority_sha
                prefix,endpoint=direct_channel.outer_prefix(config,gateway)
                options=['-S','none','-o','ControlMaster=no','-o','ControlPersist=no']
            else:
                phase='outer_receipt'
                ready_journal=session._journal(root,host,False)
                _,ready_pin=session._read(ready_journal/'ready.json');outer_receipt=session._sha(session._json(ready_pin))
                phase='outer_reuse'
                options=session.reuse_only_options(root,host,outer_receipt)
                prefix,endpoint=session._outer_prefix(config,gateway)
                if prefix[1:3]!=['-F','/dev/null'] or options[2:]!=['-o','ControlMaster=no','-o','ControlPersist=no','-o','ProxyCommand=false']:return _public()
            phase='intent'
            intent={'version':1,'host':host,'correlationId':correlation_id,'sourceSha256':source_sha,
                    'remoteSourceSha256':hashlib.sha256(_REMOTE.encode()).hexdigest(),'inventory':config_source.pin(),
                    'outerReceiptSha256':outer_receipt,'expectedUid':EXPECTED_UID,'expectedBoot':EXPECTED_BOOT}
            if direct:
                intent['transportMode']='direct'
                intent['outerAuthoritySha256']=intent.pop('outerReceiptSha256')
                intent['directSourcePins']=direct_guard.source_pins
            existing=os.path.lexists(path)
            action='status'
            if prepare and not existing:
                # Do not permit a second unresolved channel. New correlation requires
                # explicit future terminal retirement; UNKNOWN never relaunches.
                for name in os.listdir(channel_dir.fd):
                    if not name.endswith('.intent.json'):continue
                    prior_id=name[:-len('.intent.json')];_corr(prior_id)
                    terminal=stack.enter_context(private.Snapshot(channel_dir,prior_id+'.terminal.json'))
                    ended=json.loads(terminal.body,object_pairs_hook=transport._reject_duplicate_keys)
                    if set(ended)!={'state','correlationId','receiptSha256','intentSha256','gatewayBoot'} or ended['state']!='ended' or ended['correlationId']!=prior_id:return _public()
                    old_intent=stack.enter_context(private.Snapshot(channel_dir,name))
                    old_value=json.loads(old_intent.body,object_pairs_hook=transport._reject_duplicate_keys)
                    if ended['intentSha256']!=old_intent.digest or (old_value.get('sourceSha256') not in (source_sha,_REVIEWED_ENDED_PREDECESSOR,_REVIEWED_ENDED_PREDECESSOR_9A,_REVIEWED_ENDED_PREDECESSOR_9527,_REVIEWED_ENDED_PREDECESSOR_012,_REVIEWED_ENDED_PREDECESSOR_0BE3) and not (direct and old_value.get('sourceSha256')==_REVIEWED_ENDED_DIRECT_PROVIDER)) or (not direct and old_value.get('inventory')!=config_source.pin()):return _public()
                    if old_value.get('sourceSha256')==_REVIEWED_ENDED_PREDECESSOR_9A and (set(old_value)!=set(intent) or old_value.get('remoteSourceSha256')!=_REVIEWED_ENDED_REMOTE_9A):return _public()
                    if old_value.get('sourceSha256')==_REVIEWED_ENDED_PREDECESSOR_9527 and (set(old_value)!=set(intent) or old_value.get('remoteSourceSha256')!=_REVIEWED_ENDED_REMOTE_9527):return _public()
                    if old_value.get('sourceSha256')==_REVIEWED_ENDED_PREDECESSOR_012:
                        if not _ended_012_intent(old_value,intent,prior_id) or not isinstance(ended['gatewayBoot'],str) or re.fullmatch('[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}',ended['gatewayBoot']) is None:return _public()
                    if old_value.get('sourceSha256')==_REVIEWED_ENDED_PREDECESSOR_0BE3:
                        if not _ended_0be3_intent(old_value,intent,prior_id) or type(ended['gatewayBoot'])is not str or re.fullmatch('[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}',ended['gatewayBoot']) is None:return _public()
                    if direct:
                        prior_expected={**intent,'correlationId':prior_id,'inventory':old_value.get('inventory'),'outerAuthoritySha256':old_value.get('outerAuthoritySha256')}
                        pin=old_value.get('inventory');binding=old_value.get('outerAuthoritySha256')
                        if not _ended_direct_intent_matches(old_value,prior_expected) or type(pin)is not dict or set(pin)!={'generation','size','sha256'} or type(pin['generation'])is not list or len(pin['generation'])!=9 or any(type(x)is not int for x in pin['generation']) or type(pin['size'])is not int or pin['size']<=0 or type(pin['sha256'])is not str or re.fullmatch('[0-9a-f]{64}',pin['sha256'])is None or type(binding)is not str or re.fullmatch('[0-9a-f]{64}',binding)is None:return _public()
                    if direct and ended['receiptSha256'] is None and (old_value.get('directSourcePins')!=intent['directSourcePins'] or os.path.lexists(journal/(prior_id+'.ready.json'))):return _public()
                    if ended['receiptSha256'] is not None:
                        old_ready=stack.enter_context(private.Snapshot(channel_dir,prior_id+'.ready.json'))
                        old_result=json.loads(old_ready.body,object_pairs_hook=transport._reject_duplicate_keys)
                        if ended['receiptSha256']!=old_ready.digest or ended['gatewayBoot']!=old_result['result']['master']['gatewayBoot']:return _public()
                        if direct or old_value.get('sourceSha256') in (_REVIEWED_ENDED_PREDECESSOR_012,_REVIEWED_ENDED_PREDECESSOR_0BE3):
                            if type(old_result)is not dict or set(old_result)!={'intent','result'} or json.dumps(old_result['intent'],sort_keys=True)!=json.dumps(old_intent.pin(),sort_keys=True):return _public()
                            prior=old_result['result']
                            if (type(prior)is not dict or set(prior)!={'state','correlationId','master','arch','controlPath'} or prior['state']!='ready' or prior['correlationId']!=prior_id or prior['controlPath']!='/tmp/vpn-channel-'+prior_id+'/m' or json.dumps(prior['arch'],sort_keys=True)!=json.dumps({'uid':EXPECTED_UID,'boot':EXPECTED_BOOT},sort_keys=True) or not _master_shape(prior['master'])):return _public()
                        old_ready.guard()
                    old_intent.guard();terminal.guard()
                if not target.password:return _public(reason='credential_unavailable')
                session._create(path,intent,parent_fd=channel_dir.fd);action='prepare'
            if not os.path.lexists(path):return _public(reason='intent_absent')
            held=stack.enter_context(private.Snapshot(channel_dir,path.name));actual=json.loads(held.body,object_pairs_hook=transport._reject_duplicate_keys)
            # The launch outer receipt remains historical. A positively admitted
            # successor outer can observe the same channel without replaying it.
            binding_key='outerAuthoritySha256' if direct else 'outerReceiptSha256'
            original_outer=actual.get(binding_key)
            if not isinstance(original_outer,str) or re.fullmatch('[0-9a-f]{64}',original_outer) is None:return _public()
            expected={**intent,binding_key:original_outer}
            if actual!=expected or (direct and original_outer!=outer_receipt):return _public(reason='intent_binding_changed')
            def guard():
                presented.guard();ownership.guard();config_source.guard();held.guard();channel_dir.guard()
                if _source()!=source_sha or asdict(transport.load_config(root))!=asdict(config):raise ValueError('source_or_config_changed')
                if direct:direct_guard.guard()
                else:session.verify_reuse(root,host,outer_receipt)
            phase='transport'
            guard()
            argv=[*prefix,*options,'-T','-o','ClearAllForwardings=yes','-o','PermitLocalCommand=no','-o','UpdateHostKeys=no',endpoint,
                  shlex.join(('python3','-I','-B','-c',('exec('+repr(_REMOTE)+')') if direct else _REMOTE,correlation_id,action,str(target.remote_config_file or ''),target.remote_host_alias,source_sha))]
            payload=json.dumps({'passphrase':target.password} if action=='prepare' else {}).encode()
            capture=_collect(argv,payload,35)
            # Raw retention is inside all held custody, followed by a final guard.
            phase='capture_retention'
            if _private_capture is not None:_private_capture(capture)
            phase='closing'
            guard()
            if not capture['complete'] or capture['stderr']:return _public(correlationId=correlation_id)
            if capture['returnCode']!=0:
                if capture['returnCode']==3:
                    failure=json.loads(capture['stdout'],object_pairs_hook=transport._reject_duplicate_keys)
                    if (isinstance(failure,dict) and set(failure) in ({'state','correlationId','failurePhase','launchCapture'},{'state','correlationId','failurePhase','launchCapture','failureReason','exceptionClass','errno'}) and
                            failure['state']=='unknown' and failure['correlationId']==correlation_id and
                            isinstance(failure['failurePhase'],str) and failure['failurePhase'] in _REMOTE_PHASES):
                        if 'failureReason' in failure and (not isinstance(failure['failureReason'],str) or failure['failureReason'] not in _REMOTE_REASONS or not isinstance(failure['exceptionClass'],str) or failure['exceptionClass'] not in _EXCEPTION_CLASSES or (failure['errno'] is not None and (type(failure['errno'])is not int or not 0<=failure['errno']<=255))):return _public(correlationId=correlation_id,failurePhase='parser')
                        # Diagnostic bytes live only in the trusted raw callback.
                        return _public(correlationId=correlation_id,failurePhase=failure['failurePhase'],**({key:failure[key] for key in ('failureReason','exceptionClass','errno')} if 'failureReason' in failure else {}))
                return _public(correlationId=correlation_id)

            phase='parser'
            result=json.loads(capture['stdout'],object_pairs_hook=transport._reject_duplicate_keys)
            if result.get('state')=='ended':
                ready_path=journal/(correlation_id+'.ready.json')
                ready=stack.enter_context(private.Snapshot(channel_dir,ready_path.name)) if os.path.lexists(ready_path) else None
                prior=json.loads(ready.body,object_pairs_hook=transport._reject_duplicate_keys) if ready else None
                if (set(result)!={'state','correlationId','prior','gatewayBoot'} or result['correlationId']!=correlation_id or
                        result['prior']!=(prior.get('result') if prior else None) or
                        not isinstance(result['gatewayBoot'],str) or re.fullmatch('[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}',result['gatewayBoot']) is None):return _public()
                if prior and result['gatewayBoot']!=result['prior']['master']['gatewayBoot']:return _public()
                terminal={'state':'ended','correlationId':correlation_id,'receiptSha256':ready.digest if ready else None,
                          'intentSha256':held.digest,'gatewayBoot':result['gatewayBoot']}
                terminal_path=journal/(correlation_id+'.terminal.json')
                if not os.path.lexists(terminal_path):session._create(terminal_path,terminal,parent_fd=channel_dir.fd)
                held_terminal=stack.enter_context(private.Snapshot(channel_dir,terminal_path.name))
                if json.loads(held_terminal.body,object_pairs_hook=transport._reject_duplicate_keys)!=terminal:return _public()
                guard()
                if ready:ready.guard()
                held_terminal.guard()
                return _public('ended',correlationId=correlation_id)
            expected_control='/tmp/vpn-channel-'+correlation_id+'/m'
            if (set(result)!={'state','correlationId','master','arch','controlPath'} or result['state']!='ready' or
                    result['correlationId']!=correlation_id or result['controlPath']!=expected_control or
                    result['arch']!={'uid':EXPECTED_UID,'boot':EXPECTED_BOOT}):return _public(correlationId=correlation_id)
            if not _master_shape(result['master']):return _public()
            receipt={'intent':held.pin(),'result':result}
            receipt_path=journal/(correlation_id+'.ready.json')
            if action=='prepare' or not os.path.lexists(receipt_path):session._create(receipt_path,receipt,parent_fd=channel_dir.fd)
            ready=stack.enter_context(private.Snapshot(channel_dir,receipt_path.name))
            if json.loads(ready.body,object_pairs_hook=transport._reject_duplicate_keys)!=receipt:return _public()
            guard();ready.guard()
            if direct:return _public('ready',correlationId=correlation_id,receiptSha256=ready.digest,outerAuthoritySha256=outer_receipt)
            return _public('ready',correlationId=correlation_id,receiptSha256=ready.digest,outerReceiptSha256=outer_receipt)
    except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError) as failure:
        if phase=='inventory' and _private_inventory_diagnostic is not None:
            try:_private_inventory_diagnostic(inventory_diagnostics.detail(failure))
            except Exception:pass
        return _public(failurePhase=phase)


def prepare(root:Path|str,host:str,correlation_id:str,*,_private_capture=None,_private_inventory_diagnostic=None)->dict[str,Any]:
    """At most one channel launch; existing intent means read-only status."""
    try:return _operate(root,host,correlation_id,True,_private_capture,_private_inventory_diagnostic)
    except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError):return _public()

def status(root:Path|str,host:str,correlation_id:str,*,_private_capture=None,_private_inventory_diagnostic=None)->dict[str,Any]:
    """Observe same original channel; never launch, remove, adopt or replay."""
    try:return _operate(root,host,correlation_id,False,_private_capture,_private_inventory_diagnostic)
    except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError):return _public()

def route_options(root:Path|str,host:str,correlation_id:str,receipt_sha256:str)->dict[str,Any]:
    """Read-only current admission. Does not create or renew a connection.

    Consumers must call this at actual transport use, rather than cache argv.
    The old application job identity is independent of this connection metadata.
    """
    _corr(correlation_id)
    if host!=HOST or not isinstance(receipt_sha256,str) or re.fullmatch('[0-9a-f]{64}',receipt_sha256) is None:raise ValueError('receipt')
    result=status(root,host,correlation_id)
    if result.get('state')!='ready':
        refusal={**result,'correlationId':correlation_id} if result.get('state')=='unknown' else _public(correlationId=correlation_id)
        raise ChannelUnknown(refusal)
    if result.get('receiptSha256')!=receipt_sha256:raise ValueError('channel_unknown')
    outer=result.get('outerReceiptSha256')
    if not isinstance(outer,str) or re.fullmatch('[0-9a-f]{64}',outer) is None:raise ValueError('outer_receipt')
    options=session.reuse_only_options(Path(root),host,outer)
    if (not isinstance(options,list) or len(options)!=8 or options[0]!='-S' or
            not isinstance(options[1],str) or options[2:]!=['-o','ControlMaster=no','-o','ControlPersist=no','-o','ProxyCommand=false']):raise ValueError('outer_options')
    session.verify_reuse(Path(root),host,outer)
    return {'correlationId':correlation_id,'receiptSha256':receipt_sha256,'outerReceiptSha256':outer,
            'outerOptions':tuple(options),'innerOptions':('-S','/tmp/vpn-channel-'+correlation_id+'/m',
            '-o','ControlMaster=no','-o','ControlPersist=no','-o','ProxyCommand=false')}


def ensure_channel(root:Path|str,host:str,correlation_id:str,receipt_sha256:str|None=None,*,_private_capture=None,_private_inventory_diagnostic=None)->dict[str,Any]:
    """Explicit connection-only admission/renewal, at most one new launch.

    UNKNOWN observes the same intent and never starts another channel. Positive
    ended lineage permits a new correlation, retaining every original receipt.
    Caller must rebind/observe its original job; this never resubmits any job.
    A changed Arch boot requires separate fresh host admission.
    """
    try:
        _corr(correlation_id)
        if host!=HOST:return _public()
        if receipt_sha256 is not None:
            if not isinstance(receipt_sha256,str) or re.fullmatch('[0-9a-f]{64}',receipt_sha256) is None:return _public()
            root_path=Path(root).resolve(strict=True)
            with private.Directory(_journal(root_path,False)) as directory:
                with private.Snapshot(directory,correlation_id+'.ready.json') as held:
                    if held.digest!=receipt_sha256:return _public()
                    held.guard()
        result=prepare(root,host,correlation_id,_private_capture=_private_capture,_private_inventory_diagnostic=_private_inventory_diagnostic)
        if result.get('state')=='ended':
            correlation_id=uuid.uuid4().hex
            result=prepare(root,host,correlation_id,_private_capture=_private_capture,_private_inventory_diagnostic=_private_inventory_diagnostic)
        if result.get('state')!='ready':return result
        return route_options(root,host,correlation_id,result['receiptSha256'])
    except ChannelUnknown as failure:return failure.result
    except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError):return _public()
