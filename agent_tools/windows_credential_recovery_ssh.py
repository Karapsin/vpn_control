"""Fixed, journaled reset of one configured Windows fixture task account.

The public boundary accepts only a configured host and correlation. Identity,
owned scheduled-task binding, VM generation, and a new private credential come
from the owner-only inventory/store. An uncertain QGA submission is observed,
never replayed.
"""

from __future__ import annotations

import base64
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import uuid
from typing import Any

try:
    from . import native_credentials, windows_credential_probe_ssh as transport
except ImportError:  # CLI/MCP server imports agent_tools modules as top-level names.
    import native_credentials
    import windows_credential_probe_ssh as transport


REPO_ROOT = Path(__file__).resolve().parents[1]
RESET_SCRIPT = REPO_ROOT / 'scripts' / 'windows_fixture_credential_reset.ps1'
_NAME = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$')
_HASH = re.compile(r'^[0-9a-f]{64}$')
_OPERATION = 'windows-fixture-password-reset-v1'


class WindowsCredentialRecoveryError(ValueError):
    """Configured fixture, intent, or private credential was not admitted."""


_REMOTE_START = r'''import base64,hashlib,json,os,re,secrets,socket,stat,sys,time
root,env,corr=sys.argv[1:]
def out(x): print(json.dumps(x,separators=(",",":"),sort_keys=True))
def die(reason): out({"state":"unknown","reason":reason}); raise SystemExit(0)
def write(path,data):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0),0o600)
 with os.fdopen(fd,"wb") as f: f.write(data); f.flush(); os.fsync(f.fileno())
def sync(path):
 fd=os.open(path,os.O_RDONLY|getattr(os,"O_DIRECTORY",0)); os.fsync(fd); os.close(fd)
def private_dir(path):
 i=os.lstat(path)
 if not stat.S_ISDIR(i.st_mode) or stat.S_ISLNK(i.st_mode) or i.st_uid!=os.geteuid() or stat.S_IMODE(i.st_mode)!=0o700: raise ValueError()
def live(sock,pid,ticks):
 if not isinstance(sock,str) or re.fullmatch(r"/[A-Za-z0-9._/-]+",sock) is None: return False
 if not stat.S_ISSOCK(os.lstat(sock).st_mode): return False
 if open('/proc/%d/stat'%pid,'rb').read().split()[21].decode()!=str(ticks): return False
 inodes=set()
 for f in os.listdir('/proc/%d/fd'%pid):
  try:
   link=os.readlink('/proc/%d/fd/%s'%(pid,f))
   if link.startswith('socket:['): inodes.add(link[8:-1].encode())
  except OSError: pass
 return any(len(x:=line.split())==8 and x[6] in inodes and x[7]==os.fsencode(sock) for line in open('/proc/net/unix','rb'))
def exchange(sock,command,args):
 c=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); c.settimeout(6); c.connect(sock)
 try:
  sid=secrets.randbits(63)
  c.sendall(b'\xff'+json.dumps({'execute':'guest-sync-delimited','arguments':{'id':sid}}).encode()+b'\n')
  while c.recv(1)!=b'\xff': pass
  line=b''
  while not line.endswith(b'\n'): line+=c.recv(1)
  if json.loads(line).get('return')!=sid: raise ValueError()
  c.sendall(json.dumps({'execute':command,'arguments':args}).encode()+b'\n')
  line=b''
  while not line.endswith(b'\n'): line+=c.recv(1)
  result=json.loads(line)
  if 'error' in result: raise ValueError()
  return result['return']
 finally: c.close()
try:
 private_dir(root)
 if not re.fullmatch(r'[A-Za-z0-9_.-]+',env) or not re.fullmatch(r'[0-9a-f-]{36}',corr): die('invalid_binding')
 header=sys.stdin.buffer.read(4)
 if len(header)!=4: die('invalid_input')
 count=int.from_bytes(header,'big')
 if not 0<count<=65536: die('invalid_input')
 raw=sys.stdin.buffer.read(count)
 if len(raw)!=count or sys.stdin.buffer.read(1): die('invalid_input')
 value=json.loads(raw)
 if set(value)!={'schema','socketPath','pid','startTicks','accountName','expectedSid','task','encodedProgram','programSha256','credential'} or value['schema']!=1: die('invalid_input')
 if not live(value['socketPath'],value['pid'],value['startTicks']): die('vm_binding_unverified')
 program=base64.b64decode(value['encodedProgram'],validate=True)
 if hashlib.sha256(program).hexdigest()!=value['programSha256']: die('program_mismatch')
 secret=base64.b64decode(value['credential'],validate=True)
 if not 0<len(secret)<=512 or any(c in secret for c in (b'\x00',b'\r',b'\n')): die('invalid_secret')
 parent=os.path.join(root,'windows-recovery'); os.mkdir(parent,0o700) if not os.path.exists(parent) else None; private_dir(parent)
 stage=os.path.join(parent,corr); os.mkdir(stage,0o700); private_dir(stage)
 binding={k:value[k] for k in ('socketPath','pid','startTicks','accountName','expectedSid','task','programSha256')}
 write(os.path.join(stage,'binding.json'),json.dumps(binding,sort_keys=True,separators=(',',':')).encode())
 write(os.path.join(stage,'intent.json'),json.dumps({'schema':1,'state':'intent','correlationId':corr},separators=(',',':')).encode())
 sync(stage); sync(parent)
 # This call is the single mutation boundary. Unknown outcome never re-enters it.
 response=exchange(value['socketPath'],'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',value['encodedProgram']],'input-data':base64.b64encode(secret).decode(),'capture-output':True})
 pid=response['pid']
 if not isinstance(pid,int) or pid<0: die('submit_unknown')
 write(os.path.join(stage,'pid'),str(pid).encode()); sync(stage)
 out({'state':'submitted','pid':pid})
except FileExistsError: out({'state':'unknown','reason':'exclusive_stage_exists'})
except Exception: out({'state':'unknown','reason':'start_failed'})
'''


_REMOTE_STATUS = r'''import base64,json,os,re,secrets,socket,stat,sys
root,env,corr=sys.argv[1:]
def out(x): print(json.dumps(x,separators=(",",":"),sort_keys=True))
def live(sock,pid,ticks):
 if not isinstance(sock,str) or re.fullmatch(r"/[A-Za-z0-9._/-]+",sock) is None: return False
 if not stat.S_ISSOCK(os.lstat(sock).st_mode): return False
 if open('/proc/%d/stat'%pid,'rb').read().split()[21].decode()!=str(ticks): return False
 inodes=set()
 for f in os.listdir('/proc/%d/fd'%pid):
  try:
   link=os.readlink('/proc/%d/fd/%s'%(pid,f))
   if link.startswith('socket:['): inodes.add(link[8:-1].encode())
  except OSError: pass
 return any(len(x:=line.split())==8 and x[6] in inodes and x[7]==os.fsencode(sock) for line in open('/proc/net/unix','rb'))
def read(path,max_bytes=8192):
 fd=os.open(path,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0))
 try:
  i=os.fstat(fd)
  if not stat.S_ISREG(i.st_mode) or i.st_uid!=os.geteuid() or stat.S_IMODE(i.st_mode)!=0o600 or i.st_size>max_bytes: raise ValueError()
  return os.read(fd,max_bytes+1)
 finally: os.close(fd)
def write(path,data):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0),0o600)
 with os.fdopen(fd,'wb') as f: f.write(data); f.flush(); os.fsync(f.fileno())
def exchange(sock,pid):
 c=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); c.settimeout(6); c.connect(sock)
 try:
  sid=secrets.randbits(63)
  c.sendall(b'\xff'+json.dumps({'execute':'guest-sync-delimited','arguments':{'id':sid}}).encode()+b'\n')
  while c.recv(1)!=b'\xff': pass
  line=b''
  while not line.endswith(b'\n'): line+=c.recv(1)
  if json.loads(line).get('return')!=sid: raise ValueError()
  c.sendall(json.dumps({'execute':'guest-exec-status','arguments':{'pid':pid}}).encode()+b'\n')
  line=b''
  while not line.endswith(b'\n'): line+=c.recv(1)
  result=json.loads(line)
  if 'error' in result: raise ValueError()
  return result['return']
 finally: c.close()
try:
 stage=os.path.join(root,'windows-recovery',corr)
 i=os.lstat(stage)
 if not stat.S_ISDIR(i.st_mode) or stat.S_ISLNK(i.st_mode) or i.st_uid!=os.geteuid() or stat.S_IMODE(i.st_mode)!=0o700: raise ValueError()
 binding=json.loads(read(os.path.join(stage,'binding.json')))
 if not isinstance(binding,dict) or binding.get('accountName') is None: raise ValueError()
 if not live(binding['socketPath'],binding['pid'],binding['startTicks']): raise ValueError()
 receipt=os.path.join(stage,'terminal.json')
 if os.path.exists(receipt): out(json.loads(read(receipt))); raise SystemExit(0)
 pidfile=os.path.join(stage,'pid')
 if not os.path.exists(pidfile): out({'state':'unknown','reason':'submission_unconfirmed'}); raise SystemExit(0)
 pid=int(read(pidfile))
 q=exchange(binding['socketPath'],pid)
 if not q.get('exited'): out({'state':'submitted','pid':pid}); raise SystemExit(0)
 raw=base64.b64decode(q.get('out-data',''),validate=True)
 result=json.loads(raw.decode('utf-8').strip())
 if not isinstance(result,dict) or set(result)!={'operation','correlationId','success','category','stage','accountSid'} or result['operation']!='windows-fixture-password-reset-v1' or result['correlationId']!=corr or result['accountSid']!=binding['expectedSid']: raise ValueError()
 stages={'caller','account','task-state','task-owner','task-action','task-arguments','installer','session','input','mutation','complete'}
 if result['stage'] not in stages: raise ValueError()
 if result['success'] is True and result['category']=='none' and result['stage']=='complete' and q.get('exitcode')==0: answer={'state':'terminal','success':True,'category':'none','stage':'complete','pid':pid}
 elif result['success'] is False and result['category']=='admission-rejected' and result['stage'] not in {'mutation','complete'}: answer={'state':'terminal','success':False,'category':'admission-rejected','stage':result['stage'],'pid':pid}
 else: answer={'state':'unknown','reason':'mutation_outcome_uncertain','pid':pid}
 if answer['state']=='terminal': write(receipt,json.dumps(answer,separators=(',',':')).encode())
 out(answer)
except Exception: out({'state':'unknown','reason':'status_failed'})
'''


def _admission(root: Path | str, host: str) -> tuple[Any, Any, Any]:
    config = transport._config(root)
    target = config.hosts.get(host)
    if target is None or target.fixture_transfer_root is None or target.windows_credential_probe is None:
        raise WindowsCredentialRecoveryError('Configured Windows recovery fixture is unavailable.')
    probe = target.windows_credential_probe
    recovery = getattr(probe, 'recovery_admission', None)
    if recovery is None:
        raise WindowsCredentialRecoveryError('Windows recovery admission is unavailable.')
    return config, target, recovery


def _binding(target: Any, correlation_id: str) -> native_credentials.CredentialBinding:
    probe = target.windows_credential_probe
    binding = native_credentials.CredentialBinding(probe.environment, probe.account_name,
        probe.expected_sid, 'account-login', correlation_id)
    binding.validate()
    return binding


def _task(recovery: Any) -> dict[str, Any]:
    keys = ('task_name','task_path','expected_task_state','expected_last_result','expected_task_execute',
        'expected_task_principal','expected_task_arguments_sha256')
    try:
        task = {key: getattr(recovery,key) for key in keys}
    except AttributeError as error:
        raise WindowsCredentialRecoveryError('Windows recovery task binding is incomplete.') from error
    if (not _NAME.fullmatch(task['task_name']) or task['task_path'] != '\\'
            or task['expected_task_state'] not in {'Disabled','Ready'}
            or type(task['expected_last_result']) is not int
            or not 0 <= task['expected_last_result'] <= 0xffffffff
            or not isinstance(task['expected_task_execute'],str) or not task['expected_task_execute']
            or not _NAME.fullmatch(task['expected_task_principal'])
            or not _HASH.fullmatch(task['expected_task_arguments_sha256'])):
        raise WindowsCredentialRecoveryError('Windows recovery task binding is invalid.')
    return task


def _ps_literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _program(probe: Any, recovery: Any, correlation_id: str) -> tuple[str, str]:
    task = _task(recovery)
    source = RESET_SCRIPT.read_bytes()
    if not source or len(source)>32768:
        raise WindowsCredentialRecoveryError('Fixed Windows reset script is unavailable.')
    # Script bytes are fixed source; only admitted, nonsecret identity parameters vary.
    script_b64 = base64.b64encode(source).decode('ascii')
    vals = [probe.account_name,probe.expected_sid,task['task_name'],task['task_path'],
        task['expected_task_state'],str(task['expected_last_result']),task['expected_task_execute'],
        task['expected_task_principal'],task['expected_task_arguments_sha256'],correlation_id]
    wrapper = "$s=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('"+script_b64+"')); & ([ScriptBlock]::Create($s)) " + ' '.join(_ps_literal(str(v)) for v in vals)
    if len(subprocess.list2cmdline(['powershell.exe','-NoProfile','-NonInteractive','-EncodedCommand',base64.b64encode(wrapper.encode('utf-16le')).decode()]))>=32767:
        raise WindowsCredentialRecoveryError('Fixed Windows reset program exceeds command length.')
    return base64.b64encode(wrapper.encode('utf-16le')).decode(), hashlib.sha256(wrapper.encode('utf-16le')).hexdigest()


def _journal_path(store: native_credentials.NativeCredentialStore, correlation_id: str) -> Path:
    try: uuid.UUID(correlation_id)
    except (ValueError,TypeError) as error: raise WindowsCredentialRecoveryError('Recovery correlation is invalid.') from error
    if str(uuid.UUID(correlation_id)) != correlation_id:
        raise WindowsCredentialRecoveryError('Recovery correlation is invalid.')
    return store.path / 'recovery' / (correlation_id + '.json')


def _reservation_path(store: native_credentials.NativeCredentialStore,
                      binding: native_credentials.CredentialBinding) -> Path:
    return store.path / 'recovery-reservations' / store._active_key(binding)


def _reserve(root: Path | str, binding: native_credentials.CredentialBinding) -> None:
    store=native_credentials.NativeCredentialStore(root)
    with store._locked():
        path=_reservation_path(store,binding)
        store._private_dir(path.parent,create=True)
        if path.exists():
            try: existing=json.loads(store._read_file(path,4096))
            except (ValueError,UnicodeDecodeError,json.JSONDecodeError) as error:
                raise WindowsCredentialRecoveryError('Recovery reservation is invalid.') from error
            if existing != {'schema':1,'correlationId':binding.correlation_id}:
                raise WindowsCredentialRecoveryError('Another recovery owns this account binding.')
            return
        store._write_exclusive(path,json.dumps({'schema':1,'correlationId':binding.correlation_id},separators=(',',':')).encode())
        store._sync_dir(path.parent)


def _finalize(root: Path | str, binding: native_credentials.CredentialBinding,
              result: dict[str, Any]) -> None:
    store=native_credentials.NativeCredentialStore(root)
    with store._locked():
        path=_reservation_path(store,binding)
        completed=store.path/'recovery-completed'/(binding.correlation_id+'.json')
        store._private_dir(completed.parent,create=True)
        if completed.exists():
            if json.loads(store._read_file(completed,4096)) != result:
                raise WindowsCredentialRecoveryError('Recovery completion binding changed.')
            return
        try: existing=json.loads(store._read_file(path,4096))
        except (ValueError,UnicodeDecodeError,json.JSONDecodeError) as error:
            raise WindowsCredentialRecoveryError('Recovery reservation is invalid.') from error
        if existing != {'schema':1,'correlationId':binding.correlation_id}:
            raise WindowsCredentialRecoveryError('Recovery reservation binding changed.')
        store._write_exclusive(completed,json.dumps(result,sort_keys=True,separators=(',',':')).encode())
        store._sync_dir(completed.parent)
        path.unlink()
        store._sync_dir(path.parent)


def _completed(root: Path | str, correlation_id: str) -> dict[str, Any] | None:
    store=native_credentials.NativeCredentialStore(root)
    with store._locked():
        path=store.path/'recovery-completed'/(correlation_id+'.json')
        if not path.exists(): return None
        try: value=json.loads(store._read_file(path,4096))
        except (ValueError,UnicodeDecodeError,json.JSONDecodeError) as error:
            raise WindowsCredentialRecoveryError('Recovery completion is invalid.') from error
    if not isinstance(value,dict) or value.get('correlationId')!=correlation_id or value.get('state')!='terminal':
        raise WindowsCredentialRecoveryError('Recovery completion is invalid.')
    return value


def _intent(root: Path | str, correlation_id: str) -> dict[str, Any]:
    store = native_credentials.NativeCredentialStore(root)
    path = _journal_path(store,correlation_id)
    with store._locked():
        store._private_dir(path.parent)
        try: raw=store._read_file(path,8192)
        except native_credentials.CredentialStoreError as error:
            raise WindowsCredentialRecoveryError('Recovery has no durable intent.') from error
    try: record=json.loads(raw)
    except (ValueError,UnicodeDecodeError,json.JSONDecodeError) as error:
        raise WindowsCredentialRecoveryError('Recovery intent is invalid.') from error
    if (not isinstance(record,dict) or set(record)!={'schema','correlationId','host','handle','environment',
            'socketPath','pid','startTicks','accountName','expectedSid','task','programSha256','previousCredentialPath'}
            or record['schema']!=1 or record['correlationId']!=correlation_id):
        raise WindowsCredentialRecoveryError('Recovery intent is invalid.')
    return record


def _public(raw: bytes | None, correlation_id: str, handle: str) -> dict[str, Any]:
    if raw is None:
        return {'state':'unknown','correlationId':correlation_id,'handle':handle}
    try: value=json.loads(raw)
    except (ValueError,UnicodeDecodeError,json.JSONDecodeError):
        return {'state':'unknown','correlationId':correlation_id,'handle':handle}
    if not isinstance(value,dict) or value.get('state') not in {'submitted','terminal','unknown'}:
        return {'state':'unknown','correlationId':correlation_id,'handle':handle}
    result={'state':value['state'],'correlationId':correlation_id,'handle':handle}
    for key in ('pid','success','category','stage'):
        if key in value: result[key]=value[key]
    return result


def start(root: Path | str, host: str, correlation_id: str, timeout_seconds: int = 15) -> dict[str, Any]:
    config,target,recovery = _admission(root,host)
    store = native_credentials.NativeCredentialStore(root)
    path = _journal_path(store,correlation_id)
    if path.exists():
        return status(root,host,correlation_id,timeout_seconds)
    probe=target.windows_credential_probe
    task=_task(recovery)
    program,program_hash=_program(probe,recovery,correlation_id)
    binding=_binding(target,correlation_id)
    _reserve(root,binding)
    handle=store.create(binding)
    secret=store.read(handle,binding)
    if any(c in secret for c in (b'\x00',b'\r',b'\n')):
        raise WindowsCredentialRecoveryError('Generated credential is invalid.')
    record={'schema':1,'correlationId':correlation_id,'host':host,'handle':handle,
        'environment':probe.environment,'socketPath':str(probe.qga_socket_path),'pid':probe.qemu_pid,
        'startTicks':probe.qemu_start_ticks,'accountName':probe.account_name,'expectedSid':probe.expected_sid,
        'task':task,'programSha256':program_hash,'previousCredentialPath':str(probe.credential_path)}
    duplicate=False
    with store._locked():
        store._private_dir(path.parent,create=True)
        try:
            store._write_exclusive(path,json.dumps(record,sort_keys=True,separators=(',',':')).encode())
            store._sync_dir(path.parent)
        except FileExistsError:
            duplicate=True
    if duplicate:
        return status(root,host,correlation_id,timeout_seconds)
    payload={'schema':1,'socketPath':str(probe.qga_socket_path),'pid':probe.qemu_pid,
        'startTicks':probe.qemu_start_ticks,'accountName':probe.account_name,
        'expectedSid':probe.expected_sid,'task':task,'encodedProgram':program,
        'programSha256':program_hash,'credential':base64.b64encode(secret).decode()}
    secret=b''
    raw=transport._run_ssh(config,host,transport._remote_command(_REMOTE_START,
        str(target.fixture_transfer_root),probe.environment,correlation_id),transport._remote_payload(payload),timeout_seconds)
    return _public(raw,correlation_id,handle)


def _probe_correlation(correlation_id: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL,'vpn-control/windows-credential-recovery/'+correlation_id+'/verify'))


def _publish_inventory(root: Path | str, host: str, record: dict[str, Any]) -> None:
    store=native_credentials.NativeCredentialStore(root)
    with store._locked():
        path=Path(root).resolve()/'.vm-hosts.local.json'
        info=os.lstat(path)
        if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
                or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600):
            raise WindowsCredentialRecoveryError('Private inventory cannot be updated safely.')
        fd=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
        try:
            opened=os.fstat(fd)
            if (opened.st_dev,opened.st_ino)!=(info.st_dev,info.st_ino):
                raise WindowsCredentialRecoveryError('Private inventory changed during read.')
            raw=os.read(fd,1048577)
        finally: os.close(fd)
        if len(raw)>1048576:
            raise WindowsCredentialRecoveryError('Private inventory is too large.')
        config=json.loads(raw)
        probe=config['hosts'][host]['windowsCredentialProbe']
        if (probe['environment']!=record['environment'] or probe['accountName']!=record['accountName']
                or probe['expectedSid']!=record['expectedSid'] or probe['qgaSocketPath']!=record['socketPath']
                or probe['qemuPid']!=record['pid'] or probe['qemuStartTicks']!=record['startTicks']):
            raise WindowsCredentialRecoveryError('Inventory account binding changed.')
        new_path=str(store.path/record['handle']/'secret')
        if probe['credentialPath']==new_path:
            return
        if probe['credentialPath']!=record['previousCredentialPath']:
            raise WindowsCredentialRecoveryError('Inventory credential reference changed.')
        probe['credentialPath']=new_path
        fd,name=tempfile.mkstemp(prefix='.vm-hosts-credential-',dir=path.parent)
        try:
            os.fchmod(fd,0o600)
            with os.fdopen(fd,'w',encoding='utf-8') as target:
                json.dump(config,target,indent=2); target.write('\n'); target.flush(); os.fsync(target.fileno())
            current=os.lstat(path)
            if (current.st_dev,current.st_ino,current.st_size,current.st_mtime_ns)!=\
                    (info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns):
                raise WindowsCredentialRecoveryError('Private inventory changed before publication.')
            check_fd=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
            try:
                if os.read(check_fd,len(raw)+1)!=raw:
                    raise WindowsCredentialRecoveryError('Private inventory bytes changed before publication.')
            finally:
                os.close(check_fd)
            os.replace(name,path)
            store._sync_dir(path.parent)
        finally:
            if os.path.exists(name): os.unlink(name)


def _verify_and_publish(root: Path | str, host: str, record: dict[str, Any], timeout_seconds: int) -> dict[str, Any]:
    corr=record['correlationId']; handle=record['handle']; probe_corr=_probe_correlation(corr)
    binding=native_credentials.CredentialBinding(record['environment'],record['accountName'],
        record['expectedSid'],'account-login',corr)
    store=native_credentials.NativeCredentialStore(root)
    secret=store.read(handle,binding)
    probe_intent=transport._intent_path(Path(root).resolve(),probe_corr)
    if probe_intent.exists():
        observed=transport.status(root,host,probe_corr,timeout_seconds)
    else:
        observed=transport.start_with_private_secret(root,host,probe_corr,secret,timeout_seconds)
    if observed['state']=='terminal' and observed.get('success') is True and observed.get('errorCategory')=='none':
        _publish_inventory(root,host,record)
        store.publish_active(handle,binding)
        result={'state':'terminal','correlationId':corr,'handle':handle,'success':True,
                'verified':True,'probeCorrelationId':probe_corr}
        _finalize(root,binding,result)
        return result
    if observed['state']=='terminal':
        return {'state':'unknown','correlationId':corr,'handle':handle,'reason':'verification-failed',
                'probeCorrelationId':probe_corr}
    return {'state':'verifying' if observed['state']=='submitted' else 'unknown',
            'correlationId':corr,'handle':handle,'probeCorrelationId':probe_corr}


def status(root: Path | str, host: str, correlation_id: str, timeout_seconds: int = 15) -> dict[str, Any]:
    record=_intent(root,correlation_id)
    if record['host']!=host:
        raise WindowsCredentialRecoveryError('Recovery host binding does not match.')
    completed=_completed(root,correlation_id)
    if completed is not None:
        if completed.get('handle')!=record['handle']:
            raise WindowsCredentialRecoveryError('Recovery completion handle changed.')
        return completed
    config,target,_=_admission(root,host)
    probe=target.windows_credential_probe
    if (record['environment']!=probe.environment or record['socketPath']!=str(probe.qga_socket_path)
            or record['pid']!=probe.qemu_pid or record['startTicks']!=probe.qemu_start_ticks
            or record['accountName']!=probe.account_name or record['expectedSid']!=probe.expected_sid):
        raise WindowsCredentialRecoveryError('Recovery VM/account binding does not match.')
    raw=transport._run_ssh(config,host,transport._remote_command(_REMOTE_STATUS,
        str(target.fixture_transfer_root),record['environment'],correlation_id),None,timeout_seconds)
    result=_public(raw,correlation_id,record['handle'])
    if result['state']=='terminal' and result.get('success') is True:
        return _verify_and_publish(root,host,record,timeout_seconds)
    if result['state']=='terminal' and result.get('category')=='admission-rejected':
        _finalize(root,_binding(target,correlation_id),result)
    return result


def credential_status(root: Path | str, host: str, handle: str, correlation_id: str) -> dict[str, Any]:
    _,target,_=_admission(root,host)
    binding=_binding(target,correlation_id)
    result=native_credentials.NativeCredentialStore(root).status(handle,binding)
    return {'handle':result['handle'],'available':result['available'],'environment':binding.environment,
        'accountName':binding.account_name,'expectedSid':binding.expected_sid,'purpose':binding.purpose,
        'correlationId':binding.correlation_id}
