"""Durable fixed Arch-host supervisor for disposable DEB/Arch guest actions.

The acceptance adapter journals locally before calling submit. This supervisor
adds an exclusive host role claim and a detached host observer, so a lost SSH
response can be reconciled by status without repeating a guest action.
"""
from __future__ import annotations

import json
import hashlib
from pathlib import Path
import subprocess
from typing import Any, Mapping

try:
    from . import ssh_transport
    from .linux_deb_arch_acceptance import Intent
    from .linux_deb_arch_transport import FixedLiveObserver, fixed_native_plan
except ImportError:  # pragma: no cover - direct MCP fallback
    import ssh_transport  # type: ignore[no-redef]
    from linux_deb_arch_acceptance import Intent  # type: ignore[no-redef]
    from linux_deb_arch_transport import FixedLiveObserver, fixed_native_plan  # type: ignore[no-redef]


_HOST = "archlinux"
_ROLE_PORTS = {"ubuntu-fresh": 2330, "ubuntu-update": 2331, "arch-update": 2332, "arch-rollback": 2333}

_WORKER = r'''import json,os,shlex,stat,subprocess,sys,time
metadata=json.loads(sys.argv[1]); job=sys.argv[2]
role=metadata['guestRole']; port=__PORTS__[role]
tree='/home/kardinal/vpn-control-install-vm-parity-'+role
stage='/var/lib/vpn-control-parity/'+role
command=['python3','-B',stage+'/agent_tools/linux_deb_arch_native_driver.py',
 '--run-json',json.dumps(metadata['workerIntent'],sort_keys=True,separators=(',',':')),
 '--confirm-owned-disposable-guest']
ssh=['ssh','-tt','-p',str(port),'-i',tree+'/client-key','-o','IdentitiesOnly=yes',
 '-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+tree+'/known-hosts',
 '-o','BatchMode=yes','-o','ConnectTimeout=10','vpnfixture@127.0.0.1',shlex.join(command)]
result={'state':'unknown','correlationId':metadata['correlationId']}
try:
 done=subprocess.run(ssh,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=1800)
 if done.returncode==0 and len(done.stdout)<=1000000:
  lines=[line.strip().replace(b'\r',b'') for line in done.stdout.splitlines()]
  marked=[line[len(b'VPN_PARITY_RESULT='):] for line in lines if line.startswith(b'VPN_PARITY_RESULT=')]
  if len(marked)==1:
   guest=json.loads(marked[0])
   if isinstance(guest,dict):
    result={**guest,'state':'terminal','correlationId':metadata['correlationId'],
     'sourceSha':metadata['sourceSha'],'sourceFingerprint':metadata['sourceFingerprint'],
     'targetVersion':metadata['targetVersion'],'artifactIds':metadata['artifactIds'],
     'guestRole':role,'guestPort':port,'guestGeneration':metadata['guestGeneration']}
except Exception:pass
raw=(json.dumps(result,sort_keys=True,separators=(',',':'))+'\n').encode()
fd=os.open(job+'/result.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
with os.fdopen(fd,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
directory=os.open(job,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
try:os.fsync(directory)
finally:os.close(directory)
'''

_SUBMIT = r'''import json,os,stat,subprocess,sys,time
metadata=json.loads(sys.argv[1]); role=metadata.get('guestRole'); corr=metadata.get('correlationId')
if role not in __PORTS__:raise SystemExit(2)
if not isinstance(corr,str) or len(corr)!=36 or any(c not in '0123456789abcdef-' for c in corr):raise SystemExit(2)
tree='/home/kardinal/vpn-control-install-vm-parity-'+role
if metadata.get('guestPort')!=__PORTS__[role] or metadata.get('tree')!=tree:raise SystemExit(2)
pid=metadata['guestGeneration']['pid']
def ticks(pid):
 try:return int(open('/proc/%d/stat'%pid,encoding='ascii').read().rsplit(')',1)[1].split()[19])
 except (OSError,ValueError,IndexError):return None
disk=tree+'/task.qcow2'
qmp=tree+'/qmp.sock';port=__PORTS__[role]
def safe(path,kind):
 cur='/'
 try:
  for part in path.strip('/').split('/'):
   cur=os.path.join(cur,part); mode=os.lstat(cur).st_mode
   if stat.S_ISLNK(mode):return False
  return (stat.S_ISDIR if kind=='dir' else stat.S_ISREG if kind=='file' else stat.S_ISSOCK)(mode)
 except OSError:return False
def listener(port):
 result=[]
 for name in ('/proc/net/tcp','/proc/net/tcp6'):
  try:lines=open(name,encoding='ascii').readlines()[1:]
  except OSError:return None
  for line in lines:
   fields=line.split()
   if len(fields)<10:return None
   if int(fields[1].split(':')[1],16)==port and fields[3]=='0A':result.append(int(fields[9]))
 return result
if not safe(tree,'dir') or not safe(disk,'file') or not safe(qmp,'socket'):raise SystemExit(3)
info=os.stat(disk)
if (ticks(pid)!=metadata['guestGeneration']['startTicks'] or
 info.st_dev!=metadata['guestGeneration']['diskDevice'] or
 info.st_ino!=metadata['guestGeneration']['diskInode']):raise SystemExit(3)
raw=open('/proc/%d/cmdline'%pid,'rb').read(16385)
if len(raw)>16384 or not raw:raise SystemExit(3)
argv=raw.rstrip(b'\0').split(b'\0')
if not any(b'qemu-system-x86_64' in item for item in argv):raise SystemExit(3)
if not any(b'file='+disk.encode()+b',if=virtio,format=qcow2' in item for item in argv):raise SystemExit(3)
if not any(b'hostfwd=tcp:127.0.0.1:'+str(port).encode()+b'-:22' in item for item in argv):raise SystemExit(3)
if not any(qmp.encode() in item for item in argv):raise SystemExit(3)
live=listener(port)
if live is None or len(live)!=1:raise SystemExit(3)
fds=set()
for name in os.listdir('/proc/%d/fd'%pid):
 try:fds.add(os.readlink('/proc/%d/fd/%s'%(pid,name)))
 except OSError:pass
if 'socket:[%d]'%live[0] not in fds:raise SystemExit(3)
qmp_sockets=[]
for line in open('/proc/net/unix',encoding='ascii').readlines()[1:]:
 fields=line.split()
 if len(fields)>7 and fields[7]==qmp:qmp_sockets.append(int(fields[6]))
if len(qmp_sockets)!=1 or 'socket:[%d]'%qmp_sockets[0] not in fds:raise SystemExit(3)
for name in os.listdir('/proc'):
 if not name.isdigit() or int(name)==pid:continue
 try:other=open('/proc/'+name+'/cmdline','rb').read(16385)
 except OSError:continue
 if b'qemu-system-x86_64' in other and (disk.encode() in other or
  b'hostfwd=tcp:127.0.0.1:'+str(port).encode()+b'-:22' in other or qmp.encode() in other):raise SystemExit(3)
if ticks(pid)!=metadata['guestGeneration']['startTicks'] or os.stat(disk).st_ino!=info.st_ino:raise SystemExit(3)
root='/home/kardinal/.vpn-control-parity-jobs'
os.makedirs(root,mode=0o700,exist_ok=True)
check=os.lstat(root)
if not stat.S_ISDIR(check.st_mode) or check.st_uid!=os.getuid() or stat.S_IMODE(check.st_mode)!=0o700:raise SystemExit(3)
claim=root+'/'+role+'.claim'
fd=os.open(claim,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
with os.fdopen(fd,'wb') as stream:
 stream.write((json.dumps({'guestRole':role,'correlationId':corr},sort_keys=True)+'\n').encode());stream.flush();os.fsync(stream.fileno())
job=root+'/'+corr
os.mkdir(job,0o700)
fd=os.open(job+'/intent.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
with os.fdopen(fd,'wb') as stream:
 stream.write((json.dumps(metadata,sort_keys=True,separators=(',',':'))+'\n').encode());stream.flush();os.fsync(stream.fileno())
source=__WORKER__
process=subprocess.Popen([sys.executable,'-I','-B','-c','exec('+repr(source)+')',
 json.dumps(metadata,sort_keys=True,separators=(',',':')),job],
 stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
 close_fds=True,start_new_session=True)
fd=os.open(job+'/worker.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
with os.fdopen(fd,'wb') as stream:
 stream.write((json.dumps({'pid':process.pid,'startTicks':ticks(process.pid)})+'\n').encode());stream.flush();os.fsync(stream.fileno())
print(json.dumps({'state':'submitted','correlationId':corr}))
'''

_STATUS = r'''import json,os,stat,sys
role,corr=sys.argv[1:]
if role not in __PORTS__ or len(corr)!=36 or any(c not in '0123456789abcdef-' for c in corr):raise SystemExit(2)
root='/home/kardinal/.vpn-control-parity-jobs';job=root+'/'+corr
def owned_dir(path):
 cur='/'
 for part in path.strip('/').split('/'):
  cur=os.path.join(cur,part);info=os.lstat(cur)
  if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):raise SystemExit(3)
 info=os.lstat(path)
 if info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700:raise SystemExit(3)
owned_dir(root);owned_dir(job)
def read(path,maximum):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  info=os.fstat(fd)
  if (not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or
      stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1 or info.st_size>maximum):raise ValueError()
  return json.loads(os.read(fd,maximum+1))
 finally:os.close(fd)
claim=read(root+'/'+role+'.claim',512)
if claim!={'guestRole':role,'correlationId':corr}:raise SystemExit(3)
intent=read(job+'/intent.json',8192)
if intent.get('correlationId')!=corr or intent.get('guestRole')!=role:raise SystemExit(3)
try:result=read(job+'/result.json',65536)
except FileNotFoundError:
 worker=read(job+'/worker.json',512)
 try:live=int(open('/proc/%d/stat'%worker['pid'],encoding='ascii').read().rsplit(')',1)[1].split()[19])==worker['startTicks']
 except Exception:live=False
 result={'state':'running' if live else 'unknown','correlationId':corr,
  'sourceSha':intent['sourceSha'],'artifactIds':intent['artifactIds'],
  'guestRole':role,'guestPort':intent['guestPort']}
print(json.dumps(result,separators=(',',':')))
'''


def _program(source: str) -> str:
    return source.replace("__PORTS__", repr(_ROLE_PORTS)).replace("__WORKER__", repr(
        _WORKER.replace("__PORTS__", repr(_ROLE_PORTS))))


class FixedHostSupervisor:
    def __init__(self, root: Path | str, *, runner: Any = subprocess.run,
                 observer: FixedLiveObserver | None = None):
        self.root = Path(root).resolve()
        self.runner = runner
        self.observer = observer or FixedLiveObserver(root)

    def _remote(self, program: str, *args: str) -> Mapping[str, Any] | None:
        try:
            config = ssh_transport.load_config(self.root)
            if ssh_transport.connection_host(config, _HOST).password is not None:
                return None
            command = ("python3", "-I", "-B", "-c", "exec(" + repr(_program(program)) + ")", *args)
            argv = ssh_transport.build_ssh_argv(config, _HOST, 30, command=command)
            done = self.runner(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=32)
            if done.returncode != 0 or len(done.stdout) > 65536:
                return None
            result = json.loads(done.stdout)
            return result if isinstance(result, dict) else None
        except (OSError, TypeError, ValueError, KeyError, subprocess.TimeoutExpired):
            return None

    def submit(self, intent: Intent, admission: Mapping[str, Any]) -> Mapping[str, Any]:
        plan = fixed_native_plan(intent, admission)
        guest = admission["guest"]
        observed = self.observer(intent, guest, admission["preparation"])
        if (observed.get("ready") is not True or observed.get("ownerRuntimeOff") is not True
                or observed.get("packageProcessesOff") is not True
                or observed.get("protectedJobsTerminal") is not True
                or observed.get("profileUnused") is not True):
            return {"state": "unknown", "correlationId": intent.correlation_id}
        generation = {"pid": guest["qemuPid"], "startTicks": guest["qemuStartTicks"],
                      "diskDevice": guest["diskDevice"], "diskInode": guest["diskInode"]}
        preparation = admission["preparation"]
        worker_intent = {"profile": intent.profile, "distribution": intent.distribution,
                         "guestRole": intent.guest_role, "correlationId": intent.correlation_id,
                         "sourceSha": intent.source_sha,
                         "sourceFingerprint": admission["fixture"]["sourceFingerprint"],
                         "targetVersion": plan.expected_target_version, "targetSha256": plan.target_sha256,
                         "fixtureReceiptArtifactId": intent.artifact_ids["fixtureReceipt"],
                         "harnessSha256": admission["harnessSha256"],
                         "trustStoreSha256": (None if intent.profile == "fresh-deb-dependencies" else
                                              preparation["fixture"]["trustStoreSha256"])}
        worker_bytes = (json.dumps(worker_intent, sort_keys=True, separators=(",", ":")) + "\n").encode()
        if hashlib.sha256(worker_bytes).hexdigest() != preparation.get("workerIntentSha256"):
            return {"state": "unknown", "correlationId": intent.correlation_id}
        metadata = {"guestRole": intent.guest_role, "guestPort": intent.guest_port,
                    "tree": guest["tree"], "correlationId": intent.correlation_id,
                    "sourceSha": intent.source_sha, "sourceFingerprint": admission["fixture"]["sourceFingerprint"],
                    "targetVersion": plan.expected_target_version,
                    "artifactIds": dict(intent.artifact_ids), "guestGeneration": generation,
                    "workerIntent": worker_intent}
        result = self._remote(_SUBMIT, json.dumps(metadata, sort_keys=True, separators=(",", ":")))
        return result or {"state": "unknown", "correlationId": intent.correlation_id}

    def status(self, intent: Intent) -> Mapping[str, Any]:
        result = self._remote(_STATUS, intent.guest_role, intent.correlation_id)
        return result or {"state": "unknown", "correlationId": intent.correlation_id}
