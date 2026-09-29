"""Fixed, read-only guest admission for new DEB/Arch acceptance roles.

No caller supplied path, PID, command, account, or port reaches SSH.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
import subprocess
from typing import Any, Mapping

try:
    from . import ssh_transport
    from .linux_deb_arch_acceptance import Intent
except ImportError:  # pragma: no cover - direct MCP fallback
    import ssh_transport  # type: ignore[no-redef]
    from linux_deb_arch_acceptance import Intent  # type: ignore[no-redef]


_HOST = "archlinux"
_TREES = {"ubuntu-fresh": ("ubuntu", 2330), "ubuntu-update": ("ubuntu", 2331),
          "arch-update": ("arch", 2332), "arch-rollback": ("arch", 2333)}


@dataclass(frozen=True)
class NativePlan:
    profile: str
    guest_role: str
    stage: str
    argv: tuple[str, ...]
    expected_target_version: str
    target_sha256: str
    requires_rollback_trace: bool


def fixed_native_plan(intent: Intent, admission: Mapping[str, Any]) -> NativePlan:
    """Build exact public guest argv from verified immutable admission only."""
    if (admission.get("ready") is not True or admission.get("guestRole") != intent.guest_role
            or admission.get("sourceSha") != intent.source_sha
            or not isinstance(admission.get("fixture"), Mapping)
            or not isinstance(admission.get("preparation"), Mapping)):
        raise ValueError("DEB/Arch native plan is not admitted")
    stage = "/var/lib/vpn-control-parity/" + intent.guest_role
    if admission["preparation"].get("stage") != stage:
        raise ValueError("DEB/Arch native stage differs")
    target = admission["fixture"].get("targetVersion")
    if not isinstance(target, str) or not target or intent.guest_role not in _TREES:
        raise ValueError("DEB/Arch native target is invalid")
    if intent.profile == "fresh-deb-dependencies":
        argv = ("sudo", "-n", "apt-get", "install", "-y", "--", stage + "/target.deb")
    else:
        argv = ("python3", "-B", stage + "/scripts/test_linux_public_install.py",
                "--launcher", "/opt/vpn-control/bin/vpn-control", "--expected-target-version", target,
                "--confirm-owned-disposable-vm", "--require-same-source-recovery", "--retained-fixture-auth")
        if intent.distribution == "arch":
            argv += ("--arch-source-fixture", stage)
    return NativePlan(intent.profile, intent.guest_role, stage, argv, target,
                      intent.artifact_ids["targetPackage"].removeprefix("sha256-"),
                      intent.profile == "arch-rollback")
_GUEST = r'''import hashlib,json,os,subprocess,stat
try:
 distro=open('/etc/os-release',encoding='utf-8').read()
 expected=__DISTRO__
 profile=__PROFILE__
 role=__ROLE__
 base_version=__BASE_VERSION__
 server=__SERVER__
 worker_sha=__WORKER_SHA__
 native_sha=__NATIVE_SHA__
 rollback_sha=__ROLLBACK_SHA__
 distro_ok=('ID=ubuntu' in distro if expected=='ubuntu' else 'ID=arch' in distro)
 jobs_root='/var/lib/vpn-control-install-jobs'
 if os.path.lexists(jobs_root):
  if os.path.islink(jobs_root) or not os.path.isdir(jobs_root):raise ValueError('protected job root unsafe')
  names=os.listdir(jobs_root)
 else:names=[]
 jobs_clear=not names
 ancestors=set();current=os.getpid()
 while current>1 and current not in ancestors:
  ancestors.add(current)
  with open('/proc/%d/stat'%current,encoding='ascii') as stream:
   raw=stream.read().rsplit(')',1)[1].split()
  current=int(raw[1])
 procs=[];package_procs=[]
 for name in os.listdir('/proc'):
  if not name.isdigit() or int(name) in ancestors: continue
  path='/proc/'+name
  try:
   with open(path+'/cmdline','rb') as stream:raw=stream.read(8193)
   if not raw:continue
   exe=os.readlink(path+'/exe')
  except FileNotFoundError:
   if os.path.exists(path):raise ValueError('live process identity unreadable')
   continue
  except OSError:
   if os.path.exists(path):raise ValueError('live process identity unreadable')
   continue
  if len(raw)>8192:raise ValueError('live process argv oversized')
  parts=raw.rstrip(b'\0').split(b'\0') if raw else []
  first=os.path.basename(parts[0]).decode('ascii','replace') if parts else ''
  if (exe.startswith('/opt/vpn-control/') or os.path.basename(exe)=='sing-box'
      or first=='sing-box' or any(item.startswith(b'/opt/vpn-control/') and b'\n' not in item
                                   for item in parts)):
   procs.append(name)
  if first in ('apt','apt-get','dpkg','pacman','packagekitd'):
   package_procs.append(name)
 if expected=='ubuntu':
  package=subprocess.run(['dpkg-query','-W','-f=${Version}','vpn-control'],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=10)
  installed_version=package.stdout.decode('ascii','replace').split('-')[0] if package.returncode==0 else None
 else:
  launcher='/opt/vpn-control/bin/vpn-control'
  package=subprocess.run([launcher,'--version'],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=10) if os.path.isfile(launcher) else None
  installed_version=base_version if (package is not None and package.returncode==0
   and package.stdout.decode('ascii','replace').strip()==base_version) else None
 def ticks(pid):
  try:return int(open('/proc/%d/stat'%pid,encoding='ascii').read().rsplit(')',1)[1].split()[19])
  except (OSError,ValueError,IndexError):return None
 def root_stage(path):
  cur='/'
  for part in path.strip('/').split('/'):
   cur=os.path.join(cur,part); info=os.lstat(cur)
   if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or info.st_mode & 0o022:return False
  return True
 if profile=='fresh-deb-dependencies':
  xdg=subprocess.run(['dpkg-query','-W','xdg-utils'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10).returncode==0
  audit=subprocess.run(['dpkg','--audit'],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=10)
  profile_unused=(installed_version is None and not os.path.exists('/opt/vpn-control') and jobs_clear
   and not package_procs
   and not xdg and not os.path.exists('/usr/share/desktop-directories')
   and audit.returncode==0 and not audit.stdout.strip())
  stage='/var/lib/vpn-control-parity/'+role
  stage_ready=root_stage(stage)
  server_ready=True
 else:
  stage='/var/lib/vpn-control-parity/'+role
  profile_unused=jobs_clear and not package_procs and installed_version==base_version
  stage_ready=root_stage(stage) and root_stage(stage+'/server-state')
  def digest(path):
   info=os.lstat(path)
   if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode & 0o022:return None
   with open(path,'rb') as source:return hashlib.sha256(source.read(65537)).hexdigest() if info.st_size<=65536 else None
  server_ready=(ticks(server['serverPid'])==server['serverStartTicks']
   and digest(stage+'/server-state/ready.json')==server['readySha256']
   and digest(stage+'/fixture-certificate.pem')==server['certificateSha256']
   and digest(stage+'/trust.jks')==server['trustStoreSha256']
   and digest(stage+'/public-fixture.json')==server['publicFixtureSha256'])
  if server_ready:
   ready=json.load(open(stage+'/server-state/ready.json',encoding='utf-8'))
   public=json.load(open(stage+'/public-fixture.json',encoding='utf-8'))
   server_ready=(ready.get('serverPid')==server['serverPid']
    and ready.get('manifestSha256')==server['manifestSha256']
    and public=={'port':ready.get('port'),'sourceFingerprint':ready.get('sourceFingerprint'),
     'manifestSha256':ready.get('manifestSha256'),'readySha256':server['readySha256']})
 if stage_ready:
  stage_ready=root_stage(stage+'/agent_tools')
 if stage_ready:
  worker_path=stage+'/worker-intent.json'
  worker_info=os.lstat(worker_path)
  stage_ready=(stat.S_ISREG(worker_info.st_mode) and worker_info.st_uid==0
   and not worker_info.st_mode & 0o022 and worker_info.st_size<=8192
   and hashlib.sha256(open(worker_path,'rb').read(8193)).hexdigest()==worker_sha)
  for name,wanted in (('linux_deb_arch_native_driver.py',native_sha),
                      ('linux_deb_arch_rollback.py',rollback_sha)):
   path=stage+'/agent_tools/'+name
   info=os.lstat(path)
   stage_ready=(stage_ready and stat.S_ISREG(info.st_mode) and info.st_uid==0
    and not info.st_mode & 0o022 and 0<info.st_size<=1000000
    and hashlib.sha256(open(path,'rb').read(1000001)).hexdigest()==wanted)
 print(json.dumps({'complete':True,'distributionMatched':distro_ok,'ownerRuntimeOff':not procs,
  'protectedJobsTerminal':jobs_clear,'profileUnused':profile_unused,'stageReady':stage_ready,
  'packageProcessesOff':not package_procs,'fixtureServerReady':server_ready}))
except Exception:
 print(json.dumps({'complete':False}))
'''

_HOST_PROGRAM = r'''import json,os,socket,stat,subprocess,sys
manifest=json.loads(sys.argv[1]); role=manifest['guestRole']; distro,port=__ROLE_MAP__[role]
tree='/home/kardinal/vpn-control-install-vm-parity-'+role
def safe(path,kind):
 cur='/'
 try:
  for part in path.strip('/').split('/'):
   cur=os.path.join(cur,part); mode=os.lstat(cur).st_mode
   if stat.S_ISLNK(mode): return False
  return (stat.S_ISDIR if kind=='dir' else stat.S_ISREG if kind=='file' else stat.S_ISSOCK)(mode)
 except OSError: return False
def ticks(pid):
 try:return int(open('/proc/%d/stat'%pid,encoding='ascii').read().rsplit(')',1)[1].split()[19])
 except (OSError,ValueError,IndexError):return None
def listener(port):
 result=[]
 for name in ('/proc/net/tcp','/proc/net/tcp6'):
  try: lines=open(name,encoding='ascii').readlines()[1:]
  except OSError:return None
  for line in lines:
   fields=line.split()
   if len(fields)<10:return None
   if int(fields[1].split(':')[1],16)==port and fields[3]=='0A':result.append(int(fields[9]))
 return result
try:
 if manifest['tree']!=tree or manifest['sshPort']!=port or not safe(tree,'dir'):raise ValueError()
 disk=tree+'/task.qcow2'; qmp=tree+'/qmp.sock'; pid=manifest['qemuPid']
 if not safe(disk,'file') or not safe(qmp,'socket') or ticks(pid)!=manifest['qemuStartTicks']:raise ValueError()
 identity=os.stat(disk)
 if identity.st_dev!=manifest['diskDevice'] or identity.st_ino!=manifest['diskInode']:raise ValueError()
 raw=open('/proc/%d/cmdline'%pid,'rb').read(16385)
 if len(raw)>16384 or not raw:raise ValueError()
 argv=raw.rstrip(b'\0').split(b'\0')
 if not any(b'qemu-system-x86_64' in item for item in argv):raise ValueError()
 if not any(b'file='+disk.encode()+b',if=virtio,format=qcow2' in item for item in argv):raise ValueError()
 if not any(b'hostfwd=tcp:127.0.0.1:'+str(port).encode()+b'-:22' in item for item in argv):raise ValueError()
 if not any(qmp.encode() in item for item in argv):raise ValueError()
 live=listener(port)
 if live is None or len(live)!=1:raise ValueError()
 fds=set()
 for name in os.listdir('/proc/%d/fd'%pid):
  try: fds.add(os.readlink('/proc/%d/fd/%s'%(pid,name)))
  except OSError:pass
 if 'socket:[%d]'%live[0] not in fds:raise ValueError()
 qmp_sockets=[]
 for line in open('/proc/net/unix',encoding='ascii').readlines()[1:]:
  fields=line.split()
  if len(fields)>7 and fields[7]==qmp:qmp_sockets.append(int(fields[6]))
 if len(qmp_sockets)!=1 or 'socket:[%d]'%qmp_sockets[0] not in fds:raise ValueError()
 for name in os.listdir('/proc'):
  if not name.isdigit() or int(name)==pid:continue
  try: other=open('/proc/'+name+'/cmdline','rb').read(16385)
  except OSError:continue
  if b'qemu-system-x86_64' in other and (disk.encode() in other or
      b'hostfwd=tcp:127.0.0.1:'+str(port).encode()+b'-:22' in other or qmp.encode() in other):raise ValueError()
 for name in ('client-key','known-hosts'):
  if not safe(tree+'/'+name,'file'):raise ValueError()
 guest=['ssh','-p',str(port),'-i',tree+'/client-key','-o','IdentitiesOnly=yes',
  '-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+tree+'/known-hosts',
  '-o','BatchMode=yes','-o','ConnectTimeout=8','vpnfixture@127.0.0.1',
  'sudo -n -- python3 -I -B -c '+__GUEST_ARG__]
 done=subprocess.run(guest,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=12)
 if done.returncode!=0 or len(done.stdout)>4096:raise ValueError()
 facts=json.loads(done.stdout)
 if (not facts.get('complete') or not facts.get('distributionMatched')
     or not facts.get('stageReady') or not facts.get('fixtureServerReady')):raise ValueError()
 if ticks(pid)!=manifest['qemuStartTicks'] or os.stat(disk).st_ino!=identity.st_ino:raise ValueError()
 print(json.dumps({'ready':True,'qemuPid':pid,'qemuStartTicks':manifest['qemuStartTicks'],
  'diskDevice':identity.st_dev,'diskInode':identity.st_ino,'ownerRuntimeOff':facts['ownerRuntimeOff'],
  'protectedJobsTerminal':facts['protectedJobsTerminal'],'profileUnused':facts['profileUnused'],
  'packageProcessesOff':facts['packageProcessesOff']}))
except Exception:
 print(json.dumps({'ready':False}))
'''


def _program(distribution: str, profile: str, role: str, base_version: str | None,
             server: Mapping[str, Any] | None, worker_sha: str,
             native_sha: str, rollback_sha: str) -> str:
    guest = (_GUEST.replace("__DISTRO__", repr(distribution)).replace("__PROFILE__", repr(profile))
             .replace("__ROLE__", repr(role)).replace("__BASE_VERSION__", repr(base_version))
             .replace("__SERVER__", repr(dict(server) if server is not None else None))
             .replace("__WORKER_SHA__", repr(worker_sha))
             .replace("__NATIVE_SHA__", repr(native_sha))
             .replace("__ROLLBACK_SHA__", repr(rollback_sha)))
    import shlex
    return (_HOST_PROGRAM.replace("__ROLE_MAP__", repr(_TREES))
            .replace("__GUEST_ARG__", repr(shlex.quote("exec(" + repr(guest) + ")"))))


class FixedLiveObserver:
    def __init__(self, root: Path | str, *, runner: Any = subprocess.run):
        self.root = Path(root).resolve()
        self.runner = runner

    def __call__(self, intent: Intent, guest: Mapping[str, Any],
                 preparation: Mapping[str, Any]) -> dict[str, Any]:
        if intent.guest_role not in _TREES or _TREES[intent.guest_role] != (intent.distribution, intent.guest_port):
            return {"ready": False}
        if guest.get("guestRole") != intent.guest_role or guest.get("sshPort") != intent.guest_port:
            return {"ready": False}
        if (preparation.get("guestRole") != intent.guest_role
                or preparation.get("profile") != intent.profile or preparation.get("qemu", {}).get("pid") != guest.get("qemuPid")):
            return {"ready": False}
        try:
            config = ssh_transport.load_config(self.root)
            if ssh_transport.connection_host(config, _HOST).password is not None:
                return {"ready": False}
            baseline = preparation["baseline"]
            command = ("python3", "-I", "-B", "-c", "exec(" + repr(_program(
                intent.distribution, intent.profile, intent.guest_role, baseline["installedBaseVersion"],
                preparation["fixture"], preparation["workerIntentSha256"],
                preparation["nativeWorkerSha256"], preparation["rollbackWorkerSha256"])) + ")",
                       json.dumps(dict(guest), sort_keys=True, separators=(",", ":")))
            argv = ssh_transport.build_ssh_argv(config, _HOST, 25, command=command)
            done = self.runner(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=27)
            if done.returncode != 0 or len(done.stdout) > 4096:
                return {"ready": False}
            value = json.loads(done.stdout)
            return value if isinstance(value, dict) else {"ready": False}
        except (OSError, ValueError, KeyError, subprocess.TimeoutExpired):
            return {"ready": False}
