"""Exact Fedora RPM workspace observation and one-shot recovery cleanup.

The failed public install remains terminal. Cleanup removes only its retained
synthetic workspace after exact owner, package, process, and receipt proofs.
"""

from __future__ import annotations

import ast
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import uuid
from typing import Any, Mapping

from . import native_rpm_public_install_ssh as rpm, ssh_transport


_CORRELATION = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z")
_SCANNER_SHA256 = "77630e31a9e3d344fc7c0092af5399d4266a4b243d1116e673cfd6c4e87b8473"
_REASONS = {"invalid-input", "workspace-identity", "owner-generation", "owner-descriptor",
            "process-count", "process-status-invalid", "process-status-unavailable",
            "process-generation", "descriptor-count", "process-links-unavailable",
            "descriptor-unavailable", "workspace-changed", "observer-exception"}
_OBSERVER_REASONS = {"private-evidence-unsafe", "private-evidence-changed", "job-unsafe",
                     "job-identity-mismatch", "not-terminal-cleanup-failure", "pointer-unsafe",
                     "pointer-invalid", "evidence-unsafe", "result-identity-mismatch",
                     "workspace-unsafe", "privileged-observer-unavailable",
                     "privileged-observer-invalid", "observer-exception"}
_FAILED_PUBLIC = "944447ff-7ee3-42df-8ca8-f02dac670459"
_OWNER_QUIT = "bf57271c-ca8f-4715-99c6-8581180e94c1"
_TARGET_NEVRA = "vpn-control-2.2.0-1.x86_64"
_TARGET_HEADER = "3ef23bc543b6302432f514edc94ba04d75a8dc3d"


def _scanner_program(root: Path) -> str:
    """Stage only the reviewed fixed scanner function, never a guest command."""
    path = root / "scripts" / "test_linux_public_install.py"
    directory = path.parent.lstat()
    if (not stat.S_ISDIR(directory.st_mode) or directory.st_uid != os.getuid() or
            stat.S_IMODE(directory.st_mode) & 0o022):
        raise ValueError("Fixed Fedora workspace scanner directory unsafe")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as error:
        raise ValueError("Fixed Fedora workspace scanner source unsafe") from error
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or
                stat.S_IMODE(before.st_mode) & 0o022 or not 0 < before.st_size <= 1048576):
            raise ValueError("Fixed Fedora workspace scanner source unsafe")
        raw = os.read(fd, before.st_size + 1)
        after = os.fstat(fd)
        current = path.lstat()
        if (len(raw) != before.st_size or (before.st_dev, before.st_ino, before.st_size) !=
                (after.st_dev, after.st_ino, after.st_size) or
                (before.st_dev, before.st_ino) != (current.st_dev, current.st_ino)):
            raise ValueError("Fixed Fedora workspace scanner source changed")
    finally:
        os.close(fd)
    source = raw.decode("utf-8")
    tree = ast.parse(source)
    matches = [node for node in tree.body if isinstance(node, ast.FunctionDef) and
               node.name == "_privileged_workspace_observation"]
    if len(matches) != 1 or matches[0].decorator_list:
        raise ValueError("Fixed Fedora workspace scanner unavailable")
    function = ast.get_source_segment(source, matches[0])
    if (not function or len(function) > 12000 or
            hashlib.sha256(function.encode()).hexdigest() != _SCANNER_SHA256):
        raise ValueError("Fixed Fedora workspace scanner unsafe")
    return ("import json,os,stat,sys\nfrom pathlib import Path\n" + function +
            "\nif os.geteuid()!=0: raise SystemExit(3)\n"
            "workspace,uid,pid,ticks,fd,dev,ino=sys.argv[1:]\n"
            "result=_privileged_workspace_observation(Path('/proc'),Path(workspace),"
            "int(uid),int(pid),int(ticks),int(fd),(int(dev),int(ino)))\n"
            "print(json.dumps(result,separators=(',',':')))\n")


def _encoded_scanner(root: Path) -> str:
    program = _scanner_program(root).encode("utf-8")
    if len(program) > 8192:
        raise ValueError("Fixed Fedora workspace scanner too large")
    return base64.b64encode(program).decode("ascii")


_OBSERVE = r'''import base64,json,os,stat,subprocess,sys
from pathlib import Path
root,corr,bundle,artifacts,version,fingerprint,scanner=sys.argv[1:]
def unknown(reason):
 print(json.dumps({'state':'unknown','correlationId':corr,'reason':reason},separators=(',',':')));raise SystemExit(0)
def private_json(path,limit=1048576):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  info=os.fstat(fd)
  if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o600 or not 0<info.st_size<=limit:unknown('private-evidence-unsafe')
  raw=os.read(fd,info.st_size+1);after=os.fstat(fd)
  if len(raw)!=info.st_size or (info.st_dev,info.st_ino,info.st_size)!=(after.st_dev,after.st_ino,after.st_size):unknown('private-evidence-changed')
  return json.loads(raw)
 finally:os.close(fd)
try:
 job=Path(root)/'native-scenario-jobs'/'fedora2328'/'linux-rpm-public-install-recovery'/corr
 info=job.lstat()
 if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:unknown('job-unsafe')
 intent=private_json(job/'intent.json');receipt=private_json(job/'receipt.json')
 expected={'correlationId':corr,'host':'fedora2328','environment':'fedora2328',
  'scenarioId':'linux-rpm-public-install-recovery','bundleHash':bundle,'artifactIds':json.loads(artifacts)}
 if any(intent.get(k)!=v or receipt.get(k)!=v for k,v in expected.items()):unknown('job-identity-mismatch')
 if receipt.get('exitCode')!=1 or receipt.get('failurePhase') is not None:unknown('not-terminal-cleanup-failure')
 summary=receipt.get('scenarioEvidence')
 if not isinstance(summary,dict) or summary.get('result')!='failed' or summary.get('correlationId')!=corr or summary.get('cleanup',{}).get('workspaceRemoved') is not False:unknown('not-terminal-cleanup-failure')
 stdout=job/'harness.stdout';fd=os.open(stdout,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  info=os.fstat(fd)
  if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o600 or not 0<info.st_size<=4194304:unknown('pointer-unsafe')
  first=b''
  while not first.endswith(b'\n') and len(first)<=4096:
   block=os.read(fd,1)
   if not block:break
   first+=block
  if len(first)>4096 or not first.endswith(b'\n'):unknown('pointer-unsafe')
 finally:os.close(fd)
 pointer=json.loads(first);evidence=pointer.get('evidence');workspace=pointer.get('workspace')
 prefix='/tmp/vpn-public-install-evidence-'
 if not isinstance(evidence,str) or not evidence.startswith(prefix) or not evidence[len(prefix):] or '/' in evidence[len(prefix):] or workspace!=evidence+'/workspace':unknown('pointer-invalid')
 info=os.stat(evidence,follow_symlinks=False)
 if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:unknown('evidence-unsafe')
 result=private_json(Path(evidence)/'install-result.json')
 cleanup=result.get('syntheticWorkspaceCleanup')
 if result.get('sourceFingerprint')!=fingerprint or result.get('targetVersion')!=version or result.get('productionTrustedInstallSucceeded') is not True or not isinstance(cleanup,dict) or cleanup.get('requested') is not True or cleanup.get('workspaceRemoved') is not False:unknown('result-identity-mismatch')
 info=os.stat(workspace,follow_symlinks=False)
 if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:unknown('workspace-unsafe')
 fd=os.open(workspace,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:
  held=os.fstat(fd);fields=Path('/proc/self/stat').read_text(encoding='ascii').rsplit(')',1)[1].split()
  args=[workspace,str(os.geteuid()),str(os.getpid()),str(int(fields[19])),str(fd),str(held.st_dev),str(held.st_ino)]
  if len(scanner)>10924:unknown('privileged-observer-invalid')
  program=base64.b64decode(scanner,validate=True)
  if len(program)>8192:unknown('privileged-observer-invalid')
  run=subprocess.run(['sudo','-n','--','python3','-I','-B','-c',program.decode('utf-8'),*args],
   stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=35,check=False)
 finally:os.close(fd)
 if run.returncode!=0 or len(run.stdout)>4096:unknown('privileged-observer-unavailable')
 observed=json.loads(run.stdout)
 if not isinstance(observed,dict):unknown('privileged-observer-invalid')
 print(json.dumps({'state':'observed','correlationId':corr,'workspace':'retained',
  'scanner':observed},separators=(',',':')))
except SystemExit:raise
except Exception:unknown('observer-exception')
'''


def status(root: Path | str, inputs: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(inputs, Mapping) or set(inputs) != {"correlationId"} or not isinstance(inputs["correlationId"], str) or not _CORRELATION.fullmatch(inputs["correlationId"]):
        raise ValueError("Exact Fedora recovery correlation required")
    root = Path(root).resolve(strict=True)
    corr = inputs["correlationId"]
    driver = rpm.RpmPublicInstallSshDriver(root)
    public = driver.status(corr)
    summary = public.get("scenarioEvidence") if isinstance(public, Mapping) else None
    if (public.get("state") != "terminal" or public.get("correlationId") != corr or
            public.get("exitCode") != 1 or not isinstance(summary, Mapping) or
            summary.get("result") != "failed" or
            not isinstance(summary.get("cleanup"), Mapping) or
            summary["cleanup"].get("workspaceRemoved") is not False):
        return {"state": "unknown", "correlationId": corr, "reason": "public-terminal-cleanup-unavailable"}
    stored = driver._read_journal(corr)
    if not isinstance(stored, Mapping):
        return {"state": "unknown", "correlationId": corr, "reason": "public-journal-unavailable"}
    from . import linux_rpm_fixture_server_lifecycle as server
    server_record = server._journal(root, corr)
    if not isinstance(server_record, Mapping) or server_record.get("correlationId") != corr:
        return {"state": "unknown", "correlationId": corr, "reason": "server-journal-unavailable"}
    config = ssh_transport.load_config(root)
    host = config.hosts.get("fedora2328")
    if host is None or host.user != "vpnfixture" or host.fixture_transfer_root is None:
        return {"state": "unknown", "correlationId": corr, "reason": "guest-unavailable"}
    raw = driver._remote(config, "fedora2328", _OBSERVE, (
        str(host.fixture_transfer_root), corr, stored["bundleHash"],
        json.dumps(stored["artifactIds"], sort_keys=True, separators=(",", ":")),
        server_record["expectedTargetVersion"], server_record["sourceFingerprint"],
        _encoded_scanner(root)), diagnostic=True)
    if not isinstance(raw, Mapping) or raw.get("correlationId") != corr or raw.get("state") != "observed":
        reason = raw.get("reason") if isinstance(raw, Mapping) else None
        return {"state": "unknown", "correlationId": corr,
                "reason": reason if reason in _OBSERVER_REASONS else "guest-observer-unavailable"}
    scan = raw.get("scanner")
    if not isinstance(scan, Mapping):
        return {"state": "unknown", "correlationId": corr, "reason": "scanner-invalid"}
    if scan.get("state") == "absent" and type(scan.get("sameUidCount")) is int and 0 < scan["sameUidCount"] <= 4096:
        return {"state": "observed", "correlationId": corr, "workspace": "retained",
                "scannerState": "absent", "sameUidCount": scan["sameUidCount"]}
    if scan.get("state") == "referenced" and type(scan.get("pid")) is int and scan["pid"] > 1 and type(scan.get("startTicks")) is int and scan["startTicks"] > 0:
        return {"state": "observed", "correlationId": corr, "workspace": "retained",
                "scannerState": "referenced", "referencePid": scan["pid"],
                "referenceStartTicks": scan["startTicks"]}
    if scan.get("state") == "unknown" and scan.get("reason") in _REASONS:
        return {"state": "unknown", "correlationId": corr, "workspace": "retained",
                "scannerState": "unknown", "scannerReason": scan["reason"]}
    return {"state": "unknown", "correlationId": corr, "reason": "scanner-invalid"}


_PRIVILEGED_CLEANUP_GUARD = r'''import json,os,pwd,stat,subprocess,sys
from pathlib import Path
scanner,workspace,uid,pid,ticks,fd,dev,ino,nevra,header=sys.argv[1:]
def emit(state,reason=None):
 print(json.dumps({'state':state,**({'reason':reason} if reason else {})},separators=(',',':')))
try:
 if os.geteuid()!=0 or pwd.getpwnam('vpnfixture').pw_uid!=int(uid):raise ValueError('privilege')
 expected='vpn-control-2.2.0-1.x86_64';expected_header='3ef23bc543b6302432f514edc94ba04d75a8dc3d'
 if nevra!=expected or header!=expected_header:raise ValueError('target-intent')
 commands=(['rpm','-q','--qf','%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}','vpn-control'],
  ['rpm','-q','--qf','%{SHA1HEADER}','vpn-control'],['rpm','-V','vpn-control'])
 answers=[subprocess.run(command,capture_output=True,timeout=30) for command in commands]
 if any(item.returncode or item.stderr for item in answers) or answers[0].stdout.decode()!=expected or answers[1].stdout.decode()!=expected_header or answers[2].stdout:raise ValueError('package')
 entries=[item for item in os.scandir('/proc') if item.name.isdecimal()]
 if len(entries)>4096:raise ValueError('process-count')
 for entry in entries:
  try:
   lines=(Path(entry.path)/'status').read_text(encoding='ascii').splitlines()
   rows=[line.split()[1:] for line in lines if line.startswith('Uid:')]
   if len(rows)!=1 or len(rows[0])!=4:raise ValueError('process-uid')
   uids={int(value) for value in rows[0]}
   if int(uid) not in uids and 0 not in uids:continue
   raw=(Path(entry.path)/'cmdline').read_bytes()[:65537]
   if len(raw)>65536:raise ValueError('process-command')
  except FileNotFoundError:
   if not os.path.exists(entry.path):continue
   raise ValueError('process-changed')
  argv=[part.decode('utf-8','replace') for part in raw.split(b'\0') if part]
  if not argv:continue
  exe=os.path.basename(argv[0])
  if exe in ('vpn-control','sing-box','rpm','dnf','dnf5','packagekitd') or (int(uid) in uids and exe in ('java','javaw') and any('/opt/vpn-control/' in word or 'com.kardinal.vpncontrol' in word for word in argv)):
   raise ValueError('active-process')
 observed=json.loads(subprocess.run(['python3','-I','-B','-c',scanner,workspace,uid,pid,ticks,fd,dev,ino],capture_output=True,timeout=35,check=True).stdout)
 if observed.get('state')!='absent' or type(observed.get('sameUidCount')) is not int or not 0<observed['sameUidCount']<=4096:raise ValueError('workspace-reference')
 emit('ready')
except Exception:emit('unknown','guard-unavailable')
'''

_CLEANUP = r'''import base64,json,os,pwd,stat,subprocess,sys
from pathlib import Path
root,failed,corr,bundle,artifacts,version,fingerprint,scanner,header,guard=sys.argv[1:]
def emit(state,reason=None):
 print(json.dumps({'state':state,'correlationId':corr,**({'reason':reason} if reason else {})},separators=(',',':')))
def private(path):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  info=os.fstat(fd)
  if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o600 or not 0<info.st_size<=1048576:raise ValueError('private-file')
  return json.loads(os.read(fd,info.st_size+1))
 finally:os.close(fd)
def verified_quit(home,proc=Path('/proc')):
 root=Path(home)/'.vpn-control-agent-owner-quit'
 job=root/'bf57271c-ca8f-4715-99c6-8581180e94c1'
 for directory in (root,job):
  info=directory.lstat()
  if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError('owner-quit-job')
 intent=private(job/'intent.json');receipt=private(job/'receipt.json')
 expected={'correlationId':'bf57271c-ca8f-4715-99c6-8581180e94c1',
  'pid':84498,'startTicks':42693938,'controllerId':'4da9288d-dd73-4312-92d8-c7d96f046040'}
 if any(intent.get(k)!=v or receipt.get(k)!=v for k,v in expected.items()):raise ValueError('owner-quit-identity')
 if intent.get('approval')!='fedora-acceptance-disconnected-replacement-owner-quit' or receipt.get('publicAccepted') is not True or receipt.get('exitCode')!=0:raise ValueError('owner-quit-result')
 try:
  fields=(proc/str(expected['pid'])/'stat').read_text(encoding='ascii').rsplit(')',1)[1].split()
  if int(fields[19])==expected['startTicks']:raise ValueError('owner-still-live')
 except FileNotFoundError:
  if (proc/str(expected['pid'])).exists():raise ValueError('owner-unreadable')
def durable(path,value):
 data=(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as out:out.write(data);out.flush();os.fsync(out.fileno())
 fd=os.open(os.path.dirname(path),os.O_RDONLY|os.O_DIRECTORY)
 try:os.fsync(fd)
 finally:os.close(fd)
def remove(fd,depth=0):
 if depth>24:raise ValueError('depth')
 entries=list(os.scandir(fd))
 if len(entries)>100000:raise ValueError('entry-count')
 for item in entries:
  info=os.stat(item.name,dir_fd=fd,follow_symlinks=False)
  if info.st_uid!=os.geteuid() or stat.S_ISLNK(info.st_mode):raise ValueError('entry-unsafe')
  if stat.S_ISDIR(info.st_mode):
   child=os.open(item.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
   try:remove(child,depth+1)
   finally:os.close(child)
   os.rmdir(item.name,dir_fd=fd)
  elif stat.S_ISREG(info.st_mode):os.unlink(item.name,dir_fd=fd)
  else:raise ValueError('entry-unsafe')
try:
 if failed!='944447ff-7ee3-42df-8ca8-f02dac670459' or version!='2.2.0' or header!='3ef23bc543b6302432f514edc94ba04d75a8dc3d':raise ValueError('intent')
 if len(scanner)>10924 or len(guard)>32768:raise ValueError('program-size')
 scanner_code=base64.b64decode(scanner,validate=True)
 guard_code=base64.b64decode(guard,validate=True)
 if len(scanner_code)>8192 or len(guard_code)>24576:raise ValueError('program-size')
 job=Path(root)/'native-scenario-jobs'/'fedora2328'/'linux-rpm-public-install-recovery'/failed
 ji=job.lstat()
 if not stat.S_ISDIR(ji.st_mode) or ji.st_uid!=os.geteuid() or stat.S_IMODE(ji.st_mode)!=0o700:raise ValueError('public-job')
 intent=private(job/'intent.json');receipt=private(job/'receipt.json')
 expected={'correlationId':failed,'host':'fedora2328','environment':'fedora2328',
  'scenarioId':'linux-rpm-public-install-recovery','bundleHash':bundle,'artifactIds':json.loads(artifacts)}
 if any(intent.get(k)!=v or receipt.get(k)!=v for k,v in expected.items()) or receipt.get('exitCode')!=1 or receipt.get('failurePhase') is not None:raise ValueError('public-identity')
 summary=receipt.get('scenarioEvidence')
 if not isinstance(summary,dict) or summary.get('result')!='failed' or summary.get('correlationId')!=failed or summary.get('cleanup',{}).get('workspaceRemoved') is not False:raise ValueError('public-result')
 # The public receipt's ownerStopped is the pre-update owner. This separate
 # exact quit receipt proves the replacement owner has exited too.
 verified_quit(pwd.getpwnam('vpnfixture').pw_dir)
 if not isinstance(summary,dict) or summary.get('rpmVerifyClean') is not True or summary.get('credentialRestored') is not True or summary.get('cleanup',{}).get('ownerStopped') is not True or summary.get('cleanup',{}).get('protectedPreserved') is not True:raise ValueError('recovery-proof')
 pointer_fd=os.open(job/'harness.stdout',os.O_RDONLY|os.O_NOFOLLOW)
 try:
  pi=os.fstat(pointer_fd)
  if not stat.S_ISREG(pi.st_mode) or pi.st_uid!=os.geteuid() or stat.S_IMODE(pi.st_mode)!=0o600 or not 0<pi.st_size<=4194304:raise ValueError('pointer')
  first=b''
  while not first.endswith(b'\n') and len(first)<=4096:
   part=os.read(pointer_fd,1)
   if not part:break
   first+=part
 finally:os.close(pointer_fd)
 if len(first)>4096 or not first.endswith(b'\n'):raise ValueError('pointer')
 pointer=json.loads(first);evidence=pointer.get('evidence');workspace=pointer.get('workspace')
 prefix='/tmp/vpn-public-install-evidence-'
 if not isinstance(evidence,str) or not evidence.startswith(prefix) or not evidence[len(prefix):] or '/' in evidence[len(prefix):] or workspace!=evidence+'/workspace':raise ValueError('pointer')
 evidence_info=os.stat(evidence,follow_symlinks=False)
 if not stat.S_ISDIR(evidence_info.st_mode) or evidence_info.st_uid!=os.geteuid() or stat.S_IMODE(evidence_info.st_mode)!=0o700:raise ValueError('evidence')
 result=private(Path(evidence)/'install-result.json')
 cleanup=result.get('syntheticWorkspaceCleanup')
 if result.get('sourceFingerprint')!=fingerprint or result.get('targetVersion')!=version or result.get('productionTrustedInstallSucceeded') is not True or not isinstance(cleanup,dict) or cleanup.get('requested') is not True or cleanup.get('workspaceRemoved') is not False:raise ValueError('result-proof')
 evidence_fd=os.open(evidence,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 workspace_fd=os.open('workspace',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=evidence_fd)
 try:
  info=os.fstat(workspace_fd)
  if info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError('workspace')
  journal=Path(root)/'workspace-recovery-jobs';journal.mkdir(mode=0o700,exist_ok=True)
  ji=journal.lstat()
  if not stat.S_ISDIR(ji.st_mode) or ji.st_uid!=os.geteuid() or stat.S_IMODE(ji.st_mode)!=0o700:raise ValueError('journal')
  record=journal/corr
  record.mkdir(mode=0o700)
  durable(record/'intent.json',{'correlationId':corr,'failedCorrelationId':failed,
   'evidence':evidence,'workspaceDev':info.st_dev,'workspaceIno':info.st_ino})
  fields=Path('/proc/self/stat').read_text(encoding='ascii').rsplit(')',1)[1].split()
  identity=[workspace,str(os.geteuid()),str(os.getpid()),str(int(fields[19])),str(workspace_fd),str(info.st_dev),str(info.st_ino)]
  ready=subprocess.run(['sudo','-n','--','python3','-I','-B','-c',guard_code.decode(),scanner_code.decode(),*identity,'vpn-control-2.2.0-1.x86_64',header],capture_output=True,timeout=45)
  if ready.returncode or len(ready.stdout)>4096 or json.loads(ready.stdout).get('state')!='ready':
   durable(record/'receipt.json',{'state':'blocked','correlationId':corr,'reason':'final-guard-unavailable'});emit('blocked','final-guard-unavailable');raise SystemExit(0)
  current=os.stat('workspace',dir_fd=evidence_fd,follow_symlinks=False)
  if (current.st_dev,current.st_ino)!=(info.st_dev,info.st_ino):raise ValueError('workspace-changed')
  remove(workspace_fd)
  os.rmdir('workspace',dir_fd=evidence_fd)
  durable(record/'receipt.json',{'state':'terminal','result':'passed','correlationId':corr,
   'workspaceDev':info.st_dev,'workspaceIno':info.st_ino,'workspaceRemoved':True})
 finally:os.close(workspace_fd);os.close(evidence_fd)
 emit('terminal')
except FileExistsError:emit('unknown','correlation-exists')
except SystemExit:raise
except Exception:emit('unknown','cleanup-uncertain')
'''

_CLEANUP_STATUS = r'''import json,os,stat,sys
from pathlib import Path
root,failed,corr=sys.argv[1:]
def out(state,reason=None):
 print(json.dumps({'state':state,'correlationId':corr,**({'reason':reason} if reason else {})},separators=(',',':')))
try:
 job=Path(root)/'workspace-recovery-jobs'/corr
 info=job.lstat()
 if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError()
 def read(name):
  fd=os.open(job/name,os.O_RDONLY|os.O_NOFOLLOW)
  try:
   data=os.fstat(fd)
   if not stat.S_ISREG(data.st_mode) or data.st_uid!=os.geteuid() or stat.S_IMODE(data.st_mode)!=0o600 or not 0<data.st_size<=4096:raise ValueError()
   return json.loads(os.read(fd,data.st_size+1))
  finally:os.close(fd)
 intent=read('intent.json');receipt=read('receipt.json')
 if intent.get('correlationId')!=corr or intent.get('failedCorrelationId')!=failed or receipt.get('correlationId')!=corr:raise ValueError()
 if type(intent.get('workspaceDev')) is not int or type(intent.get('workspaceIno')) is not int or intent['workspaceDev']<=0 or intent['workspaceIno']<=0:raise ValueError()
 if receipt.get('state')=='blocked' and receipt.get('reason')=='final-guard-unavailable':out('blocked','final-guard-unavailable')
 elif receipt.get('state')=='terminal' and receipt.get('result')=='passed' and receipt.get('workspaceRemoved') is True:
  if receipt.get('workspaceDev')!=intent['workspaceDev'] or receipt.get('workspaceIno')!=intent['workspaceIno']:raise ValueError()
  original=Path(root)/'native-scenario-jobs'/'fedora2328'/'linux-rpm-public-install-recovery'/failed
  pointer_fd=os.open(original/'harness.stdout',os.O_RDONLY|os.O_NOFOLLOW)
  try:
   pi=os.fstat(pointer_fd)
   if not stat.S_ISREG(pi.st_mode) or pi.st_uid!=os.geteuid() or stat.S_IMODE(pi.st_mode)!=0o600 or not 0<pi.st_size<=4194304:raise ValueError()
   first=b''
   while not first.endswith(b'\n') and len(first)<=4096:
    part=os.read(pointer_fd,1)
    if not part:break
    first+=part
  finally:os.close(pointer_fd)
  pointer=json.loads(first);evidence=pointer.get('evidence');workspace=pointer.get('workspace')
  prefix='/tmp/vpn-public-install-evidence-'
  if not isinstance(evidence,str) or not evidence.startswith(prefix) or not evidence[len(prefix):] or '/' in evidence[len(prefix):] or workspace!=evidence+'/workspace' or intent.get('evidence')!=evidence:raise ValueError()
  ei=os.stat(evidence,follow_symlinks=False)
  if not stat.S_ISDIR(ei.st_mode) or ei.st_uid!=os.geteuid() or stat.S_IMODE(ei.st_mode)!=0o700:raise ValueError()
  if os.path.lexists(workspace):raise ValueError()
  out('terminal')
 else:out('unknown','receipt-invalid')
except FileNotFoundError:out('unknown','receipt-unavailable')
except Exception:out('unknown','cleanup-status-unavailable')
'''


def _cleanup_request(inputs: Mapping[str, Any]) -> tuple[str, str]:
    if (not isinstance(inputs, Mapping) or set(inputs) != {"correlationId", "cleanupCorrelationId"}
            or inputs.get("correlationId") != _FAILED_PUBLIC
            or not isinstance(inputs.get("cleanupCorrelationId"), str)
            or not _CORRELATION.fullmatch(inputs["cleanupCorrelationId"])):
        raise ValueError("Exact failed Fedora correlation and fresh cleanup correlation required")
    cleanup = inputs["cleanupCorrelationId"]
    if str(uuid.UUID(cleanup)) != cleanup or cleanup == _FAILED_PUBLIC:
        raise ValueError("Invalid cleanup correlation")
    return _FAILED_PUBLIC, cleanup


def _cleanup_journal(root: Path, cleanup: str, create: bool = False) -> Path:
    directory = root / ".rag_index" / "linux-rpm-workspace-cleanup"
    if create:
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    if directory.exists():
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError("Workspace cleanup journal unsafe")
    return directory / (cleanup + ".json")


def _save_cleanup_journal(path: Path, value: Mapping[str, Any]) -> None:
    data = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _read_cleanup_journal(path: Path) -> dict[str, Any]:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or not 0 < info.st_size <= 4096:
            raise ValueError("Workspace cleanup journal unsafe")
        value = json.loads(stream.read())
    failed, cleanup = _cleanup_request(value)
    if path.name != cleanup + ".json":
        raise ValueError("Workspace cleanup correlation mismatch")
    return {"correlationId": failed, "cleanupCorrelationId": cleanup}


def cleanup_start(root: Path | str, inputs: Mapping[str, Any]) -> dict[str, Any]:
    """One-shot exact failed workspace deletion after fresh read-only proofs."""
    failed, cleanup = _cleanup_request(inputs)
    root = Path(root).resolve(strict=True)
    journal = _cleanup_journal(root, cleanup)
    if journal.exists() or journal.is_symlink():
        _read_cleanup_journal(journal)
        return {"state": "unknown", "correlationId": cleanup, "reason": "existing-intent", "replayAllowed": False}
    from . import linux_owner_public_quit as quit_owner
    from . import linux_rpm_base_prepare as base
    owner = quit_owner.status(root, {"correlationId": _OWNER_QUIT})
    if owner.get("state") != "terminal" or owner.get("result") != "passed" or owner.get("ownerGenerationGone") is not True:
        return {"state": "blocked", "correlationId": cleanup, "reason": "owner-quit-unavailable", "replayAllowed": False}
    observed = status(root, {"correlationId": failed})
    if observed.get("state") != "observed" or observed.get("scannerState") != "absent":
        return {"state": "blocked", "correlationId": cleanup, "reason": "workspace-reference-unknown", "replayAllowed": False}
    package = base.preflight(root, {"host": "fedora2328", "environment": "fedora2328",
                                    "expectedCurrentNevra": _TARGET_NEVRA, "includeCurrentHeader": True})
    if package.get("state") != "ready" or package.get("currentNevra") != _TARGET_NEVRA or package.get("currentHeaderSha1") != _TARGET_HEADER:
        return {"state": "blocked", "correlationId": cleanup, "reason": "target-package-or-runtime-unavailable", "replayAllowed": False}
    driver = rpm.RpmPublicInstallSshDriver(root, timeout_seconds=60)
    stored = driver._read_journal(failed)
    from . import linux_rpm_fixture_server_lifecycle as server
    server_record = server._journal(root, failed)
    config = ssh_transport.load_config(root)
    host = config.hosts.get("fedora2328")
    if not isinstance(stored, Mapping) or not isinstance(server_record, Mapping) or host is None or host.user != "vpnfixture" or host.fixture_transfer_root is None:
        return {"state": "unknown", "correlationId": cleanup, "reason": "source-journals-unavailable", "replayAllowed": False}
    journal = _cleanup_journal(root, cleanup, create=True)
    try:
        _save_cleanup_journal(journal, {"correlationId": failed, "cleanupCorrelationId": cleanup})
    except FileExistsError:
        return {"state": "unknown", "correlationId": cleanup, "reason": "existing-intent", "replayAllowed": False}
    guard = base64.b64encode(_PRIVILEGED_CLEANUP_GUARD.encode()).decode("ascii")
    args = (str(host.fixture_transfer_root), failed, cleanup, stored["bundleHash"],
            json.dumps(stored["artifactIds"], sort_keys=True, separators=(",", ":")),
            server_record["expectedTargetVersion"], server_record["sourceFingerprint"],
            _encoded_scanner(root), _TARGET_HEADER, guard)
    try:
        result = driver._remote(config, "fedora2328", _CLEANUP, args, diagnostic=True)
    except Exception:
        result = None
    if isinstance(result, Mapping) and result.get("state") == "terminal" and result.get("correlationId") == cleanup:
        return cleanup_status(root, {"cleanupCorrelationId": cleanup})
    if isinstance(result, Mapping) and result.get("state") == "blocked" and result.get("correlationId") == cleanup:
        return {"state": "blocked", "correlationId": cleanup, "reason": "final-guard-unavailable", "replayAllowed": False}
    return {"state": "unknown", "correlationId": cleanup, "reason": "cleanup-response-uncertain", "replayAllowed": False}


def cleanup_status(root: Path | str, inputs: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(inputs, Mapping) or set(inputs) != {"cleanupCorrelationId"} or not isinstance(inputs["cleanupCorrelationId"], str) or not _CORRELATION.fullmatch(inputs["cleanupCorrelationId"]):
        raise ValueError("Exact cleanup correlation required")
    root = Path(root).resolve(strict=True)
    cleanup = inputs["cleanupCorrelationId"]
    journal = _cleanup_journal(root, cleanup)
    if not journal.exists():
        return {"state": "unknown", "correlationId": cleanup, "reason": "missing-intent", "replayAllowed": False}
    _read_cleanup_journal(journal)
    config = ssh_transport.load_config(root)
    host = config.hosts.get("fedora2328")
    if host is None or host.user != "vpnfixture" or host.fixture_transfer_root is None:
        return {"state": "unknown", "correlationId": cleanup, "reason": "guest-unavailable", "replayAllowed": False}
    try:
        observed = rpm.RpmPublicInstallSshDriver(root)._remote(config, "fedora2328", _CLEANUP_STATUS,
            (str(host.fixture_transfer_root), _FAILED_PUBLIC, cleanup), diagnostic=True)
    except Exception:
        observed = None
    if isinstance(observed, Mapping) and observed.get("correlationId") == cleanup:
        if observed.get("state") == "terminal":
            return {"state": "terminal", "result": "passed", "correlationId": cleanup,
                    "workspaceRemoved": True, "replayAllowed": False}
        if observed.get("state") == "blocked" and observed.get("reason") == "final-guard-unavailable":
            return {"state": "blocked", "correlationId": cleanup, "reason": "final-guard-unavailable", "replayAllowed": False}
    return {"state": "unknown", "correlationId": cleanup, "reason": "guest-status-unavailable", "replayAllowed": False}
