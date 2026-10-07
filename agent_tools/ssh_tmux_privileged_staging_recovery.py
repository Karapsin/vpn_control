"""Root-complete fixed holder reads after a measured nondumpable cwd denial.

Only original02 failed staging is reconciled. No stage replay, remote deletion,
process signal, package operation, root shell or arbitrary command interface.
Original841/8c programs and their failed observations remain immutable.
"""
from __future__ import annotations
import fcntl
import hashlib
import json
import os
from pathlib import Path
import resource
import stat
import subprocess
import tempfile
from uuid import UUID,uuid4
from . import ssh_tmux_source_staging_recovery as recovery
from . import ssh_tmux_staging_process_diagnostic as diagnostic
from . import ssh_tmux_session_ssh as old
from . import ssh_tmux_session as session
from . import windows_vm_virt_firmware_install as credentials
from . import ssh_transport

need=old.need
AdapterError=old.AdapterError
MAX_RESPONSE=old.MAX_RESPONSE
DIAGNOSTIC_ID='6a3f296d-c9ff-405c-a87e-e36e6fee2903'
DIAGNOSTIC_SHA='8c09949b930a10269de20f12166ce0d6db64adfd6ad72f81e6106d53d9ac9a56'
DIAGNOSTIC_PINS={'intent.json': {'generation': [16777234, 111572245, 33152, 503, 20, 3719, 1791040976900603831, 1791040976900603831, 1], 'sha256': '2e4929c22baed3ca8a4d7546894163c692ac9ebd4b6425cda3d9b8adc2e96c6b'}, 'result.json': {'generation': [16777234, 111572251, 33152, 503, 20, 359, 1791040977144062699, 1791040977144062699, 1], 'sha256': '24e8d1baf865ea9925ab65cbeb1f6ab72d3a2697adec34c99003c75adc4fe573'}}


ROOT_PROGRAM=recovery.PROOF
ROOT_PROGRAM=diagnostic.replace_exact(ROOT_PROGRAM,"payload=json.loads(sys.stdin.buffer.read(16385))", "payload={'request':"+repr(old.purpose(recovery.OLD_REQUEST))+"}\nif os.geteuid()!=0:raise SystemExit(30)")
ROOT_PROGRAM=ROOT_PROGRAM.replace('os.getuid()','1000')
old_scan=ROOT_PROGRAM[ROOT_PROGRAM.index('def scan():'):ROOT_PROGRAM.index('def census():')]
new_scan=r'''# Kthread is the documented /proc/PID/status field; no unreadable row is skipped.
# https://www.kernel.org/doc/html/v6.9/filesystems/proc.html
def scan():
 deadline=time.monotonic()+5;entries=list(pathlib.Path('/proc').iterdir())
 if len(entries)>8192:raise SystemExit(35)
 def bytes_at(p,name,maximum):
  fd=os.open(p/name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
  try:
   b=os.read(fd,maximum+1)
   if len(b)>maximum:raise SystemExit(36)
   return b
  finally:os.close(fd)
 def identity(raw):
  try:
   tail=raw.rsplit(b')',1)[1].split()
   return tail[0],int(tail[19])
  except (IndexError,ValueError):raise SystemExit(36)
 def kernel(raw):
  fields=[x.split(b':',1)[1].strip() for x in raw.splitlines() if x.startswith(b'Kthread:')]
  if len(fields)!=1 or fields[0] not in (b'0',b'1'):raise SystemExit(36)
  return fields[0]==b'1'
 for p in entries:
  if not p.name.isdigit() or int(p.name)==os.getpid():continue
  # All UID domains are read; permissions/missing rows/PID reuse remain unknown.
  fd=os.open(p,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
  try:
   before_dir=gen(os.fstat(fd))[:5]
   before=bytes_at(p,'stat',8192);state,start=identity(before)
   before_status=bytes_at(p,'status',8192);is_kernel=kernel(before_status)
   command=bytes_at(p,'cmdline',65536)
   if state==b'Z' or is_kernel:
    if command:raise SystemExit(36)
    cwd=None
   else:cwd=os.readlink(p/'cwd')
   after_status=bytes_at(p,'status',8192);after=bytes_at(p,'stat',8192)
   if bytes_at(p,'cmdline',65536)!=command:raise SystemExit(36)
   if cwd is not None and os.readlink(p/'cwd')!=cwd:raise SystemExit(36)
   if identity(after)[1]!=start or (identity(after)[0]==b'Z')!=(state==b'Z') or kernel(after_status)!=is_kernel or gen(os.fstat(fd))[:5]!=before_dir or gen(p.lstat())[:5]!=before_dir:raise SystemExit(36)
   fixed=os.fsencode(job);tokens=command.split(b'\0')
   if cwd is not None and (cwd==str(job) or cwd.startswith(str(job)+'/')) or any(t==fixed or t.startswith(fixed+b'/') for t in tokens):raise SystemExit(37)
   if time.monotonic()>deadline:raise SystemExit(38)
  finally:os.close(fd)
'''
ROOT_PROGRAM=diagnostic.replace_exact(ROOT_PROGRAM,old_scan,new_scan)
ROOT_PROGRAM=diagnostic.replace_exact(ROOT_PROGRAM,"'replayAllowed':False},sort_keys=True", "'replayAllowed':False,'readAuthority':{'effectiveUid':0,'filesystemUid':1000,'censusScope':'all-uids'}},sort_keys=True")

# Protected password is stdin only and suppressed before any exception returns.
# Sudo receives a fixed reviewed root program; no JSON/source/argv is accepted.
WRAPPER=r'''import json,subprocess,sys
secret=sys.stdin.buffer.read(513)
if not 0<len(secret)<=512 or b'\0' in secret or b'\n' in secret.rstrip(b'\n'):raise SystemExit(31)
try:
 r=subprocess.run(['/usr/bin/sudo','-S','-p','','--','/usr/bin/python3','-I','-B','-c','exec('+repr(ROOT_SOURCE)+')'],input=secret.rstrip(b'\n')+b'\n',stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=35,check=False,env={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C'})
except (OSError,subprocess.TimeoutExpired):raise SystemExit(32)
if r.returncode!=0 or not 0<len(r.stdout)<=16384:raise SystemExit(33)
value=json.loads(r.stdout)
print(json.dumps(value,sort_keys=True,separators=(',',':')))
'''.replace('ROOT_SOURCE',repr(ROOT_PROGRAM))


def command(program):
    need(program==WRAPPER,'unsupported_privileged_source')
    return ['/usr/bin/python3','-I','-B','-c','exec('+repr(program)+')']


def local_authority(root):
    driver=old.TmuxArchDriver(root);job,original=recovery._local(driver)
    need(old.blob(Path(diagnostic.__file__).resolve())[1]['sha256']==DIAGNOSTIC_SHA,'diagnostic_source_changed')
    diag=Path(root)/'.rag_index'/('tmux-staging-scan-'+DIAGNOSTIC_ID);identity=session.private_dir(diag)
    records={n:session.read(diag/n,131072)[1] for n in ('intent.json','result.json')}
    need(records==DIAGNOSTIC_PINS,'diagnostic_generation_changed')
    value=json.loads(session.read(diag/'result.json')[0]);diagnostic.validate_result(value,DIAGNOSTIC_ID)
    expected={'pid':992,'phase':'cwd','exitCode':36,'errno':13,'directoryState':'present','directoryKind':'directory','uid':1000,'directoryIdentity':[24,18951,16749,1000,1000]}
    need(value['rejection']==expected and session.private_dir(diag)==identity,'measured_failure_changed')
    return job,{'original':original,'diagnosticPins':records,'diagnosticIdentity':identity,
                'sourcePin':old.blob(Path(__file__).resolve())[1],'diagnosticSource':old.blob(Path(diagnostic.__file__).resolve())[1]}


def credential(root):
    path=credentials._credential_path(root)
    raw=credentials._read_credential(root)
    checked,pin=session.read(path,512)
    need(raw==checked and 0<len(raw)<=512 and b'\0' not in raw and b'\n' not in raw.rstrip(b'\n'),'unsafe_protected_credential')
    parent=path.parent.lstat();need(stat.S_ISDIR(parent.st_mode) and parent.st_uid==os.getuid() and not parent.st_mode&0o022,'unsafe_protected_credential')
    return raw,{'file':pin,'parentIdentity':session.generation(parent)[:5],'credentialPolicySource':old.blob(Path(credentials.__file__).resolve())[1]}


class PrivilegedDriver(old.TmuxArchDriver):
    def __init__(self,root,secret):
        super().__init__(root);self._secret=secret
    def _query(self, program, payload, *, job=None, guard=None):
        """Bounded private subprocess capsule; no raw output in exceptions."""
        config, original_transport = self._transport()
        argv = ssh_transport.build_ssh_argv(config, "archlinux", 10, command=command(program))
        if guard: guard()
        # Diagnostic capsules are local only, with a fresh identity per query.
        base = job if job is not None else self.root / ".rag_index"
        if job is None and not os.path.lexists(base): base.mkdir(mode=0o700)
        session.private_dir(base)
        capsule = base / ("tmux-query-" + str(uuid4())); capsule.mkdir(mode=0o700)
        stdout = capsule / "stdout"; stderr = capsule / "stderr"
        need(payload=={} and type(payload)is dict,'invalid_privileged_request')
        input_bytes = self._secret
        need(len(input_bytes) <= 131072, "payload_oversized")
        def limits(): resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_RESPONSE, MAX_RESPONSE))
        connection = ssh_transport.connection_host(config, "archlinux")
        process = None; timed_out = False
        try:
            with tempfile.TemporaryDirectory(prefix="vpn-tmux-askpass-") as askpass, \
                 stdout.open("xb") as out, stderr.open("xb") as err:
                os.chmod(stdout, 0o600); os.chmod(stderr, 0o600)
                env = None
                if connection.password:
                    unused, env = ssh_transport._askpass_environment(connection.password, Path(askpass))
                need(self._transport()[1] == original_transport, "transport_changed")
                if guard: guard()
                process = subprocess.Popen(argv, cwd=self.root, stdin=subprocess.PIPE, stdout=out, stderr=err,
                                           env=env, preexec_fn=limits)
                try:
                    process.communicate(input=input_bytes, timeout=95)
                except subprocess.TimeoutExpired:
                    timed_out = True
                    process.kill()
                    try: process.wait(timeout=2)
                    except subprocess.TimeoutExpired: pass
                    raise AdapterError("transport_timeout") from None
                finally:
                    out.flush(); os.fsync(out.fileno()); err.flush(); os.fsync(err.fileno())
            need(self._transport()[1] == original_transport, "transport_changed")
            if guard: guard()
            raw, unused = session.read(stdout, MAX_RESPONSE)
            need(process.returncode == 0, "transport_unknown")
            value = json.loads(raw)
            need(type(value) is dict, "invalid_remote_reply")
            return value
        except (OSError, ValueError, subprocess.SubprocessError):
            raise AdapterError("transport_unknown") from None
        finally:
            # Retain original bounded streams/exit before success or loss returns. This capsule cannot admit, release, or retry a job.
            try:
                out_pin = session.read(stdout, MAX_RESPONSE)[1]
                err_pin = session.read(stderr, MAX_RESPONSE)[1]
                session.write_once(capsule / "receipt.json", session.canonical({
                    "schemaVersion": 1, "requestSha256": hashlib.sha256(WRAPPER.encode()).hexdigest(),
                    "argvSha256": hashlib.sha256(session.canonical(argv)).hexdigest(),
                    "exitCode": None if process is None else process.returncode,
                    "timedOut": timed_out, "stdoutPin": out_pin, "stderrPin": err_pin,
                    "replayAllowed": False}))
            except (OSError, ValueError):
                pass  # Raw private streams survive; no missing capsule promotes authority.


def validate(value):
    need(type(value)is dict and set(value)=={'state','request','proof','replayAllowed','readAuthority'} and
         value['readAuthority']=={'effectiveUid':0,'filesystemUid':1000,'censusScope':'all-uids'} and
         type(value['readAuthority']['effectiveUid'])is int and type(value['readAuthority']['filesystemUid'])is int,
         'invalid_privileged_proof')
    recovery._valid_remote({k:v for k,v in value.items() if k!='readAuthority'})
    return value


def observe(root,correlation_id):
    need(type(correlation_id)is str and str(UUID(correlation_id))==correlation_id and correlation_id not in (recovery.OLD_CORRELATION,DIAGNOSTIC_ID),'invalid_observation_identity')
    root=Path(root).resolve(strict=True);job,before=local_authority(root)
    secret,credential_pin=credential(root)
    index=root/'.rag_index';session.private_dir(index)
    proof_job=index/('tmux-privileged-staging-'+correlation_id);proof_job.mkdir(mode=0o700)
    identity=session.private_dir(proof_job)
    intent_pin=session.write_once(proof_job/'intent.json',session.canonical({'correlationId':correlation_id,'local':before,
                 'credentialPin':credential_pin,'programSha256':hashlib.sha256(ROOT_PROGRAM.encode()).hexdigest(),'replayAllowed':False}))
    def guard():
        need(local_authority(root)[1]==before and credential(root)[1]==credential_pin and session.private_dir(proof_job)==identity and
             session.read(proof_job/'intent.json',131072)[1]==intent_pin,'privileged_observation_authority_changed')
    guard()
    value=PrivilegedDriver(root,secret)._query(WRAPPER,{},job=proof_job,guard=guard)
    validate(value);guard()
    result_pin=session.write_once(proof_job/'proof.json',session.canonical({'correlationId':correlation_id,'local':before,'intentPin':intent_pin,'remote':value,
                'rootProgramSha256':hashlib.sha256(ROOT_PROGRAM.encode()).hexdigest(),'oldOutcome':'unknown','replayAllowed':False}))
    return {'state':'observed','correlationId':correlation_id,'proofPin':result_pin,'oldCorrelationId':recovery.OLD_CORRELATION,'oldOutcome':'unknown','replayAllowed':False}


def archive(root,correlation_id,proof_pin):
    """Explicit local claim archive after repeating the complete root read.

    Remote history remains untouched. An interrupted/lost archive is consumed,
    never repeated; the old coordinator outcome remains unknown.
    """
    need(type(correlation_id)is str and str(UUID(correlation_id))==correlation_id and session._valid_pin(proof_pin),'invalid_proof_identity')
    root=Path(root).resolve(strict=True);job,before=local_authority(root)
    proof_job=root/'.rag_index'/('tmux-privileged-staging-'+correlation_id);identity=session.private_dir(proof_job)
    raw,pin=session.read(proof_job/'proof.json',131072);need(pin==proof_pin,'privileged_proof_changed');saved=json.loads(raw)
    need(set(saved)=={'correlationId','local','intentPin','remote','rootProgramSha256','oldOutcome','replayAllowed'} and saved['correlationId']==correlation_id and
         saved['local']==before and saved['rootProgramSha256']==hashlib.sha256(ROOT_PROGRAM.encode()).hexdigest() and saved['oldOutcome']=='unknown' and
         saved['replayAllowed'] is False,'privileged_proof_changed')
    validate(saved['remote'])
    intent_raw,intent_pin=session.read(proof_job/'intent.json',131072);need(intent_pin==saved['intentPin'],'privileged_intent_changed')
    intent=json.loads(intent_raw);secret,credential_pin=credential(root)
    need(intent=={'correlationId':correlation_id,'local':before,'credentialPin':credential_pin,'programSha256':hashlib.sha256(ROOT_PROGRAM.encode()).hexdigest(),'replayAllowed':False},'privileged_intent_changed')
    def guard():
        need(local_authority(root)[1]==before and credential(root)[1]==credential_pin and session.private_dir(proof_job)==identity and
             session.read(proof_job/'proof.json',131072)[1]==proof_pin and session.read(proof_job/'intent.json',131072)[1]==intent_pin,'privileged_archive_authority_changed')
    guard()
    current=PrivilegedDriver(root,secret)._query(WRAPPER,{},job=proof_job,guard=guard)
    need(validate(current)==saved['remote'],'privileged_process_or_stage_drift')
    directory=job.parent;lock=directory/'tmux-privileged-stage-recovery.lock'
    fd=os.open(lock,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_NONBLOCK,0o600)
    try:
        info=os.fstat(fd);need(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode)==0o600 and info.st_uid==os.getuid() and info.st_nlink==1,'unsafe_archive_lock')
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);lock_gen=session.generation(info)
        def dispatch_guard():
            guard();need(session.generation(os.fstat(fd))==lock_gen==session.generation(lock.lstat()),'archive_lock_changed')
        dispatch_guard()
        fence_pin=session.write_once(proof_job/'archive-fence.json',session.canonical({'correlationId':correlation_id,'proofPin':proof_pin,'local':before,'replayAllowed':False}))
        dispatch_guard()
        need(session.read(proof_job/'archive-fence.json',131072)[1]==fence_pin,'archive_fence_changed')
        claim=directory/'archlinux.claim';target=directory/(recovery.OLD_CORRELATION+'.privileged-staging-only.claim')
        old.rename_complete(claim,target)
        raw,archive_pin=session.read(target)
        need(json.loads(raw)=={'correlationId':recovery.OLD_CORRELATION,'host':'archlinux'} and archive_pin['sha256']==before['original']['original']['coordinator']['records']['claim']['sha256'],'archived_claim_changed')
        session.write_once(proof_job/'terminal.json',session.canonical({'correlationId':correlation_id,'proofPin':proof_pin,'archivePin':archive_pin,'fencePin':fence_pin,'oldOutcome':'unknown','replayAllowed':False}))
        return {'state':'archived','correlationId':correlation_id,'oldCorrelationId':recovery.OLD_CORRELATION,'oldOutcome':'unknown','replayAllowed':False}
    finally:os.close(fd)
