"""Consumed clone-failure evidence and optional exact-SHA shallow staging.

No remote cleanup, signals, package build or retry of the old correlation.
Authority is the existing single authorized operator namespace, not hostile
same-UID atomic compare-and-swap. Frozen adapter/coordinator remain unchanged.
"""
from __future__ import annotations
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import resource
import stat
import subprocess
import tempfile
from uuid import uuid4
from . import ssh_tmux_session_ssh as old
from . import ssh_tmux_session as session
from . import linux_package_fixture_build as build
from . import ssh_transport

AdapterError = old.AdapterError
need = old.need
MAX_RESPONSE = old.MAX_RESPONSE
FROZEN_ADAPTER_SHA = "bec936bd1a34679939a817777443255fbb7c6d5fc2adafc3193e25ce9ed07c44"
OLD_CORRELATION = "02f4a070-0369-4ece-ba89-7979feec7d66"
OLD_REQUEST = {"sourceSha":"d32f719a08db57e5d40ce2bf77e0d7c5b42de557", "baseVersion":"2.1.19", "targetVersion":"2.2.2", "correlationId":OLD_CORRELATION}
STDERR_SHA = "a52fc572998b56b744d23033cdedb42c134ac4b0d12a7490aedb5f085ef4e604"

ORIGINAL_ADAPTER_INTENT_PIN = {'generation': [16777234, 111563138, 33152, 503, 20, 2101, 1791037204035842154, 1791037204035842154, 1], 'sha256': '13a4d8acb603d19fda5ff0b490ec026a415cb0aabd2240b76ddc56764d24526c'}
ORIGINAL_CAPTURE_PINS = {'stdout': {'generation': [16777234, 111563141, 33152, 503, 20, 0, 1791037204055654647, 1791037204055723148, 1], 'sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'}, 'stderr': {'generation': [16777234, 111563142, 33152, 503, 20, 4096, 1791037264170235013, 1791037264170235013, 1], 'sha256': 'a52fc572998b56b744d23033cdedb42c134ac4b0d12a7490aedb5f085ef4e604'}, 'receipt.json': {'generation': [16777234, 111563187, 33152, 503, 20, 599, 1791037264220264539, 1791037264220264539, 1], 'sha256': 'c11647e85f28a9e335874dde6fcec4d19a61950f81657d927b07523ac0550875'}}

# Exact reviewed frozen program with only the measured clone operation replaced.
_CLONE = "subprocess.run(['git','clone','--no-checkout','https://github.com/Karapsin/vpn_control.git',str(source)],check=True,stdout=sys.stderr,timeout=60)"
_FETCH = """env=dict(os.environ,GIT_LFS_SKIP_SMUDGE='1',GIT_TERMINAL_PROMPT='0')
subprocess.run(['git','init',str(source)],check=True,stdout=sys.stderr,env=env,timeout=10)
subprocess.run(['git','-C',str(source),'fetch','--depth=1','--no-tags','https://github.com/Karapsin/vpn_control.git',request['sourceSha']],check=True,stdout=sys.stderr,env=env,timeout=60)"""
need(old._STAGE.count(_CLONE)==1, "stage_rewrite_changed")
STAGE_V2 = old._STAGE.replace(_CLONE,_FETCH).replace("check=True,stdout=sys.stderr,timeout=20)","check=True,stdout=sys.stderr,env=env,timeout=20)")

def command(program):
    need(program in (old._AVAILABILITY,old._ACTION,STAGE_V2,PROOF), "unsupported_program")
    return ["python3","-I","-B","-c","exec("+repr(program)+")"]


class ExactFetchDriver(old.TmuxArchDriver):
    def _snapshot(self, request):
        value=super()._snapshot(request)
        value["stagingCompanionSource"]=old.blob(Path(__file__).resolve())[1]
        value["stageProgramSha256"]=hashlib.sha256(STAGE_V2.encode()).hexdigest()
        need(value["adapterSource"]["sha256"]==FROZEN_ADAPTER_SHA,"frozen_adapter_changed")
        return value

    def _query(self, program, payload, *, job=None, guard=None):
        """Bounded private subprocess capsule; no raw output in exceptions."""
        if program == old._STAGE: program = STAGE_V2
        config, original_transport = self._transport()
        argv = ssh_transport.build_ssh_argv(config, "archlinux", 10, command=command(program))
        if guard: guard()
        # Diagnostic capsules are local only, with a fresh identity per query.
        base = job if job is not None else self.root / ".rag_index"
        if job is None and not os.path.lexists(base): base.mkdir(mode=0o700)
        session.private_dir(base)
        capsule = base / ("tmux-query-" + str(uuid4())); capsule.mkdir(mode=0o700)
        stdout = capsule / "stdout"; stderr = capsule / "stderr"
        input_bytes = session.canonical(payload)
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
                    "schemaVersion": 1, "requestSha256": hashlib.sha256(input_bytes).hexdigest(),
                    "argvSha256": hashlib.sha256(session.canonical(argv)).hexdigest(),
                    "exitCode": None if process is None else process.returncode,
                    "timedOut": timed_out, "stdoutPin": out_pin, "stderrPin": err_pin,
                    "replayAllowed": False}))
            except (OSError, ValueError):
                pass  # Raw private streams survive; no missing capsule promotes authority.

# Only fresh current-source jobs select this separately reviewed provider. The
# historical ExactFetchDriver and its original intent/capture pins stay strict.
CURRENT_ADAPTER_SHA = "91c8af7b5e47412f8bf9fbe907e69d163ad174c3dc2200bf10f795cee545cc21"

class CurrentExactFetchDriver(ExactFetchDriver):
    def _snapshot(self, request):
        value=old.TmuxArchDriver._snapshot(self, request)
        value["stagingCompanionSource"]=old.blob(Path(__file__).resolve())[1]
        value["stageProgramSha256"]=hashlib.sha256(STAGE_V2.encode()).hexdigest()
        need(value["adapterSource"]["sha256"]==CURRENT_ADAPTER_SHA,"current_adapter_changed")
        return value

# Read-only, fixed original partial staging only. No subprocess, getter, import
# of staged product code, directory creation, tmux command or cleanup operation.
PROOF = r'''
import hashlib,json,os,pathlib,stat,sys,time
from uuid import UUID
payload=json.loads(sys.stdin.buffer.read(16385))
if set(payload)!={'request'} or payload['request']!=FIXED_REQUEST:raise SystemExit(31)
request=payload['request'];root=pathlib.Path('FIXED_ROOT');job=root/request['correlationId']
def gen(i):return [i.st_dev,i.st_ino,i.st_mode,i.st_uid,i.st_gid,i.st_size,i.st_mtime_ns,i.st_ctime_ns,i.st_nlink]
def private(p):
 i=p.lstat()
 if not stat.S_ISDIR(i.st_mode) or i.st_uid!=os.getuid() or stat.S_IMODE(i.st_mode)!=0o700:raise SystemExit(32)
 return gen(i)[:5]
def read(p):
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  i=os.fstat(fd)
  if not stat.S_ISREG(i.st_mode) or i.st_uid!=os.getuid() or stat.S_IMODE(i.st_mode)!=0o600 or i.st_nlink!=1 or not 0<i.st_size<=16384:raise SystemExit(33)
  b=os.read(fd,16385)
  if len(b)!=i.st_size or gen(i)!=gen(os.fstat(fd)) or gen(i)!=gen(p.lstat()):raise SystemExit(34)
  return b,{'generation':gen(i),'sha256':hashlib.sha256(b).hexdigest()}
 finally:os.close(fd)
def scan():
 deadline=time.monotonic()+5;entries=list(pathlib.Path('/proc').iterdir())
 if len(entries)>8192:raise SystemExit(35)
 for p in entries:
  if not p.name.isdigit() or int(p.name)==os.getpid():continue
  try:
   if p.stat().st_uid!=os.getuid():continue
   with (p/'stat').open('rb') as f:before=f.read(8193)
   if len(before)>8192:raise SystemExit(36)
   if before.rsplit(b')',1)[1].split()[0]==b'Z':continue
   with (p/'cmdline').open('rb') as f:command=f.read(65537)
   cwd=os.readlink(p/'cwd')
   with (p/'stat').open('rb') as f:after=f.read(8193)
  except OSError:raise SystemExit(36)
  if len(command)>65536 or len(before)>8192 or before.rsplit(b')',1)[1].split()[19]!=after.rsplit(b')',1)[1].split()[19]:raise SystemExit(36)
  tokens=command.split(b'\0');fixed=os.fsencode(job)
  if cwd==str(job) or cwd.startswith(str(job)+'/') or any(t==fixed or t.startswith(fixed+b'/') for t in tokens):raise SystemExit(37)
  if time.monotonic()>deadline:raise SystemExit(38)
def census():
 authority={'root':private(root),'job':private(job)}
 fds=[os.open(p,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW) for p in (root,job)]
 try:
  names=sorted(os.listdir(fds[1]))
  if names not in (['stage-intent.json'],['source','stage-intent.json']):raise SystemExit(39)
  raw,pin=read(job/'stage-intent.json')
  if json.loads(raw)!=request:raise SystemExit(40)
  source=None
  if 'source' in names:
   p=job/'source';i=p.lstat()
   if not stat.S_ISDIR(i.st_mode) or i.st_uid!=os.getuid() or i.st_mode&0o022:raise SystemExit(41)
   # No staged tool, checkout, hooks, worker, gate or artifacts may be present.
   children=sorted(x.name for x in p.iterdir())
   if children not in ([],['.git']):raise SystemExit(42)
   source={'generation':gen(i),'children':children}
   if children:
    g=(p/'.git').lstat()
    if not stat.S_ISDIR(g.st_mode) or g.st_uid!=os.getuid() or g.st_mode&0o022:raise SystemExit(43)
    source['gitGeneration']=gen(g)
  scan()
  if sorted(os.listdir(fds[1]))!=names or read(job/'stage-intent.json')[1]!=pin:raise SystemExit(44)
  if source is not None and gen((job/'source').lstat())!=source['generation']:raise SystemExit(44)
  if source and source['children'] and gen((job/'source'/'.git').lstat())!=source['gitGeneration']:raise SystemExit(44)
  for index,p in enumerate((root,job)):
   if gen(os.fstat(fds[index]))[:5]!=authority['root' if index==0 else 'job'] or private(p)!=authority['root' if index==0 else 'job']:raise SystemExit(45)
  return {'authority':authority,'stageIntentPin':pin,'source':source,'noJobProcesses':True,'noBuildEffects':True}
 finally:
  for fd in fds:os.close(fd)
first=census();second=census()
if first!=second:raise SystemExit(46)
print(json.dumps({'state':'staging-only','request':request,'proof':first,'replayAllowed':False},sort_keys=True,separators=(',',':')))
'''.replace('FIXED_REQUEST',repr(old.purpose(OLD_REQUEST))).replace('FIXED_ROOT',old.REMOTE_ROOT)


def _frozen():
    need(old.blob(Path(old.__file__).resolve())[1]['sha256']==FROZEN_ADAPTER_SHA,'frozen_adapter_changed')


def _local(driver):
    _frozen();job,original=driver._saved(OLD_REQUEST)
    need(session.read(job/'tmux-adapter-intent.json',131072)[1]==ORIGINAL_ADAPTER_INTENT_PIN,'original_adapter_intent_changed')
    names=sorted(x.name for x in job.iterdir())
    capsule='tmux-query-596b46a1-344f-48d0-a8eb-6eb112d6a6b9'
    allowed={'tmux-adapter-intent.json',capsule,'stage-recovery-proof.json','stage-recovery-fence.json','stage-recovery-terminal.json'}
    need(set(names)<=allowed and capsule in names,'local_stage_effect_or_foreign_record')
    capture=job/capsule;identity=session.private_dir(capture)
    need(sorted(x.name for x in capture.iterdir())==['receipt.json','stderr','stdout'],'capture_changed')
    values={name:session.read(capture/name,MAX_RESPONSE)[1] for name in ('stdout','stderr','receipt.json')}
    need(values==ORIGINAL_CAPTURE_PINS,'original_capture_generation_changed')
    need(values['stdout']['generation'][5]==0 and values['stderr']['generation'][5]==4096 and
         values['stderr']['sha256']==STDERR_SHA,'original_timeout_capture_changed')
    receipt=json.loads(session.read(capture/'receipt.json')[0])
    need(receipt.get('stdoutPin')==values['stdout'] and receipt.get('stderrPin')==values['stderr'] and
         receipt.get('replayAllowed') is False and type(receipt.get('exitCode')) is int and receipt['exitCode']!=0,
         'original_timeout_receipt_changed')
    payload={'request':old.purpose(OLD_REQUEST),'build':base64.b64encode(driver._tools()['linux_package_fixture_build.py']['raw']).decode(),
             'tool':base64.b64encode(driver._tools()['ssh_tmux_session.py']['raw']).decode()}
    config,_=driver._transport()
    argv=ssh_transport.build_ssh_argv(config,'archlinux',10,command=old.command(old._STAGE))
    need(receipt['requestSha256']==hashlib.sha256(session.canonical(payload)).hexdigest() and
         receipt['argvSha256']==hashlib.sha256(session.canonical(argv)).hexdigest(),'original_query_changed')
    need(session.private_dir(capture)==identity,'capture_changed')
    return job,{'original':original,'intentPin':session.read(job/'tmux-adapter-intent.json')[1],
                'jobIdentity':session.private_dir(job),'captureIdentity':identity,'capturePins':values,'companionSource':old.blob(Path(__file__).resolve())[1]}


def _valid_remote(value):
    need(type(value) is dict and set(value)=={'state','request','proof','replayAllowed'} and
         value['state']=='staging-only' and value['request']==old.purpose(OLD_REQUEST) and value['replayAllowed'] is False,
         'invalid_staging_proof')
    proof=value['proof']
    need(type(proof) is dict and set(proof)=={'authority','stageIntentPin','source','noJobProcesses','noBuildEffects'} and
         proof['noJobProcesses'] is True and proof['noBuildEffects'] is True and session._valid_pin(proof['stageIntentPin']),
         'invalid_staging_proof')
    need(type(proof['authority']) is dict and set(proof['authority'])=={'root','job'} and all(
         type(g) is list and len(g)==5 and all(type(n) is int for n in g) and stat.S_ISDIR(g[2]) and stat.S_IMODE(g[2])==0o700
         for g in proof['authority'].values()),'invalid_staging_proof')
    uid=proof['authority']['job'][3]
    need(proof['authority']['root'][3]==uid and stat.S_ISREG(proof['stageIntentPin']['generation'][2]) and
         stat.S_IMODE(proof['stageIntentPin']['generation'][2])==0o600 and proof['stageIntentPin']['generation'][3]==uid and
         proof['stageIntentPin']['generation'][8]==1 and proof['stageIntentPin']['sha256']==hashlib.sha256(session.canonical(old.purpose(OLD_REQUEST))).hexdigest(),'invalid_staging_proof')
    source=proof['source']
    need(source is None or type(source) is dict and set(source) in ({'generation','children'},{'generation','children','gitGeneration'}) and
         source['children'] in ([],['.git']) and type(source['generation']) is list and len(source['generation'])==9 and
         all(type(n) is int for n in source['generation']) and stat.S_ISDIR(source['generation'][2]),'invalid_staging_proof')
    if source is not None:
        expected={'generation','children'} | ({'gitGeneration'} if source['children']==['.git'] else set())
        need(set(source)==expected,'invalid_staging_proof')
        for key in ('generation','gitGeneration'):
            if key in source:
                g=source[key]
                need(type(g) is list and len(g)==9 and all(type(n) is int and n>=0 for n in g) and
                     stat.S_ISDIR(g[2]) and g[3]==uid and not g[2]&0o022,'invalid_staging_proof')
    return value


def observe_failed_stage(root):
    """One fixed read only, new diagnostic capsule; never archive/retry implicitly."""
    driver=old.TmuxArchDriver(root);job,before=_local(driver)
    reader=ExactFetchDriver(root)
    # Query capsules go outside original consumed job. They cannot alter its
    # original evidence inventory or authority.
    value=reader._query(PROOF,{'request':old.purpose(OLD_REQUEST)},guard=lambda:need(_local(driver)[1]==before,'local_authority_changed'))
    _valid_remote(value);need(_local(driver)[1]==before,'local_authority_changed')
    pin=session.write_once(job/'stage-recovery-proof.json',session.canonical({'local':before,'remote':value,
          'proofProgramSha256':hashlib.sha256(PROOF.encode()).hexdigest()}))
    return {'state':'observed','correlationId':OLD_CORRELATION,'proofPin':pin,'replayAllowed':False}


def archive_failed_claim(root,proof_pin):
    """Explicit create-only consumed fence then exclusive local claim archive.

    Original coordinator intent, local job and all remote files are preserved.
    No replay after a lost result or interrupted archive is permitted.
    """
    need(session._valid_pin(proof_pin),'invalid_proof_pin')
    driver=old.TmuxArchDriver(root);job,before=_local(driver)
    path=job/'stage-recovery-proof.json';raw,actual=session.read(path,131072)
    need(actual==proof_pin,'recovery_proof_changed');value=json.loads(raw)
    need(set(value)=={'local','remote','proofProgramSha256'} and value['local']==before and
         value['proofProgramSha256']==hashlib.sha256(PROOF.encode()).hexdigest(),'recovery_proof_changed')
    _valid_remote(value['remote'])
    # Repeat the exact positive remote absence before the local archive.
    reader=ExactFetchDriver(root)
    current=reader._query(PROOF,{'request':old.purpose(OLD_REQUEST)},guard=lambda:need(_local(driver)[1]==before,'local_authority_changed'))
    need(_valid_remote(current)==value['remote'],'remote_staging_changed')
    directory=job.parent;lock=directory/'tmux-stage-recovery.lock'
    fd=os.open(lock,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_NONBLOCK,0o600)
    try:
        info=os.fstat(fd);need(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode)==0o600 and info.st_uid==os.getuid() and info.st_nlink==1,'unsafe_recovery_lock')
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        lock_gen=session.generation(info)
        def guard():
            need(session.generation(os.fstat(fd))==lock_gen==session.generation(lock.lstat()) and _local(driver)[1]==before and
                 session.read(path,131072)[1]==proof_pin,'local_authority_changed')
        guard()
        session.write_once(job/'stage-recovery-fence.json',session.canonical({'local':before,'proofPin':proof_pin,'replayAllowed':False}))
        guard()
        claim=directory/'archlinux.claim';archive=directory/(OLD_CORRELATION+'.staging-only.claim')
        old.rename_complete(claim,archive)
        raw,archive_pin=session.read(archive)
        need(json.loads(raw)=={'correlationId':OLD_CORRELATION,'host':'archlinux'} and
             archive_pin['sha256']==before['original']['coordinator']['records']['claim']['sha256'],'archived_claim_changed')
        session.write_once(job/'stage-recovery-terminal.json',session.canonical({'proofPin':proof_pin,'archivePin':archive_pin,
                           'oldOutcome':'unknown','remoteFilesPreserved':True,'replayAllowed':False}))
        return {'state':'archived','correlationId':OLD_CORRELATION,'oldOutcome':'unknown','replayAllowed':False}
    finally:os.close(fd)


def recovery_status(root):
    directory=build._directory(Path(root).resolve(strict=True),False)
    need(directory is not None,'coordinator_journal_missing')
    job=directory/OLD_CORRELATION;session.private_dir(job)
    try:
        terminal=json.loads(session.read(job/'stage-recovery-terminal.json')[0])
        archive=directory/(OLD_CORRELATION+'.staging-only.claim')
        need(set(terminal)=={'proofPin','archivePin','oldOutcome','remoteFilesPreserved','replayAllowed'} and
             terminal['oldOutcome']=='unknown' and terminal['remoteFilesPreserved'] is True and terminal['replayAllowed'] is False and
             session.read(archive)[1]==terminal['archivePin'],'archive_authority_changed')
        need(session.read(job/'stage-recovery-proof.json',131072)[1]==terminal['proofPin'],'recovery_proof_changed')
        return {'state':'archived','correlationId':OLD_CORRELATION,'oldOutcome':'unknown','replayAllowed':False}
    except FileNotFoundError:
        return {'state':'unknown','correlationId':OLD_CORRELATION,'replayAllowed':False}


def operate_v2(root,action,raw,*,source_root=None):
    need(type(action) is str and action in ('availability','preflight','start','status','release','collect'),'unsupported_action')
    driver=ExactFetchDriver(root,source_root=source_root)
    if action=='availability':need(raw=={} and type(raw) is dict,'invalid_request');return driver.availability()
    if action=='preflight':return driver.preflight(raw)
    if action=='start':return build.start(root,raw,driver=driver,admission=lambda unused,request:driver.preflight(request),source_root=source_root)
    need(type(raw) is dict and set(raw)=={'correlationId'} and build._correlation(raw['correlationId']),'invalid_request')
    if action=='status':return build.status(root,raw,driver=driver)
    directory=build._directory(Path(root).resolve(strict=True),False);need(directory is not None,'coordinator_journal_missing')
    request=build._read(directory/(raw['correlationId']+'.json'));need(request is not None,'missing_intent')
    if action=='release':return driver.release(request)
    return driver.collect_existing(request)
