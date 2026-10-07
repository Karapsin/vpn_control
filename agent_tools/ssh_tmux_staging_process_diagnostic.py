"""Fixed read-only process census diagnosis; never grants staging admission.

The consumed original failed stage and reviewed841 recovery module remain
immutable. Diagnostics are private and finite; no raw process command/cwd/body
is exposed, and neither claim archive nor stage replay is implemented here.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import resource
import subprocess
import tempfile
from uuid import UUID,uuid4
from . import ssh_tmux_source_staging_recovery as recovery
from . import ssh_tmux_session_ssh as old
from . import ssh_tmux_session as session
from . import ssh_transport

FROZEN_RECOVERY_SHA="841cd9f40b045df5471184fca0997ce0d51151741db0f12d0b66d10f6fc36749"
AdapterError=old.AdapterError
need=old.need
MAX_RESPONSE=old.MAX_RESPONSE


def replace_exact(source,old_text,new_text):
    need(source.count(old_text)==1,"diagnostic_source_rewrite_changed")
    return source.replace(old_text,new_text,1)


PROGRAM=recovery.PROOF
PROGRAM=replace_exact(PROGRAM,"if set(payload)!={'request'} or payload['request']!=", "if set(payload)!={'request','diagnosticId'} or payload['request']!=")
PROGRAM=replace_exact(PROGRAM,"request=payload['request'];root=", "diagnostic_id=payload['diagnosticId']\nif type(diagnostic_id)is not str or str(UUID(diagnostic_id))!=diagnostic_id:raise SystemExit(31)\nrequest=payload['request'];root=")
PROGRAM=replace_exact(PROGRAM,"def scan():", """def reject(pid,phase,code,error=None):
 directory='unknown';kind='unknown';uid=None;generation=None
 try:
  i=pathlib.Path('/proc',str(pid)).lstat()
  directory='present';kind='directory' if stat.S_ISDIR(i.st_mode) else 'other';uid=i.st_uid;generation=gen(i)[:5]
 except FileNotFoundError:directory='absent';kind='absent'
 except OSError:pass
 errno=None if error is None else error.errno
 if type(errno)is not int or not 0<=errno<=255:errno=None
 print(json.dumps({'state':'diagnostic-only','diagnosticId':diagnostic_id,'correlationId':request['correlationId'],'rejection':{'pid':pid,'phase':phase,'exitCode':code,'errno':errno,'directoryState':directory,'directoryKind':kind,'uid':uid,'directoryIdentity':generation},'admissionAllowed':False,'replayAllowed':False},sort_keys=True,separators=(',',':')))
 raise SystemExit(0)
def scan():""")
PROGRAM=replace_exact(PROGRAM,"  try:\n   if p.stat().st_uid!=os.getuid():continue", "  phase='process-directory'\n  try:\n   if p.stat().st_uid!=os.getuid():continue\n   phase='stat-before'")
PROGRAM=replace_exact(PROGRAM,"   with (p/'cmdline').open('rb')", "   phase='cmdline'\n   with (p/'cmdline').open('rb')")
PROGRAM=replace_exact(PROGRAM,"   cwd=os.readlink(p/'cwd')", "   phase='cwd'\n   cwd=os.readlink(p/'cwd')")
PROGRAM=replace_exact(PROGRAM,"   with (p/'stat').open('rb') as f:after", "   phase='stat-after'\n   with (p/'stat').open('rb') as f:after")
PROGRAM=replace_exact(PROGRAM,"  except OSError:raise SystemExit(36)", "  except OSError as error:reject(int(p.name),phase,36,error)")
PROGRAM=replace_exact(PROGRAM,"   if len(before)>8192:raise SystemExit(36)", "   if len(before)>8192:reject(int(p.name),'stat-cap',36)")
PROGRAM=replace_exact(PROGRAM,"  if len(command)>65536 or len(before)>8192 or before.rsplit(b')',1)[1].split()[19]!=after.rsplit(b')',1)[1].split()[19]:raise SystemExit(36)", """  if len(command)>65536 or len(after)>8192:reject(int(p.name),'proc-cap',36)
  try:
   before_start=before.rsplit(b')',1)[1].split()[19];after_start=after.rsplit(b')',1)[1].split()[19]
  except (IndexError,ValueError):reject(int(p.name),'stat-format',36)
  if before_start!=after_start:reject(int(p.name),'pid-generation',36)""")
PROGRAM=replace_exact(PROGRAM,"raise SystemExit(37)", "reject(int(p.name),'matching-job-process',37)")
PROGRAM=replace_exact(PROGRAM,"raise SystemExit(38)", "reject(int(p.name),'scan-deadline',38)")
PROGRAM=replace_exact(PROGRAM,"print(json.dumps({'state':'staging-only','request':request,'proof':first,'replayAllowed':False},sort_keys=True,separators=(',',':')))", "print(json.dumps({'state':'diagnostic-only','diagnosticId':diagnostic_id,'correlationId':request['correlationId'],'rejection':None,'admissionAllowed':False,'replayAllowed':False},sort_keys=True,separators=(',',':')))")


def command(program):
    need(program==PROGRAM,"unsupported_diagnostic_source")
    return ['python3','-I','-B','-c','exec('+repr(program)+')']


class DiagnosticDriver(old.TmuxArchDriver):
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


def validate_result(value,diagnostic_id):
    need(type(value)is dict and set(value)=={'state','diagnosticId','correlationId','rejection','admissionAllowed','replayAllowed'} and
         value['state']=='diagnostic-only' and value['diagnosticId']==diagnostic_id and value['correlationId']==recovery.OLD_CORRELATION and
         value['admissionAllowed'] is False and value['replayAllowed'] is False,'invalid_diagnostic_reply')
    r=value['rejection']
    if r is None:return value
    need(type(r)is dict and set(r)=={'pid','phase','exitCode','errno','directoryState','directoryKind','uid','directoryIdentity'} and
         type(r['pid'])is int and r['pid']>0 and r['phase'] in ('process-directory','stat-before','cmdline','cwd','stat-after','stat-cap','proc-cap','stat-format','pid-generation','matching-job-process','scan-deadline') and
         type(r['exitCode'])is int and r['exitCode'] in (36,37,38) and
         (r['errno'] is None or type(r['errno'])is int and 0<=r['errno']<=255) and
         r['directoryState'] in ('unknown','absent','present') and r['directoryKind'] in ('unknown','absent','directory','other'),'invalid_diagnostic_reply')
    need(r['exitCode']==(37 if r['phase']=='matching-job-process' else 38 if r['phase']=='scan-deadline' else 36),'invalid_diagnostic_reply')
    if r['directoryState']=='present':
        g=r['directoryIdentity']
        need(type(r['uid'])is int and r['uid']>=0 and type(g)is list and len(g)==5 and all(type(n)is int and n>=0 for n in g) and
             g[3]==r['uid'] and r['directoryKind'] in ('directory','other'),'invalid_diagnostic_reply')
    else:
        need(r['uid'] is None and r['directoryIdentity'] is None and
             r['directoryKind']==r['directoryState'],'invalid_diagnostic_reply')
    return value


def diagnose(root,diagnostic_id):
    """Explicit fixed readonly diagnostic; fresh identity cannot be relaunched."""
    need(type(diagnostic_id)is str and str(UUID(diagnostic_id))==diagnostic_id and diagnostic_id!=recovery.OLD_CORRELATION,
         'invalid_diagnostic_identity')
    root=Path(root).resolve(strict=True)
    unused,recovery_pin=old.blob(Path(recovery.__file__).resolve())
    need(recovery_pin['sha256']==FROZEN_RECOVERY_SHA,'frozen_recovery_changed')
    old_driver=old.TmuxArchDriver(root);job,before=recovery._local(old_driver)
    own_pin=old.blob(Path(__file__).resolve())[1]
    index=root/'.rag_index';session.private_dir(index)
    diagnostic=index/('tmux-staging-scan-'+diagnostic_id);diagnostic.mkdir(mode=0o700)
    identity=session.private_dir(diagnostic)
    intent_pin=session.write_once(diagnostic/'intent.json',session.canonical({'diagnosticId':diagnostic_id,'original':before,
                 'sourcePin':own_pin,'recoveryPin':recovery_pin,'programSha256':hashlib.sha256(PROGRAM.encode()).hexdigest(),'admissionAllowed':False,'replayAllowed':False}))
    def guard():
        need(recovery._local(old_driver)[1]==before and old.blob(Path(recovery.__file__).resolve())[1]==recovery_pin and
             old.blob(Path(__file__).resolve())[1]==own_pin and session.private_dir(diagnostic)==identity and
             session.read(diagnostic/'intent.json',131072)[1]==intent_pin,'diagnostic_authority_changed')
    guard()
    result=DiagnosticDriver(root)._query(PROGRAM,{'request':old.purpose(recovery.OLD_REQUEST),'diagnosticId':diagnostic_id},job=diagnostic,guard=guard)
    validate_result(result,diagnostic_id);guard()
    pin=session.write_once(diagnostic/'result.json',session.canonical(result))
    return {**result,'resultPin':pin}
