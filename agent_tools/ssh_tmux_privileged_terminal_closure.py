"""Root-only, fixed read of the completed tmux workspace.

This helper is an observation boundary. It cannot close a pane, release a
reservation, archive a claim, or start a replacement job. The root program is
embedded in the reviewed ``status`` action so inherited source, stage, terminal,
and anchor guards still bracket the census.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from uuid import UUID

from . import ssh_tmux_closure_census_diagnostic as diagnostic
from . import ssh_tmux_mcp_adapter as adapter
from . import ssh_tmux_session as session
from . import ssh_tmux_session_ssh as old
from . import ssh_tmux_terminal_closure as closure
from . import ssh_transport
from . import windows_vm_virt_firmware_install as credentials

need = old.need
CORRELATION = closure.CORRELATION
DIAGNOSTIC_SOURCE_SHA = "0e0ea6e85415ed627e08776c9fb7ddf32d067cbe51a34ee6d34fa6b0f6b3a461"
MAX_STDOUT = 16 * 1024
MAX_STDERR = 64 * 1024

ROOT_PROGRAM = r'''
import hashlib,json,os,pathlib
if os.geteuid()!=0:raise SystemExit(30)
if payload!={'action':'status','request':FIXED_REQUEST,'stagePin':FIXED_STAGE,'anchorPin':FIXED_ANCHOR}:raise SystemExit(31)
terminal={'state':'terminal','correlationId':FIXED_REQUEST['correlationId'],'exitCode':0,'terminalPin':FIXED_TERMINAL,'artifactVerification':'required','replayAllowed':False}
if ns['status'](job,source,payload['anchorPin'])!=terminal:raise SystemExit(32)
anchor=ns['_anchor'](job,source,payload['anchorPin']);pane=anchor.get('pane',{})
if set(pane)!={'pid','startTicks'} or type(pane['pid'])is not int or pane['pid']<=0 or type(pane['startTicks'])is not int or pane['startTicks']<0:raise SystemExit(32)
def read_at(fd,name,limit):
 child=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
 try:
  raw=os.read(child,limit+1)
  if len(raw)>limit:raise SystemExit(36)
  return raw
 finally:os.close(child)
def fields(fd):
 raw=read_at(fd,'stat',8192)
 try:x=raw.rsplit(b')',1)[1].split()
 except IndexError:raise SystemExit(36)
 if len(x)<=19:raise SystemExit(36)
 return x
def kthread(fd):
 raw=read_at(fd,'status',8192)
 values=[x.split(b':',1)[1].strip() for x in raw.splitlines() if x.startswith(b'Kthread:')]
 if len(values)!=1 or values[0] not in (b'0',b'1'):raise SystemExit(36)
 return values[0]
try:entries=list(pathlib.Path('/proc').iterdir())
except OSError:raise SystemExit(36)
if len(entries)>8192:raise SystemExit(36)
for p in entries:
 if not p.name.isdigit() or int(p.name)==os.getpid():continue
 fd=None
 try:
  fd=os.open(p,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
  before_dir=os.fstat(fd);before=fields(fd);kernel=kthread(fd);command=read_at(fd,'cmdline',65536)
  if before[0]==b'Z':raise SystemExit(36)
  if kernel==b'1':
   if command:raise SystemExit(36)
   cwd=None
  else:cwd=os.readlink('cwd',dir_fd=fd)
  after=fields(fd)
  if before[19]!=after[19] or before[0]!=after[0] or kthread(fd)!=kernel or read_at(fd,'cmdline',65536)!=command or (cwd is not None and os.readlink('cwd',dir_fd=fd)!=cwd) or os.fstat(fd)!=before_dir:raise SystemExit(36)
  fixed=os.fsencode(job);tokens=command.split(b'\0')
  if (cwd is not None and (cwd==str(job) or cwd.startswith(str(job)+'/'))) or any(x==fixed or x.startswith(fixed+b'/') for x in tokens):raise SystemExit(37)
 except OSError:raise SystemExit(36)
 finally:
  if fd is not None:os.close(fd)
if ns['status'](job,source,payload['anchorPin'])!=terminal or ns['_anchor'](job,source,payload['anchorPin'])!=anchor:raise SystemExit(32)
result={'state':'complete-root-census','correlationId':FIXED_REQUEST['correlationId'],'hostBootId':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'pane':pane,'originalDeniedPid':992,'originalDeniedStartTicks':720,'workspaceProof':False,'nativeActionAllowed':False,'replayAllowed':False}
'''

WRAPPER = r'''import subprocess,sys
secret=sys.stdin.buffer.read(513)
if not 0<len(secret)<=512 or b'\0' in secret or b'\n' in secret.rstrip(b'\n'):raise SystemExit(31)
try:r=subprocess.run(['/usr/bin/sudo','-S','-p','','--','/usr/bin/python3','-I','-B','-c','exec('+repr(ROOT_SOURCE)+')'],input=secret.rstrip(b'\n')+b'\n',stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=35,check=False,env={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C'})
except (OSError,subprocess.TimeoutExpired):raise SystemExit(32)
if r.returncode!=0 or not 0<len(r.stdout)<=16384 or len(r.stderr)>4096:
 sys.stderr.buffer.write(r.stderr[:4096]);raise SystemExit(33)
sys.stdout.buffer.write(r.stdout)
'''.replace("ROOT_SOURCE", repr(ROOT_PROGRAM))


def program():
    """Return the source-bound inherited status action with one JSON emitter."""
    need(hashlib.sha256(Path(diagnostic.__file__).read_bytes()).hexdigest() == DIAGNOSTIC_SOURCE_SHA,
         "diagnostic_source_changed")
    root = (ROOT_PROGRAM
            .replace("FIXED_REQUEST", repr(old.purpose(closure.pipe.REQUEST)))
            .replace("FIXED_STAGE", repr(closure.pipe.STAGE))
            .replace("FIXED_ANCHOR", repr(closure.pipe.ANCHOR))
            .replace("FIXED_TERMINAL", repr(closure.pipe.TERMINAL)))
    payload_prefix = "payload=json.loads(sys.stdin.buffer.read(16385));action=payload['action'];request=payload['request']"
    need(old._ACTION.count(payload_prefix) == 1, "inherited_payload_prefix_changed")
    fixed_payload = {"action": "status", "request": old.purpose(closure.pipe.REQUEST),
                     "stagePin": closure.pipe.STAGE, "anchorPin": closure.pipe.ANCHOR}
    value = old._ACTION.replace(closure._DISPATCH, root).replace(
        payload_prefix, "payload=" + repr(fixed_payload) + ";action=payload['action'];request=payload['request']")
    compile(value, "<fixed-privileged-terminal-census>", "exec")
    return value


def diagnostic_program():
    """Run the exact read-only program with finite failure classification.

    The inherited final emitter is replaced only after its source/tail guards
    have run. This distinguishes a completed census whose post-dispatch source
    guard changed from any guard or census failure before a result exists,
    without exposing raw stderr.
    """
    body = program()
    emitter = "print(json.dumps(result,sort_keys=True,separators=(',',':')))"
    need(body.count(emitter) == 1, "inherited_emitter_changed")
    body = body.replace(emitter, "pass")
    return """import json
scope={}
try:
 exec(""" + repr(body) + """,scope)
except SystemExit as stop:
 code=stop.code if type(stop.code)is int else 0
 complete=type(scope.get('result'))is dict and scope['result'].get('state')=='complete-root-census'
 phase={30:'root-role-rejected',31:'fixed-request-invalid',32:'terminal-or-anchor-invalid',36:'proc-observation-unknown',37:'workspace-reference-present'}.get(code, 'unknown')
 if code==33:phase='post-root-source-guard' if complete else 'guard-or-census-before-result'
 errno=None
 print(json.dumps({'state':'diagnosed-root-census','correlationId':""" + repr(CORRELATION) + """,'phase':phase,'pid':0,'startTicks':0,'errno':errno,'workspaceProof':False,'nativeActionAllowed':False,'replayAllowed':False},sort_keys=True,separators=(',',':')))
else:
 print(json.dumps({'state':'diagnosed-root-census','correlationId':""" + repr(CORRELATION) + """,'phase':'complete','pid':0,'startTicks':0,'errno':None,'workspaceProof':False,'nativeActionAllowed':False,'replayAllowed':False},sort_keys=True,separators=(',',':')))
"""


def _sources(root):
    """Pin every inherited source plus this helper through FD-checked reads."""
    values = diagnostic._sources(root)
    path = Path(__file__).absolute()
    values[str(path)] = closure.pipe._read(path, 262144, False)[1]
    return values


def validate(value):
    need(type(value) is dict and set(value) == {
        "state", "correlationId", "hostBootId", "pane", "originalDeniedPid",
        "originalDeniedStartTicks", "workspaceProof", "nativeActionAllowed",
        "replayAllowed"} and value["state"] == "complete-root-census" and
         value["correlationId"] == CORRELATION and type(value["hostBootId"]) is str and
         str(UUID(value["hostBootId"])) == value["hostBootId"] and
         type(value["pane"]) is dict and set(value["pane"]) == {"pid", "startTicks"} and
         type(value["pane"]["pid"]) is int and value["pane"]["pid"] > 0 and
         type(value["pane"]["startTicks"]) is int and value["pane"]["startTicks"] >= 0 and
         value["originalDeniedPid"] == 992 and value["originalDeniedStartTicks"] == 720 and
         value["workspaceProof"] is False and value["nativeActionAllowed"] is False and
         value["replayAllowed"] is False, "privileged_terminal_unknown")
    return value


def validate_diagnostic(value):
    phases = {'complete', 'root-role-rejected', 'fixed-request-invalid', 'terminal-or-anchor-invalid',
              'guard-or-census-before-result', 'post-root-source-guard', 'proc-observation-unknown',
              'workspace-reference-present', 'unknown'}
    need(type(value) is dict and set(value) == {'state', 'correlationId', 'phase', 'pid', 'startTicks',
         'errno', 'workspaceProof', 'nativeActionAllowed', 'replayAllowed'} and
         value['state'] == 'diagnosed-root-census' and value['correlationId'] == CORRELATION and
         value['phase'] in phases and type(value['pid']) is int and value['pid'] >= 0 and
         type(value['startTicks']) is int and value['startTicks'] >= 0 and
         value['errno'] is None and value['workspaceProof'] is False and
         value['nativeActionAllowed'] is False and value['replayAllowed'] is False,
         'privileged_terminal_diagnostic_unknown')
    return value


def validate_carrier_diagnostic(value):
    if type(value) is dict and value.get('state') == 'complete-root-census':
        return validate(value)
    phases = {'root-role-rejected', 'owner-facts-invalid', 'root-boot-changed',
              'proc-observation-unknown', 'workspace-reference-present', 'root-child-unknown'}
    if type(value) is dict and value.get('state') == 'root-census-proc-failed':
        steps = {'proc-list', 'proc-list-limit', 'file-oversize', 'stat-schema', 'status-schema', 'zombie-command', 'zombie-resources',
                 'zombie-link', 'zombie-postcheck', 'zombie-link-postcheck', 'kernel-command', 'identity-changed', 'proc-io'}
        need(set(value) == {'state', 'correlationId', 'substep', 'pid', 'startTicks', 'errno',
             'workspaceProof', 'nativeActionAllowed', 'replayAllowed'} and value['correlationId'] == CORRELATION and
             value['substep'] in steps and type(value['pid']) is int and value['pid'] >= 0 and
             type(value['startTicks']) is int and value['startTicks'] >= 0 and
             value['errno'] in (None, 'EPERM', 'ENOENT', 'EIO', 'EACCES', 'OTHER') and
             value['workspaceProof'] is False and value['nativeActionAllowed'] is False and
             value['replayAllowed'] is False, 'privileged_terminal_diagnostic_unknown')
        return value
    need(type(value) is dict and set(value) == {'state', 'correlationId', 'phase', 'childExit', 'errno',
         'workspaceProof', 'nativeActionAllowed', 'replayAllowed'} and value['state'] == 'root-census-failed' and
         value['correlationId'] == CORRELATION and value['phase'] in phases and type(value['childExit']) is int and
         1 <= value['childExit'] <= 255 and value['errno'] is None and value['workspaceProof'] is False and
         value['nativeActionAllowed'] is False and value['replayAllowed'] is False,
         'privileged_terminal_diagnostic_unknown')
    return value


def _observe(root, program_factory, validator):
    """One fixed privileged read with a durable private bounded capture."""
    root = Path(root).absolute()
    need(hashlib.sha256(Path(diagnostic.__file__).read_bytes()).hexdigest() == DIAGNOSTIC_SOURCE_SHA,
         "diagnostic_source_changed")
    secret = credentials._read_credential(root)
    need(0 < len(secret) <= 512 and b"\0" not in secret and b"\n" not in secret.rstrip(b"\n"),
         "credential_shape")
    # The legacy driver admits only its retired pre-stage snapshot. The reviewed
    # adapter is the same prepared-state admission used by the prior 0e read.
    driver = adapter.McpTmuxDriver(root)
    job, snapshot = driver._saved(closure.pipe.REQUEST)
    config, transport = driver._transport()
    need(ssh_transport.connection_host(config, "archlinux").password is None, "password_transport_not_supported")
    need(program_factory in (program, diagnostic_program, carrier_program), "unsupported_privileged_program")
    remote = program_factory()
    remote_sha = hashlib.sha256(remote.encode()).hexdigest()
    wrapper = remote if program_factory is carrier_program else WRAPPER.replace(repr(ROOT_PROGRAM), repr(remote))
    argv = ssh_transport.build_ssh_argv(
        config, "archlinux", 10,
        command=["/usr/bin/python3", "-I", "-B", "-c", "exec(" + repr(wrapper) + ")"])

    def guard():
        need(driver._saved(closure.pipe.REQUEST) == (job, snapshot) and
             driver._transport()[1] == transport and
             hashlib.sha256(program_factory().encode()).hexdigest() == remote_sha,
             "terminal_authority_changed")
    sources = _sources(root)
    def full_guard():
        guard()
        need(_sources(root) == sources, "terminal_authority_changed")
    authority = {"phase": "status", "snapshot": snapshot, "sources": sources,
                 "transport": transport, "local": {"privilegedTerminalCensus": True},
                 "argvSha256": hashlib.sha256(session.canonical(argv)).hexdigest()}
    def launch():
        full_guard()
        return adapter.subprocess.Popen(argv, cwd=root, stdin=adapter.subprocess.PIPE,
                                        stdout=adapter.subprocess.PIPE, stderr=adapter.subprocess.PIPE, bufsize=0)
    outcome, capsule = adapter._capture(root, authority=authority, launch=launch, payload=secret,
                                        guard=full_guard)
    need(outcome["state"] == "captured", "terminal_transport_unknown")
    receipt_raw, receipt_pin = closure.pipe._read(capsule / "receipt.json")
    need(receipt_pin == outcome["receiptPin"], "terminal_capture_changed")
    receipt = json.loads(receipt_raw)
    raw, stdout_pin = closure.pipe._read(capsule / "stdout", adapter.MAX_STDOUT)
    need(stdout_pin == receipt["stdoutPin"] and
         closure.pipe._read(capsule / "stderr", adapter.MAX_STDERR)[1] == receipt["stderrPin"],
         "terminal_capture_changed")
    value = validator(json.loads(raw, object_pairs_hook=ssh_transport._reject_duplicate_keys))
    full_guard()
    return {**value, "receiptPin": outcome["receiptPin"]}


def observe(root):
    """Perform one fixed privileged observation. It creates no proof or claim."""
    return _observe(root, carrier_program, validate)


def observe_diagnostic(root):
    """Classify a root-child failure without claiming a completed census."""
    return _observe(root, carrier_program, validate_carrier_diagnostic)

# The inherited action must run as the owner of tmux-tool.py (UID 1000). Root
# cannot pass that prefix. This closed dispatch returns only terminal/anchor
# facts after the inherited prefix and tail have verified the stage/source.
_OWNER_DISPATCH = r'''if action!='status':raise SystemExit(31)
owner_terminal=ns['status'](job,source,payload['anchorPin'])
owner_anchor=ns['_anchor'](job,source,payload['anchorPin'])
if owner_terminal!={'state':'terminal','correlationId':request['correlationId'],'exitCode':0,'terminalPin':FIXED_TERMINAL,'artifactVerification':'required','replayAllowed':False}:raise SystemExit(32)
pane=owner_anchor.get('pane',{})
if set(pane)!={'pid','startTicks'} or type(pane['pid'])is not int or pane['pid']<=0 or type(pane['startTicks'])is not int or pane['startTicks']<0:raise SystemExit(32)
result={'state':'owner-admitted-root-census','correlationId':request['correlationId'],'terminal':owner_terminal,'pane':pane,'replayAllowed':False,'nativeActionAllowed':False,'workspaceProof':False}'''


def owner_program():
    payload_prefix = "payload=json.loads(sys.stdin.buffer.read(16385));action=payload['action'];request=payload['request']"
    need(old._ACTION.count(payload_prefix) == 1, 'inherited_payload_prefix_changed')
    fixed = {'action':'status','request':old.purpose(closure.pipe.REQUEST),
             'stagePin':closure.pipe.STAGE,'anchorPin':closure.pipe.ANCHOR}
    dispatch = _OWNER_DISPATCH.replace('FIXED_TERMINAL', repr(closure.pipe.TERMINAL))
    need(old._ACTION.count(closure._DISPATCH) == 1, 'inherited_dispatch_changed')
    value = old._ACTION.replace(closure._DISPATCH, dispatch).replace(
        payload_prefix, "payload=" + repr(fixed) + ";action=payload['action'];request=payload['request']")
    compile(value, '<owner-root-census-admission>', 'exec')
    return value


ROOT_CENSUS = r'''
import json,os,pathlib
if os.geteuid()!=0:raise SystemExit(30)
facts=OWNER_FACT
if type(facts)is not dict or set(facts)!={'state','correlationId','terminal','pane','replayAllowed','nativeActionAllowed','workspaceProof'} or facts['state']!='owner-admitted-root-census' or facts['correlationId']!=FIXED_CORRELATION or facts['replayAllowed']is not False or facts['nativeActionAllowed']is not False or facts['workspaceProof']is not False:raise SystemExit(31)
pane=facts['pane'];job=pathlib.Path('/home/kardinal/.vpn-control-linux-package-fixture')/FIXED_CORRELATION
boot=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
current_pid=0;current_ticks=0
def fault(substep,error=None):
 code=getattr(error,'errno',None)
 errno={1:'EPERM',2:'ENOENT',5:'EIO',13:'EACCES'}.get(code,'OTHER' if error is not None else None)
 print(json.dumps({'state':'root-census-proc-failed','correlationId':FIXED_CORRELATION,'substep':substep,'pid':current_pid,'startTicks':current_ticks,'errno':errno,'workspaceProof':False,'nativeActionAllowed':False,'replayAllowed':False},sort_keys=True,separators=(',',':')))
 raise SystemExit(0)
def read_at(fd,name,limit):
 child=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
 try:
  raw=os.read(child,limit+1)
  if len(raw)>limit:fault('file-oversize')
  return raw
 finally:os.close(child)
def fields(fd):
 raw=read_at(fd,'stat',8192)
 try:x=raw.rsplit(b')',1)[1].split()
 except IndexError:fault('stat-schema')
 if len(x)<=19:fault('stat-schema')
 return x
def kthread(fd):
 values=[x.split(b':',1)[1].strip() for x in read_at(fd,'status',8192).splitlines() if x.startswith(b'Kthread:')]
 if len(values)!=1 or values[0] not in (b'0',b'1'):fault('status-schema')
 return values[0]
try:entries=list(pathlib.Path('/proc').iterdir())
except OSError as error:fault('proc-list',error)
if len(entries)>8192:fault('proc-list-limit')
for p in entries:
 if not p.name.isdigit() or int(p.name)==os.getpid():continue
 current_pid=int(p.name);current_ticks=0
 fd=None
 try:
  fd=os.open(p,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);before=fields(fd);current_ticks=int(before[19]);kernel=kthread(fd);command=read_at(fd,'cmdline',65536)
  if before[0]==b'Z':
   if command:fault('zombie-command')
   maps=read_at(fd,'maps',65536)
   child=os.open('fd',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
   try:
    fd_before=os.fstat(child);named_before=os.stat('fd',dir_fd=fd,follow_symlinks=False)
    if os.listdir(child) or maps:fault('zombie-resources')
   finally:os.close(child)
   for name in ('cwd','root'):
    try:os.readlink(name,dir_fd=fd)
    except OSError as error:
     if error.errno!=2:fault('zombie-link',error)
    else:fault('zombie-link')
   after=fields(fd)
   if before[19]!=after[19] or after[0]!=b'Z' or kthread(fd)!=kernel or read_at(fd,'cmdline',65536)!=command:fault('identity-changed')
   child=os.open('fd',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
   try:
    fd_after=os.fstat(child);named_after=os.stat('fd',dir_fd=fd,follow_symlinks=False)
    if (fd_before.st_dev,fd_before.st_ino,fd_before.st_mode,fd_before.st_uid,fd_before.st_gid,fd_before.st_nlink)!=(fd_after.st_dev,fd_after.st_ino,fd_after.st_mode,fd_after.st_uid,fd_after.st_gid,fd_after.st_nlink) or (named_before.st_dev,named_before.st_ino,named_before.st_mode,named_before.st_uid,named_before.st_gid,named_before.st_nlink)!=(named_after.st_dev,named_after.st_ino,named_after.st_mode,named_after.st_uid,named_after.st_gid,named_after.st_nlink) or os.listdir(child) or read_at(fd,'maps',65536):fault('zombie-postcheck')
   finally:os.close(child)
   for name in ('cwd','root'):
    try:os.readlink(name,dir_fd=fd)
    except OSError as error:
     if error.errno!=2:fault('zombie-link-postcheck',error)
    else:fault('zombie-link-postcheck')
   continue
  if kernel==b'1':
   if command:fault('kernel-command')
   cwd=None
  else:cwd=os.readlink('cwd',dir_fd=fd)
  after=fields(fd)
  if before[19]!=after[19] or before[0]!=after[0] or kthread(fd)!=kernel or read_at(fd,'cmdline',65536)!=command or (cwd is not None and os.readlink('cwd',dir_fd=fd)!=cwd):fault('identity-changed')
  fixed=os.fsencode(job)
  if (cwd is not None and (cwd==str(job) or cwd.startswith(str(job)+'/'))) or any(x==fixed or x.startswith(fixed+b'/') for x in command.split(b'\0')):raise SystemExit(37)
 except OSError as error:fault('proc-io',error)
 finally:
  if fd is not None:os.close(fd)
if pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()!=boot:raise SystemExit(32)
print(json.dumps({'state':'complete-root-census','correlationId':FIXED_CORRELATION,'hostBootId':boot,'pane':pane,'originalDeniedPid':992,'originalDeniedStartTicks':720,'workspaceProof':False,'nativeActionAllowed':False,'replayAllowed':False},sort_keys=True,separators=(',',':')))
'''


def carrier_program():
    """Fixed owner admission -> root census -> owner closing admission carrier."""
    owner = owner_program()
    root = ROOT_CENSUS.replace('FIXED_CORRELATION', repr(CORRELATION))
    return r'''import json,subprocess,sys
secret=sys.stdin.buffer.read(513)
if not 0<len(secret)<=512 or b'\0' in secret or b'\n' in secret.rstrip(b'\n'):raise SystemExit(31)
def owner():
 r=subprocess.run(['/usr/bin/python3','-I','-B','-c','exec('+repr(OWNER_SOURCE)+')'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=25,check=False,env={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C'})
 if r.returncode!=0 or len(r.stdout)>16384 or len(r.stderr)>4096:raise SystemExit(32)
 try:v=json.loads(r.stdout)
 except ValueError:raise SystemExit(32)
 if type(v)is not dict or set(v)!={'state','correlationId','terminal','pane','replayAllowed','nativeActionAllowed','workspaceProof'} or v['state']!='owner-admitted-root-census' or v['replayAllowed']is not False or v['nativeActionAllowed']is not False or v['workspaceProof']is not False:raise SystemExit(32)
 return v
first=owner();root=ROOT_SOURCE.replace('OWNER_FACT',repr(first))
r=subprocess.run(['/usr/bin/sudo','-S','-p','','--','/usr/bin/python3','-I','-B','-c','exec('+repr(root)+')'],input=secret.rstrip(b'\n')+b'\n',stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=40,check=False,env={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C'})
if r.returncode!=0:
 sys.stderr.buffer.write(r.stderr[:4096])
 phase={30:'root-role-rejected',31:'owner-facts-invalid',32:'root-boot-changed',36:'proc-observation-unknown',37:'workspace-reference-present'}.get(r.returncode,'root-child-unknown')
 print(json.dumps({'state':'root-census-failed','correlationId':first['correlationId'],'phase':phase,'childExit':r.returncode,'errno':None,'workspaceProof':False,'nativeActionAllowed':False,'replayAllowed':False},sort_keys=True,separators=(',',':')));raise SystemExit(0)
if not 0<len(r.stdout)<=16384 or len(r.stderr)>4096:sys.stderr.buffer.write(r.stderr[:4096]);raise SystemExit(33)
if owner()!=first:raise SystemExit(34)
sys.stdout.buffer.write(r.stdout)
'''.replace('OWNER_SOURCE',repr(owner)).replace('ROOT_SOURCE',repr(root))
