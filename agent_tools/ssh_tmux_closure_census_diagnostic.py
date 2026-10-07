"""Read-only classifier for the retained terminal-closure proc census failure.

This is deliberately not a weaker closure proof.  It reports one finite failed
read step for the exact completed 86 job and never reports workspace absence,
terminal completion, or any authority to archive/release/replay.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re

from . import ssh_tmux_terminal_closure as closure
from . import ssh_tmux_mcp_adapter as adapter
from . import ssh_tmux_session_ssh as old
from . import ssh_tmux_session as session
from . import ssh_transport

need = old.need
CORRELATION = closure.CORRELATION
CLOSURE_SHA = "376882d9b636d3605b1bb9ca855f4db48b7f1478caa17ae1026d92e187d7f071"

_DIAGNOSTIC = r'''
if set(payload)!={'action','request','stagePin','anchorPin'} or payload['action']!='status':raise ValueError('diagnostic_fixed_request_required')
if payload['request']!=FIXED_REQUEST or payload['stagePin']!=FIXED_STAGE or payload['anchorPin']!=FIXED_ANCHOR:raise ValueError('diagnostic_original_authority_changed')
def failure(phase,pid,ticks,err=None):
 if phase not in {'complete','principal-stat-error','principal-stat-malformed','principal-live','process-stat-before-error','process-stat-malformed','process-cmdline-error','process-cwd-error','process-stat-after-error','process-changed','proc-list-error'}:raise ValueError('diagnostic_phase_invalid')
 if type(pid)is not int or pid<0 or type(ticks)is not int or ticks<0 or err not in (None,'EACCES','ENOENT','EIO','EPERM','OTHER'):raise ValueError('diagnostic_result_invalid')
 result={'state':'diagnostic','correlationId':FIXED_REQUEST['correlationId'],'phase':phase,'pid':pid,'startTicks':ticks,'errno':err,'nativeActionAllowed':False,'replayAllowed':False,'workspaceProof':False}
 return result
def code(error):
 return {13:'EACCES',2:'ENOENT',5:'EIO',1:'EPERM'}.get(getattr(error,'errno',None),'OTHER')
def stat_fields(path):
 raw=(path/'stat').read_bytes()
 if len(raw)>8192:raise ValueError('oversize')
 part=raw.rsplit(b')',1)
 if len(part)!=2:raise ValueError('malformed')
 fields=part[1].split()
 if len(fields)<=19:raise ValueError('malformed')
 return fields
def scan(anchor):
 try:
  entries=list(pathlib.Path('/proc').iterdir())
 except OSError as error:return failure('proc-list-error',0,0,code(error))
 if len(entries)>8192:return failure('proc-list-error',0,0,'OTHER')
 else:
  pane=anchor['pane'];principal=pathlib.Path('/proc')/str(pane['pid'])
  if principal.exists():
   try:fields=stat_fields(principal)
   except OSError as error:return failure('principal-stat-error',pane['pid'],pane['startTicks'],code(error))
   except ValueError:return failure('principal-stat-malformed',pane['pid'],pane['startTicks'],None)
   else:
    if fields[19]==str(pane['startTicks']).encode() and fields[0]!=b'Z':return failure('principal-live',pane['pid'],pane['startTicks'],None)
  for item in entries:
   if not item.name.isdigit() or int(item.name)==os.getpid():continue
   pid=int(item.name);ticks=0
   try:
    if item.stat().st_uid!=os.getuid():continue
    before=stat_fields(item);ticks=int(before[19])
   except OSError as error:return failure('process-stat-before-error',pid,ticks,code(error))
   except (ValueError,IndexError):return failure('process-stat-malformed',pid,ticks,None)
   try:argv=(item/'cmdline').read_bytes()
   except OSError as error:return failure('process-cmdline-error',pid,ticks,code(error))
   if len(argv)>65536:return failure('process-cmdline-error',pid,ticks,'OTHER')
   try:
    if before[0]!=b'Z':os.readlink(item/'cwd')
   except OSError as error:return failure('process-cwd-error',pid,ticks,code(error))
   try:after=stat_fields(item)
   except OSError as error:return failure('process-stat-after-error',pid,ticks,code(error))
   except ValueError:return failure('process-stat-malformed',pid,ticks,None)
   if before[19]!=after[19] or before[0]!=after[0]:return failure('process-changed',pid,ticks,None)
  result=failure('complete',0,0,None)
 return result
def run_diagnostic():
 terminal={'state':'terminal','correlationId':FIXED_REQUEST['correlationId'],'exitCode':0,'terminalPin':FIXED_TERMINAL,'artifactVerification':'required','replayAllowed':False}
 if ns['status'](job,source,payload['anchorPin'])!=terminal:raise ValueError('diagnostic_terminal_before_changed')
 anchor=ns['_anchor'](job,source,payload['anchorPin'])
 if type(anchor)is not dict or anchor.get('pane') is None:raise ValueError('diagnostic_anchor_changed')
 result=scan(anchor)
 if ns['status'](job,source,payload['anchorPin'])!=terminal or ns['_anchor'](job,source,payload['anchorPin'])!=anchor:raise ValueError('diagnostic_terminal_after_changed')
 return result
result=run_diagnostic()
'''


def remote_program():
    need(hashlib.sha256(Path(closure.__file__).read_bytes()).hexdigest() == CLOSURE_SHA, 'closure_source_changed')
    need(old._ACTION.count(closure._DISPATCH) == 1, 'closure_dispatch_changed')
    text = (_DIAGNOSTIC.replace('FIXED_REQUEST', repr(old.purpose(closure.pipe.REQUEST)))
            .replace('FIXED_STAGE', repr(closure.pipe.STAGE))
            .replace('FIXED_ANCHOR', repr(closure.pipe.ANCHOR))
            .replace('FIXED_TERMINAL', repr(closure.pipe.TERMINAL)))
    program = old._ACTION.replace(closure._DISPATCH, text)
    compile(program, '<fixed-closure-census-diagnostic>', 'exec')
    return program


def _sources(root):
    values = closure._sources(root)
    need(hashlib.sha256(Path(closure.__file__).read_bytes()).hexdigest() == CLOSURE_SHA, 'closure_source_changed')
    path = Path(__file__).absolute()
    values[str(path)] = closure.pipe._read(path, 262144, False)[1]
    return values


def _validate(value):
    phases = {'complete','principal-stat-error','principal-stat-malformed','principal-live','process-stat-before-error','process-stat-malformed','process-cmdline-error','process-cwd-error','process-stat-after-error','process-changed','proc-list-error'}
    need(type(value) is dict and set(value) == {'state','correlationId','phase','pid','startTicks','errno','nativeActionAllowed','replayAllowed','workspaceProof'}, 'diagnostic_reply_unknown')
    need(value['state'] == 'diagnostic' and value['correlationId'] == CORRELATION and value['phase'] in phases and type(value['pid']) is int and value['pid'] >= 0 and type(value['startTicks']) is int and value['startTicks'] >= 0 and value['errno'] in (None,'EACCES','ENOENT','EIO','EPERM','OTHER') and value['nativeActionAllowed'] is False and value['replayAllowed'] is False and value['workspaceProof'] is False, 'diagnostic_reply_unknown')
    return value


def observe(root, correlation_id=CORRELATION):
    """Run the sole source-bound read-only diagnostic; no closure side effect."""
    need(type(correlation_id) is str and correlation_id == CORRELATION, 'diagnostic_fixed_correlation_required')
    root = Path(root).absolute()
    with closure.claim_lock(root) as (_, lock_guard):
        driver = adapter.McpTmuxDriver(root)
        job, snapshot = driver._saved(closure.pipe.REQUEST)
        sources = _sources(root); config, transport = driver._transport()
        need(ssh_transport.connection_host(config, 'archlinux').password is None, 'password_transport_not_supported')
        program = remote_program()
        payload = {'action':'status','request':old.purpose(closure.pipe.REQUEST),'stagePin':closure.pipe.STAGE,'anchorPin':closure.pipe.ANCHOR}
        argv = ssh_transport.build_ssh_argv(config, 'archlinux', 10, command=['python3','-I','-B','-c','exec('+repr(program)+')'])
        def guard():
            lock_guard(); need(_sources(root) == sources and driver._transport()[1] == transport, 'diagnostic_authority_changed')
            current_job, current_snapshot = driver._saved(closure.pipe.REQUEST)
            need(current_job == job and current_snapshot == snapshot, 'diagnostic_authority_changed')
        def launch():
            guard()
            return adapter.subprocess.Popen(argv, cwd=root, stdin=adapter.subprocess.PIPE, stdout=adapter.subprocess.PIPE, stderr=adapter.subprocess.PIPE, bufsize=0)
        authority = {'phase':'status','snapshot':snapshot,'sources':sources,'transport':transport,'local':{'diagnostic':True},'argvSha256':hashlib.sha256(session.canonical(argv)).hexdigest()}
        outcome, capsule = adapter._capture(root, authority=authority, launch=launch, payload=session.canonical(payload), guard=guard)
        need(outcome['state'] == 'captured', 'diagnostic_transport_unknown')
        receipt_raw, receipt_pin = closure.pipe._read(capsule/'receipt.json'); need(receipt_pin == outcome['receiptPin'], 'diagnostic_capture_changed')
        receipt = json.loads(receipt_raw)
        raw, stdout_pin = closure.pipe._read(capsule/'stdout', adapter.MAX_STDOUT)
        need(stdout_pin == receipt['stdoutPin'] and closure.pipe._read(capsule/'stderr', adapter.MAX_STDERR)[1] == receipt['stderrPin'], 'diagnostic_capture_changed')
        value = json.loads(raw, object_pairs_hook=ssh_transport._reject_duplicate_keys)
        guard(); _validate(value)
        return {'state':'diagnosed','correlationId':CORRELATION,'phase':value['phase'],'pid':value['pid'],'startTicks':value['startTicks'],'errno':value['errno'],'workspaceProof':False,'nativeActionAllowed':False,'replayAllowed':False,'receiptPin':outcome['receiptPin']}
