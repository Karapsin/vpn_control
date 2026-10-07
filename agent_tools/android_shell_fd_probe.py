"""Fixed read-only Android mksh descriptor ABI observation; root is sole operator.

No guest file is created or modified. Only /system/build.prop is opened, with
FD3/4. Native app_process inheritance is deliberately NOT claimed by this probe.
The frozen old-device prefix remains strict: a fresh AVD generation requires a
separately reviewed current-generation admission, never historical owner reuse.
"""
from __future__ import annotations
import ast
import hashlib
import inspect
import json
import os
from pathlib import Path
import re
from agent_tools import android_proxy_os_fresh_owner as fresh
from agent_tools import android_proxy_os_observation as frozen
from agent_tools import android_installer_failed_check_retirement as old

FRESH_SHA='bbe10668da1824bbd09dba8e2aa2e396a27c4f46062d4547e62d8bb7b566b669'
FRESH_REMOTE_SHA='8ae6e6b1aaa1300490f74b90c2a64e425ce557449c92d2575ef10000d7e5ed84'
CA03_SHA='c59af5946b8c8f08543c0ee45eda6b51026cbc9b1ca94be3581c954fe9d8ef13'
CA03_BYTES=99227
MKSH_PRIMARY={'url':'https://android.googlesource.com/platform/external/mksh/+/refs/heads/android15-release/src/exec.c','sha256':'b9d564010770a53d05b21c980bedadff07f4a8f196867b638b65bcc115346e5e','nativeApplicability':'unproven'}
FORMAT='%d|%i|%s|%y|%z|%a|%u|%g|%h|%F'
FIXED_PATH='/system/build.prop'


def probe_commands():
    """Six fixed scripts. Every external FD consumer has explicit self-dup when requested."""
    result=[]
    for fd in (3,4):
        for mode in ('parent','without-selfdup','with-selfdup'):
            target='"/proc/$$/fd/'+str(fd)+'"' if mode=='parent' else '/proc/self/fd/'+str(fd)
            suffix=' '+str(fd)+'>&'+str(fd) if mode=='with-selfdup' else ''
            # Parent PID in $$ belongs to the holding mksh, not an external tool.
            command=('set -eu; test "$(/system/bin/id -u)" = 2000; test ! -L /system/build.prop; '
                     'exec '+str(fd)+'</system/build.prop; '
                     '/system/bin/stat -Lc '+repr(FORMAT)+' '+target+suffix+'; '
                     '/system/bin/sha256sum '+target+suffix)
            result.append({'fd':fd,'mode':mode,'command':command})
    return result


def parse_reply(code,stdout,stderr):
    if type(code)is not int or not isinstance(stdout,bytes) or not isinstance(stderr,bytes) or len(stdout)>4096 or len(stderr)>4096:raise ValueError('fd_probe_reply_unbounded')
    if code!=0:return {'state':'command-failed','exit':code}
    if stderr:raise ValueError('fd_probe_success_stderr')
    lines=stdout.decode('utf-8','strict').splitlines()
    if len(lines)!=2:raise ValueError('fd_probe_reply_shape')
    fields=lines[0].split('|');digest,_,target=lines[1].partition(' ')
    if len(fields)!=10 or fields[-1]!='regular file' or fields[8]!='1' or not re.fullmatch('[0-9a-f]{64}',digest) or not target.strip():raise ValueError('fd_probe_reply_shape')
    return {'state':'descriptor-read','exit':0,'generation':lines[0],'sha256':digest}


def classify(reads):
    if len(reads)!=6:raise ValueError('fd_probe_incomplete')
    parent=None
    for fd in (3,4):
        group=[item for item in reads if item['fd']==fd]
        if [item['mode'] for item in group]!=['parent','without-selfdup','with-selfdup']:raise ValueError('fd_probe_order_changed')
        baseline,negative,positive=[item['result'] for item in group]
        if baseline.get('state')!='descriptor-read' or positive!=baseline:raise ValueError('fd_probe_explicit_handoff_unproven')
        if parent is not None and baseline!=parent:raise ValueError('fd_probe_source_changed')
        parent=baseline
        if negative.get('state')=='descriptor-read' and negative!=baseline:raise ValueError('fd_probe_inconsistent_inheritance')
    return {'state':'fixed-file-descriptor-observed','fileIdentity':parent,'withoutSelfdup':[r['result']['state'] for r in reads if r['mode']=='without-selfdup'],'explicitSelfdupObserved':True,'appProcessInheritance':'not-tested','guestMutationPerformed':False}


def remote_source():
    if frozen.regular_pin(Path(fresh.__file__))['sha256']!=FRESH_SHA:raise ValueError('frozen_fresh_helper_changed')
    source=fresh.remote_source()
    if hashlib.sha256(source.encode()).hexdigest()!=FRESH_REMOTE_SHA:raise ValueError('frozen_fresh_program_changed')
    tree=ast.parse(source);assignment=next(n for n in tree.body if isinstance(n,ast.Assign) and n.targets[0].id=='ADMIT_CHECKS')
    checks=ast.literal_eval(assignment.value)
    old_marker="admitted_value.get('diagnosticSourceSha256')!=diagnostic['diagnosticSourceSha256']"
    if checks.count(old_marker)!=1:raise ValueError('admission_rewrite_changed')
    checks=checks.replace(old_marker,"admitted_value.get('diagnosticSourceSha256')!="+repr(FRESH_REMOTE_SHA))
    checks+='\n'+inspect.getsource(probe_commands)+'\n'+inspect.getsource(parse_reply)+'\n'+inspect.getsource(classify)+r'''
phase='shell-fd-readonly-probe'
shell_fd_reads=[]
for case in probe_commands():
 result=subprocess.run([expected['adb'],'-s',expected['serial'],'shell','-T',case['command']],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10,check=False)
 # traced_run retains exact private bounded raw BEFORE interpretation.
 parsed=parse_reply(result.returncode,result.stdout,result.stderr)
 shell_fd_reads.append({'fd':case['fd'],'mode':case['mode'],'result':parsed})
shell_fd_probe=classify(shell_fd_reads)
phase='shell-fd-closing-guard'
if measure_owner(public_cli)!=fresh_owner_admission:raise ValueError('fresh_owner_closing_drift')
if snapshot_file(admitted_path,1048576)[1]!=admitted_pin:raise ValueError('fresh_owner_admission_generation_changed')
guard_files(pins,paths,parents);verify_manifest();fixture_stopped(output)
phase='shell-fd-observed'
'''
    # Replace both branches: a caller cannot accidentally choose original staging.
    for name in ('CHECKS','ADMIT_CHECKS'):
        node=next(n for n in tree.body if isinstance(n,ast.Assign) and n.targets[0].id==name)
        start=sum(len(line)+1 for line in source.splitlines()[:node.lineno-1]);end=sum(len(line)+1 for line in source.splitlines()[:node.end_lineno])
        source=source[:start]+name+'='+repr(checks)+'\n'+source[end:]
        tree=ast.parse(source)
    source=source.replace('effective_proxy=None;fresh_owner_admission=None;', 'effective_proxy=None;fresh_owner_admission=None;shell_fd_probe=None;',1)
    source=source.replace("'freshOwnerAdmission':fresh_owner_admission,", "'freshOwnerAdmission':fresh_owner_admission,'shellFdProbe':shell_fd_probe,")
    return 'FORMAT='+repr(FORMAT)+'\n'+source


def prepare(root,correlation,current_admission):
    root=Path(root).resolve()
    if any(not isinstance(c,str) or not fresh._UUID.fullmatch(c) for c in (correlation,current_admission)) or correlation==current_admission:raise ValueError('separate_fd_probe_uuid_required')
    original,artifact,pins=fresh._retained(root)
    ca03=root/'.runtime/parity-evidence/android-current/api35-proxy-probe-ca03-receipt.json'
    failure_pin=frozen._private_pin(ca03,1048576)
    if (failure_pin['bytes'],failure_pin['sha256'])!=(CA03_BYTES,CA03_SHA):raise ValueError('ca03_history_changed')
    base=root/'.rag_index/android-proxy-os-fresh-owner'/current_admission
    iraw,igen,isha=old.private_snapshot(base/'intent.json',65536);intent=json.loads(iraw)
    rraw,rgen,rsha=old.private_snapshot(base/'result.json',16384);result=json.loads(rraw)
    if intent.get('mode')!='admit' or intent.get('sourceSha256')!=FRESH_REMOTE_SHA or intent.get('correlationId')!=current_admission or result.get('diagnosticCorrelationId')!=current_admission or result.get('state')!='diagnosed' or result.get('currentFailurePhase')!='fresh-owner-admitted' or result.get('errorType') is not None:raise ValueError('current_positive_admission_required')
    pins+=[failure_pin]+intent['inputPins']
    for name,generation,digest,length in (('intent.json',igen,isha,len(iraw)),('result.json',rgen,rsha,len(rraw))):
        pin=frozen._private_pin(base/name,65536)
        if (pin['generation'],pin['sha256'],pin['bytes'])!=(generation,digest,length):raise ValueError('current_admission_snapshot_changed')
        pins.append(pin)
    pins.append(frozen._private_pin(base/'request.json',65536))
    pins.append(frozen.regular_pin(Path(__file__)));frozen._guard(pins)
    directory=root/'.rag_index/android-shell-fd-probe'/correlation
    directory.parent.mkdir(mode=0o700,exist_ok=True);fd=old._directory(directory.parent);os.close(fd);directory.mkdir(mode=0o700)
    value={'schema':1,'kind':'android-shell-fd-readonly-intent','correlationId':correlation,'currentAdmission':{'correlationId':current_admission,'receiptPin':result['receiptPin']},'original':original,'artifact':artifact,'inputPins':pins,'sourceSha256':hashlib.sha256(remote_source().encode()).hexdigest(),'fixedPath':FIXED_PATH,'mkshPrimary':MKSH_PRIMARY,'nativeAppProcessInheritance':'unproven','guestMutationAllowed':False}
    old._save(directory/'intent.json',value)
    return {'state':'prepared','correlationId':correlation,'nativeExecuted':False,'currentAVDGenerationSupport':'frozen-prefix-only-new-generation-requires-separate-admission','intentPath':str(directory/'intent.json')}


def observe(root,correlation):
    """Root only. Frozen native guards reject old-owner/device-generation drift."""
    root=Path(root).resolve()
    if not isinstance(correlation,str) or not fresh._UUID.fullmatch(correlation):raise ValueError('fd_probe_uuid_required')
    directory=root/'.rag_index/android-shell-fd-probe'/correlation
    raw,gen,digest=old.private_snapshot(directory/'intent.json',65536);value=json.loads(raw)
    if value.get('kind')!='android-shell-fd-readonly-intent' or value.get('sourceSha256')!=hashlib.sha256(remote_source().encode()).hexdigest() or value.get('correlationId')!=correlation:raise ValueError('fd_probe_intent_changed')
    if (directory/'request.json').exists():raise ValueError('fd_probe_consumed_no_replay')
    pin=frozen._private_pin(directory/'intent.json',65536)
    if (pin['generation'],pin['sha256'],pin['bytes'])!=(gen,digest,len(raw)):raise ValueError('fd_probe_intent_snapshot_changed')
    pins=value['inputPins']+[pin];frozen._guard(pins)
    # Close over exact existing dispatch implementation; change program only.
    scope=dict(fresh.__dict__);scope.update({'remote_source':remote_source})
    exec(compile(inspect.getsource(fresh._call),'fixed-readonly-fd-dispatch','exec'),scope)
    return scope['_call'](root,directory,value['original'],value['artifact'],pins,'observe',correlation,value['currentAdmission'])


def remote_collector_source():
    return fresh.remote_collector_source().replace("'fresh-owner-observation-final-guard')", "'fresh-owner-observation-final-guard','shell-fd-readonly-probe','shell-fd-closing-guard','shell-fd-observed')",1)


def collect(root,correlation,collection,*,kind='status',offset=0,expected_pin=None):
    """Existing receipt only; never replay FD commands or getters."""
    if not isinstance(correlation,str) or not fresh._UUID.fullmatch(correlation):raise ValueError('fd_probe_uuid_required')
    source=inspect.getsource(fresh.collect)
    old_directory='directory=_directory(root,correlation)'
    if source.count(old_directory)!=1:raise ValueError('collector_source_changed')
    source=source.replace(old_directory,"directory=root/'.rag_index/android-shell-fd-probe'/correlation",1)
    scope=dict(fresh.__dict__);scope.update({'remote_source':remote_source,'remote_collector_source':remote_collector_source})
    exec(compile(source,'fixed-fd-receipt-collector','exec'),scope)
    return scope['collect'](root,correlation,collection,kind=kind,offset=offset,expected_pin=expected_pin)
