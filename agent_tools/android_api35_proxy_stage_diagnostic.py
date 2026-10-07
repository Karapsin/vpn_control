"""Read-only current census of one consumed API35 proxy stage; never replay."""
from __future__ import annotations
import ast
import base64
import hashlib
import json
from pathlib import Path
from . import android_api35_current_proxy_probe as consumed
from . import android_device_availability as availability

SOURCE_SHA='bff6eac22e615e15e895324810c00be3fe64d62fefc5ad7f78b00d14cd745e52'
CORRELATION='bd14e4a6-745b-45f9-be33-601fb775b4cf'
CAPSULE='android-api35-current-proxy-c8c48798-01b9-4682-af8c-0e4e39f5fe87'
RESULT_FILE_SHA='639cf35bec096248ce36ba9d55928f8be998345e986ba2f58c3194992dc0b1e6'
RESULT_SHA='a5e5531db66b3e3cc1bc02ae468c6721f6471719ee5ebe2daa8e884c5683ca20'
_OBSERVER=r'''
RETAINED=__RETAINED__

def diagnostic_command():
 quote=__import__('shlex').quote;directory,path=probe_paths();fmt=quote('%d|%i|%s|%y|%z|%a|%u|%g|%h|%F');emptyfmt=quote('%a|%u|%h|%s|%F')
 return ('set -eu; uid=$(/system/bin/id -u); printf "uid:%s\\n" "$uid"; '
  'test "$uid" = 2000 || exit 0; '
  'if test -L '+directory+'; then printf "blocked:parent-symlink\\n"; exit 0; fi; '
  'if ! test -d '+directory+'; then printf "blocked:parent-absent\\n"; exit 0; fi; '
  'printf "parent:"; /system/bin/stat -c '+fmt+' '+directory+'; '
  'if test -L '+path+'; then printf "blocked:file-symlink\\n"; exit 0; fi; '
  'if ! test -f '+path+'; then printf "blocked:file-absent\\n"; exit 0; fi; '
  'printf "file:"; /system/bin/stat -c '+fmt+' '+path+'; '
  'if ! test -r '+path+'; then printf "blocked:file-inaccessible\\n"; exit 0; fi; '
  'exec 4<'+path+'; printf "fd4:"; /system/bin/stat -Lc '+fmt+' /proc/self/fd/4 4>&4; '
  'printf "empty-predicate:"; /system/bin/stat -Lc '+emptyfmt+' /proc/self/fd/4 4>&4; '
  'printf "sha256:"; /system/bin/sha256sum /proc/self/fd/4 4>&4; '
  'printf "parent-after:"; /system/bin/stat -c '+fmt+' '+directory+'; '
  'printf "file-after:"; /system/bin/stat -c '+fmt+' '+path+'; '
  'printf "fd4-after:"; /system/bin/stat -Lc '+fmt+' /proc/self/fd/4 4>&4')

def diagnostic_parse(reply):
 lines=probe_lines(reply);rows={}
 for line in lines:
  label,separator,value=line.partition(':')
  if not separator or label in rows or label not in ('uid','parent','file','fd4','empty-predicate','sha256','parent-after','file-after','fd4-after','blocked'):raise ValueError('diagnostic_reply_shape')
  rows[label]=value
 if rows.get('uid')!='2000':return {'phase':'shell-uid','complete':False,'blocked':'uid-not-shell'}
 if 'blocked' in rows:
  if rows['blocked'] not in ('parent-symlink','parent-absent','file-symlink','file-absent','file-inaccessible'):raise ValueError('diagnostic_reply_shape')
  return {'phase':'stage-path','complete':False,'blocked':rows['blocked']}
 if set(rows)!=set(('uid','parent','file','fd4','empty-predicate','sha256','parent-after','file-after','fd4-after')):raise ValueError('diagnostic_reply_shape')
 if rows['parent']!=rows['parent-after'] or any(rows['file']!=rows[key] for key in ('fd4','file-after','fd4-after')):raise ValueError('diagnostic_stage_changed')
 parent=rows['parent'].split('|');leaf=rows['file'].split('|');empty=rows['empty-predicate'].split('|');digest,_,target=rows['sha256'].partition(' ')
 if len(parent)!=10 or len(leaf)!=10 or len(empty)!=5 or not re.fullmatch('[0-9a-f]{64}',digest) or target.strip()!='/proc/self/fd/4':raise ValueError('diagnostic_reply_shape')
 # Report measured predicates without changing the consumed program's guard.
 if empty!=[leaf[i] for i in (5,6,8,2,9)]:raise ValueError('diagnostic_fd_facts_changed')
 return {'phase':'empty-fd-predicate','complete':True,'parentPrivate':parent[5:7]==['700','2000'] and parent[-1]=='directory','filePrivateSingleLink':leaf[5:7]==['600','2000'] and leaf[8]=='1','size':int(leaf[2]) if leaf[2].isdigit() else None,'type':leaf[-1],'legacyEmptyPredicateMatches':rows['empty-predicate']=='600|2000|1|0|regular file','fileSha256':digest,'parentGeneration':rows['parent'],'fileGeneration':rows['file']}

def observed_getter(directory):
 global GETTER_RECORDS,GETTER_APK_PASS
 GETTER_RECORDS={'shellFdReads':[]};stages=[];observations=[];failure=None;closing=False
 try:
  stages.append(getter_stage());getter_generation(directory);probe_fence_guard(directory,RETAINED['stageFence']);GETTER_APK_PASS='Before'
  apk=getter_apk();GETTER_RECORDS['observedPackageBefore']=apk
  if apk!=GETTER['packageSha256']:raise ValueError('getter_package_changed')
  GETTER_RECORDS['statusBefore']=getter_cli(['status'],FD_OWNER);before=fd_guard_reply(GETTER_RECORDS['statusBefore'],'status')
  GETTER_RECORDS['operationsBefore']=getter_cli(['operations','list'],FD_OWNER);fd_guard_reply(GETTER_RECORDS['operationsBefore'],'operations')
  try:
   for _ in range(2):
    probe_fence_guard(directory,RETAINED['stageFence']);case={'fd':4,'mode':'stage-diagnostic','command':diagnostic_command()};observations.append(diagnostic_parse(diagnostic_read(case)))
  except (ValueError,OSError,UnicodeError,subprocess.TimeoutExpired) as error:
   failure=str(error) if isinstance(error,ValueError) and re.fullmatch(r'(?:diagnostic|probe|getter)_[a-z_]{1,72}',str(error)) else 'diagnostic_read_unknown'
  GETTER_RECORDS['operationsAfter']=getter_cli(['operations','list'],FD_OWNER);fd_guard_reply(GETTER_RECORDS['operationsAfter'],'operations')
  GETTER_RECORDS['statusAfter']=getter_cli(['status'],FD_OWNER);after=fd_guard_reply(GETTER_RECORDS['statusAfter'],'status')
  if before!=after:raise ValueError('diagnostic_status_changed')
  GETTER_APK_PASS='After';apk=getter_apk();GETTER_RECORDS['observedPackageAfter']=apk
  if apk!=GETTER['packageSha256']:raise ValueError('getter_package_changed')
  getter_generation(directory);stages.append(getter_stage());probe_fence_guard(directory,RETAINED['stageFence'])
  if stages[0]!=stages[1]:raise ValueError('getter_stage_generation_changed')
  closing=True
  if failure is None and (len(observations)!=2 or observations[0]!=observations[1]):failure='diagnostic_observation_changed'
 except (ValueError,OSError,KeyError,TypeError,UnicodeError,subprocess.TimeoutExpired) as error:
  failure=str(error) if isinstance(error,ValueError) and re.fullmatch(r'(?:diagnostic|probe|getter|coldboot|census|alias)_[a-z_]{1,72}',str(error)) else 'diagnostic_guard_rejected'
 return {'state':'diagnostic-only','reason':failure,'observations':observations,'closingGuardsVerified':closing,'records':GETTER_RECORDS,'cliStagePins':stages,'originalCorrelationId':PROBE['correlationId'],'originalOutcome':'unknown','originalResultSha256':RETAINED['resultSha256'],'stageMutationPerformed':False,'appProcessExecuted':False,'replayAllowed':False,'productAdmitted':False,'acceptanceComplete':False}
'''


def compose(program,own_raw,retained):
    tree=ast.parse(program)
    if ast.unparse(tree.body[-1])!='coldboot_dispatch()':raise ValueError('diagnostic_dispatch_changed')
    remove={'probe_fence','probe_stage_command','probe_getter_command','probe_generation_command','parse_probe_current','parse_probe','probe_generation','observed_getter'}
    tree.body=[n for n in tree.body if not isinstance(n,ast.FunctionDef) or n.name not in remove];tree.body.pop()
    reader=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='probe_read');reader.name='diagnostic_read'
    reader.body[0]=ast.parse("if case!={'fd':4,'mode':'stage-diagnostic','command':diagnostic_command()}:raise ValueError('diagnostic_fixed_command_required')").body[0]
    template=ast.literal_eval(next(n.value for n in ast.parse(own_raw).body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='_OBSERVER' for t in n.targets)))
    result=ast.unparse(tree)+'\n'+template.replace('__RETAINED__',repr(retained))+'\ncoldboot_dispatch()\n'
    compile(result,'<fixed-stage-diagnostic>','exec');consumed.admission.original.validate_readonly(result);return result


def prepare(root:Path,reservation:dict)->dict:
    root=Path(root).absolute();source=Path(consumed.__file__).absolute();snapshot=availability._snapshot(source)
    if hashlib.sha256(snapshot[1]).hexdigest()!=SOURCE_SHA:raise ValueError('diagnostic_consumed_source_changed')
    prepared=consumed.prepare(root,reservation,CORRELATION)
    if availability._snapshot(source)!=snapshot:raise ValueError('diagnostic_consumed_source_changed')
    prepared['snapshots'][source]=snapshot
    path=root/'.runtime/parity-evidence'/CAPSULE/'stdout-0.private'
    receipt_snapshot=availability._snapshot(path);prepared['snapshots'][path]=receipt_snapshot
    if hashlib.sha256(receipt_snapshot[1]).hexdigest()!=RESULT_FILE_SHA:raise ValueError('diagnostic_consumed_receipt_changed')
    raw=b''.join(base64.b64decode(line[4:],validate=True) for line in receipt_snapshot[1].decode('ascii').splitlines() if line.startswith('out:'))
    if hashlib.sha256(raw).hexdigest()!=RESULT_SHA:raise ValueError('diagnostic_consumed_result_changed')
    value=json.loads(raw)
    if value.get('correlationId')!=CORRELATION or value.get('state')!='diagnostic-only' or value.get('reason')!='probe_command_unknown' or value.get('closingGuardsVerified')is not True or value.get('effectiveProxy')is not None or value['records']['stageReply']['exitCode']!=1 or value['records']['stageReply']['stdoutBase64']!='' or value['records']['stageReply']['stderrBase64']!='':raise ValueError('diagnostic_consumed_outcome_changed')
    own=Path(__file__).absolute();own_snapshot=availability._snapshot(own);prepared['snapshots'][own]=own_snapshot
    prepared['program']=compose(prepared['program'],own_snapshot[1],{'stageFence':value['stageFence'],'resultSha256':RESULT_SHA});guard_prepared(prepared);return prepared


def guard_prepared(prepared):consumed.guard_prepared(prepared)
def ssh_carrier(prepared):return consumed.ssh_carrier(prepared)
