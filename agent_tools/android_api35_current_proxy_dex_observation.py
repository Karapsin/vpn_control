"""Fixed current API35 read-only census of the historical proxy probe artifact."""
from __future__ import annotations
import ast
import hashlib
import json
from pathlib import Path
from . import android_api35_coldboot_fd_observation as transport
from . import android_api35_coldboot_product_observation as original
from . import android_device_availability as availability

ORIGINAL_SHA='c908a23200cf633c9db6a2ccfc057f2e360267519153593a23c4471fbefe528b'
TRANSPORT_SHA='0749ebd2313ae1c5d24ec94efea03cf92d4319ecc26504bd6791ef6e7cd5c336'
JAVA_SHA='7bdf36cfed66df1e022be0e2a6a0d886153e51e078b7422346bd44cc2e838585'
DEX_SHA='9d8166f140df3bff4223776345f9982a4b70b9f65c7eddb992f782f22aa5fa16'
DEX_BYTES=4948
HISTORY='4f77a912-98c5-411d-aab6-7b7eecce22b6'
_OBSERVER=r'''
DEX_SHA=__DEX_SHA__
DEX_BYTES=4948
DEX_PARENT='/data/local/tmp/vpn-control-os-proxy-ca03d25b-fd58-4998-b4f5-af9c0d9d1b1b'
DEX_PATH=DEX_PARENT+'/classes.dex'
FD_OWNER='d475487c-fe93-418c-9f10-5db954723a43'

def dex_command():
 quote=__import__('shlex').quote
 fmt=quote('%d|%i|%s|%y|%z|%a|%u|%g|%h|%F')
 # Fixed finite markers precede all descriptor consumers. No fallback path.
 parent=quote(DEX_PARENT);path=quote(DEX_PATH)
 return ('set -eu; test "$(/system/bin/id -u)" = 2000; '
  'if test -L '+parent+'; then printf "dex-parent-unsafe\\n"; exit 0; fi; '
  'if ! test -e '+parent+'; then printf "dex-absent\\n"; exit 0; fi; '
  'test -d '+parent+' && test "$(/system/bin/stat -c '+quote('%a|%u|%F')+' '+parent+')" = '+quote('700|2000|directory')+' || { printf "dex-parent-unsafe\\n"; exit 0; }; '
  'if test -L '+path+'; then printf "dex-file-unsafe\\n"; exit 0; fi; '
  'if ! test -e '+path+'; then printf "dex-absent\\n"; exit 0; fi; '
  'test -f '+path+' && test -r '+path+' && test "$(/system/bin/stat -c '+quote('%a|%u|%h|%F')+' '+path+')" = '+quote('600|2000|1|regular file')+' || { printf "dex-file-unsafe\\n"; exit 0; }; '
  '/system/bin/stat -c '+fmt+' '+parent+' '+path+'; exec 3<'+path+'; '
  '/system/bin/stat -Lc '+fmt+' /proc/self/fd/3 3>&3; /system/bin/sha256sum /proc/self/fd/3 3>&3; '
  '/system/bin/stat -c '+fmt+' '+parent+' '+path+'; /system/bin/stat -Lc '+fmt+' /proc/self/fd/3 3>&3')

def parse_reply(code,stdout,stderr):
 if type(code)is not int or not isinstance(stdout,bytes) or not isinstance(stderr,bytes) or len(stdout)>4096 or len(stderr)>4096:raise ValueError('dex_reply_unbounded')
 if code!=0:return {'state':'inaccessible','exitCode':code}
 if stderr:raise ValueError('dex_success_stderr')
 lines=stdout.decode('utf-8','strict').splitlines()
 if len(lines)==1 and lines[0] in ('dex-absent','dex-parent-unsafe','dex-file-unsafe'):return {'state':lines[0][4:]}
 if len(lines)!=7:raise ValueError('dex_reply_shape')
 if lines[0]!=lines[4] or lines[1]!=lines[2] or lines[1]!=lines[5] or lines[1]!=lines[6]:raise ValueError('dex_generation_changed')
 parent=lines[0].split('|');leaf=lines[1].split('|');digest,_,target=lines[3].partition(' ')
 if len(parent)!=10 or len(leaf)!=10 or parent[5:7]!=['700','2000'] or parent[-1]!='directory' or leaf[5:7]!=['600','2000'] or leaf[8:]!=['1','regular file'] or not leaf[2].isdigit() or not re.fullmatch('[0-9a-f]{64}',digest) or target.strip()!='/proc/self/fd/3':raise ValueError('dex_reply_shape')
 size=int(leaf[2]);state='empty' if size==0 else 'matching' if size==DEX_BYTES and digest==DEX_SHA else 'mismatched'
 return {'state':state,'parentGeneration':lines[0],'fileGeneration':lines[1],'bytes':size,'sha256':digest}

def observed_getter(directory):
 global GETTER_RECORDS,GETTER_APK_PASS
 GETTER_RECORDS={'shellFdReads':[]};stage=[];failure=None;observations=[];closing=False
 try:
  stage.append(getter_stage());getter_generation(directory);GETTER_APK_PASS='Before'
  apk=getter_apk();GETTER_RECORDS['observedPackageBefore']=apk
  if apk!=GETTER['packageSha256']:raise ValueError('getter_package_changed')
  GETTER_RECORDS['statusBefore']=getter_cli(['status'],FD_OWNER);before=fd_guard_reply(GETTER_RECORDS['statusBefore'],'status')
  GETTER_RECORDS['operationsBefore']=getter_cli(['operations','list'],FD_OWNER);fd_guard_reply(GETTER_RECORDS['operationsBefore'],'operations')
  try:
   for _ in range(2):observations.append(dex_read({'fd':3,'mode':'dex-census','command':dex_command()}))
  except (ValueError,OSError,UnicodeError,subprocess.TimeoutExpired) as error:
   failure=str(error) if isinstance(error,ValueError) and re.fullmatch(r'(?:dex|fd_probe|getter)_[a-z_]{1,72}',str(error)) else 'dex_read_unknown'
  GETTER_RECORDS['operationsAfter']=getter_cli(['operations','list'],FD_OWNER);fd_guard_reply(GETTER_RECORDS['operationsAfter'],'operations')
  GETTER_RECORDS['statusAfter']=getter_cli(['status'],FD_OWNER);after=fd_guard_reply(GETTER_RECORDS['statusAfter'],'status')
  if before!=after:raise ValueError('dex_status_changed')
  GETTER_APK_PASS='After';apk=getter_apk();GETTER_RECORDS['observedPackageAfter']=apk
  if apk!=GETTER['packageSha256']:raise ValueError('getter_package_changed')
  getter_generation(directory);stage.append(getter_stage())
  if stage[0]!=stage[1]:raise ValueError('getter_stage_generation_changed')
  closing=True
  if failure is None and (len(observations)!=2 or observations[0]!=observations[1]):failure='dex_observation_changed'
 except (ValueError,OSError,KeyError,TypeError,UnicodeError,subprocess.TimeoutExpired) as error:
  failure=str(error) if isinstance(error,ValueError) and re.fullmatch(r'(?:dex|fd_probe|getter|coldboot|census|alias)_[a-z_]{1,72}',str(error)) else 'dex_guard_rejected'
 matching=failure is None and closing and len(observations)==2 and observations[0].get('state')=='matching'
 return {'state':'current-dex-observed' if failure is None and closing else 'diagnostic-only','reason':failure,'dexAdmitted':matching,'observations':observations,'closingGuardsVerified':closing,'records':GETTER_RECORDS,'cliStagePins':stage,'productAdmitted':False,'acceptanceComplete':False,'historicalUnknownsPreserved':True,'appProcessExecuted':False,'guestMutationPerformed':False}
'''

def compose(program,transport_raw,own_raw):
    tree=ast.parse(program)
    names={'current_getter','observed_getter'}
    if {n.name for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in names}!=names or ast.unparse(tree.body[-1])!='coldboot_dispatch()':raise ValueError('dex_composition_changed')
    tree.body=[n for n in tree.body if not isinstance(n,ast.FunctionDef) or n.name not in names];tree.body.pop()
    frozen=ast.literal_eval(next(n.value for n in ast.parse(transport_raw).body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='_OBSERVER' for t in n.targets)))
    funcs=[n for n in ast.parse(frozen).body if isinstance(n,ast.FunctionDef) and n.name in ('fd_read','fd_guard_reply')]
    if len(funcs)!=2:raise ValueError('dex_transport_changed')
    reader=next(n for n in funcs if n.name=='fd_read');reader.name='dex_read'
    if ast.unparse(reader.body[0])!="if case not in probe_commands():\n    raise ValueError('fd_probe_fixed_command_required')":raise ValueError('dex_fixed_reader_changed')
    reader.body[0]=ast.parse("if case != {'fd':3,'mode':'dex-census','command':dex_command()}:raise ValueError('dex_fixed_command_required')").body[0]
    template=ast.literal_eval(next(n.value for n in ast.parse(own_raw).body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='_OBSERVER' for t in n.targets)))
    result=ast.unparse(tree)+'\n'+ast.unparse(ast.Module(body=funcs,type_ignores=[]))+'\n'+template.replace('__DEX_SHA__',repr(DEX_SHA))+'\ncoldboot_dispatch()\n'
    compile(result,'<current-dex-census>','exec');original.validate_readonly(result);return result

def prepare(root:Path,reservation:dict)->dict:
    root=Path(root).absolute();original_path=Path(original.__file__).absolute()
    original_snapshot=availability._snapshot(original_path)
    if hashlib.sha256(original_snapshot[1]).hexdigest()!=ORIGINAL_SHA:raise ValueError('dex_original_source_changed')
    prepared=original.prepare(root,reservation)
    if availability._snapshot(original_path)!=original_snapshot or prepared['snapshots'].get(original_path)!=original_snapshot:raise ValueError('dex_original_source_changed')
    prepared['snapshots'][original_path]=original_snapshot
    def saved(path,limit=65536):
        pin,raw=availability._snapshot(path)
        if len(raw)>limit:raise ValueError('dex_local_input_unbounded')
        prepared['snapshots'][path]=(pin,raw);return pin,raw
    transport_path=Path(transport.__file__).absolute();_,transport_raw=saved(transport_path)
    if hashlib.sha256(transport_raw).hexdigest()!=TRANSPORT_SHA:raise ValueError('dex_transport_source_changed')
    source=root/'agent_tools/fixtures/android_proxy_os_probe/ProxyProbe.java';_,java=saved(source)
    if hashlib.sha256(java).hexdigest()!=JAVA_SHA:raise ValueError('dex_java_changed')
    base=root/'.rag_index/android-proxy-os-observation'/HISTORY
    intent_pin,intent_raw=saved(base/'intent.json');intent=json.loads(intent_raw)
    _,artifact_raw=saved(base/'artifact.json');artifact=json.loads(artifact_raw)
    compiler_pin,compiler_raw=saved(base/'compiler-receipt.json');compiler=json.loads(compiler_raw)
    dex_pin,dex=saved(base/'dex/classes.dex',16384)
    if artifact.get('correlationId')!=HISTORY or compiler.get('correlationId')!=HISTORY or artifact.get('javaSha256')!=JAVA_SHA or compiler.get('javaSha256')!=JAVA_SHA or compiler.get('artifactSha256')!=DEX_SHA or len(dex)!=DEX_BYTES or hashlib.sha256(dex).hexdigest()!=DEX_SHA or dex[:8]!=b'dex\n039\x00':raise ValueError('dex_compilation_binding_changed')
    if intent.get('correlationId')!=HISTORY or intent.get('javaSha256')!=JAVA_SHA or intent.get('artifactPath')!=str(base/'dex/classes.dex') or compiler.get('intentPin')!=artifact.get('intentPin') or len(compiler.get('commands',[]))!=2 or any(type(item.get('exit')) is not int or item['exit']!=0 for item in compiler['commands']):raise ValueError('dex_compiler_receipt_changed')
    for actual,raw,expected in ((intent_pin,intent_raw,artifact['intentPin']),(compiler_pin,compiler_raw,artifact['compilerReceiptPin']),(dex_pin,dex,artifact['artifactPin'])):
        historical=[*actual[:5],actual[5]&0o777,actual[6],actual[8]]
        if historical!=expected['generation'] or hashlib.sha256(raw).hexdigest()!=expected['sha256']:raise ValueError('dex_artifact_generation_changed')
    own=Path(__file__).absolute();_,own_raw=saved(own)
    prepared['program']=compose(prepared['program'],transport_raw,own_raw);guard_prepared(prepared);return prepared

def guard_prepared(prepared):original.guard_prepared(prepared)
def ssh_carrier(prepared):return original.ssh_carrier(prepared)
