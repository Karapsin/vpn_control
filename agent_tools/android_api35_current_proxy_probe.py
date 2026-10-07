"""One separately fenced current API35 tooling stage and read-only Binder getter.

Unknown outcomes consume the correlation. Old stages, owners and leases do not
supply current authority. The guest stage is retained; no cleanup is performed.
"""
from __future__ import annotations
import ast
import base64
import hashlib
from pathlib import Path
import re
import uuid
from . import android_api35_current_proxy_dex_observation as admission
from . import android_proxy_os_observation as historical
from . import android_device_availability as availability

ADMISSION_SHA='9979cf2ef451f5676242c90924f683c37068e63b3aeb7fcc51bcd342c1a4673e'
HISTORICAL_SHA='11d72ae85282669ed6ed62805bbb01f16b1300f8abc9bfcec672fd8ed16a474d'
_OBSERVER=r'''
PROBE=__PROBE__
FD_OWNER='d475487c-fe93-418c-9f10-5db954723a43'

def probe_paths():
 directory='/data/local/tmp/vpn-control-os-proxy-'+PROBE['correlationId']
 return directory,directory+'/classes.dex'

def probe_original_records(directory):
 chain,unused=parent_fds(directory/'__probe_records__');guard_parents(chain);parent=os.dup(chain[-1]['fd']);records={}
 try:
  for name in ('intent.json','attempt.json','ready.json','child.json','exec-released.json','emulator-child.json'):
   fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=parent)
   try:
    before=fp(os.fstat(fd))
    if not stat.S_ISREG(before[5]) or before[6:9]!=[0,0,1] or stat.S_IMODE(before[5])!=0o600 or before[2]>262144:raise ValueError('probe_original_record_unsafe')
    raw=b''
    while len(raw)<=262144:
     part=os.read(fd,min(65536,262145-len(raw)))
     if not part:break
     raw+=part
    if len(raw)>262144 or before!=fp(os.fstat(fd)) or before!=fp(os.stat(name,dir_fd=parent,follow_symlinks=False)):raise ValueError('probe_original_record_changed')
    records[name]={'generation':before,'sha256':hashlib.sha256(raw).hexdigest()}
   finally:os.close(fd)
  guard_parents(chain);return records
 finally:os.close(parent);close_parents(chain)

def probe_fence_guard(directory,fence):
 if fp(directory.lstat())!=fence['parentGeneration'] or probe_original_records(directory)!=fence['originalRecords']:raise ValueError('probe_original_record_changed')
 chain,unused=parent_fds(directory/'__probe_guard__');guard_parents(chain);parent=os.dup(chain[-1]['fd'])
 try:
  if fp(os.fstat(parent))!=fence['parentGeneration'] or sorted(os.listdir(parent))!=fence['parentInventory']:raise ValueError('probe_journal_parent_changed')
  child=os.open('proxy-probe-'+PROBE['correlationId'],os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
  try:
   if fp(os.fstat(child))!=fence['journalGeneration'] or fp(os.stat('proxy-probe-'+PROBE['correlationId'],dir_fd=parent,follow_symlinks=False))!=fence['journalGeneration'] or sorted(os.listdir(child))!=['intent.json','stage-fence.json']:raise ValueError('probe_journal_changed')
   for name,pin in fence['fenceRecords'].items():
    fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=child)
    try:
     if fp(os.fstat(fd))!=pin['generation'] or fp(os.stat(name,dir_fd=child,follow_symlinks=False))!=pin['generation']:raise ValueError('probe_fence_record_changed')
     raw=os.read(fd,262145)
     if len(raw)>262144 or hashlib.sha256(raw).hexdigest()!=pin['sha256'] or fp(os.fstat(fd))!=pin['generation']:raise ValueError('probe_fence_record_changed')
    finally:os.close(fd)
  finally:os.close(child)
  guard_parents(chain)
 finally:os.close(parent);close_parents(chain)

def probe_fence(directory):
 # This per-device invocation already holds the inherited original device lock.
 # Place the new durable fence below the authenticated original journal, so its
 # creation does not alter the shared ROOT generation held by that dispatcher.
 chain,unused=parent_fds(directory/'__probe_fence__');guard_parents(chain);parent=os.dup(chain[-1]['fd']);child=None
 try:
  prior=fp(os.fstat(parent));named=fp(directory.lstat())
  if prior!=named or not stat.S_ISDIR(prior[5]) or prior[6:8]!=[0,0] or stat.S_IMODE(prior[5])!=0o700:raise ValueError('probe_journal_parent_unsafe')
  original_records=probe_original_records(directory);inventory=sorted(os.listdir(parent))
  if len(inventory)>128:raise ValueError('probe_journal_inventory_unbounded')
  name='proxy-probe-'+PROBE['correlationId']
  try:os.mkdir(name,0o700,dir_fd=parent)
  except FileExistsError:raise ValueError('probe_correlation_consumed')
  after=fp(os.fstat(parent))
  if any(after[n]!=prior[n] for n in (0,1,5,6,7)) or after[8]!=prior[8]+1 or fp(directory.lstat())!=after or sorted(os.listdir(parent))!=sorted(inventory+[name]) or probe_original_records(directory)!=original_records:raise ValueError('probe_journal_parent_changed')
  chain[-1]['pin']=after;guard_parents(chain)
  child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
  child_pin=fp(os.fstat(child))
  if child_pin!=fp(os.stat(name,dir_fd=parent,follow_symlinks=False)) or not stat.S_ISDIR(child_pin[5]) or child_pin[6:8]!=[0,0] or stat.S_IMODE(child_pin[5])!=0o700:raise ValueError('probe_journal_unsafe')
  def guard():
   guard_parents(chain)
   if fp(os.fstat(parent))!=after or fp(directory.lstat())!=after or fp(os.fstat(child))!=child_pin or fp(os.stat(name,dir_fd=parent,follow_symlinks=False))!=child_pin:raise ValueError('probe_journal_changed')
  child_inventory=[];fence_records={}
  for leaf,value in (('intent.json',{'schema':1,'correlationId':PROBE['correlationId'],'sourceSha256':PROBE['sourceSha256'],'artifactSha256':PROBE['artifactSha256'],'javaSha256':PROBE['javaSha256'],'generation':GETTER['generation'],'controllerId':FD_OWNER,'configurationRevision':0,'guestPath':probe_paths()[0],'productMutationAllowed':False}),('stage-fence.json',{'correlationId':PROBE['correlationId'],'effect':'create-only-fixed-dex-stage','replayAllowed':False})):
   guard();before=child_pin;fd=os.open(leaf,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=child)
   try:
    raw=(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode();at=0
    while at<len(raw):
     count=os.write(fd,raw[at:])
     if count<=0:raise ValueError('probe_fence_write_incomplete')
     at+=count
    os.fsync(fd);info=os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_gid!=0 or info.st_nlink!=1 or stat.S_IMODE(info.st_mode)!=0o600 or info.st_size!=len(raw) or fp(info)!=fp(os.stat(leaf,dir_fd=child,follow_symlinks=False)):raise ValueError('probe_fence_file_changed')
    os.lseek(fd,0,os.SEEK_SET)
    if os.read(fd,len(raw)+1)!=raw or fp(os.fstat(fd))!=fp(info):raise ValueError('probe_fence_file_changed')
    fence_records[leaf]={'generation':fp(info),'sha256':hashlib.sha256(raw).hexdigest()}
   finally:os.close(fd)
   child_inventory.append(leaf)
   if sorted(os.listdir(child))!=sorted(child_inventory):raise ValueError('probe_fence_inventory_changed')
   child_pin=fp(os.fstat(child))
   if any(child_pin[n]!=before[n] for n in (0,1,5,6,7,8)):raise ValueError('probe_fence_parent_changed')
   os.fsync(child);guard()
  os.fsync(parent)
  return {'correlationId':PROBE['correlationId'],'parentGeneration':after,'journalGeneration':child_pin,'parentInventory':sorted(inventory+[name]),'originalRecords':original_records,'fenceRecords':fence_records,'stageFenceDurable':True,'replayAllowed':False}
 finally:
  if child is not None:os.close(child)
  os.close(parent);close_parents(chain)

def probe_stage_command():
 quote=__import__('shlex').quote;directory,path=probe_paths();fmt=quote('%d|%i|%s|%y|%z|%a|%u|%g|%h|%F');dfmt=quote('%d|%i|%a|%u|%F')
 return ('set -eu; test "$(/system/bin/id -u)" = 2000; umask 077; '
  'test ! -e '+directory+'; test ! -L '+directory+'; /system/bin/mkdir -m 700 '+directory+'; '
  'CDPATH=; cd -P '+directory+'; test "$(/system/bin/stat -c '+quote('%a|%u|%F')+' .)" = '+quote('700|2000|directory')+'; '
  'before=$(/system/bin/stat -c '+dfmt+' .); test "$before" = "$(/system/bin/stat -c '+dfmt+' '+directory+')"; '
  'test ! -e ./classes.dex; test ! -L ./classes.dex; set -C; exec 4>./classes.dex; set +C; '
  'test "$(/system/bin/stat -Lc '+quote('%a|%u|%h|%s|%F')+' /proc/self/fd/4 4>&4)" = '+quote('600|2000|1|0|regular empty file')+'; '
  'held=$(/system/bin/stat -Lc '+fmt+' /proc/self/fd/4 4>&4); test "$held" = "$(/system/bin/stat -c '+fmt+' ./classes.dex)"; '
  'test "$before" = "$(/system/bin/stat -c '+dfmt+' '+directory+')"; '
  'printf %s '+quote(PROBE['dexBase64'])+' | /system/bin/base64 -d >&4; '
  'held=$(/system/bin/stat -Lc '+fmt+' /proc/self/fd/4 4>&4); test "$held" = "$(/system/bin/stat -c '+fmt+' ./classes.dex)"; '
  'test "$before" = "$(/system/bin/stat -c '+dfmt+' '+directory+')"; '
  'printf "%s\\n" "$before"; /system/bin/stat -c '+fmt+' '+directory+' ./classes.dex; printf "%s\\n" "$held"; /system/bin/sha256sum /proc/self/fd/4 4>&4')

def probe_generation_command():
 quote=__import__('shlex').quote;directory,path=probe_paths();fmt=quote('%d|%i|%s|%y|%z|%a|%u|%g|%h|%F')
 return ('set -eu; test "$(/system/bin/id -u)" = 2000; test ! -L '+directory+'; test ! -L '+path+'; '
  '/system/bin/stat -c '+fmt+' '+directory+' '+path+'; exec 3<'+path+'; '
  '/system/bin/stat -Lc '+fmt+' /proc/self/fd/3 3>&3; /system/bin/sha256sum /proc/self/fd/3 3>&3; '
  '/system/bin/stat -c '+fmt+' '+directory+' '+path+'; /system/bin/stat -Lc '+fmt+' /proc/self/fd/3 3>&3')

def probe_getter_command(file_generation):
 quote=__import__('shlex').quote;directory,path=probe_paths();fmt=quote('%d|%i|%s|%y|%z|%a|%u|%g|%h|%F')
 return ('set -eu; test "$(/system/bin/id -u)" = 2000; test ! -L '+directory+'; test ! -L '+path+'; exec 3<'+path+'; '
  'test "$(/system/bin/stat -Lc '+fmt+' /proc/self/fd/3 3>&3)" = '+quote(file_generation)+'; '
  'got=$(/system/bin/sha256sum /proc/self/fd/3 3>&3); test "${got%% *}" = '+PROBE['artifactSha256']+'; '
  'CLASSPATH=/proc/self/fd/3 /system/bin/app_process /system/bin ProxyProbe '+PROBE['correlationId']+' 3>&3')

def probe_reply(code,stdout,stderr):
 if type(code)is not int or not isinstance(stdout,bytes) or not isinstance(stderr,bytes) or len(stdout)>16384 or len(stderr)>16384:raise ValueError('probe_reply_unbounded')
 return {'exitCode':code,'stdoutBase64':base64.b64encode(stdout).decode(),'stderrBase64':base64.b64encode(stderr).decode()}

def probe_lines(reply):
 if reply['exitCode']!=0:raise ValueError('probe_command_unknown')
 if base64.b64decode(reply['stderrBase64'],validate=True):raise ValueError('probe_success_stderr')
 return base64.b64decode(reply['stdoutBase64'],validate=True).decode('utf-8','strict').splitlines()

def probe_generation(reply):
 lines=probe_lines(reply)
 if len(lines)!=7 or lines[0]!=lines[4] or any(lines[1]!=lines[i] for i in (2,5,6)):raise ValueError('probe_stage_generation_changed')
 parent=lines[0].split('|');leaf=lines[1].split('|')
 if len(parent)!=10 or len(leaf)!=10 or parent[5:7]!=['700','2000'] or parent[-1]!='directory' or leaf[2]!=str(PROBE['artifactBytes']) or leaf[5:7]!=['600','2000'] or leaf[8:]!=['1','regular file'] or lines[3].split()!=[PROBE['artifactSha256'],'/proc/self/fd/3']:raise ValueError('probe_stage_unsafe')
 return {'directory':lines[0],'file':lines[1],'sha256':PROBE['artifactSha256']}

def parse_probe_current(reply):
 raw=base64.b64decode(reply['stdoutBase64'],validate=True)
 if reply['exitCode']!=0:raise ValueError('probe_getter_execution_unknown')
 if base64.b64decode(reply['stderrBase64'],validate=True):raise ValueError('probe_getter_success_stderr')
 value=parse_probe(raw,PROBE['correlationId'])
 if type(value.get('schema'))is not int or value['schema']!=1 or set(value)!={'schema','state','uid','correlationId','reads'}:raise ValueError('probe_getter_schema_changed')
 for read in value['reads']:
  for proxy in read.values():
   if proxy is not None and (proxy['host'] is not None and len(proxy['host'])>4096 or len(proxy['pacUrl'])>4096 or any(len(item)>4096 for item in proxy['exclusionList'])):raise ValueError('probe_getter_value_unbounded')
 return value

def observed_getter(directory):
 global GETTER_RECORDS,GETTER_APK_PASS,PROBE_CASES
 GETTER_RECORDS={'shellFdReads':[]};PROBE_CASES=[];stages=[];failure=None;observed=None;closing=False;fence=None;device_generation=None
 try:
  stages.append(getter_stage());getter_generation(directory);GETTER_APK_PASS='Before'
  apk=getter_apk();GETTER_RECORDS['observedPackageBefore']=apk
  if apk!=GETTER['packageSha256']:raise ValueError('getter_package_changed')
  GETTER_RECORDS['statusBefore']=getter_cli(['status'],FD_OWNER);before=fd_guard_reply(GETTER_RECORDS['statusBefore'],'status')
  GETTER_RECORDS['operationsBefore']=getter_cli(['operations','list'],FD_OWNER);fd_guard_reply(GETTER_RECORDS['operationsBefore'],'operations')
  try:
   fence=probe_fence(directory)
   probe_fence_guard(directory,fence);getter_generation(directory)
   GETTER_RECORDS['statusPreStage']=getter_cli(['status'],FD_OWNER)
   if fd_guard_reply(GETTER_RECORDS['statusPreStage'],'status')!=before:raise ValueError('probe_status_changed')
   GETTER_RECORDS['operationsPreStage']=getter_cli(['operations','list'],FD_OWNER);fd_guard_reply(GETTER_RECORDS['operationsPreStage'],'operations')
   case={'fd':4,'mode':'stage','command':probe_stage_command()};PROBE_CASES.append(case);stage_reply=probe_read(case);GETTER_RECORDS['stageReply']=stage_reply
   lines=probe_lines(stage_reply)
   if len(lines)!=5 or lines[2]!=lines[3] or lines[4].split()!=[PROBE['artifactSha256'],'/proc/self/fd/4']:raise ValueError('probe_stage_reply_changed')
   fields=lines[1].split('|')
   if len(fields)!=10 or lines[0]!='|'.join(fields[i] for i in (0,1,5,6,9)):raise ValueError('probe_stage_parent_changed')
   case={'fd':3,'mode':'generation-before','command':probe_generation_command()};PROBE_CASES.append(case);generation_reply=probe_read(case);GETTER_RECORDS['generationBeforeReply']=generation_reply;device_generation=probe_generation(generation_reply)
   if device_generation['directory']!=lines[1] or device_generation['file']!=lines[2]:raise ValueError('probe_stage_generation_changed')
   probe_fence_guard(directory,fence)
   GETTER_RECORDS['statusPreGetter']=getter_cli(['status'],FD_OWNER)
   if fd_guard_reply(GETTER_RECORDS['statusPreGetter'],'status')!=before:raise ValueError('probe_status_changed')
   GETTER_RECORDS['operationsPreGetter']=getter_cli(['operations','list'],FD_OWNER);fd_guard_reply(GETTER_RECORDS['operationsPreGetter'],'operations')
   case={'fd':3,'mode':'getter','command':probe_getter_command(device_generation['file'])};PROBE_CASES.append(case);getter_reply=probe_read(case);GETTER_RECORDS['getterReply']=getter_reply;observed=parse_probe_current(getter_reply)
   case={'fd':3,'mode':'generation-after','command':probe_generation_command()};PROBE_CASES.append(case);generation_reply=probe_read(case);GETTER_RECORDS['generationAfterReply']=generation_reply
   if probe_generation(generation_reply)!=device_generation:raise ValueError('probe_stage_generation_changed')
  except (ValueError,OSError,UnicodeError,subprocess.TimeoutExpired) as error:
   observed=None;failure=str(error) if isinstance(error,ValueError) and re.fullmatch(r'(?:probe|getter)_[a-z_]{1,72}',str(error)) else 'probe_execution_unknown'
  GETTER_RECORDS['operationsAfter']=getter_cli(['operations','list'],FD_OWNER);fd_guard_reply(GETTER_RECORDS['operationsAfter'],'operations')
  GETTER_RECORDS['statusAfter']=getter_cli(['status'],FD_OWNER);after=fd_guard_reply(GETTER_RECORDS['statusAfter'],'status')
  if before!=after:raise ValueError('probe_status_changed')
  GETTER_APK_PASS='After';apk=getter_apk();GETTER_RECORDS['observedPackageAfter']=apk
  if apk!=GETTER['packageSha256']:raise ValueError('getter_package_changed')
  getter_generation(directory);stages.append(getter_stage())
  if stages[0]!=stages[1]:raise ValueError('getter_stage_generation_changed')
  if fence is not None:probe_fence_guard(directory,fence)
  closing=True
 except (ValueError,OSError,KeyError,TypeError,UnicodeError,subprocess.TimeoutExpired) as error:
  observed=None;failure=str(error) if isinstance(error,ValueError) and re.fullmatch(r'(?:probe|getter|coldboot|census|alias)_[a-z_]{1,72}',str(error)) else 'probe_guard_rejected'
 return {'state':'current-os-proxy-observed' if observed is not None and closing else 'diagnostic-only','reason':failure,'correlationId':PROBE['correlationId'],'effectiveProxy':observed,'closingGuardsVerified':closing,'stageFence':fence,'deviceStageGeneration':device_generation,'records':GETTER_RECORDS,'cliStagePins':stages,'stageRetained':True,'replayAllowed':False,'productAdmitted':False,'acceptanceComplete':False,'historicalUnknownsPreserved':True,'proxyObservationVerified':observed is not None and closing,'stageAuthority':PROBE['stageAuthority'],'proxySettingMutationPerformed':False,'guestRootUsed':False}
'''


def compose(program,transport_raw,historical_raw,own_raw,binding):
    tree=ast.parse(program)
    if ast.unparse(tree.body[-1])!='coldboot_dispatch()':raise ValueError('probe_dispatch_changed')
    remove={'observed_getter','current_getter','dex_read','dex_command','parse_reply'}
    tree.body=[n for n in tree.body if not isinstance(n,ast.FunctionDef) or n.name not in remove];tree.body.pop()
    frozen=ast.literal_eval(next(n.value for n in ast.parse(transport_raw).body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='_OBSERVER' for t in n.targets)))
    reader=next(n for n in ast.parse(frozen).body if isinstance(n,ast.FunctionDef) and n.name=='fd_read');reader.name='probe_read'
    if ast.unparse(reader.body[0])!="if case not in probe_commands():\n    raise ValueError('fd_probe_fixed_command_required')":raise ValueError('probe_reader_changed')
    reader.body[0]=ast.parse("if case not in PROBE_CASES:raise ValueError('probe_fixed_command_required')").body[0]
    # Exact frozen bounded reader, with the fixed Binder probe's larger bounds.
    for n in ast.walk(reader):
        if isinstance(n,ast.Constant) and type(n.value)is int and n.value in (4096,4097,10):n.value={4096:16384,4097:16385,10:30}[n.value]
        elif isinstance(n,ast.Name) and n.id=='parse_reply':n.id='probe_reply'
    parse=next(n for n in ast.parse(historical_raw).body if isinstance(n,ast.FunctionDef) and n.name=='parse_probe')
    parse.returns=None
    for arg in parse.args.args:arg.annotation=None
    template=ast.literal_eval(next(n.value for n in ast.parse(own_raw).body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='_OBSERVER' for t in n.targets)))
    result=ast.unparse(tree)+'\n'+ast.unparse(ast.Module(body=[reader,parse],type_ignores=[]))+'\n'+template.replace('__PROBE__',repr(binding))+'\ncoldboot_dispatch()\n'
    compile(result,'<current-api35-fixed-proxy-probe>','exec');return result


def prepare(root:Path,reservation:dict,correlation:str)->dict:
    if not isinstance(correlation,str) or str(uuid.UUID(correlation))!=correlation or correlation in (admission.HISTORY,original_correlation(),'ca03d25b-fd58-4998-b4f5-af9c0d9d1b1b'):raise ValueError('probe_new_correlation_required')
    root=Path(root).absolute();path=Path(admission.__file__).absolute();snapshot=availability._snapshot(path)
    if hashlib.sha256(snapshot[1]).hexdigest()!=ADMISSION_SHA:raise ValueError('probe_admission_source_changed')
    prepared=admission.prepare(root,reservation)
    if availability._snapshot(path)!=snapshot:raise ValueError('probe_admission_source_changed')
    prepared['snapshots'][path]=snapshot
    historical_path=Path(historical.__file__).absolute();historical_snapshot=availability._snapshot(historical_path)
    if hashlib.sha256(historical_snapshot[1]).hexdigest()!=HISTORICAL_SHA:raise ValueError('probe_historical_parser_changed')
    prepared['snapshots'][historical_path]=historical_snapshot
    own=Path(__file__).absolute();own_snapshot=availability._snapshot(own);prepared['snapshots'][own]=own_snapshot
    dex_path=root/'.rag_index/android-proxy-os-observation'/admission.HISTORY/'dex/classes.dex';raw=prepared['snapshots'][dex_path][1]
    binding={'correlationId':correlation,'sourceSha256':hashlib.sha256(own_snapshot[1]).hexdigest(),'artifactSha256':admission.DEX_SHA,'artifactBytes':admission.DEX_BYTES,'javaSha256':admission.JAVA_SHA,'dexBase64':base64.b64encode(raw).decode(),'stageAuthority':historical.STAGE_AUTHORITY}
    transport_raw=prepared['snapshots'][Path(admission.transport.__file__).absolute()][1]
    prepared['probeCorrelationId']=correlation;prepared['program']=compose(prepared['program'],transport_raw,historical_snapshot[1],own_snapshot[1],binding);guard_prepared(prepared);return prepared


def original_correlation():return admission.original.CORRELATION
def guard_prepared(prepared):admission.guard_prepared(prepared)
def ssh_carrier(prepared):return admission.ssh_carrier(prepared)
