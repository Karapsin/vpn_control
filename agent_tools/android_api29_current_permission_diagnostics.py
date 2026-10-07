"""One explicitly owned API29 diagnostics operation, fenced before public submit.

Cooperative single-operator ownership; unknown consumption never grants replay.
No VPN, settings, process adoption or permission grant is performed.
"""
from __future__ import annotations
import ast
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import uuid
from . import android_api29_current_permission_observation as historical
from . import android_device_availability as availability
from . import private_inventory_lock as private
PRIVATE_SHA='d6ce7b228059470b4792c47e4562017235cad26ae6666c2a899dd459887358b8'
HISTORICAL_SHA='818fef810405e93f06f7665252044ffdf4440d1e8388029ffa4a80b4c1623838'
OWNER=historical.OWNER
_REMOTE=r'''
DIAGNOSTIC=__DIAGNOSTIC__
URI='content://com.kardinal.vpncontrol.control'
def diagnostics_capture(argv,fd,environment,payload=None,timeout=30,limit=1048576):
 import base64
 if payload is not None and (not isinstance(payload,bytes) or payload!=DIAGNOSTIC['requestBytes'].encode() or len(payload)>512):raise ValueError('diagnostic_fixed_payload_required')
 def drop():os.setgroups([1000]);os.setgid(1000);os.setuid(1000)
 process=None;streams={};code=None;failure=None;out=b'';err=b''
 try:
  process=subprocess.Popen(argv,executable='/proc/self/fd/'+str(fd),pass_fds=(fd,),env=environment,preexec_fn=drop,stdin=subprocess.PIPE if payload is not None else subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
  streams={process.stdout:'out',process.stderr:'err'};deadline=time.monotonic()+timeout;offset=0;writer=process.stdin if payload is not None else None
  if writer is not None:os.set_blocking(writer.fileno(),False)
  while streams or writer is not None:
   remaining=deadline-time.monotonic()
   if remaining<=0:raise ValueError('diagnostic_command_timeout')
   readable,writable,_=select.select(list(streams),[writer] if writer is not None else [],[],min(remaining,1))
   if writable:
    count=os.write(writer.fileno(),payload[offset:]);offset+=count
    if count<=0:raise ValueError('diagnostic_input_unknown')
    if offset==len(payload):writer.close();writer=None
   for stream in readable:
    remaining_bytes=limit-len(out)-len(err);part=os.read(stream.fileno(),min(65536,remaining_bytes+1))
    if not part:del streams[stream];continue
    if streams[stream]=='out':out+=part[:remaining_bytes]
    else:err+=part[:remaining_bytes]
    if len(part)>remaining_bytes:raise ValueError('diagnostic_command_output_limit')
  code=process.wait(timeout=max(.01,deadline-time.monotonic()))
 except (ValueError,OSError,subprocess.TimeoutExpired) as error:failure=str(error) if isinstance(error,ValueError) and re.fullmatch(r'diagnostic_[a-z_]{1,72}',str(error)) else 'diagnostic_command_unknown'
 finally:
  if process is not None:
   if process.poll() is None:
    try:process.kill();process.wait(timeout=2)
    except (OSError,subprocess.TimeoutExpired):failure='diagnostic_reap_unknown'
   for stream in (process.stdin,process.stdout,process.stderr):
    if stream is not None:stream.close()
  GETTER_RECORDS.setdefault('captures',[]).append({'returncode':code,'failure':failure,'stdoutBase64':base64.b64encode(out).decode(),'stderrBase64':base64.b64encode(err).decode(),'stdoutBytes':len(out),'stderrBytes':len(err)})
 if failure:raise ValueError(failure)
 return {'returncode':code,'stdoutRaw':out.decode('utf-8','strict'),'stderrRaw':err.decode('utf-8','strict')}

def diagnostic_adb(words,payload=None):
 phase=DIAGNOSTIC_STATE.get('phase');transfer=DIAGNOSTIC_STATE.get('transfer')
 allowed=(phase=='fenced' and words==['call','--uri',URI,'--method','create'] and payload is None or phase=='created' and words==['write','--uri',URI+'/requests/'+transfer] and payload==DIAGNOSTIC['requestBytes'].encode() or phase=='submitted' and words==['call','--uri',URI,'--method','status','--arg',transfer] and payload is None or phase=='complete' and words==['read','--uri',URI+'/results/'+transfer] and payload is None)
 if not allowed:raise ValueError('diagnostic_fixed_transport_required')
 path=pathlib.Path(LAUNCH['adbPath']);expected=LAUNCH['adbFacts']['generation'];chain,name=parent_fds(path);fd=None
 try:
  guard_parents(chain);fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=chain[-1]['fd'])
  if fp(os.fstat(fd))!=expected or fp(os.stat(name,dir_fd=chain[-1]['fd'],follow_symlinks=False))!=expected:raise ValueError('getter_binary_changed')
  result=diagnostics_capture([str(path),'-s','emulator-5684','shell','-T','content',*words],fd,LAUNCH['environment'],payload,timeout=30,limit=1048576)
  guard_parents(chain)
  if fp(os.fstat(fd))!=expected or fp(os.stat(name,dir_fd=chain[-1]['fd'],follow_symlinks=False))!=expected:raise ValueError('getter_binary_changed')
  if type(result['returncode'])is not int or result['returncode']!=0 or result['stderrRaw']:raise ValueError('diagnostic_transport_failed')
  return result['stdoutRaw']
 finally:
  if fd is not None:os.close(fd)
  close_parents(chain)

def diagnostic_bundle(raw):
 match=re.fullmatch(r'Result: Bundle\[\{([^{}\r\n]*)}]\s*',raw)
 if not match:raise ValueError('diagnostic_bundle_unknown')
 fields={}
 for item in match.group(1).split(', ') if match.group(1) else []:
  key,sep,value=item.partition('=')
  if not sep or not key or key in fields:raise ValueError('diagnostic_bundle_unknown')
  fields[key]=value
 return fields

def diagnostic_write(chain,name,value):
 guard_parents(chain);old=chain[-1]['pin'];fd=os.open(name,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=chain[-1]['fd'])
 try:
  initial=fp(os.fstat(fd));raw=(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
  if len(raw)>16777216:raise ValueError('diagnostic_receipt_unbounded')
  offset=0
  while offset<len(raw):
   count=os.write(fd,raw[offset:])
   if count<=0:raise ValueError('diagnostic_partial_write')
   offset+=count
  os.fsync(fd);opened=fp(os.fstat(fd));named=fp(os.stat(name,dir_fd=chain[-1]['fd'],follow_symlinks=False))
  if opened!=named or any(initial[i]!=opened[i] for i in (0,1,5,6,7,8)) or not stat.S_ISREG(opened[5]) or stat.S_IMODE(opened[5])!=0o600 or opened[6:9]!=[0,0,1] or os.pread(fd,len(raw)+1,0)!=raw:raise ValueError('diagnostic_receipt_changed')
  os.fsync(chain[-1]['fd']);now=fp(os.fstat(chain[-1]['fd']))
  if any(now[i]!=old[i] for i in (0,1,5,6,7,8)):raise ValueError('diagnostic_parent_changed')
  chain[-1]['pin']=now;guard_parents(chain)
  return {'generation':opened,'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw)}
 finally:os.close(fd)

def diagnostic_fence(root_chain):
 guard_parents(root_chain);old=root_chain[-1]['pin'];name='android-api29-owned-diagnostics-'+DIAGNOSTIC['currentBootCorrelation']
 # A pre-existing directory, even without a receipt, means consumed/unknown.
 os.mkdir(name,0o700,dir_fd=root_chain[-1]['fd']);os.fsync(root_chain[-1]['fd'])
 current=fp(os.fstat(root_chain[-1]['fd']))
 if any(current[i]!=old[i] for i in (0,1,5,6,7)) or current[8]!=old[8]+1:raise ValueError('diagnostic_root_changed')
 root_chain[-1]['pin']=current;guard_parents(root_chain)
 chain,unused=parent_fds(ROOT/name/'intent.json')
 try:
  info=os.fstat(chain[-1]['fd'])
  if info.st_uid!=0 or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError('diagnostic_journal_unsafe')
  pin=diagnostic_write(chain,'intent.json',DIAGNOSTIC)
  return chain,pin
 except BaseException:close_parents(chain);raise

def diagnostic_intent_guard():
 chain=DIAGNOSTIC_STATE.get('chain');pin=DIAGNOSTIC_STATE.get('intentPin')
 if chain is None or not isinstance(pin,dict):raise ValueError('diagnostic_fence_required')
 guard_parents(chain);fd=os.open('intent.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=chain[-1]['fd'])
 try:
  generation=fp(os.fstat(fd));raw=os.read(fd,65537)
  if generation!=pin['generation'] or fp(os.stat('intent.json',dir_fd=chain[-1]['fd'],follow_symlinks=False))!=generation or len(raw)!=pin['bytes'] or hashlib.sha256(raw).hexdigest()!=pin['sha256'] or json.loads(raw)!=DIAGNOSTIC or fp(os.fstat(fd))!=generation:raise ValueError('diagnostic_intent_changed')
  guard_parents(chain)
 finally:os.close(fd)

def diagnostic_terminal(value,operation=None):
 if not isinstance(value,dict) or value.get('ok')is not True or value.get('final')is not True or value.get('code')!='OK' or value.get('controllerId')!=PERMISSION_OWNER or type(value.get('configurationRevision'))is not int or value['configurationRevision']!=0 or not isinstance(value.get('operationId'),str) or not re.fullmatch('[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}',value['operationId']):raise ValueError('diagnostic_terminal_unknown')
 if operation is None and value.get('requestId')!=DIAGNOSTIC['requestId'] or operation is not None and value['operationId']!=operation:raise ValueError('diagnostic_request_changed')
 return value

def diagnostic_owned_operations(record,terminal):
 value=getter_envelope(record,PERMISSION_OWNER,0)
 operations=value.get('data',{}).get('operations') if value else None
 keys={'controllerId','id','requestId','operation','phase','final','cancellable','completedUnits','totalUnits','code','configurationRevision','restartRequired'}
 if not isinstance(operations,list) or len(operations)!=1:raise ValueError('diagnostic_operations_unknown')
 summary=operations[0]
 expected={'controllerId':PERMISSION_OWNER,'id':terminal['operationId'],'requestId':DIAGNOSTIC['requestId'],'operation':'diagnostics.export','phase':'succeeded','final':True,'cancellable':False,'completedUnits':None,'totalUnits':None,'code':'OK','configurationRevision':0,'restartRequired':terminal.get('restartRequired')}
 if not isinstance(summary,dict) or set(summary)!=keys or summary!=expected or type(summary['configurationRevision'])is not int or type(summary['restartRequired'])is not bool or summary['final']is not True or summary['cancellable']is not False:raise ValueError('diagnostic_operation_provenance_changed')
 return summary

def diagnostic_public(record,kind):
 value=getter_envelope(record,PERMISSION_OWNER,0)
 if value is None or not isinstance(value.get('data'),dict):raise ValueError('diagnostic_public_unknown')
 data=value['data']
 if kind=='operations' and data.get('operations')!=[]:raise ValueError('diagnostic_before_operations_not_empty')
 if kind=='status' and (data.get('runtimeRunning')is not False or data.get('runtimeObservation')!='stopped' or data.get('configuredMode')!='vpn'):raise ValueError('diagnostic_runtime_not_off')
 return data

def diagnostic_operation_status(operation):
 cli=pathlib.Path(GETTER['cli']);fact=read_fixed(cli,1048576);fact.pop('raw')
 if fact['hashScope']!='full' or fact['sha256']!=GETTER['manifest']['launcherSha256']:raise ValueError('getter_cli_changed')
 environment=public_cli_environment(LAUNCH['adbPath'],cli,LAUNCH['environment'])
 args=['--json','--android','--serial','emulator-5684','--timeout-seconds','30','--controller-id',PERMISSION_OWNER,'operations','status',operation]
 record=getter_binary(cli,fact['generation'],args,environment,limit=1048576);record['stdout']=json.loads(record['stdoutRaw']);return record

def diagnostic_export():
 diagnostic_intent_guard()
 created=diagnostic_bundle(diagnostic_adb(['call','--uri',URI,'--method','create']));transfer=created.get('id')
 if not isinstance(transfer,str) or not re.fullmatch('[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}',transfer) or created!={'id':transfer,'requestUri':URI+'/requests/'+transfer,'resultUri':URI+'/results/'+transfer,'controllerId':PERMISSION_OWNER}:raise ValueError('diagnostic_created_owner_unknown')
 DIAGNOSTIC_STATE.update(phase='created',transfer=transfer);GETTER_RECORDS['transfer']=created
 diagnostic_intent_guard()
 if diagnostic_adb(['write','--uri',URI+'/requests/'+transfer],DIAGNOSTIC['requestBytes'].encode()).strip():raise ValueError('diagnostic_submit_reply_unknown')
 DIAGNOSTIC_STATE['phase']='submitted';deadline=time.monotonic()+45
 while True:
  status=diagnostic_bundle(diagnostic_adb(['call','--uri',URI,'--method','status','--arg',transfer]));GETTER_RECORDS.setdefault('transferStatuses',[]).append(status)
  if status=={'state':'complete'}:break
  if status not in ({'state':'writing'},{'state':'pending'}) or time.monotonic()>=deadline:raise ValueError('diagnostic_transfer_unknown')
  time.sleep(.1)
 DIAGNOSTIC_STATE['phase']='complete';raw=diagnostic_adb(['read','--uri',URI+'/results/'+transfer]);GETTER_RECORDS['terminalRaw']=raw
 terminal=diagnostic_terminal(json.loads(raw));GETTER_RECORDS['terminal']=terminal
 content=terminal.get('data',{}).get('content')
 observation=permission_parse({'returncode':0,'stderrRaw':'','stdoutRaw':content})
 if observation['mode']!='VPN' or observation['vpnRunning']:raise ValueError('diagnostic_runtime_not_off')
 return terminal,observation

def observed_getter(directory,root_chain):
 global GETTER_RECORDS,DIAGNOSTIC_STATE
 GETTER_RECORDS={};DIAGNOSTIC_STATE={};stage=[];chain=None;terminal=None;observation=None;failure=None;closing=False;proof=None;intent_pin=None
 try:
  stage.append(getter_stage());getter_generation(directory)
  if getter_apk()!=GETTER['packageSha256']:raise ValueError('getter_package_changed')
  GETTER_RECORDS['statusBefore']=getter_cli(['status'],PERMISSION_OWNER);before=diagnostic_public(GETTER_RECORDS['statusBefore'],'status')
  GETTER_RECORDS['operationsBefore']=getter_cli(['operations','list'],PERMISSION_OWNER);diagnostic_public(GETTER_RECORDS['operationsBefore'],'operations')
  chain,intent_pin=diagnostic_fence(root_chain);DIAGNOSTIC_STATE.update(phase='fenced',chain=chain,intentPin=intent_pin)
  try:terminal,observation=diagnostic_export()
  except (ValueError,OSError,KeyError,TypeError,UnicodeError,subprocess.TimeoutExpired) as error:failure=str(error) if isinstance(error,ValueError) and re.fullmatch(r'(?:diagnostic|permission|getter)_[a-z_]{1,72}',str(error)) else 'diagnostic_export_unknown'
  # Even an uncertain submit must complete current-epoch runtime/stage guards.
  GETTER_RECORDS['operationsAfter']=getter_cli(['operations','list'],PERMISSION_OWNER)
  if getter_envelope(GETTER_RECORDS['operationsAfter'],PERMISSION_OWNER,0) is None:raise ValueError('diagnostic_public_unknown')
  GETTER_RECORDS['statusAfter']=getter_cli(['status'],PERMISSION_OWNER);after=diagnostic_public(GETTER_RECORDS['statusAfter'],'status')
  if before!=after:raise ValueError('diagnostic_status_changed')
  if getter_apk()!=GETTER['packageSha256']:raise ValueError('getter_package_changed')
  getter_generation(directory);stage.append(getter_stage())
  if stage[0]!=stage[1]:raise ValueError('getter_stage_generation_changed')
  closing=True
  if terminal is not None:
   proof=diagnostic_owned_operations(GETTER_RECORDS['operationsAfter'],terminal)
   GETTER_RECORDS['operationStatus']=diagnostic_operation_status(terminal['operationId']);inspected=diagnostic_terminal(GETTER_RECORDS['operationStatus']['stdout'],terminal['operationId'])
   if inspected.get('data')!={k:v for k,v in terminal.get('data',{}).items() if k!='content'} or inspected.get('restartRequired')!=terminal.get('restartRequired') or inspected.get('warnings')!=terminal.get('warnings'):raise ValueError('diagnostic_inspection_changed')
   GETTER_RECORDS['operationsFinal']=getter_cli(['operations','list'],PERMISSION_OWNER)
   if diagnostic_owned_operations(GETTER_RECORDS['operationsFinal'],terminal)!=proof:raise ValueError('diagnostic_operation_changed')
   GETTER_RECORDS['statusFinal']=getter_cli(['status'],PERMISSION_OWNER)
   if diagnostic_public(GETTER_RECORDS['statusFinal'],'status')!=before:raise ValueError('diagnostic_status_changed')
   getter_generation(directory)
   if getter_apk()!=GETTER['packageSha256']:raise ValueError('getter_package_changed')
   if getter_stage()!=stage[-1]:raise ValueError('getter_stage_generation_changed')
  elif failure is None:failure='diagnostic_terminal_unknown'
 except (ValueError,OSError,KeyError,TypeError,UnicodeError,subprocess.TimeoutExpired) as error:failure=str(error) if isinstance(error,ValueError) and re.fullmatch(r'(?:diagnostic|permission|getter|coldboot|census|alias)_[a-z_]{1,72}',str(error)) else 'diagnostic_guard_rejected'
 proved=failure is None and closing and proof is not None and observation is not None
 result={'state':'current-owned-permission-observed' if proved else 'diagnostic-only','reason':failure,'permissionObserved':proved,'observation':observation,'controllerId':PERMISSION_OWNER,'configurationRevision':0,'correlationId':DIAGNOSTIC['correlationId'],'requestId':DIAGNOSTIC['requestId'],'ownedOperation':proof,'ownedTerminal':terminal,'records':GETTER_RECORDS,'cliStagePins':stage,'closingGuardsVerified':closing,'endpointAdmitted':False,'productAdmitted':False,'acceptanceComplete':False,'permissionGrantPerformed':False,'runtimeMutationPerformed':False,'replayAllowed':False,'historicalUnknownsPreserved':True,'intentPin':intent_pin}
 if chain is not None:
  try:
   diagnostic_intent_guard();diagnostic_write(chain,'terminal.json',result)
  finally:close_parents(chain)
 return result
'''

def _identifier(value):
 if not isinstance(value,str) or not re.fullmatch('[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}',value):raise ValueError('diagnostic_correlation_invalid')
 return value

def compose(program,own_raw,binding):
 tree=ast.parse(program);remove={'permission_diagnostics','permission_public','observed_getter'}
 if {n.name for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in remove}!=remove or ast.unparse(tree.body[-1])!='coldboot_dispatch()':raise ValueError('diagnostic_composition_changed')
 tree.body=[n for n in tree.body if not isinstance(n,ast.FunctionDef) or n.name not in remove];tree.body.pop()
 dispatch=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='coldboot_dispatch')
 calls=[n for n in ast.walk(dispatch) if isinstance(n,ast.Call) and ast.unparse(n.func)=='observed_getter']
 if len(calls)!=1 or len(calls[0].args)!=1 or ast.unparse(calls[0].args[0])!='directory':raise ValueError('diagnostic_dispatch_changed')
 calls[0].args.append(ast.Name(id='root_chain',ctx=ast.Load()))
 template=ast.literal_eval(next(n.value for n in ast.parse(own_raw).body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='_REMOTE' for t in n.targets)))
 result=ast.unparse(ast.fix_missing_locations(tree))+'\n'+template.replace('__DIAGNOSTIC__',repr(binding))+'\ncoldboot_dispatch()\n'
 compile(result,'<one-owned-api29-diagnostics>','exec');return result

def prepare(root:Path,reservation:dict,correlation:str)->dict:
 """Readonly preparation. Call arm exactly once before ssh_carrier is available."""
 root=Path(root).absolute();correlation=_identifier(correlation);path=Path(historical.__file__).absolute();snapshot=availability._snapshot(path)
 if hashlib.sha256(snapshot[1]).hexdigest()!=HISTORICAL_SHA:raise ValueError('diagnostic_historical_source_changed')
 private_path=Path(private.__file__).absolute();private_snapshot=availability._snapshot(private_path)
 if hashlib.sha256(private_snapshot[1]).hexdigest()!=PRIVATE_SHA:raise ValueError('diagnostic_private_source_changed')
 prepared=historical.prepare(root,reservation)
 if availability._snapshot(private_path)!=private_snapshot:raise ValueError('diagnostic_private_source_changed')
 prepared['snapshots'][private_path]=private_snapshot
 if availability._snapshot(path)!=snapshot or prepared['snapshots'].get(path)!=snapshot:raise ValueError('diagnostic_historical_source_changed')
 own=Path(__file__).absolute();saved=availability._snapshot(own);prepared['snapshots'][own]=saved
 request_id=str(uuid.uuid5(uuid.UUID(correlation),'api29-owned-diagnostics-export'))
 request={'schemaVersion':1,'requestId':request_id,'controllerId':OWNER,'ifRevision':0,'interactive':False,'asynchronous':False,'command':{'operation':'diagnostics.export','arguments':{}}}
 request_raw=json.dumps(request,sort_keys=True,separators=(',',':'))
 if len(request_raw.encode())>512:raise ValueError('diagnostic_request_unbounded')
 binding={'schema':1,'kind':'one-owned-api29-diagnostics','correlationId':correlation,'requestId':request_id,'requestBytes':request_raw,'controllerId':OWNER,'configurationRevision':0,'currentBootCorrelation':historical.original.CORRELATION,'packageSha256':historical.original.APK,'stageId':historical.original.STAGE,'sourceSha256':hashlib.sha256(saved[1]).hexdigest(),'historicalSourceSha256':HISTORICAL_SHA,'generation':None}
 # Derive the full child/QEMU/device pin already validated by frozen ec56.
 original_tree=ast.parse(prepared['program']);getter=next(n for n in original_tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='GETTER' for t in n.targets))
 binding['generation']=ast.literal_eval(getter.value)['generation']
 prepared['program']=compose(prepared['program'],saved[1],binding);prepared['diagnosticProgramSha256']=hashlib.sha256(prepared['program'].encode()).hexdigest();prepared['ownedDiagnostic']=binding;prepared['diagnosticRoot']=root;prepared['armed']=False;historical.guard_prepared(prepared);return prepared

def _local_directory(root,create=False):
 """One fixed current-generation journal; a different UUID cannot bypass it."""
 path=Path(root).absolute();held=ExitStack()
 try:
  directory=held.enter_context(private.Directory(path))
  for name in ('.rag_index','android-api29-owned-permission-diagnostics'):
   directory.guard()
   if create:
    try:os.mkdir(name,0o700,dir_fd=directory.fd);os.fsync(directory.fd)
    except FileExistsError:pass
   path=path/name;directory=held.enter_context(private.Directory(path))
  name=historical.original.CORRELATION
  if create:
   directory.guard();os.mkdir(name,0o700,dir_fd=directory.fd);os.fsync(directory.fd);directory.guard()
  path=path/name;directory=held.enter_context(private.Directory(path))
  if stat.S_IMODE(os.fstat(directory.fd).st_mode)!=0o700:raise ValueError('diagnostic_local_journal_unsafe')
  return held,directory
 except BaseException:held.close();raise

def _local_write(directory,name,value):
 raw=(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
 if len(raw)>33554432:raise ValueError('diagnostic_local_receipt_unbounded')
 directory.guard();fd=os.open(name,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory.fd)
 try:
  before=os.fstat(fd);offset=0
  while offset<len(raw):
   count=os.write(fd,raw[offset:])
   if count<=0:raise ValueError('diagnostic_local_short_write')
   offset+=count
  os.fsync(fd);after=os.fstat(fd);named=os.stat(name,dir_fd=directory.fd,follow_symlinks=False)
  if private._generation(after)!=private._generation(named) or any(getattr(before,key)!=getattr(after,key) for key in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink')) or after.st_uid!=os.getuid() or after.st_nlink!=1 or stat.S_IMODE(after.st_mode)!=0o600 or os.pread(fd,len(raw)+1,0)!=raw:raise ValueError('diagnostic_local_receipt_changed')
  os.fsync(directory.fd);directory.guard();return {'generation':list(private._generation(after)),'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw)}
 finally:os.close(fd)

def arm(prepared):
 """Create-only durable local fence. Failure/unknown is permanently consumed."""
 if prepared.get('armed')is not False:raise ValueError('diagnostic_already_armed')
 historical.guard_prepared(prepared)
 if hashlib.sha256(prepared['program'].encode()).hexdigest()!=prepared['diagnosticProgramSha256']:raise ValueError('diagnostic_program_changed')
 held,directory=_local_directory(prepared['diagnosticRoot'],True)
 try:
  value={'binding':prepared['ownedDiagnostic'],'programSha256':hashlib.sha256(prepared['program'].encode()).hexdigest()}
  pin=_local_write(directory,'intent.json',value);historical.guard_prepared(prepared)
  prepared['diagnosticIntentPin']=pin;prepared['armed']=True;return pin
 finally:held.close()

def guard_prepared(prepared):
 historical.guard_prepared(prepared)
 if hashlib.sha256(prepared['program'].encode()).hexdigest()!=prepared['diagnosticProgramSha256']:raise ValueError('diagnostic_program_changed')
 if prepared.get('armed')is not True:raise ValueError('diagnostic_local_fence_required')
 held,directory=_local_directory(prepared['diagnosticRoot'])
 try:
  with private.Snapshot(directory,'intent.json') as saved:
   pin={'generation':list(saved.generation),'sha256':hashlib.sha256(saved.body).hexdigest(),'bytes':len(saved.body)}
   if pin!=prepared['diagnosticIntentPin'] or json.loads(saved.body)!={'binding':prepared['ownedDiagnostic'],'programSha256':hashlib.sha256(prepared['program'].encode()).hexdigest()}:raise ValueError('diagnostic_local_fence_changed')
   try:os.stat('terminal.json',dir_fd=directory.fd,follow_symlinks=False)
   except FileNotFoundError:pass
   else:raise ValueError('diagnostic_local_consumed')
   saved.guard()
 finally:held.close()

def ssh_carrier(prepared):guard_prepared(prepared);return historical.ssh_carrier(prepared)

def retain(prepared,stdout:bytes,stderr:bytes,exit_code):
 """Retain raw transport before parsing, including unknown/partial failures."""
 import base64
 if not isinstance(stdout,bytes) or not isinstance(stderr,bytes) or len(stdout)+len(stderr)>16777216 or exit_code is not None and type(exit_code)is not int:raise ValueError('diagnostic_local_capture_invalid')
 # Do not discard raw on changed source; the existing arm still binds history.
 held,directory=_local_directory(prepared['diagnosticRoot'])
 try:
  with private.Snapshot(directory,'intent.json') as saved:
   if {'generation':list(saved.generation),'sha256':hashlib.sha256(saved.body).hexdigest(),'bytes':len(saved.body)}!=prepared['diagnosticIntentPin']:raise ValueError('diagnostic_local_fence_changed')
   value={'binding':prepared['ownedDiagnostic'],'intentPin':prepared['diagnosticIntentPin'],'exitCode':exit_code,'stdoutBase64':base64.b64encode(stdout).decode(),'stderrBase64':base64.b64encode(stderr).decode(),'replayAllowed':False}
   saved.guard();capture=_local_write(directory,'capture.json',value)
   return _local_write(directory,'terminal.json',{'binding':prepared['ownedDiagnostic'],'intentPin':prepared['diagnosticIntentPin'],'capturePin':capture,'replayAllowed':False})
 finally:held.close()

def status(root):
 """Local recorded status only; never launches or repeats the export."""
 held,directory=_local_directory(root)
 try:
  with private.Snapshot(directory,'intent.json') as intent:
   binding=json.loads(intent.body)['binding'];intent.guard()
   try:
    with private.Snapshot(directory,'terminal.json') as terminal:
     value=json.loads(terminal.body);terminal.guard()
     actual_intent={'generation':list(intent.generation),'sha256':hashlib.sha256(intent.body).hexdigest(),'bytes':len(intent.body)}
     if value.get('binding')!=binding or value.get('intentPin')!=actual_intent or value.get('replayAllowed')is not False:raise ValueError('diagnostic_local_history_changed')
     capture=_local_capture_pin(directory)
     if value.get('capturePin')!=capture:raise ValueError('diagnostic_local_capture_changed')
     return {'state':'consumed-recorded','correlationId':binding['correlationId'],'replayAllowed':False,'receiptSha256':hashlib.sha256(terminal.body).hexdigest()}
   except FileNotFoundError:return {'state':'consumed-unknown','correlationId':binding['correlationId'],'replayAllowed':False}
 finally:held.close()


def _local_capture_pin(directory):
 directory.guard();fd=os.open('capture.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory.fd)
 try:
  info=os.fstat(fd);gen=private._generation(info)
  if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode)!=0o600 or info.st_uid!=os.getuid() or info.st_nlink!=1 or not 0<info.st_size<=33554432:raise ValueError('diagnostic_local_capture_unsafe')
  count=0;digest=hashlib.sha256()
  while count<info.st_size:
   part=os.read(fd,min(65536,info.st_size-count))
   if not part:raise ValueError('diagnostic_local_capture_short')
   count+=len(part);digest.update(part)
  directory.guard()
  if private._generation(os.fstat(fd))!=gen or private._generation(os.stat('capture.json',dir_fd=directory.fd,follow_symlinks=False))!=gen:raise ValueError('diagnostic_local_capture_changed')
  return {'generation':list(gen),'sha256':digest.hexdigest(),'bytes':count}
 finally:os.close(fd)
