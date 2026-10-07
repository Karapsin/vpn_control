"""One fenced completion of the measured remaining API35 proxy rows."""
from __future__ import annotations
import ast,hashlib,json,os,re,stat,sys,uuid
from pathlib import Path
from . import android_api35_partial_proxy_diagnostic as diagnostic
from . import android_device_availability as availability
SOURCE='e76ce20734c02bde4f4cb9a31ebba93ad7556dcca1858c23880fffb01d358a33'
PROOF_CAPSULE='android-api35-partial-proxy-diagnostic-b23f1848-3c0e-4ccf-a5f2-cdc1b647dc13'
PROOF_SHA='88ba44f1d01032a787d1547ecc7cd3cd0d0d4baaf9752b46ef0511166e1c6f1e'
OWNER='58d546ea-8208-40a3-bba4-e8759768284e'
SCOPE='android-api35-proxy-remaining-2e581948-3a05-4b75-a566-bbdee1d7c191'
ROWS={'global_http_proxy_exclusion_list':'','global_http_proxy_host':'','global_http_proxy_port':'0','http_proxy':':0'}
KEYS=('global_http_proxy_host','global_http_proxy_port','http_proxy')
class CleanupError(ValueError):pass
_REMOTE=r'''
REMAINING=__REMAINING__
REMAINING_NAMES=('remaining-admission.json','remaining-effect-fence.json','remaining-terminal.json')

def remaining_inventory(directory,names,original_names):
 extras=sorted(set(names)-set(original_names))
 allowed=[[]] if REMAINING['action']=='admit' else [[REMAINING_NAMES[0]],sorted(REMAINING_NAMES[:2])]
 if REMAINING['action']=='admit' and REMAINING_ADMISSION_WRITTEN:allowed.append([REMAINING_NAMES[0]])
 if REMAINING['action']=='status' or REMAINING_TERMINAL_WRITTEN:allowed.append(sorted(REMAINING_NAMES))
 if names!=sorted(original_names+extras) or extras not in allowed:raise ValueError('remaining_inventory_changed')

def remaining_write(directory,name,value):
 if name not in REMAINING_NAMES:raise ValueError('remaining_record_invalid')
 chain,fd,pin=restore_journal_open(directory);record=None
 try:
  guard_parents(chain);inventory=sorted(os.listdir(fd))
  record=os.open(name,os.O_WRONLY|os.O_NOFOLLOW|os.O_CREAT|os.O_EXCL,0o600,dir_fd=fd)
  raw=(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
  if not 0<len(raw)<=262144:raise ValueError('remaining_record_unbounded')
  at=0
  while at<len(raw):
   count=os.write(record,raw[at:])
   if count<=0:raise ValueError('remaining_record_incomplete')
   at+=count
  os.fsync(record);os.fsync(fd);generation=fp(os.fstat(record));after=fp(os.fstat(fd))
  if not stat.S_ISREG(generation[5]) or stat.S_IMODE(generation[5])!=0o600 or generation[6:9]!=[0,0,1] or generation[2]!=len(raw) or generation!=fp(os.stat(name,dir_fd=fd,follow_symlinks=False)):raise ValueError('remaining_record_changed')
  if any(after[n]!=pin[n] for n in (0,1,5,6,7,8)) or sorted(os.listdir(fd))!=sorted(inventory+[name]):raise ValueError('remaining_journal_changed')
  chain[-1]['pin']=after;guard_parents(chain)
 finally:
  if record is not None:os.close(record)
  os.close(fd);close_parents(chain)
 result=partial_record(directory,name)
 if result['value']!=value or result['generation']!=generation or result['sha256']!=hashlib.sha256(raw).hexdigest():raise ValueError('remaining_record_changed')
 return result

def remaining_original(directory):
 records=partial_journal(directory)
 if records!=REMAINING['originalJournal']:raise ValueError('remaining_original_changed')
 return records

def remaining_admission(directory):
 record=partial_record(directory,REMAINING_NAMES[0]);value=record['value']
 if value!={'schema':1,'binding':REMAINING['authority'],'currentControllerId':REMAINING['controllerId'],'originalOperationOutcome':'unknown','replayAllowed':False}:raise ValueError('remaining_admission_changed')
 if REMAINING['action']!='admit' and {key:record[key] for key in ('generation','sha256')}!=REMAINING['admissionPin']:raise ValueError('remaining_admission_pin_changed')
 return record

def remaining_guard(directory,stage,expected):
 remaining_original(directory);partial_hardware(directory,stage)
 partial_public(['status'],REMAINING['controllerId']);partial_public(['operations','list'],REMAINING['controllerId'])
 census=partial_census();GETTER_RECORDS.setdefault('remainingCensuses',[]).append(census)
 if census['settings']['rows']!=expected or census['kind']!='clear':raise ValueError('remaining_proxy_changed')
 return census

def remaining_delete(index):
 if type(index)is not int or not 0<=index<3:raise ValueError('remaining_step_invalid')
 key=('global_http_proxy_host','global_http_proxy_port','http_proxy')[index]
 return 'set -eu; test "$(/system/bin/id -u)" = 2000; /system/bin/settings delete global '+key

def remaining_transaction(directory,stage):
 global REMAINING_TERMINAL_WRITTEN
 admission=remaining_admission(directory);expected=dict(REMAINING['authority']['initialRows']);initial=remaining_guard(directory,stage,expected)
 if partial_record(directory,REMAINING_NAMES[1],optional=True)['present'] or partial_record(directory,REMAINING_NAMES[2],optional=True)['present']:raise ValueError('remaining_consumed')
 fence=remaining_write(directory,REMAINING_NAMES[1],{'schema':1,'authority':REMAINING['authority'],'admissionPin':REMAINING['admissionPin'],'initial':initial,'effect':'remaining-proxy-deletes-only','replayAllowed':False})
 for index,key in enumerate(('global_http_proxy_host','global_http_proxy_port','http_proxy')):
  if remaining_admission(directory)!=admission or partial_record(directory,REMAINING_NAMES[1])!=fence:raise ValueError('remaining_authority_changed')
  remaining_guard(directory,stage,expected)
  case={'fd':3,'mode':'remaining-effect-'+str(index),'command':remaining_delete(index)};PROBE_CASES.append(case)
  effect=probe_read(case);GETTER_RECORDS.setdefault('remainingEffects',[]).append(effect);probe_lines(effect)
  del expected[key];remaining_guard(directory,stage,expected)
 if expected!={'global_http_proxy_exclusion_list':''}:raise ValueError('remaining_final_rows_changed')
 final=remaining_guard(directory,stage,expected)
 if remaining_admission(directory)!=admission or partial_record(directory,REMAINING_NAMES[1])!=fence:raise ValueError('remaining_authority_changed')
 value={'schema':1,'authority':REMAINING['authority'],'admissionPin':REMAINING['admissionPin'],'fencePin':{key:fence[key] for key in ('generation','sha256')},'state':'remaining-proxy-restored','final':final,'originalOperationOutcome':'unknown','replayAllowed':False}
 result=remaining_write(directory,REMAINING_NAMES[2],value);REMAINING_TERMINAL_WRITTEN=True;return result

def remaining_status(directory,stage):
 admission=remaining_admission(directory);fence=partial_record(directory,REMAINING_NAMES[1],optional=True);terminal=partial_record(directory,REMAINING_NAMES[2],optional=True)
 if not terminal['present']:return {'state':'unknown','reason':'remaining_terminal_absent','admission':admission,'fence':fence,'terminal':terminal}
 if not fence['present']:raise ValueError('remaining_fence_absent')
 value=terminal['value']
 if type(value.get('schema'))is not int or value['schema']!=1 or value.get('authority')!=REMAINING['authority'] or value.get('admissionPin')!=REMAINING['admissionPin'] or value.get('fencePin')!={key:fence[key] for key in ('generation','sha256')} or value.get('state')!='remaining-proxy-restored' or value.get('originalOperationOutcome')!='unknown' or value.get('replayAllowed')is not False:raise ValueError('remaining_terminal_changed')
 if type(fence['value'].get('schema'))is not int or fence['value']['schema']!=1 or fence['value'].get('authority')!=REMAINING['authority'] or fence['value'].get('admissionPin')!=REMAINING['admissionPin'] or fence['value'].get('effect')!='remaining-proxy-deletes-only' or fence['value'].get('replayAllowed')is not False:raise ValueError('remaining_fence_changed')
 final=remaining_guard(directory,stage,{'global_http_proxy_exclusion_list':''})
 if final!=value['final']:raise ValueError('remaining_final_changed')
 return {'state':'remaining-proxy-restored','record':terminal}

def observed_getter(directory):
 global GETTER_RECORDS,GETTER_APK_PASS,PROBE_CASES,RESTORE_CLOSING,RESTORE_DEADLINE,REMAINING_TERMINAL_WRITTEN,REMAINING_ADMISSION_WRITTEN
 GETTER_RECORDS={'shellFdReads':[]};REMAINING_TERMINAL_WRITTEN=False;REMAINING_ADMISSION_WRITTEN=False;GETTER_APK_PASS='Current';PROBE_CASES=[];RESTORE_CLOSING=False;RESTORE_DEADLINE=time.monotonic()+600
 stage=None;result=None;primary=None;primary_type=None;closing=None;closing_type=None
 try:
  stage=getter_stage()
  if REMAINING['action']=='admit':
   partial_hardware(directory,stage);REMAINING['controllerId']=partial_public(['status'])
   partial_public(['status'],REMAINING['controllerId'])
   remaining_guard(directory,stage,REMAINING['authority']['initialRows'])
   value={'schema':1,'binding':REMAINING['authority'],'currentControllerId':REMAINING['controllerId'],'originalOperationOutcome':'unknown','replayAllowed':False}
   result={'state':'remaining-admitted','record':remaining_write(directory,REMAINING_NAMES[0],value)};REMAINING_ADMISSION_WRITTEN=True
  elif REMAINING['action']=='restore':result={'state':'remaining-proxy-restored','record':remaining_transaction(directory,stage)}
  elif REMAINING['action']=='status':result=remaining_status(directory,stage)
  else:raise ValueError('remaining_action_invalid')
 except (ValueError,OSError,KeyError,TypeError,UnicodeError,subprocess.TimeoutExpired,NameError,AttributeError) as error:
  primary_type=type(error).__name__;primary=str(error) if isinstance(error,ValueError) and re.fullmatch('(?:remaining|partial|probe|getter|coldboot|component)_[a-z_]{1,72}',str(error)) else 'remaining_execution_unknown'
 finally:
  RESTORE_CLOSING=True
  try:
   if stage is None:raise ValueError('remaining_stage_unobserved')
   remaining_original(directory);partial_hardware(directory,stage);partial_public(['status'],REMAINING['controllerId']);partial_public(['operations','list'],REMAINING['controllerId'])
  except (ValueError,OSError,KeyError,TypeError,UnicodeError,subprocess.TimeoutExpired,NameError,AttributeError) as error:
   closing_type=type(error).__name__;closing=str(error) if isinstance(error,ValueError) and re.fullmatch('(?:remaining|partial|probe|getter|coldboot|component)_[a-z_]{1,72}',str(error)) else 'remaining_closing_unknown'
 return {'state':result['state'] if result is not None and primary is None and closing is None else 'unknown','reason':primary or closing,'primaryReason':primary,'primaryExceptionType':primary_type,'closingReason':closing,'closingExceptionType':closing_type,'closingGuardsVerified':closing is None,'correlationId':REMAINING['authority']['correlationId'],'currentControllerId':REMAINING.get('controllerId'),'originalOperationCorrelationId':RESTORE['readmission']['correlationId'],'originalOperationOutcome':'unknown','result':result,'records':GETTER_RECORDS,'productAdmitted':False,'acceptanceComplete':False,'historicalUnknownsPreserved':True,'replayAllowed':False,'pacEffectSubmitted':False}
'''

def _local_write(path,value,prepared):
    module=diagnostic.original.coldboot;file=Path(module.__file__).absolute();snapshot=availability._snapshot(file)
    if hashlib.sha256(snapshot[1]).hexdigest()!=diagnostic.original.current.admission.original.COLD_SOURCE:raise CleanupError('remaining_local_writer_changed')
    prepared['snapshots'][file]=snapshot;tree=ast.parse(snapshot[1]);function=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='_write_local_intent')
    if ast.unparse(function.body[2].test).split(' or ')[0]!="path.name != 'launch.json'":raise CleanupError('remaining_local_writer_changed')
    function.body[2].test=ast.parse("path.name not in ('intent.json','admission-ready.json','effect-fence.json') or path.parent.parent.name!="+repr(SCOPE)+" or path.parent.parent.parent.name!='.rag_index' or str(uuid.UUID(path.parent.name))!=path.parent.name",mode='eval').body
    generation=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='_local_generation');namespace=dict(os=os,sys=sys,stat=stat,re=re,json=json,Path=Path,uuid=uuid)
    exec(compile(ast.Module(body=[generation,function],type_ignores=[]),'<remaining-fixed-local-fd-writer>','exec'),namespace);namespace['_write_local_intent'](path,value)

def _proof_snapshot(root):
    # Fixed receipt is larger than the source-file reader cap. Hold every
    # route component NOFOLLOW; unrelated ancestor child counts are not proof.
    path=Path(root).absolute()/'.runtime/parity-evidence'/PROOF_CAPSULE/'diagnostic-remote-stdout-0.private';parts=path.parts;fds=[];record=None
    def pin(info):return (info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns,info.st_mode,info.st_uid,info.st_gid,info.st_nlink)
    try:
        fds.append((os.open('/',os.O_RDONLY|os.O_DIRECTORY),None,None))
        for name in parts[1:-1]:
            parent=fds[-1][0];fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent);info=pin(os.fstat(fd));fds.append((fd,name,info))
            if not stat.S_ISDIR(info[5]) or pin(os.stat(name,dir_fd=parent,follow_symlinks=False))!=info:raise CleanupError('remaining_proof_route_changed')
        if stat.S_IMODE(fds[-1][2][5])!=0o700 or fds[-1][2][6]!=os.getuid():raise CleanupError('remaining_proof_capsule_unsafe')
        parent=fds[-1][0];record=os.open(parts[-1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent);before=pin(os.fstat(record))
        if not stat.S_ISREG(before[5]) or stat.S_IMODE(before[5])!=0o600 or before[6]!=os.getuid() or before[8]!=1 or not 0<before[2]<=4194304:raise CleanupError('remaining_proof_unsafe')
        raw=b''
        while len(raw)<before[2]:
            part=os.read(record,min(65536,before[2]-len(raw)))
            if not part:raise CleanupError('remaining_proof_incomplete')
            raw+=part
        if before!=pin(os.fstat(record)) or before!=pin(os.stat(parts[-1],dir_fd=parent,follow_symlinks=False)):raise CleanupError('remaining_proof_changed')
        for index,(fd,name,initial) in enumerate(fds[1:],1):
            current=pin(os.fstat(fd));named=pin(os.stat(name,dir_fd=fds[index-1][0],follow_symlinks=False))
            if any(current[n]!=initial[n] or named[n]!=initial[n] for n in (0,1,5,6,7)):raise CleanupError('remaining_proof_route_changed')
        return before,raw
    finally:
        if record is not None:os.close(record)
        for fd,_,_ in reversed(fds):os.close(fd)

def prepare(root,reservation,correlation,action='admit'):
    if action not in ('admit','restore','status') or not isinstance(correlation,str) or str(uuid.UUID(correlation))!=correlation or correlation in (diagnostic.OPERATION,diagnostic.original._INTERRUPTED):raise CleanupError('remaining_action_invalid')
    root=Path(root).absolute();file=Path(diagnostic.__file__).absolute();snapshot=availability._snapshot(file)
    if hashlib.sha256(snapshot[1]).hexdigest()!=SOURCE:raise CleanupError('remaining_diagnostic_source_changed')
    prepared=diagnostic.prepare(root,reservation)
    if availability._snapshot(file)!=snapshot:raise CleanupError('remaining_diagnostic_source_changed')
    proof_file=root/'.runtime/parity-evidence'/PROOF_CAPSULE/'diagnostic-remote-stdout-0.private';proof_snapshot=_proof_snapshot(root)
    if hashlib.sha256(proof_snapshot[1]).hexdigest()!=PROOF_SHA:raise CleanupError('remaining_proof_changed')
    proof=json.loads(proof_snapshot[1]);result=proof['result']
    if proof.get('observationComplete')is not True or proof.get('closingGuardsVerified')is not True or proof.get('currentControllerId')!=OWNER or proof.get('pacAbsent')is not True or proof.get('effectiveProxyClear')is not True or result['censusAfter']['settings']['rows']!=ROWS or result['censusBefore']!=result['censusAfter'] or result['journalBefore']!=result['journalAfter'] or result['journalAfter']['terminal.json']['present']is not False:raise CleanupError('remaining_proof_changed')
    own=Path(__file__).absolute();own_snapshot=availability._snapshot(own);prepared['snapshots'][own]=own_snapshot;prepared['remainingProofSnapshot']=proof_snapshot;prepared['remainingRoot']=root
    authority={'correlationId':correlation,'sourceSha256':hashlib.sha256(own_snapshot[1]).hexdigest(),'historicalControllerId':OWNER,'configurationRevision':0,'initialRows':ROWS,'initialBinder':result['censusAfter']['binder'],'proofPin':{'generation':list(proof_snapshot[0]),'sha256':PROOF_SHA},'diagnosticSourceSha256':SOURCE,'originalOperationCorrelationId':diagnostic.OPERATION,'originalOperationOutcome':'unknown','originalJournalPins':{name:{k:item[k] for k in ('present','generation','sha256') if k in item} for name,item in result['journalAfter'].items()},'replayAllowed':False}
    local=root/'.rag_index'/SCOPE/correlation
    if action=='admit':_local_write(local/'intent.json',authority,prepared)
    intent=availability._snapshot(local/'intent.json')
    if json.loads(intent[1])!=authority:raise CleanupError('remaining_local_intent_changed')
    prepared['snapshots'][local/'intent.json']=intent;authority={**authority,'localIntentPin':{'generation':list(intent[0]),'sha256':hashlib.sha256(intent[1]).hexdigest()}}
    binding={'action':action,'authority':authority,'originalJournal':result['journalAfter'],'controllerId':None}
    if action in ('restore','status'):
        ready=availability._snapshot(local/'admission-ready.json');value=json.loads(ready[1])
        if value.get('authority')!=authority:raise CleanupError('remaining_local_admission_changed')
        diagnostic.original._regular_root_pin(value['admissionPin']);owner=value.get('currentControllerId')
        if not isinstance(owner,str) or re.fullmatch('[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}',owner)is None:raise CleanupError('remaining_local_owner_invalid')
        binding['controllerId']=owner;binding['admissionPin']=value['admissionPin'];prepared['snapshots'][local/'admission-ready.json']=ready
        if action=='restore':
            _local_write(local/'effect-fence.json',{'authority':authority,'admissionPin':binding['admissionPin'],'replayAllowed':False},prepared)
            prepared['snapshots'][local/'effect-fence.json']=availability._snapshot(local/'effect-fence.json')
    tree=ast.parse(prepared['program']);count=0;record_count=0
    for node in tree.body:
        if isinstance(node,ast.FunctionDef) and node.name=='partial_journal':
            for index,statement in enumerate(node.body):
                if isinstance(statement,ast.If) and ast.unparse(statement.test)=='names != expected_names':node.body[index]=ast.parse('remaining_inventory(directory,names,expected_names)').body[0];count+=1
        if isinstance(node,ast.FunctionDef) and node.name=='partial_record':
            for child in ast.walk(node):
                if isinstance(child,ast.Tuple) and all(isinstance(item,ast.Constant) for item in child.elts) and ast.literal_eval(child)==('arm.json','readmission.json','effect-fence.json','terminal.json'):
                    child.elts += [ast.Constant(name) for name in ('remaining-admission.json','remaining-effect-fence.json','remaining-terminal.json')];record_count+=1
    if count!=1 or record_count!=1:raise CleanupError('remaining_closed_composition_changed')
    tree.body=[n for n in tree.body if not isinstance(n,ast.FunctionDef) or n.name!='observed_getter'];template=ast.literal_eval(next(n.value for n in ast.parse(own_snapshot[1]).body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='_REMOTE' for t in n.targets)))
    tree.body[-1:-1]=ast.parse(template.replace('__REMAINING__',repr(binding))).body
    prepared['program']=ast.unparse(ast.fix_missing_locations(tree))+'\n';prepared['remainingBinding']=binding;prepared['remainingAction']=action;guard_prepared(prepared);return prepared

def admit(root,reservation,correlation):return prepare(root,reservation,correlation,'admit')
def restore_once(root,reservation,correlation):return prepare(root,reservation,correlation,'restore')
def status(root,reservation,correlation):return prepare(root,reservation,correlation,'status')
def guard_prepared(prepared):
    diagnostic.guard_prepared(prepared)
    if prepared.get('remainingProofSnapshot') is not None and _proof_snapshot(prepared['remainingRoot'])!=prepared['remainingProofSnapshot']:raise CleanupError('remaining_proof_changed')
def carrier(prepared):
    guard_prepared(prepared)
    if 'remainingBinding' not in prepared:raise CleanupError('remaining_prepared_required')
    return diagnostic.carrier(prepared)
def retain_admission(root,prepared,raw):
    if prepared.get('remainingAction')!='admit' or not isinstance(raw,bytes) or len(raw)>4194304:raise CleanupError('remaining_admission_response_invalid')
    guard_prepared(prepared);value=json.loads(raw);authority=prepared['remainingBinding']['authority']
    if value.get('state')!='remaining-admitted' or value.get('correlationId')!=authority['correlationId'] or value.get('closingGuardsVerified')is not True or value.get('historicalUnknownsPreserved')is not True or value.get('replayAllowed')is not False or value.get('originalOperationOutcome')!='unknown':raise CleanupError('remaining_admission_response_invalid')
    record=value['result']['record'];pin={key:record[key] for key in ('generation','sha256')};diagnostic.original._regular_root_pin(pin)
    owner=value.get('currentControllerId')
    if not isinstance(owner,str) or re.fullmatch('[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}',owner)is None:raise CleanupError('remaining_admission_owner_invalid')
    expected={'schema':1,'binding':authority,'currentControllerId':owner,'originalOperationOutcome':'unknown','replayAllowed':False};encoded=(json.dumps(expected,sort_keys=True,separators=(',',':'))+'\n').encode()
    if record['value']!=expected or hashlib.sha256(encoded).hexdigest()!=pin['sha256'] or len(encoded)!=pin['generation'][2]:raise CleanupError('remaining_admission_response_invalid')
    path=Path(root).absolute()/'.rag_index'/SCOPE/authority['correlationId']/'admission-ready.json';_local_write(path,{'authority':authority,'currentControllerId':owner,'admissionPin':pin,'responseSha256':hashlib.sha256(raw).hexdigest(),'originalOperationOutcome':'unknown'},prepared);guard_prepared(prepared);return availability._snapshot(path)
