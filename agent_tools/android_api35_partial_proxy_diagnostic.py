"""Fixed read-only census of the consumed API35 66f5 proxy transaction."""
from __future__ import annotations
import ast, hashlib, json
from pathlib import Path
from . import android_api35_owned_proxy_restore as original
from . import android_device_availability as availability
SOURCE='532b8df2fa94f1a78f40a596d33d1cda3b036abc4f81664ae3a1a7dbd8a450e0'
OPERATION='66f5e1d4-114c-4e05-8b53-cc64e92563bf'
CAPSULE='android-api35-proxy-readmission-flow-'+OPERATION
PROOFS={'admit-remote-stdout-0.private':'77c00d93fd7cd1816fcec291a300314d8932b16ec23511e998da0e661248d2ab','restore-remote-stdout-0.private':'49cd7b65640f4931ac2db82d23689b3b4cf1f417c7180fbea64b517dfa812108','status-remote-stdout-0.private':'4f5382266bff8922a6f85dc6a80e1e4067bfe94587bd0424d799f42e764e24fe'}
class DiagnosticError(ValueError):pass
_REMOTE=r'''
PARTIAL=__PARTIAL__

def partial_public(words,owner=None):
 record=getter_cli(words,owner);GETTER_RECORDS.setdefault('partialPublic',[]).append(record)
 if type(record.get('returncode'))is not int or record['returncode']!=0 or record.get('stderrRaw')!='' or record.get('captureComplete')is not True or record.get('componentRuntime')!='EXTERNAL_JDK' or record.get('backendSourceSha256')!=RESTORE['authority']['componentBackend']['backendSourceSha256']:raise ValueError('partial_public_transport_unknown')
 value=record.get('stdout')
 if not isinstance(value,dict) or type(value.get('schemaVersion'))is not int or value['schemaVersion']!=1:raise ValueError('partial_public_schema_unknown')
 current=value.get('controllerId')
 if not isinstance(current,str) or re.fullmatch('[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}',current)is None:raise ValueError('partial_public_owner_unknown')
 if owner is not None and current!=owner:raise ValueError('partial_public_owner_changed')
 envelope=getter_envelope(record,current,0)
 if envelope is None:raise ValueError('partial_public_envelope_unknown')
 data=envelope['data']
 if words==['status'] and (data.get('runtimeRunning')is not False or data.get('runtimeObservation')!='stopped'):raise ValueError('partial_runtime_not_off')
 if words==['operations','list'] and data.get('operations')!=[]:raise ValueError('partial_operations_changed')
 return current

def partial_hardware(directory,stage):
 global GETTER_APK_PASS
 getter_generation(directory)
 if getter_stage()!=stage:raise ValueError('partial_stage_changed')
 GETTER_APK_PASS='Current'
 if getter_apk()!=GETTER['packageSha256']:raise ValueError('partial_apk_changed')
 reply=restore_read(probe_generation_command(),'partial-dex-generation');GETTER_RECORDS.setdefault('partialDex',[]).append(reply)
 if probe_generation(reply)!=RESTORE['deviceStageGeneration']:raise ValueError('partial_dex_changed')

def partial_record(directory,name,optional=False):
 if name not in ('arm.json','readmission.json','effect-fence.json','terminal.json'):raise ValueError('partial_record_invalid')
 chain,fd,pin=restore_journal_open(directory);record=None
 try:
  guard_parents(chain)
  try:record=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
  except FileNotFoundError:
   if not optional:raise
   if fp(os.fstat(fd))!=pin:raise ValueError('partial_journal_changed')
   guard_parents(chain);return {'present':False}
  before=fp(os.fstat(record))
  if not stat.S_ISREG(before[5]) or stat.S_IMODE(before[5])!=0o600 or before[6:9]!=[0,0,1] or not 0<before[2]<=262144:raise ValueError('partial_record_unsafe')
  raw=b'';capture={'name':name,'present':True,'generation':before,'bytes':0,'sha256':hashlib.sha256(raw).hexdigest(),'rawBase64':'','captureComplete':False,'identityGuardVerified':False}
  GETTER_RECORDS.setdefault('partialRecordCaptures',[]).append(capture)
  while len(raw)<before[2]:
   part=os.read(record,min(65536,before[2]-len(raw)))
   if not part:raise ValueError('partial_record_incomplete')
   raw+=part
   capture.update(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),rawBase64=base64.b64encode(raw).decode())
  capture['captureComplete']=True
  # Raw bytes/pin are durable in the response collection BEFORE named/parent
  # authentication or JSON decoding. Failed guards never erase this capture.
  if before!=fp(os.fstat(record)) or before!=fp(os.stat(name,dir_fd=fd,follow_symlinks=False)) or fp(os.fstat(fd))!=pin:raise ValueError('partial_record_changed')
  guard_parents(chain);capture['identityGuardVerified']=True
  return {'present':True,'generation':before,'sha256':capture['sha256'],'rawBase64':capture['rawBase64'],'value':json.loads(raw)}
 finally:
  if record is not None:os.close(record)
  os.close(fd);close_parents(chain)

def partial_journal(directory):
 result={name:partial_record(directory,name,optional=name=='terminal.json') for name in ('arm.json','readmission.json','effect-fence.json','terminal.json')}
 GETTER_RECORDS.setdefault('partialJournals',[]).append(result)
 arm=result['arm.json'];admission=result['readmission.json'];effect=result['effect-fence.json'];terminal=result['terminal.json']
 if {key:arm[key] for key in ('generation','sha256')}!=RESTORE['readmission']['originalArmPin'] or {key:admission[key] for key in ('generation','sha256')}!=RESTORE['readmissionPin']:raise ValueError('partial_original_records_changed')
 expected={'schema':1,'operation':RESTORE['readmission'],'originalArmPin':RESTORE['readmission']['originalArmPin'],'originalOutcome':'unknown','replayAllowed':False}
 if admission['value']!=expected:raise ValueError('partial_admission_changed')
 a=arm['value']
 if type(a.get('schema'))is not int or a['schema']!=1 or a.get('binding')!=RESTORE['authority'] or a.get('sourceSha256')!=RESTORE['sourceSha256'] or a.get('correlationId')!=RESTORE['correlationId'] or a.get('replayAllowed')is not False:raise ValueError('partial_arm_changed')
 old=RESTORE['stageFence'];adjusted=a['stageFence'];before=old['parentGeneration'];after=adjusted['parentGeneration'];name=restore_journal(directory).name
 if any(after[n]!=before[n] for n in (0,1,5,6,7)) or after[8]!=before[8]+1 or adjusted!={**old,'parentGeneration':after,'parentInventory':sorted(old['parentInventory']+[name])}:raise ValueError('partial_original_parent_changed')
 probe_fence_guard(directory,adjusted)
 identity=fp(os.stat(restore_journal(directory),follow_symlinks=False))
 if a['journalIdentity']!={str(n):identity[n] for n in (0,1,5,6,7,8)}:raise ValueError('partial_journal_identity_changed')
 names=sorted(p.name for p in restore_journal(directory).iterdir());expected_names=sorted(name for name,item in result.items() if item['present'])
 if names!=expected_names:raise ValueError('partial_journal_inventory_changed')
 e=effect['value'];operation=RESTORE['readmission']
 if type(e.get('schema'))is not int or e['schema']!=1 or e.get('correlationId')!=operation['correlationId'] or e.get('sourceSha256')!=operation['sourceSha256'] or e.get('armPin')!=operation['originalArmPin'] or e.get('readmissionPin')!=RESTORE['readmissionPin'] or e.get('effect')!='owned-global-proxy-restore' or e.get('replayAllowed')is not False:raise ValueError('partial_effect_changed')
 restore_expected(e['initial'],RESTORE_OWNED,'owned')
 if terminal['present']:
  t=terminal['value']
  if type(t.get('schema'))is not int or t['schema']!=1 or t.get('correlationId')!=operation['correlationId'] or t.get('sourceSha256')!=operation['sourceSha256'] or t.get('readmissionPin')!=RESTORE['readmissionPin'] or t.get('fenceSha256')!=effect['sha256'] or t.get('originalOutcome')!='unknown' or t.get('replayAllowed')is not False:raise ValueError('partial_terminal_changed')
 return result

def partial_census():
 first=restore_read(restore_settings_command(),'partial-settings-before');GETTER_RECORDS.setdefault('partialSettings',[]).append(first);before=restore_settings(first)
 reply=restore_read(probe_getter_command(RESTORE['deviceStageGeneration']['file']),'partial-binder');GETTER_RECORDS.setdefault('partialBinder',[]).append(reply);binder=parse_probe_current(reply)
 second=restore_read(restore_settings_command(),'partial-settings-after');GETTER_RECORDS['partialSettings'].append(second);after=restore_settings(second)
 if before!=after:raise ValueError('partial_settings_changed')
 return {'settings':after,'binder':binder,'kind':restore_proxy_kind(binder)}

def observed_getter(directory):
 global GETTER_RECORDS,GETTER_APK_PASS,PROBE_CASES,RESTORE_CLOSING,RESTORE_DEADLINE
 GETTER_RECORDS={'shellFdReads':[]};GETTER_APK_PASS='Current';PROBE_CASES=[];RESTORE_CLOSING=False;RESTORE_DEADLINE=time.monotonic()+600
 stage=None;owner=None;result={};primary=None;closing=None;primary_type=None;closing_type=None
 try:
  stage=getter_stage();partial_hardware(directory,stage)
  owner=partial_public(['status']);partial_public(['status'],owner);partial_public(['operations','list'],owner)
  result['journalBefore']=partial_journal(directory);result['censusBefore']=partial_census()
  partial_hardware(directory,stage);partial_public(['status'],owner);partial_public(['operations','list'],owner)
  result['censusAfter']=partial_census();result['journalAfter']=partial_journal(directory)
  if result['journalBefore']!=result['journalAfter']:raise ValueError('partial_journal_changed')
  if result['censusBefore']!=result['censusAfter']:raise ValueError('partial_census_changed')
 except (ValueError,OSError,KeyError,TypeError,UnicodeError,subprocess.TimeoutExpired,NameError,AttributeError) as error:
  primary_type=type(error).__name__;primary=str(error) if isinstance(error,ValueError) and re.fullmatch('(?:partial|probe|getter|coldboot|component)_[a-z_]{1,72}',str(error)) else 'partial_execution_unknown'
 finally:
  RESTORE_CLOSING=True
  try:
   if stage is None or owner is None:raise ValueError('partial_initial_guard_unavailable')
   partial_hardware(directory,stage);partial_public(['status'],owner);partial_public(['operations','list'],owner)
  except (ValueError,OSError,KeyError,TypeError,UnicodeError,subprocess.TimeoutExpired,NameError,AttributeError) as error:
   closing_type=type(error).__name__;closing=str(error) if isinstance(error,ValueError) and re.fullmatch('(?:partial|probe|getter|coldboot|component)_[a-z_]{1,72}',str(error)) else 'partial_closing_unknown'
 census=result.get('censusAfter',{});rows=census.get('settings',{}).get('rows',{})
 return {'state':'diagnostic','reason':primary or closing,'primaryReason':primary,'primaryExceptionType':primary_type,'closingReason':closing,'closingExceptionType':closing_type,'closingGuardsVerified':closing is None,'observationComplete':primary is None and closing is None,'correlationId':PARTIAL['correlationId'],'originalOperationCorrelationId':RESTORE['readmission']['correlationId'],'currentControllerId':owner,'historicalOwnerMatchesCurrent':owner==FD_OWNER,'pacAbsent':('global_http_proxy_pac' not in rows) if census else None,'effectiveProxyClear':census.get('kind')=='clear' if census else None,'result':result,'records':GETTER_RECORDS,'productAdmitted':False,'acceptanceComplete':False,'historicalUnknownsPreserved':True,'readmissionGranted':False,'replayAllowed':False,'settingsEffectsSubmitted':False}
'''

def prepare(root,reservation):
    root=Path(root).absolute();path=Path(original.__file__).absolute();source=availability._snapshot(path)
    if hashlib.sha256(source[1]).hexdigest()!=SOURCE:raise DiagnosticError('partial_original_source_changed')
    prepared=original.readmission_status(root,reservation,OPERATION)
    if availability._snapshot(path)!=source:raise DiagnosticError('partial_original_source_changed')
    own=Path(__file__).absolute();own_snapshot=availability._snapshot(own);prepared['snapshots'][own]=own_snapshot
    proof_pins={}
    for name,sha in PROOFS.items():
        file=root/'.runtime/parity-evidence'/CAPSULE/name;snapshot=availability._snapshot(file)
        if hashlib.sha256(snapshot[1]).hexdigest()!=sha:raise DiagnosticError('partial_consumed_proof_changed')
        prepared['snapshots'][file]=snapshot;proof_pins[name]={'generation':list(snapshot[0]),'sha256':sha}
    binding={'correlationId':'b23f1848-3c0e-4ccf-a5f2-cdc1b647dc13','sourceSha256':hashlib.sha256(own_snapshot[1]).hexdigest(),'consumedSourceSha256':SOURCE,'proofPins':proof_pins}
    tree=ast.parse(prepared['program']);template=ast.literal_eval(next(n.value for n in ast.parse(own_snapshot[1]).body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='_REMOTE' for t in n.targets)))
    remove={'observed_getter','restore_transaction','restore_fixed_step','restore_arm','restore_readmission_admit','restore_record'}
    tree.body=[n for n in tree.body if not isinstance(n,ast.FunctionDef) or n.name not in remove]
    tree.body[-1:-1]=ast.parse(template.replace('__PARTIAL__',repr(binding))).body
    prepared['program']=ast.unparse(ast.fix_missing_locations(tree))+'\n';prepared['partialBinding']=binding
    original.guard_prepared(prepared);return prepared

def guard_prepared(prepared):original.guard_prepared(prepared)
def carrier(prepared):
    guard_prepared(prepared)
    if 'partialBinding' not in prepared:raise DiagnosticError('partial_prepared_required')
    return original.current.ssh_carrier(prepared)
