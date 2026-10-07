"""One-shot negative-only cleanup of a closed, expired API35 consent dialog."""
from __future__ import annotations
import hashlib
import inspect
import json
import os
from pathlib import Path
import stat
import xml.etree.ElementTree as ET
from agent_tools import android_consent_grant_acceptance as grant

_BOUNDS=grant._BOUNDS
_warning_owned=grant._warning_owned
_GROUP='.rag_index/android-obsolete-consent-denial'

def _cancel_button(xml):
    if not isinstance(xml,str) or not 0<len(xml)<=1048576:return None
    try:tree=ET.fromstring(xml)
    except ET.ParseError:return None
    nodes=list(tree.iter('node'))
    if tree.tag!='hierarchy' or not nodes or any(n.get('package') not in (None,'com.android.vpndialogs') for n in nodes):return None
    def owned(resource):return [n for n in nodes if n.get('resource-id')==resource]
    title=owned('android:id/alertTitle');warning=owned('com.android.vpndialogs:id/warning');cancel=owned('android:id/button2')
    if len(title)!=1 or len(warning)!=1 or len(cancel)!=1 or any(n.get('package')!='com.android.vpndialogs' for n in title+warning+cancel) or title[0].get('text')!='Connection request' or not _warning_owned(warning[0].get('text')) or cancel[0].get('text')!='Cancel' or cancel[0].get('enabled')!='true':return None
    match=_BOUNDS.fullmatch(cancel[0].get('bounds',''))
    if match is None:return None
    l,t,r,b=map(int,match.groups())
    return ((l+r)//2,(t+b)//2) if 0<=l<r<=4096 and 0<=t<b<=4096 else None

# Full semantic routing snapshots stay outside the final negative-button guard.
_DENIAL_SECONDS=2*grant._FULL_SNAPSHOT_SECONDS+2*(7*45+120+4*135)+3*180+135+5*120+4*135+120
_STATUS_SECONDS=grant._FULL_SNAPSHOT_SECONDS+180+3*120+2*135+120
_BRANCH=r'''
 if mode not in ('obsolete-deny','obsolete-deny-status'):emit('unknown','mode_invalid')
 expected_keys={'schema','kind','originalCorrelationId','closureId','denialId','observationId','intentSha256','closureProof','closureIntentSha256','closureMarkerSha256'}
 if not isinstance(recovery,dict) or set(recovery)!=expected_keys or type(recovery['schema']) is not int or recovery['schema']!=1 or recovery['kind']!='obsolete-consent-denial' or recovery['originalCorrelationId']!=correlation or recovery['intentSha256']!=intent_sha or any(not isinstance(recovery[k],str) or re.fullmatch('[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}',recovery[k]) is None for k in ('closureId','denialId','observationId')) or recovery['denialId'] in (correlation,recovery['closureId']):emit('unknown','denial_binding_invalid')
 closing_name='prompt-close-'+recovery['closureId']+'-closed.json';closure_name='prompt-close-'+recovery['closureId']+'.json'
 closure_raw=private(job/closure_name,16384);closure=json.loads(closure_raw);closing=json.loads(private(job/closing_name))
 if not isinstance(closing,dict) or type(closing.get('schema')) is not int or closing.get('schema')!=1 or set(closing)!=set(recovery['closureProof']) or closing!=recovery['closureProof'] or hashlib.sha256(closure_raw).hexdigest()!=closing.get('bindingSha256') or closing.get('intentSha256')!=intent_sha or closing.get('closureId')!=recovery['closureId'] or closing.get('observationId')!=recovery['observationId'] or closing.get('originalOutcome')!='unknown' or closing.get('grantObserved') is not False or closing.get('permissionGranted') is not False or closing.get('runtimeStarted') is not False:emit('unknown','denial_closure_invalid')
 original_names=('intent.json','identity.json','worker.py','result.json','on-intent.json','operation.json','opening.json','baseline-source-settings.json',closure_name,closing_name)
 original_records={name:(private(job/name,131072 if name=='worker.py' else 1048576 if name in ('opening.json','baseline-source-settings.json') else 16384),fingerprint((job/name).lstat())) for name in original_names}
 if not isinstance(closure.get('originalExtra'),dict) or set(closure['originalExtra'])!={'opening.json','baseline-source-settings.json'}:emit('unknown','denial_closure_invalid')
 for name,meta in closure['originalExtra'].items():
  raw,generation=original_records[name]
  if meta!={'sha256':hashlib.sha256(raw).hexdigest(),'fingerprint':generation}:emit('unknown','denial_original_changed')
 if json.loads(original_records['result.json'][0])!={'state':'unknown','result':None,'reason':'prompt_not_owned'}:emit('unknown','denial_original_invalid')
 identity=json.loads(original_records['identity.json'][0]);operation=json.loads(original_records['operation.json'][0]);opening=json.loads(original_records['opening.json'][0])
 if hashlib.sha256(json.dumps(opening,sort_keys=True,separators=(',',':')).encode()).hexdigest()!=closing.get('snapshotSha256'):emit('unknown','denial_closure_invalid')
 if set(identity)!={'pid','startTicks'} or any(type(identity[k]) is not int or identity[k]<1 for k in identity):emit('unknown','denial_original_invalid')
 try:
  fields=pathlib.Path('/proc/%d/stat'%identity['pid']).read_text().rsplit(')',1)[1].split()
  if int(fields[19])==identity['startTicks'] and fields[0]!='Z':emit('unknown','denial_worker_live')
 except FileNotFoundError:pass
 except (OSError,ValueError,IndexError):emit('unknown','denial_worker_unknown')
 def chain_stable():
  for name,(raw,generation) in original_records.items():
   if private(job/name,131072 if name=='worker.py' else 1048576 if name in ('opening.json','baseline-source-settings.json') else 16384)!=raw or fingerprint((job/name).lstat())!=generation:emit('unknown','denial_original_changed')
  for name in ('tap-intent.json','terminal.json','collected.json'):
   if (job/name).exists() or (job/name).is_symlink():emit('unknown','denial_original_invalid')
  value=json.loads(run(['python3','-I','-B','-c','exec('+repr(PROMPT_FETCH_SOURCE)+')',root,correlation,recovery['observationId'],expected,'{"mode":"metadata"}'],120,16384))
  if value!=closure.get('retained'):emit('unknown','denial_observation_changed')
 chain_stable()
 context=json.loads(private(base/('android-grant-prompt-'+correlation+'-'+recovery['observationId'])/'operation-observation.json',65536));entries=context.get('listAfter')
 if not isinstance(entries,list) or len(entries)!=1 or entries!=context.get('listBefore'):emit('unknown','denial_terminal_invalid')
 terminal_operation=entries[0]
 if not isinstance(terminal_operation,dict) or terminal_operation.get('controllerId')!=owner or terminal_operation.get('id')!=operation.get('operationId') or terminal_operation.get('operation')!='on' or terminal_operation.get('phase')!='failed' or terminal_operation.get('final') is not True or terminal_operation.get('code')!='INTERACTION_REQUIRED':emit('unknown','denial_terminal_invalid')
 for key in ('statusBefore','statusAfter'):
  value=context.get(key)
  if not isinstance(value,dict) or value.get('controllerId')!=owner or value.get('configurationRevision')!=revision or value.get('operationId')!=operation['operationId'] or value.get('final') is not True or value.get('ok') is not False or value.get('code')!='INTERACTION_REQUIRED':emit('unknown','denial_terminal_invalid')
 env=public_cli_environment(adb,pathlib.Path(cli));lock=base/'android-native-device-api35.lock'
 lease_fd=os.open(lock,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0));info=os.fstat(lease_fd)
 if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1:emit('unknown','device_lock_unsafe')
 fcntl.flock(lease_fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
 lease=base/'android-native-device-api35.lease';claim={'owner':'android-obsolete-consent-denial','host':'archlinux','device':'api35','correlationId':recovery['denialId'],'originalCorrelationId':correlation}
 name='obsolete-denial-'+recovery['denialId'];intent_name=name+'.json';tap_name=name+'-tap.json';terminal_name=name+'-terminal.json'
 if mode=='obsolete-deny':
  if (job/intent_name).exists() or (job/intent_name).is_symlink():emit('unknown','denial_consumed')
  if lease.exists() or lease.is_symlink():emit('unknown','device_lease_active')
  def protected_record(name,value):
   raw=json.dumps(value,sort_keys=True,separators=(',',':')).encode()+b'\n'
   fd=os.open(job/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
   with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno());created=fingerprint(os.fstat(f.fileno()))
   d=os.open(job,os.O_RDONLY|getattr(os,'O_DIRECTORY',0));os.fsync(d);os.close(d)
   if private(job/name)!=raw or fingerprint((job/name).lstat())!=created:emit('unknown','denial_intent_changed')
   return raw,created
  protected_record(intent_name,recovery)
  fd=os.open(lease,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
  with os.fdopen(fd,'wb') as f:f.write(json.dumps(claim,sort_keys=True,separators=(',',':')).encode());f.flush();os.fsync(f.fileno())
  d=os.open(base,os.O_RDONLY|getattr(os,'O_DIRECTORY',0));os.fsync(d);os.close(d)
  claim_fd,claim_fingerprint=retain_claim(lease,claim)
 else:
  if json.loads(private(job/intent_name))!=recovery or not (job/terminal_name).exists() or lease.exists() or lease.is_symlink():emit('unknown','denial_incomplete')
 child_raw=private(job/intent_name);child_generation=fingerprint((job/intent_name).lstat());child_sha=hashlib.sha256(child_raw).hexdigest()
 tap_generation=None;terminal_generation=None
 if mode=='obsolete-deny-status':
  tap_generation=(private(job/tap_name),fingerprint((job/tap_name).lstat()))
  terminal_generation=(private(job/terminal_name),fingerprint((job/terminal_name).lstat()))
 def child_stable():
  chain_stable()
  if private(job/intent_name)!=child_raw or fingerprint((job/intent_name).lstat())!=child_generation:emit('unknown','denial_intent_changed')
  for name,retained in ((tap_name,tap_generation),(terminal_name,terminal_generation)):
   if retained is not None and (private(job/name)!=retained[0] or fingerprint((job/name).lstat())!=retained[1]):emit('unknown','denial_intent_changed')
 def foreign_history():
  entries=semantic_operations()['operations']
  if any(x.get('controllerId')!=owner or x.get('final') is not True for x in entries):emit('unknown','operations_active')
  for entry in entries:
   if entry.get('id')==operation['operationId'] and entry!=terminal_operation:emit('unknown','denial_terminal_changed')
  return [x for x in entries if x.get('id')!=operation['operationId']]
 def light():
  device()
  if data('status')!=opening['runtime'] or data('source','show')!=opening['source'] or data('settings','show')!=opening['settings'] or data('locations','list').get('locations')!=[]:emit('unknown','denial_baseline_changed')
  if foreign_history()!=history:emit('unknown','denial_history_changed')
 def ui_absent(xml):
  try:tree=ET.fromstring(xml);nodes=list(tree.iter('node'))
  except ET.ParseError:return False
  return tree.tag=='hierarchy' and bool(nodes) and all(n.get('package')!='com.android.vpndialogs' for n in nodes)
 history=foreign_history()
 if snapshot('false')!=opening:emit('unknown','denial_baseline_changed')
 if mode=='obsolete-deny':
  first,first_meta=capture_prompt(True);point=_cancel_button(first)
  if point is None:emit('unknown','denial_prompt_not_owned')
  light();second,second_meta=capture_prompt(True)
  if second!=first or _cancel_button(second)!=point:emit('unknown','denial_prompt_changed')
  child_stable()
  tap_generation=protected_record(tap_name,{'denialId':recovery['denialId'],'intentSha256':child_sha,'point':list(point),'xmlSha256':hashlib.sha256(second.encode()).hexdigest(),'button':'android:id/button2','action':'Cancel'})
  light();latest,latest_meta=capture_prompt(False)
  if latest!=second or _cancel_button(latest)!=point:emit('unknown','denial_prompt_changed')
  if not claim_current(claim_fd,lease,claim_fingerprint):emit('unknown','device_lease_changed')
  for metadata in (first_meta,second_meta,latest_meta):verify_prompt_evidence(base/('android-grant-prompt-'+correlation+'-'+metadata['observationId']))
  child_stable();shell('input','tap',str(point[0]),str(point[1]))
 if mode=='obsolete-deny' and snapshot('false')!=opening:emit('unknown','denial_baseline_changed')
 xml,metadata=capture_prompt(True)
 if not ui_absent(xml):emit('unknown','denial_dialog_still_present')
 verify_prompt_evidence(base/('android-grant-prompt-'+correlation+'-'+metadata['observationId']))
 if foreign_history()!=history:emit('unknown','denial_history_changed')
 child_stable()
 tap=json.loads(private(job/tap_name))
 if not isinstance(tap,dict) or set(tap)!={'denialId','intentSha256','point','xmlSha256','button','action'} or tap.get('denialId')!=recovery['denialId'] or tap.get('intentSha256')!=child_sha or tap.get('button')!='android:id/button2' or tap.get('action')!='Cancel' or not isinstance(tap.get('point'),list) or len(tap['point'])!=2 or any(type(x) is not int or not 0<=x<=4096 for x in tap['point']) or not isinstance(tap.get('xmlSha256'),str) or re.fullmatch('[0-9a-f]{64}',tap['xmlSha256']) is None:emit('unknown','denial_tap_invalid')
 proof={'schema':1,'denialId':recovery['denialId'],'closureId':recovery['closureId'],'originalCorrelationId':correlation,'observationId':recovery['observationId'],'intentSha256':child_sha,'tapSha256':hashlib.sha256(private(job/tap_name)).hexdigest(),'originalOutcome':'unknown','grantObserved':False,'permissionGranted':False,'runtimeStarted':False,'uiAbsent':True,'scope':'obsolete-dialog-denial'}
 if mode=='obsolete-deny':
  if not claim_current(claim_fd,lease,claim_fingerprint):emit('unknown','device_lease_changed')
  terminal_generation=protected_record(terminal_name,proof);child_stable()
  if not claim_current(claim_fd,lease,claim_fingerprint):emit('unknown','device_lease_changed')
  lease.unlink();d=os.open(base,os.O_RDONLY|getattr(os,'O_DIRECTORY',0));os.fsync(d);os.close(d)
 elif json.loads(private(job/terminal_name))!=proof:emit('unknown','denial_terminal_changed')
 emit('complete',proof=proof,remoteClaimReleased=True)
'''
_SOURCE='PROMPT_FETCH_SOURCE='+repr(grant._PROMPT_FETCH)+'\n'+inspect.getsource(_cancel_button)+'\n'+grant._REMOTE.replace("replacement=json.loads(sys.argv[8]) if len(sys.argv)>=9 else None","recovery=json.loads(sys.argv[8]);replacement=None").replace(" if mode=='status':",_BRANCH+" if mode=='status':",1)

def _uuid(value):return isinstance(value,str) and grant._UUID.fullmatch(value) is not None

def _encode(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode()

def _hash(value):return hashlib.sha256(_encode(value)).hexdigest()

def _journal(root,denial_id):
    if not _uuid(denial_id):raise ValueError('denial ID')
    return Path(root).resolve()/_GROUP/(denial_id+'.json')

def _claim(payload):return {'owner':'android-obsolete-consent-denial','host':'archlinux','device':'api35','correlationId':payload['denialId'],'originalCorrelationId':payload['originalCorrelationId']}

def _reply(denial_id,state,reason=None,**extra):
    return {'ok':state=='complete','state':state,'reason':reason,'denialId':denial_id,'replayAllowed':False,'nativeActionAllowed':False,'productAction':False,'originalOutcome':'unknown','grantObserved':False,**extra}

def _private(path):
    meta=path.parent.lstat()
    if not stat.S_ISDIR(meta.st_mode) or meta.st_uid!=os.getuid() or stat.S_IMODE(meta.st_mode)!=0o700:raise ValueError('private parent')
    return grant._closed_marker(path)

def _raw_sha(path,value):
    fd,fp=grant._retain_claim(path,value,8192)
    try:
        os.lseek(fd,0,os.SEEK_SET);raw=os.read(fd,8193)
        if len(raw)!=fp[2] or not grant._claim_current(fd,path,fp):raise ValueError('private bytes changed')
        return hashlib.sha256(raw).hexdigest()
    finally:os.close(fd)

def _admission(root,original_id,closure_id,denial_id,observation_id):
    if not all(_uuid(x) for x in (original_id,closure_id,denial_id,observation_id)) or denial_id in (original_id,closure_id):raise ValueError('IDs')
    original=grant._load(root,original_id)
    if original is None:raise ValueError('original')
    path=grant._prompt_close_intent(root,original_id,closure_id);closing_path=path.with_suffix('.closed.json')
    closure=_private(path);closing=_private(closing_path)
    expected={'schema':1,'kind':'prompt-no-effect','correlationId':original_id,'closureId':closure_id,'observationId':observation_id,'intentSha256':_hash(original)}
    proof=closing.get('proof') if isinstance(closing,dict) else None
    keys={'schema','closureId','intentSha256','bindingSha256','observationId','snapshotSha256','originalOutcome','grantObserved','permissionGranted','runtimeStarted'}
    if type(closure.get('schema')) is not int or closure!=expected or not isinstance(closing,dict) or set(closing)!={'schema','payload','proof','leases'} or type(closing['schema']) is not int or closing['schema']!=1 or closing['payload']!=closure or not isinstance(proof,dict) or set(proof)!=keys or type(proof.get('schema')) is not int or proof.get('schema')!=1 or proof.get('closureId')!=closure_id or proof.get('observationId')!=observation_id or proof.get('intentSha256')!=_hash(original) or proof.get('originalOutcome')!='unknown' or any(proof.get(k) is not False for k in ('grantObserved','permissionGranted','runtimeStarted')) or any(not isinstance(proof.get(k),str) or grant._SHA.fullmatch(proof[k]) is None for k in ('bindingSha256','snapshotSha256')):raise ValueError('closed proof')
    leases=closing['leases']
    if not isinstance(leases,dict) or set(leases)!={'shared','document'} or any(not isinstance(fp,list) or len(fp)!=8 or any(type(x) is not int for x in fp) for fp in leases.values()):raise ValueError('closed claims')
    payload={'schema':1,'kind':'obsolete-consent-denial','originalCorrelationId':original_id,'closureId':closure_id,'denialId':denial_id,'observationId':observation_id,'intentSha256':_hash(original),'closureProof':proof,'closureIntentSha256':_raw_sha(path,closure),'closureMarkerSha256':_raw_sha(closing_path,closing)}
    return original,payload,{grant._journal(root,original_id):original,path:closure,closing_path:closing}

def _load(root,denial_id):
    payload=_private(_journal(root,denial_id))
    if not isinstance(payload,dict) or set(payload)!={'schema','kind','originalCorrelationId','closureId','denialId','observationId','intentSha256','closureProof','closureIntentSha256','closureMarkerSha256'} or payload.get('denialId')!=denial_id:raise ValueError('intent shape')
    original,current,historical=_admission(root,payload['originalCorrelationId'],payload['closureId'],denial_id,payload['observationId'])
    if payload!=current:raise ValueError('original binding changed')
    return original,payload,historical

def _observe(root,original,payload,mode):
    config,profile=grant._route(root,original)
    argv=grant.ssh_transport.build_ssh_argv(config,'archlinux',60,command=('python3','-I','-B','-c','exec('+repr(_SOURCE)+')',mode,profile['adb'],original['cliPath'],profile['serial'],original['fixtureRoot'],original['correlationId'],json.dumps(original,sort_keys=True,separators=(',',':')),json.dumps(payload,sort_keys=True,separators=(',',':'))))
    code,out=grant.android_observation._run_probe(argv,_DENIAL_SECONDS if mode=='obsolete-deny' else _STATUS_SECONDS)
    value=json.loads(out) if code==0 and len(out)<=16384 else None
    if not isinstance(value,dict) or value.get('correlationId')!=original['correlationId']:raise ValueError('observer')
    return value

_REASONS=set(grant._RECONCILE_REASONS)|{'denial_binding_invalid','denial_closure_invalid','denial_original_invalid','denial_worker_live','denial_worker_unknown','denial_original_changed','denial_observation_changed','denial_terminal_invalid','denial_consumed','denial_incomplete','denial_intent_changed','denial_terminal_changed','denial_baseline_changed','denial_history_changed','denial_prompt_not_owned','denial_prompt_changed','denial_dialog_still_present','denial_tap_invalid'}
def _result(root,original,payload,mode):
    value=_observe(root,original,payload,mode);denial_id=payload['denialId']
    if value.get('state')=='unknown':return _reply(denial_id,'unknown',value.get('reason') if value.get('reason') in _REASONS else 'denial_unknown',claimsReleased=False)
    proof=value.get('proof');expected={'schema':1,'denialId':denial_id,'closureId':payload['closureId'],'originalCorrelationId':original['correlationId'],'observationId':payload['observationId'],'intentSha256':hashlib.sha256(_encode(payload)+b'\n').hexdigest(),'originalOutcome':'unknown','grantObserved':False,'permissionGranted':False,'runtimeStarted':False,'uiAbsent':True,'scope':'obsolete-dialog-denial'}
    if value.get('state')!='complete' or value.get('remoteClaimReleased') is not True or not isinstance(proof,dict) or set(proof)!=set(expected)|{'tapSha256'} or any(type(proof.get(k)) is not type(v) or proof.get(k)!=v for k,v in expected.items()) or not isinstance(proof['tapSha256'],str) or grant._SHA.fullmatch(proof['tapSha256']) is None:raise ValueError('terminal proof')
    return _reply(denial_id,'complete',proof=proof,remoteClaimReleased=True,claimsReleased=False)

def start(root:Path|str,original_id:str,closure_id:str,denial_id:str,observation_id:str)->dict:
    held=[]
    try:
        path=_journal(root,denial_id)
        if path.exists() or path.is_symlink():return status(root,denial_id)
        original,payload,historical=_admission(root,original_id,closure_id,denial_id,observation_id)
        with grant.android_endpoint_admission._shared_device_lease(Path(root).resolve(),'archlinux','api35') as lease,grant.android_document_acceptance._device_guard(root,'archlinux','api35') as document:
            if lease.exists() or lease.is_symlink() or document.exists() or document.is_symlink():raise ValueError('active claims')
            for target,value in historical.items():
                fd,fp=grant._retain_claim(target,value,8192);held.append((fd,fp,target))
            path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
            meta=path.parent.lstat()
            if not stat.S_ISDIR(meta.st_mode) or meta.st_uid!=os.getuid() or stat.S_IMODE(meta.st_mode)!=0o700:raise ValueError('private journal')
            created=grant._write_closed_marker(path,payload);fd,fp=grant._retain_claim(path,payload,4096);held.append((fd,fp,path))
            if created!=fp:raise ValueError('intent generation')
            for target,value in ((lease,_claim(payload)),(document,{'host':'archlinux','device':'api35','correlationId':denial_id})):
                grant._write_closed_marker(target,value);fd,fp=grant._retain_claim(target,value);held.append((fd,fp,target))
            result=_result(root,original,payload,'obsolete-deny')
            if any(not grant._claim_current(fd,target,fp) for fd,fp,target in held):raise ValueError('local generation')
            return result
    except (OSError,RuntimeError,TimeoutError,ValueError,UnicodeError,KeyError,TypeError):return _reply(denial_id,'unknown','denial_admission_or_transport_unknown',claimsReleased=False)
    finally:
        for fd,_,_ in held:os.close(fd)

def status(root:Path|str,denial_id:str)->dict:
    held=[]
    try:
        original,payload,historical=_load(root,denial_id);historical[_journal(root,denial_id)]=payload
        for target,value in historical.items():
            fd,fp=grant._retain_claim(target,value,8192);held.append((fd,fp,target))
        result=_result(root,original,payload,'obsolete-deny-status')
        if any(not grant._claim_current(fd,target,fp) for fd,fp,target in held):raise ValueError('local generation')
        return result
    except (OSError,RuntimeError,TimeoutError,ValueError,UnicodeError,KeyError,TypeError):return _reply(denial_id,'unknown','denial_observation_unknown',claimsReleased=False)
    finally:
        for fd,_,_ in held:os.close(fd)

def collect(root:Path|str,denial_id:str)->dict:
    held=[];claims={}
    try:
        original,payload,historical=_load(root,denial_id);path=_journal(root,denial_id);historical[path]=payload;marker_path=path.with_suffix('.closed.json')
        with grant.android_endpoint_admission._shared_device_lease(Path(root).resolve(),'archlinux','api35') as lease,grant.android_document_acceptance._device_guard(root,'archlinux','api35') as document:
            marker=_private(marker_path) if marker_path.exists() or marker_path.is_symlink() else None
            for target,value in historical.items():
                fd,fp=grant._retain_claim(target,value,8192);held.append((fd,fp,target))
            if marker is not None:
                fd,fp=grant._retain_claim(marker_path,marker,4096);held.append((fd,fp,marker_path))
            for key,target,value in (('shared',lease,_claim(payload)),('document',document,{'host':'archlinux','device':'api35','correlationId':denial_id})):
                if target.exists() or target.is_symlink():claims[key]=(*grant._retain_claim(target,value),target)
                elif marker is None:raise ValueError('missing claim')
            result=_result(root,original,payload,'obsolete-deny-status')
            if result['state']!='complete':return result
            expected={'schema':1,'intentSha256':hashlib.sha256(path.read_bytes()).hexdigest(),'proof':result['proof'],'leases':marker['leases'] if marker is not None else {k:v[1] for k,v in claims.items()}}
            if marker is not None and marker!=expected:raise ValueError('marker')
            if marker is None:
                created=grant._write_closed_marker(marker_path,expected);fd,fp=grant._retain_claim(marker_path,expected,4096);held.append((fd,fp,marker_path))
                if fp!=created:raise ValueError('marker generation')
            def generations():
                if any(not grant._claim_current(fd,target,fp) for fd,fp,target in held):raise ValueError('historical generation')
            generations()
            for key,(fd,fp,target) in claims.items():
                generations()
                if not grant._claim_current(fd,target,fp) or expected['leases'].get(key)!=fp:raise ValueError('claim generation')
                target.unlink();d=os.open(target.parent,os.O_RDONLY|getattr(os,'O_DIRECTORY',0));os.fsync(d);os.close(d)
            generations()
            return {**result,'claimsReleased':True}
    except (OSError,RuntimeError,TimeoutError,ValueError,UnicodeError,KeyError,TypeError):return _reply(denial_id,'unknown','denial_collection_unknown',claimsReleased=False)
    finally:
        for fd,_,_ in (*held,*claims.values()):os.close(fd)

obsolete_dialog_deny=start
