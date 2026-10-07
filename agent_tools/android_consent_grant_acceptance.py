"""One-shot typed Android consent grant, with empty-location INVALID_ARGUMENT proof.

Only the fixed, owned Android system positive button is tapped. Unknown outcomes
retain the private intent and device claims; no observation replays an operation.
"""
from __future__ import annotations
import ast
import base64
import hashlib
import inspect
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import xml.etree.ElementTree as ET
from typing import Any
from agent_tools import (android_admission_readback, android_cli_stage, android_consent_acceptance,
                         android_document_acceptance, android_endpoint_admission, android_observation,
                         android_package_install, native_artifact_registry, ssh_transport)

_UUID=re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z")
_SHA=re.compile(r"[0-9a-f]{64}\Z")
_GROUP='.rag_index/android-consent-grant-acceptance'
_BOUNDS=re.compile(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]")

def _warning_owned(text: str, api: int = 35) -> bool:
    # API29 has no reviewed native warning variant yet. Retain its prompt; do not tap.
    return type(api) is int and api == 35 and text in ('VPN Control wants to set up a VPN connection that allows it to monitor network traffic. Only accept if you trust the source.','VPN Control wants to set up a VPN connection that allows it to monitor network traffic. Only accept if you trust the source. \n\n￼ appears at the top of your screen when VPN is active.')

def _positive_button(xml: str, api: int = 35) -> tuple[int,int] | None:
    if not isinstance(xml,str) or not 0<len(xml)<=1048576: return None
    try: tree=ET.fromstring(xml)
    except ET.ParseError: return None
    nodes=list(tree.iter('node'))
    if tree.tag!='hierarchy' or not nodes or any(n.get('package') not in (None,'com.android.vpndialogs') for n in nodes): return None
    owned=lambda resource:[n for n in nodes if n.get('resource-id')==resource]
    title=owned('android:id/alertTitle'); warning=owned('com.android.vpndialogs:id/warning'); positive=owned('android:id/button1')
    if (len(title)!=1 or len(warning)!=1 or len(positive)!=1 or any(n.get('package')!='com.android.vpndialogs' for n in title+warning+positive) or
        title[0].get('text')!='Connection request' or not _warning_owned(warning[0].get('text'),api) or
        positive[0].get('enabled')!='true' or positive[0].get('text')!='OK'): return None
    match=_BOUNDS.fullmatch(positive[0].get('bounds',''))
    if not match:return None
    l,t,r,b=map(int,match.groups())
    return ((l+r)//2,(t+b)//2) if 0<=l<r<=4096 and 0<=t<b<=4096 else None

_SUBMIT=android_admission_readback._ASYNC_SUBMIT.replace('android-readback-job-','android-consent-grant-')

# Upper bounds include every sequential guard, not just the large export.
_ROUTING_EXPORT_SECONDS=300
# Snapshot: 7 ADB reads + tree + diagnostics +5 JSON reads + export,
# then two status reads and a second complete device/tree guard.
_FULL_SNAPSHOT_SECONDS=7*45+120+105+3*135+5*135+(_ROUTING_EXPORT_SECONDS+15)+2*135+(7*45+120)
_RECONCILE_OBSERVER_SECONDS=3*_FULL_SNAPSHOT_SECONDS+3*135+120
_COLLECT_OBSERVER_SECONDS=2*_FULL_SNAPSHOT_SECONDS+45+120

# Exact reviewed CLI verifier and the same UI parser used by local regressions.
_REMOTE=(android_observation._canonical_cli_environment_source()+'\nCLI_STAGE_STATUS='+repr(android_cli_stage._STATUS)+'\n'+
         "import re,xml.etree.ElementTree as ET\n_BOUNDS=re.compile(r'\\[(\\d+),(\\d+)\\]\\[(\\d+),(\\d+)\\]')\n"+inspect.getsource(_warning_owned)+inspect.getsource(_positive_button)+r'''
import fcntl,hashlib,json,os,pathlib,stat,subprocess,sys,tempfile,time,uuid
mode,adb,cli,serial,root,correlation,expected=sys.argv[1:8]
replacement=json.loads(sys.argv[8]) if len(sys.argv)>=9 else None
continuation=json.loads(sys.argv[9]) if len(sys.argv)==10 else None
continuation_mode=mode in ('reconcile-continuation','reconcile-continuation-status')
replacement_mode=mode in ('reconcile-replacement','reconcile-replacement-status') or continuation_mode
if (continuation is not None)!=continuation_mode:raise ValueError('continuation mode invalid')
read_only_closure=mode in ('reconcile-replacement-status','reconcile-continuation-status')
if (replacement is not None)!=replacement_mode:raise ValueError('replacement mode invalid')
intent=json.loads(expected); base=pathlib.Path(root); job=base/('android-consent-grant-'+correlation)
owner=intent['expectedOwner']; revision=intent['expectedRevision']; env=None; lease_fd=None; claim_fd=None; checkpoint=None; owned_diagnostics={};observations_loaded=False;observation_directory=None;observation_binding=None;ephemeral_fds=[];diagnostic_history=None
intent_sha=hashlib.sha256(expected.encode()).hexdigest()
def emit(state,reason=None,**extra):
 if mode.startswith('reconcile') and diagnostic_history is not None:extra['diagnosticHistory']=diagnostic_history
 if state=='unknown' and mode.startswith('reconcile') and checkpoint is not None:extra['checkpoint']=checkpoint
 print(json.dumps({'state':state,'reason':reason,'correlationId':correlation,**extra},separators=(',',':'))); raise SystemExit(0)
def private(path,limit=8192):
 global checkpoint
 if mode.startswith('reconcile'):checkpoint={'intent.json':'original-intent','identity.json':'original-identity','worker.py':'original-worker','result.json':'original-result','no-effect-closed.json':'remote-marker','baseline-source-settings.json':'baseline-record','routing.json':'admitted-backup',('android-native-device-'+intent['device']+'.lease'):'remote-claim'}.get(path.name,'private-record')
 try:
  directory=path.parent.lstat()
  if not stat.S_ISDIR(directory.st_mode) or directory.st_uid!=os.getuid() or stat.S_IMODE(directory.st_mode)!=0o700:emit('unknown','private_directory_unsafe')
  info=path.lstat()
  if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1 or not 0<info.st_size<=limit: emit('unknown','private_file_unsafe')
  fd=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
  with os.fdopen(fd,'rb') as f:
   before=os.fstat(f.fileno()); raw=f.read(limit+1); after=os.fstat(f.fileno())
  now=path.lstat(); fingerprint=lambda x:(x.st_dev,x.st_ino,x.st_size,x.st_mtime_ns,x.st_ctime_ns)
  if len(raw)!=before.st_size or fingerprint(info)!=fingerprint(before) or fingerprint(before)!=fingerprint(after) or fingerprint(after)!=fingerprint(now): emit('unknown','private_file_changed')
  return raw
 except OSError: emit('unknown','private_file_unavailable')
def fingerprint(info):return [info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns,info.st_mode,info.st_uid,info.st_nlink]
def retain_claim(path,claim):
 fd=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0));info=os.fstat(fd)
 if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1 or not 0<info.st_size<=1024:os.close(fd);emit('unknown','device_lease_unsafe')
 raw=os.read(fd,1025)
 if len(raw)!=info.st_size or json.loads(raw)!=claim or fingerprint(info)!=fingerprint(os.fstat(fd)) or fingerprint(info)!=fingerprint(path.lstat()):os.close(fd);emit('unknown','device_lease_changed')
 return fd,fingerprint(info)
def claim_current(fd,path,expected):
 try:return fingerprint(os.fstat(fd))==expected and fingerprint(path.lstat())==expected
 except OSError:return False
def record(name,value):
 try:
  fd=os.open(job/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
  with os.fdopen(fd,'wb') as f: f.write(json.dumps(value,sort_keys=True,separators=(',',':')).encode()+b'\n'); f.flush(); os.fsync(f.fileno())
  d=os.open(job,os.O_RDONLY|getattr(os,'O_DIRECTORY',0)); os.fsync(d); os.close(d)
 except OSError: emit('unknown','durable_record_failed')
def run(argv,timeout=120,limit=1048576,allowed=(0,),environment=None):
 global checkpoint
 if mode.startswith('reconcile'):
  if argv[0]=='python3':checkpoint='cli-stage'
  elif argv[0]==adb:checkpoint='package' if 'pm' in argv or 'sha256sum' in argv else 'device'
  else:checkpoint=next((word for word in ('diagnostics','status','source','settings','locations','operations','routing') if word in argv),'public-command')
 if interaction_deadline is not None:
  remaining=interaction_deadline-time.monotonic()
  if remaining<=0:emit('unknown','prompt_deadline_expired')
  timeout=min(timeout,remaining)
 try:r=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=timeout,check=False,env=environment)
 except subprocess.TimeoutExpired:emit('unknown','reconcile_command_timeout' if mode.startswith('reconcile') else 'command_outcome_unknown')
 except OSError:emit('unknown','command_outcome_unknown')
 if r.returncode not in allowed:
  if mode.startswith('reconcile'):
   code='UNCLASSIFIED'
   if argv[0]==cli and '--json' in argv and len(r.stdout)<=16384:
    try:
     failure=json.loads(r.stdout)
     if isinstance(failure,dict) and failure.get('ok') is False and type(failure.get('final')) is bool and isinstance(failure.get('code'),str):
      if failure['code']=='TIMEOUT':code='TIMEOUT'
      elif failure['code'] in {'INVALID_ARGUMENT','NOT_FOUND','AMBIGUOUS_LOCATION','READ_ONLY_SOURCE','BUSY','CONFLICT','UNSUPPORTED','INTERACTION_REQUIRED','PERMISSION_DENIED','PERSISTENCE_FAILED','RUNTIME_FAILED','CANCELLED','OUTCOME_UNKNOWN','UNAVAILABLE','INCOMPATIBLE_PROTOCOL'}:code='OTHER'
    except (ValueError,UnicodeError):pass
   emit('unknown','reconcile_command_nonzero',commandCode=code)
  emit('unknown','command_failed')
 if len(r.stdout)>limit:emit('unknown','reconcile_command_oversize' if mode.startswith('reconcile') else 'command_failed')
 try:return r.stdout.decode('utf-8','strict').strip()
 except UnicodeError:emit('unknown','command_encoding')
def shell(*words):return run([adb,'-s',serial,'shell','-T',*words],timeout=45,limit=1048576)
def public(*words,allowed=(0,),timeout=120,limit=1048576):
 try:v=json.loads(run([cli,'--json','--android','--serial',serial,'--timeout-seconds',str(timeout),*words],timeout+15,limit,allowed,env))
 except ValueError:emit('unknown','public_invalid')
 if not isinstance(v,dict) or v.get('controllerId')!=owner or type(v.get('configurationRevision')) is not int or v['configurationRevision']!=revision:emit('unknown','owner_or_revision_changed')
 return v
def data(*words,**kwargs):
 v=public(*words,**kwargs)
 if v.get('ok') is not True or v.get('final') is not True or v.get('code')!='OK' or not isinstance(v.get('data'),dict):emit('unknown','public_invalid')
 return v['data']
def device():
 if type(intent.get('api')) is not int or {'api29':29,'api35':35}.get(intent.get('device'))!=intent['api']:emit('unknown','device_changed')
 if shell('id','-u')!='2000' or shell('getprop','ro.build.version.sdk')!=str(intent['api']) or shell('getprop','ro.product.cpu.abi')!='x86_64' or {x for x in (shell('getprop','ro.kernel.qemu.avd_name'),shell('getprop','ro.boot.qemu.avd_name')) if x}!={intent['expectedAvd']}:emit('unknown','device_changed')
 paths=[x[8:] for x in shell('pm','path','com.kardinal.vpncontrol').splitlines() if x.startswith('package:') and x.endswith('/base.apk')]
 if len(paths)!=1 or not paths[0].startswith('/data/app/') or shell('sha256sum',paths[0]).split()!=[intent['packageSha256'],paths[0]]:emit('unknown','package_changed')
 stage=json.loads(run(['python3','-I','-B','-c','exec('+repr(CLI_STAGE_STATUS)+')',root,intent['cliStageCorrelationId'],intent['cliManifestSha256']],120,16384))
 receipt=stage.get('receipt',{})
 if stage.get('state')!='published' or stage.get('correlationId')!=intent['cliStageCorrelationId'] or any(receipt.get(k)!=intent[v] for k,v in {'cliPath':'cliPath','manifestSha256':'cliManifestSha256','rpmSha256':'cliRpmSha256','launcherSha256':'cliLauncherSha256','desktopJarSha256':'cliDesktopJarSha256'}.items()):emit('unknown','cli_stage_changed')
def load_observations():
 global observations_loaded,observation_directory,observation_binding
 if observations_loaded:return
 observation_binding=hashlib.sha256(json.dumps({'intent':intent_sha,'owner':owner,'revision':revision,'sourceSha':intent['sourceSha'],'packageSha256':intent['packageSha256'],'stage':{k:intent[k] for k in ('cliStageCorrelationId','cliManifestSha256','cliRpmSha256','cliLauncherSha256','cliDesktopJarSha256')}},sort_keys=True,separators=(',',':')).encode()).hexdigest()
 observation_directory=base/('android-grant-observations-'+correlation+'-'+observation_binding)
 if observation_directory.exists() or observation_directory.is_symlink():
  meta=observation_directory.lstat()
  if not stat.S_ISDIR(meta.st_mode) or meta.st_uid!=os.getuid() or stat.S_IMODE(meta.st_mode)!=0o700:emit('unknown','observation_receipt_unsafe')
  paths=list(observation_directory.iterdir())
  if len(paths)>128:emit('unknown','observation_receipt_bound')
  for path in paths:
   receipt=json.loads(private(path,4096));summary=receipt.get('summary') if isinstance(receipt,dict) else None
   if not isinstance(summary,dict) or receipt!={'schema':1,'kind':'diagnostic-observation','bindingSha256':observation_binding,'summary':summary} or not isinstance(summary.get('id'),str) or re.fullmatch('[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}',summary['id']) is None or path.name!=summary['id']+'.json' or not diagnostic_summary(summary,summary.get('requestId'),summary.get('restartRequired')):emit('unknown','observation_receipt_invalid')
   owned_diagnostics[summary['id']]=summary
 observations_loaded=True

def diagnostic_summary(summary,request,restart):
 keys={'controllerId','id','requestId','operation','phase','final','cancellable','completedUnits','totalUnits','code','configurationRevision','restartRequired'}
 return (set(summary)==keys and summary.get('controllerId')==owner and isinstance(request,str) and re.fullmatch('[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}',request) is not None and summary.get('requestId')==request and summary.get('operation')=='diagnostics.export' and summary.get('phase')=='succeeded' and summary.get('final') is True and summary.get('cancellable') is False and summary.get('completedUnits') is None and summary.get('totalUnits') is None and summary.get('code')=='OK' and type(summary.get('configurationRevision')) is int and summary['configurationRevision']==revision and type(summary.get('restartRequired')) is bool and summary['restartRequired']==restart)

def save_observation(summary):
 try:
  observation_directory.mkdir(mode=0o700,exist_ok=True)
  meta=observation_directory.lstat()
  if not stat.S_ISDIR(meta.st_mode) or meta.st_uid!=os.getuid() or stat.S_IMODE(meta.st_mode)!=0o700 or len(list(observation_directory.iterdir()))>=128:emit('unknown','observation_receipt_unsafe')
  receipt={'schema':1,'kind':'diagnostic-observation','bindingSha256':observation_binding,'summary':summary};target=observation_directory/(summary['id']+'.json')
  fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
  with os.fdopen(fd,'wb') as out:out.write(json.dumps(receipt,sort_keys=True,separators=(',',':')).encode()+b'\n');out.flush();os.fsync(out.fileno())
  fd=os.open(observation_directory,os.O_RDONLY|getattr(os,'O_DIRECTORY',0));os.fsync(fd);os.close(fd)
  if json.loads(private(target,4096))!=receipt:emit('unknown','observation_receipt_invalid')
 except OSError:emit('unknown','observation_receipt_unknown')

def operations_diff(before,after):
 a={x['id']:x for x in before['operations']};b={x['id']:x for x in after['operations']}
 added=set(b)-set(a);removed=set(a)-set(b);changed={key for key in set(a)&set(b) if a[key]!=b[key]}
 return {'added':len(added),'removed':len(removed),'changed':len(changed),'addedDiagnostics':sum(b[key].get('operation')=='diagnostics.export' for key in added),'addedOther':sum(b[key].get('operation')!='diagnostics.export' for key in added)}

def semantic_operations():
 global diagnostic_history
 load_observations()
 value=data('operations','list');entries=value.get('operations')
 if not isinstance(entries,list) or len(entries)>128 or any(not isinstance(x,dict) or not isinstance(x.get('id'),str) for x in entries) or len({x['id'] for x in entries})!=len(entries):emit('unknown','operations_invalid')
 indexed={x['id']:x for x in entries}
 # The product bounds its terminal ledger to 30 minutes and256 entries.
 # Missing durably owned terminal observations remain retained provenance;
 # absence is not attributed to expiry or accepted as a task closure proof.
 diagnostic_history={'presentOwned':sum(key in indexed for key in owned_diagnostics),'absentRetained':sum(key not in indexed for key in owned_diagnostics),'absenceCause':'unproven'}
 if any(indexed[key]!=summary for key,summary in owned_diagnostics.items() if key in indexed):emit('unknown','observation_history_changed')
 return {**value,'operations':[x for x in entries if x['id'] not in owned_diagnostics]}
def diagnostic_export():
 parent=base.lstat()
 if not stat.S_ISDIR(parent.st_mode) or parent.st_uid!=os.getuid() or stat.S_IMODE(parent.st_mode)!=0o700:emit('unknown','diagnostic_export_unsafe')
 directory=pathlib.Path(tempfile.mkdtemp(prefix='android-grant-diagnostics-'+correlation+'-',dir=base));target=directory/'diagnostics.txt'
 directory_fd=os.open(directory,os.O_RDONLY|getattr(os,'O_DIRECTORY',0)|getattr(os,'O_NOFOLLOW',0));ephemeral_fds.append(directory_fd)
 if target.exists() or target.is_symlink():emit('unknown','diagnostic_export_unsafe')
 saved_umask=os.umask(0o077)
 try:report=public('diagnostics','export','--output',str(target),timeout=90,limit=16384)
 finally:os.umask(saved_umask)
 metadata=report.get('data')
 if not isinstance(metadata,dict) or metadata.get('format')!='text' or type(metadata.get('bytes')) is not int or not 0<metadata['bytes']<=1048576:emit('unknown','diagnostic_export_invalid')
 file_fd=os.open(target,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0));ephemeral_fds.append(file_fd);file_fingerprint=fingerprint(os.fstat(file_fd));directory_fingerprint=fingerprint(os.fstat(directory_fd))
 raw=private(target,1048576)
 if len(raw)!=metadata['bytes'] or not claim_current(file_fd,target,file_fingerprint):emit('unknown','diagnostic_export_invalid')
 return report,raw.decode('utf-8','strict'),(parent,directory,target,directory_fd,file_fd,directory_fingerprint,file_fingerprint)

def diagnostic_cleanup(artifact):
 parent,directory,target,directory_fd,file_fd,directory_fingerprint,file_fingerprint=artifact
 if not claim_current(file_fd,target,file_fingerprint) or not claim_current(directory_fd,directory,directory_fingerprint) or sorted(p.name for p in directory.iterdir())!=['diagnostics.txt'] or (base.lstat().st_dev,base.lstat().st_ino,base.lstat().st_mode,base.lstat().st_uid)!=(parent.st_dev,parent.st_ino,parent.st_mode,parent.st_uid):emit('unknown','diagnostic_export_cleanup_unknown')
 try:
  target.unlink()
  if (directory.lstat().st_dev,directory.lstat().st_ino,directory.lstat().st_mode,directory.lstat().st_uid)!=(directory_fingerprint[0],directory_fingerprint[1],directory_fingerprint[5],directory_fingerprint[6]):emit('unknown','diagnostic_export_cleanup_unknown')
  directory.rmdir()
 except OSError:emit('unknown','diagnostic_export_cleanup_unknown')
 for fd in (file_fd,directory_fd):os.close(fd);ephemeral_fds.remove(fd)

def diagnostics(permission):
 before=semantic_operations()
 report,raw,artifact=diagnostic_export()
 op=report.get('operationId');request=report.get('requestId')
 if report.get('ok') is not True or report.get('final') is not True or report.get('code')!='OK' or not isinstance(op,str) or not isinstance(request,str) or any(re.fullmatch('[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}',v) is None for v in (op,request)) or op in owned_diagnostics or any(x.get('id')==op or x.get('requestId')==request for x in before['operations']):emit('unknown','diagnostics_ambiguous')
 after=data('operations','list');entries=after.get('operations')
 if not isinstance(entries,list) or len(entries)>128 or any(not isinstance(x,dict) for x in entries):emit('unknown','operations_invalid')
 found=[x for x in entries if x.get('id')==op]
 if len(found)!=1:emit('unknown','diagnostics_ambiguous')
 summary=found[0]
 if not diagnostic_summary(summary,request,report.get('restartRequired')):emit('unknown','diagnostics_ambiguous')
 save_observation(summary);owned_diagnostics[op]=json.loads(json.dumps(summary))
 current=semantic_operations()
 if current!=before:emit('unknown','reconcile_operations_changed' if mode.startswith('reconcile') else 'operations_invalid',**({'operationsDiff':operations_diff(before,current)} if mode in ('reconcile-replacement-status','reconcile-continuation-status','reconcile-diagnostic') else {}))
 fields={}; sections=0; active=False
 for line in raw.splitlines():
  if line=='[runtime]': sections+=1; active=True; continue
  if line.startswith('[') and line.endswith(']'): active=False; continue
  if active and '=' in line:
   k,v=line.split('=',1)
   if k in ('mode','vpn_permission_granted','is_vpn_running'):
    if k in fields:emit('unknown','diagnostics_ambiguous')
    fields[k]=v
 if sections!=1 or fields!={'mode':'VPN','vpn_permission_granted':permission,'is_vpn_running':'false'}:emit('unknown','permission_or_runtime_changed')
 diagnostic_cleanup(artifact)
def rules(document):
 if not isinstance(document,dict) or document.get('type')!='vpn_control_routing_rules' or document.get('version')!=7:emit('unknown','routing_shape_invalid')
 r=document.get('rules')
 if not isinstance(r,dict) or set(r)!={'ignore_rules','block_quic_udp_443','proxy_packages','direct_domain_suffixes'} or type(r['ignore_rules']) is not bool or type(r['block_quic_udp_443']) is not bool or any(not isinstance(r[k],list) or any(not isinstance(x,str) for x in r[k]) for k in ('proxy_packages','direct_domain_suffixes')):emit('unknown','routing_shape_invalid')
 return hashlib.sha256(json.dumps(r,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()).hexdigest()
def routing(expected_status):
 raw=private(base/('android-readback-'+intent['openingReadbackCorrelationId'])/'routing.json',67108864)
 if hashlib.sha256(raw).hexdigest()!=intent['backupSha256']:emit('unknown','admitted_backup_changed')
 admitted=rules(json.loads(raw))
 if replacement_mode:
  fresh=private(base/('android-readback-'+replacement['readbackCorrelationId'])/'routing.json',67108864)
  if hashlib.sha256(fresh).hexdigest()!=replacement['backupSha256']:emit('unknown','admitted_backup_changed')
  if rules(json.loads(fresh))!=admitted:emit('unknown','routing_changed')
 # Use the packaged CLI's private streamed EXPORT path. Large inline SHOW
 # is a separately retained native timeout; it is not treated as a proof.
 before=data('status')
 if before!=expected_status:emit('unknown','routing_changed')
 parent=base.lstat()
 if not stat.S_ISDIR(parent.st_mode) or parent.st_uid!=os.getuid() or stat.S_IMODE(parent.st_mode)!=0o700:emit('unknown','routing_export_unsafe')
 directory=pathlib.Path(tempfile.mkdtemp(prefix='android-grant-export-'+correlation+'-',dir=base));target=directory/'routing.json'
 directory_fd=os.open(directory,os.O_RDONLY|getattr(os,'O_DIRECTORY',0)|getattr(os,'O_NOFOLLOW',0));file_fd=None
 try:
  if target.exists() or target.is_symlink():emit('unknown','routing_export_unsafe')
  saved_umask=os.umask(0o077)
  try:export=data('routing','export','--output',str(target),'--format','json',timeout=300,limit=16384)
  finally:os.umask(saved_umask)
  if export.get('format')!='json' or type(export.get('bytes')) is not int or not 0<export['bytes']<=67108864:emit('unknown','routing_export_invalid')
  file_fd=os.open(target,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0));file_fingerprint=fingerprint(os.fstat(file_fd));directory_fingerprint=fingerprint(os.fstat(directory_fd))
  raw=private(target,67108864)
  if len(raw)!=export['bytes'] or not claim_current(file_fd,target,file_fingerprint):emit('unknown','routing_export_invalid')
  if rules(json.loads(raw))!=admitted:emit('unknown','routing_changed')
  if data('status')!=before:emit('unknown','routing_changed')
  device()
  # Uncertain output/parent identity retains the private artifact. Only this
  # invocation's exact temporary file and directory are ever removed.
  if not claim_current(file_fd,target,file_fingerprint) or not claim_current(directory_fd,directory,directory_fingerprint) or sorted(p.name for p in directory.iterdir())!=['routing.json'] or (base.lstat().st_dev,base.lstat().st_ino,base.lstat().st_mode,base.lstat().st_uid)!=(parent.st_dev,parent.st_ino,parent.st_mode,parent.st_uid):emit('unknown','routing_export_cleanup_unknown')
  try:
   target.unlink()
   if (directory.lstat().st_dev,directory.lstat().st_ino,directory.lstat().st_mode,directory.lstat().st_uid)!=(directory_fingerprint[0],directory_fingerprint[1],directory_fingerprint[5],directory_fingerprint[6]):emit('unknown','routing_export_cleanup_unknown')
   directory.rmdir()
  except OSError:emit('unknown','routing_export_cleanup_unknown')
 finally:
  if file_fd is not None:os.close(file_fd)
  os.close(directory_fd)
 return admitted
def empty_source(source):
 return (source.get('mode')=='current-locations' and 'subscriptionId' in source and source['subscriptionId'] is None) or (source.get('mode')=='subscription' and source.get('subscriptionId')=='')
def snapshot(permission,pending=None):
 global checkpoint
 if lease.exists() or lease.is_symlink():
  if json.loads(private(lease,1024))!=claim:emit('unknown','device_lease_changed')
 elif mode=='run':emit('unknown','device_lease_missing')
 device(); diagnostics(permission)
 st=data('status'); source=data('source','show'); settings=data('settings','show'); loc=data('locations','list'); ops=data('operations','list').get('operations')
 if mode=='run' and not (job/'baseline-source-settings.json').exists():
  record('baseline-source-settings.json',{'owner':owner,'revision':revision,'intentSha256':intent_sha,'source':source,'settings':settings})
 if mode.startswith('reconcile'):checkpoint='baseline'
 if 'selectedLocationId' not in st or 'activeLocationId' not in st or st.get('runtimeRunning') is not False or st.get('runtimeObservation')!='stopped' or st.get('configuredMode')!='vpn' or st.get('selectedLocationId') is not None or st.get('activeLocationId') is not None or loc.get('locations')!=[] or not empty_source(source):emit('unknown','baseline_not_empty_off')
 if not isinstance(ops,list) or len(ops)>128:emit('unknown','operations_invalid')
 for x in ops:
  if not isinstance(x,dict) or x.get('controllerId')!=owner:emit('unknown','operations_invalid')
  if pending is not None and x.get('id')==pending:
   if x.get('final') is not False or x.get('phase')!='awaiting-user' or x.get('operation')!='on':emit('unknown','pending_operation_changed')
  elif x.get('final') is not True or x.get('phase') not in ('succeeded','failed','cancelled'):emit('unknown','operations_active')
 if pending is not None and len([x for x in ops if x.get('id')==pending])!=1:emit('unknown','pending_operation_missing')
 return {'source':source,'settings':settings,'runtime':st,'routingSha256':routing(st)}
interaction_deadline=None
prompt_evidence={}
def evidence_file(directory,name,raw,limit):
 if not isinstance(raw,bytes) or not 0<len(raw)<=limit:emit('unknown','prompt_evidence_invalid')
 before=directory.lstat();d=os.open(directory,os.O_RDONLY|getattr(os,'O_DIRECTORY',0)|getattr(os,'O_NOFOLLOW',0))
 try:
  if not stat.S_ISDIR(before.st_mode) or before.st_uid!=os.getuid() or stat.S_IMODE(before.st_mode)!=0o700 or fingerprint(before)!=fingerprint(os.fstat(d)):emit('unknown','prompt_evidence_invalid')
  fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600,dir_fd=d)
  with os.fdopen(fd,'wb') as f:
   f.write(raw);f.flush();os.fsync(f.fileno());info=os.fstat(f.fileno())
   if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1 or info.st_size!=len(raw) or fingerprint(info)!=fingerprint((directory/name).lstat()):emit('unknown','prompt_evidence_invalid')
  now=directory.lstat()
  if (now.st_dev,now.st_ino,now.st_mode,now.st_uid)!=(before.st_dev,before.st_ino,before.st_mode,before.st_uid):emit('unknown','prompt_evidence_invalid')
  os.fsync(d)
 finally:os.close(d)
 prompt_evidence[(directory,name)]=(fingerprint(info),hashlib.sha256(raw).hexdigest(),len(raw),limit)
 return {'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw)}
def verify_prompt_evidence(directory):
 for (parent,name),(expected,sha,size,limit) in prompt_evidence.items():
  if parent!=directory:continue
  try:
   raw=private(parent/name,limit)
   if fingerprint((parent/name).lstat())!=expected or len(raw)!=size or hashlib.sha256(raw).hexdigest()!=sha:emit('unknown','prompt_evidence_invalid')
  except OSError:emit('unknown','prompt_evidence_invalid')
def ui_absence_proof():
 # A fresh observation is never an ON prompt and never authorizes a tap.
 def baseline():
  device()
  st=data('status');source=data('source','show');settings=data('settings','show');locations=data('locations','list');history=data('operations','list')
  ops=history.get('operations')
  if not isinstance(ops,list) or len(ops)>512 or any(not isinstance(x,dict) or x.get('controllerId')!=owner or x.get('final') is not True or x.get('phase') not in ('succeeded','failed','cancelled') for x in ops):emit('unknown','operations_active')
  if st.get('runtimeRunning') is not False or st.get('runtimeObservation')!='stopped' or st.get('configuredMode')!='vpn' or 'selectedLocationId' not in st or st['selectedLocationId'] is not None or 'activeLocationId' not in st or st['activeLocationId'] is not None or locations.get('locations')!=[]:emit('unknown','pre_effect_state_changed')
  return {'runtime':st,'source':source,'settings':settings,'locations':locations,'history':history}
 before=baseline();observation=str(uuid.uuid4());directory=base/('android-grant-preflight-ui-'+correlation+'-'+observation)
 parent=base.lstat()
 if not stat.S_ISDIR(parent.st_mode) or parent.st_uid!=os.getuid() or stat.S_IMODE(parent.st_mode)!=0o700:emit('unknown','prompt_evidence_invalid')
 directory.mkdir(mode=0o700)
 path='/sdcard/vpn-control-consent-preflight-'+observation+'.xml'
 shell('uiautomator','dump',path);xml=shell('cat',path)
 metadata=evidence_file(directory,'ui.xml',xml.encode(),1048576)
 binding={'schema':1,'kind':'preexisting-dialog-observation','observationId':observation,'intentSha256':intent_sha,'owner':owner,'revision':revision,'xml':metadata,'baselineSha256':hashlib.sha256(json.dumps(before,sort_keys=True,separators=(',',':')).encode()).hexdigest()}
 evidence_file(directory,'binding.json',json.dumps(binding,sort_keys=True,separators=(',',':')).encode(),4096)
 shell('rm','-f',path)
 try:tree=ET.fromstring(xml);nodes=list(tree.iter('node'))
 except ET.ParseError:emit('unknown','ui_observation_invalid')
 if tree.tag!='hierarchy' or not nodes:emit('unknown','ui_observation_invalid')
 present=any(n.get('package')=='com.android.vpndialogs' for n in nodes)
 if baseline()!=before:emit('unknown','pre_effect_state_changed')
 verify_prompt_evidence(directory)
 return {'observationId':observation,'xmlSha256':metadata['sha256'],'xmlBytes':metadata['bytes'],'vpnDialogPresent':present}
def capture_prompt(screenshot=False):
 observation=str(uuid.uuid4());directory=base/('android-grant-prompt-'+correlation+'-'+observation)
 parent=base.lstat()
 if not stat.S_ISDIR(parent.st_mode) or parent.st_uid!=os.getuid() or stat.S_IMODE(parent.st_mode)!=0o700:emit('unknown','prompt_evidence_invalid')
 directory.mkdir(mode=0o700)
 path='/sdcard/vpn-control-consent-grant-'+observation+'.xml'
 shell('uiautomator','dump',path);xml=shell('cat',path)
 xml_meta=evidence_file(directory,'ui.xml',xml.encode(),1048576)
 metadata={'schema':1,'observationId':observation,'intentSha256':intent_sha,'owner':owner,'revision':revision,'operation':json.loads(private(job/'operation.json')),'xml':xml_meta}
 if screenshot:
  r=subprocess.run([adb,'-s',serial,'exec-out','screencap','-p'],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=45,check=False)
  if r.returncode!=0 or not r.stdout.startswith(b'\x89PNG\r\n\x1a\n'):emit('unknown','prompt_evidence_invalid')
  metadata['png']=evidence_file(directory,'ui.png',r.stdout,8388608)
 evidence_file(directory,'binding.json',json.dumps(metadata,sort_keys=True,separators=(',',':')).encode(),8192)
 d=os.open(directory,os.O_RDONLY|getattr(os,'O_DIRECTORY',0));os.fsync(d);os.close(d)
 shell('rm',path)
 now=base.lstat()
 if (now.st_dev,now.st_ino,now.st_mode,now.st_uid)!=(parent.st_dev,parent.st_ino,parent.st_mode,parent.st_uid):emit('unknown','prompt_evidence_invalid')
 return xml,metadata
def pre_tap(opening,pending,opening_raw,opening_fingerprint):
 if interaction_deadline is None or time.monotonic()>=interaction_deadline:emit('unknown','prompt_deadline_expired')
 if private(job/'opening.json',1048576)!=opening_raw or fingerprint((job/'opening.json').lstat())!=opening_fingerprint:emit('unknown','pre_tap_state_changed')
 backup=private(base/('android-readback-'+intent['openingReadbackCorrelationId'])/'routing.json',67108864)
 if hashlib.sha256(backup).hexdigest()!=intent['backupSha256'] or rules(json.loads(backup))!=opening['routingSha256']:emit('unknown','admitted_backup_changed')
 if json.loads(private(lease,1024))!=claim:emit('unknown','device_lease_changed')
 device()
 st=data('status');source=data('source','show');settings=data('settings','show');locations=data('locations','list');ops=data('operations','list').get('operations')
 if st!=opening['runtime'] or source!=opening['source'] or settings!=opening['settings'] or locations.get('locations')!=[]:emit('unknown','pre_tap_state_changed')
 if not isinstance(ops,list) or len(ops)>128 or any(not isinstance(x,dict) or x.get('controllerId')!=owner for x in ops):emit('unknown','operations_invalid')
 found=[x for x in ops if x.get('id')==pending]
 if len(found)!=1 or found[0].get('operation')!='on' or found[0].get('final') is not False or found[0].get('phase')!='awaiting-user':emit('unknown','pending_operation_changed')
 if any(x.get('final') is not True or x.get('phase') not in ('succeeded','failed','cancelled') for x in ops if x.get('id')!=pending):emit('unknown','operations_active')
 if time.monotonic()>=interaction_deadline:emit('unknown','prompt_deadline_expired')
def prompt():
 xml,_=capture_prompt()
 point=_positive_button(xml,intent['api'])
 if point is None:emit('unknown','prompt_not_owned')
 return point
def terminal_proof():
 receipt=json.loads(private(job/'result.json')); terminal=json.loads(private(job/'terminal.json'))
 op=json.loads(private(job/'operation.json')); value=receipt.get('result')
 required={'state':'complete','reason':None,'correlationId':correlation,'operationId':op.get('operationId'),'operationCode':'INVALID_ARGUMENT','permissionGranted':True,'runtimeStarted':False,'noLocation':True,'scope':'grant-only','owner':owner,'revision':revision,'intentSha256':intent_sha}
 def exact_terminal(candidate):
  return type(candidate) is dict and set(candidate)==set(required) and all(type(candidate[key]) is type(expected) and candidate[key]==expected for key,expected in required.items())
 if op!={'operationId':required['operationId'],'owner':owner,'revision':revision,'intentSha256':intent_sha} or not isinstance(required['operationId'],str) or str(uuid.UUID(required['operationId']))!=required['operationId'] or not exact_terminal(terminal) or receipt.get('state')!='complete' or not exact_terminal(value):emit('unknown','terminal_binding_invalid')
 on=json.loads(private(job/'on-intent.json'));tap=json.loads(private(job/'tap-intent.json'))
 if on!={'owner':owner,'revision':revision,'intentSha256':intent_sha} or set(tap)!={'operationId','point','intentSha256'} or tap.get('operationId')!=op['operationId'] or tap.get('intentSha256')!=intent_sha or not isinstance(tap.get('point'),list) or len(tap['point'])!=2 or any(type(x) is not int or not 0<=x<=4096 for x in tap['point']):emit('unknown','terminal_binding_invalid')
 return value
try:
 info=job.lstat()
 if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700:emit('unknown','job_unsafe')
 original_intent_raw=private(job/'intent.json')
 if json.loads(original_intent_raw)!=intent:emit('unknown','intent_changed')
 if mode=='status':
  identity=json.loads(private(job/'identity.json',1024))
  if set(identity)!={'pid','startTicks'} or type(identity.get('pid')) is not int or identity['pid']<1 or type(identity.get('startTicks')) is not int or identity['startTicks']<1:emit('unknown','identity_invalid')
  if not (job/'result.json').exists():
   try:fields=pathlib.Path('/proc/%d/stat'%identity['pid']).read_text().rsplit(')',1)[1].split(); live=fields[0]!='Z' and int(fields[19])==identity['startTicks']
   except (OSError,ValueError,IndexError):live=False
   emit('running' if live else 'unknown',None if live else 'missing_worker_receipt')
  receipt=json.loads(private(job/'result.json'))
  if not isinstance(receipt,dict):emit('unknown','worker_receipt_invalid')
  if receipt.get('state')=='unknown':
   # The generic wrapper has no terminal records for failed presteps. These
   # finite codes describe its retained observation only, never completion.
   allowed_reasons=('admitted_backup_changed', 'baseline_not_empty_off', 'cli_stage_changed', 'collection_marker_changed', 'command_encoding', 'command_failed', 'command_outcome_unknown', 'device_changed', 'device_lease_active', 'device_lease_changed', 'device_lease_missing', 'device_lease_unsafe', 'device_lock_unsafe', 'diagnostics_ambiguous', 'durable_record_failed', 'identity_invalid', 'intent_changed', 'job_unsafe', 'mode_invalid', 'on_not_accepted', 'operation_not_no_location', 'operation_terminal_changed', 'operations_active', 'operations_invalid', 'owner_or_revision_changed', 'package_changed', 'pending_operation_changed', 'pending_operation_missing', 'permission_or_runtime_changed', 'pre_effect_state_changed', 'pre_tap_state_changed', 'private_directory_unsafe', 'private_file_changed', 'private_file_unavailable', 'private_file_unsafe', 'prompt_changed', 'prompt_deadline_expired', 'prompt_not_owned', 'proof_unavailable', 'public_invalid', 'restoration_changed', 'routing_changed', 'routing_shape_invalid', 'scenario_unknown', 'terminal_binding_invalid', 'worker_failed', 'worker_unknown')
   normal=set(receipt)=={'state','result','reason'} and receipt.get('result') is None
   transport=set(receipt)=={'state','reason'} and receipt.get('reason') in ('worker_failed','worker_unknown')
   if not (normal or transport) or not isinstance(receipt.get('reason'),str) or receipt['reason'] not in allowed_reasons:emit('unknown','worker_receipt_invalid')
   emit('unknown',receipt['reason'],checkpoint='worker-returned-unknown')
  if set(receipt)!={'state','result','reason'} or receipt.get('state')!='complete' or receipt.get('reason') is not None:emit('unknown','worker_receipt_invalid')
  emit('complete',result=terminal_proof())
 if mode in ('reconcile-status','reconcile-diagnostic'):
  receipt_raw=private(job/'result.json');receipt=json.loads(receipt_raw)
  if receipt!={'state':'unknown','result':None,'reason':'baseline_not_empty_off'}:emit('unknown','reconcile_attempt_not_admitted')
  identity_raw=private(job/'identity.json',1024);identity=json.loads(identity_raw);worker_raw=private(job/'worker.py',131072)
  if set(identity)!={'pid','startTicks'} or any(type(identity[k]) is not int or identity[k]<1 for k in identity):emit('unknown','identity_invalid')
  worker_state='terminal'
  try:
   fields=pathlib.Path('/proc/%d/stat'%identity['pid']).read_text().rsplit(')',1)[1].split();worker_state='reused' if int(fields[19])!=identity['startTicks'] else 'live' if fields[0]!='Z' else 'terminal'
  except FileNotFoundError:pass
  except (OSError,ValueError,IndexError):worker_state='unknown'
  forbidden=('opening.json','on-intent.json','operation.json','tap-intent.json','terminal.json','collected.json')
  records={'workerState':worker_state,'grantRecords':'present' if any((job/name).exists() or (job/name).is_symlink() for name in forbidden) else 'absent','baselineRecord':'present' if (job/'baseline-source-settings.json').exists() or (job/'baseline-source-settings.json').is_symlink() else 'absent','remoteMarker':'absent','remoteClaim':'absent','lockState':'missing'}
  bindings=hashlib.sha256(json.dumps({'intent':intent_sha,'result':hashlib.sha256(receipt_raw).hexdigest(),'identity':hashlib.sha256(identity_raw).hexdigest(),'worker':hashlib.sha256(worker_raw).hexdigest()},sort_keys=True,separators=(',',':')).encode()).hexdigest()
  claim={'owner':'android-consent-grant','host':'archlinux','device':intent['device'],'correlationId':correlation};lease=base/('android-native-device-'+intent['device']+'.lease');marker=None
  if (job/'no-effect-closed.json').exists() or (job/'no-effect-closed.json').is_symlink():
   marker=json.loads(private(job/'no-effect-closed.json'))
   records['remoteMarker']='valid' if isinstance(marker,dict) and set(marker)=={'schema','intentSha256','bindingsSha256','snapshotSha256','historicalSourceSettingsAvailable','claim','leaseFingerprint'} and marker['schema']==1 and marker['intentSha256']==intent_sha and marker['bindingsSha256']==bindings and marker['claim']==claim and type(marker['historicalSourceSettingsAvailable']) is bool and isinstance(marker['snapshotSha256'],str) and re.fullmatch('[0-9a-f]{64}',marker['snapshotSha256']) and isinstance(marker['leaseFingerprint'],list) and len(marker['leaseFingerprint'])==8 and all(type(x) is int for x in marker['leaseFingerprint']) else 'invalid'
  if lease.exists() or lease.is_symlink():
   value=json.loads(private(lease,1024));records['remoteClaim']='owned' if value==claim else 'foreign'
   if value==claim:
    claim_fd,claim_fingerprint=retain_claim(lease,claim)
    if records['remoteMarker']=='valid' and marker['leaseFingerprint']!=claim_fingerprint:records['remoteClaim']='changed'
  lock=base/('android-native-device-'+intent['device']+'.lock')
  try:
   lease_fd=os.open(lock,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0));info=os.fstat(lease_fd)
   if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1:records['lockState']='unsafe'
   else:
    try:fcntl.flock(lease_fd,fcntl.LOCK_SH|fcntl.LOCK_NB);records['lockState']='free'
    except BlockingIOError:records['lockState']='busy'
  except FileNotFoundError:pass
  if mode=='reconcile-status' or records['lockState']!='free' or records['remoteClaim'] not in ('owned','absent') or records['grantRecords']!='absent' or worker_state not in ('terminal','reused'):
   emit('observed',records=records,currentProof='not-probed')
  env=public_cli_environment(adb,pathlib.Path(cli));opening=snapshot('false')
  baseline_match=None
  if records['baselineRecord']=='present':baseline_match=json.loads(private(job/'baseline-source-settings.json',1048576))=={'owner':owner,'revision':revision,'intentSha256':intent_sha,'source':opening['source'],'settings':opening['settings']}
  if snapshot('false')!=opening:emit('unknown','reconcile_current_snapshots_changed')
  if claim_fd is not None and not claim_current(claim_fd,lease,claim_fingerprint):emit('unknown','device_lease_changed')
  if private(job/'result.json')!=receipt_raw or private(job/'identity.json',1024)!=identity_raw or private(job/'worker.py',131072)!=worker_raw:emit('unknown','reconcile_original_changed')
  emit('observed',records=records,currentProof='matched' if baseline_match is not False else 'drift',historicalSourceSettings='unavailable' if baseline_match is None else 'matched' if baseline_match else 'drift')
 if mode=='reconcile' or replacement_mode:
  # Narrow pre-effect closure. Keep the original failure and all private files.
  receipt_raw=private(job/'result.json');receipt=json.loads(receipt_raw)
  if receipt!={'state':'unknown','result':None,'reason':'baseline_not_empty_off'}:emit('unknown','reconcile_attempt_not_admitted')
  identity_raw=private(job/'identity.json',1024);identity=json.loads(identity_raw)
  if set(identity)!={'pid','startTicks'} or any(type(identity[k]) is not int or identity[k]<1 for k in identity):emit('unknown','identity_invalid')
  def worker_terminal():
   try:
    fields=pathlib.Path('/proc/%d/stat'%identity['pid']).read_text().rsplit(')',1)[1].split()
    if fields[0]!='Z' and int(fields[19])==identity['startTicks']:emit('unknown','reconcile_worker_live')
   except FileNotFoundError:pass
   except (OSError,ValueError,IndexError):emit('unknown','reconcile_worker_identity_unknown')
  worker_terminal()
  replacement_records={}
  worker_raw=private(job/'worker.py',131072)
  forbidden=('opening.json','on-intent.json','operation.json','tap-intent.json','terminal.json','collected.json')
  def unchanged_original():
   worker_terminal()
   if any((job/name).exists() or (job/name).is_symlink() for name in forbidden):emit('unknown','reconcile_grant_intent_present')
   if private(job/'intent.json')!=original_intent_raw or private(job/'result.json')!=receipt_raw or private(job/'identity.json',1024)!=identity_raw or private(job/'worker.py',131072)!=worker_raw:emit('unknown','reconcile_original_changed')
   if any(private(path,16384)!=raw for path,raw in replacement_records.items()):emit('unknown','replacement_receipt_invalid')
  unchanged_original()
  if replacement_mode and ((job/'no-effect-closed.json').exists() or (job/'no-effect-closed.json').is_symlink()):emit('unknown','reconcile_attempt_not_admitted')
  bindings=hashlib.sha256(json.dumps({'intent':intent_sha,'result':hashlib.sha256(receipt_raw).hexdigest(),'identity':hashlib.sha256(identity_raw).hexdigest(),'worker':hashlib.sha256(worker_raw).hexdigest()},sort_keys=True,separators=(',',':')).encode()).hexdigest()
  lock=base/('android-native-device-'+intent['device']+'.lock');lease_fd=os.open(lock,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0));info=os.fstat(lease_fd)
  if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1:emit('unknown','device_lock_unsafe')
  try:fcntl.flock(lease_fd,(fcntl.LOCK_SH|fcntl.LOCK_NB) if read_only_closure else (fcntl.LOCK_EX|fcntl.LOCK_NB) if replacement_mode else fcntl.LOCK_EX)
  except BlockingIOError:emit('unknown','device_lock_busy')
  continuation_sha=None
  if continuation_mode:
   if not isinstance(continuation,dict) or set(continuation)!={'schema','continuationId','originalIntentSha256','replacementBindingSha256','openingDisposition'} or continuation['schema']!=1 or not isinstance(continuation['continuationId'],str) or re.fullmatch('[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}',continuation['continuationId']) is None or continuation['continuationId']==correlation or continuation['originalIntentSha256']!=intent_sha or continuation['replacementBindingSha256']!=hashlib.sha256(json.dumps(replacement,sort_keys=True,separators=(',',':')).encode()).hexdigest() or (not isinstance(continuation['openingDisposition'],dict) or set(continuation['openingDisposition'])!={'state','reason','provenance','currentSnapshotSha256','retainedBindingsSha256'} or any(continuation['openingDisposition'].get(k)!=v for k,v in {'state':'unknown','reason':'replacement_closure_incomplete','provenance':'fresh-read-only'}.items()) or any(not isinstance(continuation['openingDisposition'].get(k),str) or re.fullmatch('[0-9a-f]{64}',continuation['openingDisposition'][k]) is None for k in ('currentSnapshotSha256','retainedBindingsSha256'))):emit('unknown','continuation_intent_invalid')
   continuation_sha=hashlib.sha256(json.dumps(continuation,sort_keys=True,separators=(',',':')).encode()).hexdigest()
   continuation_name='continuation-'+continuation['continuationId']+'.json'
   if (job/continuation_name).exists() or (job/continuation_name).is_symlink():
    if json.loads(private(job/continuation_name,16384))!=continuation:emit('unknown','continuation_intent_invalid')
    if not read_only_closure:emit('unknown','continuation_consumed')
   elif read_only_closure:emit('unknown','continuation_intent_missing')
  marker_name=('continuation-'+continuation['continuationId']+'-closed.json') if continuation_mode else 'replacement-no-effect-closed.json' if replacement_mode else 'no-effect-closed.json'
  claim={'owner':'android-consent-grant','host':'archlinux','device':intent['device'],'correlationId':correlation};lease=base/('android-native-device-'+intent['device']+'.lease')
  marker=None
  if (job/marker_name).exists() or (job/marker_name).is_symlink():
   marker=json.loads(private(job/marker_name))
   if not isinstance(marker,dict) or set(marker)!=({'schema','intentSha256','bindingsSha256','snapshotSha256','historicalSourceSettingsAvailable','claim','leaseFingerprint'}|({'replacementBindingSha256'} if replacement_mode else set())|({'continuationId','continuationIntentSha256'} if continuation_mode else set())) or marker['schema']!=1 or marker['intentSha256']!=intent_sha or marker['bindingsSha256']!=bindings or marker['claim']!=claim or not isinstance(marker['leaseFingerprint'],list) or len(marker['leaseFingerprint'])!=8 or any(type(x) is not int for x in marker['leaseFingerprint']):emit('unknown','reconcile_marker_changed')
  if lease.exists() or lease.is_symlink():
   claim_fd,claim_fingerprint=retain_claim(lease,claim)
   if marker is not None and marker['leaseFingerprint']!=claim_fingerprint:emit('unknown','device_lease_changed')
  elif marker is None:emit('unknown','device_lease_missing')
  else:claim_fingerprint=marker['leaseFingerprint']
  replacement_sha=None
  if replacement_mode:
   expected_keys={'schema','originalIntentSha256','readbackCorrelationId','backupSha256','owner','revision','readbackIntent','readbackResultSha256','readbackIdentity'}
   if not isinstance(replacement,dict) or set(replacement)!=expected_keys or replacement['schema']!=1 or replacement['originalIntentSha256']!=intent_sha or replacement['owner']==owner or not isinstance(replacement['owner'],str) or re.fullmatch('[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}',replacement['owner']) is None or type(replacement['revision']) is not int or replacement['revision']<0:emit('unknown','replacement_receipt_invalid')
   rc=replacement['readbackCorrelationId']
   if not isinstance(rc,str) or re.fullmatch('[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}',rc) is None or rc==intent['openingReadbackCorrelationId']:emit('unknown','replacement_receipt_invalid')
   ri=replacement['readbackIntent'];rjob=base/('android-readback-job-'+rc)
   wanted={'host':'archlinux','device':intent['device'],'correlationId':rc,'expectedBaseSha256':intent['packageSha256'],'serial':serial,'expectedAvd':intent['expectedAvd'],'api':intent['api'],'fixtureRoot':root}
   if ri!=wanted or json.loads(private(rjob/'intent.json'))!=ri or json.loads(private(rjob/'identity.json',1024))!=replacement['readbackIdentity']:emit('unknown','replacement_receipt_invalid')
   rid=replacement['readbackIdentity']
   if not isinstance(rid,dict) or set(rid)!={'pid','startTicks'} or any(type(x) is not int or x<=0 for x in rid.values()):emit('unknown','replacement_receipt_invalid')
   replacement_records={rjob/name:private(rjob/name,16384) for name in ('intent.json','identity.json','result.json')}
   rr=json.loads(replacement_records[rjob/'result.json']);rv=rr.get('result') if isinstance(rr,dict) else None
   if not isinstance(rv,dict) or set(rr)!={'state','result','reason'} or rr.get('state')!='complete' or rr.get('reason') is not None or rv.get('admitted') is not True or hashlib.sha256(json.dumps(rv,sort_keys=True,separators=(',',':')).encode()).hexdigest()!=replacement['readbackResultSha256']:emit('unknown','replacement_receipt_invalid')
   backup=rv.get('backup',{});guard=rv.get('guard',{});dev=rv.get('device',{})
   if rv.get('package',{}).get('baseSha256')!=intent['packageSha256'] or dev.get('api')!=intent['api'] or dev.get('uid')!='2000' or dev.get('avd')!=intent['expectedAvd'] or dev.get('abi')!='x86_64' or guard.get('controllerId')!=replacement['owner'] or guard.get('configurationRevision')!=replacement['revision'] or backup.get('sha256')!=replacement['backupSha256'] or backup.get('rulesValid') is not True or backup.get('type')!='vpn_control_routing_rules' or backup.get('version')!=7 or backup.get('path')!=str(base/('android-readback-'+rc)/'routing.json') or type(backup.get('size')) is not int or not 0<backup['size']<=67108864 or guard.get('backupSha256')!=backup['sha256'] or guard.get('backupSize')!=backup['size']:emit('unknown','replacement_receipt_invalid')
   if len(private(base/('android-readback-'+rc)/'routing.json',67108864))!=backup['size']:emit('unknown','admitted_backup_changed')
   replacement_sha=hashlib.sha256(json.dumps(replacement,sort_keys=True,separators=(',',':')).encode()).hexdigest()
   binding_path=job/'replacement-binding.json';replacement_binding_raw=None
   if binding_path.exists() or binding_path.is_symlink():
    replacement_binding_raw=private(binding_path,16384)
    if json.loads(replacement_binding_raw)!=replacement:emit('unknown','replacement_receipt_invalid')
   # A status read may validate a consumed local binding before the remote
   # admission reached its binding write. It never writes the missing record.
   owner=replacement['owner'];revision=replacement['revision']
  if continuation_mode and not read_only_closure:
   if claim_fd is None:emit('unknown','device_lease_missing')
   record(continuation_name,continuation)
  env=public_cli_environment(adb,pathlib.Path(cli));opening=snapshot('false')
  operations_reference=None
  def operations_sha():
   global operations_reference
   current=semantic_operations()
   if operations_reference is None:operations_reference=current
   elif current!=operations_reference:emit('unknown','reconcile_operations_changed',**({'operationsDiff':operations_diff(operations_reference,current)} if read_only_closure else {}))
   return hashlib.sha256(json.dumps(current,sort_keys=True,separators=(',',':')).encode()).hexdigest()
  ops_sha=operations_sha()
  historical=False
  if (job/'baseline-source-settings.json').exists() or (job/'baseline-source-settings.json').is_symlink():
   baseline=json.loads(private(job/'baseline-source-settings.json',1048576))
   if baseline!={'owner':intent['expectedOwner'],'revision':intent['expectedRevision'],'intentSha256':intent_sha,'source':opening['source'],'settings':opening['settings']}:emit('unknown','reconcile_baseline_changed')
   historical=True
  if snapshot('false')!=opening or operations_sha()!=ops_sha:emit('unknown','reconcile_current_snapshots_changed')
  snapshot_sha=hashlib.sha256(json.dumps({'snapshot':opening,'operationsSha256':ops_sha},sort_keys=True,separators=(',',':')).encode()).hexdigest()
  expected_marker={'schema':1,'intentSha256':intent_sha,'bindingsSha256':bindings,'snapshotSha256':snapshot_sha,'historicalSourceSettingsAvailable':historical,'claim':claim,'leaseFingerprint':claim_fingerprint}
  if continuation_mode and (continuation['openingDisposition']['currentSnapshotSha256']!=snapshot_sha or continuation['openingDisposition']['retainedBindingsSha256']!=bindings):emit('unknown','reconcile_current_snapshots_changed')
  if replacement_mode:expected_marker['replacementBindingSha256']=replacement_sha
  if continuation_mode:
   old_path=job/'replacement-no-effect-closed.json'
   if old_path.exists() or old_path.is_symlink():
    if json.loads(private(old_path))!=expected_marker:emit('unknown','reconcile_marker_changed')
   expected_marker.update(continuationId=continuation['continuationId'],continuationIntentSha256=continuation_sha)
  if marker is not None and marker!=expected_marker:emit('unknown','reconcile_marker_changed')
  unchanged_original()
  if claim_fd is not None and not claim_current(claim_fd,lease,claim_fingerprint):emit('unknown','device_lease_changed')
  if replacement_mode and read_only_closure:
   if marker is None or claim_fd is not None:emit('unknown','replacement_closure_incomplete',currentSnapshotSha256=snapshot_sha,retainedBindingsSha256=bindings)
  else:
   if replacement_mode and not continuation_mode and not (job/'replacement-binding.json').exists():record('replacement-binding.json',replacement)
   if marker is None:record(marker_name,expected_marker)
  if json.loads(private(job/marker_name))!=expected_marker:emit('unknown','reconcile_marker_changed')
  if snapshot('false')!=opening or operations_sha()!=ops_sha:emit('unknown','reconcile_current_snapshots_changed')
  unchanged_original()
  if replacement_mode:
   if continuation_mode and replacement_binding_raw is None:
    if binding_path.exists() or binding_path.is_symlink():emit('unknown','replacement_receipt_invalid')
   elif replacement_binding_raw is not None:
    if private(binding_path,16384)!=replacement_binding_raw:emit('unknown','replacement_receipt_invalid')
   elif json.loads(private(binding_path,16384))!=replacement:emit('unknown','replacement_receipt_invalid')
  if claim_fd is not None and not claim_current(claim_fd,lease,claim_fingerprint):emit('unknown','device_lease_changed')
  if continuation_mode and json.loads(private(job/continuation_name,16384))!=continuation:emit('unknown','continuation_intent_invalid')
  if claim_fd is not None and not read_only_closure:
   if not claim_current(claim_fd,lease,claim_fingerprint):emit('unknown','device_lease_changed')
   lease.unlink();d=os.open(base,os.O_RDONLY|getattr(os,'O_DIRECTORY',0));os.fsync(d);os.close(d)
  proof={'workerTerminal':True,'noGrantIntents':True,'configurationGenerationUnchanged':True,'fullRoutingUnchanged':True,'packageUnchanged':True,'currentSourceSettingsStable':True,'currentRuntimeStable':True,'currentOperationsStable':True,'historicalSourceSettingsAvailable':historical,'permissionAbsent':True,'runtimeOff':True,'retainedBindingsSha256':bindings,'currentSnapshotSha256':snapshot_sha}
  if replacement_mode:
   proof.pop('configurationGenerationUnchanged');proof.update(replacementOwnerAdmitted=True,originalOwnerChanged=True,replacementBindingSha256=replacement_sha)
  if continuation_mode:proof.update(continuationId=continuation['continuationId'],continuationIntentSha256=continuation_sha)
  emit('closed',proof=proof,markerSha256=hashlib.sha256(private(job/marker_name)).hexdigest())
 if mode=='diagnostic':
  # This is a fresh read bound to the retained failure, not reconstructed
  # historical state. It creates no files, claim, or product operation.
  receipt=json.loads(private(job/'result.json'))
  if receipt!={'state':'unknown','result':None,'reason':'baseline_not_empty_off'}:emit('unknown','diagnostic_attempt_not_admitted')
  lock=base/('android-native-device-'+intent['device']+'.lock');lease_fd=os.open(lock,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0));info=os.fstat(lease_fd)
  if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1:emit('unknown','device_lock_unsafe')
  fcntl.flock(lease_fd,fcntl.LOCK_SH)
  expected_claim={'owner':'android-consent-grant','host':'archlinux','device':intent['device'],'correlationId':correlation}
  lease=base/('android-native-device-'+intent['device']+'.lease')
  claim_fd,claim_fingerprint=retain_claim(lease,expected_claim)
  env=public_cli_environment(adb,pathlib.Path(cli));device();diagnostics('false')
  st=data('status');source=data('source','show');loc=data('locations','list');ops=data('operations','list').get('operations')
  checks={'runtimeOff':st.get('runtimeRunning') is False,'runtimeStopped':st.get('runtimeObservation')=='stopped','vpnMode':st.get('configuredMode')=='vpn','selectionNull':st.get('selectedLocationId') is None,'activeNull':st.get('activeLocationId') is None,'locationsEmpty':loc.get('locations')==[],'sourceCurrentLocations':source.get('mode')=='current-locations','subscriptionNull':source.get('subscriptionId') is None}
  enum=lambda value,allowed:'missing' if value is None else value if isinstance(value,str) and value in allowed else 'other'
  subscription=('missing' if 'subscriptionId' not in source else 'null' if source['subscriptionId'] is None else 'empty' if source['subscriptionId']=='' else 'selected' if isinstance(source['subscriptionId'],str) else 'other')
  locations=loc.get('locations');history=ops if isinstance(ops,list) else []
  facts={'configuredMode':enum(st.get('configuredMode'),('vpn','proxy-only')),'runtimeObservation':enum(st.get('runtimeObservation'),('stopped','running','unknown')),'sourceMode':enum(source.get('mode'),('current-locations','subscription')),'subscriptionBinding':subscription,'locationShape':'array' if isinstance(locations,list) else 'missing' if 'locations' not in loc else 'other','locationCount':min(len(locations),128) if isinstance(locations,list) else 0,'locationCountTruncated':isinstance(locations,list) and len(locations)>128,'operationShape':'array' if isinstance(ops,list) else 'other','operationCount':min(len(history),128),'operationCountTruncated':len(history)>128,'operationsTerminal':isinstance(ops,list) and all(isinstance(x,dict) and x.get('controllerId')==owner and x.get('final') is True and x.get('phase') in ('succeeded','failed','cancelled') for x in history),'selectedFieldPresent':'selectedLocationId' in st,'activeFieldPresent':'activeLocationId' in st}
  if not claim_current(claim_fd,lease,claim_fingerprint):emit('unknown','device_lease_changed')
  if json.loads(private(job/'result.json'))!=receipt:emit('unknown','diagnostic_attempt_changed')
  emit('diagnosed',historicalReason='baseline_not_empty_off',observationClass='fresh-current-baseline',checks=checks,facts=facts)
 if mode=='prompt-diagnostic':
  retained_original={name:private(job/name,131072 if name=='worker.py' else 8192) for name in ('intent.json','identity.json','worker.py','result.json','on-intent.json','operation.json')}
  receipt=json.loads(retained_original['result.json'])
  if receipt!={'state':'unknown','result':None,'reason':'prompt_not_owned'}:emit('unknown','prompt_attempt_not_admitted')
  identity=json.loads(private(job/'identity.json',1024))
  if set(identity)!={'pid','startTicks'} or any(type(identity[k]) is not int or identity[k]<1 for k in identity):emit('unknown','identity_invalid')
  try:
   fields=pathlib.Path('/proc/%d/stat'%identity['pid']).read_text().rsplit(')',1)[1].split()
   if int(fields[19])==identity['startTicks'] and fields[0]!='Z':emit('unknown','prompt_worker_live')
  except FileNotFoundError:pass
  except (OSError,ValueError,IndexError):emit('unknown','prompt_worker_unknown')
  for name in ('tap-intent.json','terminal.json','collected.json'):
   if (job/name).exists() or (job/name).is_symlink():emit('unknown','prompt_attempt_not_admitted')
  on=json.loads(private(job/'on-intent.json'));op=json.loads(private(job/'operation.json'))
  if on!={'owner':owner,'revision':revision,'intentSha256':intent_sha} or set(op)!={'operationId','owner','revision','intentSha256'} or op.get('owner')!=owner or op.get('revision')!=revision or op.get('intentSha256')!=intent_sha or not isinstance(op.get('operationId'),str) or str(uuid.UUID(op['operationId']))!=op['operationId']:emit('unknown','prompt_attempt_not_admitted')
  env=public_cli_environment(adb,pathlib.Path(cli));device()
  lock=base/('android-native-device-'+intent['device']+'.lock');lease_fd=os.open(lock,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
  lock_info=os.fstat(lease_fd)
  if not stat.S_ISREG(lock_info.st_mode) or lock_info.st_uid!=os.getuid() or stat.S_IMODE(lock_info.st_mode)!=0o600 or lock_info.st_nlink!=1:emit('unknown','device_lock_unsafe')
  fcntl.flock(lease_fd,fcntl.LOCK_SH|fcntl.LOCK_NB)
  lease=base/('android-native-device-'+intent['device']+'.lease');claim={'owner':'android-consent-grant','host':'archlinux','device':intent['device'],'correlationId':correlation}
  claim_fd,claim_fingerprint=retain_claim(lease,claim)
  before=data('status');listed_before=data('operations','list').get('operations');status_before=public('--controller-id',owner,'operations','status',op['operationId'],allowed=(0,1,2),limit=16384)
  xml,metadata=capture_prompt(True)
  after=data('status');listed_after=data('operations','list').get('operations');status_after=public('--controller-id',owner,'operations','status',op['operationId'],allowed=(0,1,2),limit=16384);device()
  if not isinstance(listed_before,list) or not isinstance(listed_after,list) or len(listed_before)>128 or len(listed_after)>128 or any(not isinstance(x,dict) for x in listed_before+listed_after):emit('unknown','operations_invalid')
  if any(type(x.get('final')) is not bool or type(x.get('ok')) is not bool or not isinstance(x.get('code'),str) or len(x['code'])>64 for x in (status_before,status_after)):emit('unknown','public_invalid')
  original_before=[x for x in listed_before if x.get('id')==op['operationId']];original_after=[x for x in listed_after if x.get('id')==op['operationId']]
  evidence_directory=base/('android-grant-prompt-'+correlation+'-'+metadata['observationId'])
  evidence_file(evidence_directory,'operation-observation.json',json.dumps({'owner':owner,'revision':revision,'intentSha256':intent_sha,'operationId':op['operationId'],'statusBefore':status_before,'statusAfter':status_after,'listBefore':original_before,'listAfter':original_after,'workerIdentity':identity,'retainedRecordSha256':{k:hashlib.sha256(v).hexdigest() for k,v in retained_original.items()}},sort_keys=True,separators=(',',':')).encode(),65536)
  if any(private(job/name,131072 if name=='worker.py' else 8192)!=raw for name,raw in retained_original.items()) or original_before!=original_after or before!=after or {k:status_before.get(k) for k in ('operationId','final','code','ok')}!={k:status_after.get(k) for k in ('operationId','final','code','ok')} or not claim_current(claim_fd,lease,claim_fingerprint) or json.loads(private(job/'result.json'))!=receipt:emit('unknown','prompt_observation_changed')
  for name in ('tap-intent.json','terminal.json','collected.json'):
   if (job/name).exists() or (job/name).is_symlink():emit('unknown','prompt_observation_changed')
  verify_prompt_evidence(evidence_directory)
  try:tree=ET.fromstring(xml);nodes=list(tree.iter('node'))
  except ET.ParseError:tree=None;nodes=[]
  counts={k:min(128,len([n for n in nodes if n.get('resource-id')==v])) for k,v in {'titleCount':'android:id/alertTitle','warningCount':'com.android.vpndialogs:id/warning','positiveCount':'android:id/button1'}.items()}
  title=[n for n in nodes if n.get('resource-id')=='android:id/alertTitle'];warning=[n for n in nodes if n.get('resource-id')=='com.android.vpndialogs:id/warning'];positive=[n for n in nodes if n.get('resource-id')=='android:id/button1']
  checks={'titleMatches':len(title)==1 and title[0].get('text')=='Connection request','warningMatches':len(warning)==1 and _warning_owned(warning[0].get('text'),intent['api']),'positiveTextMatches':len(positive)==1 and positive[0].get('text')=='OK','positiveEnabled':len(positive)==1 and positive[0].get('enabled')=='true','xmlValid':tree is not None and tree.tag=='hierarchy','packagesOwned':bool(nodes) and all(n.get('package') in (None,'com.android.vpndialogs') for n in nodes),'positiveOwned':_positive_button(xml,intent['api']) is not None,'operationBound':status_after.get('operationId')==op['operationId'],'operationFinal':status_after.get('final') is True,'runtimeOff':after.get('runtimeRunning') is False,'operationListed':len(original_after)==1,'listedOperationOwned':len(original_after)==1 and original_after[0].get('controllerId')==owner and original_after[0].get('operation')=='on'}
  code=status_after.get('code');code=code if code in ('ACCEPTED','INVALID_ARGUMENT','NOT_FOUND','CANCELLED','OK','OUTCOME_UNKNOWN') else 'OTHER'
  emit('diagnosed',observationClass='fresh-current-prompt',observationId=metadata['observationId'],checks=checks,counts=counts,operationCode=code,artifacts={k:metadata[k] for k in ('xml','png')})
 if mode not in ('run','collect'):emit('unknown','mode_invalid')
 env=public_cli_environment(adb,pathlib.Path(cli))
 lock=base/('android-native-device-'+intent['device']+'.lock'); fd=os.open(lock,os.O_RDWR|os.O_CREAT|getattr(os,'O_NOFOLLOW',0),0o600)
 lease_fd=fd; info=os.fstat(fd)
 if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1:emit('unknown','device_lock_unsafe')
 fcntl.flock(fd,fcntl.LOCK_EX)
 lease=base/('android-native-device-'+intent['device']+'.lease'); claim={'owner':'android-consent-grant','host':'archlinux','device':intent['device'],'correlationId':correlation}
 if mode=='run':
  if lease.exists() or lease.is_symlink():emit('unknown','device_lease_active')
  d=os.open(lease,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
  with os.fdopen(d,'wb') as f:f.write(json.dumps(claim,sort_keys=True,separators=(',',':')).encode()+b'\n');f.flush();os.fsync(f.fileno())
  d=os.open(base,os.O_RDONLY|getattr(os,'O_DIRECTORY',0));os.fsync(d);os.close(d)
 else:
  marker=None
  if (job/'collected.json').exists() or (job/'collected.json').is_symlink():
   marker=json.loads(private(job/'collected.json'))
   if not isinstance(marker,dict) or set(marker)!={'intentSha256','claim','leaseFingerprint'} or marker['intentSha256']!=intent_sha or marker['claim']!=claim or not isinstance(marker['leaseFingerprint'],list) or len(marker['leaseFingerprint'])!=8 or any(type(x) is not int for x in marker['leaseFingerprint']):emit('unknown','collection_marker_changed')
  if lease.exists() or lease.is_symlink():
   claim_fd,claim_fingerprint=retain_claim(lease,claim)
   if marker is not None and marker['leaseFingerprint']!=claim_fingerprint:emit('unknown','device_lease_changed')
  elif marker is None:emit('unknown','device_lease_missing')
  else:claim_fingerprint=marker['leaseFingerprint']
 if mode=='collect':
  terminal=terminal_proof();op=json.loads(private(job/'operation.json'));opening=json.loads(private(job/'opening.json',1048576))
  if snapshot('true')!=opening:emit('unknown','restoration_changed')
  waited=public('--controller-id',owner,'operations','wait',op['operationId'],allowed=(0,1),timeout=30)
  if waited.get('operationId')!=op['operationId'] or waited.get('final') is not True or waited.get('ok') is not False or waited.get('code')!='INVALID_ARGUMENT':emit('unknown','operation_terminal_changed')
  expected_marker={'intentSha256':intent_sha,'claim':claim,'leaseFingerprint':claim_fingerprint}
  if claim_fd is not None and not claim_current(claim_fd,lease,claim_fingerprint):emit('unknown','device_lease_changed')
  if marker is not None:
   if json.loads(private(job/'collected.json'))!=expected_marker:emit('unknown','collection_marker_changed')
  else:record('collected.json',expected_marker)
  if claim_fd is not None:
   if not claim_current(claim_fd,lease,claim_fingerprint):emit('unknown','device_lease_changed')
   lease.unlink();d=os.open(base,os.O_RDONLY|getattr(os,'O_DIRECTORY',0));os.fsync(d);os.close(d)
  emit('complete',freshProof=True)
 opening=snapshot('false');record('opening.json',opening)
 if snapshot('false')!=opening:emit('unknown','pre_effect_state_changed')
 if snapshot('false')!=opening:emit('unknown','pre_effect_state_changed')
 if ui_absence_proof()['vpnDialogPresent']:emit('unknown','preexisting_consent_prompt')
 record('on-intent.json',{'owner':owner,'revision':revision,'intentSha256':intent_sha})
 opening_raw=private(job/'opening.json',1048576);opening_fingerprint=fingerprint((job/'opening.json').lstat())
 interaction_deadline=time.monotonic()+110
 accepted=public('--controller-id',owner,'--if-revision',str(revision),'--interactive','--async','on')
 op=accepted.get('operationId')
 if accepted.get('ok') is not True or accepted.get('final') is not False or accepted.get('code')!='ACCEPTED' or not isinstance(op,str) or str(uuid.UUID(op))!=op:emit('unknown','on_not_accepted')
 record('operation.json',{'operationId':op,'owner':owner,'revision':revision,'intentSha256':intent_sha})
 point=prompt()
 pre_tap(opening,op,opening_raw,opening_fingerprint)
 if prompt()!=point:emit('unknown','prompt_changed')
 record('tap-intent.json',{'operationId':op,'point':list(point),'intentSha256':intent_sha})
 pre_tap(opening,op,opening_raw,opening_fingerprint)
 if prompt()!=point:emit('unknown','pre_tap_state_changed')
 shell('input','tap',str(point[0]),str(point[1]))
 interaction_deadline=None
 waited=public('--controller-id',owner,'operations','wait',op,allowed=(0,1),timeout=300)
 if waited.get('operationId')!=op or waited.get('final') is not True or waited.get('ok') is not False or waited.get('code')!='INVALID_ARGUMENT':emit('unknown','operation_not_no_location')
 if snapshot('true')!=opening:emit('unknown','restoration_changed')
 terminal={'state':'complete','reason':None,'correlationId':correlation,'operationId':op,'operationCode':'INVALID_ARGUMENT','permissionGranted':True,'runtimeStarted':False,'noLocation':True,'scope':'grant-only','owner':owner,'revision':revision,'intentSha256':intent_sha}
 record('terminal.json',terminal);emit('complete',**{k:v for k,v in terminal.items() if k not in ('state','reason','correlationId')})
except SystemExit:raise
except (OSError,ValueError,TypeError,KeyError,UnicodeError):emit('unknown','proof_unavailable')
finally:
 for fd in ephemeral_fds:os.close(fd)
 if claim_fd is not None:os.close(claim_fd)
 if lease_fd is not None:
  fcntl.flock(lease_fd,fcntl.LOCK_UN);os.close(lease_fd)
''')

# Two complete device/tree guards, ten public reads, three ADB UI reads.
_UI_PREFLIGHT_SECONDS=2*(7*45+120)+10*135+3*45+120
_UI_PREFLIGHT=_REMOTE.split('\ntry:\n info=job.lstat()',1)[0]+r'''
try:
 env=public_cli_environment(adb,pathlib.Path(cli))
 lock=base/('android-native-device-'+intent['device']+'.lock');lease_fd=os.open(lock,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0));info=os.fstat(lease_fd)
 if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1:emit('unknown','device_lock_unsafe')
 try:fcntl.flock(lease_fd,fcntl.LOCK_SH|fcntl.LOCK_NB)
 except BlockingIOError:emit('unknown','device_lock_busy')
 generation=fingerprint(info);lease=base/('android-native-device-'+intent['device']+'.lease')
 if lease.exists() or lease.is_symlink():emit('blocked','device_lease_active')
 proof=ui_absence_proof()
 if lease.exists() or lease.is_symlink() or fingerprint(os.fstat(lease_fd))!=generation or fingerprint(lock.lstat())!=generation:emit('unknown','device_lease_changed')
 emit('blocked' if proof['vpnDialogPresent'] else 'ready','preexisting_consent_prompt' if proof['vpnDialogPresent'] else None,**proof)
except SystemExit:raise
except (OSError,ValueError,TypeError,KeyError,UnicodeError):emit('unknown','ui_observation_invalid')
finally:
 if lease_fd is not None:fcntl.flock(lease_fd,fcntl.LOCK_UN);os.close(lease_fd)
'''

# Grant-only deadline. The inherited document wrapper has a shorter profile.
# Three full reads precede ON, and one follows the final disposition. The live
# consent window remains independently clipped to 110 seconds in _REMOTE.
_GRANT_WORKER_SECONDS=4*_FULL_SNAPSHOT_SECONDS+_UI_PREFLIGHT_SECONDS+110+315+120

def _grant_worker(remote_source,args):
    source=android_document_acceptance._worker(remote_source,args)
    tree=ast.parse(source)
    calls=[node for node in ast.walk(tree) if isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute) and isinstance(node.func.value,ast.Name) and node.func.value.id=='subprocess' and node.func.attr=='run']
    if len(calls)!=1:raise ValueError('grant worker call shape changed')
    timeouts=[keyword.value for keyword in calls[0].keywords if keyword.arg=='timeout']
    if len(timeouts)!=1 or not isinstance(timeouts[0],ast.Constant) or type(timeouts[0].value) is not int or timeouts[0].value!=1800:raise ValueError('grant worker timeout shape changed')
    timeout=timeouts[0];raw=source.encode('utf-8');lines=raw.splitlines(keepends=True)
    begin=sum(map(len,lines[:timeout.lineno-1]))+timeout.col_offset
    end=sum(map(len,lines[:timeout.end_lineno-1]))+timeout.end_col_offset
    if raw[begin:end]!=b'1800':raise ValueError('grant worker timeout span changed')
    result=(raw[:begin]+str(_GRANT_WORKER_SECONDS).encode()+raw[end:]).decode('utf-8')
    ast.parse(result)
    return result

_UI_PREFLIGHT_REASONS={'preexisting_consent_prompt','device_lease_active','device_lease_changed','device_lock_unsafe','device_lock_busy','device_changed','package_changed','cli_stage_changed','owner_or_revision_changed','operations_active','pre_effect_state_changed','prompt_evidence_invalid','private_directory_unsafe','private_file_unsafe','private_file_changed','private_file_unavailable','ui_observation_invalid','command_outcome_unknown','command_failed','command_encoding','public_invalid'}
def _ui_preflight(root,intent):
    try:
        config,profile=_route(root,intent)
        args=('ui-preflight',profile['adb'],intent['cliPath'],profile['serial'],intent['fixtureRoot'],intent['correlationId'],json.dumps(intent,sort_keys=True,separators=(',',':')))
        argv=ssh_transport.build_ssh_argv(config,'archlinux',60,command=('python3','-I','-B','-c','exec('+repr(_UI_PREFLIGHT)+')',*args))
        code,out=android_observation._run_probe(argv,_UI_PREFLIGHT_SECONDS)
        value=json.loads(out) if code==0 and len(out)<=16384 else None
        if not isinstance(value,dict) or value.get('correlationId')!=intent['correlationId'] or value.get('state') not in ('ready','blocked','unknown'):raise ValueError('invalid UI proof')
        if value['state']=='unknown':
            if set(value)!={'state','reason','correlationId'} or not isinstance(value.get('reason'),str) or value['reason'] not in _UI_PREFLIGHT_REASONS:raise ValueError('invalid UI reason')
        elif value.get('reason')=='device_lease_active' and value['state']=='blocked':
            if set(value)!={'state','reason','correlationId'}:raise ValueError('invalid lease proof')
        else:
            if set(value)!={'state','reason','correlationId','observationId','xmlSha256','xmlBytes','vpnDialogPresent'} or not isinstance(value.get('observationId'),str) or not _UUID.fullmatch(value['observationId']) or not isinstance(value.get('xmlSha256'),str) or not _SHA.fullmatch(value['xmlSha256']) or type(value.get('xmlBytes')) is not int or not 0<value['xmlBytes']<=1048576 or type(value.get('vpnDialogPresent')) is not bool or value['state']!=('blocked' if value['vpnDialogPresent'] else 'ready') or value['reason']!=('preexisting_consent_prompt' if value['vpnDialogPresent'] else None):raise ValueError('invalid UI binding')
        return value
    except (OSError,RuntimeError,TimeoutError,ValueError,TypeError,KeyError,UnicodeError):return {'state':'unknown','reason':'ui_observation_invalid'}

_KEYS={'schema','host','device','api','correlationId','artifactId','packageSha256','cliStageCorrelationId','cliPath','cliManifestSha256','cliRpmSha256','cliLauncherSha256','cliDesktopJarSha256','openingReadbackCorrelationId','backupSha256','expectedOwner','expectedRevision','expectedAvd','fixtureRoot','sourceSha'}
def _valid(intent):
    return (isinstance(intent,dict) and set(intent)==_KEYS and intent['schema']==2 and intent['host']=='archlinux' and isinstance(intent['device'],str) and intent['device'] in ('api29','api35') and type(intent['api']) is int and intent['api']=={'api29':29,'api35':35}[intent['device']] and
            all(isinstance(intent[k],str) and _UUID.fullmatch(intent[k]) for k in ('correlationId','cliStageCorrelationId','openingReadbackCorrelationId','expectedOwner')) and
            all(isinstance(intent[k],str) and _SHA.fullmatch(intent[k]) for k in ('packageSha256','backupSha256','cliManifestSha256','cliRpmSha256','cliLauncherSha256','cliDesktopJarSha256')) and
            isinstance(intent['sourceSha'],str) and re.fullmatch('[0-9a-f]{40}',intent['sourceSha']) and type(intent['expectedRevision']) is int and intent['expectedRevision']>=0 and
            isinstance(intent['expectedAvd'],str) and 0<len(intent['expectedAvd'])<=128 and isinstance(intent['artifactId'],str) and 0<len(intent['artifactId'])<=128 and
            isinstance(intent['fixtureRoot'],str) and intent['fixtureRoot'].startswith('/') and '\x00' not in intent['fixtureRoot'] and
            intent['cliPath']==intent['fixtureRoot']+'/android-cli-stage-'+intent['cliStageCorrelationId']+'/tree/opt/vpn-control/bin/vpn-control')
def _journal(root,correlation):
    if not isinstance(correlation,str) or not _UUID.fullmatch(correlation):raise ValueError('grant correlation invalid')
    return Path(root).resolve()/_GROUP/(correlation+'.json')
def _save(root,intent):
    path=_journal(root,intent['correlationId']);path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    info=path.parent.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError('unsafe grant journal')
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
    with os.fdopen(fd,'wb') as f:f.write(json.dumps(intent,sort_keys=True,separators=(',',':')).encode()+b'\n');f.flush();os.fsync(f.fileno())
    fd=os.open(path.parent,os.O_RDONLY|getattr(os,'O_DIRECTORY',0));os.fsync(fd);os.close(fd)
def _load(root,correlation):
    path=_journal(root,correlation)
    try:
        directory=path.parent.lstat()
        if not stat.S_ISDIR(directory.st_mode) or directory.st_uid!=os.getuid() or stat.S_IMODE(directory.st_mode)!=0o700:return None
        fd=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
        with os.fdopen(fd,'rb') as f:
            info=os.fstat(f.fileno());raw=f.read(8193);after=os.fstat(f.fileno());now=path.lstat()
            fingerprint=lambda x:(x.st_dev,x.st_ino,x.st_size,x.st_mtime_ns,x.st_ctime_ns)
            if fingerprint(info)!=fingerprint(after) or fingerprint(after)!=fingerprint(now):return None
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1 or not 0<info.st_size<=8192 or len(raw)!=info.st_size:return None
        intent=json.loads(raw)
        return intent if _valid(intent) and intent['correlationId']==correlation else None
    except (OSError,ValueError,UnicodeError):return None

def _claim(correlation,device='api35'):
    if device not in ('api29','api35'):raise ValueError('grant device invalid')
    return {'owner':'android-consent-grant','host':'archlinux','device':device,'correlationId':correlation}
def _reply(correlation,state,reason=None,**more):return {'ok':state in ('submitted','running','complete','diagnosed','closed','observed'),'state':state,'reason':reason,'correlationId':correlation,'replayAllowed':False,**more}
def _stage_valid(stage,intent):
    return stage.get('ok') is True and stage.get('state')=='published' and stage.get('sourceSha')==intent['sourceSha'] and all(stage.get('receipt',{}).get(k)==intent[v] for k,v in {'cliPath':'cliPath','manifestSha256':'cliManifestSha256','rpmSha256':'cliRpmSha256','launcherSha256':'cliLauncherSha256','desktopJarSha256':'cliDesktopJarSha256'}.items())
def _route(root,intent):
    config=ssh_transport.load_config(root)
    if 'archlinux' not in config.hosts or intent['device'] not in config.hosts['archlinux'].android_devices or ssh_transport.connection_host(config,'archlinux').password is not None or str(config.hosts['archlinux'].fixture_transfer_root)!=intent['fixtureRoot']:raise ValueError('grant route changed')
    profile=android_observation._profile(config.hosts['archlinux'].android_devices[intent['device']])
    if type(profile.get('api')) is not int or profile.get('api')!=intent['api'] or profile.get('expectedAvd')!=intent['expectedAvd']:raise ValueError('grant device changed')
    return config,profile

def start(root:Path|str,host:str,device:str,correlation_id:str,artifact_id:str,cli_stage_correlation_id:str,opening_readback_correlation_id:str,expected_backup_sha256:str,expected_owner:str,expected_revision:int)->dict[str,Any]:
    if host!='archlinux' or not isinstance(device,str) or device not in ('api29','api35') or not all(isinstance(v,str) and _UUID.fullmatch(v) for v in (correlation_id,cli_stage_correlation_id,opening_readback_correlation_id,expected_owner)) or not isinstance(artifact_id,str) or not 0<len(artifact_id)<=128 or not isinstance(expected_backup_sha256,str) or not _SHA.fullmatch(expected_backup_sha256) or type(expected_revision) is not int or expected_revision<0:raise ValueError('grant inputs invalid')
    path=_journal(root,correlation_id)
    if path.exists() or path.is_symlink():return _reply(correlation_id,'unknown','existing_intent_no_replay')
    with android_endpoint_admission._shared_device_lease(Path(root).resolve(),host,device) as lease, android_document_acceptance._device_guard(root,host,device) as document_lease:
        if lease.exists() or lease.is_symlink() or document_lease.exists() or document_lease.is_symlink():return _reply(correlation_id,'blocked','device_lease_active')
        config=ssh_transport.load_config(root)
        if host not in config.hosts or device not in config.hosts[host].android_devices or config.hosts[host].fixture_transfer_root is None or ssh_transport.connection_host(config,host).password is not None:raise ValueError('grant route unavailable')
        profile=android_observation._profile(config.hosts[host].android_devices[device])
        if type(profile.get('api')) is not int or profile['api']!={'api29':29,'api35':35}[device]:raise ValueError('grant requires matching API29/API35 profile')
        source=subprocess.run(['git','rev-parse','HEAD'],cwd=root,capture_output=True,text=True,check=True,timeout=10).stdout.strip()
        artifact=native_artifact_registry.verify_artifact(root,artifact_id)
        if artifact.get('verification')!='verified' or artifact.get('artifact',{}).get('platform')!='android' or artifact['artifact'].get('artifactKind') not in ('apk','native-fixture-apk') or artifact['artifact'].get('sourceSha')!=source:raise ValueError('grant APK not exact source')
        android_package_install._inspect_apk(root,Path(artifact['location']['localPath'])); package_sha=artifact['artifact']['sha256']
        stage=android_cli_stage.status(root,cli_stage_correlation_id);receipt=stage.get('receipt',{});remote=str(config.hosts[host].fixture_transfer_root)
        intent={'schema':2,'host':host,'device':device,'api':profile['api'],'correlationId':correlation_id,'artifactId':artifact_id,'packageSha256':package_sha,'cliStageCorrelationId':cli_stage_correlation_id,'cliPath':receipt.get('cliPath'),'cliManifestSha256':receipt.get('manifestSha256'),'cliRpmSha256':receipt.get('rpmSha256'),'cliLauncherSha256':receipt.get('launcherSha256'),'cliDesktopJarSha256':receipt.get('desktopJarSha256'),'openingReadbackCorrelationId':opening_readback_correlation_id,'backupSha256':expected_backup_sha256,'expectedOwner':expected_owner,'expectedRevision':expected_revision,'expectedAvd':profile['expectedAvd'],'fixtureRoot':remote,'sourceSha':source}
        if not _valid(intent) or not _stage_valid(stage,intent):raise ValueError('grant stage invalid')
        opening=android_admission_readback.async_collect(root,opening_readback_correlation_id);v=opening.get('result',{})
        if opening.get('ok') is not True or opening.get('state')!='complete' or v.get('package',{}).get('baseSha256')!=package_sha or v.get('backup',{}).get('sha256')!=expected_backup_sha256 or v.get('backup',{}).get('rulesValid') is not True or v.get('guard',{}).get('controllerId')!=expected_owner or v.get('guard',{}).get('configurationRevision')!=expected_revision or v.get('device',{}).get('api')!=profile['api'] or v['device'].get('uid')!='2000' or v['device'].get('avd')!=profile['expectedAvd'] or v['device'].get('abi')!='x86_64':raise ValueError('grant readback not admitted')
        live_response=android_admission_readback.readback_status(root,host,device,opening_readback_correlation_id,timeout_seconds=30);live=live_response.get('result',{})
        if live_response.get('ok') is not True or live.get('deviceIdentity') is not True or live.get('stage')!='backup_present' or live.get('controllerId')!=expected_owner or live.get('configurationRevision')!=expected_revision or live.get('backup',{}).get('sha256')!=expected_backup_sha256 or live.get('backup',{}).get('formatValid') is not True:raise ValueError('grant readback changed')
        if android_consent_acceptance.preflight(root,host,device,cli_stage_correlation_id).get('state')!='ready':raise ValueError('grant permission not absent')
        if not _stage_valid(android_cli_stage.status(root,cli_stage_correlation_id),intent):raise ValueError('grant stage changed')
        ui=_ui_preflight(root,intent)
        if ui['state']!='ready':return _reply(correlation_id,ui['state'],ui.get('reason'),nativeActionAllowed=False,productAction=False)
        args=['run',profile['adb'],intent['cliPath'],profile['serial'],remote,correlation_id,json.dumps(intent,sort_keys=True,separators=(',',':'))]
        worker=_grant_worker(_REMOTE,args)
        argv=ssh_transport.build_ssh_argv(config,host,60,command=('python3','-I','-B','-c','exec('+repr(_SUBMIT)+')',remote,correlation_id,args[-1],base64.urlsafe_b64encode(worker.encode()).decode()))
        _save(root,intent)
        for target,value in ((lease,_claim(correlation_id,intent['device'])),(document_lease,{'host':host,'device':device,'correlationId':correlation_id})):
            fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
            with os.fdopen(fd,'wb') as f:f.write(json.dumps(value,sort_keys=True,separators=(',',':')).encode()+b'\n');f.flush();os.fsync(f.fileno())
            fd=os.open(target.parent,os.O_RDONLY|getattr(os,'O_DIRECTORY',0));os.fsync(fd);os.close(fd)
        try:
            code,out=android_observation._run_probe(argv,60);v=json.loads(out) if code==0 and len(out)<=16384 else None
            identity=v.get('identity',{}) if isinstance(v,dict) else {}
            if isinstance(v,dict) and v.get('state')=='submitted' and v.get('correlationId')==correlation_id and isinstance(identity,dict) and set(identity)=={'pid','startTicks'} and all(type(identity[k]) is int and identity[k]>0 for k in identity):return _reply(correlation_id,'submitted',identity=v.get('identity'))
        except (OSError,RuntimeError,TimeoutError,ValueError,UnicodeError):pass
        return _reply(correlation_id,'unknown','submit_unknown')

def _observe(root,intent,mode,replacement=None,continuation=None):
    config,profile=_route(root,intent)
    timeout=_COLLECT_OBSERVER_SECONDS if mode=='collect' else _RECONCILE_OBSERVER_SECONDS if mode in ('reconcile','reconcile-diagnostic','reconcile-replacement','reconcile-replacement-status','reconcile-continuation','reconcile-continuation-status') else 2*(7*45+120)+6*135+3*45+45+120 if mode=='prompt-diagnostic' else 180 if mode=='diagnostic' else 30
    args=(mode,profile['adb'],intent['cliPath'],profile['serial'],intent['fixtureRoot'],intent['correlationId'],json.dumps(intent,sort_keys=True,separators=(',',':')))+((json.dumps(replacement,sort_keys=True,separators=(',',':')), ) if replacement is not None else ())+((json.dumps(continuation,sort_keys=True,separators=(',',':')), ) if continuation is not None else ())
    argv=ssh_transport.build_ssh_argv(config,'archlinux',min(timeout,60),command=('python3','-I','-B','-c','exec('+repr(_REMOTE)+')',*args))
    code,out=android_observation._run_probe(argv,timeout);v=json.loads(out) if code==0 and len(out)<=16384 else None
    if not isinstance(v,dict) or v.get('correlationId')!=intent['correlationId'] or v.get('state') not in ('unknown','running','complete','diagnosed','closed','observed'):raise ValueError('grant observer invalid')
    return v

def status(root:Path|str,correlation_id:str)->dict[str,Any]:
    intent=_load(root,correlation_id)
    if intent is None:return _reply(correlation_id,'unknown','missing_or_invalid_local_intent')
    try:v=_observe(root,intent,'status');return _reply(correlation_id,v['state'],v.get('reason'),**{k:v[k] for k in ('result','checkpoint') if k in v})
    except (OSError,RuntimeError,TimeoutError,ValueError,UnicodeError):return _reply(correlation_id,'unknown','transport_or_proof_unknown')

def _exact(path,value):
    try:
        fd=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
        with os.fdopen(fd,'rb') as f:
            info=os.fstat(f.fileno());raw=f.read(2049);after=os.fstat(f.fileno());now=path.lstat()
            if (info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns,info.st_nlink)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns,after.st_nlink):return False
            return stat.S_ISREG(info.st_mode) and info.st_uid==os.getuid() and stat.S_IMODE(info.st_mode)==0o600 and info.st_nlink==1 and 0<len(raw)==info.st_size<=2048 and (info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns)==(now.st_dev,now.st_ino,now.st_size,now.st_mtime_ns) and json.loads(raw)==value
    except (OSError,ValueError,UnicodeError):return False

_DIAGNOSTIC_CHECKS={'runtimeOff','runtimeStopped','vpnMode','selectionNull','activeNull','locationsEmpty','sourceCurrentLocations','subscriptionNull'}
_DIAGNOSTIC_FACTS={'configuredMode','runtimeObservation','sourceMode','subscriptionBinding','locationShape','locationCount','locationCountTruncated','operationShape','operationCount','operationCountTruncated','operationsTerminal','selectedFieldPresent','activeFieldPresent'}
def diagnose(root:Path|str,correlation_id:str)->dict[str,Any]:
    """Read current finite baseline facts for one retained failed grant attempt."""
    intent=_load(root,correlation_id)
    flags={'nativeActionAllowed':False,'productAction':False}
    if intent is None:return _reply(correlation_id,'unknown','missing_or_invalid_local_intent',**flags)
    try:
        v=_observe(root,intent,'diagnostic')
        if v['state']!='diagnosed':return _reply(correlation_id,'unknown',v.get('reason'),**flags)
        checks=v.get('checks');facts=v.get('facts')
        enums={'configuredMode':{'vpn','proxy-only','missing','other'},'runtimeObservation':{'stopped','running','unknown','missing','other'},'sourceMode':{'current-locations','subscription','missing','other'},'subscriptionBinding':{'null','empty','selected','missing','other'},'locationShape':{'array','missing','other'},'operationShape':{'array','other'}}
        boolean_facts=_DIAGNOSTIC_FACTS-set(enums)-{'locationCount','operationCount'}
        if (set(v)!={'state','reason','correlationId','historicalReason','observationClass','checks','facts'} or v.get('historicalReason')!='baseline_not_empty_off' or v.get('observationClass')!='fresh-current-baseline' or
            not isinstance(checks,dict) or set(checks)!=_DIAGNOSTIC_CHECKS or any(type(x) is not bool for x in checks.values()) or
            not isinstance(facts,dict) or set(facts)!=_DIAGNOSTIC_FACTS or any(not isinstance(facts[k],str) or facts[k] not in values for k,values in enums.items()) or
            any(type(facts[k]) is not bool for k in boolean_facts) or any(type(facts[k]) is not int or not 0<=facts[k]<=128 for k in ('locationCount','operationCount'))):raise ValueError('diagnostic shape invalid')
        return _reply(correlation_id,'diagnosed',**{k:v[k] for k in ('historicalReason','observationClass','checks','facts')},**flags)
    except (OSError,RuntimeError,TimeoutError,ValueError,UnicodeError,KeyError,TypeError):
        return _reply(correlation_id,'unknown','diagnostic_proof_unknown',**flags)

def _fingerprint(info):
    return [info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns,info.st_mode,info.st_uid,info.st_nlink]

def _retain_claim(path,value,limit=2048):
    fd=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
    try:
        info=os.fstat(fd);raw=os.read(fd,limit+1)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1 or
            not 0<len(raw)==info.st_size<=limit or json.loads(raw)!=value or _fingerprint(info)!=_fingerprint(os.fstat(fd)) or _fingerprint(info)!=_fingerprint(path.lstat())):
            raise ValueError('grant claim unsafe or changed')
        return fd,_fingerprint(info)
    except BaseException:
        os.close(fd);raise

def _claim_current(fd,path,fingerprint):
    try:return _fingerprint(os.fstat(fd))==fingerprint and _fingerprint(path.lstat())==fingerprint
    except OSError:return False

def _closed_marker(path):
    fd=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
    with os.fdopen(fd,'rb') as f:
        info=os.fstat(f.fileno());raw=f.read(4097)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1 or
            not 0<len(raw)==info.st_size<=4096 or _fingerprint(info)!=_fingerprint(os.fstat(f.fileno())) or _fingerprint(info)!=_fingerprint(path.lstat())):
            raise ValueError('grant closed marker unsafe')
    return json.loads(raw)

def _write_closed_marker(path,value):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
    with os.fdopen(fd,'wb') as f:
        f.write(json.dumps(value,sort_keys=True,separators=(',',':')).encode()+b'\n');f.flush();os.fsync(f.fileno());created=_fingerprint(os.fstat(f.fileno()))
    fd=os.open(path.parent,os.O_RDONLY|getattr(os,'O_DIRECTORY',0));os.fsync(fd);os.close(fd)
    return created

def collect(root:Path|str,correlation_id:str)->dict[str,Any]:
    intent_path=_journal(root,correlation_id)
    digest=lambda value:hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    marker_path=intent_path.with_suffix('.closed.json')
    intent=_load(root,correlation_id)
    if intent is None:return _reply(correlation_id,'unknown','missing_local_intent')
    selected_intent=intent
    selected_intent_fp=_fingerprint(intent_path.lstat())
    with android_endpoint_admission._shared_device_lease(Path(root).resolve(),'archlinux',intent['device']) as lease, android_document_acceptance._device_guard(root,'archlinux',intent['device']) as document_lease:
        retained={};historical={};marker=None
        paths={'shared':(lease,_claim(correlation_id,intent['device'])),'document':(document_lease,{'host':'archlinux','device':intent['device'],'correlationId':correlation_id})}
        try:
            admitted_intent_fp=_fingerprint(intent_path.lstat())
            intent=_load(root,correlation_id)
            if intent is None:return _reply(correlation_id,'unknown','missing_local_intent')
            if intent!=selected_intent or admitted_intent_fp!=selected_intent_fp:raise ValueError('intent changed before device lock')
            fd,fp=_retain_claim(intent_path,intent,8192);historical['intent']=(fd,fp,intent_path)
            if fp!=admitted_intent_fp:raise ValueError('intent admission generation changed')
            def history_current():
                if any(not _claim_current(fd,path,fp) for fd,fp,path in historical.values()):raise ValueError('historical generation changed')
            if marker_path.exists() or marker_path.is_symlink():
                admitted_marker_fp=_fingerprint(marker_path.lstat())
                marker=_closed_marker(marker_path)
                if (not isinstance(marker,dict) or set(marker)!={'schema','intentSha256','terminalSha256','claims'} or marker['schema']!=1 or marker['intentSha256']!=digest(intent) or not isinstance(marker['terminalSha256'],str) or not _SHA.fullmatch(marker['terminalSha256']) or
                    not isinstance(marker['claims'],dict) or set(marker['claims'])!=set(paths) or
                    any(not isinstance(v,list) or len(v)!=8 or any(type(x) is not int for x in v) for v in marker['claims'].values())):
                    raise ValueError('closed marker changed')
                fd,fp=_retain_claim(marker_path,marker,4096);historical['marker']=(fd,fp,marker_path)
                if fp!=admitted_marker_fp:raise ValueError('marker admission generation changed')
            observed=status(root,correlation_id)
            history_current()
            if observed['state']!='complete':return observed
            binding={'schema':1,'intentSha256':digest(intent),'terminalSha256':digest(observed['result'])}
            if marker is not None and any(marker[k]!=v for k,v in binding.items()):raise ValueError('closed terminal binding changed')
            for key,(path,value) in paths.items():
                if path.exists() or path.is_symlink():
                    retained[key]=_retain_claim(path,value)
                    if marker is not None and retained[key][1]!=marker['claims'][key]:raise ValueError('claim generation changed')
                elif marker is None:raise ValueError('claim absent without closure proof')
            history_current()
            if not _stage_valid(android_cli_stage.status(root,intent['cliStageCorrelationId']),intent):raise ValueError('stage changed')
            v=_observe(root,intent,'collect')
            history_current()
            if v.get('state')!='complete' or v.get('freshProof') is not True:raise ValueError('fresh proof absent')
            if any(not _claim_current(fd,paths[key][0],fingerprint) for key,(fd,fingerprint) in retained.items()):raise ValueError('claim changed before closure')
            if marker is None:
                marker={**binding,'claims':{key:retained[key][1] for key in paths}}
                created=_write_closed_marker(marker_path,marker)
                fd,fp=_retain_claim(marker_path,marker,4096);historical['marker']=(fd,fp,marker_path)
                if created!=fp:raise ValueError('new marker generation changed')
            if _closed_marker(marker_path)!=marker:raise ValueError('closed marker changed')
            history_current()
            for key in ('document','shared'):
                if key not in retained:continue
                fd,fingerprint=retained[key];path=paths[key][0]
                # Both immutable proof records and the exact claim remain held
                # across the fresh native proof and each local closure effect.
                history_current()
                if not _claim_current(fd,path,fingerprint):raise ValueError('claim changed immediately before unlink')
                path.unlink();d=os.open(path.parent,os.O_RDONLY|getattr(os,'O_DIRECTORY',0));os.fsync(d);os.close(d)
            history_current()
        except (OSError,RuntimeError,TimeoutError,ValueError,UnicodeError,TypeError,KeyError):
            return _reply(correlation_id,'unknown','fresh_postcondition_or_closure_unknown')
        finally:
            for fd,_ in retained.values():os.close(fd)
            for fd,_,_ in historical.values():os.close(fd)
    return _reply(correlation_id,'complete',result=observed['result'],leaseReleased=True)

_NO_EFFECT_PROOF={'workerTerminal','noGrantIntents','configurationGenerationUnchanged','fullRoutingUnchanged','packageUnchanged','currentSourceSettingsStable','currentRuntimeStable','currentOperationsStable','historicalSourceSettingsAvailable','permissionAbsent','runtimeOff','retainedBindingsSha256','currentSnapshotSha256'}
def reconcile(root:Path|str,correlation_id:str)->dict[str,Any]:
    return _reconcile(root,correlation_id)

def _reconcile(root,correlation_id,replacement=None,collect_replacement=False,continuation=None,collect_continuation=False):
    """Close only owned claims of a terminal, pre-ON baseline failure."""
    intent=_load(root,correlation_id);flags={'nativeActionAllowed':False,'productAction':False}
    if intent is None:return _reply(correlation_id,'unknown','missing_or_invalid_local_intent',**flags)
    marker_path=_journal(root,correlation_id).with_suffix('.continuation-'+continuation['continuationId']+'.closed.json' if continuation is not None else '.replacement-no-effect.closed.json' if replacement is not None else '.no-effect.closed.json')
    intent_sha=hashlib.sha256(json.dumps(intent,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    with android_endpoint_admission._shared_device_lease(Path(root).resolve(),'archlinux',intent['device']) as lease, android_document_acceptance._device_guard(root,'archlinux',intent['device']) as document_lease:
        local_phase='local-records';retained={};historical_fds={};marker=None;paths={'shared':(lease,_claim(correlation_id,intent['device'])),'document':(document_lease,{'host':'archlinux','device':intent['device'],'correlationId':correlation_id})}
        try:
            if continuation is not None:
                historical_fds['intent']=(_journal(root,correlation_id),*_retain_claim(_journal(root,correlation_id),intent,8192))
                historical_fds['replacement']=(_journal(root,correlation_id).with_suffix('.replacement.json'),*_retain_claim(_journal(root,correlation_id).with_suffix('.replacement.json'),replacement,8192))
                continuation_path=_continuation_path(root,correlation_id,continuation['continuationId'])
            if replacement is not None:
                replacement_path=_journal(root,correlation_id).with_suffix('.replacement.json')
                if collect_replacement:
                    if _closed_marker(replacement_path)!=replacement:raise ValueError('replacement binding changed')
                elif replacement_path.exists() or replacement_path.is_symlink():
                    return reconcile_replacement_status(root,correlation_id)
            if marker_path.exists() or marker_path.is_symlink():
                marker=_closed_marker(marker_path)
                if (not isinstance(marker,dict) or set(marker)!={'schema','kind','intentSha256','remoteMarkerSha256','claims'} or marker['schema']!=1 or marker['kind']!=('continuation-owner-no-grant' if continuation is not None else 'replacement-owner-no-grant' if replacement is not None else 'pre-effect-no-grant') or marker['intentSha256']!=intent_sha or not isinstance(marker['claims'],dict) or set(marker['claims'])!=set(paths) or any(not isinstance(v,list) or len(v)!=8 or any(type(x) is not int for x in v) for v in marker['claims'].values())):raise ValueError('closure marker invalid')
            for key,(path,value) in paths.items():
                if path.exists() or path.is_symlink():
                    retained[key]=_retain_claim(path,value)
                    if marker is not None and retained[key][1]!=marker['claims'][key]:raise ValueError('claim generation changed')
                elif marker is None:raise ValueError('claim absent without closure marker')
            if continuation is not None:
                if collect_continuation:
                    if _closed_marker(continuation_path)!=continuation:raise ValueError('continuation changed')
                elif continuation_path.exists() or continuation_path.is_symlink():return replacement_continue_no_effect_status(root,correlation_id,continuation['continuationId'])
                else:_write_closed_marker(continuation_path,continuation)
            if replacement is not None and not collect_replacement:_write_closed_marker(replacement_path,replacement)
            local_phase='transport'
            v=_observe(root,intent,'reconcile-continuation-status' if collect_continuation else 'reconcile-continuation',replacement,continuation) if continuation is not None else _observe(root,intent,'reconcile') if replacement is None else _observe(root,intent,'reconcile-replacement-status' if collect_replacement else 'reconcile-replacement',replacement)
            if v.get('state')=='unknown':return _reconcile_unknown(correlation_id,v,flags)
            local_phase='local-proof';proof=v.get('proof');remote_sha=v.get('markerSha256');history=_diagnostic_history(v)
            if not _no_effect_valid(v,replacement,continuation):raise ValueError('no-effect proof invalid')
            if replacement is not None and (_closed_marker(replacement_path)!=replacement or _load(root,correlation_id)!=intent):raise ValueError('replacement binding changed')
            if continuation is not None and (_closed_marker(continuation_path)!=continuation or any(not _claim_current(fd,path,fp) for path,fd,fp in historical_fds.values())):raise ValueError('continuation or historical binding changed')
            if marker is not None and marker['remoteMarkerSha256']!=remote_sha:raise ValueError('remote marker changed')
            if any(not _claim_current(fd,paths[key][0],fingerprint) for key,(fd,fingerprint) in retained.items()):raise ValueError('claim changed')
            local_phase='local-marker'
            if marker is None:
                marker={'schema':1,'kind':'continuation-owner-no-grant' if continuation is not None else 'replacement-owner-no-grant' if replacement is not None else 'pre-effect-no-grant','intentSha256':intent_sha,'remoteMarkerSha256':remote_sha,'claims':{key:retained[key][1] for key in paths}}
                _write_closed_marker(marker_path,marker)
            if _closed_marker(marker_path)!=marker:raise ValueError('closure marker changed')
            local_phase='local-claims'
            for key in ('document','shared'):
                if key not in retained:continue
                fd,fingerprint=retained[key];path=paths[key][0]
                if not _claim_current(fd,path,fingerprint) or any(not _claim_current(old_fd,old_path,old_fp) for old_path,old_fd,old_fp in historical_fds.values()):raise ValueError('claim or historical binding changed before unlink')
                path.unlink();d=os.open(path.parent,os.O_RDONLY|getattr(os,'O_DIRECTORY',0));os.fsync(d);os.close(d)
        except TimeoutError:return _reply(correlation_id,'unknown','reconcile_transport_timeout',checkpoint='transport',**flags)
        except (OSError,RuntimeError):return _reply(correlation_id,'unknown','reconcile_transport_unknown' if local_phase=='transport' else 'reconcile_local_io_unknown',checkpoint=local_phase,**flags)
        except (ValueError,UnicodeError,TypeError,KeyError):return _reply(correlation_id,'unknown',{'local-records':'reconcile_local_record_invalid','transport':'reconcile_observation_invalid','local-proof':'reconcile_proof_invalid','local-marker':'reconcile_local_marker_changed','local-claims':'reconcile_local_claim_changed'}[local_phase],checkpoint=local_phase,**flags)
        finally:
            for fd,_ in retained.values():os.close(fd)
            for _,fd,_ in historical_fds.values():os.close(fd)
    return _reply(correlation_id,'closed',proof=proof,claimsReleased=True,originalOutcome='unknown',grantObserved=False,**history,**flags)

_REPLACEMENT_PROOF=(_NO_EFFECT_PROOF-{'configurationGenerationUnchanged'})|{'replacementOwnerAdmitted','originalOwnerChanged','replacementBindingSha256'}
_CONTINUATION_PROOF=_REPLACEMENT_PROOF|{'continuationId','continuationIntentSha256'}
def _no_effect_valid(value,replacement=None,continuation=None):
    proof=value.get('proof');remote_sha=value.get('markerSha256')
    if not isinstance(proof,dict):return False
    keys=_CONTINUATION_PROOF if continuation is not None else _NO_EFFECT_PROOF if replacement is None else _REPLACEMENT_PROOF
    hashes={'retainedBindingsSha256','currentSnapshotSha256'}|({'continuationIntentSha256'} if continuation is not None else set())|({'replacementBindingSha256'} if replacement is not None else set())
    return ((continuation is None or (proof is not None and proof.get('continuationId')==continuation['continuationId'] and proof.get('continuationIntentSha256')==hashlib.sha256(json.dumps(continuation,sort_keys=True,separators=(',',':')).encode()).hexdigest())) and value.get('state')=='closed' and isinstance(proof,dict) and set(proof)==keys and all(proof[k] is True for k in keys-hashes-{'historicalSourceSettingsAvailable','continuationId'}) and type(proof['historicalSourceSettingsAvailable']) is bool and all(isinstance(proof[k],str) and _SHA.fullmatch(proof[k]) for k in hashes) and isinstance(remote_sha,str) and _SHA.fullmatch(remote_sha) and (replacement is None or proof['replacementBindingSha256']==hashlib.sha256(json.dumps(replacement,sort_keys=True,separators=(',',':')).encode()).hexdigest()))

_RECONCILE_REASONS=('admitted_backup_changed', 'baseline_not_empty_off', 'cli_stage_changed', 'collection_marker_changed', 'command_encoding', 'command_outcome_unknown', 'device_changed', 'device_lease_active', 'device_lease_changed', 'device_lease_missing', 'device_lease_unsafe', 'device_lock_unsafe', 'diagnostic_attempt_changed', 'diagnostic_attempt_not_admitted', 'diagnostics_ambiguous', 'durable_record_failed', 'identity_invalid', 'intent_changed', 'job_unsafe', 'missing_or_invalid_local_intent', 'mode_invalid', 'on_not_accepted', 'operation_not_no_location', 'operation_terminal_changed', 'operations_active', 'operations_invalid', 'owner_or_revision_changed', 'package_changed', 'pending_operation_changed', 'pending_operation_missing', 'permission_or_runtime_changed', 'pre_effect_state_changed', 'pre_tap_state_changed', 'private_directory_unsafe', 'private_file_changed', 'private_file_unavailable', 'private_file_unsafe', 'prompt_changed', 'prompt_deadline_expired', 'prompt_not_owned', 'proof_unavailable', 'public_invalid', 'reconcile_attempt_not_admitted', 'reconcile_baseline_changed', 'reconcile_command_nonzero', 'reconcile_command_oversize', 'reconcile_command_timeout', 'reconcile_current_snapshots_changed', 'reconcile_grant_intent_present', 'reconcile_local_claim_changed', 'reconcile_local_io_unknown', 'reconcile_local_marker_changed', 'reconcile_local_record_invalid', 'reconcile_marker_changed', 'reconcile_observation_invalid', 'reconcile_original_changed', 'reconcile_proof_invalid', 'reconcile_transport_timeout', 'reconcile_transport_unknown', 'reconcile_worker_identity_unknown', 'reconcile_worker_live', 'restoration_changed', 'routing_changed', 'routing_shape_invalid', 'terminal_binding_invalid', 'worker_receipt_invalid','replacement_receipt_invalid','replacement_binding_missing','replacement_closure_incomplete','device_lock_busy','routing_export_invalid','routing_export_unsafe','routing_export_cleanup_unknown','continuation_intent_invalid','continuation_consumed','continuation_intent_missing','reconcile_operations_changed','observation_receipt_unsafe','observation_receipt_invalid','observation_receipt_bound','observation_receipt_unknown','observation_history_unavailable','observation_history_changed','diagnostic_export_unsafe','diagnostic_export_invalid','diagnostic_export_cleanup_unknown')
_RECONCILE_CHECKPOINTS={'original-intent','original-identity','original-worker','original-result','remote-marker','baseline-record','admitted-backup','remote-claim','private-record','cli-stage','package','device','diagnostics','status','source','settings','locations','operations','routing','baseline','public-command','transport','local-records','local-proof','local-marker','local-claims'}
def _diagnostic_history(value):
    if 'diagnosticHistory' not in value:return {}
    history=value['diagnosticHistory']
    if not isinstance(history,dict) or set(history)!={'presentOwned','absentRetained','absenceCause'} or history['absenceCause']!='unproven' or any(type(history[k]) is not int or not 0<=history[k]<=128 for k in ('presentOwned','absentRetained')) or history['presentOwned']+history['absentRetained']>128:raise ValueError('diagnostic history invalid')
    return {'diagnosticHistory':history}

def _reconcile_unknown(correlation,value,flags):
    if not isinstance(value,dict):return _reply(correlation,'unknown','reconcile_observation_invalid',**flags)
    reason=value.get('reason');phase=value.get('checkpoint');command_code=value.get('commandCode')
    try:observation=_diagnostic_history(value)
    except ValueError:return _reply(correlation,'unknown','reconcile_observation_invalid',**flags)
    for key in ('currentSnapshotSha256','retainedBindingsSha256'):
        if key in value:
            if reason!='replacement_closure_incomplete' or not isinstance(value[key],str) or not _SHA.fullmatch(value[key]):return _reply(correlation,'unknown','reconcile_observation_invalid',**flags)
            observation[key]=value[key]
    if 'operationsDiff' in value:
        diff=value['operationsDiff'];keys={'added','removed','changed','addedDiagnostics','addedOther'}
        if reason!='reconcile_operations_changed' or not isinstance(diff,dict) or set(diff)!=keys or any(type(n) is not int or not 0<=n<=128 for n in diff.values()) or diff['addedDiagnostics']+diff['addedOther']!=diff['added']:return _reply(correlation,'unknown','reconcile_observation_invalid',**flags)
        observation['operationsDiff']=diff
    if any(k in observation for k in ('currentSnapshotSha256','retainedBindingsSha256')) and any(k not in observation for k in ('currentSnapshotSha256','retainedBindingsSha256')):return _reply(correlation,'unknown','reconcile_observation_invalid',**flags)
    if ('commandCode' in value and (not isinstance(command_code,str) or command_code not in {'TIMEOUT','OTHER','UNCLASSIFIED'})) or not isinstance(reason,str) or reason not in _RECONCILE_REASONS or (phase is not None and (not isinstance(phase,str) or phase not in _RECONCILE_CHECKPOINTS)):
        return _reply(correlation,'unknown','reconcile_observation_invalid',**flags)
    return _reply(correlation,'unknown',reason,**({'checkpoint':phase} if phase is not None else {}),**({'commandCode':command_code} if 'commandCode' in value else {}),**observation,**flags)

def _reconciliation_observer(root,correlation,current):
    intent=_load(root,correlation);flags={'nativeActionAllowed':False,'productAction':False}
    if intent is None:return _reply(correlation,'unknown','missing_or_invalid_local_intent',**flags)
    local_marker='absent';local_phase='local-records';marker=None
    path=_journal(root,correlation).with_suffix('.no-effect.closed.json')
    try:
        if path.exists() or path.is_symlink():
            marker=_closed_marker(path);local_marker='valid' if isinstance(marker,dict) and set(marker)=={'schema','kind','intentSha256','remoteMarkerSha256','claims'} and marker['schema']==1 and marker['kind']=='pre-effect-no-grant' and marker['intentSha256']==hashlib.sha256(json.dumps(intent,sort_keys=True,separators=(',',':')).encode()).hexdigest() and isinstance(marker['remoteMarkerSha256'],str) and _SHA.fullmatch(marker['remoteMarkerSha256']) and isinstance(marker['claims'],dict) and set(marker['claims'])=={'shared','document'} and all(isinstance(x,list) and len(x)==8 and all(type(n) is int for n in x) for x in marker['claims'].values()) else 'invalid'
        local_claims={}
        local_paths={'shared':(Path(root).resolve()/('.rag_index/android-native-device-leases/lease-archlinux-'+intent['device']+'.json'),_claim(correlation,intent['device'])),'document':(android_document_acceptance._lease(root,'archlinux',intent['device'],correlation),{'host':'archlinux','device':intent['device'],'correlationId':correlation})}
        for key,(claim_path,value) in local_paths.items():
            try:
                candidate=_closed_marker(claim_path)
                if candidate!=value:local_claims[key]='foreign';continue
                fd,fingerprint=_retain_claim(claim_path,value)
                try:local_claims[key]='changed' if local_marker=='valid' and marker['claims'][key]!=fingerprint else 'owned'
                finally:os.close(fd)
            except FileNotFoundError:local_claims[key]='absent'
            except (OSError,ValueError,UnicodeError,TypeError):local_claims[key]='unsafe'
        local_phase='transport'
        v=_observe(root,intent,'reconcile-diagnostic' if current else 'reconcile-status')
        if not isinstance(v,dict):raise ValueError('observer schema invalid')
        if v.get('state')=='unknown':return _reconcile_unknown(correlation,v,flags)
        records=v.get('records');enums={'workerState':{'terminal','live','reused','unknown'},'grantRecords':{'absent','present'},'baselineRecord':{'absent','present'},'remoteMarker':{'absent','valid','invalid'},'remoteClaim':{'absent','owned','foreign','changed'},'lockState':{'free','busy','missing','unsafe'}}
        if (v.get('state')!='observed' or not isinstance(records,dict) or set(records)!=set(enums) or any(not isinstance(records[k],str) or records[k] not in values for k,values in enums.items()) or v.get('currentProof') not in {'not-probed','matched','drift'} or ('historicalSourceSettings' in v and (not isinstance(v['historicalSourceSettings'],str) or v['historicalSourceSettings'] not in {'unavailable','matched','drift'}))):raise ValueError('observer schema invalid')
        return _reply(correlation,'observed',records=records,localMarker=local_marker,localClaims=local_claims,currentProof=v['currentProof'],**({'historicalSourceSettings':v['historicalSourceSettings']} if 'historicalSourceSettings' in v else {}),**flags)
    except TimeoutError:return _reply(correlation,'unknown','reconcile_transport_timeout',checkpoint='transport',**flags)
    except (OSError,RuntimeError):return _reply(correlation,'unknown','reconcile_transport_unknown' if local_phase=='transport' else 'reconcile_local_io_unknown',checkpoint=local_phase,**flags)
    except (ValueError,UnicodeError,TypeError,KeyError):return _reply(correlation,'unknown','reconcile_observation_invalid' if local_phase=='transport' else 'reconcile_local_record_invalid',checkpoint=local_phase,**flags)

def reconcile_status(root:Path|str,correlation_id:str)->dict[str,Any]:
    """Private-record/claim observer; no app reads, evidence writes, or closure replay."""
    return _reconciliation_observer(root,correlation_id,False)

def reconcile_diagnose(root:Path|str,correlation_id:str)->dict[str,Any]:
    """Bounded fresh baseline reads after private reconciliation status admission."""
    return _reconciliation_observer(root,correlation_id,True)


def _replacement_binding(root,correlation):
    value=_closed_marker(_journal(root,correlation).with_suffix('.replacement.json'))
    if not isinstance(value,dict) or set(value)!={'schema','originalIntentSha256','readbackCorrelationId','backupSha256','owner','revision','readbackIntent','readbackResultSha256','readbackIdentity'} or value['schema']!=1:raise ValueError('replacement binding invalid')
    intent=_load(root,correlation)
    if intent is None or value['originalIntentSha256']!=hashlib.sha256(json.dumps(intent,sort_keys=True,separators=(',',':')).encode()).hexdigest() or not isinstance(value['owner'],str) or not _UUID.fullmatch(value['owner']) or value['owner']==intent['expectedOwner'] or type(value['revision']) is not int or value['revision']<0 or not isinstance(value['readbackCorrelationId'],str) or not _UUID.fullmatch(value['readbackCorrelationId']) or any(not isinstance(value[k],str) or not _SHA.fullmatch(value[k]) for k in ('backupSha256','readbackResultSha256')):raise ValueError('replacement binding invalid')
    return value

def reconcile_replacement(root:Path|str,correlation_id:str,replacement_readback_correlation_id:str,expected_backup_sha256:str,expected_owner:str,expected_revision:int)->dict[str,Any]:
    """One-shot replacement-owner closure admission; never reruns the grant."""
    if not all(isinstance(v,str) and _UUID.fullmatch(v) for v in (correlation_id,replacement_readback_correlation_id,expected_owner)) or not isinstance(expected_backup_sha256,str) or not _SHA.fullmatch(expected_backup_sha256) or type(expected_revision) is not int or expected_revision<0:raise ValueError('replacement inputs invalid')
    flags={'nativeActionAllowed':False,'productAction':False}
    intent=_load(root,correlation_id)
    if intent is None:return _reply(correlation_id,'unknown','missing_or_invalid_local_intent',**flags)
    path=_journal(root,correlation_id).with_suffix('.replacement.json')
    if path.exists() or path.is_symlink():
        try:
            existing=_replacement_binding(root,correlation_id)
            if (existing['readbackCorrelationId'],existing['backupSha256'],existing['owner'],existing['revision'])!=(replacement_readback_correlation_id,expected_backup_sha256,expected_owner,expected_revision):raise ValueError('replacement receipt changed')
            return reconcile_replacement_status(root,correlation_id)
        except (OSError,ValueError,TypeError,KeyError):return _reply(correlation_id,'unknown','replacement_receipt_invalid',**flags)
    try:
        ri=android_admission_readback._load_async_intent(root,replacement_readback_correlation_id)
        rc=android_admission_readback.async_collect(root,replacement_readback_correlation_id);rv=rc.get('result',{});backup=rv.get('backup',{});guard=rv.get('guard',{});dev=rv.get('device',{})
        wanted={'host':'archlinux','device':intent['device'],'correlationId':replacement_readback_correlation_id,'expectedBaseSha256':intent['packageSha256'],'serial':_route(root,intent)[1]['serial'],'expectedAvd':intent['expectedAvd'],'api':intent['api'],'fixtureRoot':intent['fixtureRoot']}
        identity=rc.get('identity')
        if expected_owner==intent['expectedOwner'] or replacement_readback_correlation_id==intent['openingReadbackCorrelationId'] or ri!=wanted or rc.get('ok') is not True or rc.get('state')!='complete' or rv.get('admitted') is not True or rv.get('package',{}).get('baseSha256')!=intent['packageSha256'] or dev.get('api')!=intent['api'] or dev.get('uid')!='2000' or dev.get('abi')!='x86_64' or dev.get('avd')!=intent['expectedAvd'] or guard.get('controllerId')!=expected_owner or guard.get('configurationRevision')!=expected_revision or backup.get('sha256')!=expected_backup_sha256 or backup.get('rulesValid') is not True or not isinstance(identity,dict) or set(identity)!={'pid','startTicks'} or any(type(x) is not int or x<=0 for x in identity.values()):raise ValueError('replacement readback invalid')
        live=android_admission_readback.readback_status(root,'archlinux',intent['device'],replacement_readback_correlation_id,timeout_seconds=30)
        lv=live.get('result',{})
        if live.get('ok') is not True or lv.get('deviceIdentity') is not True or lv.get('stage')!='backup_present' or lv.get('controllerId')!=expected_owner or lv.get('configurationRevision')!=expected_revision or lv.get('backup',{}).get('sha256')!=expected_backup_sha256 or lv.get('backup',{}).get('formatValid') is not True:raise ValueError('replacement readback changed')
        if not _stage_valid(android_cli_stage.status(root,intent['cliStageCorrelationId']),intent):raise ValueError('stage changed')
        binding={'schema':1,'originalIntentSha256':hashlib.sha256(json.dumps(intent,sort_keys=True,separators=(',',':')).encode()).hexdigest(),'readbackCorrelationId':replacement_readback_correlation_id,'backupSha256':expected_backup_sha256,'owner':expected_owner,'revision':expected_revision,'readbackIntent':ri,'readbackResultSha256':hashlib.sha256(json.dumps(rv,sort_keys=True,separators=(',',':')).encode()).hexdigest(),'readbackIdentity':identity}
        return _reconcile(root,correlation_id,binding)
    except (OSError,RuntimeError,TimeoutError,ValueError,TypeError,KeyError):return _reply(correlation_id,'unknown','replacement_receipt_invalid',**flags)

def reconcile_replacement_status(root:Path|str,correlation_id:str)->dict[str,Any]:
    """Fresh observational proof; only provenance/export evidence may be written."""
    flags={'nativeActionAllowed':False,'productAction':False}
    try:
        binding=_replacement_binding(root,correlation_id);intent=_load(root,correlation_id)
        value=_observe(root,intent,'reconcile-replacement-status',binding)
        if value.get('state')=='unknown':return _reconcile_unknown(correlation_id,value,flags)
        if not _no_effect_valid(value,binding):raise ValueError('replacement proof invalid')
        return _reply(correlation_id,'observed',proof=value['proof'],remoteClosureVerified=True,originalOutcome='unknown',grantObserved=False,**_diagnostic_history(value),**flags)
    except TimeoutError:return _reply(correlation_id,'unknown','reconcile_transport_timeout',checkpoint='transport',**flags)
    except (OSError,RuntimeError,ValueError,TypeError,KeyError):return _reply(correlation_id,'unknown','replacement_receipt_invalid',**flags)

def reconcile_replacement_collect(root:Path|str,correlation_id:str)->dict[str,Any]:
    """Collect only a fresh verified remote closure, then close exact local claims."""
    try:return _reconcile(root,correlation_id,_replacement_binding(root,correlation_id),True)
    except (OSError,ValueError,TypeError,KeyError):return _reply(correlation_id,'unknown','replacement_receipt_invalid',nativeActionAllowed=False,productAction=False)


def _continuation_path(root,correlation,continuation_id):
    if not isinstance(continuation_id,str) or not _UUID.fullmatch(continuation_id) or continuation_id==correlation:raise ValueError('continuation UUID invalid')
    return _journal(root,correlation).with_suffix('.continuation-'+continuation_id+'.json')

def _load_continuation(root,correlation,continuation_id):
    value=_closed_marker(_continuation_path(root,correlation,continuation_id));intent=_load(root,correlation);binding=_replacement_binding(root,correlation)
    expected={'schema':1,'continuationId':continuation_id,'originalIntentSha256':hashlib.sha256(json.dumps(intent,sort_keys=True,separators=(',',':')).encode()).hexdigest(),'replacementBindingSha256':hashlib.sha256(json.dumps(binding,sort_keys=True,separators=(',',':')).encode()).hexdigest(),'openingDisposition':value.get('openingDisposition') if isinstance(value,dict) else None}
    opening=expected['openingDisposition']
    if not isinstance(opening,dict) or set(opening)!={'state','reason','provenance','currentSnapshotSha256','retainedBindingsSha256'} or any(opening.get(k)!=v for k,v in {'state':'unknown','reason':'replacement_closure_incomplete','provenance':'fresh-read-only'}.items()) or any(not isinstance(opening.get(k),str) or not _SHA.fullmatch(opening[k]) for k in ('currentSnapshotSha256','retainedBindingsSha256')):raise ValueError('opening proof invalid')
    if intent is None or value!=expected:raise ValueError('continuation binding invalid')
    return value,binding,intent

def replacement_continue_no_effect(root:Path|str,correlation_id:str,continuation_id:str)->dict[str,Any]:
    """Admit one distinct closure continuation; never replay a consumed UUID."""
    path=_continuation_path(root,correlation_id,continuation_id);flags={'nativeActionAllowed':False,'productAction':False}
    if path.exists() or path.is_symlink():return replacement_continue_no_effect_status(root,correlation_id,continuation_id)
    try:
        binding=_replacement_binding(root,correlation_id);intent=_load(root,correlation_id)
        opening=reconcile_replacement_status(root,correlation_id)
        if opening.get('state')!='unknown' or opening.get('reason')!='replacement_closure_incomplete' or any(not isinstance(opening.get(k),str) or not _SHA.fullmatch(opening[k]) for k in ('currentSnapshotSha256','retainedBindingsSha256')):raise ValueError('prior closure not incomplete')
        continuation={'schema':1,'continuationId':continuation_id,'originalIntentSha256':hashlib.sha256(json.dumps(intent,sort_keys=True,separators=(',',':')).encode()).hexdigest(),'replacementBindingSha256':hashlib.sha256(json.dumps(binding,sort_keys=True,separators=(',',':')).encode()).hexdigest(),'openingDisposition':{'state':'unknown','reason':'replacement_closure_incomplete','provenance':'fresh-read-only',**{k:opening[k] for k in ('currentSnapshotSha256','retainedBindingsSha256')}}}
        result=_reconcile(root,correlation_id,binding,True,continuation,False)
        return {**result,'continuationId':continuation_id}
    except (OSError,RuntimeError,TimeoutError,ValueError,TypeError,KeyError):return _reply(correlation_id,'unknown','continuation_intent_invalid',continuationId=continuation_id,**flags)

def replacement_continue_no_effect_status(root:Path|str,correlation_id:str,continuation_id:str)->dict[str,Any]:
    """Observe the distinct child intent/closure with fresh baseline proof."""
    flags={'nativeActionAllowed':False,'productAction':False}
    try:
        continuation,binding,intent=_load_continuation(root,correlation_id,continuation_id)
        value=_observe(root,intent,'reconcile-continuation-status',binding,continuation)
        if value.get('state')=='unknown':return {**_reconcile_unknown(correlation_id,value,flags),'continuationId':continuation_id}
        if not _no_effect_valid(value,binding,continuation):raise ValueError('continuation proof invalid')
        return _reply(correlation_id,'observed',continuationId=continuation_id,proof=value['proof'],remoteClosureVerified=True,originalOutcome='unknown',grantObserved=False,**_diagnostic_history(value),**flags)
    except TimeoutError:return _reply(correlation_id,'unknown','reconcile_transport_timeout',continuationId=continuation_id,checkpoint='transport',**flags)
    except (OSError,RuntimeError,ValueError,TypeError,KeyError):return _reply(correlation_id,'unknown','continuation_intent_invalid',continuationId=continuation_id,**flags)

def replacement_continue_no_effect_collect(root:Path|str,correlation_id:str,continuation_id:str)->dict[str,Any]:
    """Close exact local claims only after the distinct remote child closed."""
    try:
        continuation,binding,_=_load_continuation(root,correlation_id,continuation_id)
        return {**_reconcile(root,correlation_id,binding,True,continuation,True),'continuationId':continuation_id}
    except (OSError,ValueError,TypeError,KeyError):return _reply(correlation_id,'unknown','continuation_intent_invalid',continuationId=continuation_id,nativeActionAllowed=False,productAction=False)


def prompt_diagnose(root:Path|str,correlation_id:str)->dict[str,Any]:
    """Capture fresh current prompt evidence; never reconstruct the failed prompt."""
    intent=_load(root,correlation_id)
    flags={'nativeActionAllowed':False,'productAction':False,'claimsReleased':False}
    if intent is None:return _reply(correlation_id,'unknown','missing_or_invalid_local_intent',**flags)
    try:
        with android_endpoint_admission._shared_device_lease(Path(root).resolve(),'archlinux',intent['device']) as lease, android_document_acceptance._device_guard(root,'archlinux',intent['device']) as document_lease:
            retained=[]
            try:
                for path,value in ((lease,_claim(correlation_id,intent['device'])),(document_lease,{'host':'archlinux','device':intent['device'],'correlationId':correlation_id})):
                    fd,fp=_retain_claim(path,value);retained.append((fd,path,fp))
                v=_observe(root,intent,'prompt-diagnostic')
                if any(not _claim_current(fd,path,fp) for fd,path,fp in retained):raise ValueError('local claim changed')
                if v['state']!='diagnosed':
                    reason=v.get('reason');allowed={'prompt_attempt_not_admitted','prompt_worker_live','prompt_worker_unknown','prompt_evidence_invalid','prompt_observation_changed','identity_invalid','device_changed','package_changed','cli_stage_changed','owner_or_revision_changed','device_lease_changed','device_lease_unsafe','device_lock_unsafe','private_file_unavailable','private_file_unsafe','private_file_changed','private_directory_unsafe','operations_invalid','command_failed','command_encoding','command_outcome_unknown','public_invalid'}
                    return _reply(correlation_id,'unknown',reason if reason in allowed else 'prompt_diagnostic_unknown',**flags)
                if set(v)!={'state','reason','correlationId','observationClass','observationId','checks','counts','operationCode','artifacts'} or v['observationClass']!='fresh-current-prompt' or not isinstance(v['observationId'],str) or not _UUID.fullmatch(v['observationId']):raise ValueError('prompt shape')
                if not isinstance(v['checks'],dict) or set(v['checks'])!={'titleMatches','warningMatches','positiveTextMatches','positiveEnabled','xmlValid','packagesOwned','positiveOwned','operationBound','operationFinal','runtimeOff','operationListed','listedOperationOwned'} or any(type(x) is not bool for x in v['checks'].values()):raise ValueError('checks')
                if not isinstance(v['counts'],dict) or set(v['counts'])!={'titleCount','warningCount','positiveCount'} or any(type(x) is not int or not 0<=x<=128 for x in v['counts'].values()):raise ValueError('counts')
                if v['operationCode'] not in ('ACCEPTED','INVALID_ARGUMENT','NOT_FOUND','CANCELLED','OK','OUTCOME_UNKNOWN','OTHER') or not isinstance(v['artifacts'],dict) or set(v['artifacts'])!={'xml','png'}:raise ValueError('artifacts')
                for key,limit in (('xml',1048576),('png',8388608)):
                    a=v['artifacts'][key]
                    if not isinstance(a,dict) or set(a)!={'sha256','bytes'} or not isinstance(a['sha256'],str) or not _SHA.fullmatch(a['sha256']) or type(a['bytes']) is not int or not 0<a['bytes']<=limit:raise ValueError('artifact')
                return _reply(correlation_id,'diagnosed',**{k:v[k] for k in ('observationClass','observationId','checks','counts','operationCode','artifacts')},**flags)
            finally:
                for fd,_,_ in retained:os.close(fd)
    except (OSError,RuntimeError,TimeoutError,ValueError,UnicodeError,KeyError,TypeError):return _reply(correlation_id,'unknown','prompt_diagnostic_unknown',**flags)

_PROMPT_FILES={'ui.xml':1048576,'ui.png':8388608,'binding.json':8192,'operation-observation.json':65536}
_PROMPT_FETCH=r'''
import base64,hashlib,json,os,pathlib,re,stat,sys
base,correlation,observation,expected,request=sys.argv[1:]
base=pathlib.Path(base);intent=json.loads(expected);request=json.loads(request)
job=base/('android-consent-grant-'+correlation);directory=base/('android-grant-prompt-'+correlation+'-'+observation)
limits={'ui.xml':1048576,'ui.png':8388608,'binding.json':8192,'operation-observation.json':65536}
def fp(i):return [i.st_dev,i.st_ino,i.st_size,i.st_mtime_ns,i.st_ctime_ns,i.st_mode,i.st_uid,i.st_nlink]
def read(p,limit):
 d=p.parent.lstat()
 if not stat.S_ISDIR(d.st_mode) or d.st_uid!=os.getuid() or stat.S_IMODE(d.st_mode)!=0o700:raise ValueError()
 fd=os.open(p,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
 with os.fdopen(fd,'rb') as f:
  before=os.fstat(f.fileno())
  if not stat.S_ISREG(before.st_mode) or before.st_uid!=os.getuid() or stat.S_IMODE(before.st_mode)!=0o600 or before.st_nlink!=1 or not 0<before.st_size<=limit:raise ValueError()
  raw=f.read(limit+1)
  if len(raw)!=before.st_size or fp(before)!=fp(os.fstat(f.fileno())) or fp(before)!=fp(p.lstat()):raise ValueError()
 return raw,fp(before)
def census():
 original,_=read(job/'intent.json',8192)
 if json.loads(original)!=intent:raise ValueError()
 binding_raw,_=read(directory/'binding.json',8192);binding=json.loads(binding_raw)
 context_raw,_=read(directory/'operation-observation.json',65536);context=json.loads(context_raw)
 sha=hashlib.sha256(expected.encode()).hexdigest()
 if binding.get('schema')!=1 or binding.get('observationId')!=observation or binding.get('intentSha256')!=sha or binding.get('owner')!=intent['expectedOwner'] or binding.get('revision')!=intent['expectedRevision'] or context.get('intentSha256')!=sha or context.get('owner')!=intent['expectedOwner'] or context.get('revision')!=intent['expectedRevision']:raise ValueError()
 records=context.get('retainedRecordSha256')
 if not isinstance(records,dict) or set(records)!={'intent.json','identity.json','worker.py','result.json','on-intent.json','operation.json'}:raise ValueError()
 original_records={}
 for name,digest in records.items():
  raw,generation=read(job/name,131072 if name=='worker.py' else 8192)
  if hashlib.sha256(raw).hexdigest()!=digest:raise ValueError()
  original_records[name]={'sha256':digest,'bytes':len(raw),'fingerprint':generation}
 op=json.loads(read(job/'operation.json',8192)[0])
 if binding.get('operation')!=op or context.get('operationId')!=op.get('operationId') or context.get('workerIdentity')!=json.loads(read(job/'identity.json',1024)[0]):raise ValueError()
 values={}
 for name,limit in limits.items():
  raw,fingerprint=read(directory/name,limit);meta={'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw),'fingerprint':fingerprint}
  if name in ('ui.xml','ui.png') and binding.get('xml' if name=='ui.xml' else 'png')!={k:meta[k] for k in ('sha256','bytes')}:raise ValueError()
  values[name]=meta
 return {'files':values,'records':original_records}
try:
 if not re.fullmatch('[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}',observation):raise ValueError()
 before=census()
 if request=={'mode':'metadata'}:reply={'state':'ready',**before}
 else:
  if set(request)!={'mode','name','offset','files','records'} or request['mode']!='chunk' or request['files']!=before['files'] or request['records']!=before['records'] or request['name'] not in limits or type(request['offset']) is not int or not 0<=request['offset']<before['files'][request['name']]['bytes']:raise ValueError()
  raw,_=read(directory/request['name'],limits[request['name']]);offset=request['offset'];chunk=raw[offset:offset+8192]
  reply={'state':'chunk','name':request['name'],'offset':offset,'bytes':len(chunk),'data':base64.b64encode(chunk).decode(),'sha256':before['files'][request['name']]['sha256']}
 if census()!=before:raise ValueError()
 print(json.dumps(reply,separators=(',',':')))
except (OSError,ValueError,KeyError,TypeError,UnicodeError):print('{"state":"unknown"}')
'''

def prompt_collect(root:Path|str,correlation_id:str,observation_id:str)->dict[str,Any]:
    """Collect four immutable prompt artifacts through bounded fixed-file chunks."""
    flags={'nativeActionAllowed':False,'productAction':False,'claimsReleased':False}
    if not isinstance(correlation_id,str) or not _UUID.fullmatch(correlation_id):return _reply(correlation_id,'unknown','prompt_collection_invalid',**flags)
    intent=_load(root,correlation_id)
    if intent is None or not isinstance(observation_id,str) or not _UUID.fullmatch(observation_id):return _reply(correlation_id,'unknown','prompt_collection_invalid',**flags)
    paths={};directory=None;local_fingerprints={};local_directory_fd=None
    try:
        config,profile=_route(root,intent)
        def fetch(request):
            argv=ssh_transport.build_ssh_argv(config,'archlinux',60,command=('python3','-I','-B','-c','exec('+repr(_PROMPT_FETCH)+')',intent['fixtureRoot'],correlation_id,observation_id,json.dumps(intent,sort_keys=True,separators=(',',':')),json.dumps(request,sort_keys=True,separators=(',',':'))))
            code,out=android_observation._run_probe(argv,120)
            if code!=0 or len(out)>16384:raise ValueError('bounded transport')
            value=json.loads(out)
            if not isinstance(value,dict):raise ValueError('response')
            return value
        metadata=fetch({'mode':'metadata'})
        if set(metadata)!={'state','files','records'} or metadata['state']!='ready' or not isinstance(metadata['files'],dict) or set(metadata['files'])!=set(_PROMPT_FILES):raise ValueError('metadata')
        files=metadata['files'];records=metadata['records']
        if not isinstance(records,dict) or set(records)!={'intent.json','identity.json','worker.py','result.json','on-intent.json','operation.json'}:raise ValueError('original census')
        for name,m in records.items():
            if not isinstance(m,dict) or set(m)!={'sha256','bytes','fingerprint'} or not isinstance(m['sha256'],str) or not _SHA.fullmatch(m['sha256']) or type(m['bytes']) is not int or not 0<m['bytes']<=(131072 if name=='worker.py' else 8192) or not isinstance(m['fingerprint'],list) or len(m['fingerprint'])!=8 or any(type(v) is not int for v in m['fingerprint']):raise ValueError('original metadata')
        for name,limit in _PROMPT_FILES.items():
            m=files[name]
            if not isinstance(m,dict) or set(m)!={'sha256','bytes','fingerprint'} or not isinstance(m['sha256'],str) or not _SHA.fullmatch(m['sha256']) or type(m['bytes']) is not int or not 0<m['bytes']<=limit or not isinstance(m['fingerprint'],list) or len(m['fingerprint'])!=8 or any(type(v) is not int for v in m['fingerprint']):raise ValueError('file metadata')
        parent=_journal(root,correlation_id).parent;directory=parent/('prompt-'+correlation_id+'-'+observation_id)
        parent_stat=parent.lstat()
        if not stat.S_ISDIR(parent_stat.st_mode) or parent_stat.st_uid!=os.getuid() or stat.S_IMODE(parent_stat.st_mode)!=0o700:raise ValueError('private parent')
        directory.mkdir(mode=0o700)
        parent_info=parent.lstat();directory_info=directory.lstat()
        local_directory_fd=os.open(directory,os.O_RDONLY|getattr(os,'O_DIRECTORY',0)|getattr(os,'O_NOFOLLOW',0))
        def check_parents():
            for path,old in ((parent,parent_info),(directory,directory_info)):
                now=path.lstat()
                if (now.st_dev,now.st_ino,now.st_mode,now.st_uid)!=(old.st_dev,old.st_ino,old.st_mode,old.st_uid):raise ValueError('local parent changed')
            held=os.fstat(local_directory_fd)
            if (held.st_dev,held.st_ino,held.st_mode,held.st_uid)!=(directory_info.st_dev,directory_info.st_ino,directory_info.st_mode,directory_info.st_uid):raise ValueError('local directory descriptor changed')
        check_parents()
        for name,m in files.items():
            check_parents()
            target=directory/name;fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600,dir_fd=local_directory_fd)
            digest=hashlib.sha256();offset=0
            with os.fdopen(fd,'wb') as f:
                while offset<m['bytes']:
                    check_parents()
                    v=fetch({'mode':'chunk','name':name,'offset':offset,'files':files,'records':records})
                    if set(v)!={'state','name','offset','bytes','data','sha256'} or v['state']!='chunk' or v['name']!=name or type(v['offset']) is not int or v['offset']!=offset or v['sha256']!=m['sha256'] or type(v['bytes']) is not int or v['bytes']!=min(8192,m['bytes']-offset) or not isinstance(v['data'],str) or len(v['data'])>10924:raise ValueError('chunk')
                    raw=base64.b64decode(v['data'],validate=True)
                    if len(raw)!=v['bytes']:raise ValueError('chunk size')
                    check_parents()
                    f.write(raw);digest.update(raw);offset+=len(raw)
                f.flush();os.fsync(f.fileno());info=os.fstat(f.fileno())
                if digest.hexdigest()!=m['sha256'] or info.st_size!=m['bytes'] or info.st_nlink!=1 or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600 or _fingerprint(info)!=_fingerprint(target.lstat()):raise ValueError('local bytes')
            paths[name]=str(target);local_fingerprints[name]=_fingerprint(info)
        if fetch({'mode':'metadata'})!=metadata:raise ValueError('final remote census')
        for path,old in ((parent,parent_info),(directory,directory_info)):
            now=path.lstat()
            if (now.st_dev,now.st_ino,now.st_mode,now.st_uid)!=(old.st_dev,old.st_ino,old.st_mode,old.st_uid):raise ValueError('local parent changed')
        for name,path in paths.items():
            fd=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
            with os.fdopen(fd,'rb') as f:
                before=os.fstat(f.fileno());raw=f.read(_PROMPT_FILES[name]+1)
                if _fingerprint(before)!=local_fingerprints[name] or _fingerprint(before)!=_fingerprint(os.fstat(f.fileno())) or _fingerprint(before)!=_fingerprint(Path(path).lstat()) or len(raw)!=files[name]['bytes'] or hashlib.sha256(raw).hexdigest()!=files[name]['sha256']:raise ValueError('final local artifact')
        if _load(root,correlation_id)!=intent:raise ValueError('local original changed')
        receipt={'schema':1,'correlationId':correlation_id,'observationId':observation_id,'files':files,'records':records}
        check_parents()
        fd=os.open('collected.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600,dir_fd=local_directory_fd)
        with os.fdopen(fd,'wb') as f:f.write(json.dumps(receipt,sort_keys=True,separators=(',',':')).encode());f.flush();os.fsync(f.fileno())
        d=os.open(directory,os.O_RDONLY|getattr(os,'O_DIRECTORY',0));os.fsync(d);os.close(d)
        return _reply(correlation_id,'complete',observationId=observation_id,localPaths=paths,**flags)
    except (OSError,RuntimeError,TimeoutError,ValueError,UnicodeError,KeyError,TypeError):return _reply(correlation_id,'unknown','prompt_collection_unknown',observationId=observation_id,**flags)

    finally:
        if local_directory_fd is not None:os.close(local_directory_fd)

# Two full snapshots, four private provenance readers and four extra public reads.
_PROMPT_CLOSE_SECONDS=2*_FULL_SNAPSHOT_SECONDS+4*120+4*135+120
_PROMPT_CLOSE_BRANCH=r'''
 if mode in ('prompt-close','prompt-close-status'):
  if not isinstance(recovery,dict) or set(recovery)!={'schema','kind','correlationId','closureId','observationId','intentSha256'} or recovery['schema']!=1 or recovery['kind']!='prompt-no-effect' or recovery['correlationId']!=correlation or recovery['intentSha256']!=intent_sha or any(not isinstance(recovery[k],str) or re.fullmatch('[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}',recovery[k]) is None for k in ('closureId','observationId')) or recovery['closureId']==correlation:emit('unknown','prompt_closure_invalid')
  def retained_prompt():
   value=json.loads(run(['python3','-I','-B','-c','exec('+repr(PROMPT_FETCH_SOURCE)+')',root,correlation,recovery['observationId'],expected,'{"mode":"metadata"}'],120,16384))
   if set(value)!={'state','files','records'} or value['state']!='ready':emit('unknown','prompt_closure_binding_changed')
   return value
  retained=retained_prompt();context=json.loads(private(base/('android-grant-prompt-'+correlation+'-'+recovery['observationId'])/'operation-observation.json',65536))
  if json.loads(private(job/'result.json'))!={'state':'unknown','result':None,'reason':'prompt_not_owned'}:emit('unknown','prompt_attempt_not_admitted')
  op=json.loads(private(job/'operation.json'));identity=json.loads(private(job/'identity.json',1024));opening=json.loads(private(job/'opening.json',1048576))
  if op!={'operationId':op.get('operationId'),'owner':owner,'revision':revision,'intentSha256':intent_sha} or not isinstance(op.get('operationId'),str) or re.fullmatch('[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}',op['operationId']) is None or json.loads(private(job/'on-intent.json'))!={'owner':owner,'revision':revision,'intentSha256':intent_sha} or set(identity)!={'pid','startTicks'} or any(type(identity[k]) is not int or identity[k]<1 for k in identity):emit('unknown','prompt_attempt_not_admitted')
  historical_entries=context.get('listBefore');closing_entries=context.get('listAfter')
  summary_keys={'controllerId','id','requestId','operation','phase','final','cancellable','completedUnits','totalUnits','code','configurationRevision','restartRequired'}
  if not isinstance(historical_entries,list) or len(historical_entries)!=1 or historical_entries!=closing_entries or not isinstance(historical_entries[0],dict) or set(historical_entries[0])!=summary_keys:emit('unknown','prompt_terminal_not_retained')
  retained_terminal=historical_entries[0]
  if retained_terminal.get('id')!=op['operationId'] or retained_terminal.get('controllerId')!=owner or retained_terminal.get('configurationRevision')!=revision or retained_terminal.get('operation')!='on' or retained_terminal.get('phase')!='failed' or retained_terminal.get('final') is not True or retained_terminal.get('code')!='INTERACTION_REQUIRED':emit('unknown','prompt_terminal_not_retained')
  original_extra={name:{'sha256':hashlib.sha256(private(job/name,1048576)).hexdigest(),'fingerprint':fingerprint((job/name).lstat())} for name in ('opening.json','baseline-source-settings.json')}
  def original_stable():
   if retained_prompt()!=retained:emit('unknown','prompt_closure_binding_changed')
   for name,meta in original_extra.items():
    if hashlib.sha256(private(job/name,1048576)).hexdigest()!=meta['sha256'] or fingerprint((job/name).lstat())!=meta['fingerprint']:emit('unknown','prompt_closure_binding_changed')
   for name in ('tap-intent.json','terminal.json','collected.json'):
    if (job/name).exists() or (job/name).is_symlink():emit('unknown','prompt_attempt_not_admitted')
  original_stable()
  for key in ('statusBefore','statusAfter'):
   value=context.get(key)
   if not isinstance(value,dict) or value.get('controllerId')!=owner or value.get('configurationRevision')!=revision or value.get('operationId')!=op.get('operationId') or value.get('final') is not True or value.get('ok') is not False or value.get('code')!='INTERACTION_REQUIRED':emit('unknown','prompt_terminal_not_retained')
  if context.get('statusBefore')!=context.get('statusAfter'):
   # Read request IDs may differ; all retained semantic terminal fields must agree.
   if {k:context['statusBefore'].get(k) for k in ('controllerId','configurationRevision','operationId','final','ok','code','data','warnings','restartRequired')}!={k:context['statusAfter'].get(k) for k in ('controllerId','configurationRevision','operationId','final','ok','code','data','warnings','restartRequired')}:emit('unknown','prompt_terminal_not_retained')
  try:
   fields=pathlib.Path('/proc/%d/stat'%identity['pid']).read_text().rsplit(')',1)[1].split()
   if int(fields[19])==identity['startTicks'] and fields[0]!='Z':emit('unknown','prompt_worker_live')
  except FileNotFoundError:pass
  except (OSError,ValueError,IndexError):emit('unknown','prompt_worker_unknown')
  env=public_cli_environment(adb,pathlib.Path(cli))
  lock=base/('android-native-device-'+intent['device']+'.lock');lease_fd=os.open(lock,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0));info=os.fstat(lease_fd)
  if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1:emit('unknown','device_lock_unsafe')
  fcntl.flock(lease_fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
  lease=base/('android-native-device-'+intent['device']+'.lease');claim={'owner':'android-consent-grant','host':'archlinux','device':intent['device'],'correlationId':correlation}
  binding_name='prompt-close-'+recovery['closureId']+'.json';marker_name='prompt-close-'+recovery['closureId']+'-closed.json'
  binding={'request':recovery,'retained':retained,'originalExtra':original_extra}
  if mode=='prompt-close':
   if (job/binding_name).exists() or (job/binding_name).is_symlink():emit('unknown','prompt_closure_consumed')
   claim_fd,claim_fingerprint=retain_claim(lease,claim)
   record(binding_name,binding)
  else:
   if json.loads(private(job/binding_name,16384))!=binding:emit('unknown','prompt_closure_binding_changed')
   if not (job/marker_name).exists() or lease.exists() or lease.is_symlink():emit('unknown','prompt_closure_incomplete')
  binding_sha=hashlib.sha256(private(job/binding_name,16384)).hexdigest();binding_fingerprint=fingerprint((job/binding_name).lstat())
  def foreign_history():
   entries=semantic_operations()['operations']
   if any(x.get('controllerId')!=owner or x.get('final') is not True for x in entries):emit('unknown','operations_active')
   for entry in entries:
    if entry.get('id')==op['operationId'] and entry!=retained_terminal:emit('unknown','prompt_terminal_changed')
   return [x for x in entries if x.get('id')!=op['operationId']]
  history=foreign_history()
  current=snapshot('false')
  if current!=opening:emit('unknown','restoration_changed')
  operations=data('operations','list').get('operations')
  if not isinstance(operations,list) or len(operations)>128 or any(not isinstance(x,dict) or x.get('controllerId')!=owner or x.get('final') is not True for x in operations):emit('unknown','operations_active')
  original_entries=[x for x in operations if x.get('id')==op['operationId']]
  if len(original_entries)>1:emit('unknown','operations_invalid')
  if original_entries:
   entry=original_entries[0]
   if entry.get('operation')!='on' or entry.get('phase')!='failed' or entry.get('code')!='INTERACTION_REQUIRED':emit('unknown','prompt_terminal_changed')
   value=public('--controller-id',owner,'operations','status',op['operationId'],allowed=(0,1,2),limit=16384)
   if value.get('operationId')!=op['operationId'] or value.get('final') is not True or value.get('ok') is not False or value.get('code')!='INTERACTION_REQUIRED':emit('unknown','prompt_terminal_changed')
  if snapshot('false')!=opening:emit('unknown','restoration_changed')
  original_stable()
  if foreign_history()!=history:emit('unknown','prompt_history_changed')
  if fingerprint((job/binding_name).lstat())!=binding_fingerprint or hashlib.sha256(private(job/binding_name,16384)).hexdigest()!=binding_sha:emit('unknown','prompt_closure_binding_changed')
  marker={'schema':1,'closureId':recovery['closureId'],'intentSha256':intent_sha,'bindingSha256':binding_sha,'observationId':recovery['observationId'],'snapshotSha256':hashlib.sha256(json.dumps(opening,sort_keys=True,separators=(',',':')).encode()).hexdigest(),'originalOutcome':'unknown','grantObserved':False,'permissionGranted':False,'runtimeStarted':False}
  if mode=='prompt-close':
   if not claim_current(claim_fd,lease,claim_fingerprint):emit('unknown','device_lease_changed')
   record(marker_name,marker)
   original_stable()
   if fingerprint((job/binding_name).lstat())!=binding_fingerprint or hashlib.sha256(private(job/binding_name,16384)).hexdigest()!=binding_sha:emit('unknown','prompt_closure_binding_changed')
   if not claim_current(claim_fd,lease,claim_fingerprint):emit('unknown','device_lease_changed')
   lease.unlink();d=os.open(base,os.O_RDONLY|getattr(os,'O_DIRECTORY',0));os.fsync(d);os.close(d)
  elif json.loads(private(job/marker_name))!=marker:emit('unknown','prompt_closure_binding_changed')
  emit('closed' if mode=='prompt-close' else 'observed',proof=marker,remoteClaimReleased=True)
'''
_PROMPT_CLOSE_SOURCE=_REMOTE.replace("replacement=json.loads(sys.argv[8]) if len(sys.argv)>=9 else None", "recovery=json.loads(sys.argv[8]);replacement=None").replace(" if mode=='status':",_PROMPT_CLOSE_BRANCH+" if mode=='status':",1)
_PROMPT_CLOSE_SOURCE='PROMPT_FETCH_SOURCE='+repr(_PROMPT_FETCH)+'\n'+_PROMPT_CLOSE_SOURCE

def _prompt_close_intent(root,correlation_id,closure_id):
    if not isinstance(closure_id,str) or not _UUID.fullmatch(closure_id) or closure_id==correlation_id:raise ValueError('closure ID')
    return _journal(root,correlation_id).with_suffix('.prompt-close-'+closure_id+'.json')

def _prompt_close_observe(root,intent,payload,mode):
    config,profile=_route(root,intent)
    argv=ssh_transport.build_ssh_argv(config,'archlinux',60,command=('python3','-I','-B','-c','exec('+repr(_PROMPT_CLOSE_SOURCE)+')',mode,profile['adb'],intent['cliPath'],profile['serial'],intent['fixtureRoot'],intent['correlationId'],json.dumps(intent,sort_keys=True,separators=(',',':')),json.dumps(payload,sort_keys=True,separators=(',',':'))))
    code,out=android_observation._run_probe(argv,_PROMPT_CLOSE_SECONDS)
    value=json.loads(out) if code==0 and len(out)<=16384 else None
    if not isinstance(value,dict) or value.get('correlationId')!=intent['correlationId']:raise ValueError('closure observer')
    return value

def _prompt_close_result(root,intent,payload,mode):
    flags={'nativeActionAllowed':False,'productAction':False,'originalOutcome':'unknown','grantObserved':False,'claimsReleased':False}
    value=_prompt_close_observe(root,intent,payload,mode)
    if value.get('state')=='unknown':
        reason=value.get('reason');allowed={'prompt_closure_invalid','prompt_closure_binding_changed','prompt_closure_consumed','prompt_closure_incomplete','prompt_attempt_not_admitted','prompt_terminal_not_retained','prompt_terminal_changed','prompt_history_changed','prompt_worker_live','prompt_worker_unknown','restoration_changed','operations_active','operations_invalid','device_lease_changed','device_lease_unsafe','private_file_unavailable','private_file_changed','private_file_unsafe','private_directory_unsafe','device_changed','package_changed','cli_stage_changed','owner_or_revision_changed','routing_changed','permission_or_runtime_changed','diagnostics_ambiguous','command_failed','command_outcome_unknown'}
        return _reply(intent['correlationId'],'unknown',reason if reason in allowed else 'prompt_closure_unknown',closureId=payload['closureId'],**flags)
    proof=value.get('proof');expected={'schema':1,'closureId':payload['closureId'],'intentSha256':payload['intentSha256'],'observationId':payload['observationId'],'originalOutcome':'unknown','grantObserved':False,'permissionGranted':False,'runtimeStarted':False}
    if value.get('state') not in ('closed','observed') or value.get('remoteClaimReleased') is not True or not isinstance(proof,dict) or set(proof)!=set(expected)|{'bindingSha256','snapshotSha256'} or any(type(proof.get(k)) is not type(v) or proof.get(k)!=v for k,v in expected.items()) or any(not isinstance(proof[k],str) or not _SHA.fullmatch(proof[k]) for k in ('bindingSha256','snapshotSha256')):raise ValueError('closure proof')
    return _reply(intent['correlationId'],value['state'],closureId=payload['closureId'],proof=proof,remoteClaimReleased=True,**flags)

def prompt_close_no_effect(root:Path|str,correlation_id:str,closure_id:str,observation_id:str)->dict[str,Any]:
    """One explicit closure of retained failed interaction; never ON or UI actions."""
    flags={'nativeActionAllowed':False,'productAction':False,'claimsReleased':False,'originalOutcome':'unknown','grantObserved':False}
    try:
        intent=_load(root,correlation_id);path=_prompt_close_intent(root,correlation_id,closure_id)
        if intent is None or not isinstance(observation_id,str) or not _UUID.fullmatch(observation_id):raise ValueError('closure admission')
        if path.exists() or path.is_symlink():return prompt_close_no_effect_status(root,correlation_id,closure_id)
        payload={'schema':1,'kind':'prompt-no-effect','correlationId':correlation_id,'closureId':closure_id,'observationId':observation_id,'intentSha256':hashlib.sha256(json.dumps(intent,sort_keys=True,separators=(',',':')).encode()).hexdigest()}
        with android_endpoint_admission._shared_device_lease(Path(root).resolve(),'archlinux',intent['device']) as lease,android_document_acceptance._device_guard(root,'archlinux',intent['device']) as document_lease:
            retained=[]
            try:
                for target,value in ((lease,_claim(correlation_id,intent['device'])),(document_lease,{'host':'archlinux','device':intent['device'],'correlationId':correlation_id})):
                    fd,fp=_retain_claim(target,value);retained.append((fd,target,fp))
                _write_closed_marker(path,payload)
                fd,fp=_retain_claim(path,payload,4096);retained.append((fd,path,fp))
                result=_prompt_close_result(root,intent,payload,'prompt-close')
                if _load(root,correlation_id)!=intent or any(not _claim_current(fd,target,fp) for fd,target,fp in retained):raise ValueError('local drift')
                return result
            finally:
                for fd,_,_ in retained:os.close(fd)
    except (OSError,RuntimeError,TimeoutError,ValueError,UnicodeError,KeyError,TypeError):return _reply(correlation_id,'unknown','prompt_closure_unknown',closureId=closure_id,**flags)

def prompt_close_no_effect_status(root:Path|str,correlation_id:str,closure_id:str)->dict[str,Any]:
    try:
        intent=_load(root,correlation_id);payload=_closed_marker(_prompt_close_intent(root,correlation_id,closure_id))
        if intent is None or payload.get('correlationId')!=correlation_id or payload.get('closureId')!=closure_id:raise ValueError('intent')
        return _prompt_close_result(root,intent,payload,'prompt-close-status')
    except (OSError,RuntimeError,TimeoutError,ValueError,UnicodeError,KeyError,TypeError):return _reply(correlation_id,'unknown','prompt_closure_unknown',closureId=closure_id,nativeActionAllowed=False,productAction=False,claimsReleased=False,originalOutcome='unknown',grantObserved=False)

def prompt_close_no_effect_collect(root:Path|str,correlation_id:str,closure_id:str)->dict[str,Any]:
    flags={'nativeActionAllowed':False,'productAction':False,'claimsReleased':False,'originalOutcome':'unknown','grantObserved':False}
    try:
        intent=_load(root,correlation_id);path=_prompt_close_intent(root,correlation_id,closure_id);payload=_closed_marker(path);marker_path=path.with_suffix('.closed.json')
        if intent is None:raise ValueError('intent')
        with android_endpoint_admission._shared_device_lease(Path(root).resolve(),'archlinux',intent['device']) as lease,android_document_acceptance._device_guard(root,'archlinux',intent['device']) as document_lease:
            intent_fp=_fingerprint(path.lstat())
            retained={};historical={};marker=_closed_marker(marker_path) if marker_path.exists() or marker_path.is_symlink() else None
            try:
                for key,target,value,limit in (('original',_journal(root,correlation_id),intent,8192),('child',path,payload,4096)):
                    fd,fp=_retain_claim(target,value,limit);historical[key]=(fd,fp,target)
                if historical['child'][1]!=intent_fp:raise ValueError('intent admission drift')
                if marker is not None:
                    fd,fp=_retain_claim(marker_path,marker,4096);historical['marker']=(fd,fp,marker_path)
                def history_current():
                    if any(not _claim_current(fd,target,fp) for fd,fp,target in historical.values()):raise ValueError('historical generation drift')
                for key,target,value in (('shared',lease,_claim(correlation_id,intent['device'])),('document',document_lease,{'host':'archlinux','device':intent['device'],'correlationId':correlation_id})):
                    if target.exists() or target.is_symlink():retained[key]=(*_retain_claim(target,value),target)
                    elif marker is None:raise ValueError('missing claim')
                result=_prompt_close_result(root,intent,payload,'prompt-close-status')
                if result['state']!='observed':return result
                binding={'schema':1,'payload':payload,'proof':result['proof'],'leases':marker['leases'] if marker is not None else {k:v[1] for k,v in retained.items()}}
                if marker is not None and marker!=binding:raise ValueError('marker drift')
                if _load(root,correlation_id)!=intent or _closed_marker(path)!=payload or _fingerprint(path.lstat())!=intent_fp or any(not _claim_current(fd,target,fp) or binding['leases'].get(key)!=fp for key,(fd,fp,target) in retained.items()):raise ValueError('claim drift')
                if marker is None:
                    created=_write_closed_marker(marker_path,binding)
                    fd,fp=_retain_claim(marker_path,binding,4096);historical['marker']=(fd,fp,marker_path)
                    if created!=fp:raise ValueError('new marker generation drift')
                history_current()
                for fd,fp,target in retained.values():
                    history_current()
                    if not _claim_current(fd,target,fp):raise ValueError('claim drift')
                    target.unlink();d=os.open(target.parent,os.O_RDONLY|getattr(os,'O_DIRECTORY',0));os.fsync(d);os.close(d)
                history_current()
                return {**result,'state':'closed','ok':True,'claimsReleased':True}
            finally:
                for fd,_,_ in (*retained.values(),*historical.values()):os.close(fd)
    except (OSError,RuntimeError,TimeoutError,ValueError,UnicodeError,KeyError,TypeError):return _reply(correlation_id,'unknown','prompt_closure_unknown',closureId=closure_id,**flags)
