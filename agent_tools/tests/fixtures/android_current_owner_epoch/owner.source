"""Fresh API35 read-only owner admission; no installer or runtime authority.

The frozen bundle supplies all native readers and private receipt primitives.
Only positive fresh envelopes can establish an epoch; CONFLICT never does.
"""
from __future__ import annotations
import ast,hashlib,json,re
from pathlib import Path
from . import android_installer_component_bundle as bundle
from . import android_component_command_transport as command
from . import android_device_availability as availability
BUNDLE_SHA='6d2ff26ae551d1d7c3b2b7ba7428b02fdd1e28e91beb760a4a4ee12de7738a85'
COMMAND_SHA='cd241219e689ae6fd925ccfb05ae140d86ac0d4818cdcc0de84043b01617a367'
OLD_OWNER='58d546ea-8208-40a3-bba4-e8759768284e'
_KEYS={'host','device','correlationId','sourceSha','expectedAvd','expectedApi','packageSha256','reservation'}
_REMOTE=r'''
def owner_admission_package_uid(package,process_uid):
 # Fixed primary Android user only: appId and legacy userId both map directly
 # to the observed user-0 process UID. No cross-user arithmetic or fallback.
 if type(package)is not str or type(process_uid)is not int or not 10000<=process_uid<100000:raise ValueError('owner_admission_app_uid_changed')
 lines=package.splitlines();headers=[i for i,line in enumerate(lines) if line.startswith('  Package [')]
 if len(headers)!=1 or re.fullmatch(r'  Package \[com\.kardinal\.vpncontrol\] \([0-9a-f]+\):',lines[headers[0]])is None or headers[0]==0 or lines[headers[0]-1]!='Packages:':raise ValueError('owner_admission_package_block_unknown')
 block=[]
 for line in lines[headers[0]+1:]:
  if line.strip() and len(line)-len(line.lstrip())<=2:break
  block.append(line)
 text='\n'.join(block)
 identities=re.findall(r'(?m)^    (appId|userId)=([0-9]+)$',text)
 identity_lines=[line for line in block if re.match(r'\s*(?:appId|userId)\s*=',line)]
 users=[line for line in block if re.match(r'    User [0-9]+:',line)]
 if len(identities)!=1 or len(identity_lines)!=1 or int(identities[0][1])!=process_uid or len(users)!=1 or not users[0].startswith('    User 0: ') or [token for token in users[0].split()[2:] if token.startswith('installed=')]!=['installed=true']:raise ValueError('owner_admission_app_uid_changed')
 versions=re.findall(r'(?m)^    versionName=(\S+)$',text);codes=re.findall(r'(?m)^    versionCode=([0-9]+)(?:\s.*)?$',text)
 if versions!=['2.2.2'] or codes!=['16840'] or 'DEBUGGABLE'in text:raise ValueError('owner_admission_package_version_changed')
 return process_uid

def owner_admission_ledger(value,owner,revision):
 # AndroidSettingsControl.operationSummary, ControlOperation terminal invariants.
 keys={'controllerId','id','requestId','operation','phase','final','cancellable','completedUnits','totalUnits','code','configurationRevision','restartRequired'}
 operations={'on','off','status','restart','find-best','source.show','source.set','subscriptions.list','subscriptions.show','subscriptions.add','subscriptions.update','subscriptions.delete','subscriptions.refresh','locations.list','locations.show','locations.add','locations.update','locations.delete','locations.select','locations.benchmark','locations.import','locations.export','routing.show','routing.set','routing.import','routing.export','routing.apps.list','routing.apps.set','routing.apps.add','routing.apps.remove','routing.apps.select-all','routing.apps.clear','settings.show','settings.set','settings.apply','settings.languages','ssh.key.status','ssh.key.import','stats','logs','diagnostics.export','operations.list','operations.status','operations.wait','operations.cancel','updates.status','updates.check','updates.transport-probe','updates.download','updates.install','updates.cancel','updates.dismiss','serve','gui.show','gui.hide','quit','capabilities'}
 failures={'INVALID_ARGUMENT','NOT_FOUND','AMBIGUOUS_LOCATION','READ_ONLY_SOURCE','BUSY','CONFLICT','UNSUPPORTED','INTERACTION_REQUIRED','PERMISSION_DENIED','PERSISTENCE_FAILED','RUNTIME_FAILED','CANCELLED','TIMEOUT','OUTCOME_UNKNOWN','UNAVAILABLE','INCOMPATIBLE_PROTOCOL'}
 if type(value)is not dict or set(value)!={'scope','operations'} or value['scope']!='android-provider-operations' or type(value['operations'])is not list or len(value['operations'])>256:raise ValueError('owner_admission_ledger_unknown')
 ids=set();requests=set()
 for row in value['operations']:
  if type(row)is not dict or set(row)!=keys or row['controllerId']!=owner or type(row['id'])is not str or re.fullmatch('[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}',row['id'])is None or type(row['requestId'])is not str or not row['requestId'].strip() or type(row['operation'])is not str or row['operation']not in operations or row['final']is not True or row['cancellable']is not False or type(row['configurationRevision'])is not int or not 0<=row['configurationRevision']<=revision or type(row['restartRequired'])is not bool:raise ValueError('owner_admission_ledger_row_unknown')
  if row['id']in ids or row['requestId']in requests:raise ValueError('owner_admission_ledger_duplicate')
  ids.add(row['id']);requests.add(row['requestId'])
  if type(row['phase'])is not str or type(row['code'])is not str or not ((row['phase']=='succeeded' and row['code']=='OK') or (row['phase']=='cancelled' and row['code']=='CANCELLED') or (row['phase']=='failed' and row['code']in failures)):raise ValueError('owner_admission_ledger_terminal_unknown')
  for key in ('completedUnits','totalUnits'):
   if row[key]is not None and (type(row[key])is not int or not 0<=row[key]<=2**63-1):raise ValueError('owner_admission_ledger_progress_unknown')
  if row['completedUnits']is not None and row['totalUnits']is not None and row['completedUnits']>row['totalUnits']:raise ValueError('owner_admission_ledger_progress_unknown')

class OwnerAdmissionGuard(COMPONENT_BUNDLE.BaselineGuard):
 def __init__(self,receipt,selected,backend,request):
  b=COMPONENT_BUNDLE
  if type(request)is not dict or set(request)!=OWNER_ADMISSION_KEYS or request['host']!='archlinux' or request['device']!='android-api35' or type(request['expectedApi'])is not int or request['expectedApi']!=35 or request['sourceSha']!=b._PRODUCT_SHA or type(request['correlationId'])is not str or not re.fullmatch('[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}',request['correlationId']) or type(request['reservation'])is not dict or not request['reservation']:raise ValueError('owner_admission_request_unknown')
  self.receipt=copy.deepcopy(receipt);self.modules=selected;self.backend=backend;self.request=copy.deepcopy(request)
  b._selected_modules(receipt,selected)
  self.context_device=b._context_device(backend,request['device'],35,request['expectedAvd'],'emulator-5682',backend['GETTER']['cli'],request['packageSha256'])
  self.function_pins=b._guard_backend(selected,backend,self.context_device)
  self.phase='current-owner-read-only';self.sequence=0;self.expected=None
  if backend['LAUNCH']['intent']['reservation']!=request['reservation']:raise ValueError('owner_admission_reservation_changed')
  output=Path(backend['ROOT'])/('android-installer-component-baseline-'+request['correlationId'])
  b._new_directory(output,receiver_root=Path(backend['ROOT']))
  output=output/'current-owner-admission';b._new_directory(output)
  self.args=types.SimpleNamespace(output=output,serial='emulator-5682',cli=Path(backend['GETTER']['cli']))
  self.measurement={'avd':request['expectedAvd'],'api':35,'packageSha256':request['packageSha256']}
  self.host=backend['command_host_identity']();backend['command_host_guard']();self.stage=copy.deepcopy(backend['getter_stage']())
  self.expected=self._physical();self.app=self._app_process();self.version=self._version()
  package=self._text(['shell','-T','dumpsys','package','com.kardinal.vpncontrol'])
  if 'versionName=2.2.2' not in package or 'versionCode=16840' not in package or 'DEBUGGABLE' in package:raise ValueError('owner_admission_package_version_changed')
  owner_admission_package_uid(package,self.app['uid'])
  self.owner,self.revision=self._fresh_owner(self.expected,request['packageSha256'])
  if self.revision!=0:raise ValueError('owner_admission_revision_changed')
  settings=[];operations=[];statuses=[]
  for unused in range(2):
   statuses.append(self._fresh_reply(['status'],self.owner,self.expected,request['packageSha256']))
   operation=self._fresh_reply(['operations','list'],self.owner,self.expected,request['packageSha256']);operations.append(operation['data'])
   owner_admission_ledger(operation['data'],self.owner,self.revision)
   settings.append(self._settings())
  if statuses[0]['data']!=statuses[1]['data'] or any(item['configurationRevision']!=self.revision or item['data'].get('runtimeRunning')is not False or item['data'].get('runtimeObservation')!='stopped' for item in statuses) or settings[0]!=settings[1] or operations[0]!=operations[1] or type(operations[0].get('operations'))is not list or any(type(row)is not dict or row.get('final')is not True for row in operations[0]['operations']):raise ValueError('owner_admission_public_unstable')
  if self._app_process()!=self.app or self._physical()!=self.expected or backend['getter_stage']()!=self.stage:raise ValueError('owner_admission_process_changed')
  self.settings=settings[0];self.operations=operations[0];self.status=statuses[-1]['data']
  response_pins={str(path.name):b._read(path,True)[1] for path in sorted(output.iterdir())}
  self.certificate={'responsePins':response_pins,'bundleReceipt':copy.deepcopy(receipt),'backendBinding':copy.deepcopy(backend['EXTERNAL']),'environmentSha256':hashlib.sha256(b._raw(backend['LAUNCH']['environment'])).hexdigest(),'commandSourceSha256':backend['COMMAND_SOURCE_SHA'],'schema':1,'kind':'api35-current-owner-read-only-admission','sourceSha256':OWNER_ADMISSION_SOURCE_SHA,'request':copy.deepcopy(request),'controllerId':self.owner,'configurationRevision':self.revision,'facts':copy.deepcopy(self.expected),'appProcess':copy.deepcopy(self.app),'stage':copy.deepcopy(self.stage),'host':copy.deepcopy(self.host),'cliVersion':self.version,'installedPackageDump':package,'settings':self.settings,'operations':self.operations,'status':self.status,'componentRuntime':'EXTERNAL_JDK','installedLauncherAccepted':False,'bundledRuntimeAccepted':False,'installerLeaseGranted':False,'guestMutationPerformed':False,'acceptanceComplete':False,'replayAllowed':False}
  for name,pin in response_pins.items():
   if b._read(output/name,True)[1]!=pin:raise ValueError('owner_admission_response_changed')
  path=output/'admission.json';b._write(path,b._raw(self.certificate));self.certificatePin=b._read(path,True)[1]
  for name,pin in response_pins.items():
   if b._read(output/name,True)[1]!=pin:raise ValueError('owner_admission_response_changed')
 def _physical(self):
  if hasattr(self,'batch_admission'):raise ValueError('owner_admission_batch_disabled')
  facts=super()._physical();original=self.backend['GETTER']['generation'].get('device')
  keys=('sdk','abi','kernelAvd','bootAvd','bootCompleted','shellUid','guestBootId')
  if type(original)is not dict or original.get('matched')is not True or any(type(original.get(key))is not str or original[key]!=facts[key] for key in keys):raise ValueError('owner_admission_original_guest_changed')
  return facts
 def enable_physical_batch(self):
  raise ValueError('owner_admission_batch_disabled')
 def _candidate_physical(self,sha):
  if sha!=self.request['packageSha256']:raise ValueError('owner_admission_package_changed')
  return self._physical()
 def _evidence(self,name,value):
  COMPONENT_BUNDLE._write(self.args.output/('read-'+name+'.json'),COMPONENT_BUNDLE._raw({'sourceSha256':OWNER_ADMISSION_SOURCE_SHA,'request':self.request,'record':copy.deepcopy(value),'guestMutationPerformed':False,'replayAllowed':False}))
 def _app_process(self):
  raw=self._text(['shell','-T','pidof','com.kardinal.vpncontrol'])
  if not re.fullmatch('[1-9][0-9]*',raw):raise ValueError('owner_admission_app_process_unknown')
  pid=int(raw);table=self._text(['shell','-T','ps','-A','-o','PID,UID,NAME']);rows=table.splitlines()
  if not rows or rows[0].split()!=['PID','UID','NAME']:raise ValueError('owner_admission_app_census_unknown')
  found=[];pids=set()
  for line in rows[1:]:
   fields=line.split()
   if len(fields)!=3 or not fields[0].isdigit() or not fields[1].isdigit() or int(fields[0])in pids:raise ValueError('owner_admission_app_census_unknown')
   pids.add(int(fields[0]))
   if fields[2]=='com.kardinal.vpncontrol':found.append((int(fields[0]),int(fields[1])))
  if len(found)!=1 or found[0][0]!=pid or found[0][1]<10000:raise ValueError('owner_admission_app_process_unknown')
  rawstat=self._text(['shell','-T','cat','/proc/'+str(pid)+'/stat']);match=re.fullmatch(str(pid)+r' \(([^()\r\n]+)\) (.+)',rawstat)
  if match is None:raise ValueError('owner_admission_app_stat_unknown')
  fields=match[2].split()
  if len(fields)<20 or not fields[19].isdigit() or int(fields[19])<=0:raise ValueError('owner_admission_app_stat_unknown')
  return {'pid':pid,'uid':found[0][1],'name':'com.kardinal.vpncontrol','comm':match[1],'startTicks':int(fields[19]),'guestBootId':self.expected['guestBootId']}
 def _version(self):
  backend=self.backend;jdk=backend['EXTERNAL']['selectedJdk'];appdir=str(Path(backend['GETTER']['cli']).parent.parent/'lib/app')
  args=[*[option.replace('$APPDIR',appdir) for option in backend['EXTERNAL']['javaOptions']],'-cp',':'.join(appdir+'/'+name for name in backend['EXTERNAL']['classpath']),'com.kardinal.vpncontrol.desktop.MainKt','--version'];records=backend['GETTER_RECORDS'];isolated={};result=None
  backend['GETTER_RECORDS']=isolated
  try:
   backend['external_jdk_guard']();self._physical()
   environment=self.modules['tls'].public_cli_environment(backend['LAUNCH']['adbPath'],Path(backend['GETTER']['cli']),backend['LAUNCH']['environment'])
   result=backend['command_binary'](Path(jdk['root'])/'bin/java',jdk['files']['bin/java']['generation'],args,environment,limit=16384,timeout=30)
  finally:
   backend['GETTER_RECORDS']=records;self._capture({'versionResult':result,'captures':isolated.get('captures',[])})
   backend['external_jdk_guard']();self._physical()
  if type(result)is not dict or type(result.get('returncode'))is not int or result['returncode']!=0 or result.get('stdoutRaw')!='2.2.2\n' or result.get('stderrRaw')!='' or len(isolated.get('captures',[]))!=1 or isolated['captures'][0].get('failure')is not None or type(isolated['captures'][0].get('returncode'))is not int or isolated['captures'][0]['returncode']!=0 or isolated['captures'][0].get('stdoutBase64')!=base64.b64encode(b'2.2.2\n').decode() or isolated['captures'][0].get('stderrBase64')!='' or type(isolated['captures'][0].get('stdoutBytes'))is not int or isolated['captures'][0]['stdoutBytes']!=6 or type(isolated['captures'][0].get('stderrBytes'))is not int or isolated['captures'][0]['stderrBytes']!=0:raise ValueError('owner_admission_cli_version_unknown')
  return '2.2.2'
 def _settings(self):
  result=self.backend['component_command'](['settings','show'],self.owner,self.revision,'baseline',self._physical,self._capture);value=result.get('stdout')
  if type(value)is not dict or value.get('ok')is not True or value.get('final')is not True or value.get('code')!='OK' or value.get('controllerId')!=self.owner or type(value.get('configurationRevision'))is not int or value['configurationRevision']!=self.revision or type(value.get('data'))is not dict:raise ValueError('owner_admission_settings_unknown')
  return value['data']

def owner_admission_run(receipt,backend,request):
 selected=COMPONENT_BUNDLE.modules(receipt);guard=OwnerAdmissionGuard.__new__(OwnerAdmissionGuard)
 try:guard.__init__(receipt,selected,backend,request)
 except BaseException:
  if hasattr(guard,'args'):
   closing={'physicalVerified':False,'appProcessVerified':False,'admissionGranted':False}
   try:
    if guard.expected is not None:closing['physicalVerified']=guard._physical()==guard.expected
   except Exception:pass
   try:
    if hasattr(guard,'app'):closing['appProcessVerified']=guard._app_process()==guard.app
   except Exception:pass
   guard._evidence('failed-closing',closing)
  raise
 return {'state':'api35-current-owner-admitted','controllerId':guard.owner,'configurationRevision':guard.revision,'certificatePath':str(guard.args.output/'admission.json'),'certificatePin':guard.certificatePin,'componentRuntime':'EXTERNAL_JDK','installerLeaseGranted':False,'guestMutationPerformed':False,'acceptanceComplete':False,'replayAllowed':False}
'''

def prepare_source(receipt:dict,prepared:dict,request:dict)->str:
 """Local source assembly only; the sole operator executes the reviewed result."""
 if type(request)is not dict or set(request)!=_KEYS or request.get('device')!='android-api35' or type(request.get('expectedApi'))is not int or request['expectedApi']!=35:raise ValueError('owner_admission_request_unknown')
 for module,sha in ((bundle,BUNDLE_SHA),(command,COMMAND_SHA)):
  snapshot=availability._snapshot(Path(module.__file__).absolute())
  if hashlib.sha256(snapshot[1]).hexdigest()!=sha:raise ValueError('owner_admission_source_changed')
  prepared['snapshots'][Path(module.__file__).absolute()]=snapshot
 getter=command.readonly._assignment(ast.parse(prepared['program']),'GETTER');launch=command.readonly._assignment(ast.parse(prepared['program']),'LAUNCH')
 if request.get('host')!='archlinux' or request.get('sourceSha')!=bundle._PRODUCT_SHA or request.get('packageSha256')!=getter['packageSha256'] or request.get('expectedAvd')!=launch['avd'] or request.get('reservation')!=launch['intent']['reservation'] or launch.get('device')!='api35':raise ValueError('owner_admission_request_unknown')
 own=Path(__file__).absolute();snap=availability._snapshot(own);prepared['snapshots'][own]=snap
 source=bundle.carrier_source(receipt,prepared,request['correlationId'])
 template=command.readonly._assignment(ast.parse(snap[1]),'_REMOTE')
 suffix='\ncopy=__import__("copy")\ntypes=__import__("types")\nre=__import__("re")\nbase64=__import__("base64")\nPath=__import__("pathlib").Path\nOWNER_ADMISSION_KEYS='+repr(_KEYS)+'\nOWNER_ADMISSION_SOURCE_SHA='+repr(hashlib.sha256(snap[1]).hexdigest())+'\n'+template+'\nOWNER_ADMISSION_RESULT=owner_admission_run(COMPONENT_RECEIPT,globals(),'+repr(request)+')\n'
 result=source+suffix;compile(result,'<fixed-api35-current-owner-admission>','exec');command.readonly.guard(prepared);return result
