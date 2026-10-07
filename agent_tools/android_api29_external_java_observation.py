"""Fixed external-JDK Android component comparison; not package acceptance.

Census never executes Java. Comparison accepts only the retained, source-bound
inventory of two fixed distro JDK candidates and the complete current CLI stage.
"""
from __future__ import annotations
import ast
import hashlib
import json
from pathlib import Path
import re
from . import android_api29_current_owner_observation as original
from . import android_device_availability as availability
ORIGINAL_SHA='3fdf093cb5bd0228722cf8472c545566637a4e4522dc9918db9091a7a56122c7'
CONFIG_SHA='b2ec931d6c46cd49c596e5d446da6d76637522ccaf90d5b9bfb0ef00f78288f3'
BASELINE='.runtime/parity-evidence/android-api29-current-owner-40925770-7ccc-448f-8f93-699c3d19e5ca/result-0.private'
BASELINE_SHA='e929a642100614997d18f65fbddaecb2a3642d558b30149b3b4f4ee007f99884'
CENSUS='.runtime/parity-evidence/android-api29-external-java-census/result.json'
CANDIDATES={'jdk17':'/usr/lib/jvm/java-17-openjdk','jdk21':'/usr/lib/jvm/java-21-openjdk'}
JDK_FILES=('bin/java','release','lib/libjli.so','lib/server/libjvm.so','lib/libjava.so','lib/modules')
_REMOTE=r'''
EXTERNAL=__EXTERNAL__
def external_file(path,limit):
 chain,name=parent_fds(pathlib.Path(path));fd=None
 try:
  guard_parents(chain);fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=chain[-1]['fd']);generation=fp(os.fstat(fd))
  if fp(os.stat(name,dir_fd=chain[-1]['fd'],follow_symlinks=False))!=generation or generation[6:9]!=[0,0,1] or not stat.S_ISREG(generation[5]) or generation[5]&0o022 or not 0<generation[2]<=limit:raise ValueError('external_jdk_file_unsafe')
  if path.endswith('/bin/java') and not generation[5]&0o111:raise ValueError('external_jdk_not_executable')
  digest=hashlib.sha256();count=0;raw=b''
  while count<generation[2]:
   part=os.read(fd,min(65536,generation[2]-count))
   if not part:raise ValueError('external_jdk_short_read')
   count+=len(part);digest.update(part)
   if path.endswith('/release'):
    if count>65536:raise ValueError('external_jdk_release_unbounded')
    raw+=part
  guard_parents(chain)
  if fp(os.fstat(fd))!=generation or fp(os.stat(name,dir_fd=chain[-1]['fd'],follow_symlinks=False))!=generation:raise ValueError('external_jdk_generation_changed')
  return {'generation':generation,'bytesRead':count,'sha256':digest.hexdigest(),'hashScope':'full'},raw
 finally:
  if fd is not None:os.close(fd)
  close_parents(chain)

def external_jdk(alias):
 if alias not in EXTERNAL['candidates']:raise ValueError('external_jdk_alias_required')
 root=EXTERNAL['candidates'][alias];facts={};release=None
 for relative in EXTERNAL['jdkFiles']:
  fact,raw=external_file(root+'/'+relative,268435456 if relative=='lib/modules' else 67108864);facts[relative]=fact
  if relative=='release':
   if len(raw)>65536:raise ValueError('external_jdk_release_unbounded')
   text=raw.decode('utf-8','strict');versions=re.findall(r'^JAVA_VERSION="([^"\r\n]+)"$',text,re.M)
   if len(versions)!=1 or not re.fullmatch(r'(?:17|21)\.[0-9]+\.[0-9]+(?:\.[0-9]+)?(?:\+[0-9A-Za-z_.-]+)?',versions[0]) or int(versions[0].split('.')[0])!=int(alias[3:]):raise ValueError('external_jdk_version_unknown')
   release=versions[0]
 # Re-read the complete fixed runtime inputs, not only the Java executable.
 for relative in EXTERNAL['jdkFiles']:
  again,_=external_file(root+'/'+relative,268435456 if relative=='lib/modules' else 67108864)
  if facts[relative]!=again:raise ValueError('external_jdk_generation_changed')
 return {'state':'observed','alias':alias,'root':root,'declaredJavaVersion':release,'files':facts}

def external_census():
 result={}
 for alias in EXTERNAL['candidates']:
  try:result[alias]=external_jdk(alias)
  except (OSError,ValueError,UnicodeError) as error:result[alias]={'state':'unknown','reason':str(error) if isinstance(error,ValueError) and re.fullmatch(r'external_[a-z_]{1,72}',str(error)) else 'external_jdk_unavailable'}
 return result

def external_jdk_guard():
 expected=EXTERNAL['selectedJdk']
 if expected is None or external_jdk(expected['alias'])!=expected:raise ValueError('external_jdk_generation_changed')

def external_cli(words,owner=None):
 if words not in (['--version'],['status'],['operations','list']):raise ValueError('external_fixed_command_required')
 if owner is not None and (not isinstance(owner,str) or not re.fullmatch('[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}',owner)):raise ValueError('external_owner_invalid')
 jdk=EXTERNAL['selectedJdk'];path=pathlib.Path(jdk['root'])/'bin/java';appdir=str(pathlib.Path(GETTER['cli']).parent.parent/'lib/app')
 options=[option.replace('$APPDIR',appdir) for option in EXTERNAL['javaOptions']]
 classpath=':'.join(appdir+'/'+name for name in EXTERNAL['classpath'])
 args=[*options,'-cp',classpath,'com.kardinal.vpncontrol.desktop.MainKt']
 if words==['--version']:args+=words
 else:args+=['--json','--android','--serial','emulator-5684','--timeout-seconds','30',*(['--controller-id',owner] if owner else []),*words]
 if set(LAUNCH['environment'])!={'ANDROID_AVD_HOME','ANDROID_HOME','ANDROID_SDK_ROOT','HOME','LOGNAME','PATH','USER'}:raise ValueError('external_fixed_environment_required')
 environment=public_cli_environment(LAUNCH['adbPath'],pathlib.Path(GETTER['cli']),LAUNCH['environment'])
 result=getter_binary(path,jdk['files']['bin/java']['generation'],args,environment,limit=1048576)
 if words==['--version']:
  if type(result['returncode'])is not int or result['returncode']!=0 or result['stdoutRaw']!='2.2.2\n' or result['stderrRaw']!='':raise ValueError('external_product_version_failed')
 else:
  try:result['stdout']=json.loads(result['stdoutRaw'])
  except (ValueError,TypeError):result['stdout']=None
 return result

def observed_getter(directory):
 global GETTER_RECORDS
 GETTER_RECORDS={};stage=[];failure=None;closing=False;inventory=None;owner=None;revision=None;ledger=None;stable=False;jdk_closed=False
 try:
  stage.append(getter_stage());getter_generation(directory)
  if getter_apk()!=GETTER['packageSha256']:raise ValueError('getter_package_changed')
  if EXTERNAL['action']=='census':
   inventory=external_census();stable=any(item.get('state')=='observed' for item in inventory.values())
  else:
   try:
    external_jdk_guard();GETTER_RECORDS['productVersion']=external_cli(['--version'])
    GETTER_RECORDS['statusDiscovery']=external_cli(['status']);first=owner_status(GETTER_RECORDS['statusDiscovery']);owner=first['controllerId'];revision=first['configurationRevision']
    GETTER_RECORDS['operationsBefore']=external_cli(['operations','list'],owner);ledger=owner_operations(GETTER_RECORDS['operationsBefore'],owner,revision)
    GETTER_RECORDS['statusPinned']=external_cli(['status'],owner);second=owner_status(GETTER_RECORDS['statusPinned'],owner,revision)
    GETTER_RECORDS['operationsAfter']=external_cli(['operations','list'],owner);after=owner_operations(GETTER_RECORDS['operationsAfter'],owner,revision)
    GETTER_RECORDS['statusFinal']=external_cli(['status'],owner);last=owner_status(GETTER_RECORDS['statusFinal'],owner,revision)
    if first['data']!=second['data'] or second['data']!=last['data']:raise ValueError('owner_status_changed')
    if ledger!=after:raise ValueError('owner_ledger_changed')
    stable=True
   except (ValueError,OSError,KeyError,TypeError,UnicodeError,subprocess.TimeoutExpired) as error:failure=str(error) if isinstance(error,ValueError) and re.fullmatch(r'(?:external|owner|permission|getter)_[a-z_]{1,72}',str(error)) else 'external_read_unknown'
   try:external_jdk_guard();jdk_closed=True
   except (ValueError,OSError,KeyError,TypeError,UnicodeError) as error:failure=str(error) if isinstance(error,ValueError) and re.fullmatch(r'external_[a-z_]{1,72}',str(error)) else 'external_jdk_closing_unknown'
  if getter_apk()!=GETTER['packageSha256']:raise ValueError('getter_package_changed')
  getter_generation(directory);stage.append(getter_stage())
  if stage[0]!=stage[1]:raise ValueError('getter_stage_generation_changed')
  closing=True
 except (ValueError,OSError,KeyError,TypeError,UnicodeError,subprocess.TimeoutExpired) as error:failure=str(error) if isinstance(error,ValueError) and re.fullmatch(r'(?:external|owner|permission|getter|coldboot|census|alias)_[a-z_]{1,72}',str(error)) else 'external_guard_rejected'
 admitted=failure is None and closing and stable and (EXTERNAL['action']=='census' or jdk_closed)
 return {'state':'external-jdk-census' if admitted and EXTERNAL['action']=='census' else 'external-jdk-component-observed' if admitted else 'diagnostic-only','reason':failure,'componentRuntime':'EXTERNAL_JDK','censusComplete':admitted and EXTERNAL['action']=='census','componentFlowObserved':admitted and EXTERNAL['action']=='compare','sourceSha256':EXTERNAL['sourceSha256'],'originalSourceSha256':EXTERNAL['originalSourceSha256'],'baselineSha256':EXTERNAL['baselineSha256'],'candidates':inventory,'selectedJdk':EXTERNAL['selectedJdk'],'generation':GETTER['generation'],'stageId':GETTER['stageId'],'packageSha256':GETTER['packageSha256'],'controllerId':owner,'configurationRevision':revision,'operations':ledger,'ledgerEmpty':admitted and ledger==[],'closingGuardsVerified':closing,'jdkClosingGuardsVerified':jdk_closed,'records':GETTER_RECORDS,'cliStagePins':stage,'permissionObserved':False,'exportSubmitted':False,'installedLauncherAccepted':False,'bundledRuntimeAccepted':False,'endpointAdmitted':False,'productAdmitted':False,'acceptanceComplete':False,'replayAllowed':False,'historicalUnknownsPreserved':True}
'''

def _configuration(raw,manifest):
 if hashlib.sha256(raw).hexdigest()!=CONFIG_SHA:raise ValueError('external_config_changed')
 lines=raw.decode('utf-8','strict').splitlines();classes=[line[14:] for line in lines if line.startswith('app.classpath=')];options=[line[13:] for line in lines if line.startswith('java-options=')]
 expected=['-Djpackage.app-version=2.2.2','-Dcompose.application.resources.dir=$APPDIR/resources','-Dcompose.application.configure.swing.globals=true','-Dskiko.library.path=$APPDIR']
 if len(classes)!=57 or len(set(classes))!=57 or options!=expected or [line for line in lines if line.startswith('app.mainclass=')]!=['app.mainclass=com.kardinal.vpncontrol.desktop.MainKt'] or any(not re.fullmatch(r'\$APPDIR/[A-Za-z0-9_.-]+\.jar',name) for name in classes):raise ValueError('external_config_shape')
 files={item['path']:item for item in manifest['files']}
 if any('opt/vpn-control/lib/app/'+name[8:] not in files for name in classes):raise ValueError('external_classpath_unbound')
 return [name[8:] for name in classes],options

def _selected(value,binding):
 if not isinstance(value,dict) or value.get('state')!='external-jdk-census' or value.get('censusComplete')is not True or value.get('closingGuardsVerified')is not True or value.get('componentRuntime')!='EXTERNAL_JDK' or any(value.get(k)!=binding[k] for k in ('sourceSha256','originalSourceSha256','baselineSha256','generation','stageId','packageSha256')) or not isinstance(value.get('cliStagePins'),list) or len(value['cliStagePins'])!=2 or value['cliStagePins'][0]!=value['cliStagePins'][1]:raise ValueError('external_census_unadmitted')
 candidates=value.get('candidates')
 if not isinstance(candidates,dict) or set(candidates)!=set(CANDIDATES):raise ValueError('external_census_shape')
 for alias,root in CANDIDATES.items():
  row=candidates[alias]
  if not isinstance(row,dict) or row.get('state') not in ('observed','unknown'):raise ValueError('external_census_shape')
  if row['state']=='unknown':continue
  if set(row)!={'state','alias','root','declaredJavaVersion','files'} or row['root']!=root or row['alias']!=alias or not isinstance(row['declaredJavaVersion'],str) or not re.fullmatch(r'(?:17|21)\.[0-9]+\.[0-9]+(?:\.[0-9]+)?(?:\+[0-9A-Za-z_.-]+)?',row['declaredJavaVersion']) or int(row['declaredJavaVersion'].split('.')[0])!=int(alias[3:]) or not isinstance(row['files'],dict) or set(row['files'])!=set(JDK_FILES):raise ValueError('external_census_shape')
  for fact in row['files'].values():
   gen=fact.get('generation') if isinstance(fact,dict) else None
   if set(fact)!={'generation','bytesRead','sha256','hashScope'} or not isinstance(gen,list) or len(gen)!=9 or any(type(n)is not int for n in gen) or gen[6:9]!=[0,0,1] or not __import__('stat').S_ISREG(gen[5]) or gen[5]&0o022 or gen[2]<=0 or gen[2]>268435456 or fact.get('bytesRead')!=gen[2] or fact.get('hashScope')!='full' or not isinstance(fact.get('sha256'),str) or not re.fullmatch('[0-9a-f]{64}',fact['sha256']):raise ValueError('external_census_file_invalid')
 if any(row.get('state')=='observed' and not row['files']['bin/java']['generation'][5]&0o111 for row in candidates.values()):raise ValueError('external_census_file_invalid')
 return next((candidates[k] for k in CANDIDATES if candidates[k]['state']=='observed'),None)

def prepare(root:Path,reservation:dict,action:str='census')->dict:
 if action not in ('census','compare'):raise ValueError('external_fixed_action_required')
 root=Path(root).absolute();path=Path(original.__file__).absolute();source=availability._snapshot(path)
 if hashlib.sha256(source[1]).hexdigest()!=ORIGINAL_SHA:raise ValueError('external_original_source_changed')
 prepared=original.prepare(root,reservation)
 if availability._snapshot(path)!=source or prepared['snapshots'].get(path)!=source:raise ValueError('external_original_source_changed')
 def saved(path):
  snap=availability._snapshot(path);prepared['snapshots'][path]=snap;return snap[1]
 own=Path(__file__).absolute();own_raw=saved(own);tree=ast.parse(prepared['program']);getter=ast.literal_eval(next(n.value for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='GETTER' for t in n.targets)))
 stage=root/'.rag_index/android-cli-stages'/getter['stageId']/'tree';config=saved(stage/'opt/vpn-control/lib/app/vpn-control.cfg');classes,options=_configuration(config,getter['manifest'])
 baseline_raw=saved(root/BASELINE)
 if hashlib.sha256(baseline_raw).hexdigest()!=BASELINE_SHA:raise ValueError('external_launcher_baseline_changed')
 baseline=json.loads(baseline_raw);record=baseline.get('records',{}).get('statusDiscovery',{});reply=record.get('stdout',{})
 if record.get('returncode')!=0 or reply.get('ok')is not True or reply.get('code')!='OK' or reply.get('controllerId')!='6373d143-1372-4835-a89b-baafb0959b9f' or reply.get('configurationRevision')!=0 or record.get('stderrRaw')!='pure virtual method called\nterminate called without an active exception\n' or baseline.get('closingGuardsVerified')is not True:raise ValueError('external_launcher_baseline_invalid')
 binding={'action':action,'candidates':CANDIDATES,'jdkFiles':list(JDK_FILES),'classpath':classes,'javaOptions':options,'selectedJdk':None,'sourceSha256':hashlib.sha256(own_raw).hexdigest(),'originalSourceSha256':ORIGINAL_SHA,'baselineSha256':BASELINE_SHA,'generation':getter['generation'],'stageId':getter['stageId'],'packageSha256':getter['packageSha256']}
 if action=='compare':
  raw=saved(root/CENSUS)
  if len(raw)>4194304:raise ValueError('external_census_unbounded')
  binding['selectedJdk']=_selected(json.loads(raw),binding)
  if binding['selectedJdk']is None:raise ValueError('external_jdk_unavailable')
 names={'observed_getter'}
 if {n.name for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in names}!=names or ast.unparse(tree.body[-1])!='coldboot_dispatch()':raise ValueError('external_composition_changed')
 tree.body=[n for n in tree.body if not isinstance(n,ast.FunctionDef) or n.name not in names];tree.body.pop()
 template=ast.literal_eval(next(n.value for n in ast.parse(own_raw).body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='_REMOTE' for t in n.targets)))
 prepared['program']=ast.unparse(tree)+'\n'+template.replace('__EXTERNAL__',repr(binding))+'\ncoldboot_dispatch()\n'
 compile(prepared['program'],'<fixed-external-jdk-component>','exec');guard_prepared(prepared);return prepared

def guard_prepared(prepared):original.guard_prepared(prepared)
def ssh_carrier(prepared):return original.ssh_carrier(prepared)
