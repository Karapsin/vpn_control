"""Fixed API35 current-generation getters; no lifecycle or replay effects."""
from __future__ import annotations
import ast
import hashlib
import json
from pathlib import Path
from . import android_avd_coldboot as coldboot
from . import android_coldboot_product_observation as analog
from . import android_device_availability as availability

COLD_SOURCE='e80f7c833ca5dbf817afadb7c4fe896d6ddb6e1a792fcc2759311fcf996b0957'
ANALOG_SOURCE='d90b7c6338163bd46ea0c89b8582af45f10e9376b94d9b08c4e6902cfdc1c885'
CORRELATION='e3e97a65-b14a-4c32-8954-a441ac28ec47'
STATUS='android-coldboot-status-api35-da8b7788-8176-4346-b934-73131c5d41f2/result.json'
STAGE='b31ed749-4aa5-435e-8481-1fbacbefed9a'
MANIFEST='acf7b161b786780f0f57ddb4e23dcd674e88bcb14745190709eba93ac581b579'
FIXED_GENERATION={'child': {'pid': 1420710, 'startTicks': 2970292, 'bootId': '25515f23-b966-4c3a-ae63-d38452375578', 'exe': '/usr/bin/python3.14', 'exeGeneration': [66306, 1227482, 14424, 1786348016000000000, 1786804189213449734, 33261, 0, 0, 1], 'commandSha256': '15bfaf15908a44e2cf14e459560a0702bf96dddff66725e8c59e7613631d0a25'}, 'guest': {'pid': 1420715, 'startTicks': 2970310, 'hostBootId': '25515f23-b966-4c3a-ae63-d38452375578', 'sessionId': 1420710, 'exeGeneration': [66307, 115870992, 23718968, 1774601179883356671, 1774601179884356669, 33261, 1000, 1000, 1], 'commandSha256': '2866934e9f4bbaa4f94504f6acdbcee1cf2e7a89e1c316174dc79d5c4e2701b3'}, 'device': {'sdk': '35', 'abi': 'x86_64', 'kernelAvd': '', 'bootAvd': 'vpn-control-parity113-api35', 'bootCompleted': '1', 'shellUid': '2000', 'guestBootId': 'd177ded3-526f-486d-bd19-3042d1836d9a', 'matched': True}}
STATUS_SHA='3e53fb612d93301c610a10c6f3f9289d37de3b4902b5507e8dd16dd8784f92d9'
APK='352af218242311884a355f789c0d1c45b736c35270b096f41408de55e2c4ed33'
_GETTER=r'''
import select,shutil,base64
GETTER=__GETTER__
def getter_generation(directory):
 value=original_status(directory)
 if value.get('state')!='guest-generation-admitted' or value.get('guestAdmitted') is not True or any(value.get(key)!=GETTER['generation'][key] for key in ('child','guest','device')):raise ValueError('getter_generation_changed')
 return value

def getter_bounded(argv,fd,environment,timeout=30,limit=1048576):
 def drop():os.setgroups([1000]);os.setgid(1000);os.setuid(1000)
 process=subprocess.Popen(argv,executable='/proc/self/fd/'+str(fd),pass_fds=(fd,),env=environment,preexec_fn=drop,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
 streams={process.stdout:b'',process.stderr:b''};open_streams=list(streams);deadline=time.monotonic()+timeout
 try:
  while open_streams:
   remaining=deadline-time.monotonic()
   if remaining<=0:raise ValueError('getter_command_timeout')
   ready,_,_=select.select(open_streams,[],[],min(remaining,1))
   for stream in ready:
    part=os.read(stream.fileno(),min(65536,limit+1-sum(map(len,streams.values()))))
    if not part:open_streams.remove(stream);continue
    streams[stream]+=part
    if sum(map(len,streams.values()))>limit:raise ValueError('getter_command_output_limit')
  code=process.wait(timeout=max(0.01,deadline-time.monotonic()))
  return {'returncode':code,'stdoutRaw':streams[process.stdout].decode('utf-8','strict'),'stderrRaw':streams[process.stderr].decode('utf-8','strict')}
 finally:
  GETTER_RECORDS['lastBoundedCommand']={'stdoutRaw':streams[process.stdout].decode('utf-8','replace'),'stderrRaw':streams[process.stderr].decode('utf-8','replace'),'stdoutBase64':base64.b64encode(streams[process.stdout]).decode(),'stderrBase64':base64.b64encode(streams[process.stderr]).decode(),'returncode':process.poll()}
  if process.poll() is None:
   process.kill()
   try:process.wait(timeout=2)
   except subprocess.TimeoutExpired:pass
  for stream in streams:stream.close()

def getter_binary(path,expected,args,environment,limit=1048576):
 chain,name=parent_fds(path);fd=None
 try:
  fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=chain[-1]['fd'])
  if fp(os.fstat(fd))!=expected or fp(os.stat(name,dir_fd=chain[-1]['fd'],follow_symlinks=False))!=expected:raise ValueError('getter_binary_changed')
  guard_parents(chain);result=getter_bounded([str(path),*args],fd,environment,limit=limit)
  guard_parents(chain)
  if fp(os.fstat(fd))!=expected or fp(os.stat(name,dir_fd=chain[-1]['fd'],follow_symlinks=False))!=expected:raise ValueError('getter_binary_changed')
  return result
 finally:
  if fd is not None:os.close(fd)
  close_parents(chain)

def getter_adb(words):
 if words!=['shell','-T','pm','path','com.kardinal.vpncontrol'] and not (len(words)==4 and words[:3]==['shell','-T','sha256sum'] and re.fullmatch(r'/data/app/[A-Za-z0-9_./+~=-]+/base\.apk',words[3]) and '..' not in pathlib.PurePosixPath(words[3]).parts):raise ValueError('getter_readonly_adb_required')
 result=getter_binary(pathlib.Path(LAUNCH['adbPath']),LAUNCH['adbFacts']['generation'],['-s','emulator-5682',*words],LAUNCH['environment'])
 key='packagePath'+GETTER_APK_PASS if words[:4]==['shell','-T','pm','path'] else 'packageHash'+GETTER_APK_PASS
 GETTER_RECORDS[key]=result
 if result['returncode']!=0:raise ValueError('getter_adb_failed')
 return result['stdoutRaw'].strip()

def getter_apk():
 raw=getter_adb(['shell','-T','pm','path','com.kardinal.vpncontrol']);paths=[line[8:] for line in raw.splitlines() if line.startswith('package:')]
 if len(paths)!=1 or not re.fullmatch(r'/data/app/[A-Za-z0-9_./+~=-]+/base\.apk',paths[0]) or '..' in pathlib.PurePosixPath(paths[0]).parts:raise ValueError('getter_package_path_unknown')
 parts=getter_adb(['shell','-T','sha256sum',paths[0]]).split()
 if len(parts)!=2 or parts[1]!=paths[0]:raise ValueError('getter_package_hash_unknown')
 if not re.fullmatch(r'[0-9a-f]{64}',parts[0]):raise ValueError('getter_package_hash_unknown')
 return parts[0]

def getter_stage():
 directory=ROOT/('android-cli-stage-'+GETTER['stageId']);pins={}
 for name in ('intent.json','receipt.json'):
  item=read_fixed(directory/name,262144);raw=item.pop('raw')
  if item['hashScope']!='full' or item['generation'][6:9]!=[1000,1000,1] or stat.S_IMODE(item['generation'][5])!=0o600:raise ValueError('getter_stage_control_unsafe')
  value=json.loads(raw);pins[name]=item
  if value.get('manifestSha256')!=GETTER['manifestSha256'] or value.get('rpmSha256')!=GETTER['rpmSha256']:raise ValueError('getter_stage_binding_changed')
  if name=='intent.json' and value.get('manifest')!=GETTER['manifest']:raise ValueError('getter_stage_manifest_changed')
  if name=='receipt.json' and (value.get('state')!='published' or value.get('cliPath')!=GETTER['cli']):raise ValueError('getter_stage_unpublished')
 tree=directory/'tree';observed=tree_facts(tree);manifest=GETTER['manifest'];expected={'.',*[item['path'] for item in manifest['directories']],*[item['path'] for item in manifest['files']]}
 if set(observed)!=expected:raise ValueError('getter_stage_inventory_changed')
 for item in manifest['directories']:
  fact=observed[item['path']]
  if fact['kind']!='directory' or stat.S_IMODE(fact['generation'][5])!=item['mode']:raise ValueError('getter_stage_directory_changed')
 for item in manifest['files']:
  fact=read_fixed(tree/item['path'],268435456);fact.pop('raw')
  if fact['hashScope']!='full' or fact['sha256']!=item['sha256'] or fact['generation'][2]!=item['size'] or stat.S_IMODE(fact['generation'][5])!=item['mode'] or fact['generation']!=observed[item['path']]['generation']:raise ValueError('getter_stage_file_changed')
  pins[item['path']]=fact
 return pins

def getter_cli(words,owner=None):
 if words not in (['status'],['operations','list'],['routing','show']):raise ValueError('getter_readonly_command_required')
 cli=pathlib.Path(GETTER['cli']);fact=read_fixed(cli,1048576);fact.pop('raw')
 if fact['hashScope']!='full' or fact['sha256']!=GETTER['manifest']['launcherSha256']:raise ValueError('getter_cli_changed')
 environment=public_cli_environment(LAUNCH['adbPath'],cli,LAUNCH['environment'])
 args=['--json','--android','--serial','emulator-5682','--timeout-seconds','30',*(['--controller-id',owner] if owner else []),*words]
 result=getter_binary(cli,fact['generation'],args,environment,limit=8388608)
 try:result['stdout']=json.loads(result['stdoutRaw'])
 except (ValueError,TypeError):result['stdout']=None
 return result

def getter_envelope(record,owner=None,revision=None):
 value=record.get('stdout')
 if record.get('returncode')!=0 or not isinstance(value,dict) or value.get('ok') is not True or value.get('final') is not True or value.get('code')!='OK':return None
 if not isinstance(value.get('controllerId'),str) or not value['controllerId'] or type(value.get('configurationRevision')) is not int:raise ValueError('getter_owner_invalid')
 if owner is not None and (value['controllerId']!=owner or value['configurationRevision']!=revision):raise ValueError('getter_owner_changed')
 return value

def current_getter(directory):
 global GETTER_RECORDS,GETTER_APK_PASS
 GETTER_RECORDS={}
 before=getter_generation(directory)
 GETTER_APK_PASS='Before';installed=getter_apk()
 records=GETTER_RECORDS;records['observedPackageBefore']=installed
 if installed!=GETTER['packageSha256']:
  GETTER_APK_PASS='After';closing=getter_apk();records['observedPackageAfter']=closing
  after=getter_generation(directory)
  return {'state':'diagnostic-only','productAdmitted':False,'acceptanceComplete':False,'reason':'installed_apk_differs' if closing==installed else 'installed_apk_unstable','observedPackageSha256':installed,'records':records,'generation':[before,after],'historicalUnknownsPreserved':True}
 records=GETTER_RECORDS;records['statusBefore']=getter_cli(['status']);first=getter_envelope(records['statusBefore'])
 if first is None:
  GETTER_APK_PASS='After';closing=getter_apk();records['observedPackageAfter']=closing
  after=getter_generation(directory)
  return {'state':'diagnostic-only','productAdmitted':False,'acceptanceComplete':False,'reason':'provider_unavailable' if closing==installed else 'installed_apk_unstable','observedPackageSha256':installed,'records':records,'generation':[before,after],'historicalUnknownsPreserved':True}
 owner=first['controllerId'];revision=first['configurationRevision']
 for name,words in (('operations',['operations','list']),('routing',['routing','show']),('operationsAfter',['operations','list']),('routingAfter',['routing','show']),('statusAfter',['status'])):
  records[name]=getter_cli(words,owner)
  if getter_envelope(records[name],owner,revision) is None:raise ValueError('getter_public_read_failed')
 operations=records['operations']['stdout'].get('data',{}).get('operations');routing=records['routing']['stdout'].get('data',{}).get('routing')
 data=first.get('data',{})
 if data.get('runtimeRunning') is not False or data.get('runtimeObservation')!='stopped' or records['statusAfter']['stdout'].get('data')!=data:raise ValueError('getter_runtime_not_stably_off')
 if records['operationsAfter']['stdout'].get('data')!=records['operations']['stdout'].get('data') or records['routingAfter']['stdout'].get('data')!=records['routing']['stdout'].get('data'):raise ValueError('getter_rules_or_operations_changed')
 if not isinstance(operations,list) or any(not isinstance(item,dict) or item.get('final') is not True for item in operations) or not isinstance(routing,dict):raise ValueError('getter_history_or_rules_unknown')
 GETTER_APK_PASS='After';closing=getter_apk();records['observedPackageAfter']=closing
 if closing!=GETTER['packageSha256']:raise ValueError('getter_package_changed')
 after=getter_generation(directory)
 return {'state':'current-product-getters-admitted','productAdmitted':True,'acceptanceComplete':False,'observedPackageSha256':installed,'controllerId':owner,'configurationRevision':revision,'records':records,'generation':[before,after],'historicalUnknownsPreserved':True}

def observed_getter(directory):
 global GETTER_RECORDS
 GETTER_RECORDS={};before=None;after=None
 try:
  before=getter_stage();result=current_getter(directory);after=getter_stage()
  if before!=after:raise ValueError('getter_stage_generation_changed')
  result['cliStagePins']=before;result['newSourceSha256']=GETTER['newSourceSha256'];return result
 except (ValueError,OSError,KeyError,TypeError) as error:
  reason=str(error) if isinstance(error,ValueError) and re.fullmatch(r'(?:getter|coldboot|census|alias)_[a-z_]{1,72}',str(error)) else 'getter_guard_rejected'
  return {'state':'diagnostic-only','reason':reason,'productAdmitted':False,'acceptanceComplete':False,'records':GETTER_RECORDS,'observedPackageSha256':GETTER_RECORDS.get('observedPackageBefore'),'cliStagePins':[before,after],'historicalUnknownsPreserved':True}
'''

def prepare(root: Path,reservation: dict) -> dict:
    root=Path(root).absolute();source=Path(coldboot.__file__).absolute();pin,raw=availability._snapshot(source)
    if hashlib.sha256(raw).hexdigest()!=COLD_SOURCE:raise ValueError('getter_consumed_coldboot_changed')
    analog_path=Path(analog.__file__).absolute();analog_pin,analog_raw=availability._snapshot(analog_path)
    if hashlib.sha256(analog_raw).hexdigest()!=ANALOG_SOURCE:raise ValueError('getter_consumed_analog_changed')
    prepared=coldboot.prepare(root,'api35',CORRELATION,reservation,'status')
    prepared['snapshots'][analog_path]=(analog_pin,analog_raw)
    def saved(relative):
        path=root/relative;pin,raw=availability._snapshot(path);prepared['snapshots'][path]=(pin,raw);return json.loads(raw)
    current=saved('.runtime/parity-evidence/'+STATUS)
    if current.get('state')!='guest-generation-admitted' or current.get('correlationId')!=CORRELATION or current.get('guestAdmitted') is not True:raise ValueError('getter_generation_unadmitted')
    generation={key:current[key] for key in ('child','guest','device')}
    if generation!=FIXED_GENERATION:raise ValueError('getter_fixed_generation_changed')
    if hashlib.sha256(prepared['snapshots'][root/('.runtime/parity-evidence/'+STATUS)][1]).hexdigest()!=STATUS_SHA:raise ValueError('getter_original_status_changed')
    stage=saved('.rag_index/android-cli-stages/'+STAGE+'/intent.json');manifest=stage['manifest']
    if stage['correlationId']!=STAGE or stage['fixtureRoot']!='/home/kardinal/.vpn-control-mcp-fixtures' or stage['sourceSha']!='d32f719a08db57e5d40ce2bf77e0d7c5b42de557' or stage['manifestSha256']!=MANIFEST or hashlib.sha256(json.dumps(manifest,sort_keys=True,separators=(',',':')).encode()).hexdigest()!=MANIFEST:raise ValueError('getter_manifest_unadmitted')
    apk=saved('.runtime/parity-evidence/android-current/d32-apk/receipt.json')
    if apk['sha256']!=APK or apk['bytes']!=45026948 or apk['sourceSha']!='d32f719a08db57e5d40ce2bf77e0d7c5b42de557':raise ValueError('getter_source_apk_changed')
    own=Path(__file__).absolute();own_pin,own_raw=availability._snapshot(own);prepared['snapshots'][own]=(own_pin,own_raw)
    script=root/'scripts/android_no_update_tls_preflight.py';script_pin,script_raw=availability._snapshot(script);prepared['snapshots'][script]=(script_pin,script_raw)
    functions=[node for node in ast.parse(script_raw).body if isinstance(node,ast.FunctionDef) and node.name=='public_cli_environment']
    if len(functions)!=1:raise ValueError('getter_environment_helper_changed')
    helper=ast.get_source_segment(script_raw.decode(),functions[0])
    binding={'generation':generation,'packageSha256':APK,'stageId':STAGE,'manifestSha256':MANIFEST,'manifest':manifest,'rpmSha256':stage['rpmSha256'],'cli':stage['fixtureRoot']+'/android-cli-stage-'+STAGE+'/tree/opt/vpn-control/bin/vpn-control','newSourceSha256':hashlib.sha256(own_raw).hexdigest()}
    tree=ast.parse(prepared['program']);dispatch=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='coldboot_dispatch')
    assignments=[node for node in ast.walk(dispatch) if isinstance(node,ast.Assign) and any(isinstance(target,ast.Name) and target.id=='result' for target in node.targets)]
    if len(assignments)!=1 or not isinstance(assignments[0].value,ast.IfExp):raise ValueError('getter_status_composition_changed')
    assignments[0].value=ast.Call(func=ast.Name(id='observed_getter',ctx=ast.Load()),args=[ast.Name(id='directory',ctx=ast.Load())],keywords=[])
    # Retain the exact existing lock/read guards, with no admission-directory
    # creation and no new lock file creation available to this observer.
    admission=[node for node in ast.walk(dispatch) if isinstance(node,ast.If) and ast.unparse(node.test)=="LAUNCH['action'] == 'admit'"]
    if len(admission)!=1:raise ValueError('getter_admission_composition_changed')
    for node in ast.walk(dispatch):
        for field,value in ast.iter_fields(node):
            if isinstance(value,list) and admission[0] in value:value.remove(admission[0])
    locks=[node for node in ast.walk(dispatch) if isinstance(node,ast.Call) and ast.unparse(node.func)=='os.open' and node.args and ast.unparse(node.args[0])=='lock_name']
    if len(locks)!=1:raise ValueError('getter_lock_composition_changed')
    locks[0].args[1]=ast.parse('os.O_RDWR | os.O_NOFOLLOW',mode='eval').body
    mutations={'admit_once','launch_once','child_exec','emulator_exec','close_supervisor_inherited','journal_write','refresh_root_after_directory_create','write_capsule','capture','selected_preflight','open_emulator','census_history'}
    tree.body=[node for node in tree.body if not isinstance(node,ast.FunctionDef) or node.name not in mutations]
    if not isinstance(tree.body[-1],ast.Expr) or ast.unparse(tree.body[-1])!='coldboot_dispatch()':raise ValueError('getter_dispatch_changed')
    tree.body.pop();program=ast.unparse(ast.fix_missing_locations(tree))+'\n'
    template=ast.literal_eval(next(node.value for node in ast.parse(own_raw).body if isinstance(node,ast.Assign) and any(isinstance(target,ast.Name) and target.id=='_GETTER' for target in node.targets)))
    prepared['program']=program+'\nfrom pathlib import Path\n'+helper+'\n'+template.replace('__GETTER__',repr(binding))+'\ncoldboot_dispatch()\n'
    compile(prepared['program'],'<fixed-current-product-getter>','exec');validate_readonly(prepared['program']);guard_prepared(prepared);return prepared

def guard_prepared(prepared):coldboot.guard_prepared(prepared)
def ssh_carrier(prepared):return coldboot.ssh_carrier(prepared)


def validate_readonly(program):
    """Reject inherited creation/launch syntax before the root can dispatch it."""
    tree=ast.parse(program)
    forbidden={'admit_once','launch_once','child_exec','emulator_exec','journal_write','refresh_root_after_directory_create','write_capsule','capture'}
    for node in ast.walk(tree):
        if isinstance(node,ast.FunctionDef) and node.name in forbidden:raise ValueError('getter_readonly_definition_required')
        if isinstance(node,ast.Call):
            name=ast.unparse(node.func)
            if name in {'os.mkdir','os.makedirs','os.write','os.fchmod','os.chmod','os.fork','os.execv','os.execve','os.kill','os.system','os.unlink','os.remove','os.rmdir','os.rename','os.replace','subprocess.call','subprocess.check_call','subprocess.check_output','shutil.rmtree'} or name in forbidden:raise ValueError('getter_readonly_syntax_required')
            if isinstance(node.func,ast.Attribute) and node.func.attr in {'mkdir','makedirs','write_bytes','write_text','unlink','rmdir','rename','replace','chmod'}:raise ValueError('getter_readonly_method_required')
            if any(isinstance(part,ast.Attribute) and part.attr in {'O_CREAT','O_EXCL','O_TRUNC','O_WRONLY'} for part in ast.walk(node)):raise ValueError('getter_readonly_open_required')
    calls=[n for n in tree.body if isinstance(n,ast.Expr) and isinstance(n.value,ast.Call) and isinstance(n.value.func,ast.Name) and n.value.func.id=='coldboot_dispatch']
    if len(calls)!=1 or calls[0] is not tree.body[-1]:raise ValueError('getter_readonly_dispatch_required')


def prepare_existing_readonly(root: Path,reservation: dict,correlation: str,historical_producer: dict) -> dict:
    root=Path(root).absolute();source=Path(coldboot.__file__).absolute();pin,raw=availability._snapshot(source)
    if hashlib.sha256(raw).hexdigest()!=COLD_SOURCE:raise ValueError('getter_consumed_coldboot_changed')
    analog_path=Path(analog.__file__).absolute();analog_pin,analog_raw=availability._snapshot(analog_path)
    if hashlib.sha256(analog_raw).hexdigest()!=ANALOG_SOURCE:raise ValueError('getter_consumed_analog_changed')
    prepared=coldboot.prepare_existing_api35_readonly(root,correlation,reservation,historical_producer)
    prepared['snapshots'][analog_path]=(analog_pin,analog_raw)
    def saved(relative):
        path=root/relative;pin,raw=availability._snapshot(path);prepared['snapshots'][path]=(pin,raw);return json.loads(raw)
    current=saved('.runtime/parity-evidence/'+STATUS)
    if current.get('state')!='guest-generation-admitted' or current.get('correlationId')!=CORRELATION or current.get('guestAdmitted') is not True:raise ValueError('getter_generation_unadmitted')
    generation={key:current[key] for key in ('child','guest','device')}
    if generation!=FIXED_GENERATION:raise ValueError('getter_fixed_generation_changed')
    if hashlib.sha256(prepared['snapshots'][root/('.runtime/parity-evidence/'+STATUS)][1]).hexdigest()!=STATUS_SHA:raise ValueError('getter_original_status_changed')
    stage=saved('.rag_index/android-cli-stages/'+STAGE+'/intent.json');manifest=stage['manifest']
    if stage['correlationId']!=STAGE or stage['fixtureRoot']!='/home/kardinal/.vpn-control-mcp-fixtures' or stage['sourceSha']!='d32f719a08db57e5d40ce2bf77e0d7c5b42de557' or stage['manifestSha256']!=MANIFEST or hashlib.sha256(json.dumps(manifest,sort_keys=True,separators=(',',':')).encode()).hexdigest()!=MANIFEST:raise ValueError('getter_manifest_unadmitted')
    apk=saved('.runtime/parity-evidence/android-current/d32-apk/receipt.json')
    if apk['sha256']!=APK or apk['bytes']!=45026948 or apk['sourceSha']!='d32f719a08db57e5d40ce2bf77e0d7c5b42de557':raise ValueError('getter_source_apk_changed')
    own=Path(__file__).absolute();own_pin,own_raw=availability._snapshot(own);prepared['snapshots'][own]=(own_pin,own_raw)
    script=root/'scripts/android_no_update_tls_preflight.py';script_pin,script_raw=availability._snapshot(script);prepared['snapshots'][script]=(script_pin,script_raw)
    functions=[node for node in ast.parse(script_raw).body if isinstance(node,ast.FunctionDef) and node.name=='public_cli_environment']
    if len(functions)!=1:raise ValueError('getter_environment_helper_changed')
    helper=ast.get_source_segment(script_raw.decode(),functions[0])
    binding={'generation':generation,'packageSha256':APK,'stageId':STAGE,'manifestSha256':MANIFEST,'manifest':manifest,'rpmSha256':stage['rpmSha256'],'cli':stage['fixtureRoot']+'/android-cli-stage-'+STAGE+'/tree/opt/vpn-control/bin/vpn-control','newSourceSha256':hashlib.sha256(own_raw).hexdigest()}
    tree=ast.parse(prepared['program']);dispatch=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='coldboot_dispatch')
    assignments=[node for node in ast.walk(dispatch) if isinstance(node,ast.Assign) and any(isinstance(target,ast.Name) and target.id=='result' for target in node.targets)]
    if len(assignments)!=1 or ast.unparse(assignments[0].value)!='original_status(directory)':raise ValueError('getter_status_composition_changed')
    assignments[0].value=ast.Call(func=ast.Name(id='observed_getter',ctx=ast.Load()),args=[ast.Name(id='directory',ctx=ast.Load())],keywords=[])
    # Retain the exact existing lock/read guards, with no admission-directory
    # creation and no new lock file creation available to this observer.
    locks=[node for node in ast.walk(dispatch) if isinstance(node,ast.Call) and ast.unparse(node.func)=='os.open' and node.args and ast.unparse(node.args[0])=='lock_name']
    if len(locks)!=1:raise ValueError('getter_lock_composition_changed')
    locks[0].args[1]=ast.parse('os.O_RDWR | os.O_NOFOLLOW',mode='eval').body
    mutations={'admit_once','launch_once','child_exec','emulator_exec','close_supervisor_inherited','journal_write','refresh_root_after_directory_create','write_capsule','capture','selected_preflight','open_emulator','census_history'}
    tree.body=[node for node in tree.body if not isinstance(node,ast.FunctionDef) or node.name not in mutations]
    if not isinstance(tree.body[-1],ast.Expr) or ast.unparse(tree.body[-1])!='coldboot_dispatch()':raise ValueError('getter_dispatch_changed')
    tree.body.pop();program=ast.unparse(ast.fix_missing_locations(tree))+'\n'
    template=ast.literal_eval(next(node.value for node in ast.parse(own_raw).body if isinstance(node,ast.Assign) and any(isinstance(target,ast.Name) and target.id=='_GETTER' for target in node.targets)))
    prepared['program']=program+'\nfrom pathlib import Path\n'+helper+'\n'+template.replace('__GETTER__',repr(binding))+'\ncoldboot_dispatch()\n'
    compile(prepared['program'],'<fixed-current-product-getter>','exec');validate_readonly(prepared['program']);guard_prepared(prepared);return prepared
