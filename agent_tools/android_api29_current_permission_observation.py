"""Fixed current API29 readonly VPN permission observation; no grant authority."""
from __future__ import annotations
import ast
import hashlib
from pathlib import Path
from . import android_coldboot_product_observation as original
from . import android_device_availability as availability
ORIGINAL_SHA='ec56e238b0bac95d67ae1942b7218bb844db1e48b29cff1ad7b390b1721d8ae7'
OWNER='401cea62-1852-4642-bd4d-a9d5ed372394'
_OBSERVER=r'''
PERMISSION_OWNER=__OWNER__
def getter_bounded(argv,fd,environment,timeout=30,limit=1048576):
 import base64
 def drop():os.setgroups([1000]);os.setgid(1000);os.setuid(1000)
 process=None;streams={};code=None;failure=None
 try:
  process=subprocess.Popen(argv,executable='/proc/self/fd/'+str(fd),pass_fds=(fd,),env=environment,preexec_fn=drop,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
  streams={process.stdout:b'',process.stderr:b''};opened=list(streams);deadline=time.monotonic()+timeout
  while opened:
   remaining=deadline-time.monotonic()
   if remaining<=0:raise ValueError('permission_command_timeout')
   ready,_,_=select.select(opened,[],[],min(remaining,1))
   for stream in ready:
    remaining_bytes=limit-sum(map(len,streams.values()))
    part=os.read(stream.fileno(),min(65536,remaining_bytes+1))
    if not part:opened.remove(stream);continue
    streams[stream]+=part[:remaining_bytes]
    if len(part)>remaining_bytes:raise ValueError('permission_command_output_limit')
  code=process.wait(timeout=max(.01,deadline-time.monotonic()))
 except (ValueError,OSError,subprocess.TimeoutExpired) as error:
  failure=str(error) if isinstance(error,ValueError) and str(error) in ('permission_command_timeout','permission_command_output_limit') else 'permission_command_unknown'
 finally:
  if process is not None:
   if process.poll() is None:
    try:
     process.kill();process.wait(timeout=2)
    except (OSError,subprocess.TimeoutExpired):failure='permission_command_reap_unknown'
   rawout=streams.get(process.stdout,b'');rawerr=streams.get(process.stderr,b'')
   GETTER_RECORDS.setdefault('captures',[]).append({'returncode':code,'failure':failure,'stdoutBase64':base64.b64encode(rawout).decode(),'stderrBase64':base64.b64encode(rawerr).decode(),'stdoutBytes':len(rawout),'stderrBytes':len(rawerr)})
   for stream in streams:stream.close()
 if failure:raise ValueError(failure)
 return {'returncode':code,'stdoutRaw':rawout.decode('utf-8','strict'),'stderrRaw':rawerr.decode('utf-8','strict')}

def permission_diagnostics():
 cli=pathlib.Path(GETTER['cli']);fact=read_fixed(cli,1048576);fact.pop('raw')
 if fact['hashScope']!='full' or fact['sha256']!=GETTER['manifest']['launcherSha256']:raise ValueError('getter_cli_changed')
 environment=public_cli_environment(LAUNCH['adbPath'],cli,LAUNCH['environment'])
 return getter_binary(cli,fact['generation'],['--android','--serial','emulator-5684','--timeout-seconds','30','--controller-id',PERMISSION_OWNER,'diagnostics','export','--output','-'],environment,limit=1048576)

def permission_parse(record):
 if type(record.get('returncode'))is not int or record['returncode']!=0 or record.get('stderrRaw')!='' or not isinstance(record.get('stdoutRaw'),str):raise ValueError('permission_diagnostics_failed')
 raw=record['stdoutRaw']
 if len(raw.encode('utf-8'))>1048576:raise ValueError('permission_diagnostics_unbounded')
 section=False;sections=0;values={}
 for line in raw.splitlines():
  if line.startswith('[') and line.endswith(']'):
   section=line=='[runtime]';sections+=int(section);continue
  if section and '=' in line:
   key,value=line.split('=',1)
   if key in ('mode','vpn_permission_granted','is_vpn_running'):
    if key in values:raise ValueError('permission_runtime_ambiguous')
    values[key]=value
 if sections!=1 or set(values)!={'mode','vpn_permission_granted','is_vpn_running'} or values['mode'] not in ('VPN','PROXY_ONLY') or any(values[k] not in ('true','false') for k in ('vpn_permission_granted','is_vpn_running')):raise ValueError('permission_runtime_ambiguous')
 return {'mode':values['mode'],'permissionGranted':values['vpn_permission_granted']=='true','vpnRunning':values['is_vpn_running']=='true'}

def permission_public(record,kind):
 value=getter_envelope(record,PERMISSION_OWNER,0)
 if value is None:raise ValueError('permission_public_unavailable')
 data=value.get('data')
 if not isinstance(data,dict):raise ValueError('permission_public_shape')
 if kind=='operations':
  if data.get('operations')!=[]:raise ValueError('permission_operations_not_empty')
 elif data.get('runtimeRunning') is not False or data.get('runtimeObservation')!='stopped':raise ValueError('permission_runtime_not_off')
 return data

def observed_getter(directory):
 global GETTER_RECORDS
 GETTER_RECORDS={};stage=[];failure=None;observation=None;closing=False
 try:
  stage.append(getter_stage());getter_generation(directory)
  if getter_apk()!=GETTER['packageSha256']:raise ValueError('getter_package_changed')
  GETTER_RECORDS['statusBefore']=getter_cli(['status'],PERMISSION_OWNER);before=permission_public(GETTER_RECORDS['statusBefore'],'status')
  GETTER_RECORDS['operationsBefore']=getter_cli(['operations','list'],PERMISSION_OWNER);permission_public(GETTER_RECORDS['operationsBefore'],'operations')
  try:
   GETTER_RECORDS['diagnostics']=permission_diagnostics();observation=permission_parse(GETTER_RECORDS['diagnostics'])
   if observation['vpnRunning']:raise ValueError('permission_runtime_not_off')
   if observation['mode']!='VPN':raise ValueError('permission_mode_not_vpn')
  except (ValueError,OSError,UnicodeError,subprocess.TimeoutExpired) as error:failure=str(error) if isinstance(error,ValueError) and re.fullmatch(r'(?:permission|getter)_[a-z_]{1,72}',str(error)) else 'permission_read_unknown'
  GETTER_RECORDS['operationsAfter']=getter_cli(['operations','list'],PERMISSION_OWNER);permission_public(GETTER_RECORDS['operationsAfter'],'operations')
  GETTER_RECORDS['statusAfter']=getter_cli(['status'],PERMISSION_OWNER);after=permission_public(GETTER_RECORDS['statusAfter'],'status')
  if before!=after:raise ValueError('permission_status_changed')
  if getter_apk()!=GETTER['packageSha256']:raise ValueError('getter_package_changed')
  getter_generation(directory);stage.append(getter_stage())
  if stage[0]!=stage[1]:raise ValueError('getter_stage_generation_changed')
  closing=True
 except (ValueError,OSError,KeyError,TypeError,UnicodeError,subprocess.TimeoutExpired) as error:failure=str(error) if isinstance(error,ValueError) and re.fullmatch(r'(?:permission|getter|coldboot|census|alias)_[a-z_]{1,72}',str(error)) else 'permission_guard_rejected'
 proved=failure is None and closing and observation is not None
 return {'state':'current-permission-observed' if proved else 'diagnostic-only','reason':failure,'permissionObserved':proved,'observation':observation,'controllerId':PERMISSION_OWNER,'configurationRevision':0,'records':GETTER_RECORDS,'cliStagePins':stage,'closingGuardsVerified':closing,'endpointAdmitted':False,'productAdmitted':False,'acceptanceComplete':False,'permissionGrantPerformed':False,'historicalUnknownsPreserved':True}
'''

def compose(program,own_raw):
 tree=ast.parse(program);names={'current_getter','observed_getter','getter_bounded','write_capsule','capture'}
 if {n.name for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in names}!=names or ast.unparse(tree.body[-1])!='coldboot_dispatch()':raise ValueError('permission_composition_changed')
 tree.body=[n for n in tree.body if not isinstance(n,ast.FunctionDef) or n.name not in names];tree.body.pop()
 template=ast.literal_eval(next(n.value for n in ast.parse(own_raw).body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='_OBSERVER' for t in n.targets)))
 result=ast.unparse(tree)+'\n'+template.replace('__OWNER__',repr(OWNER))+'\ncoldboot_dispatch()\n'
 # The inherited observer has already removed launch/admission definitions.
 for n in ast.walk(ast.parse(result)):
  if isinstance(n,ast.Call) and (ast.unparse(n.func) in {'os.mkdir','os.makedirs','os.write','os.fork','os.execve','os.system','os.replace','os.unlink','journal_write','admit_once','launch_once'} or any(isinstance(p,ast.Attribute) and p.attr in {'O_CREAT','O_TRUNC','O_EXCL','O_WRONLY'} for p in ast.walk(n))):raise ValueError('permission_readonly_required')
 compile(result,'<api29-current-permission>','exec');return result

def prepare(root:Path,reservation:dict)->dict:
 root=Path(root).absolute();path=Path(original.__file__).absolute();saved=availability._snapshot(path)
 if hashlib.sha256(saved[1]).hexdigest()!=ORIGINAL_SHA:raise ValueError('permission_original_source_changed')
 prepared=original.prepare(root,reservation)
 if availability._snapshot(path)!=saved or prepared['snapshots'].get(path)!=saved:raise ValueError('permission_original_source_changed')
 own=Path(__file__).absolute();snapshot=availability._snapshot(own);prepared['snapshots'][own]=snapshot
 prepared['program']=compose(prepared['program'],snapshot[1]);guard_prepared(prepared);return prepared

def guard_prepared(prepared):original.guard_prepared(prepared)
def ssh_carrier(prepared):return original.ssh_carrier(prepared)
