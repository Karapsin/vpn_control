"""One fixed API35 routing read; diagnostic evidence cannot admit a product."""
from __future__ import annotations
import ast
import hashlib
import json
from pathlib import Path
from . import android_api35_coldboot_product_observation as original
from . import android_device_availability as availability

SOURCE='c908a23200cf633c9db6a2ccfc057f2e360267519153593a23c4471fbefe528b'
PRIOR='.runtime/parity-evidence/android-coldboot-product-api35-1b9217cf-3088-4aa3-90b7-f43f9c5cabd4/result.json'
PRIOR_SHA='66c8bc154fdf5e96098ded70edb5a272ca885976af6bf66ac86f34dafb88d76a'
OWNER='d475487c-fe93-418c-9f10-5db954723a43'
_MEASUREMENT=r'''
ROUTING_OWNER=__OWNER__
ROUTING_OUTER_SECONDS=45

def routing_process_sample(process):
 # Only the diagnostic's own child. No arbitrary PID or proc body output.
 def bounded(name):
  with open('/proc/'+str(process.pid)+'/'+name,'rb') as stream:
   raw=stream.read(16385)
  if len(raw)>16384:raise ValueError('routing_proc_limit')
  return raw
 try:
  first=bounded('stat');parts=first[first.rfind(b')')+2:].split()
  if len(parts)<22 or int(parts[1])!=os.getpid():raise ValueError('routing_proc_identity')
  status=bounded('status');command=bounded('cmdline');last=bounded('stat');closing=last[last.rfind(b')')+2:].split()
  if len(closing)<22 or parts[19]!=closing[19] or parts[1]!=closing[1]:raise ValueError('routing_proc_changed')
  values={}
  for line in status.decode('ascii','strict').splitlines():
   key,sep,value=line.partition(':')
   if sep and key in ('Threads','VmRSS','VmSize'):values[key]=value.strip()
  return {'state':'measured','pid':process.pid,'parentPid':int(parts[1]),'startTicks':int(parts[19]),'processState':closing[0].decode('ascii'),'commandSha256':hashlib.sha256(command).hexdigest(),'resources':values}
 except (OSError,ValueError,UnicodeError):return {'state':'unavailable','pid':process.pid,'exitCode':process.poll()}

def getter_bounded(argv,fd,environment,timeout=30,limit=1048576):
 def drop():os.setgroups([1000]);os.setgid(1000);os.setuid(1000)
 measured=argv[-2:]==['routing','show']
 if measured and (argv!=[GETTER['cli'],'--json','--android','--serial','emulator-5682','--timeout-seconds','30','--controller-id',ROUTING_OWNER,'routing','show']):raise ValueError('getter_routing_command_changed')
 process=subprocess.Popen(argv,executable='/proc/self/fd/'+str(fd),pass_fds=(fd,),env=environment,preexec_fn=drop,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
 streams={process.stdout:b'',process.stderr:b''};open_streams=list(streams);started=time.monotonic();deadline=started+(ROUTING_OUTER_SECONDS if measured else timeout);trace=[];next_sample=started
 try:
  while open_streams:
   now=time.monotonic()
   if measured and now>=next_sample and len(trace)<47:
    trace.append({'elapsedMs':int((now-started)*1000),'child':routing_process_sample(process),'exitCode':process.poll(),'stdoutEof':process.stdout not in open_streams,'stderrEof':process.stderr not in open_streams,'stdoutBytes':len(streams[process.stdout]),'stderrBytes':len(streams[process.stderr])});next_sample=now+1
   remaining=deadline-now
   if remaining<=0:raise ValueError('getter_command_timeout')
   ready,_,_=select.select(open_streams,[],[],min(remaining,.25))
   for stream in ready:
    part=os.read(stream.fileno(),min(65536,limit+1-sum(map(len,streams.values()))))
    if not part:open_streams.remove(stream);continue
    streams[stream]+=part
    if sum(map(len,streams.values()))>limit:raise ValueError('getter_command_output_limit')
  code=process.wait(timeout=max(.01,deadline-time.monotonic()))
  return {'returncode':code,'stdoutRaw':streams[process.stdout].decode('utf-8','strict'),'stderrRaw':streams[process.stderr].decode('utf-8','strict')}
 finally:
  code=process.poll()
  GETTER_RECORDS['lastBoundedCommand']={'stdoutRaw':streams[process.stdout].decode('utf-8','replace'),'stderrRaw':streams[process.stderr].decode('utf-8','replace'),'stdoutBase64':base64.b64encode(streams[process.stdout]).decode(),'stderrBase64':base64.b64encode(streams[process.stderr]).decode(),'returncode':code}
  if measured:
   GETTER_RECORDS['routingPartial']=dict(GETTER_RECORDS['lastBoundedCommand'])
   GETTER_RECORDS['routingMeasurement']={'publicTimeoutSeconds':30,'outerTimeoutSeconds':ROUTING_OUTER_SECONDS,'elapsedMs':int((time.monotonic()-started)*1000),'child':routing_process_sample(process),'samples':trace,'stdoutEof':process.stdout not in open_streams,'stderrEof':process.stderr not in open_streams,'exitCode':code,'classification':('child_live_at_outer_deadline' if time.monotonic()>=deadline else 'child_live_when_capture_ended') if code is None else 'child_exited_pipe_open' if open_streams else 'terminal_collected','providerPhase':'unmeasured'}
  if code is None:
   process.kill()
   try:process.wait(timeout=2)
   except subprocess.TimeoutExpired:pass
  for stream in streams:stream.close()

def routing_guard_reply(record,kind):
 value=getter_envelope(record,ROUTING_OWNER,0)
 if value is None:raise ValueError('getter_routing_current_owner_unavailable')
 data=value.get('data',{})
 if kind=='status' and (data.get('runtimeRunning') is not False or data.get('runtimeObservation')!='stopped'):raise ValueError('getter_routing_not_off')
 if kind=='operations' and data.get('operations')!=[]:raise ValueError('getter_routing_operations_changed')
 return data

def observed_getter(directory):
 global GETTER_RECORDS,GETTER_APK_PASS
 GETTER_RECORDS={};stage=[];guard_failure=None
 try:
  stage.append(getter_stage());getter_generation(directory)
  GETTER_APK_PASS='Before';apk=getter_apk();GETTER_RECORDS['observedPackageBefore']=apk
  if apk!=GETTER['packageSha256']:raise ValueError('getter_package_changed')
  for name,words in (('statusBefore',['status']),('operationsBefore',['operations','list'])):
   GETTER_RECORDS[name]=getter_cli(words,ROUTING_OWNER);routing_guard_reply(GETTER_RECORDS[name],'status' if words==['status'] else 'operations')
  try:GETTER_RECORDS['routing']=getter_cli(['routing','show'],ROUTING_OWNER)
  except (ValueError,OSError,subprocess.TimeoutExpired):guard_failure='getter_routing_command_incomplete'
  # Even a routing timeout must close the source/guest/current owner guards.
  for name,words in (('statusAfter',['status']),('operationsAfter',['operations','list'])):
   GETTER_RECORDS[name]=getter_cli(words,ROUTING_OWNER);routing_guard_reply(GETTER_RECORDS[name],'status' if words==['status'] else 'operations')
  if GETTER_RECORDS['statusBefore']['stdout']['data']!=GETTER_RECORDS['statusAfter']['stdout']['data']:raise ValueError('getter_routing_status_changed')
  GETTER_APK_PASS='After';apk=getter_apk();GETTER_RECORDS['observedPackageAfter']=apk
  if apk!=GETTER['packageSha256']:raise ValueError('getter_package_changed')
  getter_generation(directory);stage.append(getter_stage())
  if stage[0]!=stage[1]:raise ValueError('getter_stage_generation_changed')
 except (ValueError,OSError,KeyError,TypeError,subprocess.TimeoutExpired) as error:
  guard_failure=str(error) if isinstance(error,ValueError) and re.fullmatch(r'(?:getter|coldboot|census|alias)_[a-z_]{1,72}',str(error)) else 'getter_guard_rejected'
 return {'state':'diagnostic-only','reason':guard_failure or 'getter_routing_terminal_collected','closingGuardsVerified':len(stage)==2 and stage[0]==stage[1] and guard_failure in (None,'getter_routing_command_incomplete'),'productAdmitted':False,'acceptanceComplete':False,'records':GETTER_RECORDS,'cliStagePins':stage,'historicalUnknownsPreserved':True,'priorResultSha256':__PRIOR_SHA__}
'''


def prepare(root: Path,reservation: dict) -> dict:
    root=Path(root).absolute()
    source=Path(original.__file__).absolute();pin,raw=availability._snapshot(source)
    if hashlib.sha256(raw).hexdigest()!=SOURCE:raise ValueError('getter_consumed_source_changed')
    prepared=original.prepare(root,reservation)
    prior_path=root/PRIOR;prior_pin,prior_raw=availability._snapshot(prior_path)
    if hashlib.sha256(prior_raw).hexdigest()!=PRIOR_SHA:raise ValueError('getter_original_timeout_changed')
    prior=json.loads(prior_raw)
    if prior.get('productAdmitted') is not False or prior.get('reason')!='getter_command_timeout' or prior['records']['statusBefore']['stdout']['controllerId']!=OWNER:raise ValueError('getter_original_timeout_unbound')
    own=Path(__file__).absolute();own_pin,own_raw=availability._snapshot(own)
    prepared['snapshots'].update({source:(pin,raw),prior_path:(prior_pin,prior_raw),own:(own_pin,own_raw)})
    tree=ast.parse(prepared['program']);names={'getter_bounded','current_getter','observed_getter'}
    found={n.name for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in names}
    if found!=names:raise ValueError('getter_diagnostic_composition_changed')
    tree.body=[n for n in tree.body if not isinstance(n,ast.FunctionDef) or n.name not in names]
    if ast.unparse(tree.body[-1])!='coldboot_dispatch()':raise ValueError('getter_dispatch_changed')
    tree.body.pop()
    template=ast.literal_eval(next(n.value for n in ast.parse(own_raw).body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='_MEASUREMENT' for t in n.targets)))
    prepared['program']=ast.unparse(tree)+'\n'+template.replace('__OWNER__',repr(OWNER)).replace('__PRIOR_SHA__',repr(PRIOR_SHA))+'\ncoldboot_dispatch()\n'
    compile(prepared['program'],'<fixed-API35-routing-diagnostic>','exec');original.validate_readonly(prepared['program']);original.guard_prepared(prepared);return prepared


def guard_prepared(prepared):original.guard_prepared(prepared)
def ssh_carrier(prepared):return original.ssh_carrier(prepared)
