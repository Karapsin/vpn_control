"""Current API35 large routing reads, with immutable private chunk evidence."""
from __future__ import annotations
import ast
import hashlib
from pathlib import Path
from . import android_api35_coldboot_product_observation as original
from . import android_device_availability as availability

SOURCE='c908a23200cf633c9db6a2ccfc057f2e360267519153593a23c4471fbefe528b'
OWNER='d475487c-fe93-418c-9f10-5db954723a43'
_OBSERVER=r'''
LARGE_OWNER=__OWNER__
LARGE_PUBLIC_SECONDS=300
LARGE_OUTER_SECONDS=330
LARGE_OUTPUT_LIMIT=33554432

def large_chunks(raw):
 return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'encoding':'base64','chunkBytes':65536,'chunks':[base64.b64encode(raw[offset:offset+65536]).decode('ascii') for offset in range(0,len(raw),65536)]}

def getter_bounded(argv,fd,environment,timeout=30,limit=1048576):
 def drop():os.setgroups([1000]);os.setgid(1000);os.setuid(1000)
 measured=argv[-2:]==['routing','show']
 expected=[GETTER['cli'],'--json','--android','--serial','emulator-5682','--timeout-seconds',str(LARGE_PUBLIC_SECONDS),'--controller-id',LARGE_OWNER,'routing','show']
 if measured and (argv!=expected or limit!=LARGE_OUTPUT_LIMIT or LARGE_PHASE not in ('routingBefore','routingAfter')):raise ValueError('getter_large_command_changed')
 process=subprocess.Popen(argv,executable='/proc/self/fd/'+str(fd),pass_fds=(fd,),env=environment,preexec_fn=drop,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
 streams={process.stdout:bytearray(),process.stderr:bytearray()};open_streams=list(streams);started=time.monotonic();deadline=started+(LARGE_OUTER_SECONDS if measured else timeout)
 try:
  while open_streams:
   remaining=deadline-time.monotonic()
   if remaining<=0:raise ValueError('getter_command_timeout')
   ready,_,_=select.select(open_streams,[],[],min(remaining,1))
   for stream in ready:
    part=os.read(stream.fileno(),min(65536,limit+1-sum(map(len,streams.values()))))
    if not part:open_streams.remove(stream);continue
    streams[stream].extend(part)
    if sum(map(len,streams.values()))>limit:raise ValueError('getter_command_output_limit')
  code=process.wait(timeout=max(.01,deadline-time.monotonic()))
  return {'returncode':code,'stdoutRaw':streams[process.stdout].decode('utf-8','strict'),'stderrRaw':streams[process.stderr].decode('utf-8','strict')}
 finally:
  record={'returncode':process.poll(),'elapsedMs':int((time.monotonic()-started)*1000),'stdout':large_chunks(streams[process.stdout]),'stderr':large_chunks(streams[process.stderr]),'stdoutEof':process.stdout not in open_streams,'stderrEof':process.stderr not in open_streams,'publicTimeoutSeconds':LARGE_PUBLIC_SECONDS if measured else 30,'outerTimeoutSeconds':LARGE_OUTER_SECONDS if measured else timeout}
  GETTER_RECORDS[LARGE_PHASE if measured else 'lastBoundedCommand']=record
  if process.poll() is None:
   process.kill()
   try:process.wait(timeout=2)
   except subprocess.TimeoutExpired:pass
  for stream in streams:stream.close()

def getter_cli(words,owner=None):
 if words not in (['status'],['operations','list'],['routing','show']) or owner!=LARGE_OWNER:raise ValueError('getter_large_readonly_owner_required')
 cli=pathlib.Path(GETTER['cli']);fact=read_fixed(cli,1048576);fact.pop('raw')
 if fact['hashScope']!='full' or fact['sha256']!=GETTER['manifest']['launcherSha256']:raise ValueError('getter_cli_changed')
 environment=public_cli_environment(LAUNCH['adbPath'],cli,LAUNCH['environment'])
 args=['--json','--android','--serial','emulator-5682','--timeout-seconds',str(LARGE_PUBLIC_SECONDS if words==['routing','show'] else 30),'--controller-id',LARGE_OWNER,*words]
 result=getter_binary(cli,fact['generation'],args,environment,limit=LARGE_OUTPUT_LIMIT if words==['routing','show'] else 8388608)
 try:result['stdout']=json.loads(result['stdoutRaw'])
 except (ValueError,TypeError):result['stdout']=None
 return result

def large_reply(record,kind):
 value=getter_envelope(record,LARGE_OWNER,0)
 if value is None:raise ValueError('getter_large_reply_not_final')
 data=value.get('data',{})
 if kind=='status' and (data.get('runtimeRunning') is not False or data.get('runtimeObservation')!='stopped'):raise ValueError('getter_large_runtime_not_off')
 if kind=='operations' and data.get('operations')!=[]:raise ValueError('getter_large_operations_changed')
 return value

def large_semantic(value):
 data=value.get('data')
 if not isinstance(data,dict) or set(data)!={'routing'} or not isinstance(data['routing'],dict):raise ValueError('getter_large_routing_schema')
 routing=data['routing']
 if set(routing)!={'type','version','exported_at','rules'} or routing['type']!='vpn_control_routing_rules' or type(routing['version'])is not int or routing['version']!=7 or not isinstance(routing['exported_at'],str) or not routing['exported_at'] or not isinstance(routing['rules'],dict):raise ValueError('getter_large_routing_schema')
 # Only this generated timestamp is excluded. Every rule field, list order,
 # type and value remains in the canonical full semantic bytes.
 return json.dumps({key:routing[key] for key in ('type','version','rules')},sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode('utf-8')

def large_small_record(record):
 return {'returncode':record['returncode'],'stdout':large_chunks(record['stdoutRaw'].encode('utf-8')),'stderr':large_chunks(record['stderrRaw'].encode('utf-8'))}

def observed_getter(directory):
 global GETTER_RECORDS,GETTER_APK_PASS,LARGE_PHASE
 GETTER_RECORDS={};stage=[];failure=None;admitted=False;semantics=[]
 try:
  stage.append(getter_stage());getter_generation(directory)
  GETTER_APK_PASS='Before';apk=getter_apk();GETTER_RECORDS['observedPackageBefore']=apk
  if apk!=GETTER['packageSha256']:raise ValueError('getter_package_changed')
  status=getter_cli(['status'],LARGE_OWNER);before=large_reply(status,'status')['data'];GETTER_RECORDS['statusBefore']=large_small_record(status)
  operations=getter_cli(['operations','list'],LARGE_OWNER);large_reply(operations,'operations');GETTER_RECORDS['operationsBefore']=large_small_record(operations)
  for phase in ('routingBefore','routingAfter'):
   getter_generation(directory)
   LARGE_PHASE=phase;record=getter_cli(['routing','show'],LARGE_OWNER);value=large_reply(record,'routing');semantic=large_semantic(value);semantics.append(semantic)
   GETTER_RECORDS[phase]['envelope']={key:value.get(key) for key in ('schemaVersion','controllerId','requestId','ok','code','final','configurationRevision','operationId','restartRequired','warnings')}
   GETTER_RECORDS[phase]['semanticSha256']=hashlib.sha256(semantic).hexdigest();GETTER_RECORDS[phase]['semanticBytes']=len(semantic)
   GETTER_RECORDS[phase]['ruleValueCounts']={key:len(value['data']['routing']['rules'][key]) for key in ('proxy_packages','direct_domain_suffixes') if isinstance(value['data']['routing']['rules'].get(key),list)}
   if len(semantics)==2 and semantics[0]!=semantic:raise ValueError('getter_large_semantic_changed')
  operations=getter_cli(['operations','list'],LARGE_OWNER);large_reply(operations,'operations');GETTER_RECORDS['operationsAfter']=large_small_record(operations)
  status=getter_cli(['status'],LARGE_OWNER);after=large_reply(status,'status')['data'];GETTER_RECORDS['statusAfter']=large_small_record(status)
  if before!=after:raise ValueError('getter_large_status_changed')
  GETTER_APK_PASS='After';apk=getter_apk();GETTER_RECORDS['observedPackageAfter']=apk
  if apk!=GETTER['packageSha256']:raise ValueError('getter_package_changed')
  getter_generation(directory);stage.append(getter_stage())
  if stage[0]!=stage[1]:raise ValueError('getter_stage_generation_changed')
  admitted=True
 except (ValueError,OSError,KeyError,TypeError,UnicodeError,subprocess.TimeoutExpired) as error:
  failure=str(error) if isinstance(error,ValueError) and re.fullmatch(r'(?:getter|coldboot|census|alias)_[a-z_]{1,72}',str(error)) else 'getter_guard_rejected'
 return {'state':'current-large-routing-observed' if admitted else 'diagnostic-only','reason':failure,'currentRoutingVerified':admitted,'productAdmitted':False,'acceptanceComplete':False,'records':GETTER_RECORDS,'cliStagePins':stage,'historicalUnknownsPreserved':True,'semanticComparison':'full-type-version-rules-excluding-generated-exported_at-only'}
'''


def prepare(root:Path,reservation:dict)->dict:
    source=Path(original.__file__).absolute();pin,raw=availability._snapshot(source)
    if hashlib.sha256(raw).hexdigest()!=SOURCE:raise ValueError('getter_consumed_source_changed')
    prepared=original.prepare(root,reservation)
    own=Path(__file__).absolute();own_pin,own_raw=availability._snapshot(own)
    prepared['snapshots'].update({source:(pin,raw),own:(own_pin,own_raw)})
    tree=ast.parse(prepared['program']);names={'getter_bounded','getter_cli','current_getter','observed_getter'}
    if {n.name for n in tree.body if isinstance(n,ast.FunctionDef)and n.name in names}!=names:raise ValueError('getter_large_composition_changed')
    tree.body=[n for n in tree.body if not isinstance(n,ast.FunctionDef)or n.name not in names]
    if ast.unparse(tree.body[-1])!='coldboot_dispatch()':raise ValueError('getter_dispatch_changed')
    tree.body.pop()
    template=ast.literal_eval(next(n.value for n in ast.parse(own_raw).body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='_OBSERVER' for t in n.targets)))
    prepared['program']=ast.unparse(tree)+'\n'+template.replace('__OWNER__',repr(OWNER))+'\ncoldboot_dispatch()\n'
    compile(prepared['program'],'<fixed-API35-large-routing-observer>','exec');original.validate_readonly(prepared['program']);original.guard_prepared(prepared);return prepared


def guard_prepared(prepared):original.guard_prepared(prepared)
def ssh_carrier(prepared):return original.ssh_carrier(prepared)
