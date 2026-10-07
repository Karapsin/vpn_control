"""Six fixed shell descriptor reads on the current admitted API35 generation.

No app_process inheritance, cleanup, update or mutation authority is inferred.
"""
from __future__ import annotations
import ast
import hashlib
from pathlib import Path
from . import android_api35_coldboot_product_observation as original
from . import android_shell_fd_probe as historical
from . import android_device_availability as availability

SOURCE='c908a23200cf633c9db6a2ccfc057f2e360267519153593a23c4471fbefe528b'
PROBE_SOURCE='21d78968b5810ca43d11009e1f0c56dece7493f7d1de83cb00cb28bec70531c4'
OWNER='d475487c-fe93-418c-9f10-5db954723a43'
_OBSERVER=r'''
FD_OWNER=__OWNER__
_frozen_parse_reply=parse_reply

def parse_reply(code,stdout,stderr):
 # Only the measured pre-open denial and our fixed fixture guard are labeled.
 # Unknown command failures retain the frozen parser's conservative result.
 value=_frozen_parse_reply(code,stdout,stderr)
 if value.get('state')=='command-failed' and stderr in (b"/system/bin/sh: can't open /system/build.prop: Permission denied\n",b"/system/bin/sh: can't open /system/etc/hosts: Permission denied\n",b'fd_probe_fixture_unreadable\n'):
  return {'state':'fixture-unreadable','exit':code,'phase':'fixture-before-descriptor-open'}
 return value

def fd_read(case):
 if case not in probe_commands():raise ValueError('fd_probe_fixed_command_required')
 path=pathlib.Path(LAUNCH['adbPath']);chain,name=parent_fds(path);fd=None;process=None;streams={};opened=[];timed_out=False
 argv=[str(path),'-s','emulator-5682','shell','-T',case['command']]
 record={'fd':case['fd'],'mode':case['mode'],'command':case['command'],'argvSha256':hashlib.sha256(json.dumps(argv,separators=(',',':')).encode()).hexdigest(),'exitCode':None,'stdoutBase64':'','stderrBase64':'','timedOut':False,'captureComplete':False}
 GETTER_RECORDS['shellFdReads'].append(record)
 try:
  fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=chain[-1]['fd']);expected=LAUNCH['adbFacts']['generation']
  if fp(os.fstat(fd))!=expected or fp(os.stat(name,dir_fd=chain[-1]['fd'],follow_symlinks=False))!=expected:raise ValueError('getter_adb_changed')
  guard_parents(chain)
  def drop():os.setgroups([1000]);os.setgid(1000);os.setuid(1000)
  process=subprocess.Popen(argv,executable='/proc/self/fd/'+str(fd),pass_fds=(fd,),env=LAUNCH['environment'],preexec_fn=drop,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
  streams={process.stdout:b'',process.stderr:b''};opened=list(streams);deadline=time.monotonic()+10
  while opened:
   remaining=deadline-time.monotonic()
   if remaining<=0:timed_out=True;raise ValueError('fd_probe_command_timeout')
   ready,_,_=select.select(opened,[],[],min(remaining,.25))
   for stream in ready:
    part=os.read(stream.fileno(),min(65536,4097-len(streams[stream])))
    if not part:opened.remove(stream);continue
    streams[stream]+=part
    if len(streams[stream])>4096:raise ValueError('fd_probe_output_limit')
  try:code=process.wait(timeout=max(.01,deadline-time.monotonic()))
  except subprocess.TimeoutExpired:timed_out=True;raise ValueError('fd_probe_command_timeout')
  guard_parents(chain)
  if fp(os.fstat(fd))!=expected or fp(os.stat(name,dir_fd=chain[-1]['fd'],follow_symlinks=False))!=expected:raise ValueError('getter_adb_changed')
  record['exitCode']=code;record['captureComplete']=True
  return parse_reply(code,streams[process.stdout],streams[process.stderr])
 finally:
  record['timedOut']=timed_out
  if process is not None:
   record['exitCode']=process.poll()
   record['stdoutBase64']=base64.b64encode(streams.get(process.stdout,b'')).decode()
   record['stderrBase64']=base64.b64encode(streams.get(process.stderr,b'')).decode()
   record['stdoutEof']=process.stdout not in opened;record['stderrEof']=process.stderr not in opened
   if process.poll() is None:
    process.kill()
    try:process.wait(timeout=2)
    except subprocess.TimeoutExpired:pass
   for stream in streams:stream.close()
  if fd is not None:os.close(fd)
  close_parents(chain)

def fd_guard_reply(record,kind):
 value=getter_envelope(record,FD_OWNER,0)
 if value is None:raise ValueError('fd_probe_public_owner_unavailable')
 data=value.get('data',{})
 if kind=='status' and (data.get('runtimeRunning') is not False or data.get('runtimeObservation')!='stopped'):raise ValueError('fd_probe_runtime_not_off')
 if kind=='operations' and data.get('operations')!=[]:raise ValueError('fd_probe_operations_changed')
 return data

def observed_getter(directory):
 global GETTER_RECORDS,GETTER_APK_PASS
 GETTER_RECORDS={'shellFdReads':[]};stage=[];failure=None;observed=None;closing=False
 try:
  stage.append(getter_stage());getter_generation(directory);GETTER_APK_PASS='Before'
  apk=getter_apk();GETTER_RECORDS['observedPackageBefore']=apk
  if apk!=GETTER['packageSha256']:raise ValueError('getter_package_changed')
  GETTER_RECORDS['statusBefore']=getter_cli(['status'],FD_OWNER);before=fd_guard_reply(GETTER_RECORDS['statusBefore'],'status')
  GETTER_RECORDS['operationsBefore']=getter_cli(['operations','list'],FD_OWNER);fd_guard_reply(GETTER_RECORDS['operationsBefore'],'operations')
  reads=[];probe_failure=None
  try:
   for case in probe_commands():reads.append({'fd':case['fd'],'mode':case['mode'],'result':fd_read(case)})
  except (ValueError,OSError,UnicodeError,subprocess.TimeoutExpired) as error:
   probe_failure=str(error) if isinstance(error,ValueError) and re.fullmatch(r'(?:fd_probe|getter)_[a-z_]{1,72}',str(error)) else 'fd_probe_command_unknown'
  GETTER_RECORDS['operationsAfter']=getter_cli(['operations','list'],FD_OWNER);fd_guard_reply(GETTER_RECORDS['operationsAfter'],'operations')
  GETTER_RECORDS['statusAfter']=getter_cli(['status'],FD_OWNER);after=fd_guard_reply(GETTER_RECORDS['statusAfter'],'status')
  if before!=after:raise ValueError('fd_probe_status_changed')
  GETTER_APK_PASS='After';apk=getter_apk();GETTER_RECORDS['observedPackageAfter']=apk
  if apk!=GETTER['packageSha256']:raise ValueError('getter_package_changed')
  getter_generation(directory);stage.append(getter_stage())
  if stage[0]!=stage[1]:raise ValueError('getter_stage_generation_changed')
  closing=True
  if probe_failure is not None:raise ValueError(probe_failure)
  if any(item['result'].get('state')=='fixture-unreadable' for item in reads):raise ValueError('fd_probe_fixture_unreadable')
  observed=classify(reads)
 except (ValueError,OSError,KeyError,TypeError,UnicodeError,subprocess.TimeoutExpired) as error:
  failure=str(error) if isinstance(error,ValueError) and re.fullmatch(r'(?:fd_probe|getter|coldboot|census|alias)_[a-z_]{1,72}',str(error)) else 'fd_probe_guard_rejected'
 return {'state':'current-shell-descriptors-observed' if observed is not None else 'diagnostic-only','reason':failure,'shellFdProbe':observed,'closingGuardsVerified':closing,'records':GETTER_RECORDS,'cliStagePins':stage,'productAdmitted':False,'acceptanceComplete':False,'historicalUnknownsPreserved':True,'appProcessInheritance':'not-tested','guestMutationPerformed':False}
'''


def _functions(raw):
    tree=ast.parse(raw);names={'probe_commands','parse_reply','classify'};nodes=[node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name in names]
    if len(nodes)!=3 or {node.name for node in nodes}!=names:raise ValueError('fd_probe_frozen_functions_changed')
    assignments={node.targets[0].id:ast.literal_eval(node.value) for node in tree.body if isinstance(node,ast.Assign) and isinstance(node.targets[0],ast.Name) and node.targets[0].id=='FORMAT'}
    if set(assignments)!={'FORMAT'}:raise ValueError('fd_probe_frozen_format_changed')
    # The historical source is SHA pinned by prepare. Rewrite only its two
    # fixed target literals; no path parameter or fallback is admitted.
    replacements=0
    for node in ast.walk(next(node for node in nodes if node.name=='probe_commands')):
        if isinstance(node,ast.Constant) and isinstance(node.value,str) and '/system/build.prop' in node.value:
            replacements+=node.value.count('/system/build.prop')
            if 'test ! -L /system/build.prop; ' in node.value:
                node.value=node.value.replace('test ! -L /system/build.prop; ',"{ test ! -L /system/etc/hosts && test -f /system/etc/hosts && test -r /system/etc/hosts; } || { printf 'fd_probe_fixture_unreadable\\n' >&2; exit 73; }; ")
            else:node.value=node.value.replace('/system/build.prop','/system/etc/hosts')
    if replacements!=2:raise ValueError('fd_probe_frozen_target_changed')
    return 'FORMAT='+repr(assignments['FORMAT'])+'\n'+ast.unparse(ast.Module(body=nodes,type_ignores=[]))+'\n'


def compose(program,probe_raw,observer_raw):
    tree=ast.parse(program);names={'current_getter','observed_getter'}
    if {node.name for node in tree.body if isinstance(node,ast.FunctionDef) and node.name in names}!=names:raise ValueError('fd_probe_composition_changed')
    tree.body=[node for node in tree.body if not isinstance(node,ast.FunctionDef) or node.name not in names]
    if ast.unparse(tree.body[-1])!='coldboot_dispatch()':raise ValueError('fd_probe_dispatch_changed')
    tree.body.pop();template=ast.literal_eval(next(node.value for node in ast.parse(observer_raw).body if isinstance(node,ast.Assign) and any(isinstance(target,ast.Name) and target.id=='_OBSERVER' for target in node.targets)))
    result=ast.unparse(tree)+'\n'+_functions(probe_raw)+template.replace('__OWNER__',repr(OWNER))+'\ncoldboot_dispatch()\n'
    compile(result,'<fixed-current-api35-fd-observer>','exec');original.validate_readonly(result);return result


def prepare(root:Path,reservation:dict)->dict:
    pins={}
    for path,digest in ((Path(original.__file__).absolute(),SOURCE),(Path(historical.__file__).absolute(),PROBE_SOURCE)):
        pin,raw=availability._snapshot(path)
        if hashlib.sha256(raw).hexdigest()!=digest:raise ValueError('fd_probe_consumed_source_changed')
        pins[path]=(pin,raw)
    prepared=original.prepare(root,reservation);own=Path(__file__).absolute();own_pin,own_raw=availability._snapshot(own);pins[own]=(own_pin,own_raw)
    prepared['snapshots'].update(pins);prepared['program']=compose(prepared['program'],pins[Path(historical.__file__).absolute()][1],own_raw)
    guard_prepared(prepared);return prepared


def guard_prepared(prepared):original.guard_prepared(prepared)
def ssh_carrier(prepared):return original.ssh_carrier(prepared)
