"""Closed installer component transport; external JDK is not package acceptance.

The existing native caller supplies its measured device/intent guard and a durable
private capture writer. This module grants no guest, installer or TLS authority.
The frozen read backend remains unchanged. No filesystem payload commands exist.
"""
from __future__ import annotations
import ast
import hashlib
from pathlib import Path
from . import android_external_java_component_transport as readonly

READ_SOURCE = '20aa6be0a8b6de65fa2d68ae8801bbdaf7426be31de8c28640144e1a63956e0c'

def _bounded_source():
    """Only the frozen reader's credential hook/name change; capture is identical."""
    tree=ast.parse(readonly.bounded_source._OBSERVER)
    node=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='getter_bounded')
    node.name='command_bounded'
    drop=next(n for n in node.body if isinstance(n,ast.FunctionDef) and n.name=='drop')
    drop.body=ast.parse("command_host_guard()\nif COMMAND_HOST['uid']==0:\n os.setgroups([1000]);os.setgid(1000);os.setuid(1000)\n").body
    node.body.insert(1,ast.parse('command_host_guard()').body[0])
    return ast.unparse(ast.fix_missing_locations(node))+'\n'

REMOTE = r'''
def command_host_identity():
 value={'uid':os.getuid(),'euid':os.geteuid(),'gid':os.getgid(),'egid':os.getegid(),'groups':sorted(os.getgroups())}
 if value['uid']!=value['euid'] or value['gid']!=value['egid'] or not ((value['uid']==0 and value['gid']==0) or (value['uid']==1000 and value['gid']==1000)) or len(value['groups'])>64 or any(type(x)is not int or x<0 for x in value['groups']):raise ValueError('command_host_identity_unadmitted')
 return value

def command_host_guard():
 if command_host_identity()!=COMMAND_HOST:raise ValueError('command_host_identity_changed')

def command_request(words,owner,revision,phase):
 if type(words)is not list or any(type(x)is not str for x in words):raise ValueError('command_catalogue_required')
 if type(owner)is not str or re.fullmatch('[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}',owner)is None:raise ValueError('command_owner_required')
 if type(revision)is not int or revision<0:raise ValueError('command_revision_required')
 baseline=words in (['status'],['operations','list'],['source','show'],['settings','show'],['locations','list'],['stats'],['routing','show'],['routing','export','--output','-'],['diagnostics','export','--output','-'])
 operation=len(words)==3 and words[:2] in (['operations','status'],['operations','wait'],['operations','cancel']) and re.fullmatch('[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}',words[2])is not None
 if phase=='baseline' and baseline:return 30,False,False,False
 if phase=='reconcile' and words==['updates','status']:return 30,False,False,False
 if phase in ('operation-status','operation-wait','operation-cancel') and operation and words[1]==phase[10:]:return (120 if words[1]=='wait' else 30),False,False,words[1]=='cancel'
 if phase=='check' and words==['updates','check']:return 180,False,False,True
 if phase=='download' and words==['updates','download']:return 240,False,False,True
 if phase=='install-noninteractive' and words==['updates','install']:return 30,False,False,True
 if phase=='install-interactive' and words==['updates','install']:return 30,True,True,True
 raise ValueError('command_catalogue_required')

def command_binary(path,expected,args,environment,limit,timeout):
 chain,name=parent_fds(path);fd=None
 try:
  fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=chain[-1]['fd'])
  if fp(os.fstat(fd))!=expected or fp(os.stat(name,dir_fd=chain[-1]['fd'],follow_symlinks=False))!=expected:raise ValueError('getter_binary_changed')
  guard_parents(chain)
  result=command_bounded([str(path),*args],fd,environment,limit=limit,timeout=timeout)
  guard_parents(chain)
  if fp(os.fstat(fd))!=expected or fp(os.stat(name,dir_fd=chain[-1]['fd'],follow_symlinks=False))!=expected:raise ValueError('getter_binary_changed')
  return result
 finally:
  if fd is not None:os.close(fd)
  close_parents(chain)

def component_command(words,owner,revision,phase,guard,capture,deadline=None):
 import base64,copy,math
 timeout,interactive,asynchronous,mutation=command_request(words,owner,revision,phase)
 if not callable(guard) or not callable(capture):raise ValueError('command_caller_fences_required')
 if deadline is not None:
  if type(deadline)not in (int,float) or not math.isfinite(deadline) or not 0<deadline<=timeout:raise ValueError('command_deadline_invalid')
  timeout=deadline
 if {k:GETTER[k] for k in ('cli','stageId','packageSha256','manifestSha256')}!=EXTERNAL['getterIdentity']:raise ValueError('component_stage_identity_changed')
 if set(LAUNCH['environment'])!={'ANDROID_AVD_HOME','ANDROID_HOME','ANDROID_SDK_ROOT','HOME','LOGNAME','PATH','USER'}:raise ValueError('component_fixed_environment_required')
 command_host_guard();guard();external_jdk_guard();stage=getter_stage();start=len(GETTER_RECORDS.get('captures',[]));result=None
 try:
  if mutation:
   # A positive STATUS immediately before admission, never a CONFLICT payload.
   status=component_command(['status'],owner,revision,'baseline',guard,capture,deadline=min(30,timeout));value=status.get('stdout')
   start=len(GETTER_RECORDS.get('captures',[]))
   if not isinstance(value,dict) or value.get('ok')is not True or value.get('final')is not True or value.get('code')!='OK' or value.get('controllerId')!=owner or type(value.get('configurationRevision'))is not int or value['configurationRevision']!=revision or not isinstance(value.get('data'),dict) or value['data'].get('runtimeRunning')is not False:raise ValueError('command_owner_changed')
   guard();external_jdk_guard()
   if getter_stage()!=stage:raise ValueError('component_stage_generation_changed')
  jdk=EXTERNAL['selectedJdk'];path=pathlib.Path(jdk['root'])/'bin/java';appdir=str(pathlib.Path(GETTER['cli']).parent.parent/'lib/app')
  args=[*[option.replace('$APPDIR',appdir) for option in EXTERNAL['javaOptions']],'-cp',':'.join(appdir+'/'+name for name in EXTERNAL['classpath']),'com.kardinal.vpncontrol.desktop.MainKt']
  args+=['--json','--android','--serial',EXTERNAL['serial'],'--timeout-seconds',str(max(1,math.ceil(timeout))), '--controller-id',owner]
  if mutation:args+=['--if-revision',str(revision)]
  if interactive:args+=['--interactive']
  if asynchronous:args+=['--async']
  args+=words
  environment=public_cli_environment(LAUNCH['adbPath'],pathlib.Path(GETTER['cli']),LAUNCH['environment'])
  result=command_binary(path,jdk['files']['bin/java']['generation'],args,environment,limit=1048576,timeout=timeout+15)
 finally:
  # Includes timeout, undecodable UTF8 and generation loss. The caller must write
  # this create-only private record before any semantic result validation.
  try:capture({'phase':phase,'owner':owner,'revision':revision,'words':words[:],'stdoutRaw':result.get('stdoutRaw') if result else None,'stderrRaw':result.get('stderrRaw') if result else None,'returncode':result.get('returncode') if result else None,'captures':copy.deepcopy(GETTER_RECORDS.get('captures',[])[start:]),'componentRuntime':'EXTERNAL_JDK','installedLauncherAccepted':False,'bundledRuntimeAccepted':False})
  finally:
   try:command_host_guard();guard()
   finally:
    try:external_jdk_guard()
    finally:
     if getter_stage()!=stage:raise ValueError('component_stage_generation_changed')
 if type(result.get('returncode'))is not int or result['returncode'] not in (0,1,2,130) or type(result.get('stdoutRaw'))is not str or result.get('stderrRaw')!='':raise ValueError('command_transport_unknown')
 entries=GETTER_RECORDS.get('captures',[])[start:]
 if len(entries)!=1:raise ValueError('command_capture_unknown')
 entry=entries[0]
 if entry.get('failure')is not None or type(entry.get('returncode'))is not int or entry['returncode']!=result['returncode'] or entry.get('stdoutBase64')!=base64.b64encode(result['stdoutRaw'].encode()).decode() or entry.get('stderrBase64')!='' or type(entry.get('stdoutBytes'))is not int or entry['stdoutBytes']!=len(result['stdoutRaw'].encode()) or type(entry.get('stderrBytes'))is not int or entry['stderrBytes']!=0:raise ValueError('command_capture_unknown')
 raw_export=words in (['routing','export','--output','-'],['diagnostics','export','--output','-'])
 if not raw_export:
  try:result['stdout']=json.loads(result['stdoutRaw'])
  except (ValueError,TypeError):raise ValueError('command_json_invalid')
  if not isinstance(result['stdout'],dict):raise ValueError('command_json_invalid')
 result.update(componentRuntime='EXTERNAL_JDK',backendSourceSha256=EXTERNAL['backendSourceSha256'],commandTransportSha256=COMMAND_SOURCE_SHA,captureComplete=True,installedLauncherAccepted=False,bundledRuntimeAccepted=False)
 return result
'''

def prepare(root: Path, prepared: dict, device: str) -> tuple[dict, dict]:
    """Reuse every fixed source/config/JDK/stage input from c466 unchanged."""
    snapshot=readonly.availability._snapshot(Path(readonly.__file__).absolute())
    if hashlib.sha256(snapshot[1]).hexdigest()!=READ_SOURCE:
        raise ValueError('command_read_source_changed')
    binding=readonly.prepare_binding(root,prepared,device)
    readonly.install(prepared,binding)
    own=Path(__file__).absolute();pin=readonly.availability._snapshot(own)
    prepared['snapshots'][own]=pin
    tree=ast.parse(prepared['program'])
    names={'command_request','command_binary','component_command'}
    if any(isinstance(n,ast.FunctionDef) and n.name in names for n in tree.body):
        raise ValueError('command_backend_already_present')
    source=ast.parse('COMMAND_SOURCE_SHA='+repr(hashlib.sha256(pin[1]).hexdigest())+'\n'+REMOTE+'\n'+_bounded_source()+'\nCOMMAND_HOST=command_host_identity()\n')
    tree.body[-1:-1]=source.body
    prepared['program']=ast.unparse(tree)+'\n'
    prepared['commandProgramSha256']=hashlib.sha256(prepared['program'].encode()).hexdigest()
    compile(prepared['program'],'<installer-component-command>','exec')
    readonly.guard(prepared)
    return prepared,binding

def namespace_source(prepared:dict)->str:
    """Source-closed prefix for an independently guarded installer worker.

    Initialization retains the frozen historical source checks. It does not run
    the coldboot dispatch or claim that its old epoch is current admission.
    The caller must hold prepare()'s local snapshots through dispatch.
    """
    readonly.guard(prepared)
    raw=prepared['program']
    if hashlib.sha256(raw.encode()).hexdigest()!=prepared.get('commandProgramSha256'):
        raise ValueError('command_program_changed')
    tree=ast.parse(raw)
    if ast.dump(tree.body[-1])!=ast.dump(ast.parse('coldboot_dispatch()').body[0]):
        raise ValueError('command_dispatch_changed')
    tree.body.pop()
    source=ast.unparse(tree)+'\n'
    compile(source,'<installer-component-namespace>','exec')
    readonly.guard(prepared)
    return source
