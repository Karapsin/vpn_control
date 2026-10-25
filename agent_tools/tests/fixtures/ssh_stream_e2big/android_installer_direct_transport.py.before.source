"""Fixed API35 full-update source launcher, original worker observer and mailbox.

No import submits a job. Native operators supply freshly admitted inputs; source
assembly and typed DTOs never manufacture current device/lease/custody authority.
No caller command/program/path selector, lease adoption, retry or signal API.
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
import selectors
import shlex
import stat
import subprocess
import sys
import time
import types
import uuid
from . import android_installer_component_bundle as bundle
from . import android_installer_outer_transport as outer

PRODUCT=outer.UPDATE_PRODUCT
BASE=outer.UPDATE_BASE
TARGET=outer.UPDATE_TARGET
SIGNER=outer.UPDATE_SIGNER
MAX_PROGRAM=8*1024*1024
MAX_RAW=8*1024*1024
CHUNK=524288
_HOST='archlinux'
_DEVICE='android-api35'


def require(value,code):
    if not value:raise ValueError(code)


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()+b'\n'


def equal(first,second):return canonical(first)==canonical(second)


def sha(raw):return hashlib.sha256(raw).hexdigest()


def correlation(value):
    require(type(value)is str and str(uuid.UUID(value))==value,'direct_correlation_invalid')
    return value


def principal(value):
    require(type(value)is dict and set(value)=={'uid','euid','gid','egid','groups'},'direct_principal_invalid')
    require(all(type(value[n])is int and value[n]==0 for n in ('uid','euid','gid','egid')),'direct_root_receiver_required')
    require(type(value['groups'])is list and value['groups'] and all(type(n)is int and n>=0 for n in value['groups']) and value['groups']==sorted(set(value['groups'])),'direct_principal_invalid')
    return json.loads(canonical(value))


def posix():
    require(os.name=='posix' and all(callable(getattr(os,n,None))for n in ('getuid','geteuid','getgid','getegid','getgroups','setsid')) and all(hasattr(os,n)for n in ('O_NOFOLLOW','O_NONBLOCK','O_DIRECTORY')),'direct_posix_required')


def snapshot(path,limit=MAX_PROGRAM,private=False):
    posix();path=Path(path);chain,parents=bundle._parents(path.parent);fd=None
    try:
        fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=chain[-1][1]);info=os.fstat(fd);generation=bundle._pin(info)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_uid==os.getuid() and 0<=info.st_size<=limit and (not private or stat.S_IMODE(info.st_mode)==0o600),'direct_file_invalid')
        raw=bytearray()
        while block:=os.read(fd,min(CHUNK,limit+1-len(raw))):
            raw.extend(block);require(len(raw)<=limit,'direct_file_limit')
        require(len(raw)==info.st_size and equal(bundle._pin(os.fstat(fd)),generation) and equal(bundle._pin(os.stat(path.name,dir_fd=chain[-1][1],follow_symlinks=False)),generation),'direct_file_changed')
        for name,ancestor in chain:
            require(equal(bundle._pin(os.fstat(ancestor))[:5],parents[name]) and equal(bundle._pin(os.stat(name,follow_symlinks=False))[:5],parents[name]),'direct_parent_changed')
        return bytes(raw),{'path':str(path),'generation':generation,'parents':parents,'sha256':sha(raw)}
    finally:
        if fd is not None:os.close(fd)
        bundle._close(chain)


def future_inputs(value,remote_root):
    """Type-preserving future bindings; no booleans establish native authority."""
    keys={'schema','host','device','api','serial','correlationId','productSourceSha','expectedOwner','expectedRevision','expectedAvd','hostBootId','hostPrincipal','reservation','historicalProducer','assetAuthority'}
    require(type(value)is dict and set(value)==keys,'direct_inputs_invalid')
    require(type(value['schema'])is int and value['schema']==1 and value['host']==_HOST and value['device']==_DEVICE and type(value['api'])is int and value['api']==35 and value['serial']=='emulator-5682' and value['productSourceSha']==PRODUCT,'direct_inputs_crossed')
    for key in ('correlationId','expectedOwner','hostBootId'):correlation(value[key])
    require(type(value['expectedRevision'])is int and value['expectedRevision']>=0 and type(value['expectedAvd'])is str and value['expectedAvd'] and len(value['expectedAvd'])<=128,'direct_owner_invalid')
    principal(value['hostPrincipal'])
    require(type(value['reservation'])is dict and value['reservation'] and type(value['historicalProducer'])is dict and value['historicalProducer'],'direct_original_initializer_required')
    custody_shape(value['assetAuthority'],remote_root,value['correlationId'])
    return json.loads(canonical(value))


def _source_set(root):
    names=(*bundle.FILES,'agent_tools/android_installer_outer_transport.py','agent_tools/android_installer_direct_transport.py',
           'agent_tools/android_installer_asset_staging.py','agent_tools/tests/test_android_installer_asset_staging.py',
           'agent_tools/ssh_transport.py','agent_tools/ssh_channel_selection.py','agent_tools/ssh_fresh_nested_channel.py',
           'agent_tools/ssh_connection_session.py','agent_tools/ssh_gateway_tmux_master.py','agent_tools/ssh_gateway_tmux_master_ssh.py','agent_tools/ssh_tmux_mcp_adapter.py')
    return {name:snapshot(Path(root)/name,private=False)[1] for name in names}


def _source_guard(root,pins):
    for name,pin in pins.items():
        require(equal(snapshot(Path(root)/name,private=False)[1],pin),'direct_source_changed')
    # All source body reads precede the final held/named generation-only pass.
    held=[]
    try:
        for name,pin in pins.items():
            chain,parents=bundle._parents((Path(root)/name).parent)
            try:fd=os.open(Path(name).name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=chain[-1][1])
            except BaseException:bundle._close(chain);raise
            held.append((Path(root)/name,pin,chain,parents,fd))
        for path,pin,chain,parents,fd in held:
            require(equal(bundle._pin(os.fstat(fd)),pin['generation']) and equal(bundle._pin(os.stat(path.name,dir_fd=chain[-1][1],follow_symlinks=False)),pin['generation']) and equal(parents,pin['parents']),'direct_source_changed')
            for name,ancestor in chain:require(equal(bundle._pin(os.fstat(ancestor))[:5],parents[name]) and equal(bundle._pin(os.stat(name,follow_symlinks=False))[:5],parents[name]),'direct_source_parent_changed')
    finally:
        for _,_,chain,_,fd in reversed(held):os.close(fd);bundle._close(chain)


def _root_from_program(source):
    nodes=[n.value for n in ast.parse(source).body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='ROOT'for t in n.targets)]
    require(len(nodes)==1 and isinstance(nodes[0],ast.Call) and ast.unparse(nodes[0].func)=='pathlib.Path' and len(nodes[0].args)==1 and not nodes[0].keywords and isinstance(nodes[0].args[0],ast.Constant)and type(nodes[0].args[0].value)is str,'direct_root_binding_invalid')
    root=Path(nodes[0].args[0].value);require(root.is_absolute()and '..'not in root.parts,'direct_root_binding_invalid');return root


def assemble(root,inputs,receipt):
    """Actual owned getter/command/bundle factories, no caller source accepted."""
    from . import android_api35_coldboot_product_observation as getter
    from . import android_component_command_transport as command
    owned=getter.prepare_existing_readonly(Path(root),inputs['reservation'],inputs['correlationId'],inputs['historicalProducer'])
    prepared,_=command.prepare(Path(root),owned,'android-api35')
    prefix=bundle.carrier_source(receipt,prepared,str(uuid.uuid5(uuid.UUID(inputs['correlationId']),'complete-update-tool-bundle')))
    remote_root=_root_from_program(prefix);inputs=future_inputs(inputs,remote_root)
    launch=command.readonly._assignment(ast.parse(prepared['program']),'LAUNCH');getter_dto=command.readonly._assignment(ast.parse(prepared['program']),'GETTER')
    require(launch['device']=='api35' and launch['avd']==inputs['expectedAvd'] and equal(launch['intent']['reservation'],inputs['reservation']) and getter_dto['packageSha256']==BASE,'direct_initializer_crossed')
    baseline={'host':_HOST,'device':_DEVICE,'correlationId':str(uuid.uuid5(uuid.UUID(inputs['correlationId']),'complete-update-backup')),'sourceSha':PRODUCT,'expectedOwner':inputs['expectedOwner'],'expectedRevision':inputs['expectedRevision'],'expectedAvd':inputs['expectedAvd'],'expectedApi':35,'packageSha256':BASE,'reservation':inputs['reservation']}
    pair={'sourceSha':PRODUCT,'baseArtifactId':'sha256-'+BASE,'baseSha256':BASE,'baseVersion':'2.2.2','baseCode':16840,'targetArtifactId':'sha256-'+TARGET,'targetSha256':TARGET,'targetVersion':'2.2.3','targetCode':16860,'signerSha256':SIGNER}
    raw,pin=snapshot(Path(outer.__file__),private=False)
    packet={'schema':1,'kind':'api35-complete-update-direct','correlationId':inputs['correlationId'],'productSourceSha':PRODUCT,'helperSourceEqualsProductCommit':False,'treeSha256':receipt['treeSha256'],'commandProgramSha256':prepared['commandProgramSha256'],'outerSourceSha256':pin['sha256'],'futureInputsSha256':sha(canonical(inputs))}
    packet_sha=sha(canonical(packet))
    direct_raw,_=snapshot(Path(__file__),private=False)
    definitions=worker_definitions_source(direct_raw)
    suffix=worker_bindings_source(inputs,remote_root,baseline,pair,packet_sha)
    source=(WORKER_GATE+prefix+'\n'+outer.outer_namespace_source(raw)+definitions+suffix+'\ndirect_entry()\n').encode()
    require(len(source)<=MAX_PROGRAM,'direct_program_limit');compile(source,'<fixed-complete-api35-update>','exec',dont_inherit=True)
    command.readonly.guard(prepared);bundle.load(receipt)
    return source,packet,prepared,remote_root


def write_once(directory,name,raw):
    require(type(raw)is bytes and re.fullmatch(r'[a-z0-9-]+\.(json|py|private)',name),'direct_journal_role_invalid')
    fd=os.open(Path(directory)/name,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        at=0
        while at<len(raw):
            count=os.write(fd,raw[at:at+CHUNK]);require(count>0,'direct_write_unknown');at+=count
        os.fsync(fd);pin=bundle._pin(os.fstat(fd))
        require(equal(pin,bundle._pin(os.stat(Path(directory)/name,follow_symlinks=False))),'direct_journal_changed')
    finally:os.close(fd)
    parent=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(parent)
    finally:os.close(parent)
    closed_raw,closed_pin=snapshot(Path(directory)/name,max(1,len(raw)+1),True)
    require(equal(closed_pin['generation'],pin)and closed_raw==raw,'direct_journal_changed')
    return closed_pin


def _capsule(root,corr):return Path(root)/'.runtime'/'parity-evidence'/('android-installer-direct-'+correlation(corr))


def prepare(root,inputs):
    """Local preparation only; current facts are still measured by native guards."""
    posix();root=Path(root).absolute()
    # Parse the canonical root from the typed custody path without discovering a
    # server path. The real factory must independently yield exactly this root.
    require(type(inputs)is dict and type(inputs.get('assetAuthority'))is dict,'direct_inputs_invalid')
    candidate=inputs['assetAuthority'].get('inputDirectory');require(type(candidate)is str,'direct_inputs_invalid')
    remote_root=Path(candidate).parent;inputs=future_inputs(inputs,remote_root)
    capsule=_capsule(root,inputs['correlationId']);require(not os.path.lexists(capsule),'direct_already_prepared')
    pins=_source_set(root);capsule.mkdir(mode=0o700)
    receipt=bundle.prepare(root,capsule/'tool-bundle',bundle.reviewed_tree(root)['treeSha256'])
    source,packet,prepared,actual_root=assemble(root,inputs,receipt)
    require(actual_root==remote_root,'direct_root_binding_invalid')
    chunks=[]
    for n,at in enumerate(range(0,len(source),CHUNK)):
        name=f'program-{n:04d}.py';part=source[at:at+CHUNK];pin=write_once(capsule,name,part);chunks.append({'name':name,'pin':pin})
    intent={'schema':1,'inputs':inputs,'packet':packet,'programSha256':sha(source),'programBytes':len(source),'chunks':chunks,'sources':pins,'toolReceipt':receipt,'remoteRoot':str(remote_root),'replayAllowed':False}
    write_once(capsule,'intent.json',canonical(intent));_source_guard(root,pins)
    return {'state':'prepared','correlationId':inputs['correlationId'],'packetSha256':sha(canonical(packet)),'programSha256':sha(source),'nativeSubmitted':False,'replayAllowed':False}


def custody_shape(authority,root,corr):
    """Pre-claim custody excludes a lease; no fabricated future FD pin."""
    require(type(authority)is dict and set(authority)=={'schema','correlationId','productSourceSha','inputDirectory','files','tlsReceipt'},'direct_custody_invalid')
    require(type(authority['schema'])is int and authority['schema']==1 and authority['correlationId']==corr and authority['productSourceSha']==PRODUCT,'direct_custody_crossed')
    directory=Path(root)/('android-complete-update-inputs-'+corr)
    require(authority['inputDirectory']==str(directory) and type(authority['files'])is dict and set(authority['files'])==set(outer.OUTER_FILES),'direct_custody_paths_changed')
    for name,pin in authority['files'].items():
        outer.outer_pin_shape(pin);require(pin['path']==str(directory/name),'direct_custody_paths_changed')
        if name.endswith('.apk'):require(pin['generation'][6]==45026948 and pin['sha256']==(BASE if name=='base.apk'else TARGET),'direct_apk_changed')
    outer.outer_pin_shape(authority['tlsReceipt']);require(authority['tlsReceipt']['path']==str(directory/'receipt.json'),'direct_custody_paths_changed')
    return json.loads(canonical(authority))


def shared_claim_source():
    """Original canonical flock/O_EXCL claim, one guarded mixed-principal branch.

    The extra ROOT is from the authenticated original carrier, not an ingress
    option. The original source and its unique replaced check are pinned.
    """
    from . import android_installer_dispatch as dispatch
    old="if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700: emit('unknown','root_unsafe')"
    require(dispatch._REMOTE_SHARED.count(old)==1,'direct_shared_claim_source_changed')
    new="""ordinary=(info.st_uid==os.getuid())
privileged=(root_raw==ADMITTED_ROOT and info.st_uid==1000 and info.st_gid==1000 and os.getuid()==0 and os.geteuid()==0 and os.getgid()==0 and os.getegid()==0)
if not stat.S_ISDIR(info.st_mode) or not (ordinary or privileged) or stat.S_IMODE(info.st_mode)!=0o700: emit('unknown','root_unsafe')"""
    return dispatch._REMOTE_SHARED.replace(old,new)


def runtime_source(raw):
    """Source-only finite definitions. Native role entry is added separately."""
    tree=ast.parse(raw)
    names={'require','canonical','equal','sha','correlation','principal','posix','write_once'}
    nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name in names]
    require({n.name for n in nodes}==names,'direct_runtime_source_changed')
    return 'import hashlib,json,os,re,stat,time,uuid\nfrom pathlib import Path\nCHUNK=524288\n'+ast.unparse(ast.Module(body=nodes,type_ignores=[]))+'\n'


def worker_definitions_source(raw):
    """Exact finite emitted worker definitions and production imports."""
    names={'require','canonical','equal','sha','correlation','posix','snapshot','write_once','claim_after_backup','_direct_prepare','direct_entry'}
    nodes=[n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)and n.name in names]
    require({n.name for n in nodes}==names,'direct_runtime_source_changed')
    return 'import contextlib,hashlib,io,json,os,re,stat,sys,time,uuid\nfrom pathlib import Path\nbundle=COMPONENT_BUNDLE\nCHUNK=524288\nMAX_PROGRAM=8388608\n'+ast.unparse(ast.Module(body=nodes,type_ignores=[]))+'\n_SHARED_CLAIM_SOURCE='+repr(shared_claim_source())+'\n'


def worker_bindings_source(inputs,remote_root,baseline,pair,packet_sha):
    """Fixed literals emitted after assemble authenticates every future input."""
    admission={**baseline,'correlationId':str(uuid.uuid5(uuid.UUID(inputs['correlationId']),'complete-update-readonly-admission'))}
    return '\nUPDATE_CORRELATION='+repr(inputs['correlationId'])+'\nUPDATE_BASELINE_REQUEST='+repr(admission)+'\nDIRECT_BACKUP_REQUEST='+repr(baseline)+'\nUPDATE_PAIR='+repr(pair)+'\nUPDATE_SOURCE_PACKET_SHA='+repr(packet_sha)+'\nDIRECT_CUSTODY='+repr(inputs['assetAuthority'])+'\nDIRECT_INPUTS='+repr(inputs)+'\n_DIRECT_AUTHENTICATED_ROOT=Path('+repr(str(remote_root))+')\nDIRECT_JOURNAL=Path(os.environ.pop("DIRECT_JOURNAL"))\n'


# The actual emitted collector is tested with harmless local worker programs.
# A fixed full-update worker is its sole production input, source hash-bound by
# the framed bootstrap; this function is not a public command selector.
SUPERVISOR = r'''
import hashlib,json,os,selectors,stat,subprocess,sys,time
from pathlib import Path
ROOT=Path(sys.argv[1]);EXPECTED=sys.argv[2];DEADLINE=1800;CAP=8388608;CHUNK=524288

def raw(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()+b'\n'
def pin(info):return [info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns]
def write(name,body):
 fd=os.open(ROOT/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  offset=0
  while offset<len(body):
   size=os.write(fd,body[offset:offset+CHUNK])
   if size<=0:raise ValueError('direct_write_unknown')
   offset+=size
  os.fsync(fd)
 finally:os.close(fd)
 directory=os.open(ROOT,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(directory)
 finally:os.close(directory)
 return {'name':name,'bytes':len(body),'sha256':hashlib.sha256(body).hexdigest()}
def birth(pid):
 body=Path('/proc/'+str(pid)+'/stat').read_bytes();end=body.rfind(b') ')
 if end<0:raise ValueError('direct_birth_unknown')
 fields=body[end+2:].split()
 return {'pid':pid,'startTicks':int(fields[19]),'bootId':Path('/proc/sys/kernel/random/boot_id').read_text().strip()}
root_info=ROOT.lstat()
if not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid!=os.getuid() or stat.S_IMODE(root_info.st_mode)!=0o700:raise ValueError('direct_leaf_unsafe')
worker_fd=os.open(ROOT/'worker.py',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
held=os.fstat(worker_fd)
if not stat.S_ISREG(held.st_mode)or held.st_nlink!=1 or stat.S_IMODE(held.st_mode)!=0o600 or held.st_uid!=os.getuid():raise ValueError('direct_worker_unsafe')
body=b''
while block:=os.read(worker_fd,CHUNK):
 body+=block
 if len(body)>8388608:raise ValueError('direct_worker_limit')
if hashlib.sha256(body).hexdigest()!=EXPECTED or pin(os.fstat(worker_fd))!=pin(held) or pin((ROOT/'worker.py').lstat())!=pin(held):raise ValueError('direct_worker_changed')
os.lseek(worker_fd,0,os.SEEK_SET)
write('supervisor.json',raw({'schema':1,'identity':birth(os.getpid()),'workerSha256':EXPECTED,'replayAllowed':False}))
# No worker is released until the accepted original supervisor is journaled.
gate_read,gate_write=os.pipe()
environment=os.environ.copy();environment['DIRECT_GATE_FD']=str(gate_read)
child=subprocess.Popen([sys.executable,'-I','-u','-B','/proc/self/fd/'+str(worker_fd)],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,pass_fds=(worker_fd,gate_read),env=environment,start_new_session=True)
write('worker.json',raw({'schema':1,'identity':birth(child.pid),'sourceGeneration':pin(held),'workerSha256':EXPECTED,'replayAllowed':False}))
os.close(gate_read)
if pin(os.fstat(worker_fd))!=pin(held) or pin((ROOT/'worker.py').lstat())!=pin(held):raise ValueError('direct_worker_changed')
os.write(gate_write,b'GO\n');os.close(gate_write)
selector=selectors.DefaultSelector();eof={'stdout':False,'stderr':False};parts={'stdout':[],'stderr':[]};hashes={name:hashlib.sha256()for name in eof};lengths={name:0 for name in eof}
for name,stream in [('stdout',child.stdout),('stderr',child.stderr)]:os.set_blocking(stream.fileno(),False);selector.register(stream,selectors.EVENT_READ,name)
started=time.monotonic();reason=None
while selector.get_map():
 if time.monotonic()-started>DEADLINE:reason='direct_observation_timeout';break
 for key,_ in selector.select(.2):
  block=os.read(key.fileobj.fileno(),CHUNK)
  name=key.data
  if not block:eof[name]=True;selector.unregister(key.fileobj);continue
  # Raw retained before classification. Overflow does not authorize replay or
  # killing the installer; same original supervisor/worker identities persist.
  record=write(name+'-'+str(len(parts[name])).zfill(5)+'.private',block);parts[name].append(record);hashes[name].update(block);lengths[name]+=len(block)
  if sum(lengths.values())>CAP:reason='direct_raw_limit';break
 if reason:break
rc=child.poll()
if all(eof.values()):rc=child.wait(timeout=5)
write('terminal.json',raw({'schema':1,'reason':reason,'returncode':rc,'eof':eof,'raw':{name:{'bytes':lengths[name],'sha256':hashes[name].hexdigest(),'chunks':parts[name]}for name in eof},'workerSha256':EXPECTED,'replayAllowed':False}))
os.close(worker_fd)
'''


def supervisor_source():
    compile(SUPERVISOR,'<fixed-update-supervisor>','exec',dont_inherit=True)
    return SUPERVISOR.encode()

WORKER_GATE="import os as _direct_gate_os\n_direct_gate_fd=int(_direct_gate_os.environ.pop('DIRECT_GATE_FD'))\n_direct_go=_direct_gate_os.read(_direct_gate_fd,4)\n_direct_gate_os.close(_direct_gate_fd)\nif _direct_go!=b'GO\\n':raise ValueError('direct_dispatch_gate_missing')\n"


def saved_terminal(directory,expected_source):
    """Read only original capture; missing terminal/EOF never starts a worker."""
    directory=Path(directory)
    try:
        raw,pin=snapshot(directory/'terminal.json',65536,True);value=json.loads(raw)
        require(type(value)is dict and set(value)=={'schema','reason','returncode','eof','raw','workerSha256','replayAllowed'} and type(value['schema'])is int and value['schema']==1 and value['workerSha256']==expected_source and value['replayAllowed']is False,'direct_terminal_invalid')
        require(type(value['eof'])is dict and set(value['eof'])=={'stdout','stderr'} and all(type(x)is bool for x in value['eof'].values()),'direct_terminal_invalid')
        channels={};pins=[pin]
        for name in ('stdout','stderr'):
            item=value['raw'][name];require(type(item)is dict and set(item)=={'bytes','sha256','chunks'} and type(item['bytes'])is int and 0<=item['bytes']<=MAX_RAW+CHUNK and type(item['chunks'])is list and len(item['chunks'])<=17,'direct_raw_invalid')
            body=b''
            for number,part in enumerate(item['chunks']):
                require(type(part)is dict and set(part)=={'name','bytes','sha256'} and part['name']==name+'-'+str(number).zfill(5)+'.private' and type(part['bytes'])is int and 0<part['bytes']<=CHUNK,'direct_raw_invalid')
                raw,part_pin=snapshot(directory/part['name'],CHUNK,True);require(len(raw)==part['bytes'] and sha(raw)==part['sha256'],'direct_raw_changed');body+=raw;pins.append(part_pin)
            require(len(body)==item['bytes'] and sha(body)==item['sha256'],'direct_raw_changed');channels[name]=body
        # No raw/body read follows this original held/named closure.
        bundle._evidence_generation_closure({pin['path']:pin for pin in pins})
        held=[]
        try:
            for original in pins:
                fd=os.open(original['path'],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK);held.append((original,fd))
            for original,fd in held:
                require(equal(bundle._pin(os.fstat(fd)),original['generation'])and equal(bundle._pin(os.stat(original['path'],follow_symlinks=False)),original['generation']),'direct_saved_changed')
        finally:
            for _,fd in held:os.close(fd)
        complete=value['reason']is None and type(value['returncode'])is int and all(value['eof'].values())
        return {'state':'terminal'if complete else'unknown','raw':channels,'receipt':value,'transportComplete':complete,'replayAllowed':False}
    except FileNotFoundError:
        return {'state':'unknown','reason':'direct_terminal_missing','transportComplete':False,'replayAllowed':False}


def framed_program(program):
    require(type(program)is bytes and 0<len(program)<=MAX_PROGRAM,'direct_program_limit')
    return canonical({'schema':1,'bytes':len(program),'sha256':sha(program)})+program


def read_frame(stream):
    header=stream.readline(513)
    require(len(header)<=512 and header.endswith(b'\n'),'direct_frame_invalid')
    value=json.loads(header);require(type(value)is dict and set(value)=={'schema','bytes','sha256'} and type(value['schema'])is int and value['schema']==1 and type(value['bytes'])is int and 0<value['bytes']<=MAX_PROGRAM and type(value['sha256'])is str and re.fullmatch('[a-f0-9]{64}',value['sha256']),'direct_frame_invalid')
    body=stream.read(value['bytes']+1)
    require(len(body)==value['bytes']and sha(body)==value['sha256'],'direct_frame_changed')
    return body


def claim_after_backup(guard,corr,directory,backup):
    """Fixed canonical claim after actual BaselineGuard and full backup closure."""
    import contextlib,io
    require(type(guard)is bundle.BaselineGuard,'direct_genuine_baseline_required')
    corr=correlation(corr);directory=Path(directory)
    require(guard.request['device']=='android-api35'and guard.request['expectedApi']==35 and guard.args.serial=='emulator-5682','direct_guard_crossed')
    require(type(backup)is dict and set(backup)>={'path','sha256','size'},'direct_backup_required')
    expected_request={**guard.request,'correlationId':str(uuid.uuid5(uuid.UUID(corr),'complete-update-backup'))}
    require(type(backup.get('schema'))is int and backup['schema']==1 and backup.get('kind')=='android-installer-routing-backup'and type(backup.get('readCount'))is int and backup['readCount']==2 and equal(backup.get('request'),expected_request),'direct_backup_binding_changed')
    raw,pin=snapshot(Path(backup['path']),32*1024*1024,True)
    require(len(raw)==backup['size']and sha(raw)==backup['sha256']and Path(backup['path'])==Path(guard.backend['ROOT'])/('android-installer-component-baseline-'+str(uuid.uuid5(uuid.UUID(corr),'complete-update-backup')))/'routing-backup'/'opening-routing.json','direct_backup_changed')
    root=Path(guard.backend['ROOT']);require(root==_DIRECT_AUTHENTICATED_ROOT,'direct_claim_root_changed');host=guard.backend['command_host_identity']();guard.backend['command_host_guard']()
    require(all(type(host[n])is int and host[n]==0 for n in ('uid','euid','gid','egid')),'direct_root_receiver_required')
    admission_raw,admission_pin=bundle._read(guard.args.output/'component-guard-current-admission.json',True)
    admission=json.loads(admission_raw)
    require(equal(admission_pin,guard.admission_pin)and equal(admission['binding'],guard.request)and equal(admission['record']['facts'],guard.expected)and equal(admission['record']['host'],guard.host)and equal(admission['record']['stage'],guard.stage),'direct_baseline_binding_changed')
    guard() # Actual fresh physical/task/public closure before the canonical claim.
    intent={'schema':1,'phase':'lease-claim','correlationId':corr,'request':guard.request,'backup':{'path':str(backup['path']),'pin':pin},'sourceTreeSha256':guard.receipt['treeSha256'],'admissionPin':guard.admission_pin,'host':host,'replayAllowed':False}
    write_once(directory,'lease-claim-intent.json',canonical(intent))
    # Body reads are complete before the final guard. A failed guard leaves the
    # durable once intent and may not be reissued/adopted by this entry.
    guard()
    capture=io.StringIO();old_argv=sys.argv
    namespace={'__name__':'fixed_shared_claim','ADMITTED_ROOT':str(root)}
    try:
        sys.argv=['fixed-shared-lease','claim',str(root),'archlinux','android-api35',corr,'android-installer']
        with contextlib.redirect_stdout(capture):
            try:exec(compile(_SHARED_CLAIM_SOURCE,'<canonical-shared-claim>','exec'),namespace)
            except SystemExit as stopped:require(stopped.code==0,'direct_lease_claim_unknown')
    finally:
        sys.argv=old_argv
        body=capture.getvalue().encode();write_once(directory,'lease-claim-raw.private',body)
    record=json.loads(body)
    require(equal(record,{'state':'claimed','reason':None,'correlationId':corr,'replayAllowed':False}),'direct_lease_claim_unknown')
    lease=root/'android-native-device-android-api35.lease';raw,lease_pin=snapshot(lease,1024,True)
    expected={'owner':'android-installer','host':'archlinux','device':'android-api35','correlationId':corr}
    require(equal(json.loads(raw),expected),'direct_lease_changed')
    write_once(directory,'lease-claim-terminal.json',canonical({'schema':1,'phase':'lease-claim','intentSha256':sha(canonical(intent)),'record':record,'lease':lease_pin,'replayAllowed':False}))
    return lease_pin


def _direct_prepare():
    """Private actual pre-release sequence, called only by fixed direct entry."""
    global UPDATE_ASSET_AUTHORITY,UPDATE_BASELINE_REQUEST
    require(equal({'uid':os.getuid(),'euid':os.geteuid(),'gid':os.getgid(),'egid':os.getegid(),'groups':sorted(os.getgroups())},DIRECT_INPUTS['hostPrincipal']),'direct_host_changed')
    require(Path('/proc/sys/kernel/random/boot_id').read_text().strip()==DIRECT_INPUTS['hostBootId'],'direct_boot_changed')
    original_receipt=write_once(DIRECT_JOURNAL,'component-receipt.json',canonical(COMPONENT_RECEIPT))
    _raw,receipt_origin=snapshot(DIRECT_JOURNAL/'component-receipt.json',65536,True)
    require(equal(receipt_origin['generation'],original_receipt['generation'])and receipt_origin['sha256']==original_receipt['sha256'],'direct_receipt_changed')
    print('COMPLETE_UPDATE_DIRECT_CUSTODY '+json.dumps({'schema':1,'correlationId':UPDATE_CORRELATION,'sourcePacketSha256':UPDATE_SOURCE_PACKET_SHA,'componentReceipt':receipt_origin},sort_keys=True,separators=(',',':')),flush=True)
    selected=bundle.modules(COMPONENT_RECEIPT)
    guard=bundle.BaselineGuard(COMPONENT_RECEIPT,selected,globals(),UPDATE_BASELINE_REQUEST)
    guard()
    # The routing module constructs its own positively authenticated guard and
    # immutable full backup. Its correlation differs from this guard's leaf.
    backup=bundle.routing_backup(COMPONENT_RECEIPT,globals(),DIRECT_BACKUP_REQUEST)
    # Claim uses the backup guard's fresh independently recorded admission.
    # Reconstructing at the same leaf is forbidden, so the backup helper exposes
    # no guard reuse; the claim guard owns the direct readonly admission leaf.
    claim=claim_after_backup(guard,UPDATE_CORRELATION,DIRECT_JOURNAL,backup)
    UPDATE_ASSET_AUTHORITY={**DIRECT_CUSTODY,'lease':claim}
    UPDATE_BASELINE_REQUEST=json.loads(canonical(DIRECT_BACKUP_REQUEST))
    prepared=_complete_update_stage(backup)
    return prepared


def direct_entry():
    """Concrete full actor: read admission/backup → claim → custody → actor."""
    prepared=_direct_prepare()
    actor=CompleteUpdate(prepared['args'],globals())
    return CompleteUpdateOuter(actor).run()

BOOTSTRAP=r'''
import hashlib,json,os,resource,stat,subprocess,sys,time
from pathlib import Path
ROOT=Path(__ROOT__);CORR=__CORR__;EXPECTED=__SHA__;LENGTH=__LENGTH__;SUPERVISOR=__SUPERVISOR__;HOST_BINDING=__HOST_BINDING__
stream=sys.stdin.buffer
header=stream.readline(513)
# sudo can consume the credential line or use its existing cached admission.
# The sole optional prefix stays in memory and is never logged or written.
if not header.startswith(b'{'):
 if len(header)>513 or not header.endswith(b'\n'):raise ValueError('direct_frame_invalid')
 header=stream.readline(513)
value=json.loads(header)
if type(value)is not dict or set(value)!={'schema','bytes','sha256'}or type(value['schema'])is not int or value['schema']!=1 or type(value['bytes'])is not int or value['bytes']!=LENGTH or value['sha256']!=EXPECTED:raise ValueError('direct_frame_invalid')
program=stream.read(LENGTH+1)
if len(program)!=LENGTH or hashlib.sha256(program).hexdigest()!=EXPECTED:raise ValueError('direct_frame_changed')
def host_guard():
 facts={'uid':os.getuid(),'euid':os.geteuid(),'gid':os.getgid(),'egid':os.getegid(),'groups':sorted(os.getgroups())}
 if json.dumps(facts,sort_keys=True)!=json.dumps(HOST_BINDING['principal'],sort_keys=True):raise ValueError('direct_host_changed')
 if Path('/proc/sys/kernel/random/boot_id').read_text().strip()!=HOST_BINDING['bootId']:raise ValueError('direct_boot_changed')
 chain=[]
 try:
  fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);chain.append(('/',fd))
  for part in ROOT.parts[1:]:
   fd=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=chain[-1][1]);chain.append((str(Path(chain[-1][0])/part),fd))
  for name,fd in chain:
   info=os.fstat(fd);named=os.stat(name,follow_symlinks=False)
   held=[info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid];seen=[named.st_dev,named.st_ino,named.st_mode,named.st_uid,named.st_gid]
   if held!=HOST_BINDING['rootParents'][name]or seen!=held:raise ValueError('direct_root_parent_changed')
 finally:
  for _,fd in reversed(chain):os.close(fd)
host_guard()
parent=ROOT.lstat()
if not stat.S_ISDIR(parent.st_mode)or stat.S_IMODE(parent.st_mode)!=0o700 or not (parent.st_uid==os.getuid() or parent.st_uid==parent.st_gid==1000 and os.getuid()==os.geteuid()==os.getgid()==os.getegid()==0):raise ValueError('direct_root_unsafe')
leaf=ROOT/('android-installer-component-bundle-'+CORR)
original_limit=resource.getrlimit(resource.RLIMIT_FSIZE)
if original_limit[1]!=resource.RLIM_INFINITY and original_limit[1]<8388608:raise ValueError('direct_source_file_limit')
staging_limit=(8388608,original_limit[1])
os.mkdir(leaf,0o700)
directory=os.open(leaf,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
created={};stage_complete=False
def pin(info):return [info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns]
try:
 resource.setrlimit(resource.RLIMIT_FSIZE,staging_limit)
 if resource.getrlimit(resource.RLIMIT_FSIZE)!=staging_limit:raise ValueError('direct_source_file_limit')
 for name,body in [('worker.py',program),('supervisor.py',SUPERVISOR.encode())]:
  fd=os.open(name,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
  try:
   offset=0
   while offset<len(body):
    size=os.write(fd,body[offset:offset+524288])
    if size<=0:raise ValueError('direct_write_unknown')
    offset+=size
   os.fsync(fd)
   created[name]=(fd,pin(os.fstat(fd)),hashlib.sha256(body).hexdigest(),len(body))
  finally:
   if name not in created:os.close(fd)
 os.fsync(directory)
 stage_complete=True
finally:
 resource.setrlimit(resource.RLIMIT_FSIZE,original_limit)
 if resource.getrlimit(resource.RLIMIT_FSIZE)!=original_limit:raise ValueError('direct_source_file_limit_restore')
 if not stage_complete:
  for fd,_,_,_ in created.values():os.close(fd)
  os.close(directory)
try:
 if sorted(os.listdir(directory))!=['supervisor.py','worker.py']:raise ValueError('direct_staged_source_changed')
 for name,(fd,original,digest,size)in created.items():
  os.lseek(fd,0,os.SEEK_SET);body=b''
  while len(body)<=size:
   block=os.read(fd,min(524288,size+1-len(body)))
   if not block:break
   body+=block
  if len(body)!=size or hashlib.sha256(body).hexdigest()!=digest:raise ValueError('direct_staged_source_changed')
 host_guard()
 current=os.fstat(directory);named=leaf.lstat()
 if pin(current)[:5]!=pin(named)[:5]or not stat.S_ISDIR(current.st_mode)or stat.S_IMODE(current.st_mode)!=0o700 or current.st_uid!=os.getuid():raise ValueError('direct_staged_source_changed')
 # All body/catalogue/host reads precede the final original-generation pass.
 for name,(fd,original,_,_)in created.items():
  if pin(os.fstat(fd))!=original or pin(os.stat(name,dir_fd=directory,follow_symlinks=False))!=original or not stat.S_ISREG(original[2])or original[3]!=os.getuid()or stat.S_IMODE(original[2])!=0o600 or original[5]!=1:raise ValueError('direct_staged_source_changed')
 source_fd=created['supervisor.py'][0]
 os.lseek(source_fd,0,os.SEEK_SET)
 environment=os.environ.copy();environment['DIRECT_JOURNAL']=str(leaf)
 # Execute the originally held descriptor; no reopened source adoption.
 child=subprocess.Popen([sys.executable,'-I','-u','-B','/proc/self/fd/'+str(source_fd),str(leaf),EXPECTED],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,pass_fds=(source_fd,),env=environment,start_new_session=True)
finally:
 for fd,_,_,_ in created.values():os.close(fd)
 os.close(directory)
deadline=time.monotonic()+5
receipt=leaf/'supervisor.json'
while not receipt.exists() and time.monotonic()<deadline:time.sleep(.02)
if not receipt.exists():raise ValueError('direct_supervisor_unknown')
fd=os.open(receipt,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
try:
 info=os.fstat(fd);body=os.read(fd,65537)
 if not stat.S_ISREG(info.st_mode)or info.st_nlink!=1 or stat.S_IMODE(info.st_mode)!=0o600 or info.st_uid!=os.getuid()or len(body)>65536:raise ValueError('direct_supervisor_unsafe')
 record=json.loads(body)
 if record['identity']['pid']!=child.pid or record['workerSha256']!=EXPECTED:raise ValueError('direct_supervisor_changed')
finally:os.close(fd)
print(json.dumps({'state':'submitted','correlationId':CORR,'pid':child.pid,'identity':record['identity'],'workerSha256':EXPECTED,'replayAllowed':False},separators=(',',':')),flush=True)
'''


def bootstrap_source(root,corr,program,host_binding):
    correlation(corr);require(Path(root).is_absolute()and '..'not in Path(root).parts,'direct_root_binding_invalid')
    require(type(program)is bytes and 0<len(program)<=MAX_PROGRAM,'direct_program_limit')
    require(type(host_binding)is dict and set(host_binding)=={'principal','bootId','rootParents'},'direct_host_binding_invalid')
    correlation(host_binding['bootId'])
    source=BOOTSTRAP
    for token,value in [('__ROOT__',repr(str(root))),('__CORR__',repr(corr)),('__SHA__',repr(sha(program))),('__LENGTH__',str(len(program))),('__SUPERVISOR__',repr(supervisor_source().decode())),('__HOST_BINDING__',repr(json.loads(canonical(host_binding))))]:
        require(source.count(token)==1,'direct_bootstrap_source_changed');source=source.replace(token,value)
    compile(source,'<fixed-direct-bootstrap>','exec',dont_inherit=True)
    require(len(source.encode())<65536,'direct_argv_limit')
    return source


def host_observation_source(root,host_binding):
    """Same original host/root predicate before a saved-journal observation."""
    nodes=[node for node in ast.parse(BOOTSTRAP).body if isinstance(node,ast.FunctionDef)and node.name=='host_guard']
    require(len(nodes)==1,'direct_bootstrap_source_changed')
    return 'import os,json\nfrom pathlib import Path\nROOT=Path('+repr(str(root))+')\nHOST_BINDING='+repr(json.loads(canonical(host_binding)))+'\n'+ast.unparse(ast.Module(body=nodes,type_ignores=[]))+'\nhost_guard()\n'


def intent_host_binding(intent):
    parents=intent['inputs']['assetAuthority']['files']['base.apk']['parents'];rootpath=Path(intent['remoteRoot'])
    allowed={'/',*(str(p)for p in [rootpath,*rootpath.parents])}
    return {'principal':intent['inputs']['hostPrincipal'],'bootId':intent['inputs']['hostBootId'],'rootParents':{name:value for name,value in parents.items()if name in allowed}}


def observer_source(root,corr,journal,action,accepted,packet_sha,custody):
    """No initializer replay. Authenticate original staged bundle and mailbox."""
    require(action in ('status','handoff-ready','continue'),'direct_observation_role_invalid')
    correlation(corr);require(type(packet_sha)is str and re.fullmatch('[a-f0-9]{64}',packet_sha),'direct_packet_invalid')
    root=Path(root);journal=Path(journal)
    require(journal==root/('android-installer-component-bundle-'+str(uuid.uuid5(uuid.UUID(corr),'complete-update-direct-worker'))),'direct_journal_crossed')
    require(type(custody)is dict and set(custody)=={'schema','correlationId','sourcePacketSha256','componentReceipt'}and type(custody['schema'])is int and custody['schema']==1 and custody['correlationId']==corr and custody['sourcePacketSha256']==packet_sha,'direct_original_custody_changed')
    outer.outer_pin_shape(custody['componentReceipt'])
    require(custody['componentReceipt']['path']==str(journal/'component-receipt.json'),'direct_original_custody_changed')
    bundle_raw,_=snapshot(Path(bundle.__file__),private=False);outer_raw,_=snapshot(Path(outer.__file__),private=False)
    source='import json,pathlib,types\nROOT=pathlib.Path('+repr(str(root))+')\nCOMPONENT_BUNDLE=types.ModuleType("saved_component_bundle")\nCOMPONENT_BUNDLE.__file__='+repr(str(journal/'bundle-reader.py'))+'\nexec(compile('+repr(bundle_raw)+',COMPONENT_BUNDLE.__file__,"exec"),COMPONENT_BUNDLE.__dict__)\n'
    source+='origin='+repr(custody['componentReceipt'])+'\nreceipt_raw,receipt_pin=COMPONENT_BUNDLE._read(pathlib.Path(origin["path"]),True)\nif json.dumps(receipt_pin,sort_keys=True,separators=(",",":"))!=json.dumps({k:origin[k]for k in ("generation","parents","sha256")},sort_keys=True,separators=(",",":")):raise ValueError("direct_original_custody_changed")\nCOMPONENT_RECEIPT=json.loads(receipt_raw)\nCOMPONENT_BUNDLE.load(COMPONENT_RECEIPT)\n'
    source+=outer.outer_namespace_source(outer_raw)+'\nUPDATE_CORRELATION='+repr(corr)+'\nUPDATE_SOURCE_PACKET_SHA='+repr(packet_sha)+'\nUPDATE_OUTER_ACCEPTED='+repr(accepted)+'\n'
    source+='result='+('outer_saved_status()'if action=='status'else'outer_submit_saved_callback('+repr(action)+')')+'\nprint(json.dumps(result,sort_keys=True,separators=(",",":")),flush=True)\n'
    compile(source,'<original-update-observation>','exec',dont_inherit=True)
    return source.encode()


def prepared_program(root,corr):
    capsule=_capsule(root,corr);raw,intent_pin=snapshot(capsule/'intent.json',1048576,True);intent=json.loads(raw)
    require(type(intent)is dict and intent.get('inputs',{}).get('correlationId')==corr and intent.get('replayAllowed')is False,'direct_intent_invalid')
    _source_guard(root,intent['sources']);bundle.load(intent['toolReceipt'])
    parts=[];pins=[]
    for index,chunk in enumerate(intent['chunks']):
        require(chunk['name']==f'program-{index:04d}.py','direct_program_catalogue_changed')
        part,pin=snapshot(capsule/chunk['name'],CHUNK,True);require(equal(pin,chunk['pin']),'direct_program_changed');parts.append(part);pins.append(pin)
    source=b''.join(parts);require(len(source)==intent['programBytes']and sha(source)==intent['programSha256'],'direct_program_changed')
    expected,packet,prepared,actual_root=assemble(root,intent['inputs'],intent['toolReceipt'])
    require(source==expected and equal(packet,intent['packet'])and str(actual_root)==intent['remoteRoot'],'direct_factory_changed')
    _source_guard(root,intent['sources']);require(equal(snapshot(capsule/'intent.json',1048576,True)[1],intent_pin),'direct_intent_changed')
    return capsule,intent,source


def fixed_ssh_argv(root,source):
    """Future operator-only route; no implicit fresh connection or fallback."""
    from . import ssh_transport
    root=Path(root)
    require((root/'.rag_index'/'ssh-channel-selection').exists(),'direct_selected_route_required')
    config=ssh_transport.load_config(root)
    require(type(source)is str,'direct_bootstrap_source_changed')
    bridge="import base64;exec(compile(base64.b64decode("+repr(base64.b64encode(source.encode()).decode())+"),'<fixed-direct-entry>','exec'))"
    command=['sudo','-S','-p','','--','python3','-I','-u','-B','-c',bridge]
    argv=ssh_transport.build_ssh_argv(config,'archlinux',timeout_seconds=60,command=command)
    # Validate the actual generated two-leg template; never rewrite its options.
    inner=shlex.split(argv[-1])
    require(inner and Path(inner[0]).name=='ssh'and inner[-1]==shlex.join(command),'direct_nested_route_changed')
    for leg in (argv[:-1],inner[:-1]):
        for option in ('ControlMaster=no','ControlPersist=no','ProxyCommand=false'):
            require(leg.count(option)==1,'direct_reuse_only_route_required')
        require(leg.count('-S')==1 and leg[leg.index('-S')+1].startswith('/'),'direct_reuse_only_route_required')
    require(sum(len(x.encode())+1 for x in argv)<65536,'direct_argv_limit')
    return argv


def _dispatch_hold(path,pin,expected_raw):
    """Keep original journal inode and every ancestor until collection closes."""
    chain=[];fd=None
    try:
        chain,parents=bundle._parents(path.parent)
        fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=chain[-1][1])
        raw=bytearray()
        while block:=os.read(fd,len(expected_raw)+1-len(raw)):
            raw.extend(block);require(len(raw)<=len(expected_raw),'direct_dispatch_changed')
        require(bytes(raw)==expected_raw and sha(raw)==pin['sha256'] and equal(parents,pin['parents']),'direct_dispatch_changed')
        held=(path,pin,chain,fd);_dispatch_guard([held]);return held
    except BaseException as exc:
        close_error=None
        if fd is not None:
            try:os.close(fd)
            except BaseException as error:close_error=error
        for _,ancestor in reversed(chain):
            try:os.close(ancestor)
            except BaseException as error:
                if close_error is None:close_error=error
        if close_error is not None:raise close_error from exc
        if isinstance(exc,(OSError,ValueError)):raise ValueError('direct_dispatch_changed')from exc
        raise


def _dispatch_guard(held):
    # Pure whole-population check; all body reads and publication precede it.
    try:
        # Close every ancestor before any final original journal leaf. A late
        # ancestor read can expose drift in another entry in this population.
        for path,pin,chain,fd in held:
            for name,ancestor in chain:
                require(equal(bundle._pin(os.fstat(ancestor))[:5],pin['parents'][name]) and equal(bundle._pin(os.stat(name,follow_symlinks=False))[:5],pin['parents'][name]),'direct_dispatch_changed')
        for path,pin,chain,fd in held:
            require(equal(bundle._pin(os.fstat(fd)),pin['generation']) and equal(bundle._pin(os.stat(path.name,dir_fd=chain[-1][1],follow_symlinks=False)),pin['generation']),'direct_dispatch_changed')
    except OSError as exc:raise ValueError('direct_dispatch_changed')from exc


def _transport_capture(capsule,argv,frame,role,root,pins,program_sha):
    """One concrete process, complete raw-before-parse. No retry on failure."""
    dispatch_raw=canonical({'schema':1,'phase':role,'argvSha256':sha(canonical(argv)),'framedSourceSha256':program_sha,'replayAllowed':False})
    # Separate create-only reservation stays sticky even if dispatch is removed.
    once_pin=write_once(capsule,role+'-once.json',dispatch_raw)
    dispatch_pin=write_once(capsule,role+'-dispatch.json',dispatch_raw)
    held=[]
    try:
        for name,pin in [(role+'-once.json',once_pin),(role+'-dispatch.json',dispatch_pin)]:held.append(_dispatch_hold(capsule/name,pin,dispatch_raw))
        _source_guard(root,pins)
        _dispatch_guard(held)
        child=subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
        publication_failures=[]
        def publish(name,raw,kind):
            # Storage failure cannot discard the already accepted original child.
            try:return write_once(capsule,name,raw)
            except (OSError,ValueError):
                if kind not in publication_failures:publication_failures.append(kind)
                return None
        publish(role+'-child.json',canonical({'schema':1,'pid':child.pid,'localLaunchMonotonicNs':time.monotonic_ns(),'birthProven':False,'replayAllowed':False}),'child')
        # A bootstrap frame contains no caller credential in its journals; the
        # credential prefix is held only in the pipe writer's memory.
        selector=None;buffers={'stdout':bytearray(),'stderr':bytearray()};records={name:{'bytes':0,'chunks':[],'storageComplete':True}for name in buffers};chunk_numbers={name:0 for name in buffers};digests={name:hashlib.sha256()for name in buffers};eof={name:False for name in buffers};offset=0;reason=None;deadline=time.monotonic()+75
        try:
            selector=selectors.DefaultSelector()
            for name,stream in [('stdout',child.stdout),('stderr',child.stderr)]:
                os.set_blocking(stream.fileno(),False);selector.register(stream,selectors.EVENT_READ,name)
            os.set_blocking(child.stdin.fileno(),False);selector.register(child.stdin,selectors.EVENT_WRITE,'stdin')
            while selector.get_map():
                if time.monotonic()>=deadline:reason='direct_transport_timeout';break
                for key,_ in selector.select(.2):
                    if key.data=='stdin':
                        try:count=os.write(key.fileobj.fileno(),frame[offset:offset+65536])
                        except BrokenPipeError:count=0;reason='direct_transport_stdin_unknown'
                        offset+=count
                        if offset==len(frame)or reason:selector.unregister(key.fileobj);key.fileobj.close()
                        continue
                    name=key.data;block=os.read(key.fileobj.fileno(),CHUNK)
                    if not block:eof[name]=True;selector.unregister(key.fileobj);continue
                    if sum(len(x)for x in buffers.values())+len(block)>MAX_RAW:reason='direct_transport_raw_limit';break
                    # Raw bytes reach O_EXCL/fsync custody before JSON interpretation.
                    part=role+'-'+name+'-'+str(chunk_numbers[name]).zfill(5)+'.private';chunk_numbers[name]+=1
                    pin=publish(part,block,name)
                    if pin is None:records[name]['storageComplete']=False
                    else:records[name]['chunks'].append(pin)
                    records[name]['bytes']+=len(block);digests[name].update(block);buffers[name].extend(block)
                if reason:break

        except (OSError,ValueError):reason='direct_transport_io_unknown'
        for name in records:records[name]['sha256']=digests[name].hexdigest()
        stdout=bytes(buffers['stdout']);stderr=bytes(buffers['stderr'])
        if all(eof.values()):
            try:child.wait(timeout=max(.01,deadline-time.monotonic()))
            except subprocess.TimeoutExpired:reason='direct_transport_exit_unknown'
            except OSError:reason='direct_transport_io_unknown'
        transport_reason=reason
        if publication_failures:reason='direct_journal_publication_failed'
        publish(role+'-raw-terminal.json',canonical({'schema':1,'pid':child.pid,'returncode':child.poll(),'reason':reason,'transportReason':transport_reason,'publicationFailures':list(publication_failures),'eof':eof,'raw':records,'replayAllowed':False}),'terminal')
        try:
            if selector is not None:selector.close()
            if all(eof.values()):child.stdout.close();child.stderr.close()
        except OSError:reason='direct_transport_io_unknown'
        try:_dispatch_guard(held)
        except ValueError:
            reason='direct_dispatch_changed'
            publish(role+'-custody-unknown.json',canonical({'schema':1,'reason':reason,'pid':child.pid,'rawRetained':True,'replayAllowed':False}),'custody')
        if publication_failures:reason='direct_journal_publication_failed'
        return child,stdout,stderr,eof,reason

    finally:
        for _,_,chain,fd in reversed(held):os.close(fd);bundle._close(chain)


def submission_shape(value,corr,program_sha):
    require(type(value)is dict and set(value)=={'state','correlationId','pid','identity','workerSha256','replayAllowed'}and value['state']=='submitted'and value['correlationId']==corr and type(value['pid'])is int and value['pid']>0 and value['workerSha256']==program_sha and value['replayAllowed']is False,'direct_submission_unknown')
    identity=value['identity']
    require(type(identity)is dict and set(identity)=={'pid','startTicks','bootId'}and type(identity['pid'])is int and identity['pid']==value['pid']and type(identity['startTicks'])is int and identity['startTicks']>0,'direct_submission_unknown')
    correlation(identity['bootId'])
    return json.loads(canonical(value))


def _postcollection_unknown(corr,child,out,err,eof,reason,error,*,original_remote_pid=None,secondary_error=None):
    """Diagnostic facts of the returned original tuple; no custody/admission claim."""
    result={'state':'unknown','correlationId':corr,'localPid':child.pid,'reason':reason,'exceptionClass':type(error).__name__,'replayAllowed':False,'nativeAcceptance':False,
            'localTransport':{'returncode':child.returncode,'stdoutBytes':len(out),'stdoutSha256':sha(out),'stderrBytes':len(err),'stderrSha256':sha(err),'eof':dict(eof)}}
    if original_remote_pid is not None:result['originalRemotePid']=original_remote_pid
    if secondary_error is not None:result['secondaryExceptionClass']=type(secondary_error).__name__
    return result


def start(root,corr,credential=None):
    """ONE future operator submission. No credential source is read here."""
    corr=correlation(corr);capsule,intent,program=prepared_program(root,corr)
    require(credential is None or type(credential)is bytes and 0<len(credential)<=512 and b'\n'not in credential and b'\r'not in credential,'direct_credential_frame_invalid')
    worker_corr=str(uuid.uuid5(uuid.UUID(corr),'complete-update-direct-worker'))
    host_binding=intent_host_binding(intent)
    bootstrap=bootstrap_source(intent['remoteRoot'],worker_corr,program,host_binding)
    argv=fixed_ssh_argv(root,bootstrap)
    require(not os.path.lexists(capsule/'start-dispatch.json'),'direct_once_consumed')
    _source_guard(root,intent['sources'])
    frame=(b''if credential is None else credential+b'\n')+framed_program(program)
    # Frame digests in transport journals exclude the sudo prefix.
    # No credential is passed in argv, request records, exceptions or files.
    child,out,err,eof,reason=_transport_capture(capsule,argv,frame,'start',root,intent['sources'],sha(program))
    if reason or err or child.poll()!=0 or not all(eof.values()):return {'state':'unknown','correlationId':corr,'localPid':child.pid,'replayAllowed':False}
    accepted=json.loads(out)
    accepted=submission_shape(accepted,worker_corr,sha(program))
    # The original accepted fact survives diagnostic publication/closing loss.
    # Still attempt source closing after a refused journal; neither failure
    # authorizes replay or turns the original submission into acceptance.
    post_error=None;post_reason=None;secondary_error=None
    try:
        write_once(capsule,'accepted.json',canonical({'schema':1,'correlationId':corr,'remote':accepted,'sourcePacketSha256':sha(canonical(intent['packet'])),'replayAllowed':False}))
    except (OSError,ValueError) as error:
        post_error=error;post_reason='direct_accepted_journal_publication_failed'
    try:_source_guard(root,intent['sources'])
    except (OSError,ValueError) as error:
        if post_error is None:post_error=error;post_reason='direct_postcollection_source_unknown'
        else:secondary_error=error
    if post_error is not None:
        return _postcollection_unknown(corr,child,out,err,eof,post_reason,post_error,original_remote_pid=accepted['pid'],secondary_error=secondary_error)
    return {'state':'submitted','correlationId':corr,'localPid':child.pid,'originalRemotePid':accepted['pid'],'replayAllowed':False,'nativeAcceptance':False}


def observe(root,corr,accepted,custody,action='status',credential=None):
    """Original actor observation/callback only; no lease claim or worker replay."""
    corr=correlation(corr);capsule,intent,_program=prepared_program(root,corr)
    require(action in ('status','handoff-ready','continue'),'direct_observation_role_invalid')
    worker_corr=str(uuid.uuid5(uuid.UUID(corr),'complete-update-direct-worker'))
    journal=Path(intent['remoteRoot'])/('android-installer-component-bundle-'+worker_corr)
    source=host_observation_source(intent['remoteRoot'],intent_host_binding(intent)).encode()+observer_source(intent['remoteRoot'],corr,journal,action,accepted,sha(canonical(intent['packet'])),custody)
    # Small observer also uses a fixed stdin frame; it may never execute the
    # original initializer. The callback is source-bound to the original handle.
    require(credential is None or type(credential)is bytes and 0<len(credential)<=512 and b'\n'not in credential and b'\r'not in credential,'direct_credential_frame_invalid')
    reader='import hashlib,json,sys\nh=sys.stdin.buffer.readline(513)\nif not h.startswith(b"{"):h=sys.stdin.buffer.readline(513)\nv=json.loads(h)\nif v!='+repr({'schema':1,'bytes':len(source),'sha256':sha(source)})+':raise ValueError("direct_frame_invalid")\np=sys.stdin.buffer.read('+str(len(source)+1)+')\nif len(p)!='+str(len(source))+' or hashlib.sha256(p).hexdigest()!='+repr(sha(source))+':raise ValueError("direct_frame_changed")\nexec(compile(p,"<original-update-observation>","exec"))\n'
    argv=fixed_ssh_argv(root,reader)
    role='observe-'+action+'-'+str(len(list(capsule.glob('observe-*-dispatch.json')))).zfill(4)
    _source_guard(root,intent['sources']);frame=(b''if credential is None else credential+b'\n')+framed_program(source)
    child,out,err,eof,reason=_transport_capture(capsule,argv,frame,role,root,intent['sources'],sha(source))
    try:_source_guard(root,intent['sources'])
    except (OSError,ValueError) as error:
        return _postcollection_unknown(corr,child,out,err,eof,'direct_postcollection_source_unknown',error)
    if reason or err or child.poll()!=0 or not all(eof.values()):return {'state':'unknown','correlationId':corr,'localPid':child.pid,'replayAllowed':False}
    return json.loads(out)


def original_journal_source(root,corr,worker_sha):
    """Read current original chunks only, never initializer/lease/CLI execution."""
    corr=correlation(corr);root=Path(root)
    journal=root/('android-installer-component-bundle-'+str(uuid.uuid5(uuid.UUID(corr),'complete-update-direct-worker')))
    require(type(worker_sha)is str and re.fullmatch('[a-f0-9]{64}',worker_sha),'direct_source_invalid')
    module_raw,_=snapshot(Path(bundle.__file__),private=False)
    source='import json,pathlib,types,base64,os,stat\nfrom pathlib import Path\nbundle=types.ModuleType("saved_original_reader")\nbundle.__file__='+repr(str(journal/'reader.py'))+'\nexec(compile('+repr(module_raw)+',bundle.__file__,"exec"),bundle.__dict__)\n'
    defs=[node for node in ast.parse(snapshot(Path(__file__),private=False)[0]).body if isinstance(node,ast.FunctionDef)and node.name in ('require','canonical','equal','sha','posix','snapshot','saved_terminal')]
    source+='import hashlib\nCHUNK=524288\nMAX_PROGRAM=8388608\nMAX_RAW=8388608\n'+ast.unparse(ast.Module(body=defs,type_ignores=[]))+'\n'
    source+='journal=Path('+repr(str(journal))+')\nexpected='+repr(worker_sha)+'\n'
    source+=r'''
raw,pin=snapshot(journal/'supervisor.json',65536,True);supervisor=json.loads(raw)
require(supervisor['workerSha256']==expected,'direct_original_source_changed')
records=[];pins=[pin];accepted=[];custody=[]
# Scan the complete finite stdout catalogue, retaining the actual available raw.
# A partial stream may have no accepted actor yet; that never grants replay.
names=os.listdir(journal)
parts=sorted(n for n in names if n.startswith('stdout-'))
require(len(parts)<=17,'direct_original_raw_limit')
body=b''
for index,name in enumerate(parts):
 require(name=='stdout-'+str(index).zfill(5)+'.private','direct_original_catalogue_changed')
 part,pin=snapshot(journal/name,524288,True);body+=part;pins.append(pin)
records=[{'channel':'stdout','bodyBase64':base64.b64encode(body).decode(),'bytes':len(body),'sha256':sha(body)}]
for line in body.splitlines():
 if line.startswith(b'COMPLETE_UPDATE_ACCEPTED '):accepted.append(json.loads(line[len(b'COMPLETE_UPDATE_ACCEPTED '):]))
 if line.startswith(b'COMPLETE_UPDATE_DIRECT_CUSTODY '):custody.append(json.loads(line[len(b'COMPLETE_UPDATE_DIRECT_CUSTODY '):]))
require(len(accepted)<=1 and len(custody)<=1,'direct_original_accepted_changed')
collector=saved_terminal(journal,expected)
collector_record={'state':collector['state'],'receipt':collector.get('receipt'),'replayAllowed':False}
if 'raw'in collector:
 stderr=collector['raw']['stderr'];records.append({'channel':'stderr','bodyBase64':base64.b64encode(stderr).decode(),'bytes':len(stderr),'sha256':sha(stderr)})
bundle._evidence_generation_closure({pin['path']:pin for pin in pins})
print(json.dumps({'state':'original-observed','supervisor':supervisor,'actorAccepted':accepted[0]if accepted else None,'actorCustody':custody[0]if custody else None,'collector':collector_record,'raw':records,'replayAllowed':False},sort_keys=True,separators=(',',':')),flush=True)
'''
    compile(source,'<original-update-journal-reader>','exec',dont_inherit=True)
    return source.encode()


def _observer_frame_reader(source):
    return 'import hashlib,json,sys\nh=sys.stdin.buffer.readline(513)\nif not h.startswith(b"{"):h=sys.stdin.buffer.readline(513)\nv=json.loads(h)\nif v!='+repr({'schema':1,'bytes':len(source),'sha256':sha(source)})+':raise ValueError("direct_frame_invalid")\np=sys.stdin.buffer.read('+str(len(source)+1)+')\nif len(p)!='+str(len(source))+' or hashlib.sha256(p).hexdigest()!='+repr(sha(source))+':raise ValueError("direct_frame_changed")\nexec(compile(p,"<original-update-observation>","exec"))\n'


def status(root,corr,credential=None):
    corr=correlation(corr);capsule,intent,program=prepared_program(root,corr)
    require(os.path.lexists(capsule/'start-dispatch.json'),'direct_original_dispatch_missing')
    source=host_observation_source(intent['remoteRoot'],intent_host_binding(intent)).encode()+original_journal_source(intent['remoteRoot'],corr,sha(program))
    require(credential is None or type(credential)is bytes and 0<len(credential)<=512 and b'\n'not in credential and b'\r'not in credential,'direct_credential_frame_invalid')
    argv=fixed_ssh_argv(root,_observer_frame_reader(source))
    role='status-'+str(len(list(capsule.glob('status-*-dispatch.json')))).zfill(4)
    child,out,err,eof,reason=_transport_capture(capsule,argv,(b''if credential is None else credential+b'\n')+framed_program(source),role,root,intent['sources'],sha(source))
    try:_source_guard(root,intent['sources'])
    except (OSError,ValueError) as error:
        return _postcollection_unknown(corr,child,out,err,eof,'direct_postcollection_source_unknown',error)
    if reason or err or child.poll()!=0 or not all(eof.values()):return {'state':'unknown','correlationId':corr,'replayAllowed':False}
    result=json.loads(out)
    require(type(result)is dict and set(result)=={'state','supervisor','actorAccepted','actorCustody','collector','raw','replayAllowed'}and result['state']=='original-observed'and result['replayAllowed']is False,'direct_status_unknown')
    if result['actorAccepted']is None:return {**result,'nativeAcceptance':False}
    require(result['actorCustody']is not None,'direct_original_custody_missing')
    original={'schema':1,'workerSha256':sha(program),'accepted':result['actorAccepted'],'custody':result['actorCustody']}
    path=capsule/'actor-original.json'
    try:
        if os.path.lexists(path):require(equal(json.loads(snapshot(path,65536,True)[0]),original),'direct_original_accepted_changed')
        else:write_once(capsule,'actor-original.json',canonical(original))
    except (OSError,ValueError) as error:
        secondary_error=None
        try:_source_guard(root,intent['sources'])
        except (OSError,ValueError) as closing_error:secondary_error=closing_error
        return _postcollection_unknown(corr,child,out,err,eof,'direct_original_actor_publication_failed',error,secondary_error=secondary_error)
    observed=observe(root,corr,result['actorAccepted'],result['actorCustody'],'status',credential)
    projection=project_original_capture(corr,intent,result)
    try:_source_guard(root,intent['sources'])
    except (OSError,ValueError) as error:
        return _postcollection_unknown(corr,child,out,err,eof,'direct_postcollection_source_unknown',error)
    return {'state':observed.get('state','unknown'),'journal':observed,'collector':result['collector'],'raw':result['raw'],'component':projection,'nativeAcceptance':False,'replayAllowed':False}


def project_original_capture(corr,intent,result):
    """Actual original raw EOF plus unchanged outer finite result projection."""
    unknown={'state':'unknown','correlationId':corr,'replayAllowed':False,'installedLauncherAccepted':False,'bundledRuntimeAccepted':False}
    collector=result.get('collector')
    if type(collector)is not dict or collector.get('state')!='terminal':return unknown
    receipt=collector.get('receipt')
    if type(receipt)is not dict or receipt.get('workerSha256')!=intent['programSha256']:return unknown
    channels={}
    for row in result.get('raw',[]):
        if type(row)is not dict or set(row)!={'channel','bodyBase64','bytes','sha256'}or row['channel']not in ('stdout','stderr')or row['channel']in channels:return unknown
        body=base64.b64decode(row['bodyBase64'],validate=True)
        if type(row['bytes'])is not int or len(body)!=row['bytes']or sha(body)!=row['sha256']:return unknown
        if receipt.get('raw',{}).get(row['channel'],{}).get('sha256')!=sha(body)or receipt['raw'][row['channel']].get('bytes')!=len(body):return unknown
        channels[row['channel']]=body
    if set(channels)!={'stdout','stderr'}:return unknown
    source,_=snapshot(Path(outer.__file__),private=False)
    scope={'__name__':'direct_original_projection','UPDATE_CORRELATION':corr,'UPDATE_SOURCE_PACKET_SHA':sha(canonical(intent['packet']))}
    exec(compile(outer.outer_namespace_source(source),'<actual-original-capture-projection>','exec'),scope)
    return scope['outer_capture_projection'](channels['stdout'],channels['stderr'],receipt.get('returncode'),receipt.get('eof'))


def callback(root,corr,phase,credential=None):
    require(phase in ('handoff-ready','continue'),'direct_callback_invalid')
    capsule,intent,program=prepared_program(root,correlation(corr))
    raw,_=snapshot(capsule/'actor-original.json',65536,True);original=json.loads(raw)
    require(type(original)is dict and set(original)=={'schema','workerSha256','accepted','custody'}and type(original['schema'])is int and original['schema']==1 and original['workerSha256']==sha(program),'direct_original_accepted_changed')
    return observe(root,corr,original['accepted'],original['custody'],phase,credential)


def main(argv=None):
    """Finite explicit operator entry; invocation alone grants no native facts."""
    import argparse
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',required=True)
    sub=parser.add_subparsers(dest='action',required=True)
    prepare_parser=sub.add_parser('prepare');prepare_parser.add_argument('--inputs',required=True)
    for action in ('start','status','callback'):
        item=sub.add_parser(action);item.add_argument('--correlation-id',required=True)
        item.add_argument('--credential-stdin',action='store_true')
        if action=='callback':item.add_argument('--phase',required=True,choices=('handoff-ready','continue'))
    args=parser.parse_args(argv);credential=None
    if getattr(args,'credential_stdin',False):
        line=sys.stdin.buffer.readline(514)
        require(line.endswith(b'\n')and 1<len(line)<=513 and b'\r'not in line,'direct_credential_frame_invalid')
        credential=line[:-1]
    if args.action=='prepare':
        body,_=snapshot(Path(args.inputs),MAX_PROGRAM,True)
        value=prepare(Path(args.root),json.loads(body))
    elif args.action=='start':value=start(Path(args.root),args.correlation_id,credential)
    elif args.action=='status':value=status(Path(args.root),args.correlation_id,credential)
    else:value=callback(Path(args.root),args.correlation_id,args.phase,credential)
    print(canonical(value).decode(),end='',flush=True)
    return 0

if __name__=='__main__':raise SystemExit(main())
