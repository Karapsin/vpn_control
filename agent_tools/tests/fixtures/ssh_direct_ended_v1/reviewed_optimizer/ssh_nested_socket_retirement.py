"""Read-only admission for one orphan socket from completed owned recovery.

The observer never reads private keys, starts a master, signals a process or
changes a remote path. Archive is deliberately unavailable until actual orphan
proof has been reviewed. Cooperative inventory ownership excludes repository
writers; observations are not atomic CAS against arbitrary external writers.
"""
from __future__ import annotations
import hashlib
import inspect
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
from contextlib import ExitStack
from agent_tools import ssh_transport as transport, ssh_connection_recovery as recovery
from agent_tools import ssh_recovery_adoption as adoption, ssh_connection_session as session
from agent_tools.private_inventory_lock import Directory, Snapshot, InventoryLock, lock_directory

DEPENDENCIES = {
 'ssh_transport.py':'91943bb626e384ac0bf0164d91365eb51a0b53a6e1703c89287150b826aeee08',
 'ssh_connection_recovery.py':'ab335eca235cad2b2c327f3f803cf6066ada8289766c49828f76427e7c10d837',
 'ssh_recovery_adoption.py':'cb07b4c3ea864adb3f18a2509a19d6844c60ef0f61b500d58c9fe5c8c41d1775',
 'private_inventory_lock.py':'d6ce7b228059470b4792c47e4562017235cad26ae6666c2a899dd459887358b8',
 'ssh_connection_session.py':'dba4466d09aff57787cb008edcd044bc1cb4c3a22f4325c6a41efebe230a0720'}
HEADER = b'Num       RefCount Protocol Flags    Type St Inode Path\n'
LIMIT = 4_194_304


def generation(info):
    return [info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,
            info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns]


def parse_unix_table(body: bytes, path: str) -> dict:
    if not isinstance(body,bytes) or not body.startswith(HEADER) or not body.endswith(b'\n') or len(body)>LIMIT:
        raise ValueError('kernel_table_incomplete')
    rows=body[len(HEADER):].splitlines();seen=set();endpoints=0
    for row in rows:
        fields=row.split(None,7)
        if (len(fields) not in (7,8) or not re.fullmatch(rb'[0-9a-fA-F]+:',fields[0])
            or any(not re.fullmatch(rb'[0-9a-fA-F]{8}',fields[i]) for i in (1,2,3))
            or not re.fullmatch(rb'[0-9a-fA-F]{4}',fields[4]) or not re.fullmatch(rb'[0-9a-fA-F]{2}',fields[5])
            or not re.fullmatch(rb'[0-9]+',fields[6]) or fields[6] in seen):
            raise ValueError('kernel_table_unknown_row')
        # Unprivileged kernels mask every Num pointer to zero. Inodes remain
        # distinct; a duplicate inode means an unsupported/inconsistent table.
        seen.add(fields[6])
        if len(fields)==8 and fields[7]==path.encode():endpoints+=1
    if endpoints:raise ValueError('kernel_endpoint_present')
    return {'endpointCount':0,'rowCount':len(rows),'bytes':len(body),'sha256':hashlib.sha256(body).hexdigest(),'completeEOF':True}


def read_table(path='/proc/net/unix'):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        chunks=[];total=0
        while True:
            part=os.read(fd,min(65536,LIMIT+1-total))
            if not part:break
            chunks.append(part);total+=len(part)
            if total>LIMIT:raise ValueError('kernel_table_unbounded')
        return b''.join(chunks)
    finally:os.close(fd)


def parent_guard(chain):
    for index,(fd,name,pin) in enumerate(chain):
        named=os.stat('/',follow_symlinks=False) if index==0 else os.stat(name,dir_fd=chain[index-1][0],follow_symlinks=False)
        if generation(os.fstat(fd))!=pin or generation(named)!=pin or not stat.S_ISDIR(named.st_mode):
            raise ValueError('route_parent_changed')


def file_pin(path, *, body=False, private=False):
    path=Path(path)
    if not path.is_absolute() or '..' in path.parts:raise ValueError('route_parent_unsafe')
    chain=[];leaf=-1
    try:
        flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW
        try:
            fd=os.open('/',flags);chain.append((fd,None,generation(os.fstat(fd))))
            for name in path.parent.parts[1:]:
                fd=os.open(name,flags,dir_fd=chain[-1][0]);chain.append((fd,name,generation(os.fstat(fd))))
        except OSError as exc:raise ValueError('route_parent_unsafe') from exc
        final=os.fstat(chain[-1][0])
        if final.st_uid!=os.getuid() or final.st_mode&0o022:raise ValueError('route_parent_unsafe')
        parent_guard(chain)
        before=os.stat(path.name,dir_fd=chain[-1][0],follow_symlinks=False)
        if not stat.S_ISREG(before.st_mode) or before.st_uid!=os.getuid() or before.st_nlink!=1 or before.st_mode&0o022 or private and stat.S_IMODE(before.st_mode)!=0o600:
            raise ValueError('route_file_unsafe')
        pin={'generation':generation(before),'parents':[{'name':name,'generation':meta} for _,name,meta in chain]}
        if body:
            leaf=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=chain[-1][0])
            if generation(os.fstat(leaf))!=pin['generation']:raise ValueError('route_file_changed')
            parent_guard(chain)
            chunks=[];total=0
            while True:
                chunk=os.read(leaf,65536)
                if not chunk:break
                chunks.append(chunk);total+=len(chunk)
                if total>1048576:raise ValueError('route_file_unbounded')
            raw=b''.join(chunks)
            if len(raw)!=before.st_size or generation(os.fstat(leaf))!=pin['generation']:raise ValueError('route_file_changed')
            pin.update(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),
                       unsupportedConfigDirectives=any(re.match(rb'\s*(include|match)\b',line,re.I) for line in raw.splitlines()))
        if generation(os.stat(path.name,dir_fd=chain[-1][0],follow_symlinks=False))!=pin['generation']:raise ValueError('route_file_changed')
        parent_guard(chain)
        return pin
    finally:
        if leaf>=0:os.close(leaf)
        for fd,_,_ in reversed(chain):os.close(fd)


def socket_snapshot(path):
    path=Path(path)
    if path.name!='m' or not re.fullmatch(r'r-[0-9a-f]{15,16}',path.parent.name) or not path.is_absolute():raise ValueError('socket_path_unsafe')
    chain=[]
    for name in (path.parent,*path.parent.parents):
        info=os.lstat(name)
        if not stat.S_ISDIR(info.st_mode) or (info.st_mode&0o022 and not (info.st_uid==0 and info.st_mode&stat.S_ISVTX)):
            raise ValueError('socket_parent_unsafe')
        chain.append({'path':str(name),'generation':generation(info)})
    directory=os.lstat(path.parent);socket=os.lstat(path)
    if directory.st_uid!=os.getuid() or stat.S_IMODE(directory.st_mode)!=0o700 or sorted(os.listdir(path.parent))!=['m']:
        raise ValueError('socket_directory_foreign')
    if not stat.S_ISSOCK(socket.st_mode) or socket.st_uid!=os.getuid() or stat.S_IMODE(socket.st_mode)!=0o600 or socket.st_nlink!=1:
        raise ValueError('socket_foreign')
    return {'socket':generation(socket),'directory':generation(directory),'ancestry':chain}


def net_namespace():
    return {'generation':generation(os.stat('/proc/self/ns/net')),'link':os.readlink('/proc/self/ns/net')}


def ssh_options(spec):
    return ['ssh','-F',spec['configFile'],'-S',spec['controlPath'],'-o','ControlMaster=no','-o','ControlPersist=no',
            '-o','ClearAllForwardings=yes','-o','PermitLocalCommand=no','-o','UpdateHostKeys=no','-o','ProxyCommand=false']


def effective_route(spec):
    result=subprocess.run([*ssh_options(spec),'-G',spec['remoteHostAlias']],capture_output=True,timeout=5)
    if result.returncode!=0 or len(result.stdout)>65536 or result.stderr:raise ValueError('effective_route_unknown')
    values={}
    for line in result.stdout.decode('utf-8',errors='strict').splitlines():
        name,_,value=line.partition(' ')
        if name=='identityfile':values.setdefault(name,[]).append(value)
    keys=values.get('identityfile',[])
    if not keys or any(not Path(p).is_absolute() for p in keys):raise ValueError('effective_key_unknown')
    existing={p:file_pin(p,private=True) for p in keys if os.path.lexists(p)}
    if not existing:raise ValueError('effective_key_unavailable')
    return {'effectiveSha256':hashlib.sha256(result.stdout).hexdigest(),'keyMetadata':existing}


def refusal(spec):
    result=subprocess.run([*ssh_options(spec),'-O','check',spec['remoteHostAlias']],capture_output=True,timeout=5)
    expected=('Control socket connect('+spec['controlPath']+'): Connection refused\r\n').encode()
    # OpenSSH builds without CR emit LF. No additional text or ambiguous errors.
    if result.returncode!=255 or result.stdout or result.stderr not in (expected,expected.replace(b'\r\n',b'\n')):
        raise ValueError('control_refusal_not_exact')
    return {'returnCode':255,'bytes':len(result.stderr),'sha256':hashlib.sha256(result.stderr).hexdigest(),'exactConnectionRefused':True}


def observe_remote(spec):
    config=file_pin(spec['configFile'],body=True)
    # Include/Match exec would add unpinned input or command execution.
    if config['unsupportedConfigDirectives']:raise ValueError('config_dependency_unsupported')
    if file_pin(spec['configFile'],body=True)!=config:raise ValueError('route_file_changed')
    initial=socket_snapshot(spec['controlPath']);namespace=net_namespace();route=effective_route(spec)
    observations=[]
    for _ in range(2):
        if socket_snapshot(spec['controlPath'])!=initial or net_namespace()!=namespace:raise ValueError('socket_or_namespace_changed')
        before=parse_unix_table(read_table(),spec['controlPath']);check=refusal(spec)
        after=parse_unix_table(read_table(),spec['controlPath'])
        if socket_snapshot(spec['controlPath'])!=initial or net_namespace()!=namespace or file_pin(spec['configFile'],body=True)!=config or effective_route(spec)!=route:
            raise ValueError('orphan_admission_changed')
        observations.append({'before':before,'check':check,'after':after})
    return {'schema':1,'state':'owned-orphan-observed','controlPath':spec['controlPath'],'socketSnapshot':initial,
            'netNamespace':namespace,'remoteConfigPin':config,'effectiveRoute':route,'observations':observations,
            'mutationPerformed':False,'credentialRead':False,'singleOperatorRequired':True}


def remote_source():
    functions=(generation,parse_unix_table,read_table,parent_guard,file_pin,socket_snapshot,net_namespace,ssh_options,effective_route,refusal,observe_remote)
    return ('import hashlib,json,os,re,stat,subprocess,sys\nfrom pathlib import Path\nHEADER='+repr(HEADER)+'\nLIMIT='+repr(LIMIT)+'\n'
            +'\n'.join(inspect.getsource(f) for f in functions)
            +'\nspec=json.loads(sys.argv[1]);print(json.dumps(observe_remote(spec),sort_keys=True,separators=(",",":")))\n')


def _owned_binding(root,config,host,stack):
    target=config.hosts[host];control=str(target.remote_control_path)
    if target.transport!='nested' or not target.gateway or target.remote_host_alias is None:raise ValueError('unsupported_route')
    matches=[];receipt_dir=stack.enter_context(Directory(root/'.rag_index/ssh-recovery-adoption'))
    names=os.listdir(receipt_dir.fd)
    if len(names)>4096:raise ValueError('adoption_history_unbounded')
    for name in names:
        if re.fullmatch(r'[0-9a-f]{64}\.adopted\.json',name):
            snapshot=stack.enter_context(Snapshot(receipt_dir,name));value=adoption._json(snapshot.body)
            if value.get('host')==host and value.get('controlPath')==control:matches.append((name,snapshot,value))
    if len(matches)!=1:raise ValueError('owned_adoption_not_unique')
    name,terminal,value=matches[0]
    if value.get('state')!='adopted' or type(value.get('schemaVersion'))is not int or value['schemaVersion']!=1:raise ValueError('adoption_incomplete')
    corr=value['correlationId']
    if not isinstance(corr,str) or not re.fullmatch(r'[0-9a-f]{32}',corr) or Path(control).parent.name!='r-'+corr[:15] or Path(control).name!='m':raise ValueError('correlation_socket_crossed')
    raw=adoption._json(stack.source.body)
    raw['hosts'][host]['remoteControlPath']=value['oldControlPath']
    previous=adoption._validate_candidate(adoption._encode(raw),root);old=previous.hosts[host]
    route_sha=adoption._route_sha(adoption._encode(raw),previous,host)
    key=adoption._route_key(host,value['oldControlPath'],control,corr,route_sha)
    if name!=key+'.adopted.json' or route_sha!=value['routeSha256']:raise ValueError('adoption_route_changed')
    path=recovery._intent_path(root,host,old);directory=stack.enter_context(Directory(path.parent));intent=stack.enter_context(Snapshot(directory,path.name))
    parsed=adoption._intent(intent,host,old)
    if parsed['controlPath']!=control or parsed['correlationId']!=corr or intent.pin()!=value['intent']:raise ValueError('recovery_history_changed')
    pending=stack.enter_context(Snapshot(receipt_dir,key+'.pending.json'))
    pv=adoption._json(pending.body)
    if any(pv.get(k)!=value.get(k) for k in ('host','controlPath','oldControlPath','correlationId','routeSha256','source','intent','ownershipLock')) or pv.get('state')!='pending':raise ValueError('adoption_pending_changed')
    return target,{'terminal':terminal.pin(),'pending':pending.pin(),'recovery':intent.pin(),'correlationId':corr},[terminal,pending,intent]


def observe(root: Path|str,host: str,correlation: str) -> dict:
    """Root-only fixed read-only remote observation; saves private proof locally."""
    if not re.fullmatch(r'[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}',correlation):raise ValueError('observation_uuid_required')
    root=Path(root).resolve(strict=True)
    with ExitStack() as stack:
        directory=stack.enter_context(Directory(root));receipts=stack.enter_context(lock_directory(directory));ownership=stack.enter_context(InventoryLock(receipts))
        source=stack.enter_context(Snapshot(directory,transport.CONFIG_FILENAME));stack.source=source
        source_directory=stack.enter_context(Directory(root/'agent_tools'))
        dependencies={}
        for name,sha in DEPENDENCIES.items():
            p=root/'agent_tools'/name;pin=file_pin(p,body=True)
            if pin['sha256']!=sha:raise ValueError('reviewed_dependency_changed')
            dependencies[str(p)]=pin
        own=file_pin(Path(__file__),body=True)
        config=adoption._validate_candidate(source.body,root);target,binding,histories=_owned_binding(root,config,host,stack)
        def guard():
            ownership.guard();source.guard();source_directory.guard()
            for h in histories:h.guard()
            for p,pin in dependencies.items():
                if file_pin(p,body=True)!=pin:raise ValueError('reviewed_dependency_changed')
            if file_pin(Path(__file__),body=True)!=own:raise ValueError('observer_source_changed')
        spec={'controlPath':str(target.remote_control_path),'remoteHostAlias':target.remote_host_alias,
              'configFile':str(target.remote_config_file) if target.remote_config_file else '~/.ssh/config'}
        # Resolve only the default config on the remote host, never an arbitrary caller path.
        remote=remote_source().replace('spec=json.loads(sys.argv[1]);','spec=json.loads(sys.argv[1]);spec["configFile"]=str(Path.home()/".ssh/config") if spec["configFile"]=="~/.ssh/config" else spec["configFile"];',1)
        prefix,endpoint=session._outer_prefix(config,transport.connection_host(config,target.gateway))
        import shlex
        argv=[*prefix,'-o','ControlMaster=no','-o','ControlPath=none','-o','ClearAllForwardings=yes','-o','PermitLocalCommand=no','-o','UpdateHostKeys=no',endpoint,
              shlex.join(('python3','-I','-B','-c',remote,json.dumps(spec,sort_keys=True)))]
        guard();completed=subprocess.run(argv,capture_output=True,timeout=25);guard()
        evidence=root/'.rag_index/ssh-nested-socket-retirement'
        evidence.mkdir(mode=0o700,exist_ok=True)
        with Directory(evidence) as output:
            base={'schema':1,'host':host,'correlationId':correlation,'binding':binding,'inventory':source.pin(),'dependencies':dependencies,'observer':own,'remoteSourceSha256':hashlib.sha256(remote.encode()).hexdigest()}
            # Private raw stderr is retained but never returned.
            for suffix,body in (('stdout',completed.stdout),('stderr',completed.stderr)):
                fd=os.open(correlation+'.'+suffix,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=output.fd)
                with os.fdopen(fd,'wb') as stream:stream.write(body);stream.flush();os.fsync(stream.fileno())
            if completed.returncode!=0 or len(completed.stdout)>65536:raise ValueError('remote_orphan_observation_unknown')
            result=adoption._json(completed.stdout)
            if result.get('state')!='owned-orphan-observed' or result.get('controlPath')!=spec['controlPath'] or result.get('mutationPerformed')is not False:raise ValueError('remote_orphan_binding_changed')
            proof={**base,'result':result};guard();pin=adoption._write_receipt(output,correlation+'.observation.json',proof);guard()
    return {'ok':True,'state':'owned-orphan-observed','correlationId':correlation,'proofSha256':pin['sha256'],'mutationPerformed':False}


def retire(*args,**kwargs):
    raise ValueError('actual_orphan_proof_review_required')
