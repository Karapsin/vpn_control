"""Retire an exact expired ready recovery intent, retaining immutable history.

Only fixed read-only gateway observations are available. A durable create-only
fence precedes exclusive local rename. Consumed attempts are status-only. The
inventory flock coordinates writers; guards do not promise CAS against actors
which ignore that lock. Original ready receipts contain no process birth proof.
"""
from __future__ import annotations
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from contextlib import ExitStack
from . import ssh_connection_recovery as recovery, ssh_recovery_adoption as adoption, ssh_transport as transport
from . import private_inventory_lock as private

_REMOTE = r'''
import json,os,re,stat,subprocess,sys
spec=json.loads(sys.argv[1]);paths=spec['paths'];alias=spec['alias'];config=spec['config']
if not paths or len(paths)!=2 or any(not p.startswith('/') or '..' in p.split('/') for p in paths):raise ValueError('paths')
def context():
 return {'bootId':open('/proc/sys/kernel/random/boot_id').read().strip(),'netNamespace':os.readlink('/proc/self/ns/net')}
def table(path):
 with open('/proc/net/unix','rb') as f:raw=f.read(1048577)
 if len(raw)>1048576 or not raw.endswith(b'\n') or not raw.startswith(b'Num       RefCount'):raise ValueError('table')
 count=0
 for row in raw.splitlines()[1:]:
  fields=row.split(None,7)
  if len(fields) not in (7,8) or not re.fullmatch(rb'[0-9a-fA-F]+:',fields[0]) or any(not re.fullmatch(rb'[0-9a-fA-F]+',x) for x in fields[1:6]) or not re.fullmatch(rb'[0-9]+',fields[6]):raise ValueError('row')
  if len(fields)==8 and fields[7].decode('utf-8','strict')==path:count+=1
 if count:raise ValueError('endpoint present')
 return {'completeEOF':True,'endpointCount':0,'rowCount':len(raw.splitlines())-1}
def absent(path):
 try:os.lstat(path)
 except FileNotFoundError:return True
 raise ValueError('path present')
before=context();result=[]
for path in paths:
 absent(path);first=table(path)
 argv=['ssh','-T']+(['-F',config] if config else [])+['-S',path,'-O','check',alias]
 check=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5)
 text=check.stderr.decode('utf-8','strict')
 expected='Control socket connect('+path+'): No such file or directory'
 if check.returncode!=255 or check.stdout!=b'' or text not in (expected,expected+'\n',expected+'\r\n'):raise ValueError('check unknown')
 absent(path);last=table(path)
 result.append({'controlPath':path,'pathAbsent':True,'check':{'returnCode':255,'exactMissingSocket':True},'before':first,'after':last})
after=context()
if before!=after:raise ValueError('context changed')
print(json.dumps({'state':'both-endpoints-absent','context':before,'observations':result,'mutationPerformed':False,'credentialRead':False},sort_keys=True))
'''.strip()


def _target(config,host):
    target=config.hosts[host]
    if target.transport!='nested' or not target.gateway or not target.remote_control_path or not target.remote_host_alias:raise ValueError('nested route required')
    return target


def _unknown():
    return {'state':'unknown','replayAllowed':False,'nextAction':'inspect-recovery-retirement'}


def _file_pin(path):
    with private.Directory(path.parent) as directory:
        directory.guard();fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory.fd)
        try:
            info=os.fstat(fd);generation=private._generation(info)
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_mode&0o022 or info.st_nlink!=1 or not 0<info.st_size<=1048576:raise ValueError('source unsafe')
            raw=os.read(fd,1048577)
            if len(raw)!=info.st_size or private._generation(os.fstat(fd))!=generation or private._generation(os.stat(path.name,dir_fd=directory.fd,follow_symlinks=False))!=generation:raise ValueError('source raced')
            directory.guard()
            return {'generation':list(generation),'size':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
        finally:os.close(fd)


class _SourceSnapshot(private.Snapshot):
    """Retained FD and named ancestry for an owned non-writable tool source."""
    def __init__(self,directory,name):
        self.directory=directory;self.name=name;self.fd=-1
        directory.guard()
        try:
            self.fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory.fd)
            info=os.fstat(self.fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_mode&0o022 or info.st_nlink!=1 or not 0<info.st_size<=1048576:raise ValueError('source unsafe')
            self.generation=private._generation(info);self.body=os.read(self.fd,1048577)
            if len(self.body)!=info.st_size:raise ValueError('source read incomplete')
            self.digest=hashlib.sha256(self.body).hexdigest();self.guard()
        except BaseException:
            self.close();raise


def _source_paths():
    return [str(Path(module.__file__).absolute()) for module in
            (sys.modules[__name__],recovery,adoption,transport,private)]


def _held_sources(stack,expected):
    if not isinstance(expected,dict) or set(expected)!=set(_source_paths()):raise ValueError('source set changed')
    result=[]
    for name,pin in expected.items():
        path=Path(name);directory=stack.enter_context(private.Directory(path.parent))
        source=stack.enter_context(_SourceSnapshot(directory,path.name))
        if source.pin()!=pin:raise ValueError('original source generation changed')
        result.append(source)
    return result


def source_authority():
    return {str(Path(module.__file__).absolute()):_file_pin(Path(module.__file__).absolute()) for module in
            (sys.modules[__name__],recovery,adoption,transport,private)}


def _names(intent_path,correlation):
    key=hashlib.sha256((intent_path.name+'\0'+correlation).encode()).hexdigest()
    return ('.retire-'+key+'.pending.json','.retire-'+key+'.terminal.json','.retired-'+key+'.intent.json')


def _observe(config,target,correlation,timeout):
    derived=recovery._recovery_socket_path(target,correlation)
    if derived is None:raise ValueError('path unavailable')
    spec={'paths':[str(target.remote_control_path),str(derived[1])],'alias':target.remote_host_alias,'config':str(target.remote_config_file or '')}
    result=recovery._gateway_run(config,target,('python3','-I','-B','-c',f'exec({_REMOTE!r})',json.dumps(spec,sort_keys=True)),timeout)
    if result is None or result.returncode!=0 or result.stderr or len(result.stdout)>8192:raise ValueError('absence unknown')
    return adoption._json(result.stdout.encode())


def _proof(value,target,correlation):
    paths=[str(target.remote_control_path),str(recovery._recovery_socket_path(target,correlation)[1])]
    if set(value)!={'state','context','observations','mutationPerformed','credentialRead'} or value['state']!='both-endpoints-absent' or value['mutationPerformed']is not False or value['credentialRead']is not False:raise ValueError('positive absence required')
    context=value['context']
    if not isinstance(context,dict) or set(context)!={'bootId','netNamespace'} or not re.fullmatch(r'[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}',context.get('bootId','')) or not re.fullmatch(r'net:\[[0-9]+\]',context.get('netNamespace','')):raise ValueError('kernel context required')
    rows=value['observations']
    if not isinstance(rows,list) or len(rows)!=2:raise ValueError('both paths required')
    for path,row in zip(paths,rows):
        if set(row)!={'controlPath','pathAbsent','check','before','after'} or row['controlPath']!=path or row['pathAbsent']is not True or row['check']!={'returnCode':255,'exactMissingSocket':True}:raise ValueError('socket absence unproven')
        for name in ('before','after'):
            table=row[name]
            if set(table)!={'completeEOF','endpointCount','rowCount'} or table['completeEOF']is not True or type(table['endpointCount'])is not int or table['endpointCount']!=0 or type(table['rowCount'])is not int or table['rowCount']<0:raise ValueError('kernel absence unproven')
    return value


def authority(root,host,correlation):
    """Read exact local review pins; these contain no remote absence authority."""
    presented=private.PresentedPath(Path(root).absolute())
    with private.Directory(presented.canonical) as directory, private.Snapshot(directory,transport.CONFIG_FILENAME) as source:
        config=adoption._validate_candidate(source.body,presented.canonical);target=_target(config,host)
        path=recovery._intent_path(presented.canonical,host,target)
        with private.Directory(path.parent) as intents,private.Snapshot(intents,path.name) as intent:
            value=adoption._intent(intent,host,target)
            if value['correlationId']!=correlation:raise ValueError('correlation changed')
            presented.guard();source.guard();intent.guard()
            return {'inventory_pin':source.pin(),'intent_pin':intent.pin(),'source_pins':source_authority()}


def _rename(directory,old,new):
    libc=ctypes.CDLL(None,use_errno=True)
    if sys.platform=='darwin':function=libc.renameatx_np;flag=4
    elif sys.platform.startswith('linux'):function=libc.renameat2;flag=1
    else:raise ValueError('exclusive rename unsupported')
    function.argtypes=[ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint];function.restype=ctypes.c_int
    if function(directory.fd,os.fsencode(old),directory.fd,os.fsencode(new),flag)!=0:raise OSError(ctypes.get_errno(),'exclusive archive failed')


def _close_generations(*snapshots):
    """Generation-only closure after every potentially mutating body read.

    Full ctime and named/FD identity are checked, with no later content read
    before the local effect. This remains cooperative ownership, not CAS.
    """
    for snapshot in snapshots:
        snapshot.directory.guard()
        if private._generation(os.fstat(snapshot.fd))!=snapshot.generation or private._generation(os.stat(snapshot.name,dir_fd=snapshot.directory.fd,follow_symlinks=False))!=snapshot.generation:
            raise ValueError('final held generation changed')
    for snapshot in snapshots:snapshot.directory.guard()


def _status(directory,pending_name,terminal_name,archive_name,*,stack=None,snapshots=None,held_sources=None):
    with ExitStack() as local:
        holder=stack if stack is not None else local
        pending=holder.enter_context(private.Snapshot(directory,pending_name))
        value=adoption._json(pending.body)
        fields={'schemaVersion','state','host','correlationId','originalName','originalIntent','inventory','sources','archive','absence','replayAllowed'}
        if set(value)!=fields or type(value['schemaVersion'])is not int or value['schemaVersion']!=1 or value['state']!='pending' or value['replayAllowed']is not False or not isinstance(value['host'],str) or not transport._ALIAS_RE.fullmatch(value['host']) or not isinstance(value['correlationId'],str) or not re.fullmatch(r'[0-9a-f]{32}',value['correlationId']) or not isinstance(value['originalName'],str) or not re.fullmatch(re.escape(value['host'])+r'-[0-9a-f]{64}\.json',value['originalName']) or _names(Path(value['originalName']),value['correlationId'])!=(pending_name,terminal_name,archive_name):raise ValueError('retirement fence unsupported')
        sources=held_sources if held_sources is not None else _held_sources(holder,value['sources'])
        if {str(source.directory.path/source.name):source.pin() for source in sources}!=value['sources']:raise ValueError('held source authority changed')
        if not adoption._exists(directory,terminal_name):return _unknown()
        terminal=holder.enter_context(private.Snapshot(directory,terminal_name));archive=holder.enter_context(private.Snapshot(directory,archive_name))
        result=adoption._json(terminal.body)
        if type(result.get('schemaVersion'))is not int:raise ValueError('terminal schema unsupported')
        if result!={'schemaVersion':1,'state':'retired','pending':pending.pin(),'archive':archive_name,'archived':archive.pin()} or value.get('archive')!=archive_name or value.get('originalIntent',{}).get('sha256')!=archive.digest or value.get('originalIntent',{}).get('size')!=len(archive.body):raise ValueError('archive terminal changed')
        original=value['originalIntent']['generation'];current=archive.pin()['generation']
        if original[:8]!=current[:8] or current[8]<original[8]:raise ValueError('archive generation changed')
        retained=[*sources,archive,terminal,pending]
        for source in retained:source.guard()
        # Only generation/ancestry checks follow the last content read.
        _close_generations(*retained)
        if snapshots is not None:snapshots.extend(retained)
        return {'state':'retired','replayAllowed':False,'nextAction':'connection-recover','historicalStatus':True}


def status(root,host,correlation):
    try:
        presented=private.PresentedPath(Path(root).absolute())
        with private.Directory(presented.canonical) as directory,private.Snapshot(directory,transport.CONFIG_FILENAME) as source:
            config=adoption._validate_candidate(source.body,presented.canonical);path=recovery._intent_path(presented.canonical,host,_target(config,host))
            with private.Directory(path.parent) as intents,ExitStack() as held:
                retained=[]
                answer=_status(intents,*_names(path,correlation),stack=held,snapshots=retained)
                presented.guard();source.guard();_close_generations(source,*retained);return answer
    except (OSError,ValueError,TypeError,KeyError):return _unknown()


def require_admission(root,host,target,*,stack=None,snapshots=None):
    """Fail closed on any consumed retirement without exact archived terminal.

    Call while holding private inventory ownership before a successor is made.
    This is local historical validation and never contacts a remote endpoint.
    """
    path=recovery._intent_path(Path(root),host,target)
    if not path.parent.exists():return
    with ExitStack() as local:
        holder=stack if stack is not None else local
        directory=holder.enter_context(private.Directory(path.parent))
        names=os.listdir(directory.fd)
        if len(names)>4096:raise ValueError('retirement history unbounded')
        for name in names:
            if not re.fullmatch(r'\.retire-[0-9a-f]{64}\.pending\.json',name):continue
            pending=holder.enter_context(private.Snapshot(directory,name))
            value=adoption._json(pending.body)
            expected=_names(Path(value['originalName']),value['correlationId'])
            # Validate every discovered retirement fence before deciding
            # whether its host applies; missing/malformed host is unknown.
            result=_status(directory,*expected,stack=holder,snapshots=snapshots)
            if value.get('host')!=host:continue
            if name!=expected[0] or result['state']!='retired':raise ValueError('unresolved retirement history')
            if snapshots is not None:snapshots.append(pending)
            pending.guard()
            _close_generations(pending,*(snapshots or []))
        directory.guard()


def retire(root,host,correlation,*,inventory_pin,intent_pin,source_pins,timeout=5):
    if type(timeout)is not int or not 1<=timeout<=60 or not isinstance(host,str) or not transport._ALIAS_RE.fullmatch(host) or not isinstance(correlation,str) or not re.fullmatch(r'[0-9a-f]{32}',correlation):return _unknown()
    try:
        with private.ownership(root) as (presented,directory,ownership),ExitStack() as stack:
            source=stack.enter_context(private.Snapshot(directory,transport.CONFIG_FILENAME))
            config=adoption._validate_candidate(source.body,presented.canonical);target=_target(config,host)
            path=recovery._intent_path(presented.canonical,host,target)
            intents=stack.enter_context(private.Directory(path.parent));pending_name,terminal_name,archive_name=_names(path,correlation)
            if adoption._exists(intents,pending_name):
                closing=[]
                answer=_status(intents,pending_name,terminal_name,archive_name,stack=stack,snapshots=closing)
                presented.guard();ownership.guard();source.guard();_close_generations(source,*closing)
                return answer
            if adoption._exists(intents,terminal_name) or adoption._exists(intents,archive_name):return _unknown()
            intent=stack.enter_context(private.Snapshot(intents,path.name));value=adoption._intent(intent,host,target)
            if value['correlationId']!=correlation or source.pin()!=inventory_pin or intent.pin()!=intent_pin :raise ValueError('exact authority required')
            tools=_held_sources(stack,source_pins)
            receipts=stack.enter_context(private.lock_directory(directory))
            def guard():
                presented.guard();ownership.guard();source.guard();intent.guard();receipts.guard();intents.guard()
                for tool in tools:tool.guard()
                key=adoption._route_key(host,str(target.remote_control_path),value['controlPath'],correlation,adoption._route_sha(source.body,config,host))
                if any(adoption._exists(receipts,key+'.'+kind+'.json') for kind in ('pending','adopted')) or adoption._intent_fenced(receipts,host,str(target.remote_control_path),value['controlPath'],correlation):raise ValueError('adoption already consumed')
            guard();first=_proof(_observe(config,target,correlation,timeout),target,correlation);guard()
            pending_value={'schemaVersion':1,'state':'pending','host':host,'correlationId':correlation,'originalName':path.name,'originalIntent':intent.pin(),'inventory':source.pin(),'sources':source_pins,'archive':archive_name,'absence':first,'replayAllowed':False}
            pending_pin=adoption._write_receipt(intents,pending_name,pending_value)
            pending=stack.enter_context(private.Snapshot(intents,pending_name))
            if pending.pin()!=pending_pin:raise ValueError('pending changed')
            guard();pending.guard();second=_proof(_observe(config,target,correlation,timeout),target,correlation)
            if second['context']!=first['context']:raise ValueError('kernel context changed')
            if adoption._exists(intents,terminal_name) or adoption._exists(intents,archive_name):raise ValueError('archive collision')
            guard();pending.guard();intent.guard()
            _close_generations(*tools,intent,source,pending)
            _rename(intents,path.name,archive_name);os.fsync(intents.fd)
            archive=stack.enter_context(private.Snapshot(intents,archive_name))
            if archive.body!=intent.body or archive.pin()['generation'][:8]!=intent.pin()['generation'][:8]:raise ValueError('archived original changed')
            presented.guard();ownership.guard();source.guard();pending.guard();archive.guard()
            for tool in tools:tool.guard()
            _close_generations(*tools,source,pending,archive)
            terminal={'schemaVersion':1,'state':'retired','pending':pending.pin(),'archive':archive_name,'archived':archive.pin()}
            adoption._write_receipt(intents,terminal_name,terminal)
            closing=[]
            answer=_status(intents,pending_name,terminal_name,archive_name,held_sources=tools,stack=stack,snapshots=closing)
            presented.guard();ownership.guard();source.guard();pending.guard();archive.guard()
            for tool in tools:tool.guard()
            _close_generations(*tools,source,pending,archive,*closing)
            return answer
    except (OSError,ValueError,TypeError,KeyError,AttributeError,transport.SshConfigError,recovery.RecoveryError):return _unknown()
