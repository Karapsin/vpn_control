"""Current readiness admission over immutable original nested-channel capsules.

The legacy provider remains unchanged: this separate read-only observation route
executes only its original status capsule, verifies the original ready receipt,
and retains connection identity across unrelated coordinator source revisions.
"""
from __future__ import annotations
from contextlib import ExitStack,contextmanager
from dataclasses import asdict,dataclass
import hashlib
import ast
import stat
import types
import sys

_EXECUTING_CODE=sys._getframe().f_code
import json
import os
from pathlib import Path
import re
import shlex
import time

from . import private_inventory_lock as private
from . import ssh_connection_session as session
from . import ssh_fresh_nested_channel as channel
from . import ssh_transport as transport
from . import readiness_nested_membership as membership

GROUP='.rag_index/readiness-nested-channel'

class NestedUnknown(ValueError):
    pass

class NestedEnded(NestedUnknown):
    pass


class NestedIntegrityChanged(NestedUnknown):
    pass


class DirectoryMembershipChanged(NestedUnknown):
    """Positive finite original authority proof; no old-route dispatch grant."""
    def __init__(self,correlation,receipt,proof,records_fingerprint):
        super().__init__('nested_directory_membership_changed')
        self.correlation=correlation;self.receipt=receipt;self.proof=proof;self.records_fingerprint=records_fingerprint


def directory(root,host):
    if type(host)is not str or transport._ALIAS_RE.fullmatch(host)is None:raise NestedUnknown('nested_host')
    return Path(root).absolute()/GROUP/host


def present(root,host):
    return os.path.lexists(directory(root,host)/'current.json')


@contextmanager
def _original_records(root,host,corr,receipt):
    channel._corr(corr)
    if type(receipt)is not str or re.fullmatch('[0-9a-f]{64}',receipt)is None:raise NestedUnknown('nested_receipt')
    root=Path(root).resolve(strict=True)
    with ExitStack()as stack:
        base=stack.enter_context(private.Directory(root))
        config=transport.load_config(root);target=config.hosts[host]
        if target.transport!='nested' or len(transport._route_hosts(config.hosts,host))!=2:raise NestedUnknown('nested_route')
        parent=stack.enter_context(private.Directory(channel._context_journal(root,host,corr,False,True)))
        intent=stack.enter_context(private.Snapshot(parent,corr+'.intent.json'))
        ready=stack.enter_context(private.Snapshot(parent,corr+'.ready.json'))
        value=json.loads(intent.body,object_pairs_hook=transport._reject_duplicate_keys)
        admitted=json.loads(ready.body,object_pairs_hook=transport._reject_duplicate_keys)
        if type(value)is not dict or type(admitted)is not dict:raise NestedUnknown('nested_record_schema')
        from . import ssh_direct_nested_channel as direct
        version=value.get('version')
        config_pin=stack.enter_context(direct.private_inventory(root) if version==3 else private.Snapshot(base,transport.CONFIG_FILENAME))
        if version==3:
            config=config_pin.load_config(root);target=config.hosts[host]
            if target.transport!='nested' or len(transport._route_hosts(config.hosts,host))!=2:raise NestedUnknown('nested_route')
        if (version not in (2,3) or value.get('host')!=host or value.get('correlationId')!=corr
                or value.get('transportMode')!='direct' or value.get('inventory')!=config_pin.pin()
                or ready.digest!=receipt or admitted.get('intent')!=intent.pin()):raise NestedUnknown('nested_original_binding')
        # The complete historical fixed source catalog is retained as data.
        # Never import an old local module or substitute current source bytes.
        from . import ssh_direct_nested_channel as direct
        if set(value.get('directSourcePins',{}))!=set(direct.source_catalog(version)):raise NestedUnknown('nested_source_catalog')
        hashes={'remote':value['remoteSourceSha256'],'ssh_fresh_nested_channel.py':value['sourceSha256'],**value['directSourcePins']}
        capsules=[]
        for name,digest in hashes.items():
            held=stack.enter_context(private.Snapshot(parent,corr+'.'+name+'.source'))
            if held.digest!=digest:raise NestedUnknown('nested_capsule_changed')
            capsules.append(held)
            if name=='remote':remote=held.body.decode()
        def guard():
            for held in [config_pin,intent,ready,*capsules]:held.guard()
        inventory_pin=config_pin.pin()
        fingerprint=hashlib.sha256(session._json({'host':host,'root':str(root),
            'inventoryGeneration':inventory_pin['generation'],'intent':intent.pin(),'ready':ready.pin(),
            'capsules':[(name,held.pin())for name,held in zip(hashes,capsules)]})).hexdigest()
        guard()
        yield config,target,value,admitted,remote,guard,fingerprint
        guard()


def _metadata(actual,corr,receipt):
    if (actual.get('state')!='ready' or actual.get('controlPath')!='/tmp/vpn-channel-'+corr+'/m'
            or actual.get('correlationId')!=corr or not channel._peer_shape(actual.get('arch'))
            or not channel._master_shape(actual.get('master'))):raise NestedUnknown('nested_original_schema')
    return {'correlationId':corr,'receiptSha256':receipt,'controlPath':actual['controlPath'],
            'boot':actual['arch']['boot'],'uid':actual['arch']['uid']}


def _original(root,host,corr,receipt,deadline=None):
    _guard_binding_source()
    with _original_records(root,host,corr,receipt)as(config,target,value,admitted,remote,guard,fingerprint):
        gateway=transport.connection_host(config,target.gateway)
        prefix,endpoint=transport.fresh_direct_prefix(config,gateway.alias)
        argv=[*prefix,'-S','none','-o','ControlMaster=no','-o','ControlPersist=no','-T',endpoint,
              shlex.join(('python3','-I','-B','-c','exec('+repr(remote)+')',corr,'status',
                          str(target.remote_config_file or ''),target.remote_host_alias,value['sourceSha256']))]
        guard()
        timeout=35 if deadline is None else min(35,deadline-time.monotonic())
        if timeout<=0:raise NestedUnknown('nested_original_deadline')
        captured=channel._collect(argv,b'{}',timeout)
        guard()
        if (not captured['complete'] or captured['overflow'] or captured['returnCode']!=0 or captured['stderr']):
            # Only this complete, finite original refusal can trigger a second
            # read-only diagnostic. Other uncertainty retains its old blocker.
            try:refusal=json.loads(captured['stdout'],object_pairs_hook=transport._reject_duplicate_keys)
            except (ValueError,TypeError):refusal=None
            if (captured['complete'] and not captured['overflow'] and captured['returnCode']==3 and not captured['stderr']
                    and type(refusal)is dict and set(refusal)=={'state','correlationId','failurePhase','failureReason','exceptionClass','errno','launchCapture'}
                    and refusal.get('launchCapture')is None and refusal.get('state')=='unknown' and refusal.get('correlationId')==corr
                    and refusal.get('failurePhase')=='remote_intent' and refusal.get('failureReason')=='remote_intent_changed'
                    and refusal.get('exceptionClass')=='ValueError' and refusal.get('errno')is None):
                try:diagnostic=membership.diagnostic_source(remote)
                except ValueError:raise NestedUnknown('nested_original_unknown')from None
                argv[-1]=shlex.join(('python3','-I','-B','-c','exec('+repr(diagnostic)+')',corr,'status',
                                    str(target.remote_config_file or ''),target.remote_host_alias,value['sourceSha256']))
                guard()
                timeout=35 if deadline is None else max(0,min(35,deadline-time.monotonic()))
                if timeout<=0:raise NestedUnknown('nested_original_unknown')
                checked=channel._collect(argv,b'{}',timeout);guard()
                if checked['complete'] and not checked['overflow'] and checked['returnCode']==3 and not checked['stderr']:
                    try:other=json.loads(checked['stdout'],object_pairs_hook=transport._reject_duplicate_keys)
                    except (ValueError,TypeError):other=None
                    if (type(other)is dict and set(other)==set(refusal) and other.get('correlationId')==corr
                            and other.get('failurePhase')=='remote_intent' and other.get('failureReason')=='remote_intent_changed'
                            and other.get('exceptionClass')=='ValueError' and other.get('errno')is None and other.get('launchCapture')is None):
                        raise NestedIntegrityChanged('nested_original_integrity_changed')
                if checked['complete'] and not checked['overflow'] and checked['returnCode']==0 and not checked['stderr']:
                    try:proof=json.loads(checked['stdout'],object_pairs_hook=transport._reject_duplicate_keys)
                    except (ValueError,TypeError):proof=None
                    fields={'state','correlationId','gatewayBoot','sourceSha256','originalIntentSha256','currentIntentSha256'}
                    if (type(proof)is dict and set(proof)==fields and proof['state']=='directory_membership_changed'
                            and proof['correlationId']==corr and proof['gatewayBoot']==admitted['result']['master']['gatewayBoot']
                            and proof['sourceSha256']==value['sourceSha256']
                            and all(type(proof[k])is str and re.fullmatch('[0-9a-f]{64}',proof[k])for k in ('originalIntentSha256','currentIntentSha256'))):
                        raise DirectoryMembershipChanged(corr,receipt,proof,fingerprint)
            raise NestedUnknown('nested_original_unknown')
        actual=json.loads(captured['stdout'],object_pairs_hook=transport._reject_duplicate_keys)
        if type(actual)is not dict:raise NestedUnknown('nested_original_schema')
        if (set(actual)=={'state','correlationId','prior','gatewayBoot'} and actual.get('state')=='ended'
                and actual.get('correlationId')==corr and actual.get('prior')==admitted.get('result')
                and actual.get('gatewayBoot')==admitted['result']['master']['gatewayBoot']):
            raise NestedEnded('nested_original_ended')
        if actual!=admitted.get('result'):raise NestedUnknown('nested_original_changed')
        return _metadata(actual,corr,receipt)


def admit(root,host,corr,receipt):
    """Explicit new readiness selection; original legacy history stays intact."""
    observed=_original(root,host,corr,receipt)
    for path in (Path(root)/'.rag_index',Path(root)/GROUP,directory(root,host)):
        path.mkdir(mode=0o700,exist_ok=True)
    with private.Directory(directory(root,host))as parent,private.InventoryLock(parent):
        record={'version':1,'host':host,'correlationId':corr,'receiptSha256':receipt}
        name='admission-'+corr+'.json'
        if not os.path.lexists(parent.path/name):session._create(parent.path/name,record,parent_fd=parent.fd)
        with private.Snapshot(parent,name)as held:
            if json.loads(held.body)!=record:raise NestedUnknown('nested_admission_changed')
            temporary='pointer-'+hashlib.sha256(os.urandom(32)).hexdigest()+'.json'
            session._create(parent.path/temporary,record,parent_fd=parent.fd)
            os.replace(temporary,'current.json',src_dir_fd=parent.fd,dst_dir_fd=parent.fd);os.fsync(parent.fd)
            held.guard();parent.guard()
    return {'state':'selected','host':host,**observed}


def route_options(root,host,config=None,deadline=None):
    if config is not None and asdict(transport.load_config(root))!=asdict(config):raise NestedUnknown('nested_configuration_changed')
    with private.Directory(directory(root,host))as parent,private.Snapshot(parent,'current.json')as current:
        value=json.loads(current.body,object_pairs_hook=transport._reject_duplicate_keys)
        if (type(value)is not dict or set(value)!={'version','host','correlationId','receiptSha256'}
                or type(value.get('version'))is not int or value['version']!=1 or value.get('host')!=host):raise NestedUnknown('nested_selection_binding')
        observed=_original(root,host,value['correlationId'],value['receiptSha256'],deadline)
        current.guard();parent.guard();return observed


_ROUTE_ISSUER=object()
_SOURCE_SHA=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


@dataclass(frozen=True)
class RouteBinding:
    """Private live-observed route witness; static recustody grants no dispatch."""
    root: str
    host: str
    fingerprint: str
    records_fingerprint: str
    metadata: tuple
    issuer: object


def _source_state(root,host,config=None):
    root=Path(root).resolve(strict=True)
    with private.Directory(directory(root,host))as parent,private.Snapshot(parent,'current.json')as current:
        value=json.loads(current.body,object_pairs_hook=transport._reject_duplicate_keys)
        if (type(value)is not dict or set(value)!={'version','host','correlationId','receiptSha256'}
                or type(value.get('version'))is not int or value['version']!=1 or value.get('host')!=host):raise NestedUnknown('nested_selection_binding')
        with _original_records(root,host,value['correlationId'],value['receiptSha256'])as(actual_config,target,intent,admitted,remote,guard,fingerprint):
            if config is not None and asdict(actual_config)!=asdict(config):raise NestedUnknown('nested_configuration_changed')
            metadata=_metadata(admitted['result'],value['correlationId'],value['receiptSha256'])
            combined=hashlib.sha256(session._json([fingerprint,current.pin()])).hexdigest()
            guard();current.guard();parent.guard()
            return combined,fingerprint,metadata


def _held_source(path):
    path=Path(path).absolute()
    with private.Directory(path.parent)as parent:
        fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent.fd)
        try:
            before=os.fstat(fd)
            if (not stat.S_ISREG(before.st_mode)or before.st_uid!=os.getuid()or before.st_nlink!=1
                    or not 0<before.st_size<=1048576):raise NestedUnknown('nested_binding_source_changed')
            raw=os.read(fd,1048577)
            def generation(info):return (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns)
            if (len(raw)!=before.st_size or generation(os.fstat(fd))!=generation(before)
                    or generation(os.stat(path.name,dir_fd=parent.fd,follow_symlinks=False))!=generation(before)):
                raise NestedUnknown('nested_binding_source_changed')
            parent.guard();return raw
        finally:os.close(fd)


def _compiled_function(code,qualname):
    for value in code.co_consts:
        if isinstance(value,types.CodeType):
            if value.co_qualname==qualname:return value
            nested=_compiled_function(value,qualname)
            if nested is not None:return nested
    return None


def verify_executing_sources():
    """Authenticate loaded direct code as well as current source file bytes."""
    own=_held_source(__file__)
    if hashlib.sha256(own).hexdigest()!=_SOURCE_SHA:raise NestedUnknown('nested_binding_source_changed')
    code=compile(own,__file__,'exec',dont_inherit=True)
    if _EXECUTING_CODE!=code:raise NestedUnknown('nested_binding_executing_code_changed')
    helper_path=Path(__file__).with_name('readiness_nested_membership.py')
    if Path(membership.__file__).absolute()!=helper_path.absolute():raise NestedUnknown('nested_binding_source_changed')
    raw=_held_source(helper_path);tree=ast.parse(raw)
    constants={node.targets[0].id:node.value for node in tree.body if isinstance(node,ast.Assign)
               and len(node.targets)==1 and isinstance(node.targets[0],ast.Name)}
    comparator=ast.literal_eval(constants['_COMPARATOR'])
    reviewed=ast.literal_eval(constants['_REVIEWED'].args[0])
    if membership._COMPARATOR!=comparator or membership._REVIEWED!=frozenset(reviewed):
        raise NestedUnknown('nested_binding_executing_code_changed')
    compiled=compile(raw,membership.__file__,'exec',dont_inherit=True)
    if getattr(membership,'_EXECUTING_CODE',None)!=compiled:raise NestedUnknown('nested_binding_executing_code_changed')
    if membership.diagnostic_source.__code__!=_compiled_function(compiled,'diagnostic_source'):
        raise NestedUnknown('nested_binding_executing_code_changed')
    comparator_code=compile(comparator,membership.__file__+':comparator','exec',flags=__import__('__future__').annotations.compiler_flag,dont_inherit=True)
    if membership.membership_only.__code__!=_compiled_function(comparator_code,'membership_only'):
        raise NestedUnknown('nested_binding_executing_code_changed')


def _guard_binding_source():
    verify_executing_sources()


def qualified_route(root,host,config=None,deadline=None):
    """Issue only after complete actual original status; keep default getters live."""
    _guard_binding_source()
    actual=route_options(root,host,config,deadline)
    fingerprint,records_fingerprint,metadata=_source_state(root,host,config)
    if metadata!=actual:raise NestedUnknown('nested_binding_generation_changed')
    _guard_binding_source()
    return RouteBinding(str(Path(root).resolve(strict=True)),host,fingerprint,records_fingerprint,tuple(sorted(metadata.items())),_ROUTE_ISSUER)


def source_options(binding,root,host,config=None):
    """Read only static custody of one previously live-observed original route."""
    _guard_binding_source()
    if (type(binding)is not RouteBinding or binding.issuer is not _ROUTE_ISSUER
            or binding.root!=str(Path(root).resolve(strict=True))or binding.host!=host):raise NestedUnknown('nested_foreign_route_binding')
    fingerprint,records_fingerprint,metadata=_source_state(root,host,config)
    if fingerprint!=binding.fingerprint or tuple(sorted(metadata.items()))!=binding.metadata:raise NestedUnknown('nested_binding_generation_changed')
    _guard_binding_source()
    return metadata


def original_source_options(binding,root,host,config=None):
    """Historical custody only, never current connection admission or dispatch."""
    _guard_binding_source()
    if (type(binding)is not RouteBinding or binding.issuer is not _ROUTE_ISSUER
            or binding.root!=str(Path(root).resolve(strict=True))or binding.host!=host):raise NestedUnknown('nested_foreign_route_binding')
    metadata=dict(binding.metadata)
    with _original_records(root,host,metadata['correlationId'],metadata['receiptSha256'])as(actual_config,target,intent,admitted,remote,guard,fingerprint):
        if config is not None and asdict(actual_config)!=asdict(config):raise NestedUnknown('nested_configuration_changed')
        if fingerprint!=binding.records_fingerprint or _metadata(admitted['result'],metadata['correlationId'],metadata['receiptSha256'])!=metadata:raise NestedUnknown('nested_original_binding_changed')
        guard();_guard_binding_source()
        return metadata


_SUCCESSOR_ISSUER=object()
class _MembershipSuccessor:
    """Ephemeral held original source authority, never a dispatchable route."""
    def __init__(self,root,host,correlation,receipt,guard):
        self.root=root;self.host=host;self.correlation=correlation
        self.receipt=receipt;self._guard=guard;self._issuer=_SUCCESSOR_ISSUER;self.closed=False


def validate_membership_successor(proof,root,host,previous=None,new_correlation=None):
    _guard_binding_source()
    if (type(proof)is not _MembershipSuccessor or proof._issuer is not _SUCCESSOR_ISSUER or proof.closed
            or proof.root!=str(Path(root).resolve(strict=True))or proof.host!=host):
        raise NestedUnknown('nested_foreign_successor_proof')
    if previous is not None and previous!=proof.correlation:return False
    if new_correlation is not None:
        channel._corr(new_correlation)
        if new_correlation==proof.correlation:raise NestedUnknown('nested_successor_socket_reused')
    proof._guard();_guard_binding_source()
    return True


def _ended_selection(stack,root,host,current,predecessor):
    """Hold the exact retained terminal of a selected channel that ended normally."""
    if (type(current)is not dict or set(current)!={'version','host','correlationId','receiptSha256'}
            or current['version']!=1 or current['host']!=host or current['correlationId']==predecessor):
        raise NestedUnknown('nested_selection_binding')
    corr=current['correlationId'];channel._corr(corr)
    try:
        parent=stack.enter_context(private.Directory(channel._context_journal(root,host,corr,False,True)))
        intent=stack.enter_context(private.Snapshot(parent,corr+'.intent.json'))
        ready=stack.enter_context(private.Snapshot(parent,corr+'.ready.json'))
        terminal=stack.enter_context(private.Snapshot(parent,corr+'.terminal.json'))
    except FileNotFoundError:
        raise NestedUnknown('nested_selection_binding') from None
    admitted=json.loads(ready.body,object_pairs_hook=transport._reject_duplicate_keys)
    ended=json.loads(terminal.body,object_pairs_hook=transport._reject_duplicate_keys)
    master=admitted.get('result',{}).get('master') if type(admitted)is dict and type(admitted.get('result'))is dict else None
    if (ready.digest!=current['receiptSha256'] or type(master)is not dict
            or ended!={'state':'ended','correlationId':corr,'receiptSha256':ready.digest,
                       'intentSha256':intent.digest,'gatewayBoot':master.get('gatewayBoot')}):
        raise NestedUnknown('nested_selection_binding')
    def guard():
        for held in (parent,intent,ready,terminal):held.guard()
    guard();return guard


@contextmanager
def membership_successor(root,host,correlation,receipt,deadline=None):
    """Hold a positively unusable immutable original while creating another.

    Source/custody drift other than the finite directory-membership condition
    never issues this scope. Closing it invalidates every retained reference.
    The selection names this original, or a later successor whose exact
    retained terminal proves it ended; the original itself stays unresolved.
    """
    _guard_binding_source()
    with private.Directory(directory(root,host))as selected,private.Snapshot(selected,'current.json')as pointer,ExitStack()as held_selection:
        try:_original(root,host,correlation,receipt,deadline)
        except DirectoryMembershipChanged as observed:diagnosed_fingerprint=observed.records_fingerprint
        else:raise NestedUnknown('nested_successor_original_not_unavailable')
        pointer.guard();selected.guard()
        current=json.loads(pointer.body,object_pairs_hook=transport._reject_duplicate_keys)
        selection_guard=lambda:None
        if current!={'version':1,'host':host,'correlationId':correlation,'receiptSha256':receipt}:
            selection_guard=_ended_selection(held_selection,root,host,current,correlation)
        with _original_records(root,host,correlation,receipt)as(_config,_target,_intent,_admitted,_remote,guard,_fingerprint):
            if _fingerprint!=diagnosed_fingerprint:raise NestedUnknown('nested_successor_original_generation_changed')
            def held_guard():
                pointer.guard();selected.guard();selection_guard();guard();_guard_binding_source()
            proof=_MembershipSuccessor(str(Path(root).resolve(strict=True)),host,correlation,receipt,held_guard)
            held_guard()
            try:yield proof
            finally:
                proof.closed=True;held_guard()
