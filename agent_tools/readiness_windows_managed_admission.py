"""Managed-first originals and current admission; never provision or sign in.

Pure loading retains original creator, seed and bootstrap packets. Only a fresh
actual original-owner observer can provide historical bootstrap authority.
Running admission independently verifies current public no-seed graphs,
storage, actual TPM ownership and Windows identity. Stopped observation makes
no clean-shutdown or current TPM claim and never asks a stopped guest for QGA.
"""
import hashlib
import inspect
import json
import math
import os
import stat
from pathlib import Path
import subprocess
import sys
import time
import weakref
from uuid import UUID,uuid4,uuid5

from . import durable_remote_job as jobs
from . import readiness_windows_bootstrap_durable as bootstrap
from . import readiness_windows_creator_registry as creators
from . import readiness_windows_host_jobs as host
from . import readiness_windows_seed_detach as seed
from . import readiness_windows_lifecycle as lifecycle
from . import readiness_windows_tpm_owner as tpm
from . import readiness_windows_guest as guest

_EXECUTING_CODE=inspect.currentframe().f_code
_ORIGINALS=weakref.WeakKeyDictionary()
_CURRENT=weakref.WeakKeyDictionary()
QUALIFIED_RECOVERIES=frozenset()
_seed_graph=seed._seed_graph
_SOURCE_PIN=bootstrap._source_pin(Path(__file__).lstat())


def _need(value):
    if not value:raise ValueError('windows_managed_admission_unresolved')


def _guard_sources():
    bootstrap._guard_sources();_need(_seed_graph is seed._seed_graph)
    path=Path(__file__).absolute();_need(bootstrap._source_pin(path.lstat())==_SOURCE_PIN)
    with bootstrap._bootstrap_source(path)as(raw,check):
        bootstrap._verify_callables(sys.modules[__name__],raw,compile(raw,str(path),'exec',dont_inherit=True));check()


def credential_metadata(path):
    """Hold exact private-handle metadata without reading or hashing its bytes."""
    _guard_sources();path=Path(path)
    _need(path.is_absolute()and '..'not in path.parts and str(path)==os.fspath(path))
    held=[];ancestors=[]
    def identity(info):return(info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid)
    try:
        parent=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);held.append(parent)
        for name in path.parts[1:-1]:
            child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent);held.append(child)
            ancestors.append((parent,name,child,identity(os.fstat(child))));parent=child
        fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent);held.append(fd)
        info=os.fstat(fd);pin=bootstrap._source_pin(info)
        _need(stat.S_ISREG(info.st_mode)and info.st_uid==os.geteuid()and stat.S_IMODE(info.st_mode)==0o600
            and info.st_nlink==1 and 1<=info.st_size<=512)
        for before,name,after,wanted in ancestors:
            _need(identity(os.fstat(after))==identity(os.stat(name,dir_fd=before,follow_symlinks=False))==wanted)
        _need(bootstrap._source_pin(os.fstat(fd))==bootstrap._source_pin(os.stat(path.name,dir_fd=parent,follow_symlinks=False))==pin)
        return pin
    finally:
        for fd in reversed(held):os.close(fd)


class ManagedOriginal:
    __slots__=('__weakref__',)
    def __new__(cls,*args,**kwargs):raise TypeError('windows_managed_original_opaque')
    def __reduce__(self):raise TypeError('windows_managed_original_opaque')
    def as_dict(self):return _load(self)[0]


def _load(value):
    _guard_sources();_need(type(value)is ManagedOriginal and value in _ORIGINALS)
    binding,handle,seed_job,seed_original,finalizer,expected=_ORIGINALS[value]
    record=handle.guard();seed_record,_,_=host._load(seed_job)
    body,_,_=seed._body(seed_original);final_record,_,_,plan=bootstrap._load(finalizer)
    _need(creators._scope(binding)==record['scope']==creators._scope(body['binding'])
        and body['creatorNamespace']==record['namespace']and body['creatorOperationId']==record['plan']['operationId']
        and seed_record['operationId']==body['operationId']and final_record['namespace']==seed_record['namespace'])
    request=seed.validate_read_request(plan['initial']['request'])
    result={'binding':binding,'creatorOperationId':body['creatorOperationId'],'seedOperationId':body['operationId'],
        'finalizerOperationId':final_record['operationId'],'expectedSid':request['detachment']['account'],
        'rootIdentity':request['rootIdentity'],'mutable':request['mutable']}
    _need(result==expected);return json.loads(json.dumps(result)),handle,seed_original,finalizer,request


def load(root,binding,finalizer_operation):
    """Pure exact-original load. No transport, enrollment, repair or readiness."""
    _guard_sources();lifecycle.packets.validate_binding(binding)
    _need(binding['provider']=='libvirt-windows'and lifecycle._uuid(finalizer_operation))
    handle=creators.load(root,binding);_need(type(handle)is creators.CreatorHandle)
    machine=binding['spec']['deploymentId'];target='windows-host:'+binding['spec']['host']+':'+machine
    rid=hashlib.sha256(b'private-credential-seed-detach-v1').hexdigest();op=str(uuid5(UUID(machine),rid))
    seed_job=host.reopen(root,target,machine,op);original=seed.reopen_ejection(handle,seed_job)
    finalizer=bootstrap.reopen(root,original,finalizer_operation);_,_,_,plan=bootstrap._load(finalizer)
    request=seed.validate_read_request(plan['initial']['request']);body=original.as_dict()
    expected={'binding':binding,'creatorOperationId':body['creatorOperationId'],'seedOperationId':op,
        'finalizerOperationId':finalizer_operation,'expectedSid':request['detachment']['account'],
        'rootIdentity':request['rootIdentity'],'mutable':request['mutable']}
    value=object.__new__(ManagedOriginal)
    _ORIGINALS[value]=(json.loads(json.dumps(binding)),handle,seed_job,original,finalizer,expected);_load(value);return value


def _public_xml(raw):
    from xml.etree import ElementTree as ET
    if type(raw)is not str or not 0<len(raw.encode())<=262144:raise ValueError('windows_managed_public_graph_unresolved')
    tree=ET.fromstring(raw)
    if any('}'in node.tag or node.tag in {'metadata','description','title','secret','auth','encryption'}for node in tree.iter())or any(
        'password'in key.lower()or key.lower().startswith('passwd')or key.lower()=='secret'for node in tree.iter()for key in node.attrib):
        raise ValueError('windows_managed_private_graph_unqualified')
    return raw


def _live_without_runtime_id(raw,actual=None):
    """Only the selected manager's positive domain root id is transient."""
    from xml.etree import ElementTree as ET
    tree=ET.fromstring(_public_xml(raw));value=tree.attrib.pop('id',None)
    if(tree.tag!='domain'or type(value)is not str or not value.isdecimal()
        or not 0<int(value)<2**31 or str(int(value))!=value):
        raise ValueError('windows_managed_runtime_id_unresolved')
    if actual is not None and(type(actual)is not int or not 0<actual<2**31 or value!=str(actual)):
        raise ValueError('windows_managed_runtime_id_unresolved')
    return ET.tostring(tree,encoding='unicode')


def _current_graph(binding,request,root,domain,generation,structure,private,vm_guard):
    """Actual selected graph and immutable original intent; no seed byte read."""
    import json,os,hashlib
    def need(value):
        if not value:raise ValueError('windows_managed_current_graph_unresolved')
    vm_guard();need(domain.UUIDString()==binding['spec']['deploymentId']and domain.name()==binding['domain'])
    active=bool(domain.isActive());runtime=domain.ID()if active else None
    need(not active or type(runtime)is int and 0<runtime<2**31)
    need(list(structure(private(root,True)))==request['rootIdentity'])
    for name,wanted in request['mutable'].items():need(list(structure(private(root/name)))==wanted)
    name='private-seed-'+request['detachment']['operationId']+'.intent.json';path=root/name
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        expected=request['detachment']['intentGeneration']
        need(list(generation(os.fstat(fd)))==list(generation(os.lstat(path)))==expected and expected[6]<=1048576)
        raw=os.read(fd,1048577);need(len(raw)==expected[6]);intent=json.loads(raw)
        need(list(generation(os.fstat(fd)))==list(generation(os.lstat(path)))==expected)
    finally:os.close(fd)
    need(intent['machine']==request['machine']and intent['creatorOperationId']==request['creator']['operationId']
        and intent['operationId']==request['detachment']['operationId']and intent['seedGeneration']==request['seedGeneration']
        and intent['seedPath']==binding['spec']['root']+'/seed.iso'and intent['replayAllowed']is False)
    inactive=_public_xml(domain.XMLDesc(2));live=_public_xml(domain.XMLDesc(0))if active else None
    plain,_=_seed_graph(inactive,intent['seedPath'],'ua-vpn-control-credential-seed',attached=False)
    need(plain==intent['otherInactive'])
    if live is not None:
        plain_live,_=_seed_graph(live,intent['seedPath'],'ua-vpn-control-credential-seed',attached=False)
        need(_live_without_runtime_id(plain_live,runtime)==_live_without_runtime_id(intent['otherLive']))
    digest=hashlib.sha256(inactive.encode()).hexdigest();need(digest==binding['xmlSha256'])
    vm_guard();need(bool(domain.isActive())==active and domain.UUIDString()==binding['spec']['deploymentId'])
    if active:
        renewed=domain.ID();need(type(renewed)is int and 0<renewed<2**31 and renewed==runtime)
    return {'inactiveXmlSha256':digest,'liveGraphVerified':live is not None,'seedAttached':False,
        'rootIdentity':request['rootIdentity'],'mutable':request['mutable']}


def program(original,history,operation,*,witness=None,request_only=False):
    """Fixed current metadata/probe controller; no input, start or shutdown."""
    _guard_sources();summary,handle,_,_,request=_load(original)
    closed=creators.historical_bootstrap(handle,history).as_dict()
    _need(closed['expectedSid']==summary['expectedSid']and lifecycle._uuid(operation)and type(request_only)is bool)
    binding=summary['binding']
    source=lifecycle.libvirt_lineage_program(binding,operation,owner_witness=witness,request_only=request_only).decode()
    # Validate public XML before every existing canonical hash boundary.
    old='xml=domain.XMLDesc(libvirt.VIR_DOMAIN_XML_INACTIVE).encode()'
    _need(source.count(old)==1);source=source.replace(old,'xml=_public_xml(domain.XMLDesc(libvirt.VIR_DOMAIN_XML_INACTIVE)).encode()')
    old='xml=domain.XMLDesc(2).encode();need('
    _need(source.count(old)==1);source=source.replace(old,'xml=_public_xml(domain.XMLDesc(2)).encode();need(')
    start=source.index('        print(json.dumps(_capture_libvirt_lineage(')
    end=source.index('        return\n',start)+len('        return\n')
    branch='''        graph=_current_graph(MANAGED_BINDING,MANAGED_REQUEST,root,domain,generation,structure,private,vm_guard)
        if not domain.isActive():
            result={'state':'observed','operationId':OPERATION,'provider':PROVIDER,'machine':SPEC['deploymentId'],
                'hostBoot':CONTEXT['hostBootId'],'guest':'stopped','actor':None,
                'controlConnection':'libvirt:'+str(manager['pid'])+':'+str(manager['startTicks'])+':'+str(socket_pin[1]),
                'sessionFacts':None,'displayFacts':None,'guestAgent':False,'idleFacts':None,'hostWork':None}
            print(json.dumps({'kind':'windows-managed-current-admission-v1','graph':graph,'lineage':None,'observation':result}));return
        lineage=_capture_libvirt_lineage(SPEC,CONTEXT,OPERATION,root,current_actor,manager,socket_pin,
            domain,connection,URI,DOMAIN,XML_SHA,SOCKET_PATH,read,process,owns,vm_guard,closing,generation,structure,
            private,instance_intent,pin,birth,LIFECYCLE_TPM_OWNER,LIFECYCLE_TPM_REQUEST_ONLY)
        if LIFECYCLE_TPM_REQUEST_ONLY:
            print(json.dumps({'kind':'windows-managed-current-request-v1','request':lineage,'graph':graph}));return
        current_state=machine_state()
        require(current_state in {'running','paused','suspended'},'windows_managed_guest_unrecognized')
        if current_state!='running':
            result={'state':'observed','operationId':OPERATION,'provider':PROVIDER,'machine':SPEC['deploymentId'],
                'hostBoot':CONTEXT['hostBootId'],'guest':current_state,'actor':current_actor,
                'controlConnection':'libvirt:'+str(manager['pid'])+':'+str(manager['startTicks'])+':'+str(socket_pin[1]),
                'sessionFacts':None,'displayFacts':None,'guestAgent':False,'idleFacts':None,'hostWork':None}
            print(json.dumps({'kind':'windows-managed-current-admission-v1','graph':graph,'lineage':lineage,'observation':result}));return
        rpc('guest-ping',{});first=script('managed-current-session',SESSION_SCRIPT)
        second=script('managed-current-session-confirm',SESSION_SCRIPT)
        require(first==second,'windows_managed_current_session_changed')
        require(_current_graph(MANAGED_BINDING,MANAGED_REQUEST,root,domain,generation,structure,private,vm_guard)==graph,'windows_managed_current_graph_changed')
        result={'state':'observed','operationId':OPERATION,'provider':PROVIDER,'machine':SPEC['deploymentId'],
            'hostBoot':CONTEXT['hostBootId'],'guest':'running','actor':current_actor,
            'controlConnection':'libvirt:'+str(manager['pid'])+':'+str(manager['startTicks'])+':'+str(socket_pin[1]),
            'sessionFacts':second,'displayFacts':None,'guestAgent':True,'idleFacts':None,'hostWork':None}
        print(json.dumps({'kind':'windows-managed-current-admission-v1','graph':graph,'lineage':lineage,'observation':result}));return
'''
    source=source[:start]+branch+source[end:]
    prefix='MANAGED_BINDING='+repr(binding)+'\nMANAGED_REQUEST='+repr(request)+'\n'
    prefix+=inspect.getsource(_public_xml)+'\n'+inspect.getsource(_live_without_runtime_id)+'\n'+inspect.getsource(seed._seed_graph)+'\n'+inspect.getsource(_current_graph)+'\n'
    source=prefix+source;compile(source,'fixed managed current admission','exec');return source.encode()


def _run(backend,original,operation,source_factory,deadline,*,witness=None):
    _guard_sources();_load(original);backend._guard()
    remaining=deadline-time.monotonic();_need(math.isfinite(remaining)and remaining>0)
    root=backend.root;directory=root/'.runtime/readiness-windows-managed-admission'/str(uuid4())
    directory.parent.mkdir(mode=0o700,parents=True,exist_ok=True);jobs._private(directory.parent,directory=True);directory.mkdir(mode=0o700)
    with bootstrap.transport.admitted_transport(root,backend.binding['spec']['host'],operation,deadline=deadline)as admitted:
        with bootstrap.deploy.direct.Guard(root,host=backend.binding['spec']['host'])as authority:
            source=source_factory();jobs._create(directory/'caller.source',source)
            command=('python3','-I','-B','-c','exec('+repr(source.decode())+')')
            argv=bootstrap.transport.build_ssh_argv(authority.config,backend.binding['spec']['host'],60,command=command)
            if witness is not None:witness.guard_dispatch(admitted)
            admitted.revalidate();authority.guard();backend._guard();_load(original)
            remaining=deadline-time.monotonic();_need(remaining>0)
            try:result=bootstrap.transport.run_ssh(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=min(60,remaining),cwd=root)
            except subprocess.TimeoutExpired as error:
                counts={}
                for name,raw,limit in (('stdout',error.stdout,4*1024**2),('stderr',error.stderr,1024**2)):
                    available=type(raw)is bytes;captured=raw if available else b''
                    jobs._create(directory/(name+'.public'),captured[:limit])
                    counts.update({name+'Available':available,name+'CapturedBytes':len(captured),
                        name+'RetainedBytes':min(len(captured),limit),name+'Complete':False})
                jobs._publish(directory/'unavailable.json',{'reason':'original_observation_timeout','replayAllowed':False,**counts})
                raise ValueError('windows_managed_original_observation_unknown')from None
            except Exception:
                jobs._publish(directory/'unavailable.json',{'reason':'original_observation_unavailable','replayAllowed':False});raise
            bootstrap._capture_callback(directory,{'operationId':operation},result)
            _need(result.returncode==0 and result.stderr==b''and 0<len(result.stdout)<=4*1024**2)
            value=host._json(result.stdout);_need(type(value)is dict)
            admitted.revalidate();authority.guard();backend._guard();_load(original)
            jobs._publish(directory/'closing.json',{'operationId':operation,'sourceSha256':hashlib.sha256(source).hexdigest(),
                'stdoutSha256':hashlib.sha256(result.stdout).hexdigest(),'sourceClosed':True})
            artifacts=('caller.source','stdout.public','stderr.public','callback.json','closing.json')
            host._create_custody(directory,'custody.json',artifacts)
            return value,(directory,host._custody(directory,'custody.json',artifacts))


class CurrentManagedAdmission:
    __slots__=('__weakref__',)
    def __new__(cls,*args,**kwargs):raise TypeError('windows_managed_current_observer_required')
    def __reduce__(self):raise TypeError('windows_managed_current_observer_required')
    def as_dict(self):
        _guard_sources();_need(type(self)is CurrentManagedAdmission and self in _CURRENT)
        original,history,expected,expires,captures=_CURRENT[self];_need(time.monotonic()<expires);_load(original);history.as_dict()
        for directory,custody in captures:
            _need(host._custody(directory,'custody.json',('caller.source','stdout.public','stderr.public','callback.json','closing.json'))==custody)
        return json.loads(json.dumps(expected))


def _validate_current(summary,request,actual,expected_owner=None):
    """Shape/join validation only; this function cannot mint current authority."""
    _need(type(actual)is dict and set(actual)=={'kind','graph','lineage','observation'}and actual['kind']=='windows-managed-current-admission-v1')
    binding=summary['binding'];facts=actual['observation'];graph=actual['graph']
    _need(type(facts)is dict and facts['state']=='observed'and facts['machine']==binding['spec']['deploymentId']
        and facts['provider']=='libvirt-windows'and facts['hostBoot']==binding['context']['hostBootId']
        and facts['guest']in{'running','stopped','paused','suspended'})
    _need(type(graph)is dict and set(graph)=={'inactiveXmlSha256','liveGraphVerified','seedAttached','rootIdentity','mutable'}
        and graph['inactiveXmlSha256']==binding['xmlSha256']and type(graph['liveGraphVerified'])is bool
        and graph['seedAttached']is False and graph['rootIdentity']==request['rootIdentity']and graph['mutable']==request['mutable'])
    if facts['guest']!='stopped':
        lineage=lifecycle.validate_lineage(binding,actual['lineage']).as_dict()
        _need(type(expected_owner)is dict and set(expected_owner)=={'holder','qemu'})
        holder=expected_owner['holder'];qemu=expected_owner['qemu']
        _need(lineage['tpm']['pid']==holder['pid']and lineage['tpm']['startTicks']==holder['birth']
            and lineage['qemu']['pid']==qemu['pid']and lineage['qemu']['startTicks']==qemu['birth']
            and lineage['qemu']['executableGeneration']==qemu['executableGeneration'])
        _need(graph['liveGraphVerified']is True and lineage['rootIdentity']==request['rootIdentity']
            and lineage['mutable']==request['mutable']and lineage['qemu']==facts['actor'])
        if facts['guest']=='running':
            guest.validate_session(facts['sessionFacts'],summary['expectedSid'],binding['setup']['user'],binding['spec']['deploymentId'])
            _need(facts['guestAgent']is True)
        else:_need(facts['sessionFacts']is None and facts['guestAgent']is False)
    else:_need(graph['liveGraphVerified']is False and actual['lineage']is None and facts['sessionFacts']is None and facts['actor']is None and facts['guestAgent']is False)
    return json.loads(json.dumps(actual))


def observe(backend,original,*,deadline):
    """Read-only actual original history plus independent current VM admission."""
    _guard_sources();summary,_,_,finalizer,request=_load(original)
    _need(summary['binding']==backend.binding and summary['expectedSid']==backend.expected_sid
        and type(deadline)in(int,float)and math.isfinite(deadline)and deadline>time.monotonic())
    history=bootstrap.observe_original(backend.root,finalizer,guard=backend._guard,deadline=deadline)
    operation=str(uuid4())
    first,capture=_run(backend,original,operation,lambda:program(original,history,operation,request_only=True),deadline);captures=[capture];expected_owner=None
    if first.get('kind')=='windows-managed-current-request-v1':
        _need(set(first)=={'kind','request','graph'}and backend.credential_file is not None)
        with tpm.observe(backend.root,backend.binding['spec']['host'],first['request'],backend.credential_file,guard=backend._guard,deadline=deadline)as witness:
            actual,capture=_run(backend,original,operation,lambda:program(original,history,operation,witness=witness),deadline,witness=witness);captures.append(capture)
            expected_owner={'holder':witness.validate(witness.request),'qemu':witness.request['qemu']}
        _need(actual['graph']==first['graph'])
    else:
        actual=first;_need(actual.get('observation',{}).get('guest')=='stopped')
    _validate_current(summary,request,actual,expected_owner)
    result=object.__new__(CurrentManagedAdmission);_CURRENT[result]=(original,history,actual,min(deadline,time.monotonic()+30),tuple(captures));result.as_dict();return result
