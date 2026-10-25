"""Finite ordinary-guest lease capsule; builders never contact a VM.

The backend must bind the actual selected guest and retained namespace before
running these bytes through its original ordinary-account executor. No public
caller can provide source/path/credentials or choose a different namespace.
Native DIRECT qualification is required before any provider factory exposes it.
"""
from __future__ import annotations

from dataclasses import asdict
import ast
import base64
import re
import hashlib
import json
from pathlib import Path
import sys

from . import durable_remote_job as jobs
from . import readiness_tart_macos_leases as leases

_EXECUTING_CODE = sys._getframe().f_code
ROOT = '/private/var/tmp/vc-recovery-macos-leases-v2'
_ROOTS = frozenset({'/private/var/tmp/vc-recovery-macos-leases', ROOT})
_ACTIONS = frozenset({'probe', 'enroll', 'namespace-status', 'acquire', 'status', 'cancel', 'reconcile', 'inventory'})
_FILES = ('durable_remote_job.py', 'tart_macos_probe.py', 'readiness_tart_macos_leases.py')


def _need(value):
    if not value:
        raise leases.MacLeaseError('macos_lease_bridge_invalid')


def source(action, binding, *, namespace=None, operation=None, ttl=None):
    """Capture one fixed internal action; guest generation pins are not guessed."""
    _need(type(action) is str and action in _ACTIONS and type(binding) is leases.MacLeaseBinding)
    binding.__post_init__()
    if action in {'probe', 'enroll', 'namespace-status'}:
        _need(namespace is None and operation is None and ttl is None)
    elif action == 'inventory':
        _need(type(namespace) is dict and operation is None and ttl is None)
    else:
        jobs._uuid(operation)
        _need(type(namespace) is dict)
        if action == 'acquire': leases._ttl(ttl)
        else: _need(ttl is None)
    root = Path(__file__).parent
    captured = {name: (root / name).read_bytes() for name in _FILES}
    _need(all(0 < len(raw) <= 262144 for raw in captured.values()))
    own = Path(__file__).read_bytes()
    _need(_EXECUTING_CODE == compile(own, __file__, 'exec', dont_inherit=True))
    pins = {name: hashlib.sha256(raw).hexdigest() for name, raw in captured.items()}
    if namespace is not None:
        _need(set(namespace) == {'schemaVersion','root','target','machine','account','sources',
                                 'rootGeneration','jobGeneration','admissionGeneration'}
              and type(namespace['schemaVersion']) is int and namespace['schemaVersion']==1
              and all(type(namespace[name]) is list and len(namespace[name])==2
                      and all(type(item)is int and item>0 for item in namespace[name])
                      for name in ('rootGeneration','jobGeneration','admissionGeneration')))
        _need(namespace.get('sources') == pins and namespace.get('root') == ROOT
              and (namespace.get('target'), namespace.get('machine'), namespace.get('account')) ==
                  (binding.target, binding.machine, binding.account))
    config = {'action': action, 'binding': asdict(binding), 'namespace': namespace,
              'operation': operation, 'ttl': ttl, 'root': ROOT, 'sources': pins}
    return _render(captured, _GUEST, config)


def _render(captured, guest, config):
    if config['action']=='status':guest += _ORIGINAL_STATUS
    preamble = ('import sys,types\n'
                "package=types.ModuleType('_fixed_macos_lease');package.__path__=[];sys.modules[package.__name__]=package\n")
    for name in _FILES:
        short = name[:-3]
        preamble += (f"m=types.ModuleType('_fixed_macos_lease.{short}');m.__package__=package.__name__;"
                     f"m.__file__='<fixed-{name}>';sys.modules[m.__name__]=m;setattr(package,{short!r},m)\n")
        if name == 'readiness_tart_macos_leases.py':
            preamble += "m.__dict__['__captured_probe_source__']=" + repr(captured['tart_macos_probe.py']) + '\n'
        preamble += 'exec(compile(' + repr(captured[name]) + f",'<fixed-{name}>','exec'),m.__dict__)\n"
        if name == 'durable_remote_job.py':
            preamble += 'm.owner_source=lambda:' + repr(captured[name]) + '\n'
    value = (preamble + '\nCONFIG=' + repr(config) + '\n' + guest + '\nraise SystemExit(main())\n').encode()
    _need(len(value) <= 262144)
    return value


def capsule(binding, namespace=None):
    """Archive public source bytes privately; return a bounded artifact, not a DTO.

    Trusted custody must publish this artifact create-only and retain its SHA,
    inode and ownership in the original admission. A caller-provided digest is
    not authority. Normal public tool inputs never contain this artifact.
    """
    # Reuse the same admission/schema/source closure as a current fixed request.
    source('namespace-status' if namespace is None else 'inventory', binding, namespace=namespace)
    root = Path(__file__).parent
    files = {name:base64.b64encode((root/name).read_bytes()).decode('ascii') for name in _FILES}
    own = Path(__file__).read_bytes()
    _need(_EXECUTING_CODE == compile(own,__file__,'exec',dont_inherit=True))
    if namespace is not None:
        _need(namespace['sources']=={name:hashlib.sha256(base64.b64decode(data)).hexdigest()for name,data in files.items()})
    result = {'schemaVersion':1,'provider':'tart-macos','binding':asdict(binding),'namespace':namespace,
              'bridge':base64.b64encode(own).decode('ascii'),'files':files}
    raw = json.dumps(result,sort_keys=True,separators=(',',':')).encode()
    _need(len(raw)<=262144)
    return raw


def _original_source(raw, action, *, expected_sha256, operation=None, ttl=None):
    """Internal original archive renderer; authority stays with trusted factories.

    The digest must come from the retained original immutable host admission,
    never from a newly supplied public blob. No live source file is read and no
    current registration replaces the original target/account/root generations.
    """
    _need(type(raw)is bytes and 0<len(raw)<=262144 and type(expected_sha256)is str
          and re.fullmatch(r'[0-9a-f]{64}',expected_sha256)
          and hashlib.sha256(raw).hexdigest()==expected_sha256
          and type(action)is str and action in {'acquire','status','cancel','reconcile','inventory','namespace-status'})
    if action=='acquire':leases._ttl(ttl)
    else:_need(ttl is None)
    try:
        value=json.loads(raw)
        _need(type(value)is dict and set(value)=={'schemaVersion','provider','binding','namespace','bridge','files'}
              and type(value['schemaVersion'])is int and value['schemaVersion']==1 and value['provider']=='tart-macos'
              and type(value['files'])is dict and set(value['files'])==set(_FILES))
        binding=leases.MacLeaseBinding(**value['binding'])
        captured={name:base64.b64decode(data,validate=True)for name,data in value['files'].items()}
        bridge=base64.b64decode(value['bridge'],validate=True)
        _need(0<len(bridge)<=262144 and all(0<len(data)<=262144 for data in captured.values()))
        tree=ast.parse(bridge)
        roots=[node.value.value for node in tree.body if isinstance(node,ast.Assign)
               and any(isinstance(target,ast.Name)and target.id=='ROOT'for target in node.targets)
               and isinstance(node.value,ast.Constant)and type(node.value.value)is str]
        _need(len(roots)==1 and roots[0]in _ROOTS)
        original_root=roots[0]
        bodies=[node.value.value for node in tree.body if isinstance(node,ast.Assign)
                and any(isinstance(target,ast.Name)and target.id=='_GUEST'for target in node.targets)
                and isinstance(node.value,ast.Constant)and type(node.value.value)is str]
        _need(len(bodies)==1)
        namespace=value['namespace']
        if action=='namespace-status':
            _need(namespace is None and operation is None)
        else:
            _need(type(namespace)is dict and namespace.get('sources')==
                  {name:hashlib.sha256(data).hexdigest()for name,data in captured.items()}
                  and namespace.get('root')==original_root
                  and (namespace.get('target'),namespace.get('machine'),namespace.get('account'))==
                      (binding.target,binding.machine,binding.account))
            if action=='inventory':_need(operation is None)
            else:jobs._uuid(operation)
        config={'action':action,'binding':asdict(binding),'namespace':namespace,'operation':operation,'ttl':None,
                'root':original_root,'sources':{name:hashlib.sha256(data).hexdigest()for name,data in captured.items()}}
        config['ttl']=ttl
        return _render(captured,bodies[0],config)
    except (ValueError,TypeError,KeyError,SyntaxError,UnicodeError):
        raise leases.MacLeaseError('macos_lease_bridge_original_invalid')from None


def observer_source(raw, action, *, expected_sha256, operation=None):
    """Original observer only; a caller digest never authorizes acquisition."""
    _need(type(action)is str and action in {'status','cancel','reconcile','inventory','namespace-status'})
    return _original_source(raw,action,expected_sha256=expected_sha256,operation=operation)


def qualified_acquire_source(raw, *, expected_sha256, operation, ttl):
    """Internal fixed producer renderer, NOT a qualification/admission API.

    The opaque provider factory must first authenticate native qualification,
    original enrollment, source/archive custody and current actual readiness.
    expected_sha256 comes only from that trusted immutable artifact reference.
    Public callers never supply this blob/hash; no reenrollment is supported.
    """
    _need(capsule_root(raw,expected_sha256=expected_sha256)==ROOT)
    jobs._uuid(operation);leases._ttl(ttl)
    return _original_source(raw,'acquire',expected_sha256=expected_sha256,operation=operation,ttl=ttl)


def capsule_root(raw, *, expected_sha256):
    """Pure original root from the SHA-authenticated captured source constant."""
    _need(type(raw)is bytes and 0<len(raw)<=262144 and type(expected_sha256)is str
          and re.fullmatch(r'[0-9a-f]{64}',expected_sha256)
          and hashlib.sha256(raw).hexdigest()==expected_sha256)
    try:
        value=json.loads(raw);bridge=base64.b64decode(value['bridge'],validate=True)
        roots=[node.value.value for node in ast.parse(bridge).body if isinstance(node,ast.Assign)
               and any(isinstance(target,ast.Name)and target.id=='ROOT'for target in node.targets)
               and isinstance(node.value,ast.Constant)and type(node.value.value)is str]
        _need(len(roots)==1 and roots[0]in _ROOTS)
        return roots[0]
    except (ValueError,TypeError,KeyError,SyntaxError,UnicodeError):
        raise leases.MacLeaseError('macos_lease_bridge_original_invalid')from None


def bind_namespace(raw, packet, *, expected_sha256):
    """Append-only metadata binding of an original enrollment capsule.

    The caller publishes the returned artifact under a NEW immutable pin. This
    never modifies original source bytes/target/account, the old capsule, guest
    marker, jobs or assertions, and never reads current source modules.
    """
    root=capsule_root(raw,expected_sha256=expected_sha256)
    try:
        value=json.loads(raw)
        _need(type(value)is dict and set(value)=={'schemaVersion','provider','binding','namespace','bridge','files'}
              and type(value['schemaVersion'])is int and value['schemaVersion']==1 and value['provider']=='tart-macos'
              and set(value['files'])==set(_FILES))
        binding=leases.MacLeaseBinding(**value['binding'])
        pins={name:hashlib.sha256(base64.b64decode(data,validate=True)).hexdigest()
              for name,data in value['files'].items()}
        _need(type(packet)is dict and set(packet)=={'schemaVersion','root','target','machine','account','sources',
                  'rootGeneration','jobGeneration','admissionGeneration'}
              and type(packet['schemaVersion'])is int and packet['schemaVersion']==1
              and packet['root']==root and packet['sources']==pins
              and (packet['target'],packet['machine'],packet['account'])==(binding.target,binding.machine,binding.account)
              and all(type(packet[key])is list and len(packet[key])==2 and all(type(n)is int and n>0 for n in packet[key])
                      for key in ('rootGeneration','jobGeneration','admissionGeneration'))
              and (value['namespace']is None or value['namespace']==packet))
        value['namespace']=packet
        result=json.dumps(value,sort_keys=True,separators=(',',':')).encode();_need(len(result)<=262144)
        # Validate original body/files/schema through the observer-only renderer.
        observer_source(result,'inventory',expected_sha256=hashlib.sha256(result).hexdigest())
        return result
    except (ValueError,TypeError,KeyError,SyntaxError,UnicodeError):
        raise leases.MacLeaseError('macos_lease_bridge_original_invalid')from None


_GUEST = r'''
import json,os,pwd,uuid
from pathlib import Path
from _fixed_macos_lease import durable_remote_job as J,readiness_tart_macos_leases as L,tart_macos_probe as P

def need(value,reason='macos_lease_bridge_invalid'):
    if not value:raise ValueError(reason)

def binding():
    b=L.MacLeaseBinding(**CONFIG['binding'])
    need(os.geteuid()>=501 and str(os.geteuid())==b.account,'macos_lease_account_changed')
    user=pwd.getpwuid(os.geteuid())
    need((user.pw_name,user.pw_dir)==(b.principal,b.home),'macos_lease_account_changed')
    native=P.Native()
    need(native.machine()==b.machine.lower(),'macos_lease_machine_changed')
    boot,_=native.boot()
    if CONFIG['action'] in {'probe','enroll','acquire','cancel','reconcile'}:
        need(boot.lower()==b.boot.lower(),'macos_lease_boot_changed')
        J._binding_live(b.job_binding())
    # Status/inventory/namespace-status may read retained terminal metadata
    # across boots. They cannot create a job, assertion, namespace or request.
    return b

def console(b):
    scope={'D':vars(J),'P':vars(P)}
    exec(L._ASSERTIONS,scope)
    api=scope['MacAssertions'](L.asdict(b));facts=api.console()
    return {'machine':b.machine,'boot':b.boot,'account':b.account,'principal':b.principal,'home':b.home,
            'console':facts,'display':api.native.displays()}

def namespace(b):
    root=Path(CONFIG['root']);need(str(root)=='/private/var/tmp/vc-recovery-macos-leases-v2')
    marker={'schemaVersion':1,'root':str(root),'target':b.target,'machine':b.machine,'account':b.account,'sources':CONFIG['sources']}
    if CONFIG['action']=='enroll':
        created=False
        try:root.mkdir(mode=0o700);created=True
        except FileExistsError:pass
        J._root(root)
        if created:
            (root/'jobs').mkdir(mode=0o700);(root/'admissions').mkdir(mode=0o700)
            marker['rootGeneration']=list(J.root_generation(root))
            marker['jobGeneration']=list(J.root_generation(root/'jobs'))
            marker['admissionGeneration']=list(J.root_generation(root/'admissions'))
            J._publish(root/'namespace.json',marker)
    J._root(root)
    need({path.name for path in root.iterdir()}=={'namespace.json','jobs','admissions'},
         'macos_lease_namespace_changed')
    actual=J._record(root/'namespace.json')
    expected={**marker,'rootGeneration':list(J.root_generation(root)),
              'jobGeneration':list(J.root_generation(root/'jobs')),
              'admissionGeneration':list(J.root_generation(root/'admissions'))}
    need(actual==expected,'macos_lease_namespace_changed')
    if CONFIG['namespace']is not None:need(actual==CONFIG['namespace'],'macos_lease_namespace_changed')
    return root,actual

def original(root,op,b):
    value=J._record(root/'admissions'/(op+'.json'))
    need(type(value)is dict and set(value)=={'schemaVersion','operationId','binding','ttlSeconds','namespace'}
         and type(value['schemaVersion'])is int and value['schemaVersion']==1
         and value['operationId']==op and value['binding']==L.asdict(b)
         and value['namespace']==CONFIG['namespace'],'macos_lease_original_changed')
    L._ttl(value['ttlSeconds'])
    return value

def invoke():
    b=binding();action=CONFIG['action']
    if action=='probe':return console(b)
    root,packet=namespace(b)
    if action in {'enroll','namespace-status'}:return packet
    gen=tuple(packet['jobGeneration']);owner_root=root/'jobs'
    if action=='inventory':
        entries={}
        for path in (root/'admissions').iterdir():
            need(path.name.endswith('.json'),'macos_lease_inventory_incomplete')
            op=J._uuid(path.name[:-5]);value=J._record(path)
            old=L.MacLeaseBinding(**value['binding'])
            need((old.target,old.machine,old.account)==(b.target,b.machine,b.account),'macos_lease_inventory_incomplete')
            original(root,op,old)
            entries[op]=L.inspect(owner_root,op,old,generation=gen)
        for path in owner_root.iterdir():
            if path.name=='macos-assertions.lock':
                need(J._read(path,128)==b'macos-assertions-lock-v1\n','macos_lease_inventory_incomplete');continue
            op=J._uuid(path.name);need(op in entries,'macos_lease_inventory_incomplete')
        return {'visibilityComplete':True,'leases':list(entries.values()),
                'idle':all(v.get('restored')is True and v['jobState']=='terminal' for v in entries.values())}
    op=J._uuid(CONFIG['operation']);path=root/'admissions'/(op+'.json')
    if action=='acquire':
        ttl=L._ttl(CONFIG['ttl'])
        expected={'schemaVersion':1,'operationId':op,'binding':L.asdict(b),'ttlSeconds':ttl,'namespace':packet}
        try:J._publish(path,expected)
        except FileExistsError:
            need(original(root,op,b)==expected,'macos_lease_original_changed')
            # A consumed admission never reconstructs submission, including a
            # lost reply before the owner creates its own directory.
            return L.inspect(owner_root,op,b,generation=gen)
        return L.acquire(owner_root,op,b,ttl,generation=gen)
    original(root,op,b)
    if action=='status':return L.inspect(owner_root,op,b,generation=gen)
    if action=='cancel':return L.cancel(owner_root,op,b,generation=gen)
    if action=='reconcile':return L.reconcile(owner_root,op,b,generation=gen)
    raise ValueError('macos_lease_action_invalid')

def main():
    try:value=invoke()
    except (ValueError,OSError,TypeError,KeyError,AttributeError):
        print('{"reason":"macos_lease_original_unavailable","state":"blocked"}');return 3
    raw=json.dumps(value,sort_keys=True)
    if len(raw.encode('utf-8'))>262144:
        print('{"reason":"macos_lease_reply_overflow","state":"blocked"}');return 3
    print(raw);return 0
'''


# This current trusted wrapper may inspect genuine original namespaces after
# host source updates. It never edits/replays the captured producer, admission,
# marker, settings or owner. Only exact absence on the original boot is typed.
_ORIGINAL_STATUS = r'''
_original_invoke = invoke

def _both_original_paths_absent(root,op):
    for path in (root/'admissions'/(op+'.json'),root/'jobs'/op):
        try:path.lstat()
        except FileNotFoundError:continue
        return False
    return True

def invoke():
    if CONFIG['action']=='status':
        b=binding();root,packet=namespace(b);op=J._uuid(CONFIG['operation'])
        if _both_original_paths_absent(root,op):
            # Same machine/account was established by binding(); raw boot and
            # positive complete namespace/source/generation custody are needed
            # before absence can authorize later SAME-UUID preparation.
            J._binding_live(b.job_binding())
            again,actual=namespace(b)
            need(actual==packet and str(again)==str(root),'macos_lease_namespace_changed')
            if _both_original_paths_absent(again,op):
                return {'schemaVersion':1,'provider':'tart-macos','operationId':op,
                    'state':'unsubmitted','jobState':'unsubmitted','reason':'original_admission_absent',
                    'replayAllowed':False,'nextAction':'none'}
    return _original_invoke()
'''
