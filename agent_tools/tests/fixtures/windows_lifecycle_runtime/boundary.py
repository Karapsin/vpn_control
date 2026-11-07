"""Finite routine source boundary for authentic lifecycle/runtime controls.

Original control/test function and class ASTs stay unchanged except the old
path-reloading `load` helper, which compiles only captured authenticated bytes.
No native process, input, task or VM admission is represented by these peers.
"""
from __future__ import annotations
import ast
import hashlib
import importlib.abc
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import types
import unittest
import uuid

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[3]
PRODUCTION={
    'lifecycle_cases.py':'agent_tools/windows_lifecycle_cases.py',
    'traffic_worker.py':'agent_tools/windows_lifecycle_traffic_worker.py',
    'scheduled_fixture_worker.py':'agent_tools/windows_lifecycle_scheduled_fixture_worker.py',
    'socks_fixture_worker.py':'agent_tools/windows_lifecycle_socks_fixture_worker.py',
    'runtime_fixture_worker.py':'agent_tools/windows_lifecycle_runtime_fixture_worker.py',
    'runtime_stages.py':'agent_tools/windows_lifecycle_runtime_stages.py',
    'no_tray_desktop.py':'agent_tools/windows_no_tray_desktop.py',
    'tun_stages.py':'agent_tools/windows_tun_stages.py',
    'tun_native_observer.py':'agent_tools/windows_tun_native_observer.py',
    'runtime_branch_cases.py':'agent_tools/windows_runtime_branch_cases.py',
}
BEFORE={
    'gui-port': 'lifecycle_cases.v1.before.source',
    'partial-control': 'scheduled_fixture_worker.v1.before.source',
    'operation-request': 'runtime_stages.operation.before.source',
    'tun-context': 'tun_stages.context.before.source',
    'custom-route': 'runtime_branches.route.before.source',
    'fixture-live': 'runtime_branches.fixture.before.source',
    'custom-direct': 'runtime_branches.direct.before.source',
    'probe-closing': 'runtime_branches.closing.before.source',
}
LIFECYCLE_CASES=('gui-port','partial-control','handler-ledger','operation-request',*(
    'tun-'+stage+'-'+variant for stage in ('ready','off') for variant in (
        'wrong-admin','wrong-session','wrong-workspace','wrong-programdata','foreign-state-workspace','boolean-session')))
BRANCH_CASES=('custom-route','fixture-live','custom-direct','closing-actor-replacement','closing-listener-takeover')
RUNS=[]

def sha(raw):return hashlib.sha256(raw).hexdigest()
def generation(value):return (value.st_dev,value.st_ino,value.st_mode,value.st_nlink,value.st_size,value.st_mtime_ns,value.st_ctime_ns)
def powershell():return os.environ.get('VPN_CONTROL_TEST_POWERSHELL') or shutil.which('powershell.exe') or shutil.which('pwsh')

class Sources:
    def __init__(self):
        value=json.loads((HERE/'provenance.json').read_bytes());assert value['schemaVersion']==1
        self.pins={key:pin for group in ('production','fixtures','baselineInputs') for key,pin in value[group].items()}
        self.held={};self.closed=False
        for relative in (
            'shared/core/src/commonMain/kotlin/com/kardinal/vpncontrol/data/SingBoxRouteDnsBuilder.kt',
            'desktopApp/src/main/kotlin/com/kardinal/vpncontrol/desktop/DesktopProxyConfigFactory.kt'):
            self.capture(ROOT/relative)
    def capture(self,path):
        path=Path(path);key=str(path.relative_to(ROOT));assert key in self.pins,'finite-source-role-required'
        if key not in self.held:
            flags=os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)
            descriptor=os.open(path,flags);stream=os.fdopen(descriptor,'rb');raw=stream.read(8*1024*1024+1);info=os.fstat(descriptor)
            self.held[key]=(path,stream,raw,generation(info))
            pin=self.pins[key]
            assert stat.S_ISREG(info.st_mode) and info.st_nlink==1 and len(raw)==pin['bytes'] and sha(raw)==pin['sha256'],'authentic-source-bytes-required'
        self.guard();return self.held[key][2]
    def guard(self):
        assert not self.closed,'source-custody-closed'
        for path,stream,raw,identity in self.held.values():
            stream.seek(0);assert stream.read(8*1024*1024+1)==raw,'original-source-bytes-changed'
            assert generation(os.fstat(stream.fileno()))==identity==generation(path.stat()),'original-or-named-source-generation-changed'
    def close(self):
        self.guard()
        for path,stream,raw,identity in self.held.values():stream.close()
        self.closed=True
    def code(self,path):
        target=Path(path)
        allowed={*(ROOT/value for value in PRODUCTION.values() if value.endswith('.py')),
            *(HERE/value for value in BEFORE.values()),
            *(HERE/stage/'controls.source' for stage in ('local','stages','review','ledger','context','branches','closing')),
            HERE/'capability_probe.py',HERE/'capability_probe.windows-rename.before.source',
            ROOT/'scripts/integration/socks_http_fixture.py',ROOT/'scripts/integration/https_subscription_relay_fixture.py',
            ROOT/'scripts/integration/desktop_scheduled_refresh_fixture.py'}
        assert target in allowed,'finite-executable-source-role-required'
        return self.capture(target)
    def module(self,path,name=None):
        target=Path(path);raw=self.code(target);name=name or '_routine_source_'+uuid.uuid4().hex
        module=types.ModuleType(name);module.__file__=str(target);module.__package__='';sys.modules[name]=module
        code=compile(raw,str(target),'exec',dont_inherit=True);self.guard();exec(code,module.__dict__);self.guard();return module


def aliases():
    result={}
    for stage in ('local','stages','review','ledger','context','branches','closing'):
        for old,new in PRODUCTION.items():result[str(HERE/stage/old)]=ROOT/new
    result.update({str(HERE/'before'/'lifecycle_cases.py'):HERE/BEFORE['gui-port'],
        str(HERE/'before'/'scheduled_fixture_worker.py'):HERE/BEFORE['partial-control'],
        str(HERE/'stages'/'before-local-operation-correlation.runtime_stages.py'):HERE/BEFORE['operation-request'],
        str(HERE/'context'/'tun_stages.before.source'):HERE/BEFORE['tun-context'],
        str(HERE/'branches'/'runtime_branch_cases.route-shape.before.source'):HERE/BEFORE['custom-route'],
        str(HERE/'branches'/'runtime_branch_cases.fixture-liveness.before.source'):HERE/BEFORE['fixture-live'],
        str(HERE/'branches'/'runtime_branch_cases.direct-probe.before.source'):HERE/BEFORE['custom-direct'],
        str(HERE/'closing'/'runtime_branch_cases.before.source'):HERE/BEFORE['probe-closing']})
    return result


def controls(stage,sources):
    assert stage in {'local','stages','review','ledger','context','branches','closing'}
    path=HERE/stage/'controls.source';original=sources.capture(path).decode();tree=ast.parse(original);mapped=aliases()
    def load_path(path,name=None):return sources.module(mapped.get(str(path),Path(path)),name)
    def load_name(name):return load_path(HERE/stage/(name+'.py'))
    def load_variant(source):
        assert source in {'before','after'}
        key='tun_stages.py' if stage=='context' else 'runtime_branch_cases.py'
        before=BEFORE['tun-context' if stage=='context' else 'probe-closing']
        return sources.module(HERE/before if source=='before' else ROOT/PRODUCTION[key])
    def load_branches(before=False):
        return sources.module(HERE/BEFORE['custom-route'] if before else ROOT/PRODUCTION['runtime_branch_cases.py'])
    replacement={'local':'def load(name):\n    return _load_name(name)\n',
        'stages':'def load(path,name=None):\n    return _load_path(path,name)\n',
        'review':'def load(path):\n    return _load_path(path)\n',
        'ledger':'def load(name,path):\n    return _load_path(path,name)\n',
        'context':'def load(source):\n    return _load_variant(source)\n',
        'branches':'def load(before=False):\n    return _load_branches(before)\n',
        'closing':'def load(source):\n    return _load_variant(source)\n'}[stage]
    changes=[]
    for node in tree.body:
        if isinstance(node,ast.FunctionDef) and node.name=='load':changes.append((node.lineno,node.end_lineno,replacement))
        if isinstance(node,ast.Assign) and len(node.targets)==1 and isinstance(node.targets[0],ast.Name):
            key=node.targets[0].id
            if key=='HERE':changes.append((node.lineno,node.end_lineno,'HERE=Path('+repr(str(HERE/stage))+')\n'))
            if key=='ROOT':changes.append((node.lineno,node.end_lineno,'ROOT=Path('+repr(str(HERE/stage if stage=='local' else ROOT))+')\n'))
            if key=='REPO':changes.append((node.lineno,node.end_lineno,'REPO=Path('+repr(str(ROOT))+')\n'))
            if key=='BEFORE':changes.append((node.lineno,node.end_lineno,'BEFORE=Path('+repr(str(HERE/'before'))+')\n'))
    lines=original.splitlines(True)
    for start,end,text in sorted(changes,reverse=True):lines[start-1:end]=[text]
    rendered=''.join(lines)
    bodies=lambda text:[ast.dump(node,include_attributes=False) for node in ast.parse(text).body
        if isinstance(node,(ast.FunctionDef,ast.ClassDef)) and node.name!='load']
    assert bodies(original)==bodies(rendered),'authentic-control-body-drift'
    name='_routine_controls_'+stage+'_'+uuid.uuid4().hex;module=types.ModuleType(name);module.__file__=str(path);module.__package__=''
    module.__dict__.update(_load_path=load_path,_load_name=load_name,_load_variant=load_variant,_load_branches=load_branches)
    sys.modules[name]=module;sources.guard();exec(compile(rendered,str(path),'exec',dont_inherit=True),module.__dict__);sources.guard()
    # Two original branch oracles instantiate SourceFileLoader inline. Supply a
    # module-local finite loader view; do not modify process-global importlib.
    if stage=='branches':
        class CapturedLoader(importlib.abc.Loader):
            def __init__(self,name,path):self.name,self.path=name,Path(path)
            def create_module(self,spec):return None
            def get_filename(self,name):return str(mapped.get(str(self.path),self.path))
            def exec_module(self,target):
                actual=mapped.get(str(self.path),self.path);raw=sources.code(actual);target.__file__=str(actual)
                sources.guard();exec(compile(raw,str(actual),'exec',dont_inherit=True),target.__dict__);sources.guard()
        module.importlib=types.SimpleNamespace(util=importlib.util,machinery=types.SimpleNamespace(SourceFileLoader=CapturedLoader))
    return module


def run_suite(stage):
    assert stage in {'local','stages','context','branches'}
    sources=Sources();module=controls(stage,sources);result=unittest.TestResult()
    unittest.defaultTestLoader.loadTestsFromModule(module).run(result);sources.guard();sources.close()
    expected={'local':12,'stages':14,'context':2,'branches':19}[stage]
    assert result.testsRun==expected and not result.skipped and result.wasSuccessful(),(stage,result.testsRun,result.failures,result.errors,result.skipped)
    RUNS.append({'stage':stage,'actualBodyControls':result.testsRun,'legacyDecisionHelperIsNotPhysicalInputAuthority':stage=='stages','nativeExecuted':False})
    return result.testsRun


def oracle(case,phase):
    assert case in (*LIFECYCLE_CASES,*BRANCH_CASES) and phase in {'before','after'}
    sources=Sources();saved=list(sys.argv)
    try:
        if case in {'gui-port','partial-control'}:
            m=controls('review',sources);(m.port_pair if case=='gui-port' else m.control_pair)(m.BEFORE if phase=='before' else m.HERE)
        elif case=='handler-ledger':controls('ledger',sources).exercise(phase)
        elif case=='operation-request':
            m=controls('stages',sources);m.operation_pair(sources.module(HERE/BEFORE[case]) if phase=='before' else m.runtime)
        elif case.startswith('tun-'):
            _,stage,variant=case.split('-',2);controls('context',sources).exercise(phase,stage,variant)
        elif case in {'custom-route','fixture-live','custom-direct'}:
            m=controls('branches',sources);{'custom-route':m.route_pair,'fixture-live':m.fixture_pair,'custom-direct':m.direct_probe_pair}[case](phase=='before')
        else:controls('closing',sources).run(phase,case.removeprefix('closing-'))
        sources.guard()
    finally:sys.argv=saved;sources.close()


def pair(case):
    assert case in (*LIFECYCLE_CASES,*BRANCH_CASES)
    results=[];env=dict(os.environ);env.pop('PYTHONPATH',None);env.pop('DYLD_INSERT_LIBRARIES',None);env['PYTHONDONTWRITEBYTECODE']='1'
    for phase,expected in [('before',1),('after',0)]:
        command=[sys.executable,'-B','-c','from agent_tools.tests.fixtures.windows_lifecycle_runtime.boundary import oracle; import sys; oracle(sys.argv[1],sys.argv[2])',case,phase]
        child=subprocess.Popen(command,cwd=ROOT,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        stdout,stderr=child.communicate();assert len(stdout)+len(stderr)<=1024*1024
        text=(stdout+stderr).decode(errors='replace')
        assert child.returncode==expected,(case,phase,child.returncode,text)
        if phase=='before':
            expected_reason={'gui-port':'sampler bypasses product by connecting directly to upstream fixture',
                'partial-control':'JSONDecodeError: Expecting property name enclosed in double quotes',
                'handler-ledger':'scheduled request lacks timestamp/path/userAgent attribution',
                'operation-request':'original-operation-status-join',
                'custom-route':'custom-management-route-prefix-changed',
                'fixture-live':'exited-original-fixture-was-admitted',
                'custom-direct':'custom-unrecognized-direct-probe-transformation'}.get(case,
                    'foreign collector context was accepted by original TUN consumer' if case.startswith('tun-')
                    else 'closing-native-replacement-was-attributed-to-old-runtime')
            assert expected_reason in text,(case,'wrong-causal-failure',text)
        results.append({'case':case,'phase':phase,'exitCode':child.returncode,'stdout':stdout,'stderr':stderr,'naturalExit':True,'completeEof':True,'nativeExecuted':False})
    RUNS.extend(results);return results


def valid_closing():
    sources=Sources();m=controls('closing',sources);m.run('after','valid');sources.close()


def parser():
    executable=powershell()
    if executable is None:raise unittest.SkipTest('PowerShell unavailable; native/query execution remains unqualified')
    sources=Sources();sources.capture(HERE/'parse_only.ps1');sources.capture(ROOT/'agent_tools/windows_runtime_tcp_listeners.ps1')
    env=dict(os.environ);env.update(POWERSHELL_UPDATECHECK='Off',POWERSHELL_TELEMETRY_OPTOUT='1');env.pop('DYLD_INSERT_LIBRARIES',None)
    child=subprocess.Popen([executable,'-NoLogo','-NoProfile','-NonInteractive','-File',str(HERE/'parse_only.ps1'),'-SourcePath',str(ROOT/'agent_tools/windows_runtime_tcp_listeners.ps1')],
        cwd=ROOT,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    stdout,stderr=child.communicate();sources.close()
    assert child.returncode==0 and stderr==b'' and b'"parsed":true,"executedTarget":false' in stdout,(child.returncode,stdout,stderr)
    return {'parserOnly':True,'targetExecuted':False,'windowsNativeQualified':False,'stdout':stdout,'stderr':stderr}


def rename_peer_oracle(phase):
    assert phase in {'before','after'}
    sources=Sources();module=sources.module(HERE/('capability_probe.windows-rename.before.source' if phase=='before' else 'capability_probe.py'))
    try:
        value=module.run('windows-like')
        assert value['testsRun']==8 and value['causalPairs']==21
        print(json.dumps({'wholeWindowsLikeSuitePassed':True,'nativeExecuted':False}),flush=True)
    finally:sources.close()


def rename_peer_pair():
    results=[];env=dict(os.environ);env.pop('PYTHONPATH',None);env.pop('DYLD_INSERT_LIBRARIES',None);env['PYTHONDONTWRITEBYTECODE']='1'
    for phase,expected in [('before',1),('after',0)]:
        argv=[sys.executable,'-B','-c','from agent_tools.tests.fixtures.windows_lifecycle_runtime.boundary import rename_peer_oracle; import sys; rename_peer_oracle(sys.argv[1])',phase]
        child=subprocess.Popen(argv,cwd=ROOT,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        stdout,stderr=child.communicate();assert child.returncode==expected,(phase,child.returncode,stdout,stderr)
        if phase=='before':assert b'FileExistsError not raised' in stderr,'wrong-windows-rename-peer-causal-failure'
        else:assert b'wholeWindowsLikeSuitePassed' in stdout and stderr==b''
        results.append({'case':'windows-rename-peer','phase':phase,'exitCode':child.returncode,'stdout':stdout,'stderr':stderr,'naturalExit':True,'completeEof':True,'nativeExecuted':False})
    RUNS.extend(results);return results
