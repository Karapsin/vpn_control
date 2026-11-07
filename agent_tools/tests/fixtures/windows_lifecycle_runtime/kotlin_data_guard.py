"""Two genuine source-data custody decisions using unchanged branch oracles."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import uuid
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[3]
DATA=(
 'shared/core/src/commonMain/kotlin/com/kardinal/vpncontrol/data/SingBoxRouteDnsBuilder.kt',
 'desktopApp/src/main/kotlin/com/kardinal/vpncontrol/desktop/DesktopProxyConfigFactory.kt')

def generation(s):return (s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def load_boundary(phase):
    assert phase in {'before','after'}
    path=HERE/('kotlin_data_boundary.before.source' if phase=='before' else 'boundary.py')
    stream=path.open('rb');raw=stream.read();identity=generation(os.fstat(stream.fileno()))
    pin=json.loads((HERE/'provenance.json').read_bytes())['fixtures'][str(path.relative_to(ROOT))]
    assert len(raw)==pin['bytes'] and hashlib.sha256(raw).hexdigest()==pin['sha256']
    def guard():
        stream.seek(0);assert stream.read()==raw and generation(os.fstat(stream.fileno()))==identity==generation(path.stat()),'boundary-source-custody-changed'
    module=types.ModuleType('_data_boundary_'+phase+'_'+uuid.uuid4().hex);module.__file__=str(path);sys.modules[module.__name__]=module
    guard();exec(compile(raw,str(path),'exec',dont_inherit=True),module.__dict__);guard()
    module._routine_source_guard=guard;module._routine_source_stream=stream
    return module

def exercise(phase,case):
    assert case in {'route','direct','valid'}
    module=load_boundary(phase)
    with tempfile.TemporaryDirectory(prefix='owned-kotlin-data-') as temporary:
        root=Path(temporary);fixture=root/'agent_tools/tests/fixtures/windows_lifecycle_runtime'
        fixture.mkdir(parents=True);(fixture/'branches').mkdir()
        paths=[*DATA,'agent_tools/windows_runtime_branch_cases.py',
            'agent_tools/tests/fixtures/windows_lifecycle_runtime/branches/controls.source']
        provenance={'schemaVersion':1,'production':{},'fixtures':{},'baselineInputs':{}}
        for relative in paths:
            source=ROOT/relative;raw=source.read_bytes();target=root/relative;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw)
            group='baselineInputs' if relative in DATA else 'fixtures' if '/fixtures/' in relative else 'production'
            provenance[group][relative]={'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw)}
        (fixture/'provenance.json').write_text(json.dumps(provenance))
        module.ROOT,module.HERE=root,fixture
        sources=module.Sources();controls=module.controls('branches',sources);refused=False;reason=None
        try:
            if case!='valid':
                path=root/DATA[0 if case=='route' else 1]
                # An irrelevant comment keeps every unchanged oracle token and
                # resulting CUSTOM meaning valid; only actual source custody
                # distinguishes the unobserved changed data from the original.
                with path.open('ab') as stream:stream.write(b'\n// controlled owned Kotlin-data change\n');stream.flush();os.fsync(stream.fileno())
            try:
                if case in {'route','valid'}:controls.actual_shape(controls.m)
                if case in {'direct','valid'}:controls.direct_probe_pair(False)
                sources.guard()
            except AssertionError as error:
                reason=str(error);assert reason in {'original-source-bytes-changed','original-or-named-source-generation-changed'},reason
                refused=True
            assert refused is (case!='valid'),'changed-Kotlin-data-was-accepted-by-original-routine-boundary'
            print(json.dumps({'phase':phase,'case':case,'refused':refused,'reason':reason,
                'unchangedActualOracleBody':True,'nativeExecuted':False,'networkExecuted':False}),flush=True)
        finally:
            # These are known read-only handles for intentionally mutated owned
            # test copies, never product/native custody or source replay.
            for path,stream,raw,identity in sources.held.values():stream.close()
            sources.closed=True
            module._routine_source_guard();module._routine_source_stream.close()


def pair(case):
    assert case in {'route','direct'}
    rows=[];env=dict(os.environ);env.pop('PYTHONPATH',None);env.pop('DYLD_INSERT_LIBRARIES',None);env['PYTHONDONTWRITEBYTECODE']='1'
    for phase,expected in [('before',1),('after',0)]:
        argv=[sys.executable,'-B','-c','from agent_tools.tests.fixtures.windows_lifecycle_runtime.kotlin_data_guard import exercise; import sys; exercise(sys.argv[1],sys.argv[2])',phase,case]
        child=subprocess.Popen(argv,cwd=ROOT,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        stdout,stderr=child.communicate();assert child.returncode==expected,(case,phase,child.returncode,stdout,stderr)
        if phase=='before':assert b'changed-Kotlin-data-was-accepted-by-original-routine-boundary' in stderr
        else:assert b'"refused": true' in stdout and stderr==b''
        rows.append({'case':'kotlin-data-'+case,'phase':phase,'exitCode':child.returncode,'stdout':stdout,'stderr':stderr,'naturalExit':True,'completeEof':True,'nativeExecuted':False})
    from agent_tools.tests.fixtures.windows_lifecycle_runtime import boundary
    boundary.RUNS.extend(rows);return rows
