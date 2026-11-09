"""Exact current ordinary owner source binding; no native execution."""
from __future__ import annotations
import hashlib
import os
import types
from pathlib import Path
import sys
import unittest
ROOT=Path(__file__).resolve().parents[2]
BEFORE=False

ROUTINE_PATH=ROOT/'agent_tools/tests/test_windows_system_collector.py'
ROUTINE_SHA='70c6db2ed0dca349cc59ca63a0c091d7db8050c1b16f4c33a26affdb072e2027'
_qualified=None

def _guard_qualified():
    if _qualified is None:raise ValueError('source-binding-not-held')
    stream,opening,raw=_qualified
    generation=lambda info:(info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,
        info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns)
    if generation(os.fstat(stream.fileno()))!=opening or generation(ROUTINE_PATH.stat())!=opening:
        raise ValueError('source-binding-source-generation-drift')
    stream.seek(0)
    if stream.read()!=raw:raise ValueError('source-binding-source-bytes-drift')

def load():
    global _qualified
    stream=ROUTINE_PATH.open('rb')
    generation=lambda info:(info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,
        info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns)
    opening=generation(os.fstat(stream.fileno()));raw=stream.read()
    if hashlib.sha256(raw).hexdigest()!=ROUTINE_SHA:
        stream.close();raise ValueError('source-binding-source-drift')
    _qualified=(stream,opening,raw)
    value=types.ModuleType('_owner_source_whole_routine')
    value.__file__=str(ROUTINE_PATH);sys.modules[value.__name__]=value
    try:
        # Compile only the raw bytes authenticated above; never reopen the name for execution.
        exec(compile(raw,str(ROUTINE_PATH),'exec',dont_inherit=True),value.__dict__)
        _guard_qualified();value._guard()
    except BaseException:
        for held,_,_,_ in getattr(value,'_held',{}).values():held.close()
        stream.close();raise
    return value

M=load()
OLD=M._load_source(ROOT/'agent_tools/tests/fixtures/windows_system_collector/before/v4/collector_contract.py',
    'c500a3e3302297a8a90865b62d3f12d65cc33f68edfb386043588a2233642b1e')

class OwnerSourceBindingTests(unittest.TestCase):
    def setUp(self):_guard_qualified();M._guard()
    def tearDown(self):_guard_qualified();M._guard()
    @classmethod
    def tearDownClass(cls):
        try:_guard_qualified();M._guard()
        finally:
            for stream,_,_,_ in M._held.values():stream.close()
            _qualified[0].close()

    def test_authentic_before_and_current_source_binding_pair(self):
        global BEFORE
        outcomes={}
        for phase,before in (('before',True),('current',False)):
            BEFORE=before;result=unittest.TestResult()
            case=OwnerSourceBindingTests('test_exact_current_owner_source_admits_without_relaxing_task_identity')
            # Run the identical oracle without class-level teardown between phases.
            case.run(result)
            outcomes[phase]=(result.testsRun,len(result.failures),len(result.errors))
        BEFORE=False
        self.assertEqual(outcomes,{'before':(1,1,0),'current':(1,0,0)})

    def test_exact_current_owner_source_admits_without_relaxing_task_identity(self):
        body=M.BODY;r,p,g=body.inputs();contract=OLD if BEFORE else body.C
        accepted=True
        try:contract.validate(r,{'contract':body.W.CONTRACT_SHA,'worker':body.W.WORKER_SHA},g)
        except ValueError:accepted=False
        self.assertTrue(accepted,'actual ba9 source must be admitted, never pretended d631')

    def test_old_foreign_hash_and_changed_task_identity_refuse_current(self):
        body=M.BODY
        for kind in ('old','foreign','argv','birth','sid','session'):
            r,p,g=body.inputs()
            if kind in {'old','foreign'}:r['ordinaryTask']['ownerSourcePin']['sha256']=('d6317f066f4a679e37f0a6aa5c30c229a2c6115ae2968aed568bec91d07362b2' if kind=='old' else '0'*64)
            elif kind=='argv':r['ordinaryTask']['ownerArgv'][2]='-Arbitrary'
            elif kind=='birth':r['ordinaryTask']['ownerActor']['creationFileTime']=0
            elif kind=='sid':r['ordinaryTask']['workerActor']['sid']='S-1-5-21-1-2-3-1009'
            else:r['ordinaryTask']['workerActor']['sessionId']=3
            with self.subTest(kind=kind),self.assertRaises(ValueError):body.C.validate(r,{'contract':body.W.CONTRACT_SHA,'worker':body.W.WORKER_SHA},g)

    def test_actual_protected_os_ps_candidate_matches_the_only_current_source(self):
        raw=(ROOT/'agent_tools/windows_ordinary_task_owner.ps1').read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),M.BODY.C.TASK_OWNER_SHA)

if __name__=='__main__':
    if '--before' in sys.argv:sys.argv.remove('--before');BEFORE=True
    unittest.main()
