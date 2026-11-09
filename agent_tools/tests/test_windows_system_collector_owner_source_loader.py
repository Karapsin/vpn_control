"""Actual whole-qualifier named-source replacement regression; local files only."""
from __future__ import annotations
import ast
import hashlib
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[2]
ROWS={'agent_tools/tests/fixtures/windows_system_collector/before/duplicate-child-raw-save/collector_wrapper.py': '41c427cc2eecb38218e219a84a82e6562daad49ff766c2bc532b5f03b95799de', 'agent_tools/tests/fixtures/windows_system_collector/before/ready-read-sharing/system_collector_worker.py': '052bf280609d72d269d855f26ddd2116d33ccedc54ce5bb077e3f80b24d801cf', 'agent_tools/tests/fixtures/windows_system_collector/before/source-read-exec/test_windows_system_collector_owner_source.py.source': '65ded8020bd179a14395bef2fa946488d72c784c98f26296d5cfd0ecbfa99664', 'agent_tools/tests/fixtures/windows_system_collector/before/v2/collector_body.py': 'eaeedc92d50fe51c59018c57795a29e05126aaeab567b0f9a4b9c441cd3bccc8', 'agent_tools/tests/fixtures/windows_system_collector/before/v2/collector_contract.py': '3b7148670ff88675dfcded83786290973160607fa4d647bb6250d1c3a494005d', 'agent_tools/tests/fixtures/windows_system_collector/before/v2/collector_wrapper.py': '02552ddbcf1e10c0fa1c770aa75d48aef1526e014fe41ea590cfd515af572b32', 'agent_tools/tests/fixtures/windows_system_collector/before/v2/ordinary_task_guard.ps1': '8105ad57f5140e6caef6fd21848f34d1684a00ca7c9e54ce64908211260844c1', 'agent_tools/tests/fixtures/windows_system_collector/before/v2/system_bootstrap_template.ps1': 'f1bf692804e149c2474ec854f463f6808f6bc3061793f9fffb8e84cb6c2700ea', 'agent_tools/tests/fixtures/windows_system_collector/before/v2/system_collector_native.cs': 'de48e24ca998ed30f480f130f9b8cf3cf610a86c31408d0abf144947f2264d70', 'agent_tools/tests/fixtures/windows_system_collector/before/v2/system_collector_worker.py': 'd3ab44e9a7d5cd521069f407ffbf7c6a33cae3e237b48cb5dc0750ffecc4bb9a', 'agent_tools/tests/fixtures/windows_system_collector/before/v3/collector_contract.py': '4633fcb10e815868c5d112e47a7a78053412435744242aabbfc18b8b8c10f619', 'agent_tools/tests/fixtures/windows_system_collector/before/v4/collector_contract.py': 'c500a3e3302297a8a90865b62d3f12d65cc33f68edfb386043588a2233642b1e', 'agent_tools/tests/fixtures/windows_system_collector/causal_body.py': '7a0d528d662ea4de63a691d44042cc9da02ff59eba6b99a6d74b3bad64946489', 'agent_tools/tests/fixtures/windows_system_collector/current_caller_body.py': 'cb1ad01692e792492f29e6f76c9f32074ae16f4136b5ab61659eae8b97554d5a', 'agent_tools/tests/fixtures/windows_system_collector/current_collector_body.py': 'd68f904655389c1b907f330dc7969c892b64ff54faccd98956fcd8c98eff0dc3', 'agent_tools/tests/fixtures/windows_system_collector/current_final_body.py': '8cfdb13519dfe50a7c810d6d0d2a6412cbb88beafa2fcb21944db2ef73798c23', 'agent_tools/tests/fixtures/windows_system_collector/originals/causal_controls.py.source': 'f6467ffb4c4ec3d05d1a00a3cd37a7f1bd06456339f0a2d675d35ebafad3447f', 'agent_tools/tests/fixtures/windows_system_collector/originals/test_caller_hold.py.source': 'f810787ae350221aaa9af5ad40768d9a22f54c7a4eefdb05317ebd61f2c199ea', 'agent_tools/tests/fixtures/windows_system_collector/originals/test_final_hold_guard.py.source': 'f89455652794f82febd493ba0fb8dd9a8c3b70b42ced4af0d4e0e5f204bd2fb6', 'agent_tools/tests/fixtures/windows_system_collector/originals/test_private_collector.py.source': '8ce287fc351048453eb7a16b887e08f4eb1dface72688eb7e1bb6ced7e29b5fe', 'agent_tools/tests/fixtures/windows_system_collector/originals/test_private_collector_v2.py.source': '9a24489726d579322b83f407ec82292095304c339fcb736d40b2df42a28e9568', 'agent_tools/tests/test_windows_system_collector.py': '70c6db2ed0dca349cc59ca63a0c091d7db8050c1b16f4c33a26affdb072e2027', 'agent_tools/tests/test_windows_system_collector_owner_source.py': 'fd3a45eee136a06e5455471485a69434c0aae01a30c21a797fb25f28cf1df94b', 'agent_tools/windows_artifact_transfer.py': '2938a7c6c25d23adc9683ced126fe2d3c0a88614dab59a7b134a624d6f8b0ee8', 'agent_tools/windows_ordinary_task_owner.ps1': 'ba9afe8db7e35b18c380327534a884f3e284a11ff5f7bffb660685dc4dca86b6', 'agent_tools/windows_public_updater/native_collector.py': '5a38ac02dd120d755a1d7bff25d8d0cd5fbf438c5fb52e57db15c45e335807a2', 'agent_tools/windows_public_updater/update_receipts.py': '5e2e406b82d4a446ab971f27918b3b0f110e67e3eb8cae971b0bfe4256aa71ec', 'agent_tools/windows_qga_transfer.py': 'bf05c8f08c1e5210ba79ffb59186206e80dc13fef057748dab3596df8ab6f022', 'agent_tools/windows_system_collector/caller_hold.py': '51a165023d867b7097cb75675f7a938ad683a0c188c88388a7ac0f5b16d851d1', 'agent_tools/windows_system_collector/collector_contract.py': 'a00dd01e2515f23b11d4eb21cafc67e2c45a20a4043e261d66a52845802620eb', 'agent_tools/windows_system_collector/collector_wrapper.py': 'fe5425999627f1bc449939664cb6580790bb4e04511bc8905ce348e27ac0d8fa', 'agent_tools/windows_system_collector/hold_protocol.py': 'b0e197fc68b077d5ea3a0f55338249b7b9a02e53d6f1da689367cbd1bf4f9335', 'agent_tools/windows_system_collector/native_primitives.py': 'ee28050bd0e33166956cc4f4ac68ca10cc89c30c01ae93468379895fee268a18', 'agent_tools/windows_system_collector/ordinary_task_guard.ps1': '8105ad57f5140e6caef6fd21848f34d1684a00ca7c9e54ce64908211260844c1', 'agent_tools/windows_system_collector/release_template.ps1': '7f9f1bda81a697c1c9c450536d4ced2a5ea700e30d4b59e60df3a395dd6f5ed1', 'agent_tools/windows_system_collector/system_bootstrap_template.ps1': '6fb8331ed2f975cb89bf107eb586b065ad54795d0a545809dccf897bd9ab8aee', 'agent_tools/windows_system_collector/system_collector_native.cs': '88ad6bbbf8b309bb641017d035bdf6688d37ac5d6e506bcffd4122203850a955', 'agent_tools/windows_system_collector/system_collector_worker.py': '323e2550b7efa53f93382efa366cfcf4cbf9e870b34a6578447b68128b2327fc', 'scripts/windows_broker_fixture_observer.py': '6d08edf9e57b09e98ce80d414b2ac12da4f39eb82e27cd2a3f06d9f900e04dcb', 'agent_tools/tests/fixtures/windows_system_collector/oracle_interpreter_guard.py': '75fee7d6ac34054484c17b1ea00cede1ced32fac0504c85682fec5e3755719c8', 'agent_tools/tests/fixtures/windows_system_collector/oracle-cleanup.before.source': 'a7d3e8f0e8dd68f23a88f7620296d01d29c8cd626e16a7bd5b1fe6f7836d8233', 'agent_tools/tests/fixtures/windows_system_collector/oracle-cleanup.provenance.json': 'd1b9bcb284ca60c0cf02f90ad34184c50520a3ffc197eb9b5ae249d6ae0f74c2'}
_held={}
CAUSAL_RESULTS={}
INJECTION_OBSERVATIONS={}
BEFORE=False
CURRENT='agent_tools/tests/test_windows_system_collector_owner_source.py'
OLD='agent_tools/tests/fixtures/windows_system_collector/before/source-read-exec/test_windows_system_collector_owner_source.py.source'
ROUTINE='agent_tools/tests/test_windows_system_collector.py'

def generation(s):return(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def guard():
    for relative,(stream,opening,raw) in _held.items():
        if generation(os.fstat(stream.fileno()))!=opening or generation((ROOT/relative).stat())!=opening:raise ValueError('qualifier-control-source-generation-drift')
        stream.seek(0)
        if stream.read()!=raw:raise ValueError('qualifier-control-source-byte-drift')
for relative,expected in ROWS.items():
    stream=(ROOT/relative).open('rb');opening=generation(os.fstat(stream.fileno()));raw=stream.read()
    if hashlib.sha256(raw).hexdigest()!=expected:raise ValueError('qualifier-control-source-admission')
    _held[relative]=(stream,opening,raw)
guard()


def _historical_qualifier_for_current_cohort(raw):
    """Bind only historical source-admission DATA to the current routine cohort.

    OLD stays byte-exact on disk and is authenticated by the retained ROWS pin.
    The whole historical loader/functions/assertions execute unchanged; only its
    top-level M=load expected-source DATA is renewed for this source cohort.
    """
    assert hashlib.sha256(raw).hexdigest() == ROWS[OLD]
    current = ROWS[ROUTINE]
    assert type(current) is str and len(current) == 64 and all(c in '0123456789abcdef' for c in current)
    original = ast.parse(raw)
    assignments = [node for node in original.body if isinstance(node, ast.Assign)
        and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id == 'M']
    assert len(assignments) == 1
    call = assignments[0].value
    assert isinstance(call, ast.Call) and isinstance(call.func, ast.Name) and call.func.id == 'load'
    assert len(call.args) == 3 and not call.keywords
    assert isinstance(call.args[0], ast.Constant) and call.args[0].value == '_owner_source_whole_routine'
    assert ast.dump(call.args[1], include_attributes=False) == ast.dump(ast.parse("ROOT/'agent_tools/tests/test_windows_system_collector.py'", mode='eval').body, include_attributes=False)
    value = call.args[2]
    assert isinstance(value, ast.Constant) and value.value == '8357285fc9cd2094bca956e428a0ef477741c951509c5eb67b16be247af546ee'
    lines = raw.splitlines(keepends=True)
    start = sum(map(len, lines[:value.lineno-1])) + value.col_offset
    end = sum(map(len, lines[:value.end_lineno-1])) + value.end_col_offset
    rebound = raw[:start] + repr(current).encode() + raw[end:]
    value.value = current
    assert ast.dump(original, include_attributes=False) == ast.dump(ast.parse(rebound), include_attributes=False)
    return rebound

class SourceReplacementTests(unittest.TestCase):
    def setUp(self):guard()
    def tearDown(self):guard()
    def test_whole_qualifier_executes_checked_bytes_and_refuses_named_replacement(self):
        with tempfile.TemporaryDirectory(prefix='owned-qualifier-race-') as temporary:
            root=Path(temporary).resolve()
            for relative,(_,_,raw) in _held.items():
                target=root/relative;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw)
            target=root/ROUTINE;qualifier=root/CURRENT
            raw=_held[OLD if BEFORE else CURRENT][2]
            if BEFORE:raw=_historical_qualifier_for_current_cohort(raw)
            original_open=Path.open;fired=False
            class ReadOnce:
                def __init__(self,stream):self.stream=stream
                def __enter__(self):return self
                def __exit__(self,*args):self.stream.close()
                def __getattr__(self,name):return getattr(self.stream,name)
                def read(self,*args):
                    nonlocal fired
                    value=self.stream.read(*args)
                    if not fired:
                        fired=True
                        replacement=target.with_suffix('.replacement')
                        with original_open(replacement,'wb') as out:out.write(b'replacement_was_executed=True\n_held={}\n_guard=lambda:None\n')
                        os.replace(replacement,target)
                    return value
            def opened(path,*args,**kwargs):
                stream=original_open(path,*args,**kwargs)
                mode=args[0] if args else kwargs.get('mode','r')
                return ReadOnce(stream) if path==target and mode=='rb' and not fired else stream
            module=types.ModuleType('_actual_whole_owner_qualifier_control');module.__file__=str(qualifier)
            prior=dict(sys.modules);refused=False;failure=None
            try:
                with patch.object(Path,'open',opened),patch.object(sys,'dont_write_bytecode',True):
                    try:exec(compile(raw,str(qualifier),'exec',dont_inherit=True),module.__dict__)
                    except ValueError as exc:failure=str(exc);refused=failure=='source-binding-source-generation-drift'
                loaded=sys.modules.get('_owner_source_whole_routine')
                INJECTION_OBSERVATIONS['before' if BEFORE else 'current']={'fired':fired,'originalExecuted':loaded is not None and hasattr(loaded,'ROWS'),'replacementExecuted':bool(getattr(loaded,'replacement_was_executed',False)),'refused':refused,'failure':failure}
                self.assertTrue(fired and loaded is not None and hasattr(loaded,'ROWS') and refused,
                    f'whole qualifier custody: fired={fired}, module={loaded}, original={hasattr(loaded,"ROWS")}, refused={refused}, failure={failure}')
            finally:
                loaded=sys.modules.get('_owner_source_whole_routine')
                for stream,_,_,_ in getattr(loaded,'_held',{}).values():
                    if not stream.closed:stream.close()
                held=getattr(module,'_qualified',None)
                if held is not None and not held[0].closed:held[0].close()
                for name in set(sys.modules)-set(prior):sys.modules.pop(name,None)
                for name,value in prior.items():sys.modules[name]=value

    def test_authentic_whole_before_and_current_named_replacement_pair(self):
        global BEFORE
        for phase,before in [('before',True),('current',False)]:
            BEFORE=before;result=unittest.TestResult()
            SourceReplacementTests('test_whole_qualifier_executes_checked_bytes_and_refuses_named_replacement').run(result)
            CAUSAL_RESULTS[phase]={'testsRun':result.testsRun,'failures':[v for _,v in result.failures],'errors':[v for _,v in result.errors]}
        BEFORE=False
        self.assertEqual({k:v['fired'] for k,v in INJECTION_OBSERVATIONS.items()},{'before':True,'current':True},'both actual source reads must receive replacement before any causal RED is counted')
        self.assertEqual(INJECTION_OBSERVATIONS['before']['replacementExecuted'],True)
        self.assertEqual(INJECTION_OBSERVATIONS['current']['originalExecuted'],True)
        self.assertEqual(INJECTION_OBSERVATIONS['current']['refused'],True)
        self.assertEqual({k:(v['testsRun'],len(v['failures']),len(v['errors'])) for k,v in CAUSAL_RESULTS.items()},
            {'before':(1,1,0),'current':(1,0,0)})

class HeldSuite(unittest.TestSuite):
    def run(self,result,debug=False):
        guard()
        try:return super().run(result,debug)
        finally:
            try:guard()
            finally:
                for stream,_,_ in _held.values():stream.close()
def load_tests(loader,tests,pattern):return HeldSuite([loader.loadTestsFromTestCase(SourceReplacementTests)])
if __name__=='__main__':
    if '--before' in sys.argv:sys.argv.remove('--before');BEFORE=True
    unittest.main()
