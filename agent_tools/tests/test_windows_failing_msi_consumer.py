"""Finite full failing-MSI consumer source and authentic before controls; no native actions."""
from __future__ import annotations
import hashlib
import os
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[2]
FIXTURES=Path(__file__).parent/'fixtures/windows_failing_msi_consumer'
ROWS={'agent_tools/tests/fixtures/windows_failing_msi_consumer/before/caller-protocol/caller_hold.py': '6a6fbbe73e8d70db247656af330a8a4de9b2119a181ae4e3af5d0757dc8f0ef5', 'agent_tools/tests/fixtures/windows_failing_msi_consumer/before/caller-protocol/hold_protocol.py': '70440195ac8f3116f4a40b788616419ea88591eb430119ce386f6b31684fc1c1', 'agent_tools/tests/fixtures/windows_failing_msi_consumer/before/hash-only/native_collector.py': '246bb5e7110fe5fdad986e3cf082683934070195098730bf79ab86e0fd0296b2', 'agent_tools/tests/fixtures/windows_failing_msi_consumer/before/v2/system_collector_worker.py': 'd3ab44e9a7d5cd521069f407ffbf7c6a33cae3e237b48cb5dc0750ffecc4bb9a', 'agent_tools/tests/fixtures/windows_failing_msi_consumer/caller_body.py': '6eea1db21e04744d7251a1d388a033303fc18516ca9074af3fcbfd85f7b15420', 'agent_tools/tests/fixtures/windows_failing_msi_consumer/originals/test_failing_caller_body.py.source': '945ac7c218aa6dbabd13b1208d7543e007e5c3ca93087958f527a1fdce9865d9', 'agent_tools/tests/fixtures/windows_failing_msi_consumer/originals/test_failing_msi_caller_pipeline.py.source': '70cc354d0e87f54ddd86823f85799882344f6e8aa87ae47d18f0cb04a6751ec9', 'agent_tools/tests/fixtures/windows_failing_msi_consumer/originals/test_fault_msi_consumer.py.source': 'c31b5b0dd0e098803108abf5fd014e980f4e2df2be95760f9fe52f4005876b44', 'agent_tools/tests/fixtures/windows_failing_msi_consumer/originals/test_private_failing_msi.py.source': '15f38d0d7bac088a03bc8bfbd04b90e55904ff52bc590eeb73a7000d17b5f799', 'agent_tools/tests/fixtures/windows_failing_msi_consumer/originals/test_system_consumer.py.source': '20a49f32a1cb01c47fec7eeb4231dfcba62f4acbed366dfffa6ca8b171e0a04b', 'agent_tools/tests/fixtures/windows_failing_msi_consumer/pipeline_body.py': '750c4a07042847809b0ada7e6b4d9c26c446ca189ad26a3d83b80dc55f1e84cd', 'agent_tools/tests/fixtures/windows_failing_msi_consumer/producer_body.py': '5e0f09d4f531350927aa97c1f369498ffc118f180c3fae70da1ce6cbda0f154c', 'agent_tools/tests/fixtures/windows_failing_msi_consumer/semantic_body.py': '20dd8e66027b406819b72d154e6345784a767d01faee80b237b16ee4169d4f00', 'agent_tools/tests/fixtures/windows_failing_msi_consumer/system_body.py': '07cdf5de61a14f431821506db1425effb94f2be3cc6e17b515d5bf560661708b', 'agent_tools/windows_artifact_transfer.py': '2938a7c6c25d23adc9683ced126fe2d3c0a88614dab59a7b134a624d6f8b0ee8', 'agent_tools/windows_failing_msi/failing_msi_fixture.py': '3941f950cf19c010130fb128449569402498a46e3c82fdc97a7f94783e6d7e33', 'agent_tools/windows_public_updater/failing_msi_cases.py': '0b1c4e3acb312fb7bd34f1c098abede5d6c93b591e5e08b858d516f89d14d034', 'agent_tools/windows_public_updater/failing_msi_native_collector.py': '7c23f177a701b7e553cccc1fc4ec9de1fadde8991e451050e64e94539da36a8b', 'agent_tools/windows_public_updater/fault_msi_consumer.py': 'ae20e4b1a268af6a222ce9a530c811171fe44e26a50f07b3aac3b3ba82f48af4', 'agent_tools/windows_qga_transfer.py': 'bf05c8f08c1e5210ba79ffb59186206e80dc13fef057748dab3596df8ab6f022', 'agent_tools/windows_system_collector/failing_msi_bootstrap_template.ps1': '74cc27de77a48d76edbb321f34e9c4bd1d9e23423c4dc6ce8c41b6782d7dfe16', 'agent_tools/windows_system_collector/failing_msi_caller_hold.py': '1bcf0896dbc11c4a854f2df4a55b75225dab87479aeccb1132a060bda7cb663f', 'agent_tools/windows_system_collector/failing_msi_contract.py': '802303fab31a395853807ac3558144e2c163aa18bf949403844860575a57e6b4', 'agent_tools/windows_system_collector/failing_msi_hold_protocol.py': 'ab4e9d11d03d58f4f7400f7488fd6c18d7c10f3738c7d4af52a4dd0950998d4d', 'agent_tools/windows_system_collector/failing_msi_worker.py': '72d52731192589c1c4aa0c94f4bfbaf5335bc408b178077c4e53f1e48e1e0bc0', 'agent_tools/windows_system_collector/failing_msi_wrapper.py': '2828379fef8cbda5d706318ad979127a25a174dc2a9e5b3737b1bb88567fc694', 'agent_tools/windows_system_collector/native_primitives.py': 'ee28050bd0e33166956cc4f4ac68ca10cc89c30c01ae93468379895fee268a18', 'agent_tools/windows_system_collector/ordinary_task_guard.ps1': '8105ad57f5140e6caef6fd21848f34d1684a00ca7c9e54ce64908211260844c1', 'agent_tools/windows_system_collector/release_template.ps1': 'e80512879ca619639bddff758186eadfeca74cf738552946c3b1dc7cf77c24aa', 'agent_tools/windows_system_collector/system_collector_native.cs': '88ad6bbbf8b309bb641017d035bdf6688d37ac5d6e506bcffd4122203850a955'}
_held={};_modules={};CAUSAL_RESULTS={}
def generation(s):return(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def _guard():
    for relative,(stream,opening,raw) in _held.items():
        if generation(os.fstat(stream.fileno()))!=opening or generation((ROOT/relative).stat())!=opening:raise ValueError('failing-routine-generation-drift:'+relative)
        stream.seek(0)
        if stream.read()!=raw:raise ValueError('failing-routine-byte-drift:'+relative)
for relative,expected in ROWS.items():
    stream=(ROOT/relative).open('rb');opening=generation(os.fstat(stream.fileno()));raw=stream.read()
    if hashlib.sha256(raw).hexdigest()!=expected:raise ValueError('failing-routine-source-admission:'+relative)
    _held[relative]=(stream,opening,raw)
def _load_source(path,expected=None):
    relative=str(path.relative_to(ROOT)).replace(os.sep,'/')
    if relative not in ROWS or expected is not None and ROWS[relative]!=expected:raise ValueError('failing-routine-undeclared-source:'+relative)
    _guard()
    if relative in _modules:return _modules[relative]
    value=types.ModuleType('_fixed_failing_routine_'+hashlib.sha256(relative.encode()).hexdigest()[:16]);value.__file__=str(path)
    value._load_source=_load_source;value._guard=_guard;value._canonical_root=ROOT;value._fixture_root=FIXTURES
    sys.modules[value.__name__]=value;_modules[relative]=value
    exec(compile(_held[relative][2],str(path),'exec',dont_inherit=True),value.__dict__);_guard();return value
SYSTEM=_load_source(FIXTURES/'system_body.py')
SEMANTIC=_load_source(FIXTURES/'semantic_body.py')
CALLER=_load_source(FIXTURES/'caller_body.py')
PIPELINE=_load_source(FIXTURES/'pipeline_body.py')
class HashOnlyCausalPair(unittest.TestCase):
    def test_actual_before_metadata_hash_only_and_current_semantic_refusal(self):
        outcomes={}
        for phase,before in [('before',True),('current',False)]:
            result=unittest.TestResult()
            with patch.object(SEMANTIC,'BEFORE',before):SEMANTIC.SemanticConsumerTests('test_rejects_hash_only_metadata_even_when_file_hash_matches').run(result)
            outcomes[phase]={'testsRun':result.testsRun,'failures':[v for _,v in result.failures],'errors':[v for _,v in result.errors]}
        CAUSAL_RESULTS['hash-only']=outcomes
        self.assertEqual({k:(v['testsRun'],len(v['failures']),len(v['errors'])) for k,v in outcomes.items()},
            {'before':(1,1,0),'current':(1,0,0)})
class HeldSuite(unittest.TestSuite):
    def run(self,result,debug=False):
        _guard()
        try:return super().run(result,debug)
        finally:
            try:_guard()
            finally:
                for stream,_,_ in _held.values():stream.close()
def load_tests(loader,tests,pattern):return HeldSuite([loader.loadTestsFromModule(SYSTEM),loader.loadTestsFromModule(SEMANTIC),
    loader.loadTestsFromModule(CALLER),loader.loadTestsFromModule(PIPELINE),loader.loadTestsFromTestCase(HashOnlyCausalPair)])
if __name__=='__main__':unittest.main()
