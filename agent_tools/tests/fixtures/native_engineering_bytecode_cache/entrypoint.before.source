"""Actual future clean producer imports and fixed local protocol, no native calls."""
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch
from agent_tools import linux_package_fixture_build as build
from agent_tools import native_execution_context as context
from agent_tools.tests import test_native_execution_context as fixture

_HARNESS=r'''
import io,json,sys
from pathlib import Path
from unittest.mock import patch
source=Path(sys.argv[1]);root=Path(sys.argv[2]);packet=json.loads(sys.stdin.buffer.read() if sys.argv[3]=='-' else sys.argv[3])
sys.path.insert(0,str(source))
from agent_tools import linux_package_fixture_build as build
from agent_tools import native_execution_context as context
from agent_tools import ssh_tmux_resource_admission as resource
from agent_tools import ssh_tmux_session_ssh as old
assert Path(build.__file__).resolve().is_relative_to(source)
assert Path(resource.__file__).resolve().is_relative_to(source)
seen=[]
def fixed_local_effect(storage,operation,raw,*,source_root,engineering_context):
 assert Path(storage)==root and Path(source_root)==source
 assert type(engineering_context)is context.EngineeringExecutionContext
 assert engineering_context.coordinator_root==root and engineering_context.source_root==source
 engineering_context.require_native_consumers((Path(build.__file__),Path(old.__file__)))
 seen.append(operation)
 if operation=='preflight':return {'state':'ready','sourceSha':raw['sourceSha'],'baseVersion':raw['baseVersion'],'targetVersion':raw['targetVersion'],'host':'archlinux','packageFamilies':['default','arch'],'nativeActionAllowed':False,'reason':'available'}
 return {'state':'unknown','correlationId':raw['correlationId'],'reason':'submission-response-uncertain' if operation=='start' else 'missing-journal','replayAllowed':False}
class In:
 buffer=io.BytesIO(json.dumps(packet).encode())
class Out:
 buffer=io.BytesIO()
result=Out()
with patch.object(resource,'operate',side_effect=fixed_local_effect),patch.object(resource,'directory',return_value=root),patch.object(sys,'stdin',In()),patch.object(sys,'stdout',result):
 build._engineering_main(root)
output=json.loads(result.buffer.getvalue());assert seen==[packet['operation']] or (packet['operation']=='start' and not seen and output.get('reason')=='already-journaled')
print(json.dumps(output,separators=(',',':')))
'''

@unittest.skipUnless(os.name=='posix','Local private frozen producer control')
class NativeEngineeringEntrypointTest(unittest.TestCase):
    setUp=fixture.NativeExecutionContextTest.setUp
    git=fixture.NativeExecutionContextTest.git
    engineering=fixture.NativeExecutionContextTest.engineering
    def packet(self,artifact,operation='preflight'):
        return {'operation':operation,'request':self.request,'artifactIds':[artifact['artifactId']]}
    def run_frozen(self,packet):
        child=subprocess.run([sys.executable,'-I','-B','-c',_HARNESS,str(self.native),str(self.coordinator),json.dumps(packet)],capture_output=True,text=True,timeout=30)
        self.assertEqual(0,child.returncode,child.stderr)
        return json.loads(child.stdout)
    def test_actual_future_frozen_producer_local_main_enrolls_and_observes_original_after_ref_advance(self):
        artifact,_=self.engineering()
        first=self.run_frozen(self.packet(artifact))
        self.assertEqual('ready',first['state']);self.assertFalse(first['finalAcceptance'])
        self.assertEqual(self.sha,first['sourceSha']);self.assertEqual('2.2.9',first['originalPackageVersion'])
        target=first['targetSha'];enrollment=self.coordinator/build._JOURNAL/(self.request['correlationId']+'.engineering.json')
        original=enrollment.read_bytes()
        (self.coordinator/'agent_tools/check_output_retention.py').write_text('check_only = 3\n')
        self.git('add','agent_tools/check_output_retention.py');self.git('commit','-m','later unrelated checkpoint');self.git('push','origin','dev')
        observed=self.run_frozen(self.packet(artifact,'status'))
        self.assertEqual(target,observed['targetSha']);self.assertEqual(original,enrollment.read_bytes())
        with self.assertRaisesRegex(context.ExecutionContextError,'native_target_ref_changed'):
            build._engineering_context(self.coordinator,self.native,self.request,(artifact['artifactId'],),'start')
    def test_real_isolated_script_mode_rejects_extra_packet_fields_before_platform_effects(self):
        child=subprocess.run([sys.executable,'-I','-B',str(self.native/'agent_tools/linux_package_fixture_build.py'),'--engineering-local',str(self.coordinator)],input=b'{"operation":"status","driver":"arbitrary"}',capture_output=True,timeout=10)
        self.assertNotEqual(0,child.returncode);self.assertIn(b'Engineering packet fields differ',child.stderr)
    def test_dispatch_rejects_arbitrary_mode_command_or_foreign_source_before_child(self):
        artifact,_=self.engineering()
        inputs={**self.request,'engineeringContext':{'sourceRoot':str(self.native),'artifactIds':[artifact['artifactId']]}}
        for operation,raw in (('release',inputs),('start',{**inputs,'command':'caller'}),
                              ('status',{**inputs,'engineeringContext':{**inputs['engineeringContext'],'admission':False}})):
            with self.subTest(operation=operation),patch('subprocess.Popen',side_effect=AssertionError('No child/native effect')) as child:
                with self.assertRaises((ValueError,TypeError)):context.dispatch_linux_engineering(self.coordinator,operation,raw)
                child.assert_not_called()

    def test_actual_bounded_parent_invoker_serializes_fixed_packet_to_frozen_producer(self):
        artifact,_=self.engineering()
        inputs={**self.request,'engineeringContext':{'sourceRoot':str(self.native),'artifactIds':[artifact['artifactId']]}}
        actual_popen=subprocess.Popen;seen=[]
        def inert_local_launch(argv,*args,**kwargs):
            if len(argv)>3 and argv[0]==sys.executable and argv[3]==str(self.native/'agent_tools/linux_package_fixture_build.py'):
                self.assertEqual([sys.executable,'-I','-B',str(self.native/'agent_tools/linux_package_fixture_build.py'),'--engineering-local',str(self.coordinator)],argv)
                self.assertEqual(self.native,kwargs['cwd']);seen.append(argv)
                argv=[sys.executable,'-I','-B','-c',_HARNESS,str(self.native),str(self.coordinator),'-']
            return actual_popen(argv,*args,**kwargs)
        with patch.object(subprocess,'Popen',side_effect=inert_local_launch):
            result=context.dispatch_linux_engineering(self.coordinator,'preflight',inputs)
        self.assertEqual(1,len(seen));self.assertTrue(result['ok']);self.assertFalse(result['nativeActionAllowed'])
        self.assertFalse(result['finalAcceptance']);self.assertEqual(self.sha,result['sourceSha'])
        self.assertNotIn('sourceRoot',result);self.assertNotIn('authority',result)
        capsules=list((self.coordinator/'.rag_index').glob('ssh-tmux-pipe-*'))
        # The existing capture helper retains both streams and its EOF receipt.
        receipts=list((self.coordinator/'.rag_index').rglob('receipt.json'))
        self.assertTrue(receipts)
    def test_unknown_parent_start_capture_is_consumed_before_child_launch_and_never_replayed(self):
        from agent_tools import ssh_tmux_mcp_adapter as adapter
        artifact,_=self.engineering()
        build._engineering_context(self.coordinator,self.native,self.request,(artifact['artifactId'],),'preflight')
        inputs={**self.request,'engineeringContext':{'sourceRoot':str(self.native),'artifactIds':[artifact['artifactId']]}}
        with patch.object(adapter,'_capture',side_effect=TimeoutError('Original local response unavailable')) as capture:
            with self.assertRaises(TimeoutError):context.dispatch_linux_engineering(self.coordinator,'start',inputs)
            second=context.dispatch_linux_engineering(self.coordinator,'start',inputs)
        self.assertEqual(1,capture.call_count);self.assertEqual('unknown',second['state'])
        self.assertEqual('already-journaled',second['reason']);self.assertFalse(second['replayAllowed'])
        self.assertFalse(second['finalAcceptance'])

    def test_actual_child_uncertain_start_dispatch_is_never_replayed_by_direct_cli(self):
        artifact,_=self.engineering()
        self.run_frozen(self.packet(artifact))
        first=self.run_frozen(self.packet(artifact,'start'))
        self.assertEqual('unknown',first['state']);self.assertEqual('submission-response-uncertain',first['reason'])
        second=self.run_frozen(self.packet(artifact,'start'))
        self.assertEqual('already-journaled',second['reason']);self.assertFalse(second['replayAllowed'])
        burn=self.coordinator/build._JOURNAL/(self.request['correlationId']+'.engineering-child-start.json')
        self.assertEqual(self.request,json.loads(burn.read_bytes())['request'])
    def test_actual_script_rejects_stale_matching_bytecode_before_any_repository_import(self):
        import importlib.util
        import importlib._bootstrap_external
        helper=self.native/'agent_tools/native_execution_context.py';marker=self.base/'cached-helper-executed'
        # Cache header matches the unchanged actual named source mtime and size.
        stale=compile(helper.read_text()+'\nfrom pathlib import Path\nPath('+repr(str(marker))+').write_text("stale cache executed")\n',str(helper),'exec')
        cache=Path(importlib.util.cache_from_source(str(helper)));cache.parent.mkdir(exist_ok=True)
        cache.write_bytes(importlib._bootstrap_external._code_to_timestamp_pyc(stale,int(helper.stat().st_mtime),helper.stat().st_size))
        original=helper.read_bytes()
        child=subprocess.run([sys.executable,'-I','-B',str(self.native/'agent_tools/linux_package_fixture_build.py'),'--engineering-local',str(self.coordinator)],input=b'{"operation":"status","driver":"caller"}',capture_output=True,timeout=10)
        self.assertNotEqual(0,child.returncode);self.assertIn(b'Engineering packet fields differ',child.stderr)
        self.assertEqual(original,helper.read_bytes());self.assertFalse(marker.exists())
