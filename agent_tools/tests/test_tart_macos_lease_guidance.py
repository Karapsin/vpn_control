"""Observed native reply projections through fresh real MCP/SDK callers.

The controlled server replaces only provider effects with retained reply data.
It exercises production normalization, public tool wrapper and typed guidance;
it does not register or qualify a synthetic provider.
"""
import asyncio
from datetime import timedelta
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest

from agent_tools import readiness_tart_macos_lease_executor as executor
from agent_tools import native_next_action as guidance
from agent_tools import readiness_lease_workflow as facade
from agent_tools import durable_remote_job as jobs
from agent_tools import readiness_tart_macos_leases as leases
from types import SimpleNamespace
from uuid import uuid4

ROOT=Path(__file__).resolve().parents[2]
FIXTURES=Path(__file__).parent/'fixtures'
OPERATION='cd7ae194-d72a-4bd6-9d86-190f10a2931f'

SERVER=r'''
import importlib.util,json,sys,types
from pathlib import Path
from importlib.machinery import SourceFileLoader
from agent_tools import mcp_server as server,native_next_action as guidance,readiness_lease_workflow as facade
root=Path(sys.argv[1]);before=sys.argv[2]=='before'
if before:
 path=root/'agent_tools/tests/fixtures/macos_lease_next_action.before.source'
 loader=SourceFileLoader('agent_tools._lease_guidance_before',str(path))
 spec=importlib.util.spec_from_loader(loader.name,loader);producer=importlib.util.module_from_spec(spec);loader.exec_module(producer)
else:
 from agent_tools import readiness_tart_macos_lease_executor as producer
data=json.loads((root/'agent_tools/tests/fixtures/macos_lease_native_replies.json').read_text())['replies']
calls=[]
def provider(action,inputs):
 calls.append(action)
 state='unknown'if action=='readiness-lease-acquire'else'active'if len(calls)==2 else'expired'
 native=data[state]
 assert inputs=={'fixtureId':'controlled-mac','operationId':native['operationId']}
 value={'provider':'tart-macos','fixtureId':'controlled-mac','operationId':native['operationId']}
 return facade._external_result(value,producer.normalize(native,native['operationId']))
server._vm_workflow_impl=provider
effects=types.SimpleNamespace(bounded_failure_details=lambda *a:{},record_failure=lambda *a:{},describe=lambda *a:{})
server._agent_module=lambda name:guidance if name=='native_next_action'else effects
server.MCP_SERVER.run(transport='stdio')
'''


class NativeLeaseGuidanceTests(unittest.TestCase):
    @unittest.skipUnless(os.name=='posix','actual original detached owner protocol')
    def test_actual_inspect_before_assertion_receipt_follows_starting_never_claims_active(self):
        with tempfile.TemporaryDirectory()as temporary:
            root=Path(temporary).resolve();root.chmod(0o700);gate=root/'release'
            operation=str(uuid4());binding=jobs.current_binding('controlled-startup','controlled-machine')
            source=("import time\nfrom pathlib import Path\nend=time.monotonic()+4\n"
                    "while not Path("+repr(str(gate))+").exists()and time.monotonic()<end:time.sleep(.01)\n")
            generation=jobs.root_generation(root);jobs.submit(root,operation,binding,jobs.Program('controlled-startup',source.encode()),generation=generation)
            try:
                end=time.monotonic()+3
                while jobs.observe(root,operation,binding,generation=generation)['state']!='running'and time.monotonic()<end:time.sleep(.01)
                # The exact inspect body sees a live original durable owner,
                # before any lease-acquired assertion receipt exists.
                native=leases.inspect(root,operation,SimpleNamespace(job_binding=lambda:binding),generation=generation)
                self.assertEqual((native['state'],native['jobState'],native['reason']),('unknown','running','original_owner_running'))
                result=executor.normalize(native,operation)
                self.assertEqual((result['state'],result['nativeState']),('starting','unknown'))
                value=facade._external_result({'fixtureId':'controlled-mac','operationId':operation,'provider':'tart-macos'},result)
                route=guidance.next_action('vm_workflow','readiness-lease-status',value)
                self.assertEqual(route['kind'],'observe_original')
                self.assertEqual(route['action']['args']['inputs']['operationId'],operation)
                for changed in ({'reason':'correlated_terminal'},{'reason':'original_owner_missing'},
                                {'jobState':'unknown'},{'nextAction':'resolve_blocker'}):
                    self.assertFalse(executor.normalize({**native,**changed},operation)['ok'])
            finally:
                gate.write_text('release');end=time.monotonic()+5
                while jobs.observe(root,operation,binding,generation=generation)['state']!='terminal'and time.monotonic()<end:time.sleep(.01)
                self.assertEqual(jobs.observe(root,operation,binding,generation=generation)['state'],'terminal')

    def test_authentic_native_shapes_require_structural_proof_before_ok_or_follow(self):
        replies=json.loads((FIXTURES/'macos_lease_native_replies.json').read_text())['replies']
        for name,value in replies.items():
            with self.subTest(state=name):
                result=executor.normalize(value,OPERATION)
                wrapped=facade._external_result({'fixtureId':'controlled-mac','operationId':OPERATION,'provider':'tart-macos'},result)
                route=guidance.next_action('vm_workflow','readiness-lease-status',wrapped)
                self.assertEqual(route['kind'],'complete'if name=='expired'else'observe_original')
                if name!='expired':self.assertEqual(route['action']['args']['inputs']['operationId'],OPERATION)
        base=replies['active']
        for changes in ({'schemaVersion':True},{'provider':'foreign'},{'jobState':'invented'},{'jobState':[]},
                        {'state':[]},{'nextAction':{}},
                        {'reason':'PRIVATE unexpected text'},{'restored':None},{'privateInput':'NEVER-ECHO'}):
            with self.subTest(changes=changes),self.assertRaisesRegex(executor.mac.MacBlocked,'^macos_original_lease_reply_invalid$')as error:
                executor.normalize({**base,**changes},OPERATION)
            self.assertNotIn('PRIVATE',str(error.exception));self.assertNotIn('NEVER-ECHO',str(error.exception))
        for changes in ({'state':'unknown','reason':'correlated_terminal'}, {'jobState':'terminal'}, {'nextAction':'none'}):
            result=executor.normalize({**base,**changes},OPERATION)
            self.assertFalse(result['ok'])

    async def sdk_scenario(self,before):
        from mcp import ClientSession,StdioServerParameters
        from mcp.client.stdio import stdio_client
        environment={key:value for key,value in os.environ.items()if not key.startswith('DYLD_')}
        parameters=StdioServerParameters(command=sys.executable,args=['-B','-c',SERVER,str(ROOT),'before'if before else'current'],cwd=ROOT,env=environment)
        calls=[]
        with tempfile.TemporaryFile(mode='w+',encoding='utf-8')as errors:
            async with stdio_client(parameters,errlog=errors)as streams:
                async with ClientSession(*streams,read_timeout_seconds=timedelta(seconds=10))as session:
                    await session.initialize()
                    payload={'action':'readiness-lease-acquire','inputs':{'fixtureId':'controlled-mac','operationId':OPERATION}}
                    while len(calls)<4:
                        calls.append(payload['action'])
                        reply=await session.call_tool('vm_workflow',payload)
                        result=reply.structuredContent
                        if result is None:result=json.loads(next(block.text for block in reply.content if block.type=='text'))
                        route=result['nextAction']
                        if route['kind']!='observe_original':return calls,route
                        self.assertEqual(route['action']['tool'],'vm_workflow')
                        self.assertEqual(route['action']['action'],'readiness-lease-status')
                        self.assertEqual(route['action']['args']['inputs'],payload['inputs'])
                        payload={'action':route['action']['action'],**route['action']['args']}
                    self.fail('typed original observation failed to terminate')

    def test_whole_before_stalls_fresh_mcp_client_current_follows_same_original_to_complete(self):
        calls,route=asyncio.run(self.sdk_scenario(True))
        self.assertEqual(calls,['readiness-lease-acquire']);self.assertEqual(route['kind'],'resolve_blocker')
        calls,route=asyncio.run(self.sdk_scenario(False))
        self.assertEqual(calls,['readiness-lease-acquire','readiness-lease-status','readiness-lease-status'])
        self.assertEqual(route['kind'],'complete')


if __name__=='__main__':unittest.main()
