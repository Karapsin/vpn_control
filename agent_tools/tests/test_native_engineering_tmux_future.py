"""Future reviewed frozen producer: genuine inherited admission, inert effects."""
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from agent_tools.tests import test_native_execution_context as fixture

_DRIVER = r'''
import hashlib,json,os,sys,subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
source=Path(sys.argv[1]);root=Path(sys.argv[2]);request=json.loads(sys.argv[3]);artifact=sys.argv[4]
sys.path.insert(0,str(source))
from agent_tools import linux_package_fixture_build as build
from agent_tools import native_execution_context as context
from agent_tools import ssh_tmux_resource_admission as resource
from agent_tools import ssh_tmux_session_ssh as old
from agent_tools import ssh_tmux_mcp_adapter as adapter
from agent_tools import ssh_transport
admitted=context.EngineeringExecutionContext.qualify(root,source,request,(artifact,))
driver=resource.ResourceDriver(root,source_root=source,engineering_context=admitted)
assert Path(build.__file__).is_relative_to(source) and Path(resource.__file__).is_relative_to(source)
tools=driver._tools();assert tools['linux_package_fixture_build.py']['pin']['sha256']==old.BUILD_SHA
calls=[]
def pin(number):return {'generation':[1,number,33152,os.getuid(),os.getgid(),1,1,1,1],'sha256':'a'*64}
# This test replaces the transport boundary, while the production adapter keeps
# its actual intent reader and source-bound equality checks. Supply its current
# public record shape using real, harmless private files and a public host pin.
route=root/'.rag_index/engineering-transport-fixture';route.mkdir(mode=0o700)
config=route/'inventory.json';key=route/'identity';known=route/'known-hosts'
for path,body in ((config,b'{}'),(key,b'local noncredential test fixture'),(known,b'public test host key')):
 path.write_bytes(body);path.chmod(0o600)
def fixed_transport():
 value={'version':2,'purpose':'mcp-tmux-private-transport-v2','host':'archlinux',
        'publicRouteSha256':hashlib.sha256(b'fixed public engineering transport fixture').hexdigest(),
        'privateFiles':{str(path):adapter._private_metadata(path) for path in (config,key)},
        'publicFiles':{str(known):old.blob(known)[1]},
        'privateCustodySourceSha256':ssh_transport._automatic_module()._PRIVATE_CONFIG_SHA}
 assert adapter._valid_transport(value)
 return None,value
def fixed_effect(program,payload,*,job=None,guard=None):
 if guard:guard()
 calls.append('availability' if program==old._AVAILABILITY else 'stage' if program==old._STAGE else payload['action'])
 if program==old._AVAILABILITY:return {'available':True,'reason':'available','nativeActionAllowed':False}
 if program==old._STAGE:return {'state':'staged','correlationId':request['correlationId'],'stagePin':pin(1)}
 action=payload['action']
 if action=='prepare':return {'state':'prepared','correlationId':request['correlationId'],'anchorPin':pin(2),'replayAllowed':False,'artifactVerification':'required'}
 if action=='release':return {'state':'released','correlationId':request['correlationId'],'replayAllowed':False,'artifactVerification':'required'}
 return {'state':'running','correlationId':request['correlationId'],'replayAllowed':False,'artifactVerification':'required'}
with patch.object(ssh_transport,'load_config',return_value=SimpleNamespace(hosts={'archlinux':object()})),patch.object(driver,'_transport',side_effect=fixed_transport),patch.object(driver,'_query',side_effect=fixed_effect):
 proof=driver.preflight(request);assert proof['state']=='ready' and not proof['finalAcceptance']
 result=build.start(root,request,source_root=source,engineering_context=admitted,driver=driver,admission=lambda unused,req:driver.preflight(req))
 assert result['state']=='submitted',result
 initial=list(calls)
 # Later unrelated tooling checkpoint changes only the live admission reference.
 path=root/'agent_tools/check_output_retention.py';path.write_text('check_only = 3\n')
 for args in (('add','agent_tools/check_output_retention.py'),('commit','-m','later tooling while same original runs'),('push','origin','dev')):
  subprocess.run(['git','-C',str(root),*args],capture_output=True,check=True)
 observed=build.status(root,{'correlationId':request['correlationId']},driver=driver)
 assert observed['state']=='running' and observed['sourceSha']==request['sourceSha']
 before=len(calls)
 try:driver.release(request)
 except context.ExecutionContextError as error:assert str(error)=='native_target_ref_changed'
 else:raise AssertionError('Mutation after admission reference advance')
 assert len(calls)==before
 duplicate=build.start(root,request,source_root=source,engineering_context=admitted,driver=driver)
 assert duplicate['state']=='unknown' and not duplicate['replayAllowed']
 assert calls.count('stage')==calls.count('prepare')==calls.count('release')==1
print(json.dumps({'initialCalls':initial,'calls':calls,'coordinatorStorage':True,'producerFrozen':True,'historicalReadOnly':True,'mutationAfterRefAdvance':False,'sourceSha':request['sourceSha'],'finalAcceptance':False}))
'''

@unittest.skipUnless(os.name=='posix','Local frozen producer private journals')
class FutureFrozenTmuxTest(unittest.TestCase):
    setUp=fixture.NativeExecutionContextTest.setUp
    git=fixture.NativeExecutionContextTest.git
    engineering=fixture.NativeExecutionContextTest.engineering
    def test_actual_loaded_frozen_resource_driver_preflight_submit_readonly_and_mutation_fences(self):
        artifact,_=self.engineering()
        child=subprocess.run([sys.executable,'-I','-B','-c',_DRIVER,str(self.native),str(self.coordinator),json.dumps(self.request),artifact['artifactId']],capture_output=True,text=True,timeout=60)
        self.assertEqual(0,child.returncode,child.stderr)
        proof=json.loads(child.stdout);self.assertTrue(proof['producerFrozen']);self.assertTrue(proof['coordinatorStorage'])
        self.assertEqual(['availability','availability','stage','prepare','release'],proof['initialCalls'])
        self.assertFalse(proof['finalAcceptance']);self.assertEqual(self.sha,proof['sourceSha'])
