"""Actual SDK ClientSession context with local inert streams; no server/toolcall."""
import argparse,asyncio,contextlib,hashlib,io,json,os,tempfile,unittest,uuid
from pathlib import Path
from unittest import mock
try:
 import anyio
 from mcp import types
 from agent_tools import ssh_keeper_mcp_client as client
except ImportError:
 anyio=None;client=None
from agent_tools.ssh_keeper_mcp_delivery import FrameObserver
@contextlib.asynccontextmanager
async def inert_stdio(*args,**kwargs):
 a,b=anyio.create_memory_object_stream(0);c,d=anyio.create_memory_object_stream(0)
 try:yield b,c
 finally:
  for stream in (a,b,c,d):await stream.aclose()
@unittest.skipIf(anyio is None,'MCP SDK unavailable; install agent_tools/requirements-mcp.txt')
class DispositionTests(unittest.TestCase):
 def setUp(self):
  # Actual client.save journals require these flags and I/O operations. SDK
  # accounting uses that real writer; unavailable storage is an honest skip.
  flags=('O_WRONLY','O_CREAT','O_EXCL','O_NOFOLLOW')
  operations=('open','write','fsync','close','chmod')
  if any(type(getattr(os,name,None))is not int for name in flags) or any(not callable(getattr(os,name,None)) for name in operations):self.skipTest('OS lacks required client output journal capabilities')
 def run_case(self,phase):
  with tempfile.TemporaryDirectory(prefix='mcp-disposition-') as tmp:
   root=Path(tmp).resolve();(root/'agent_tools').mkdir();body=b'# inert declared public source\n';(root/'agent_tools/mcp_server.py').write_bytes(body)
   args=argparse.Namespace(server_sha256=hashlib.sha256(body).hexdigest(),identity=json.dumps({'correlationId':str(uuid.uuid4()),'receiptSha256':'a'*64,'sourceManifestSha256':'b'*64}),action='connection-channel-keep',session='own-failed-session',output_root=root)
   init=mock.AsyncMock(side_effect=ValueError('inert_initialize_refusal')) if phase=='initialize' else mock.AsyncMock(return_value=types.InitializeResult(protocolVersion='2025-11-25',capabilities=types.ServerCapabilities(),serverInfo=types.Implementation(name='inert_fixture',version='1')))
   listing=mock.AsyncMock(side_effect=ValueError('inert_list_refusal'));call=mock.AsyncMock(side_effect=AssertionError('no tools/call allowed'))
   with mock.patch.object(client,'ROOT',root),mock.patch.object(client,'stdio_client',inert_stdio),mock.patch.object(client.ClientSession,'initialize',init),mock.patch.object(client.ClientSession,'list_tools',listing),mock.patch.object(client.ClientSession,'call_tool',call),contextlib.redirect_stdout(io.StringIO()):rc=asyncio.run(client.main(args))
   self.assertEqual(1,rc);self.assertEqual(0,call.await_count);value=json.loads((root/'own-failed-session/client-result.json').read_bytes());self.assertEqual('unknown',value['state']);self.assertIs(value.get('effectfulCallSent'),None);self.assertIs(value['requestPlanned'],True);self.assertIs(value['sdkCallAttempted'],False);self.assertIs(value['relayToolCallFrameObserved'],None);self.assertIs(value['relayToolCallFrameFullyForwarded'],None);self.assertIs(value['serverExecutionProven'],False);return value
 def test_initialize_refusal_with_planned_request_never_claims_sent(self):self.run_case('initialize')
 def test_list_refusal_with_planned_request_never_claims_sent(self):self.run_case('list')
class ForwardingTests(unittest.TestCase):
 def observer(self):return FrameObserver()
 def test_complete_tools_frame_is_forwarding_only(self):
  obj=self.observer();data=b'{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"ssh_workflow"}}\n';events=obj.add(data,len(data));self.assertEqual(1,len(events));self.assertIs(events[0]['fullyForwarded'],True);self.assertIs(events[0]['serverExecutionProven'],False)
 def test_fragmented_frame_and_partial_delivery_remain_distinct(self):
  obj=self.observer();first=b'{"method":"tools/';second=b'call"}\n';self.assertEqual([],obj.add(first,len(first)));events=obj.add(second,0);self.assertEqual(1,len(events));self.assertIs(events[0]['fullyForwarded'],False);self.assertEqual(0,obj.summary()['fullyForwardedToolCallFrameCount']);self.assertIs(obj.summary()['serverExecutionProven'],False)
 def test_initialization_list_frames_are_not_tools_call(self):
  obj=self.observer();data=b'{"method":"initialize"}\n{"method":"notifications/initialized"}\n{"method":"tools/list"}\n';self.assertEqual([],obj.add(data,len(data)));self.assertEqual(0,obj.summary()['toolCallFrameCount'])
if __name__=='__main__':unittest.main(verbosity=2)
