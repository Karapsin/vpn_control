"""Actual qualified Proxy + complete finish method; all sockets/files owned local."""
from pathlib import Path
from contextlib import contextmanager
import ast,copy,hashlib,json,os,selectors,socket,stat,subprocess,sys,tempfile,threading,time,unittest
F=Path(__file__).resolve().parent/'fixtures'/'ssh_acceptance_controller_cleanup'
PINS={'call-intent-00000000.json': '15ce8dc8fad27daf4d6c6f3f99a782c8642be124f6c53d3d130933919b689ad8', 'call-result-00000000.json': '04904be424c24ca7ed61be1c7aae156e5ce12f5f82c767aafe8fd4736ee549c7', 'client-intent.json': 'e06b721c622923547aabf59e945dfba221721cd915e1dfa7fe2aadc460b2281d', 'client-result.json': '11cd804bca609b67f46fc9e6a7371b9d395ce7c5761634775c591064a7bd8c9a', 'controller.before.source': '9dd62085a257562c162685086bfd637c3788628a723a63c17fe845d9dba96032', 'controller.fixed.source': '309dd35f968916ade2b3a255944d1c84f6bc3713b34800b3cb497ad76455f978', 'readback.before.source': 'ba345e927f5031ddbf6e60c8009b5ca99b6521d9cc33e009d031983bc55b5f00', 'readback.fixed.source': '5a4e9fe02934e199b9dbbc7e7a1b45c4a683683c2ca96ffb35ae7decb2b7cf77', 'readback-join-data.json': '7e3d5b2028e07aaf6255bb622855faf765fa876facb8e74b84dd736161aeadca'}
def raw(name):
 value=(F/name).read_bytes();assert hashlib.sha256(value).hexdigest()==PINS[name];return value

def definitions(fixed):
 tree=ast.parse(raw('controller.fixed.source'if fixed else'controller.before.source'));names={'fingerprint','save','read','SourceHold','Proxy','finish_local_scope','exact_normal_sdk_status'}
 selected=[n for n in tree.body if isinstance(n,(ast.FunctionDef,ast.ClassDef))and n.name in names];assert len(selected)==len(names)
 ns={k:v for k,v in globals().items()if k in('Path','hashlib','json','os','selectors','socket','stat','subprocess','sys','threading','time')}
 exec(compile(ast.Module(body=selected,type_ignores=[]),'authenticated-complete-owned-proxy-and-finish','exec'),ns);return ns

@contextmanager
def actual_case(fixed):
 ns=definitions(fixed)
 with tempfile.TemporaryDirectory(prefix='actual-proxy-cleanup-')as td:
  root=Path(td);source=root/'held-public.source';source.write_bytes(b'public fixture source\n');held=ns['SourceHold'](source);listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen();listener.settimeout(3)
  proxy=ns['Proxy'](*listener.getsockname());client=socket.create_connection(('127.0.0.1',proxy.port),timeout=3);peer,_=listener.accept();peer.settimeout(3)
  client.sendall(b'controlled-forward');assert peer.recv(64)==b'controlled-forward';peer.sendall(b'controlled-return');assert client.recv(64)==b'controlled-return'
  scope={'operation':'public-original-fixture','holders':[held],'guard':held.guard,'proxy':proxy,'clients':[]}
  try:yield ns,root,source,held,proxy,scope
  finally:
   proxy.close_owned_route();client.close();peer.close();listener.close()
   try:held.close()
   except OSError:pass
   assert proxy.server.fileno()==-1 and not proxy.thread.is_alive()and all(not t.is_alive()for t in proxy.threads)

def assert_closed(test,held,proxy):
 with test.assertRaises(OSError):os.fstat(held.fd)
 test.assertEqual(proxy.server.fileno(),-1);test.assertFalse(proxy.thread.is_alive());test.assertTrue(all(not t.is_alive()for t in proxy.threads));test.assertTrue(all(p['client'].fileno()==p['upstream'].fileno()==-1 for p in proxy.pairs))

@unittest.skipUnless(os.name=='posix'and hasattr(os,'O_NOFOLLOW')and hasattr(os,'getuid'),'requires owned POSIX filesystem/socket custody')
class ActualProxyCleanupTests(unittest.TestCase):
 def test_actual_native_before_red_and_actual_class_fixed_green(self):
  with actual_case(False)as(ns,root,source,held,proxy,scope):
   with self.assertRaisesRegex(AttributeError,'diagnostics'):ns['finish_local_scope'](root,scope)
   self.assertFalse((root/'final-closure.json').exists());os.fstat(held.fd)
   self.assertEqual(proxy.server.fileno(),-1)
  with actual_case(True)as(ns,root,source,held,proxy,scope):
   ns['finish_local_scope'](root,scope);assert_closed(self,held,proxy);v=json.loads((root/'final-closure.json').read_bytes());self.assertTrue(v['allParentDescriptorsClosed']);self.assertTrue(v['sourceClosing']);self.assertFalse(v['proxy']['diagnostics']['trafficRetained']);self.assertEqual(v['proxy']['diagnostics']['clientToUpstreamBytes']if'clientToUpstreamBytes'in v['proxy']['diagnostics']else v['proxy']['diagnostics']['attempts'][0]['clientToUpstreamBytes'],18)
 def test_actual_proxy_serialization_failure_still_seals_and_closes(self):
  with actual_case(True)as(ns,root,source,held,proxy,scope):
   # Corrupt only public diagnostic metadata on the actual class instance;
   # its real snapshot method, sockets, threads and finish function all run.
   with proxy.lock:proxy.attempts[0]['forwardErrorClass']=object()
   ns['finish_local_scope'](root,scope);assert_closed(self,held,proxy);v=json.loads((root/'final-closure.json').read_bytes());self.assertTrue(v['proxy']['diagnosticsUnavailable']);self.assertTrue(v['allParentDescriptorsClosed']);self.assertTrue(v['sourceClosing']);self.assertNotIn('diagnostics',v['proxy'])
 def test_source_guard_refusal_still_closes_actual_descriptors(self):
  with actual_case(True)as(ns,root,source,held,proxy,scope):
   source.write_bytes(b'changed real held source\n');ns['finish_local_scope'](root,scope);assert_closed(self,held,proxy);v=json.loads((root/'final-closure.json').read_bytes());self.assertFalse(v['sourceClosing']);self.assertTrue(v['allParentDescriptorsClosed'])
 def test_observation_failure_still_closes_actual_route_and_held_files(self):
  with actual_case(True)as(ns,root,source,held,proxy,scope):
   scope['clients']=[(None,)];ns['finish_local_scope'](root,scope);assert_closed(self,held,proxy);v=json.loads((root/'final-closure.json').read_bytes());self.assertTrue(v['observationIncomplete']);self.assertEqual(v['proxy']['state'],'closed-after-observation-failure');self.assertTrue(v['allParentDescriptorsClosed'])
 def records(self):return {name:json.loads(raw(name))for name in('client-intent.json','call-intent-00000000.json','call-result-00000000.json','client-result.json')}
 def test_actual_sdk_first_call_index_red_green(self):
  records=self.records();client=records['client-intent.json'];op=records['call-intent-00000000.json']['operationId'];host=client['request']['host'];args=(records,op,host,client['serverSha256'],client['clientPid'])
  with self.assertRaisesRegex(ValueError,'fresh_status_original_request_changed'):definitions(False)['exact_normal_sdk_status'](*args)
  value=definitions(True)['exact_normal_sdk_status'](*args);self.assertEqual(value,records['call-result-00000000.json']['structuredContent']);self.assertEqual(records['call-intent-00000000.json']['relayAttempt'],0)
 def test_schema_identity_privacy_and_terminal_fences_remain(self):
  base=self.records();client=base['client-intent.json'];op=base['call-intent-00000000.json']['operationId'];host=client['request']['host'];fn=definitions(True)['exact_normal_sdk_status']
  for record,key,value in [('call-intent-00000000.json','relayAttempt',1),('call-intent-00000000.json','automaticReplay',True),('call-intent-00000000.json','operationId','00000000-0000-4000-8000-000000000000'),('client-intent.json','serverSha256','0'*64),('client-intent.json','clientPid',client['clientPid']+1),('client-result.json','allRelayAttemptsClosed',False),('client-result.json','attemptedToolCalls',2),('call-result-00000000.json','isError',True)]:
   with self.subTest(record=record,key=key):
    records=copy.deepcopy(base);records[record][key]=value
    with self.assertRaises(ValueError):fn(records,op,host,client['serverSha256'],client['clientPid'])
 def test_proxy_ast_unchanged_and_only_validator_finish_changed(self):
  trees=[ast.parse(raw(name))for name in('controller.before.source','controller.fixed.source')]
  for tree in trees:tree.body=[n for n in tree.body if not(isinstance(n,ast.FunctionDef)and n.name in('finish_local_scope','exact_normal_sdk_status'))]
  self.assertEqual(ast.dump(trees[0],include_attributes=False),ast.dump(trees[1],include_attributes=False))
 def test_provenance_authenticates_every_input(self):
  self.assertEqual(json.loads((F/'provenance.json').read_bytes())['pins'],PINS)
  for name in PINS:raw(name)

class ReadbackCanonicalJoinTests(unittest.TestCase):
 def data(self):return json.loads(raw('readback-join-data.json'))
 def check(self,fixed,data):
  tree=ast.parse(raw('readback.fixed.source'if fixed else'readback.before.source'))
  nodes=[n for n in ast.walk(tree)if isinstance(n,ast.Assert)and ("packet['requestSha256']"in ast.unparse(n.test)or "intent['requestSha256']"in ast.unparse(n.test))]
  self.assertEqual(len(nodes),2 if fixed else 1)
  namespace={**data,'sha':lambda value:hashlib.sha256(value).hexdigest(),'json':json}
  exec(compile(ast.Module(body=nodes,type_ignores=[]),'authenticated-readback-pretransport-assertions','exec'),namespace)
 def test_actual_program_vs_envelope_digest_before_red_fixed_green(self):
  data=self.data();self.assertNotEqual(data['packet']['requestSha256'],data['intent']['requestSha256'])
  with self.assertRaises(AssertionError):self.check(False,data)
  self.check(True,data)
 def test_program_envelope_and_owner_digest_drift_each_block(self):
  for target,key in(('packet','requestSha256'),('intent','requestSha256'),('packet','ownerSourceSha256')):
   with self.subTest(target=target,key=key):
    data=self.data();data[target][key]='0'*64
    with self.assertRaises(AssertionError):self.check(True,data)

if __name__=='__main__':unittest.main()
