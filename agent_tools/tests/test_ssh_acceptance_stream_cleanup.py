"""Real local descriptors/children exercise whole preserved closure functions."""
from pathlib import Path
from contextlib import contextmanager
import ast,hashlib,json,os,selectors,socket,stat,subprocess,sys,tempfile,threading,time,unittest
F=Path(__file__).resolve().parent/'fixtures'/'ssh_acceptance_stream_cleanup'
PINS={'controller.before.source':'237efd148d0d41055c28f1472250d3324bc5165b22568456c8fe52d7a2bd1757','controller.fixed.source':'aabda457980c81a2578adba9c29711d9c8644c7ed29b7af1d9a40bf1678940bb'}
def raw(name):
 body=(F/name).read_bytes();assert hashlib.sha256(body).hexdigest()==PINS[name];return body

def definitions(fixed):
 tree=ast.parse(raw('controller.fixed.source'if fixed else'controller.before.source'));names={'fingerprint','SourceHold','Proxy','save','read','finish_local_scope'};nodes=[n for n in tree.body if isinstance(n,(ast.FunctionDef,ast.ClassDef))and n.name in names];assert len(nodes)==len(names)
 namespace={k:v for k,v in globals().items()if k in('Path','hashlib','json','os','selectors','socket','stat','subprocess','sys','threading','time')};exec(compile(ast.Module(body=nodes,type_ignores=[]),'authenticated-complete-closure','exec'),namespace);return namespace

@contextmanager
def owned(fixed,*,pipe=False,live=False,proxy=False):
 namespace=definitions(fixed)
 with tempfile.TemporaryDirectory(prefix='owned-parent-streams-')as td:
  root=Path(td);source=root/'held.source';source.write_bytes(b'public source\n');held=namespace['SourceHold'](source);read_end=None
  if pipe:read_end,write_end=os.pipe();out=os.fdopen(write_end,'wb')
  else:out=(root/'stdout.public').open('xb')
  err=(root/'stderr.public').open('xb');code='import sys;sys.stdin.buffer.read(1)'if live else'pass';p=subprocess.Popen([sys.executable,'-I','-B','-c',code],stdin=subprocess.PIPE if live else subprocess.DEVNULL,stdout=out,stderr=err)
  if not live:assert p.wait(timeout=3)==0
  actual_proxy=None;listener=client=peer=None
  if proxy:
   listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen();listener.settimeout(3);actual_proxy=namespace['Proxy'](*listener.getsockname());client=socket.create_connection(('127.0.0.1',actual_proxy.port),timeout=3);peer,_=listener.accept();peer.settimeout(3);client.sendall(b'public');assert peer.recv(16)==b'public';peer.sendall(b'return');assert client.recv(16)==b'return'
  scope={'operation':'owned-public-stream-test','clients':[(p,out,err,'fixed-public-client')],'holders':[held],'guard':held.guard,'proxy':actual_proxy}
  try:yield namespace,root,source,held,p,out,err,scope
  finally:
   if live and p.poll()is None:p.stdin.write(b'x');p.stdin.flush()
   if p.stdin is not None:p.stdin.close()
   p.wait(timeout=3)
   for stream in(out,err):
    try:stream.close()
    except OSError:pass
   try:held.close()
   except OSError:pass
   if read_end is not None:os.close(read_end)
   if actual_proxy is not None:
    actual_proxy.close_owned_route()
    for s in(client,peer,listener):s.close()
    assert not actual_proxy.thread.is_alive()and all(not t.is_alive()for t in actual_proxy.threads)

def finish(case):
 namespace,root,source,held,p,out,err,scope=case;namespace['finish_local_scope'](root,scope);return json.loads((root/'final-closure.json').read_bytes())

@unittest.skipUnless(os.name=='posix'and hasattr(os,'O_NOFOLLOW')and hasattr(os,'getuid'),'requires owned POSIX descriptors')
class OwnedStreamCleanupTests(unittest.TestCase):
 def test_real_buffered_file_flush_failure_before_red_current_green(self):
  for fixed in(False,True):
   with self.subTest(fixed=fixed),owned(fixed)as case:
    out,err=case[5:7];out.write(b'buffered public bytes');os.close(out.fileno());v=finish(case)
    if not fixed:
     self.assertTrue(v['allParentDescriptorsClosed']);self.assertFalse(err.closed);os.fstat(err.fileno())
    else:
     self.assertTrue(err.closed);self.assertTrue(v['clientStreams'][0]['streams']['stdout']['flushFailed']);self.assertEqual(v['allParentDescriptorsClosed'],out.closed and err.closed)
 def test_actual_pipe_fsync_refusal_before_red_current_green(self):
  for fixed in(False,True):
   with self.subTest(fixed=fixed),owned(fixed,pipe=True)as case:
    out,err=case[5:7];v=finish(case)
    if not fixed:self.assertTrue(v['allParentDescriptorsClosed']);self.assertFalse(out.closed);self.assertFalse(err.closed);os.fstat(err.fileno())
    else:
     self.assertTrue(out.closed and err.closed);self.assertTrue(v['allParentDescriptorsClosed']);self.assertTrue(v['clientStreams'][0]['streams']['stdout']['fsyncFailed']);self.assertFalse(v['clientStreams'][0]['streams']['stdout']['flushFailed'])
 def test_actual_live_client_not_signalled_but_parent_streams_closed(self):
  with owned(True,live=True)as case:
   p=case[4];self.assertIsNone(p.poll());v=finish(case);self.assertEqual(v['clients'][0]['state'],'live-original-unknown');self.assertIsNone(p.poll());self.assertTrue(case[5].closed and case[6].closed);self.assertTrue(v['allParentDescriptorsClosed']);self.assertFalse(v['remoteOwnerSignalled']or v['sharedMasterSignalled'])
 def test_terminal_and_preclosed_stream_states_preserved(self):
  with owned(True)as case:
   case[5].close();case[6].close();v=finish(case);self.assertEqual(v['clients'][0]['state'],'terminal-reaped');self.assertEqual(v['clients'][0]['returnCode'],0);self.assertTrue(v['allParentDescriptorsClosed']);self.assertTrue(v['clients'][0]['parentStreamsClosed'])
 def test_real_source_guard_failure_still_closes_streams_and_holder(self):
  with owned(True)as case:
   case[2].write_bytes(b'changed real source\n');v=finish(case);self.assertFalse(v['sourceClosing']);self.assertTrue(v['allParentDescriptorsClosed']);self.assertTrue(case[5].closed and case[6].closed)
   with self.assertRaises(OSError):os.fstat(case[3].fd)
 def test_partial_metadata_closes_known_stream_and_reports_visibility_blocker(self):
  with owned(True)as case:
   case[7]['clients']=[(case[4],case[5])];v=finish(case);self.assertTrue(case[5].closed);self.assertFalse(v['allParentDescriptorsClosed']);self.assertTrue(v['clientStreamsVisibilityIncomplete']);self.assertTrue(v['observationIncomplete'])
 def test_actual_qualified_proxy_composes_with_real_stream_fsync_failure(self):
  with owned(True,pipe=True,proxy=True)as case:
   v=finish(case);proxy=case[7]['proxy'];self.assertEqual(proxy.server.fileno(),-1);self.assertFalse(proxy.thread.is_alive());self.assertTrue(all(not t.is_alive()for t in proxy.threads));self.assertTrue(v['proxy']['diagnostics']['stopped']);self.assertFalse(v['proxy']['diagnostics']['trafficRetained']);self.assertTrue(v['allParentDescriptorsClosed'])
 def test_only_finish_ast_changes_and_all_fixtures_authenticated(self):
  trees=[ast.parse(raw(n))for n in('controller.before.source','controller.fixed.source')]
  for tree in trees:tree.body=[n for n in tree.body if not(isinstance(n,ast.FunctionDef)and n.name=='finish_local_scope')]
  self.assertEqual(ast.dump(trees[0],include_attributes=False),ast.dump(trees[1],include_attributes=False));self.assertEqual(json.loads((F/'provenance.json').read_bytes())['pins'],PINS)
if __name__=='__main__':unittest.main()
