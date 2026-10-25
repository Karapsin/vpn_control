"""Actual complete Proxy AST with owned loopback sockets only; no SSH/network target."""
from pathlib import Path
import ast,errno,hashlib,json,os,select,selectors,socket,struct,subprocess,sys,tempfile,threading,time,unittest
HERE=Path(__file__).resolve().parent

def load(name):
 raw=(HERE/name).read_bytes()
 assert hashlib.sha256(raw).hexdigest()=={'controller.a088.before.source':'a088df1dfcd24fdc836b16d8c5011cb61e26397bcfc3265630624e2814926e51','controller.5011.before.source':'5011866be6fb1b384f3af0ed0e0c8d053ddc0ea0aeae3478fb76436ab80b7d0f','controller.selector_candidate.source':'902f9713f7ea728b490a143729fbd4f9a768bcbaef7806b2d7b9a4b1e6c52767'}[name]
 node=next(n for n in ast.parse(raw).body if isinstance(n,ast.ClassDef)and n.name=='Proxy')
 def save(path,value):
  fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  with os.fdopen(fd,'w')as out:json.dump(value,out);out.flush();os.fsync(out.fileno())
 scope={'socket':socket,'select':select,'threading':threading,'selectors':selectors,'save':save}
 exec(compile(ast.Module(body=[node],type_ignores=[]),str(HERE/name),'exec'),scope)
 return scope['Proxy']

def wait(fn):
 end=time.monotonic()+3
 while time.monotonic()<end:
  v=fn()
  if v:return v
  time.sleep(.005)
 raise AssertionError('bounded controlled loopback observation timeout')

def receive(s,n):
 raw=b''
 while len(raw)<n:
  part=s.recv(n-len(raw))
  if not part:raise AssertionError('unexpected controlled loopback EOF')
  raw+=part
 return raw

class ProxyObservationTests(unittest.TestCase):
 def setUp(self):self.resources=[];self.proxies=[]
 def tearDown(self):
  for p in self.proxies:
   p.close_owned_route()
   self.assertFalse(p.thread.is_alive());self.assertTrue(all(not t.is_alive()for t in p.threads));self.assertEqual(-1,p.server.fileno())
   for pair in p.pairs:
    self.assertEqual(-1,pair['client'].fileno());self.assertEqual(-1,pair['upstream'].fileno())
  for s in self.resources:s.close()
 def linked(self,filename='controller.selector_candidate.source'):
  listener=socket.socket();self.resources.append(listener);listener.bind(('127.0.0.1',0));listener.listen();listener.settimeout(3)
  proxy=load(filename)('127.0.0.1',listener.getsockname()[1]);self.proxies.append(proxy)
  client=socket.create_connection(('127.0.0.1',proxy.port),timeout=3);self.resources.append(client)
  upstream,_=listener.accept();upstream.settimeout(3);self.resources.append(upstream);wait(lambda:proxy.pairs)
  return proxy,client,upstream
 def test_actual_old_forwarding_has_no_receipt_red_current_directional_metadata_green(self):
  for name,old in(('controller.a088.before.source',True),('controller.selector_candidate.source',False)):
   proxy,client,upstream=self.linked(name);a=b'fixed-public-client-canary';b=b'fixed-public-upstream-canary'
   client.sendall(a);self.assertEqual(a,receive(upstream,len(a)));upstream.sendall(b);self.assertEqual(b,receive(client,len(b)))
   if old:self.assertFalse(hasattr(proxy,'diagnostic_snapshot'))
   else:
    wait(lambda:proxy.diagnostic_snapshot()['attempts'][0]['upstreamToClientBytes']==len(b));v=proxy.diagnostic_snapshot();row=v['attempts'][0]
    self.assertEqual((len(a),len(b)),(row['clientReadBytes'],row['upstreamReadBytes']));self.assertEqual((len(a),len(b)),(row['clientToUpstreamBytes'],row['upstreamToClientBytes']));self.assertEqual('connected',row['connectPhase']);self.assertNotIn('canary',json.dumps(v));self.assertFalse(v['trafficRetained'])
 def test_upstream_reset_records_numeric_errno_phase_and_side_without_error_text(self):
  proxy,client,upstream=self.linked();upstream.setsockopt(socket.SOL_SOCKET,socket.SO_LINGER,struct.pack('ii',1,0));upstream.close()
  wait(lambda:proxy.diagnostic_snapshot()['attempts'][0]['closed']);row=proxy.diagnostic_snapshot()['attempts'][0]
  self.assertEqual(('read','upstream-to-client','os-error'),(row['forwardPhase'],row['direction'],row['forwardErrorClass']));self.assertIs(type(row['forwardErrno']),int);self.assertIn(row['forwardErrno'],(errno.ECONNRESET,errno.ECONNABORTED));self.assertNotIn('exception',json.dumps(row).lower())
 def test_eof_records_direction_and_closed_pair(self):
  proxy,client,upstream=self.linked();client.shutdown(socket.SHUT_WR);wait(lambda:proxy.diagnostic_snapshot()['attempts'][0]['closed']);row=proxy.diagnostic_snapshot()['attempts'][0]
  self.assertEqual(('eof','client-to-upstream',None),(row['forwardPhase'],row['eofDirection'],row['forwardErrno']));self.assertEqual(b'',upstream.recv(1))
 def test_exact_owned_drop_once_receipt_and_no_live_pair_replay(self):
  proxy,client,upstream=self.linked()
  with tempfile.TemporaryDirectory()as temporary:
   path=Path(temporary)/'drop.json';master={'recoveryId':'controlled-original','child':{'actor':{'pid':1,'birth':'fixed-public-model'}},'socketPath':'/fixed/public-control'}
   proxy.drop_once(path,master);wait(lambda:proxy.diagnostic_snapshot()['attempts'][0]['closed']);value=json.loads(path.read_bytes());self.assertEqual(1,value['faultCount']);self.assertFalse(value['remoteJobSignalAllowed'])
   with self.assertRaisesRegex(ValueError,'private_proxy_original_pair_unresolved'):proxy.drop_once(Path(temporary)/'forbidden.json',master)
   self.assertFalse((Path(temporary)/'forbidden.json').exists())
 def test_cancellation_closes_all_exact_owned_threads_and_fds(self):
  proxy,client,upstream=self.linked();proxy.close_owned_route();value=proxy.diagnostic_snapshot()
  self.assertTrue(value['stopped']);self.assertTrue(value['listenerClosed']);self.assertTrue(value['acceptThreadClosed']);self.assertEqual(0,value['liveForwardThreadCount']);self.assertTrue(all(r['closed']for r in value['attempts']))
 def test_refused_upstream_records_connect_errno_without_forwarding(self):
  listener=socket.socket();listener.bind(('127.0.0.1',0));port=listener.getsockname()[1];listener.close()
  proxy=load('controller.selector_candidate.source')('127.0.0.1',port);self.proxies.append(proxy);client=socket.create_connection(('127.0.0.1',proxy.port),timeout=3);self.resources.append(client)
  wait(lambda:proxy.diagnostic_snapshot()['attempts']and proxy.diagnostic_snapshot()['attempts'][0]['closed']);row=proxy.diagnostic_snapshot()['attempts'][0]
  self.assertEqual(('failed','not-started'),(row['connectPhase'],row['forwardPhase']));self.assertEqual(errno.ECONNREFUSED,row['connectErrno']);self.assertEqual([],proxy.pairs)
 def test_receipt_list_is_bounded_without_altering_forwarding_control_list(self):
  proxy=load('controller.selector_candidate.source')('127.0.0.1',1);self.proxies.append(proxy)
  for _ in range(40):proxy._attempt()
  value=proxy.diagnostic_snapshot();self.assertEqual(40,value['attemptCount']);self.assertEqual(32,len(value['attempts']));self.assertTrue(value['capped']);self.assertEqual([],proxy.pairs)


def high_descriptor_control():
 import resource
 from types import SimpleNamespace
 holders=[];resources=[];proxies=[];select_inputs=[];selector_states=[]
 limit=resource.getrlimit(resource.RLIMIT_NOFILE)
 if limit[0]<1500:resource.setrlimit(resource.RLIMIT_NOFILE,(1500 if limit[1]==resource.RLIM_INFINITY else min(1500,limit[1]),limit[1]))
 try:
  while not holders or holders[-1]<1150:holders.append(os.open(os.devnull,os.O_RDONLY))
  results={}
  for filename,old in(('controller.5011.before.source',True),('controller.selector_candidate.source',False)):
   source=(HERE/filename).read_bytes()
   assert hashlib.sha256(source).hexdigest()==('5011866be6fb1b384f3af0ed0e0c8d053ddc0ea0aeae3478fb76436ab80b7d0f'if old else'902f9713f7ea728b490a143729fbd4f9a768bcbaef7806b2d7b9a4b1e6c52767')
   node=next(n for n in ast.parse(source).body if isinstance(n,ast.ClassDef)and n.name=='Proxy')
   def actual_select(readers,writers,errors,timeout):
    select_inputs.append([s.fileno()for s in readers])
    return select.select(readers,writers,errors,timeout)
   class ActualSelector:
    def __init__(self):
     self.real=selectors.DefaultSelector();self.fd=self.real.fileno()if hasattr(self.real,'fileno')else None;self.state={'closed':False,'kernelFdAbsent':None,'backend':type(self.real).__name__};selector_states.append(self.state)
    def register(self,*a,**k):return self.real.register(*a,**k)
    def select(self,*a,**k):return self.real.select(*a,**k)
    def close(self):
     self.real.close();self.state['closed']=True
     if self.fd is not None:
      try:os.fstat(self.fd)
      except OSError as error:self.state['kernelFdAbsent']=error.errno==errno.EBADF
      else:self.state['kernelFdAbsent']=False
   ns={'socket':socket,'select':SimpleNamespace(select=actual_select),'selectors':SimpleNamespace(DefaultSelector=ActualSelector,EVENT_READ=selectors.EVENT_READ),'threading':threading,'save':lambda *a:None}
   exec(compile(ast.Module(body=[node],type_ignores=[]),str(HERE/filename),'exec'),ns)
   listener=socket.socket();resources.append(listener);listener.bind(('127.0.0.1',0));listener.listen();listener.settimeout(3)
   proxy=ns['Proxy']('127.0.0.1',listener.getsockname()[1]);proxies.append(proxy)
   client=socket.create_connection(('127.0.0.1',proxy.port),timeout=3);resources.append(client)
   public=b'fixed-public-high-fd-client'
   send_failed=False
   try:client.sendall(public)
   except OSError:send_failed=True
   upstream,_=listener.accept();upstream.settimeout(3);resources.append(upstream);wait(lambda:proxy.pairs)
   assert min(listener.fileno(),proxy.server.fileno(),client.fileno(),upstream.fileno())>=1024
   if old:
    wait(lambda:proxy.diagnostic_snapshot()['attempts'][0]['closed']);row=proxy.diagnostic_snapshot()['attempts'][0]
    assert(row['forwardPhase'],row['forwardErrorClass'],row['clientReads'],row['upstreamReads'])==('select','value-error',0,0)
    assert row['clientToUpstreamBytes']==row['upstreamToClientBytes']==0
    assert select_inputs and min(select_inputs[-1])>=1024
    results['before']={'failedAtSelect':True,'valueError':True,'inputDescriptors':select_inputs[-1],'readBytes':0,'sourceComplete':True}
   else:
    assert not send_failed and receive(upstream,len(public))==public
    response=b'fixed-public-high-fd-upstream';upstream.sendall(response);assert receive(client,len(response))==response
    wait(lambda:proxy.diagnostic_snapshot()['attempts'][0]['upstreamToClientBytes']==len(response))
    row=proxy.diagnostic_snapshot()['attempts'][0];assert(row['clientReadBytes'],row['upstreamReadBytes'])==(len(public),len(response));assert row['forwardErrno']is None and row['forwardErrorClass']is None
    client.shutdown(socket.SHUT_WR);wait(lambda:proxy.diagnostic_snapshot()['attempts'][0]['closed']);assert proxy.diagnostic_snapshot()['attempts'][0]['eofDirection']=='client-to-upstream'
    results['fixed']={'bidirectional':True,'halfClosePreserved':True,'clientBytes':len(public),'upstreamBytes':len(response),'sourceComplete':True}
   proxy.close_owned_route();assert not proxy.thread.is_alive()and all(not t.is_alive()for t in proxy.threads)
   assert proxy.server.fileno()==-1 and all(pair['client'].fileno()==pair['upstream'].fileno()==-1 for pair in proxy.pairs)
  assert len(selector_states)==1 and all(v['closed']and v['kernelFdAbsent']is True for v in selector_states)
  results['allOwnedThreadsSocketsSelectorsClosed']=True;results['actualSelectorBackend']=selector_states[0]['backend'];results['externalNetworkCalls']=0
  return results
 finally:
  for proxy in proxies:proxy.close_owned_route()
  for s in resources:s.close()
  for fd in reversed(holders):os.close(fd)

class HighDescriptorTests(unittest.TestCase):
 @unittest.skipUnless(os.name=='posix','high descriptor POSIX proxy qualification')
 def test_actual_complete_before_select_high_fd_red_default_selector_green_and_all_closed(self):
  import resource
  if resource.getrlimit(resource.RLIMIT_NOFILE)[1]!=resource.RLIM_INFINITY and resource.getrlimit(resource.RLIMIT_NOFILE)[1]<1500:self.skipTest('isolated child cannot safely acquire1500 descriptor budget')
  result=subprocess.run([sys.executable,'-I','-B',str(HERE/'test_proxy_high_descriptors.py'),'--high-fd-case'],stdin=subprocess.DEVNULL,capture_output=True,timeout=12)
  self.assertEqual((0,b''),(result.returncode,result.stderr));value=json.loads(result.stdout)
  self.assertTrue(value['before']['valueError']);self.assertTrue(value['fixed']['bidirectional']);self.assertTrue(value['fixed']['halfClosePreserved']);self.assertTrue(value['allOwnedThreadsSocketsSelectorsClosed']);self.assertEqual(0,value['externalNetworkCalls'])

if __name__=='__main__':
 if sys.argv[1:]==['--high-fd-case']:print(json.dumps(high_descriptor_control(),sort_keys=True))
 else:unittest.main()
