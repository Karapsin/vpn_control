"""Actual complete Proxy AST with owned loopback sockets only; no SSH/network target."""
from pathlib import Path
import ast,errno,hashlib,json,os,select,selectors,socket,struct,subprocess,sys,tempfile,threading,time,unittest
HERE=Path(__file__).resolve().parent
# Current Proxy: drop_once leaves closing to the owning forward thread. The
# selector candidate is the complete unfixed beforeimage of that drop race.
CURRENT='controller.drop_observation_candidate.source'

def load(name,selector_module=selectors):
 raw=(HERE/name).read_bytes()
 assert hashlib.sha256(raw).hexdigest()=={'controller.a088.before.source':'a088df1dfcd24fdc836b16d8c5011cb61e26397bcfc3265630624e2814926e51','controller.5011.before.source':'5011866be6fb1b384f3af0ed0e0c8d053ddc0ea0aeae3478fb76436ab80b7d0f','controller.selector_candidate.source':'902f9713f7ea728b490a143729fbd4f9a768bcbaef7806b2d7b9a4b1e6c52767',CURRENT:'ca1dab8bc2f7dbab4f2910156705c4ab242bb13e99db986bd73f7da0da60cbc4'}[name]
 node=next(n for n in ast.parse(raw).body if isinstance(n,ast.ClassDef)and n.name=='Proxy')
 def save(path,value):
  fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  with os.fdopen(fd,'w')as out:json.dump(value,out);out.flush();os.fsync(out.fileno())
 scope={'socket':socket,'select':select,'threading':threading,'selectors':selector_module,'save':save}
 exec(compile(ast.Module(body=[node],type_ignores=[]),str(HERE/name),'exec'),scope)
 return scope['Proxy']

def observed(proxy,**extra):
 # Bounded state only: receipts, pair flags, descriptor numbers and thread liveness; never traffic.
 return {'snapshot':proxy.diagnostic_snapshot()if hasattr(proxy,'diagnostic_snapshot')else None,'stopped':proxy.stopped,'acceptThreadAlive':proxy.thread.is_alive(),'forwardThreadsAlive':[t.is_alive()for t in list(proxy.threads)],'pairs':[{'closed':p['closed'],'clientFd':p['client'].fileno(),'upstreamFd':p['upstream'].fileno()}for p in list(proxy.pairs)],**extra}

def wait(fn,diagnostic=dict):
 start=time.monotonic();end=start+3
 while time.monotonic()<end:
  v=fn()
  if v:return v
  time.sleep(.005)
 # Complete bounded state, so one failed run shows which transition never happened.
 try:state=diagnostic()
 except Exception as error:state={'diagnosticError':type(error).__name__}
 raise AssertionError('bounded controlled loopback observation timeout '+json.dumps({'boundSeconds':3,'elapsedSeconds':round(time.monotonic()-start,3),'state':state},sort_keys=True,default=repr))

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
   p.close_owned_route();state=observed(p)
   self.assertFalse(p.thread.is_alive(),state);self.assertTrue(all(not t.is_alive()for t in p.threads),state);self.assertEqual(-1,p.server.fileno(),state)
   for pair in p.pairs:
    self.assertEqual(-1,pair['client'].fileno(),state);self.assertEqual(-1,pair['upstream'].fileno(),state)
  for s in self.resources:s.close()
 def linked(self,filename=CURRENT,selector_module=selectors):
  listener=socket.socket();self.resources.append(listener);listener.bind(('127.0.0.1',0));listener.listen();listener.settimeout(3)
  proxy=load(filename,selector_module)('127.0.0.1',listener.getsockname()[1]);self.proxies.append(proxy)
  client=socket.create_connection(('127.0.0.1',proxy.port),timeout=3);self.resources.append(client)
  upstream,_=listener.accept();upstream.settimeout(3);self.resources.append(upstream);wait(lambda:proxy.pairs,lambda:observed(proxy))
  return proxy,client,upstream
 def held_drop(self,filename):
  # The forward thread's next select() is held outside the kernel selector wait
  # while drop_once runs, then released; each later selector cycle's ready count is kept.
  from types import SimpleNamespace
  control={'hold':threading.Event(),'parked':threading.Event(),'release':threading.Event(),'afterRelease':[]}
  class HeldSelector:
   def __init__(self):self.real=selectors.DefaultSelector()
   def register(self,*a,**k):return self.real.register(*a,**k)
   def select(self,timeout=None):
    if control['hold'].is_set()and not control['parked'].is_set():control['parked'].set();control['release'].wait(30)
    ready=self.real.select(timeout)
    if control['release'].is_set():control['afterRelease'].append(len(ready))
    return ready
   def close(self):self.real.close()
  proxy,client,upstream=self.linked(filename,SimpleNamespace(DefaultSelector=HeldSelector,EVENT_READ=selectors.EVENT_READ))
  temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup);root=Path(temporary.name)
  master={'recoveryId':'controlled-original','child':{'actor':{'pid':1,'birth':'fixed-public-model'}},'socketPath':'/fixed/public-control'}
  control['hold'].set()
  try:wait(control['parked'].is_set,lambda:observed(proxy,afterRelease=control['afterRelease']));proxy.drop_once(root/'drop.json',master)
  finally:control['release'].set()
  return proxy,control,root,master
 def test_actual_old_forwarding_has_no_receipt_red_current_directional_metadata_green(self):
  for name,old in(('controller.a088.before.source',True),(CURRENT,False)):
   proxy,client,upstream=self.linked(name);a=b'fixed-public-client-canary';b=b'fixed-public-upstream-canary'
   client.sendall(a);self.assertEqual(a,receive(upstream,len(a)));upstream.sendall(b);self.assertEqual(b,receive(client,len(b)))
   if old:self.assertFalse(hasattr(proxy,'diagnostic_snapshot'))
   else:
    wait(lambda:proxy.diagnostic_snapshot()['attempts'][0]['upstreamToClientBytes']==len(b),lambda:observed(proxy));v=proxy.diagnostic_snapshot();row=v['attempts'][0]
    self.assertEqual((len(a),len(b)),(row['clientReadBytes'],row['upstreamReadBytes']));self.assertEqual((len(a),len(b)),(row['clientToUpstreamBytes'],row['upstreamToClientBytes']));self.assertEqual('connected',row['connectPhase']);self.assertNotIn('canary',json.dumps(v));self.assertFalse(v['trafficRetained'])
 def test_upstream_reset_records_numeric_errno_phase_and_side_without_error_text(self):
  proxy,client,upstream=self.linked();upstream.setsockopt(socket.SOL_SOCKET,socket.SO_LINGER,struct.pack('ii',1,0));upstream.close()
  wait(lambda:proxy.diagnostic_snapshot()['attempts'][0]['closed'],lambda:observed(proxy));row=proxy.diagnostic_snapshot()['attempts'][0]
  self.assertEqual(('read','upstream-to-client','os-error'),(row['forwardPhase'],row['direction'],row['forwardErrorClass']));self.assertIs(type(row['forwardErrno']),int);self.assertIn(row['forwardErrno'],(errno.ECONNRESET,errno.ECONNABORTED));self.assertNotIn('exception',json.dumps(row).lower())
 def test_eof_records_direction_and_closed_pair(self):
  proxy,client,upstream=self.linked();client.shutdown(socket.SHUT_WR);wait(lambda:proxy.diagnostic_snapshot()['attempts'][0]['closed'],lambda:observed(proxy));row=proxy.diagnostic_snapshot()['attempts'][0]
  self.assertEqual(('eof','client-to-upstream',None),(row['forwardPhase'],row['eofDirection'],row['forwardErrno']));self.assertEqual(b'',upstream.recv(1))
 def test_exact_owned_drop_once_receipt_and_no_live_pair_replay(self):
  proxy,client,upstream=self.linked()
  with tempfile.TemporaryDirectory()as temporary:
   path=Path(temporary)/'drop.json';master={'recoveryId':'controlled-original','child':{'actor':{'pid':1,'birth':'fixed-public-model'}},'socketPath':'/fixed/public-control'}
   proxy.drop_once(path,master);wait(lambda:proxy.diagnostic_snapshot()['attempts'][0]['closed'],lambda:observed(proxy));value=json.loads(path.read_bytes());self.assertEqual(1,value['faultCount'],value);self.assertFalse(value['remoteJobSignalAllowed'],value)
   with self.assertRaisesRegex(ValueError,'private_proxy_original_pair_unresolved',msg=json.dumps(observed(proxy))):proxy.drop_once(Path(temporary)/'forbidden.json',master)
   self.assertFalse((Path(temporary)/'forbidden.json').exists(),observed(proxy))
 def test_drop_while_forwarder_is_outside_its_selector_wait_red_before_green_current(self):
  probe=selectors.DefaultSelector();backend=type(probe).__name__;probe.close()
  if backend not in('EpollSelector','KqueueSelector'):self.skipTest('closed registered descriptors leave epoll and kqueue selectors silently')
  for filename,old in(('controller.selector_candidate.source',True),(CURRENT,False)):
   with self.subTest(source=filename):
    proxy,control,root,master=self.held_drop(filename);state=lambda:observed(proxy,backend=backend,afterRelease=list(control['afterRelease']))
    if old:
     # RED: drop_once closed both registered sockets before the forward thread read
     # any readiness; the selector forgot them, so the drop is never observed, the
     # pair stays live and a second fault receipt is accepted for it.
     wait(lambda:len(control['afterRelease'])>=3,state);value=state();row=value['snapshot']['attempts'][0]
     self.assertEqual(([0,0,0],False,'select',[True]),(value['afterRelease'][:3],row['closed'],row['forwardPhase'],value['forwardThreadsAlive']),value)
     self.assertEqual([{'closed':False,'clientFd':-1,'upstreamFd':-1}],value['pairs'],value)
     proxy.drop_once(root/'replay.json',master);self.assertEqual(1,json.loads((root/'replay.json').read_bytes())['faultCount'])
    else:
     wait(lambda:proxy.diagnostic_snapshot()['attempts'][0]['closed'],state);value=state();row=value['snapshot']['attempts'][0]
     self.assertGreaterEqual(value['afterRelease'][0],1,value);self.assertEqual(('eof',[{'closed':True,'clientFd':-1,'upstreamFd':-1}]),(row['forwardPhase'],value['pairs']),value)
     with self.assertRaisesRegex(ValueError,'private_proxy_original_pair_unresolved',msg=json.dumps(value)):proxy.drop_once(root/'replay.json',master)
     self.assertFalse((root/'replay.json').exists(),value)
 def test_cancellation_closes_all_exact_owned_threads_and_fds(self):
  proxy,client,upstream=self.linked();proxy.close_owned_route();value=proxy.diagnostic_snapshot()
  self.assertTrue(value['stopped']);self.assertTrue(value['listenerClosed']);self.assertTrue(value['acceptThreadClosed']);self.assertEqual(0,value['liveForwardThreadCount']);self.assertTrue(all(r['closed']for r in value['attempts']))
 def test_refused_upstream_records_connect_errno_without_forwarding(self):
  listener=socket.socket();listener.bind(('127.0.0.1',0));port=listener.getsockname()[1];listener.close()
  proxy=load(CURRENT)('127.0.0.1',port);self.proxies.append(proxy);client=socket.create_connection(('127.0.0.1',proxy.port),timeout=3);self.resources.append(client)
  wait(lambda:proxy.diagnostic_snapshot()['attempts']and proxy.diagnostic_snapshot()['attempts'][0]['closed'],lambda:observed(proxy));row=proxy.diagnostic_snapshot()['attempts'][0]
  self.assertEqual(('failed','not-started'),(row['connectPhase'],row['forwardPhase']));self.assertEqual(errno.ECONNREFUSED,row['connectErrno']);self.assertEqual([],proxy.pairs)
 def test_receipt_list_is_bounded_without_altering_forwarding_control_list(self):
  proxy=load(CURRENT)('127.0.0.1',1);self.proxies.append(proxy)
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
  for filename,old in(('controller.5011.before.source',True),(CURRENT,False)):
   source=(HERE/filename).read_bytes()
   assert hashlib.sha256(source).hexdigest()==('5011866be6fb1b384f3af0ed0e0c8d053ddc0ea0aeae3478fb76436ab80b7d0f'if old else'ca1dab8bc2f7dbab4f2910156705c4ab242bb13e99db986bd73f7da0da60cbc4')
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
   upstream,_=listener.accept();upstream.settimeout(3);resources.append(upstream);wait(lambda:proxy.pairs,lambda:observed(proxy))
   assert min(listener.fileno(),proxy.server.fileno(),client.fileno(),upstream.fileno())>=1024
   if old:
    wait(lambda:proxy.diagnostic_snapshot()['attempts'][0]['closed'],lambda:observed(proxy));row=proxy.diagnostic_snapshot()['attempts'][0]
    assert(row['forwardPhase'],row['forwardErrorClass'],row['clientReads'],row['upstreamReads'])==('select','value-error',0,0),row
    assert row['clientToUpstreamBytes']==row['upstreamToClientBytes']==0,row
    assert select_inputs and min(select_inputs[-1])>=1024,select_inputs
    results['before']={'failedAtSelect':True,'valueError':True,'inputDescriptors':select_inputs[-1],'readBytes':0,'sourceComplete':True}
   else:
    assert not send_failed and receive(upstream,len(public))==public,send_failed
    response=b'fixed-public-high-fd-upstream';upstream.sendall(response);assert receive(client,len(response))==response
    wait(lambda:proxy.diagnostic_snapshot()['attempts'][0]['upstreamToClientBytes']==len(response),lambda:observed(proxy))
    row=proxy.diagnostic_snapshot()['attempts'][0];assert(row['clientReadBytes'],row['upstreamReadBytes'])==(len(public),len(response)),row;assert row['forwardErrno']is None and row['forwardErrorClass']is None,row
    client.shutdown(socket.SHUT_WR);wait(lambda:proxy.diagnostic_snapshot()['attempts'][0]['closed'],lambda:observed(proxy));assert proxy.diagnostic_snapshot()['attempts'][0]['eofDirection']=='client-to-upstream',observed(proxy)
    results['fixed']={'bidirectional':True,'halfClosePreserved':True,'clientBytes':len(public),'upstreamBytes':len(response),'sourceComplete':True}
   proxy.close_owned_route();assert not proxy.thread.is_alive()and all(not t.is_alive()for t in proxy.threads),observed(proxy)
   assert proxy.server.fileno()==-1 and all(pair['client'].fileno()==pair['upstream'].fileno()==-1 for pair in proxy.pairs),observed(proxy)
  assert len(selector_states)==1 and all(v['closed']and v['kernelFdAbsent']is True for v in selector_states),selector_states
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
  self.assertEqual((0,b''),(result.returncode,result.stderr),result.stdout);value=json.loads(result.stdout)
  self.assertTrue(value['before']['valueError'],value);self.assertTrue(value['fixed']['bidirectional'],value);self.assertTrue(value['fixed']['halfClosePreserved'],value);self.assertTrue(value['allOwnedThreadsSocketsSelectorsClosed'],value);self.assertEqual(0,value['externalNetworkCalls'],value)

if __name__=='__main__':
 if sys.argv[1:]==['--high-fd-case']:print(json.dumps(high_descriptor_control(),sort_keys=True))
 else:unittest.main()
