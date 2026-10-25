import unittest
from unittest import mock
from agent_tools import ssh_tmux_privileged_terminal_claim_bridge as bridge

class BridgeTests(unittest.TestCase):
 def value(self):
  return {'state':'complete-root-census','correlationId':bridge.CORRELATION,'hostBootId':'12345678-1234-4123-8123-123456789abc','pane':{'pid':1,'startTicks':2},'originalDeniedPid':992,'originalDeniedStartTicks':720,'workspaceProof':False,'nativeActionAllowed':False,'replayAllowed':False,'receiptPin':{'generation':[1,2,3,4,5,6,7,8,1],'sha256':'a'*64}}
 def test_fresh_requires_completed_false_authority_flags_and_receipt(self):
  with mock.patch.object(bridge.privileged,'observe_diagnostic',return_value=self.value()):
   fresh=bridge._fresh('/inert');self.assertEqual((1,2),(fresh['pane']['pid'],fresh['pane']['startTicks']))
  for key,value in [('workspaceProof',True),('state','root-census-failed'),('receiptPin',None)]:
   bad=self.value();bad[key]=value
   with mock.patch.object(bridge.privileged,'observe_diagnostic',return_value=bad),self.assertRaises(ValueError):bridge._fresh('/inert')
 def test_proof_schema_keeps_resource_release_false(self):
  proof={'correlationId':bridge.CORRELATION,'observedAtUnixMs':1,'base':{},'fresh':{},'resourceReleaseAllowed':False,'replayAllowed':False}
  bridge._valid_proof(proof)
  proof['resourceReleaseAllowed']=True
  with self.assertRaises(ValueError):bridge._valid_proof(proof)
 def test_sources_pin_the_bridge_implementation_itself(self):
  with mock.patch.object(bridge.closure,'_sources',return_value={}),\
       mock.patch.object(bridge.hashlib,'sha256',return_value=type('Digest',(),{'hexdigest':lambda _:bridge.PRIVILEGED_SHA})()):
   sources=bridge._sources('/inert')
  self.assertIn(str(__import__('pathlib').Path(bridge.__file__).absolute()),sources)
if __name__=='__main__':unittest.main()

class BridgeClosureSurfaceTests(unittest.TestCase):
 def test_close_uses_one_fenced_noreplace_claim_archive_and_never_resource_release(self):
  import inspect
  source=inspect.getsource(bridge.close)
  self.assertIn("fence.json",source)
  self.assertIn("closure._rename(parent,'archlinux.claim',target,'archived-claim')",source)
  self.assertNotIn("release(",source)
  self.assertNotIn("reservation",source)
  self.assertNotIn("signal",source)
 def test_close_requires_fresh_census_and_short_lifetime_before_rename(self):
  import inspect
  source=inspect.getsource(bridge.close)
  self.assertGreaterEqual(source.count("_proof_fresh(proof)"),3)
  self.assertIn("fresh=_fresh(root)",source)
  self.assertIn("fresh['boot']==proof['fresh']['boot']",source)
  self.assertIn("fresh['pane']==proof['fresh']['pane']",source)

class BridgeFenceTests(unittest.TestCase):
 def _harness(self):
  """A descriptor-backed claim fixture; only remote census is substituted."""
  import contextlib, copy, os, tempfile
  from pathlib import Path
  temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
  root=Path(temporary.name)
  journal=root/'.rag_index/linux-package-fixture-build'
  journal.mkdir(parents=True,mode=0o700)
  claim_path=journal/'archlinux.claim';claim_path.write_bytes(b'claim');claim_path.chmod(0o600)
  fd=os.open(journal,os.O_RDONLY|os.O_DIRECTORY);self.addCleanup(os.close,fd)
  claim={'generation':bridge.session.generation(os.stat(claim_path)),'sha256':'a'*64}
  reservation={'generation':[9]*9,'sha256':'r'*64}
  local={'pins':{str((journal/'archlinux.claim').relative_to(root)):claim,
                 '.rag_index/native-environments/reservations.json':reservation}}
  proof={'correlationId':bridge.CORRELATION,'observedAtUnixMs':__import__('time').time_ns()//1000000,
         'base':{'local':local,'sources':{}},'fresh':{'boot':'b','pane':{'pid':1,'startTicks':2}},
         'resourceReleaseAllowed':False,'replayAllowed':False}
  directory=root/'proof';directory.mkdir(mode=0o700)
  pin={'generation':[1]*9,'sha256':'p'*64}
  identity={'proofId':'12345678-1234-4123-8123-123456789abc','proofPin':pin}
  class Target:
   def guard(self):pass
   def __enter__(self):return self
   def __exit__(self,*_):return False
  @contextlib.contextmanager
  def lock(_):yield type('Parent',(),{'fd':fd})(),lambda:None
  reads={'fence.json':{'generation':[2]*9,'sha256':'f'*64},
         'archived-claim':claim,'proof.json':pin}
  def read(path,*_):return (b'{}',reads[Path(path).name])
  from types import SimpleNamespace
  return SimpleNamespace(root=root,claim=claim,local=local,proof=proof,
      original=copy.deepcopy(local),directory=directory,pin=pin,identity=identity,
      Target=Target,lock=lock,reads=reads,read=read)

 def _patch_close(self,fixture,states=('observed','observed','closed'),fresh=None,
                  base=None,write=None,rename=None,generation=None):
  """Run the public close path with its lock, proof, and descriptor claim intact."""
  import contextlib
  state_values=iter(states)
  write=write or [fixture.reads['fence.json'],{'generation':[3]*9,'sha256':'t'*64}]
  patches=[
   mock.patch.object(bridge,'_proof',return_value=(fixture.directory,fixture.proof,fixture.pin)),
   mock.patch.object(bridge,'status',side_effect=lambda *_:{'state':next(state_values)}),
   mock.patch.object(bridge.closure,'claim_lock',fixture.lock),
   mock.patch.object(bridge,'Directory',return_value=fixture.Target()),
   mock.patch.object(bridge,'_base',return_value=fixture.proof['base'] if base is None else base),
   mock.patch.object(bridge,'_fresh',return_value=fresh or {'boot':'b','pane':{'pid':1,'startTicks':2}}),
   mock.patch.object(bridge.pipe,'_write_once',side_effect=write),
   mock.patch.object(bridge.pipe,'_read',side_effect=fixture.read),
   mock.patch.object(bridge.closure,'_rename',side_effect=rename),
  ]
  if generation is not None:patches.append(mock.patch.object(bridge.session,'generation',side_effect=generation))
  return contextlib.ExitStack(),patches

 def test_close_fences_then_performs_exactly_one_claim_rename(self):
  fixture=self._harness();events=[]
  def write(*args):
   events.append('fence' if str(args[0]).endswith('fence.json') else 'terminal')
   return fixture.reads['fence.json'] if events[-1]=='fence' else {'generation':[3]*9,'sha256':'t'*64}
  def rename(*_):events.append('rename')
  stack,patches=self._patch_close(fixture,write=write,rename=rename)
  with stack:
   for patch in patches:stack.enter_context(patch)
   result=bridge.close(fixture.root,fixture.identity)
  self.assertEqual(result['state'],'closed')
  self.assertEqual(events,['fence','rename','terminal'])
  self.assertEqual(fixture.local,fixture.original)

 def test_source_boot_pane_and_claim_generation_drift_refuse_before_rename(self):
  cases=(
   ('local',{'local':{'pins':{}},'sources':{}},None,None),
   ('source','source-drift',None,None),
   ('boot',None,{'boot':'different','pane':{'pid':1,'startTicks':2}},None),
   ('pane',None,{'boot':'b','pane':{'pid':2,'startTicks':2}},None),
   ('claim',None,None,lambda _:'changed'),
  )
  for name,base,fresh,generation in cases:
   with self.subTest(name=name):
    fixture=self._harness();stack,patches=self._patch_close(
     fixture,states=('observed','observed'),
     base=({'local':fixture.proof['base']['local'],'sources':{'owner-anchor':'changed'}} if base=='source-drift' else base),
     fresh=fresh,generation=generation)
    with stack:
     entered=[stack.enter_context(patch) for patch in patches]
     rename=entered[-1 if generation is None else -2]
     with self.assertRaises(ValueError):bridge.close(fixture.root,fixture.identity)
    rename.assert_not_called();self.assertEqual(fixture.local,fixture.original)

 def test_claim_archive_is_real_descriptor_relative_no_replace(self):
  """The bridge calls the inherited descriptor-relative archive primitive."""
  import os,tempfile
  from pathlib import Path
  with tempfile.TemporaryDirectory(dir='.') as temporary:
   root=Path(temporary).absolute();source=root/'source';target=root/'target'
   source.mkdir(mode=0o700);target.mkdir(mode=0o700)
   (source/'archlinux.claim').write_bytes(b'claim');(source/'archlinux.claim').chmod(0o600)
   with bridge.Directory(source) as source_directory,bridge.Directory(target) as target_directory:
    bridge.closure._rename(source_directory,'archlinux.claim',target_directory,'archived-claim')
   self.assertFalse((source/'archlinux.claim').exists())
   self.assertEqual((target/'archived-claim').read_bytes(),b'claim')
   (source/'archlinux.claim').write_bytes(b'new');(source/'archlinux.claim').chmod(0o600)
   with bridge.Directory(source) as source_directory,bridge.Directory(target) as target_directory:
    with self.assertRaises(ValueError):
     bridge.closure._rename(source_directory,'archlinux.claim',target_directory,'archived-claim')
   self.assertEqual((source/'archlinux.claim').read_bytes(),b'new')
   self.assertEqual((target/'archived-claim').read_bytes(),b'claim')

 def test_stale_proof_and_lost_fence_never_retry_the_claim_rename(self):
  fixture=self._harness();fixture.proof['observedAtUnixMs']=0
  stack,patches=self._patch_close(fixture,states=('observed',))
  with stack:
   entered=[stack.enter_context(patch) for patch in patches];rename=entered[-1]
   with self.assertRaises(ValueError):bridge.close(fixture.root,fixture.identity)
  rename.assert_not_called()

  fixture=self._harness();terminal_failure=OSError('disk full')
  stack,patches=self._patch_close(fixture,write=[fixture.reads['fence.json'],terminal_failure])
  with stack:
   entered=[stack.enter_context(patch) for patch in patches];rename=entered[-1]
   with self.assertRaises(OSError):bridge.close(fixture.root,fixture.identity)
  rename.assert_called_once()
  # A fence without a terminal receipt is a lost outcome, never a retry.
  with mock.patch.object(bridge,'_proof',return_value=(fixture.directory,fixture.proof,fixture.pin)),\
       mock.patch.object(bridge,'status',return_value={'state':'unknown'}),\
       mock.patch.object(bridge.closure,'_rename') as replay:
   self.assertEqual(bridge.close(fixture.root,fixture.identity)['state'],'unknown')
  replay.assert_not_called();self.assertEqual(fixture.local,fixture.original)

class BridgeActualDurableFlowTests(unittest.TestCase):
 def _fixture(self):
  import tempfile,os
  from pathlib import Path
  temporary=tempfile.TemporaryDirectory(dir='.');self.addCleanup(temporary.cleanup)
  root=Path(temporary.name).absolute();index=root/'.rag_index';index.mkdir(mode=0o700)
  journal=index/'linux-package-fixture-build';journal.mkdir(mode=0o700)
  claim=journal/'archlinux.claim';claim.write_bytes(b'claim');claim.chmod(0o600)
  pin=bridge.pipe._read(claim)[1]
  local={'pins':{str(claim.relative_to(root)):pin,
      '.rag_index/native-environments/reservations.json':{'generation':[9]*9,'sha256':'r'*64},
      'owner-anchor.json':{'generation':[8]*9,'sha256':'a'*64}}}
  fresh={'boot':'12345678-1234-4123-8123-123456789abc','pane':{'pid':1,'startTicks':2},
      'receiptPin':{'generation':[1]*9,'sha256':'b'*64},'result':{'fixture':True}}
  return root,claim,{'local':local,'sources':{'fixed-owner-anchor':'pin'}},fresh

 def _ready(self,root,base,fresh):
  with mock.patch.object(bridge,'_base',return_value=base),mock.patch.object(bridge,'_fresh',return_value=fresh):
   return bridge.observe(root)

 def test_real_observe_proof_close_status_uses_durable_fence_and_noreplace(self):
  root,claim,base,fresh=self._fixture();ready=self._ready(root,base,fresh)
  with mock.patch.object(bridge,'_base',return_value=base),mock.patch.object(bridge,'_fresh',return_value=fresh):
   closed=bridge.close(root,{'proofId':ready['proofId'],'proofPin':ready['proofPin']})
  self.assertEqual(closed['state'],'closed');self.assertFalse(claim.exists())
  archived=root/'.rag_index/ssh-tmux-privileged-terminal-claim-bridge'/ready['proofId']/'archived-claim'
  self.assertEqual(archived.read_bytes(),b'claim')
  self.assertEqual(bridge.status(root,{'proofId':ready['proofId'],'proofPin':ready['proofPin']})['state'],'closed')
  self.assertEqual(base['local']['pins']['.rag_index/native-environments/reservations.json']['sha256'],'r'*64)

 def test_real_terminal_write_loss_stays_unknown_and_cannot_replay(self):
  root,claim,base,fresh=self._fixture();ready=self._ready(root,base,fresh);original=bridge.pipe._write_once
  def fail_terminal(path,data):
   if path.name=='terminal.json':raise OSError('inert terminal write failure')
   return original(path,data)
  identity={'proofId':ready['proofId'],'proofPin':ready['proofPin']}
  with mock.patch.object(bridge,'_base',return_value=base),mock.patch.object(bridge,'_fresh',return_value=fresh),\
       mock.patch.object(bridge.pipe,'_write_once',side_effect=fail_terminal):
   with self.assertRaises(OSError):bridge.close(root,identity)
  self.assertFalse(claim.exists());self.assertEqual(bridge.status(root,identity)['state'],'unknown')
  self.assertEqual(bridge.close(root,identity)['state'],'unknown')

 def test_real_claim_descriptor_drift_after_fresh_census_fences_and_refuses(self):
  root,claim,base,fresh=self._fixture();ready=self._ready(root,base,fresh);calls=[]
  def drift_after_fresh(_):
   calls.append(True)
   if len(calls)==1:
    claim.write_bytes(b'drift');claim.chmod(0o600)
   return fresh
  identity={'proofId':ready['proofId'],'proofPin':ready['proofPin']}
  with mock.patch.object(bridge,'_base',return_value=base),mock.patch.object(bridge,'_fresh',side_effect=drift_after_fresh):
   with self.assertRaises(ValueError):bridge.close(root,identity)
  self.assertTrue(claim.exists());self.assertEqual(claim.read_bytes(),b'drift')
  self.assertEqual(bridge.status(root,identity)['state'],'unknown')

 def test_age_rechecked_after_fresh_census_before_the_fence(self):
  root,claim,base,fresh=self._fixture();now=10_000_000_000
  with mock.patch.object(bridge.time,'time_ns',return_value=now):ready=self._ready(root,base,fresh)
  identity={'proofId':ready['proofId'],'proofPin':ready['proofPin']}
  times=iter((now,now+(bridge.MAX_AGE_MS+1)*1_000_000))
  with mock.patch.object(bridge,'_base',return_value=base),mock.patch.object(bridge,'_fresh',return_value=fresh),\
       mock.patch.object(bridge.time,'time_ns',side_effect=lambda:next(times)):
   with self.assertRaises(ValueError):bridge.close(root,identity)
  self.assertTrue(claim.exists());self.assertEqual(bridge.status(root,identity)['state'],'observed')

 def test_real_bridge_source_pin_drift_refuses_before_fence(self):
  root,claim,base,fresh=self._fixture();own=__import__('pathlib').Path(bridge.__file__).absolute()
  with mock.patch.object(bridge.closure,'local_proof',return_value=base['local']),\
       mock.patch.object(bridge.closure,'_sources',return_value={'closure':'fixed'}),\
       mock.patch.object(bridge,'_fresh',return_value=fresh):
   ready=bridge.observe(root)
  original=bridge.pipe._read
  def changed_source(path,*args,**kwargs):
   raw,pin=original(path,*args,**kwargs)
   if __import__('pathlib').Path(path).absolute()==own:
    return raw,dict(pin,sha256='0'*64)
   return raw,pin
  identity={'proofId':ready['proofId'],'proofPin':ready['proofPin']}
  with mock.patch.object(bridge.closure,'local_proof',return_value=base['local']),\
       mock.patch.object(bridge.closure,'_sources',return_value={'closure':'fixed'}),\
       mock.patch.object(bridge,'_fresh',return_value=fresh),\
       mock.patch.object(bridge.pipe,'_read',side_effect=changed_source):
   with self.assertRaises(ValueError):bridge.close(root,identity)
  self.assertTrue(claim.exists());self.assertEqual(bridge.status(root,identity)['state'],'observed')
