"""Twenty retained ACL diagnostic controls, bound to native successor 9143.

Only the two metadata modules and two capture modules execute whole definitions.
Driver execution is limited to five named original AST functions. Complete
controller/launcher bodies and original harnesses are authenticated data only.
The C endpoint implements controlled replies; it calls no Darwin metadata API.
No routine reads ignored runtime paths or runs a guest/getter/privileged helper.
"""
import ast,ctypes as C,hashlib,json,os,shutil,stat,struct,subprocess,sys,tempfile,time,types,unittest,uuid
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch
from agent_tools.source_module_loader import SourceSession
ROOT=Path(__file__).resolve().parents[2]
HERE=Path(__file__).resolve().parent/'fixtures'/'tart_macos_acl_diagnostic'
FILES=('cap.controls.source', 'capture.before.source', 'capture.current.source', 'component.controls.source', 'component.current.source', 'component.lp64.before.source', 'controller.current.source', 'deadline.controls.source', 'driver.cap.before.source', 'driver.current.source', 'driver.deadline.before.source', 'fake_metadata.c', 'launcher.current.source', 'native-cap-failure.txt', 'native-result.json', 'native-rpc-closure.json', 'native-source-closing.json', 'packet.controls.source', 'tart_macos_active_source_index.py.source', 'tart_macos_probe.py.source', 'tart_macos_service_census.py.source')
PROVENANCE_SHA256='8d88746ec39953b4435a0d6da32145c89b69da9a935fe9c5f3e9ab1996ca0000'
M=None

def evidence():
 raw=(HERE/'provenance.json').read_bytes()
 if hashlib.sha256(raw).hexdigest()!=PROVENANCE_SHA256:raise AssertionError('provenance changed')
 result=json.loads(raw)
 if set(result['files'])!=set(FILES):raise AssertionError('fixture scope changed')
 return result

def fixture(name):
 if name not in FILES:raise ValueError('fixed fixture scope')
 raw=(HERE/name).read_bytes();row=evidence()['files'][name]
 if len(raw)!=row['bytes'] or hashlib.sha256(raw).hexdigest()!=row['sha256']:raise AssertionError('fixture changed: '+name)
 return raw

def module(name):
 if name not in ('component.current.source','component.lp64.before.source','capture.current.source','capture.before.source'):raise ValueError('fixed executable scope')
 result=types.ModuleType('_acl_'+name.replace('.','_'));result.__file__=str(HERE/name)
 exec(compile(fixture(name),result.__file__,'exec'),result.__dict__)
 return result

@unittest.skipUnless(os.name=='posix','POSIX ctypes/owned-FD capability required')
class ComponentTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  global M
  M=module('component.current.source')
  if not shutil.which('cc'):raise unittest.SkipTest('controlled C ABI compiler unavailable')
  cls.temp=tempfile.TemporaryDirectory(prefix='controlled-metadata-abi-');cls.addClassCleanup(cls.temp.cleanup)
  fixture('fake_metadata.c')
  library=Path(cls.temp.name)/'fake.dylib'
  subprocess.run(['cc','-shared','-fPIC',str(HERE/'fake_metadata.c'),'-o',str(library)],check=True,capture_output=True,timeout=20)
  cls.lib=C.CDLL(str(library),use_errno=True);cls.lib.configure.argtypes=[C.c_int];cls.lib.counts.argtypes=[C.c_int];cls.lib.counts.restype=C.c_int
 def setUp(self):self.lib.configure(0);self.native=M.NativeMetadata(self.lib)
 def test_real_c_abi_ordered_types_uuid_mask_flags_and_cleanup(self):
  value=self.native.acl(7);self.assertEqual(value['state'],'available');self.assertEqual(value['entryCount'],2)
  self.assertEqual([v['type']for v in value['orderedEntries']],['allow','deny'])
  self.assertEqual([v['index']for v in value['orderedEntries']],[0,1]);self.assertTrue(value['orderedEntries'][1]['inheritance']['inherited'])
  self.assertEqual(value['orderedEntries'][0]['qualifierGuid'],'112233445566778899aabbccddeeff01')
  self.assertEqual(value['orderedEntries'][0]['permissionMask'],(1<<60)|0x2022)
  self.assertEqual((self.lib.counts(0),self.lib.counts(1)),(1,2));self.assertEqual(value['effectiveAccess'],'not_evaluated')
 def test_null_acl_never_means_empty_and_darwin_end_semantics(self):
  for mode,reason in [(1,'permission_denied'),(2,'not_found'),(3,'acl_invalid'),(5,'acl_entry_unavailable'),(6,'acl_entry_unavailable')]:
   self.lib.configure(mode);self.assertEqual(self.native.acl(7),{'state':'unavailable','reason':reason})
  self.lib.configure(4);value=self.native.acl(7);self.assertEqual((value['state'],value['entryCount']),('available',0));self.assertEqual(self.lib.counts(0),1)
 def test_128_entry_bound_and_every_error_free_original_copy(self):
  for mode,reason in [(7,'acl_tag_unavailable'),(8,'acl_entry_overflow'),(9,'acl_qualifier_unavailable'),(10,'acl_release_failed'),(11,'acl_permissions_unavailable'),(12,'acl_flags_unavailable'),(13,'acl_flags_unavailable')]:
   self.lib.configure(mode);self.assertEqual(self.native.acl(7),{'state':'unavailable','reason':reason});self.assertEqual(self.lib.counts(0),1)
  self.lib.configure(8);self.native.acl(7);self.assertEqual(self.lib.counts(1),128)
 def test_volume_actual_struct_request_length_valid_and_capability_masks(self):
  self.assertEqual((C.sizeof(M.Attrlist),C.sizeof(M.Capabilities)),(24,36))
  self.assertEqual(M.Attrlist.volattr.offset,8);self.assertEqual(M.Capabilities.valid.offset,20)
  value=self.native.volume(7);self.assertEqual(value['state'],'available');self.assertTrue(value['formatSealedKnown']);self.assertTrue(value['formatSealed']);self.assertEqual(value['namespaceIntegrity'],'unqualified')
  self.lib.configure(16);value=self.native.volume(7);self.assertFalse(value['formatSealedKnown']);self.assertFalse(value['formatSealed'])
  for mode,reason in [(14,'permission_denied'),(15,'volume_reply_length')]:
   self.lib.configure(mode);self.assertEqual(self.native.volume(7),{'state':'unavailable','reason':reason})
 def test_volume_parser_short_and_oversize_cannot_be_success(self):
  for raw in [b'',bytes(35),bytes(37),struct.pack('=I8I',0,0,0,0,0,0,0,0,0),struct.pack('=I8I',1000000,0,0,0,0,0,0,0,0)]:
   with self.assertRaises(M.GetterUnavailable):M.parse_volume(raw)
 def test_credential_memberships_not_success_when_memberd_unavailable(self):
  value=self.native.credentials();self.assertEqual(value['effectiveUid'],os.geteuid());self.assertEqual(value['effectiveAccess'],'not_evaluated')
  self.assertTrue(all(v['state']=='available'and'guid'in v for v in value['membership']))
  self.lib.configure(17);value=self.native.credentials();self.assertTrue(all(v['state']=='unavailable'and'guid'not in v for v in value['membership']))
 def owned(self):
  temp=tempfile.TemporaryDirectory(prefix='fixed-acl-owned-');self.addCleanup(temp.cleanup);root=Path(temp.name).resolve();path=root/'parent'/'component';path.mkdir(parents=True);return root,path
 @unittest.skipUnless(hasattr(os.stat_result,'st_flags'),'Darwin st_flags FD custody capability required')
 def test_real_fd_path_binding_both_getters_and_no_child_content(self):
  root,path=self.owned();(path/'must-not-read').write_text('private-control-marker')
  calls=[]
  class Reader:
   def read(_,fd):calls.append(M.generation(os.fstat(fd)));return {'metadata':'synthetic'}
  with patch.object(os,'read',side_effect=AssertionError('content read')),patch.object(os,'listdir',side_effect=AssertionError('directory list')):
   value=M.directory_metadata(str(path),M.generation(path.stat()),Reader())
  self.assertEqual(len(calls),2);self.assertTrue(value['namedFdGenerationStable']);self.assertFalse(value['directoryContentsRead']);self.assertEqual(value['componentAuthentication'],'unqualified')
 @unittest.skipUnless(hasattr(os.stat_result,'st_flags'),'Darwin st_flags FD custody capability required')
 def test_real_parent_rename_in_second_getter_blocked_after_callback(self):
  root,path=self.owned();calls=[]
  class Reader:
   def read(_,fd):
    calls.append(fd)
    if len(calls)==2:
     path.parent.rename(root/'moved');path.parent.mkdir();path.mkdir()
    return {'metadata':'same'}
  with self.assertRaises(M.Unavailable):M.directory_metadata(str(path),M.generation(path.stat()),Reader())
  self.assertEqual(len(calls),2)
 @unittest.skipUnless(hasattr(os.stat_result,'st_flags'),'Darwin st_flags FD custody capability required')
 def test_symlink_or_stale_generation_refuses_before_getter(self):
  root,path=self.owned();alias=root/'alias';alias.symlink_to(path,target_is_directory=True)
  class Reader:
   def read(_,fd):raise AssertionError('unexpected getter')
  for selected,identity in [(alias,M.generation(path.stat())),(path,(1,)*9)]:
   with self.assertRaises(M.Unavailable):M.directory_metadata(str(selected),identity,Reader())
 def test_public_projection_source_no_private_principals_or_acl_values(self):
  tree=ast.parse(fixture('component.current.source'));collect=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='collect')
  assignment=next(n for n in ast.walk(collect)if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='public'for t in n.targets));keys={k.value for k in assignment.value.keys}
  self.assertFalse(keys&{'credentials','componentPath','qualifierGuid','permissionMask','orderedEntries','groups','membership'});self.assertTrue({'nativeQualified','idleAuthority','namespaceIntegrity'}<=keys)
  calls={n.func.attr for n in ast.walk(tree)if isinstance(n,ast.Call)and isinstance(n.func,ast.Attribute)}
  self.assertFalse(calls&{'listdir','scandir','ioctl','acl_set_fd','acl_set_fd_np','acl_add_perm','chmod','chflags','setgroups'})
  # NativeMetadata.read is our fixed getter dispatcher, not os.read/content.
  os_calls={n.func.attr for n in ast.walk(tree)if isinstance(n,ast.Call)and isinstance(n.func,ast.Attribute)and isinstance(n.func.value,ast.Name)and n.func.value.id=='os'}
  self.assertFalse(os_calls&{'listdir','scandir','ioctl','chmod','chflags'})
 def test_dynamic_public_counts_never_emit_private_guid_paths_groups_or_exception(self):
  private={'componentPath':'/private-controlled-marker','credentials':{'groups':[999999]},'metadata':{'acl':{'state':'available','entryCount':2,'orderedEntries':[{'qualifierGuid':'private-guid-sentinel','permissionMask':123}]},'volume':{'state':'available','formatSealedKnown':True,'formatSealed':False}}}
  counts=M.public_counts([private]);serialized=json.dumps(counts)
  for forbidden in ['private-controlled-marker','private-guid-sentinel','999999','123','orderedEntries','credentials']:self.assertNotIn(forbidden,serialized)
  private['metadata']['acl']={'state':'unavailable','reason':'private exception /private-controlled-marker'}
  counts=M.public_counts([private]);self.assertEqual(counts['aclUnavailableReasons'],{'other_error':1});self.assertNotIn('private',json.dumps(counts))
 def test_complete_builder_pins_deadline_and_rejects_changed_source_before_dispatch(self):
  sources={name:fixture(name+'.source')for name in M.PINS}
  component=fixture('component.current.source');source=M.build(sources,(1,502,1,1,0),component)
  self.assertLessEqual(len(source),262144);self.assertLess(source.index(b'signal.alarm(60)'),source.index(b'exec(compile('));compile(source,'<controlled-generated-getter>','exec')
  changed=dict(sources);name=next(iter(changed));changed[name]+=b'\n'
  with self.assertRaises(M.Unavailable):M.build(changed,(1,502,1,1,0),component)
  with self.assertRaises(M.Unavailable):M.build(sources,(1,502,1,1,0),component+b'\n_EXECUTING = None\n')
 def test_pinned_sdk_lp64_declaration_old_red_current_exact_green(self):
  old=module('component.lp64.before.source');old.NativeMetadata(self.lib)
  with self.assertRaises(AssertionError):self.assertIs(self.lib.fgetattrlist.argtypes[-1],C.c_uint)
  M.NativeMetadata(self.lib);self.assertIs(self.lib.fgetattrlist.argtypes[-1],C.c_uint)
  if sys.platform!='darwin':self.skipTest('actual Darwin SDK LP64 declaration requires Darwin')
  sdk=Path('/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk');header=sdk/'usr/include/unistd.h'
  self.assertEqual(hashlib.sha256(header.read_bytes()).hexdigest(),'8d535079658f063bcef358ef4c1c1b52b8e88dacfc22cbf4db0f6bf8abe40637')
  # The compiler resolves the ACTUAL SDK's __LP64__ branch; this is not a
  # duplicated Python/fake signature claiming itself correct.
  template='#include <unistd.h>\n#ifndef __LP64__\n#error LP64 required\n#endif\n_Static_assert(__builtin_types_compatible_p(__typeof__(&fgetattrlist),int(*)(int,void*,void*,size_t,%s)),"exact LP64 SDK declaration");\n'
  for typename,success in [('unsigned long',False),('unsigned int',True)]:
   reply=subprocess.run(['cc','-fsyntax-only','-isysroot',str(sdk),'-x','c','-'],input=(template%typename).encode(),capture_output=True,timeout=20)
   self.assertEqual(reply.returncode==0,success)
   if not success:self.assertIn(b'static assertion failed',reply.stderr)
  old=module('component.lp64.before.source')
  old.NativeMetadata(self.lib)
  with self.assertRaises(AssertionError):self.assertIs(self.lib.fgetattrlist.argtypes[-1],C.c_uint)
  M.NativeMetadata(self.lib);self.assertIs(self.lib.fgetattrlist.argtypes[-1],C.c_uint);self.assertEqual(C.sizeof(self.lib.fgetattrlist.argtypes[-1]),4)

@unittest.skipUnless(os.name=='posix','owned process/FD capability required')
class PacketTests(unittest.TestCase):
 def test_capture_exact_new_scope_full_eof(self):
  with ExitStack()as stack:
   session=SourceSession(ROOT/'agent_tools','private_inventory_lock');stack.callback(session.close);P=session.module;J=session.load('durable_remote_job');R=session.load('readiness_tart_macos_registry')
   module=types.ModuleType('_acl_capture_test');raw=fixture('capture.current.source');exec(compile(raw,str(HERE/'capture.current.source'),'exec'),module.__dict__)
   before=types.ModuleType('_namespace_capture_test');raw=fixture('capture.before.source');exec(compile(raw,str(HERE/'capture.before.source'),'exec'),before.__dict__)
   with tempfile.TemporaryDirectory(prefix='acl-capture-')as temp:
    os.chmod(temp,0o700)
    with P.Directory(Path(temp).resolve())as directory:
     with self.assertRaises(ValueError):before.PublicRpcCapture(directory,'call-1-catalog')
     with module.PublicRpcCapture(directory,'call-1-catalog')as retained:
      result,receipt=retained.run([sys.executable,'-I','-B','-c','import sys,time;data=sys.stdin.buffer.read();time.sleep(.15);sys.stdout.buffer.write(data);sys.stderr.write("public-error")'],b'{"finite":true}',deadline=time.monotonic()+20,birth=J._birth,parent=lambda pid:R._parent(pid,time.monotonic()+2))
     self.assertEqual(result.stdout,b'{"finite":true}');self.assertEqual(result.stderr,b'public-error');self.assertTrue(receipt['actorAbsent']);self.assertFalse(receipt['partial']);self.assertTrue(receipt['stdoutEof']and receipt['stderrEof'])
     with self.assertRaises(ValueError):module.PublicRpcCapture(directory,'call-2-enroll')
     self.assertEqual((Path(temp)/'call-1-catalog.stdout.json').stat().st_mode&0o777,0o600)
 def test_filter_only_finite_output(self):
  tree=ast.parse(fixture('driver.current.source'))
  names={'need','public_reply'};nodes=[n for n in tree.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))and n.name in names]
  ns={'MACHINE':'ecdc399a-8f2b-5410-b85d-e4db56ddc6c1','RAW_BOOT':'87AC272F-619B-4CC0-B9FC-3E32DAEE5B18','uuid':__import__('uuid')};exec(compile(ast.Module(body=nodes,type_ignores=[]),'<exact-public-filter>','exec'),ns)
  blocked={'public':{'state':'blocked','reason':'macos_component_acl_diagnostic_unavailable'}};self.assertEqual(ns['public_reply'](blocked,None),blocked['public'])
  for bad in [{'public':{'state':'blocked','reason':'PRIVATE'}},{'public':{'state':'blocked','reason':'macos_component_acl_diagnostic_unavailable','path':'PRIVATE'}}]:
   with self.assertRaises(RuntimeError):ns['public_reply'](bad,None)
 def test_whole_packet_exact_captured_bytes_and_no_admission(self):
  metadata=evidence()
  for name in FILES:fixture(name)
  self.assertEqual(metadata['operationId'],'9143d37e-1a30-4773-bb6d-fb6f706bb07b')
  for name,expected in [('driver.current.source','2441a0ee19c0748a866aa16c79dfc143ef505fa689b954dfc0d6259c87eed12b'),('controller.current.source','a12c6a451abe1f2c68ac9a2419eb33ade68969bd385eaf1b294c4d5f94c48769'),('launcher.current.source','a1e64f9c610f6c71fa3e8f9b1e1145922a33727278c5dcee6828c221076824bf'),('native-source-closing.json','aeea8a5e5eadc21801294c6a88832f6f2794083de344d62d9d73e802d11e6699')]:
   self.assertEqual(hashlib.sha256(fixture(name)).hexdigest(),expected)
  for name in ('driver.current.source','controller.current.source','launcher.current.source'):compile(fixture(name),str(HERE/name),'exec')
  with ExitStack()as stack:
   session=SourceSession(ROOT/'agent_tools','durable_remote_job');stack.callback(session.close)
   self.assertEqual(session.module.Program('macos-acl-metadata-controller',fixture('controller.current.source'),1048576).digest,metadata['files']['controller.current.source']['sha256'])
  closing=json.loads(fixture('native-source-closing.json'));self.assertEqual(len(closing['sources']),22)
  rpc=json.loads(fixture('native-rpc-closure.json'));self.assertEqual(rpc['dispatchCount'],13);self.assertTrue(rpc['allOriginalActorsAbsent']and rpc['allRawEof'])
  result=json.loads(fixture('native-result.json'));self.assertEqual(result['operationId'],metadata['operationId']);self.assertEqual(result['returncode'],0)
  for key in ('nativeQualified','idleAuthority'):self.assertFalse(result['reply'][key])
  self.assertIn(b'macos_custody_unavailable',fixture('native-cap-failure.txt'))

@unittest.skipUnless(os.name=='posix','owned process/FD capability required')
class DeadlineTests(unittest.TestCase):
 def test_exact_spent_group_old_launches_new_zero(self):
  old=fixture('driver.deadline.before.source');new=fixture('driver.current.source')
  with ExitStack()as stack:
   session=SourceSession(ROOT/'agent_tools','private_inventory_lock');stack.callback(session.close);P=session.module;J=session.load('durable_remote_job');R=session.load('readiness_tart_macos_registry')
   C=types.ModuleType('_actual_acl_capture');raw=fixture('capture.current.source');exec(compile(raw,str(HERE/'capture.current.source'),'exec'),C.__dict__)
   with tempfile.TemporaryDirectory(prefix='acl-spent-')as temporary:
    root=Path(temporary).resolve();root.chmod(0o700);shim=root/'public-only-shim'
    shim.write_text('#!'+sys.executable+'\nimport sys,time\nsys.stdin.buffer.read();time.sleep(.1);sys.stdout.write("{\\"public\\":true}")\n');shim.chmod(0o700)
    canonical=(sys.executable,'-I','-B','-c','public_only')
    for label,source in [('old',old),('new',new)]:
     outpath=root/label;outpath.mkdir(mode=0o700)
     with P.Directory(outpath)as out:
      selected={n.name:n for n in ast.walk(ast.parse(source))if isinstance(n,ast.FunctionDef)and n.name in {'need','guard','output_record','captured_native'}}
      self.assertEqual(set(selected),{'need','guard','output_record','captured_native'})
      no=types.SimpleNamespace(guard=lambda:None)
      ns={'os':os,'sys':sys,'time':time,'json':json,'hashlib':__import__('hashlib'),'stat':__import__('stat'),'out':out,'session':no,'self_source':no,'component_source':no,'capture_source':no,'prior_source':no,'run_dir':no,'GROUP_DEADLINE':time.monotonic()-.1,'phase':{'value':'catalog'},'native_calls':[],'VM':'vm-public','MACHINE':'machine-public','OP':'public-operation','protocol':types.SimpleNamespace(stdin_command=lambda _: (canonical,None)),'capture':C,'jobs':J,'mac_registry':R}
      nodes=[selected[name]for name in ('need','output_record','guard','captured_native')];exec(compile(ast.Module(body=nodes,type_ignores=[]),'<whole-authentic-driver-methods>','exec'),ns)
      binding=types.SimpleNamespace(vm_name='vm-public',machine='machine-public',tart_binary=str(shim),guest_python=sys.executable);custody=types.SimpleNamespace(binding=binding,run_intent={'operationId':'2d933a39-0fb6-46a4-9fd9-02221d81c4b9'})
      argv=(str(shim),'exec','-i','vm-public',sys.executable,*canonical[1:])
      if label=='old':
       result=ns['captured_native'](custody,argv,b'public source',time.monotonic()+2);self.assertEqual(result.returncode,0);self.assertEqual(len(ns['native_calls']),1);self.assertTrue(ns['native_calls'][0]['actorAbsent'])
      else:
       with self.assertRaisesRegex(RuntimeError,'acl_group_deadline'):ns['captured_native'](custody,argv,b'public source',time.monotonic()+2)
       self.assertEqual(ns['native_calls'],[]);self.assertEqual(list(outpath.iterdir()),[])

@unittest.skipUnless(os.name=='posix','owned process/FD capability required')
class CapTests(unittest.TestCase):
 def setUp(self):
  self.stack=ExitStack();self.addCleanup(self.stack.close);s=SourceSession(ROOT/'agent_tools','private_inventory_lock');self.stack.callback(s.close);self.P=s.module;self.J=s.load('durable_remote_job');self.R=s.load('readiness_tart_macos_registry');self.C=types.ModuleType('_actual_fixed_capture');raw=fixture('capture.current.source');exec(compile(raw,str(HERE/'capture.current.source'),'exec'),self.C.__dict__)
  self.old=fixture('driver.cap.before.source');self.new=fixture('driver.current.source');temp=self.stack.enter_context(tempfile.TemporaryDirectory(prefix='acl-cap-'));self.root=Path(temp).resolve();self.root.chmod(0o700);self.shim=self.root/'public-only';self.shim.write_text('#!'+sys.executable+'\nimport sys,time\nsys.stdin.buffer.read();time.sleep(.1);sys.stdout.write("{\\"public\\":true}")\n');self.shim.chmod(0o700)
 def case(self,source,prior,*,wrong_vm=False,expired=False):
  path=self.root/str(len(list(self.root.iterdir())));path.mkdir(mode=0o700)
  with self.P.Directory(path)as out:
   selected={n.name:n for n in ast.walk(ast.parse(source))if isinstance(n,ast.FunctionDef)and n.name in {'need','guard','output_record','captured_native'}};no=types.SimpleNamespace(guard=lambda:None);canonical=(sys.executable,'-I','-B','-c','public_only')
   ns={'os':os,'sys':sys,'time':time,'json':json,'hashlib':__import__('hashlib'),'stat':__import__('stat'),'out':out,'session':no,'self_source':no,'component_source':no,'capture_source':no,'prior_source':no,'run_dir':no,'GROUP_DEADLINE':time.monotonic()+(-1 if expired else 10),'phase':{'value':'root-after'},'native_calls':[None]*prior,'VM':'vm-public','MACHINE':'machine-public','OP':'public-operation','protocol':types.SimpleNamespace(stdin_command=lambda _: (canonical,None)),'capture':self.C,'jobs':self.J,'mac_registry':self.R}
   exec(compile(ast.Module(body=[selected[n]for n in ('need','output_record','guard','captured_native')],type_ignores=[]),'<authentic-complete-private-caller>','exec'),ns)
   binding=types.SimpleNamespace(vm_name='foreign'if wrong_vm else'vm-public',machine='machine-public',tart_binary=str(self.shim),guest_python=sys.executable);c=types.SimpleNamespace(binding=binding,run_intent={'operationId':'2d933a39-0fb6-46a4-9fd9-02221d81c4b9'});argv=(str(self.shim),'exec','-i','vm-public',sys.executable,*canonical[1:])
   try:result=ns['captured_native'](c,argv,b'public_source',time.monotonic()+2)
   except RuntimeError:return 'refused',ns['native_calls'],list(path.iterdir())
   return result,ns['native_calls'],list(path.iterdir())
 def test_authentic_old12_refuses_current13th_exact_owned_child(self):
  result,calls,files=self.case(self.old,12);self.assertEqual(result,'refused');self.assertEqual(len(calls),12);self.assertEqual(files,[])
  result,calls,files=self.case(self.new,12);self.assertEqual(result.returncode,0);self.assertEqual(len(calls),13);self.assertTrue(calls[-1]['actorAbsent']);self.assertTrue(calls[-1]['stdoutEof']and calls[-1]['stderrEof']);self.assertFalse(calls[-1]['partial'])
 def test_17th_foreign_vm_and_expired_all_zero_child(self):
  for prior,kw in [(16,{}),(12,{'wrong_vm':True}),(12,{'expired':True})]:
   result,calls,files=self.case(self.new,prior,**kw);self.assertEqual(result,'refused');self.assertEqual(len(calls),prior);self.assertEqual(files,[])
 def test_fixed_static_path_is13_current_source_accounting(self):
  tree=ast.parse((ROOT/'agent_tools/readiness_tart_macos.py').read_text());classes={n.name:n for n in tree.body if isinstance(n,ast.ClassDef)}
  def method(cls,name):return next(n for n in classes[cls].body if isinstance(n,ast.FunctionDef)and n.name==name)
  def count(node,attr):return sum(isinstance(n,ast.Call)and ((isinstance(n.func,ast.Attribute)and n.func.attr==attr)or (isinstance(n.func,ast.Name)and n.func.id=='_call'and n.args and isinstance(n.args[0],ast.Attribute)and n.args[0].attr==attr))for n in ast.walk(node))
  self.assertEqual(count(method('MacTartBackend','_observe'),'guest_probe'),1);self.assertEqual(count(method('MacTartBackend','_observe'),'idle_facts'),1)
  self.assertEqual(count(method('MacTartBackend','guest_job_executor'),'_observe'),1);self.assertEqual(count(method('MacGuestExecutor','execute'),'_observe'),1);self.assertEqual(count(method('MacGuestExecutor','execute'),'ordinary_guest_call'),1)
  rt=ast.parse((ROOT/'agent_tools/readiness_tart_macos_registry.py').read_text());custody=next(n for n in rt.body if isinstance(n,ast.ClassDef)and n.name=='MacCustody');idle=next(n for n in custody.body if isinstance(n,ast.FunctionDef)and n.name=='idle_facts');self.assertEqual(count(idle,'unlock_observer_inventory'),1)
  # Current admitted namespace causes one fixed inventory per _observe:
  # factory2 + executor2 + each of3selected calls(2freshobserve+1actual).
  self.assertEqual(2+2+3*(2+1),13);tree=ast.parse(self.new);self.assertTrue(any(isinstance(n,ast.Compare)and isinstance(n.ops[0],ast.Lt)and isinstance(n.comparators[0],ast.Constant)and n.comparators[0].value==16 for n in ast.walk(tree)))


if __name__=='__main__':unittest.main()
