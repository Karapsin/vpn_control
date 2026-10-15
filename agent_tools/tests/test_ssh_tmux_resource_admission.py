import copy
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest import mock
from agent_tools import ssh_tmux_resource_admission as r

REQUEST={'sourceSha':'d32f719a08db57e5d40ce2bf77e0d7c5b42de557','baseVersion':'2.1.19','targetVersion':'2.2.2','correlationId':'d93cd8dd-a62f-480a-abd8-478be5cc1d21'}
@unittest.skipUnless(os.name == 'posix' and r.closure.pipe is not None and r.closure.fcntl is not None,
                     'POSIX descriptor-relative coordinator and flock required')
class ResourceTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name).resolve();self.root.chmod(0o700)
  (self.root/'.rag_index').mkdir(mode=0o700);(self.root/'.rag_index/native-environments').mkdir(mode=0o700);(self.root/r.build._JOURNAL).mkdir(mode=0o700)
  self.identity={'reservationId':'env-new','token':'opaque-private','hostAlias':'archlinux','environment':'owned-linux-package-build-'+REQUEST['correlationId'],'operator':'root-tmux-build'}
  self.rows=[{'id':'env-old','hostAlias':'archlinux','requestedMemoryBytes':r.MEMORY,'allocationState':'pending'}, {'id':'env-new',**{k:v for k,v in self.identity.items() if k!='reservationId'},'requestedMemoryBytes':r.MEMORY,'allocationState':'pending','activeJob':'absent','activeJobEvidence':None}]
  self.path=self.root/'.rag_index/native-environments/reservations.json';r.closure.pipe._write_once(self.path,json.dumps({'version':1,'reservations':self.rows}).encode())
 def host(self):
  now=time.time_ns()//1000000
  samples=[{'observedAtUnixMs':now-100+i*100,'availableMemoryBytes':50*1024**3,'psi':'normal','vmstat':{'pswpin':0,'pswpout':0,'oomKill':0}} for i in range(2)]
  return {'state':'observed','hostBootId':REQUEST['correlationId'],'vms':[],'physicalMemoryBytes':64*1024**3,'swapUsedBytes':0,'samples':samples,'diskAvailableBytes':100*1024**3,'diskDevice':1,'inventoryComplete':True}
 def prepare(self):
  def query(root,program,payload,guard):guard();return self.host(),{'receipt':'retained'}
  with mock.patch.object(r.build,'preflight'),mock.patch.object(r,'sources',return_value={}),mock.patch.object(r,'fixed_resource_query',side_effect=query):return r.prepare(self.root,REQUEST,self.identity,source_root=self.root)
 def test_causal_missing_resource_binding_never_enters_build(self):
  with mock.patch.object(r.adapter,'McpTmuxDriver'),mock.patch.object(r.build,'start') as entered:
   with self.assertRaises((ValueError,FileNotFoundError)):r.operate(self.root,'start',REQUEST,source_root=self.root)
   entered.assert_not_called()
 def test_prepare_counts_old_reservation_and_preserves_all_rows(self):
  before=self.path.read_bytes();self.assertTrue(self.prepare()['resourceBound'])
  with mock.patch.object(r,'sources',return_value={}):record,_,_=r.load(self.root,REQUEST,self.root)
  self.assertEqual(r.MEMORY,record['plan']['reservedMemoryBytes']);self.assertEqual(2*r.MEMORY+2*1024**3,record['plan']['requiredMemoryBytes']);self.assertEqual(before,self.path.read_bytes())
 def test_old_unbound_row_cannot_be_adopted(self):
  identity={**self.identity,'reservationId':'env-old','environment':'owned-linux-package-build'}
  with self.assertRaises(ValueError):r.inventory(self.root,REQUEST,identity)
 def test_capacity_and_disk_and_incomplete_census_reject(self):
  for key,value in [('diskAvailableBytes',1),('physicalMemoryBytes',10*1024**3),('inventoryComplete',False)]:
   host=self.host();host[key]=value
   with self.assertRaises(ValueError):r.budget(host,[{'id':'env-old','memoryBytes':r.MEMORY}])
 def test_forged_qemu_and_private_measurement_reject(self):
  host=self.host();host['private']='/secret'
  with self.assertRaises(ValueError):r.budget(host,[])
  host=self.host();host['vms']=[{'pid':False}]
  with self.assertRaises(ValueError):r.budget(host,[])
 def test_admission_is_create_only_and_source_closed(self):
  self.prepare()
  with self.assertRaises((ValueError,FileExistsError)):self.prepare()
  with mock.patch.object(r,'sources',return_value={'changed':1}):
   with self.assertRaises(ValueError):r.load(self.root,REQUEST,self.root)
 def test_crossed_source_and_correlation_reject(self):
  self.prepare()
  with mock.patch.object(r,'sources',return_value={}):
   with self.assertRaises(ValueError):r.load(self.root,REQUEST,self.root/'foreign')
 def test_host_program_fixed_no_arbitrary_payload(self):
  program=r.host_program();compile(program,'<fixed>','exec')
  self.assertIn("principal=pwd.getpwuid(int(sudo_uid))",program);self.assertIn('vms!=vms2',program);self.assertNotIn('subprocess',program);self.assertNotIn('os.system',program)

 def test_stage_and_release_refresh_host_and_binding_drift_blocks_effect(self):
  self.prepare()
  with mock.patch.object(r,'sources',return_value={}):record,pin,seal=r.load(self.root,REQUEST,self.root)
  job=self.root/r.build._JOURNAL/REQUEST['correlationId'];job.mkdir(mode=0o700)
  driver=object.__new__(r.ResourceDriver);driver.root=self.root;driver.source_root=self.root
  payload={'request':r.old.purpose(REQUEST)}
  entered=[]
  def base(driver,program,payload,**kw):kw['guard']();entered.append(program);return {'state':'ok'}
  def query(root,program,payload,guard):guard();return record['host'],{}
  with mock.patch.object(r,'sources',return_value={}),mock.patch.object(r,'fixed_resource_query',side_effect=query) as host, mock.patch.object(r.adapter.McpTmuxDriver,'_query',new=base):
   driver._query(r.old._STAGE,payload,job=job,guard=lambda:None)
   driver._query(r.old._ACTION,{**payload,'action':'release'},job=job,guard=lambda:None)
   self.assertEqual(2,host.call_count);self.assertEqual(2,len(entered))
   changed=copy.deepcopy(record['host']);changed['hostBootId']='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';host.side_effect=lambda *args:(changed,{})
   with self.assertRaises(ValueError):driver._query(r.old._ACTION,{**payload,'action':'release'},job=job,guard=lambda:None)
   self.assertEqual(2,len(entered))
 def test_inventory_changed_during_host_probe_never_enters_stage(self):
  self.prepare()
  with mock.patch.object(r,'sources',return_value={}):record,pin,seal=r.load(self.root,REQUEST,self.root)
  job=self.root/r.build._JOURNAL/REQUEST['correlationId'];job.mkdir(mode=0o700)
  driver=object.__new__(r.ResourceDriver);driver.root=self.root;driver.source_root=self.root
  def query(root,program,payload,guard):
   self.path.write_bytes(self.path.read_bytes()+b' ');guard();return record['host'],{}
  with mock.patch.object(r,'sources',return_value={}),mock.patch.object(r,'fixed_resource_query',side_effect=query),mock.patch.object(r.adapter.McpTmuxDriver,'_query') as effect:
   with self.assertRaises(ValueError):driver._query(r.old._STAGE,{'request':r.old.purpose(REQUEST)},job=job,guard=lambda:None)
   effect.assert_not_called()

 def test_generated_host_program_reads_full_qemu_memory_and_safe_disk(self):
  import builtins,io,os,types
  from contextlib import redirect_stdout
  proc=self.root/'proc';proc.mkdir();(proc/'sys/kernel/random').mkdir(parents=True);(proc/'sys/kernel/random/boot_id').write_text(REQUEST['correlationId'])
  (proc/'1').mkdir();(proc/'1/comm').write_text('systemd\n');(proc/'1/ns').mkdir();(proc/'self/ns').mkdir(parents=True);(proc/'1/ns/pid').symlink_to('pid:[123]');(proc/'self/ns/pid').symlink_to('pid:[123]');(proc/'self/mountinfo').write_text('1 2 0:1 / /proc rw - proc proc rw\n');(proc/'1/stat').write_text('1 (systemd) '+' '.join(['S']+['0']*18+['1','0']));(proc/'1/exe').symlink_to('/sbin/init')
  (proc/'pressure').mkdir();(proc/'pressure/memory').write_text('some avg10=0.00\nfull avg10=0.00\n')
  (proc/'meminfo').write_text('MemAvailable: 52428800 kB\nMemTotal: 67108864 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n');(proc/'vmstat').write_text('pswpin 0\npswpout 0\noom_kill 0\n')
  process=proc/'123';process.mkdir();(process/'comm').write_text(getattr(self,'fixture_comm','7')+'\n');fields=['S']+['0']*20;fields[19]='456';fields[3]='123';(process/'stat').write_text('123 (qemu) '+' '.join(fields));(process/'cmdline').write_bytes(b'qemu-system-x86_64\0-m\0'+b'2048\0'+getattr(self,'cmdline_padding',b''));exe=self.root/'qemu-system-x86_64';exe.write_bytes(b'fixed');(process/'exe').symlink_to(exe)
  def mapped(value):return str(proc)+str(value)[5:] if isinstance(value,(str,Path)) and str(value).startswith('/proc') else value
  fakeos=types.SimpleNamespace(**{k:getattr(os,k) for k in dir(os)});fakeos.listdir=lambda path:os.listdir(mapped(path));fakeos.geteuid=lambda:0;fakeos.readlink=lambda path:os.readlink(mapped(path));fakeos.path=types.SimpleNamespace(**{k:getattr(os.path,k) for k in dir(os.path)});fakeos.path.exists=lambda path:os.path.exists(mapped(path));fakeos.stat=lambda path,*args,**kwargs:os.stat(mapped(path),*args,**kwargs)
  original_readlink=fakeos.readlink
  def readlink(path):
   if getattr(self,'unreadable_qemu_exe',False) and str(path)=='/proc/123/exe':raise PermissionError(13,'Permission denied')
   return original_readlink(path)
  fakeos.readlink=readlink
  original_import=builtins.__import__
  def imports(name,*args,**kwargs):return fakeos if name=='os' else original_import(name,*args,**kwargs)
  fakebuiltins={**vars(builtins),'__import__':imports,'open':lambda path,*args,**kwargs:builtins.open(mapped(path),*args,**kwargs)}
  fakepwd=types.SimpleNamespace(getpwuid=lambda uid:types.SimpleNamespace(pw_uid=os.getuid(),pw_dir=str(self.root)))
  real_join=fakeos.path.join
  fakeos.environ={**os.environ,'SUDO_UID':str(os.getuid())}
  fakeos.path.join=lambda parent,leaf:str(self.root) if parent==str(self.root) and leaf=='.vpn-control-mcp-fixtures' else real_join(parent,leaf)
  def imports(name,*args,**kwargs):return fakeos if name=='os' else fakepwd if name=='pwd' else original_import(name,*args,**kwargs)
  fakebuiltins['__import__']=imports
  output=io.StringIO();program=r.host_program()
  with mock.patch('sys.stdin',types.SimpleNamespace(buffer=io.BytesIO(b'{}'))),redirect_stdout(output):exec(program,{'__builtins__':fakebuiltins})
  value=json.loads(output.getvalue());self.assertTrue(value['inventoryComplete']);self.assertEqual(1,len(value['vms']));self.assertEqual(2*1024**3,value['vms'][0]['configuredMemoryBytes']);self.assertEqual(456,value['vms'][0]['startTicks']);self.assertNotIn('command',value['vms'][0])

 def test_prior_instance_bound_program_fails_same_new_epoch_control(self):
  import hashlib,types
  path=Path(__file__).parent/'fixtures/resource_instance/before.source';raw=path.read_bytes()
  self.assertEqual('a4b43bf9b62db221c2a81e88affee722f84325b25235ece3d1544efac4a8e50f',hashlib.sha256(raw).hexdigest())
  old=types.ModuleType('agent_tools._resource_before');old.__package__='agent_tools';old.__file__=str(path)
  exec(compile(raw,str(path),'exec'),old.__dict__)
  # The immutable predecessor requires its actual whole host producer. Its
  # exact source pin remains unchanged when today's transport wrapper evolves.
  host_path=path.with_name('native_host.before.source');host_raw=host_path.read_bytes()
  provenance=json.loads(host_path.with_name('native_host.provenance.json').read_bytes())
  self.assertEqual(old.HOST_SHA,provenance['sourceSha256'])
  self.assertEqual(old.HOST_SHA,hashlib.sha256(host_raw).hexdigest())
  prior_host=types.ModuleType('agent_tools._resource_before_native_host')
  prior_host.__package__='agent_tools';prior_host.__file__=str(host_path)
  exec(compile(host_raw,str(host_path),'exec'),prior_host.__dict__)
  old.host=prior_host
  for module,expect_failure in ((old,True),(r,False)):
   fixture=ResourceTests('runTest');fixture.setUp()
   try:
    method=fixture.test_generated_host_program_reads_full_qemu_memory_and_safe_disk
    with mock.patch.dict(method.__func__.__globals__,{'r':module}):
     if expect_failure:
      with self.assertRaisesRegex(ValueError,'resource_host_unknown'):method()
     else:method()
   finally:fixture.doCleanups()

 def test_generated_resource_program_keeps_actual_exe_eacces_unknown(self):
  self.unreadable_qemu_exe=True;self.fixture_comm='qemu-system-x86'
  with self.assertRaisesRegex(ValueError,'resource_process_unknown'):
   self.test_generated_host_program_reads_full_qemu_memory_and_safe_disk()

 def test_generated_resource_program_preserves_original_cmdline_bound(self):
  self.cmdline_padding=b'x'*20000+b'\0'
  with self.assertRaisesRegex(ValueError,'resource_identity_changed'):
   self.test_generated_host_program_reads_full_qemu_memory_and_safe_disk()

 def test_closed_privileged_query_retains_capture_and_checks_closing_source(self):
  import types,sys
  from agent_tools import ssh_direct_nested_channel as direct, ssh_transport
  authority=mock.MagicMock();authority.__enter__.return_value=authority
  authority.config=types.SimpleNamespace(hosts={'archlinux':types.SimpleNamespace(transport='nested',user='kardinal',password='inert-fixture-secret')})
  calls=[];real_popen=r.adapter.subprocess.Popen
  def launch(unused,*args,**kwargs):return real_popen([sys.executable,'-I','-B','-c','import sys;sys.stdin.buffer.read();print('+repr(json.dumps(self.host()))+')'],*args,**kwargs)
  with mock.patch.object(direct,'Guard',return_value=authority),mock.patch.object(ssh_transport,'build_ssh_argv',return_value=['ssh','fixed']) as argv,mock.patch.object(r.adapter.subprocess,'Popen',side_effect=launch) as launched,mock.patch.object(r.adapter,'_capture',wraps=r.adapter._capture) as collect:
   value,receipt=r.fixed_resource_query(self.root,r.host_program(),{},lambda:calls.append('guard'))
   self.assertEqual('observed',value['state']);self.assertTrue((self.root/receipt['directory']/'stdout').is_file())
   self.assertGreaterEqual(len(calls),4);self.assertEqual(1,collect.call_count);self.assertEqual(1,launched.call_count);self.assertEqual(b'inert-fixture-secret\n{}',collect.call_args.kwargs['payload']);self.assertEqual('sudo',argv.call_args.kwargs['command'][0]);self.assertNotIn('inert-fixture-secret',str(argv.call_args.kwargs['command']));self.assertEqual(30,collect.call_args.kwargs['timeout_seconds'])
  with mock.patch.object(direct,'Guard') as before:
   with self.assertRaisesRegex(ValueError,'resource_fixed_query_required'):r.fixed_resource_query(self.root,r.host_program(),{'arbitrary':'payload'},lambda:None)
   before.assert_not_called()

 def test_privileged_query_unknown_and_closing_guard_never_returns_resource(self):
  import types,sys
  from agent_tools import ssh_direct_nested_channel as direct, ssh_transport
  authority=mock.MagicMock();authority.__enter__.return_value=authority;authority.config=types.SimpleNamespace(hosts={'archlinux':types.SimpleNamespace(transport='nested',user='kardinal',password='inert-fixture-secret')})
  real_popen=r.adapter.subprocess.Popen
  with mock.patch.object(direct,'Guard',return_value=authority),mock.patch.object(ssh_transport,'build_ssh_argv',return_value=['ssh','fixed']):
   for body,reason in (("import sys;sys.stdin.buffer.read();sys.exit(1)",'resource_capture_unknown'),("import sys;sys.stdin.buffer.read();print('{}');sys.stderr.write('failure')",'resource_capture_changed')):
    def launch(unused,*args,**kwargs):return real_popen([sys.executable,'-I','-B','-c',body],*args,**kwargs)
    with mock.patch.object(r.adapter.subprocess,'Popen',side_effect=launch):
     with self.assertRaisesRegex(ValueError,reason):r.fixed_resource_query(self.root,r.host_program(),{},lambda:None)
   with mock.patch.object(r.adapter.subprocess,'Popen') as launched:
    with self.assertRaisesRegex(ValueError,'closing_changed'):r.fixed_resource_query(self.root,r.host_program(),{},lambda:(_ for _ in ()).throw(ValueError('closing_changed')))
    launched.assert_not_called()



class ResourcePortableSchemaTests(unittest.TestCase):
 def test_private_identity_schema_rejected_before_coordinator_io(self):
  for identity in ({},{'reservationId':False,'token':'private','hostAlias':'archlinux','environment':'anything','operator':'root-tmux-build'}):
   with self.subTest(identity=identity),self.assertRaisesRegex(ValueError,'resource_identity_invalid'):
    r.inventory(Path.cwd(),REQUEST,identity)
 def test_malformed_host_schema_rejected_without_transport(self):
  for value in ({},{'state':'observed','private':'secret'},False):
   with self.subTest(value=value),self.assertRaisesRegex(ValueError,'resource_measurement_invalid'):
    r.budget(value,[])
 def test_closed_host_program_factory_compiles_without_posix_execution(self):
  program=r.host_program();compile(program,'<portable-fixed-program>','exec')
  self.assertIn('resource_fixed_payload_required',program)
 def test_invalid_public_action_has_no_coordinator_effect(self):
  with self.assertRaisesRegex(ValueError,'resource_action_invalid'):
   r.operate(Path.cwd(),'arbitrary-command',{})
