import base64,importlib.util,json,os,pathlib,subprocess,sys,tempfile,unittest,uuid
P=pathlib.Path(os.environ.get('PARSER_SOURCE', pathlib.Path(__file__).resolve().parents[2]/'scripts/test_linux_public_install.py'));spec=importlib.util.spec_from_file_location('parser_under_test',P);m=importlib.util.module_from_spec(spec)
_import_path=list(sys.path)
try:
 sys.path.insert(0,str(P.parent));spec.loader.exec_module(m)
finally:sys.path[:]=_import_path
@unittest.skipUnless(os.name=='posix' and hasattr(os,'geteuid') and hasattr(os,'O_NOFOLLOW'),'Linux endpoint descriptor semantics require POSIX; native Linux gate retained')
class StrictAdmission(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.path=pathlib.Path(self.tmp.name)/'activation.port';self.cid=str(uuid.uuid4());self.token=base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip('=');self.value={'schemaVersion':1,'port':41689,'controllerId':self.cid,'token':self.token};self.write()
 def tearDown(self):self.tmp.cleanup()
 def write(self):self.path.write_text(json.dumps(self.value));self.path.chmod(0o600)
 def refuse(self):
  with self.assertRaises(RuntimeError)as e:m.endpoint_port(self.path,self.cid)
  self.assertEqual(str(e.exception),'private_endpoint_admission_failed');self.assertIsNone(e.exception.__cause__)
 def test_duplicate_key_refuses(self):
  raw=json.dumps(self.value);self.path.write_text('{"port":12345,'+raw[1:]);self.refuse()
 def test_boolean_schema_refuses(self):self.value['schemaVersion']=True;self.write();self.refuse()
 def test_float_schema_refuses(self):self.value['schemaVersion']=1.0;self.write();self.refuse()
 def test_fifo_refuses_without_waiting_for_writer(self):
  self.path.unlink();os.mkfifo(self.path,0o600)
  code="import importlib.util,sys; from pathlib import Path; sys.path.insert(0,str(Path(sys.argv[1]).parent)); s=importlib.util.spec_from_file_location('p',sys.argv[1]); m=importlib.util.module_from_spec(s); s.loader.exec_module(m)\ntry:m.endpoint_port(sys.argv[2],sys.argv[3])\nexcept RuntimeError as e:sys.exit(0 if str(e)=='private_endpoint_admission_failed' else 2)\nelse:sys.exit(3)"
  child=subprocess.Popen([sys.executable,'-B','-c',code,str(P),str(self.path),self.cid],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
  try:
   out,err=child.communicate(timeout=1);self.assertEqual(child.returncode,0);self.assertEqual(out,b'');self.assertEqual(err,b'')
  except subprocess.TimeoutExpired:
   child.terminate();out,err=child.communicate(timeout=3);self.fail('owned parser child blocked on FIFO; joined after SIGTERM')


import contextlib,io
@unittest.skipUnless(os.name=='posix' and hasattr(os,'geteuid') and hasattr(os,'O_NOFOLLOW'),'Linux endpoint descriptor semantics require POSIX; native Linux gate retained')
class EndpointRead(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.path=pathlib.Path(self.tmp.name)/'activation.port';self.cid=str(uuid.uuid4());self.token=base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip('=');self.value={'schemaVersion':1,'port':41689,'controllerId':self.cid,'token':self.token,'documentTransfers':True};self.write()
 def tearDown(self):self.tmp.cleanup()
 def write(self):self.path.write_text(json.dumps(self.value));self.path.chmod(0o600)
 def refuse(self):
  output=io.StringIO()
  with contextlib.redirect_stdout(output),contextlib.redirect_stderr(output):
   with self.assertRaises(RuntimeError)as e:m.endpoint_port(self.path,self.cid)
  self.assertEqual(str(e.exception),'private_endpoint_admission_failed');self.assertNotIn(self.token,output.getvalue());self.assertIsNone(e.exception.__cause__)
 def test_actual_schema_one_endpoint_returns_only_port(self):self.assertEqual(m.endpoint_port(self.path,self.cid),41689)
 def test_controller_mismatch_is_redacted(self):self.value['controllerId']=str(uuid.uuid4());self.write();self.refuse()
 def test_nonprivate_permissions_refuse(self):self.path.chmod(0o644);self.refuse()
 def test_boolean_port_refuses(self):self.value['port']=True;self.write();self.refuse()
 def test_invalid_token_refuses(self):self.value['token']='invalid';self.write();self.refuse()

@unittest.skipUnless(os.name=='posix' and hasattr(os,'geteuid'),'Linux proc identity fixture requires POSIX; native Linux gate retained')
class WaitClientSocket(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.proc=pathlib.Path(self.tmp.name);self.pid=1234;self.birth=4567;self.uid=os.geteuid();self.port=41689
  self.p=self.proc/str(self.pid);self.p.mkdir();(self.p/'fd').mkdir();(self.p/'net').mkdir()
  self.argv=['--state-dir','/fixture/workspace','--json','--controller-id',str(uuid.uuid4()),'operations','wait',str(uuid.uuid4())]
  self.write_birth(self.birth);(self.p/'cmdline').write_bytes(b'java\0'+b'\0'.join(p.encode()for p in self.argv)+b'\0')
  (self.p/'fd/3').symlink_to('socket:[777]')
  (self.p/'net/tcp').write_text('header\n 0: 0100007F:A000 0100007F:A2D9 01 0:0 0:0 0 0 0 777\n')
  (self.p/'net/tcp6').write_text('header\n')
 def tearDown(self):self.tmp.cleanup()
 def write_birth(self,value):(self.p/'stat').write_text('1234 (native waiter) S 1 0 0 '+' '.join(['0']*15+[str(value)]))
 def observe(self):return m._wait_client_socket_observation(self.proc,self.pid,self.birth,self.uid,self.port,self.argv)
 def test_exact_socket_and_argv_qualified(self):self.assertTrue(self.observe()['connectedToOwnedActivationPort'])
 def test_reused_pid_refuses(self):
  self.write_birth(self.birth+1)
  with self.assertRaisesRegex(RuntimeError,'identity differs'):self.observe()
 def test_foreign_uid_refuses(self):
  self.uid+=1
  with self.assertRaisesRegex(RuntimeError,'identity differs'):self.observe()
 def test_wrong_operation_refuses(self):
  self.argv[-1]=str(uuid.uuid4())
  with self.assertRaisesRegex(RuntimeError,'argv differs'):self.observe()
 def test_unowned_socket_not_admitted(self):
  (self.p/'fd/3').unlink();self.assertFalse(self.observe()['connectedToOwnedActivationPort'])
 def test_wrong_activation_port_not_admitted(self):self.port+=1;self.assertFalse(self.observe()['connectedToOwnedActivationPort'])


class FixedFixturePacing(unittest.TestCase):
 def setUp(self):
  import hashlib
  self.tmp=tempfile.TemporaryDirectory();self.path=pathlib.Path(self.tmp.name)/'target.deb';self.data=b'fixture'*20000;self.path.write_bytes(self.data)
  self.manifest={'assets':[{'fileName':'target.deb','platform':'linux','packageType':'deb','sizeBytes':len(self.data),'sha256':hashlib.sha256(self.data).hexdigest()}]}
  self.fixture=sys.modules['prepare_desktop_update_fixture'];self.chunks=[]
  self.wire=type('Wire',(),{'sendall':lambda _,chunk:self.chunks.append(chunk)})()
 def tearDown(self):self.tmp.cleanup()
 def response(self,resource='target.deb',paced=False):return self.fixture.write_resource_response(self.wire,resource,self.manifest,{'target.deb':self.path},b'{"manifest":true}',linux_update_wait_loss=paced)
 def test_default_bytes_are_unpaced(self):
  from unittest.mock import patch
  with patch.object(self.fixture.time,'sleep')as sleep:self.assertEqual(self.response(),len(self.data))
  sleep.assert_not_called();self.assertEqual(b''.join(self.chunks[1:]),self.data)
 def test_enabled_asset_preserves_bytes_and_uses_only_fixed_delay(self):
  from unittest.mock import patch
  with patch.object(self.fixture.time,'sleep')as sleep:self.assertEqual(self.response(paced=True),len(self.data))
  self.assertEqual(sleep.call_count,3);self.assertTrue(all(c.args==(0.012,)for c in sleep.call_args_list));self.assertEqual(b''.join(self.chunks[1:]),self.data)
 def test_manifest_remains_unpaced(self):
  from unittest.mock import patch
  with patch.object(self.fixture.time,'sleep')as sleep:self.response('manifest',True)
  sleep.assert_not_called();self.assertTrue(self.chunks[0].endswith(b'{"manifest":true}'))
 def test_frozen_source_tamper_refuses_before_response(self):
  self.path.write_bytes(b'tamper')
  with self.assertRaisesRegex(ValueError,'Frozen package changed'):self.response(paced=True)
  self.assertEqual(self.chunks,[])

class UsedRoute(unittest.TestCase):
 def test_package_update_fixed_argv_enables_recovery_and_rollback_excludes_it(self):
  from unittest.mock import patch
  import types
  path=pathlib.Path(os.environ.get('LINUX_DRIVER_SOURCE',P.parents[1]/'agent_tools/linux_deb_arch_native_driver.py'))
  spec=importlib.util.spec_from_file_location('owned_native_driver',path);driver=importlib.util.module_from_spec(spec);spec.loader.exec_module(driver)
  with tempfile.TemporaryDirectory()as temp:
   stage=pathlib.Path(temp);(stage/'target.deb').write_bytes(b'guarded-package')
   intent={'distribution':'ubuntu','profile':'package-update','targetSha256':'a'*64,'trustStoreSha256':'b'*64,'harnessSha256':'c'*64,'sourceFingerprint':'d'*64,'fixtureReceiptArtifactId':'fixture-id','targetVersion':'2.2.2'}
   receipt={'sourceFingerprint':intent['sourceFingerprint'],'derivedFrom':{'derivedFromArtifactId':'fixture-id'}};ready={'sourceFingerprint':intent['sourceFingerprint'],'port':41689}
   def digest(path,**_):return intent['targetSha256']if path.name=='target.deb'else intent['trustStoreSha256']if path.name=='trust.jks'else intent['harnessSha256']
   def read(path,**_):return json.dumps(receipt if path.name=='fixture-receipt.json'else ready).encode()
   with patch.object(driver,'_sha_staged_file',side_effect=digest),patch.object(driver,'_read_small_owned',side_effect=read),patch.object(pathlib.Path,'lstat',return_value=types.SimpleNamespace(st_mode=0o40755,st_uid=0)):
    argv,_=driver._update_setup(intent,stage)
    self.assertIn('--cleanup-synthetic-workspace',argv);self.assertNotIn('--preserve-existing-fixture-password',argv);self.assertIn('--download-wait-client-loss',argv);self.assertEqual(argv[argv.index('--download-target-bytes')+1],str(len(b'guarded-package')));self.assertEqual(argv[argv.index('--download-target-sha256')+1],intent['targetSha256'])
    intent['profile']='arch-rollback';argv,_=driver._update_setup(intent,stage);self.assertNotIn('--download-wait-client-loss',argv)
 def test_current_serve_parser_calls_fixed_enabled_bool(self):
  from unittest.mock import patch
  fixture=sys.modules['prepare_desktop_update_fixture']
  args=['fixture','serve','--directory','/fixture','--certificate','/cert','--private-key','/key','--ready-file','/ready','--confirm-owned-disposable-guest','--linux-update-wait-loss']
  with patch.object(sys,'argv',args),patch.object(fixture,'serve')as serve:fixture.main()
  self.assertTrue(serve.call_args.kwargs['linux_update_wait_loss'])
 def test_connection_routes_enabled_bool_to_actual_response(self):
  from unittest.mock import patch
  fixture=sys.modules['prepare_desktop_update_fixture'];chunks=[]
  wire=type('Wire',(),{'sendall':lambda _,chunk:chunks.append(chunk),'close':lambda _:None})()
  tls=type('Tls',(),{'wrap_socket':lambda _,request,server_side:wire})()
  with patch.object(fixture,'read_request_header',side_effect=[('CONNECT','github.com:443','github.com'),('GET','asset','github.com',[])]),patch.object(fixture,'select_resource',return_value='asset'),patch.object(fixture,'write_resource_response',return_value=123)as response,contextlib.redirect_stdout(io.StringIO()):
   fixture.serve_connection(wire,tls,{}, {},b'',lambda _:None,linux_update_wait_loss=True)
  self.assertTrue(response.call_args.kwargs['linux_update_wait_loss'])

@unittest.skipUnless(os.name=='posix' and hasattr(os,'geteuid'),'Linux cleanup descriptors require POSIX; native acceptance retained')
class CleanupAdmission(unittest.TestCase):
 def admit_until_artifact_boundary(self,*,preserve=False):
  from unittest.mock import patch
  import types
  class ArtifactBoundary(Exception):pass
  with patch.object(m.os,'uname',return_value=types.SimpleNamespace(sysname='Linux')),patch.object(m.os,'getuid',return_value=1000),patch.object(pathlib.Path,'resolve',side_effect=ArtifactBoundary),patch.object(m,'require_human_terminal'):
   with self.assertRaises(ArtifactBoundary):
    m.run(pathlib.Path('/fixture/native/launcher'),'2.2.2',True,same_source_recovery=True,
          retained_fixture_auth=True,preserve_existing_fixture_password=preserve,
          cleanup_synthetic_workspace_after_success=True)
 def test_locked_baseline_restores_and_actual_request_admits_cleanup(self):
  from unittest.mock import patch
  import types
  from scripts import linux_fixture_auth as auth
  uid=os.geteuid();account=lambda _:types.SimpleNamespace(pw_name='vpnfixture',pw_uid=uid);calls=[]
  def runner(argv,**kwargs):
   calls.append(argv)
   return types.SimpleNamespace(returncode=0,stdout='vpnfixture L 2026-09-24 0 99999 7 -1'if argv[:2]==['passwd','--status']else'')
  with tempfile.TemporaryDirectory(prefix='vpn-public-install-evidence-')as tmp:
   evidence=pathlib.Path(tmp).resolve();evidence.chmod(0o700);directory=evidence/'auth';workspace=evidence/'workspace';workspace.mkdir(mode=0o700);(workspace/'owned').write_text('synthetic')
   identity=dict(platform='linux',geteuid=lambda:uid,account_lookup=account)
   auth.prepare(credential_dir=directory,correlation='owned-causal-L',purpose=auth.PURPOSE,guest_confirmation=auth.OWNED_GUEST_CONFIRMATION,runner=runner,password_factory=lambda:'inert-unit-value',**identity)
   restored=auth.restore(credential_dir=directory,correlation='owned-causal-L',terminal_receipt={'correlation':'owned-causal-L','final':True},terminal_validator=lambda r,c:r['correlation']==c and r['final']is True,runner=runner,**identity)
   self.assertTrue(restored['restored']);self.assertFalse(directory.exists());self.assertIn(['sudo','-n','passwd','--lock','--','vpnfixture'],calls)
   self.admit_until_artifact_boundary()
   owner=types.SimpleNamespace(poll=lambda:0)
   # Explicit kernel observation seam: host regression, not native absence proof.
   with patch.object(m,'_no_process_uses_workspace',return_value=None):
    m.cleanup_synthetic_workspace(workspace,evidence,owner,True,True,restored['restored'])
   self.assertFalse(workspace.exists())
 def test_preserved_password_request_stays_admitted(self):self.admit_until_artifact_boundary(preserve=True)
 def test_unrestored_credential_cannot_remove_workspace(self):
  import types
  with tempfile.TemporaryDirectory(prefix='vpn-public-install-evidence-')as tmp:
   evidence=pathlib.Path(tmp);workspace=evidence/'workspace';workspace.mkdir()
   with self.assertRaisesRegex(RuntimeError,'restored credential'):
    m.cleanup_synthetic_workspace(workspace,evidence,types.SimpleNamespace(poll=lambda:0),True,True,False)
   self.assertTrue(workspace.exists())
 def test_unknown_recovery_cannot_remove_workspace(self):
  import types
  with tempfile.TemporaryDirectory(prefix='vpn-public-install-evidence-')as tmp:
   evidence=pathlib.Path(tmp);workspace=evidence/'workspace';workspace.mkdir()
   with self.assertRaisesRegex(RuntimeError,'terminal protected recovery'):
    m.cleanup_synthetic_workspace(workspace,evidence,types.SimpleNamespace(poll=lambda:0),True,False,True)
   self.assertTrue(workspace.exists())

if __name__=='__main__':unittest.main()
