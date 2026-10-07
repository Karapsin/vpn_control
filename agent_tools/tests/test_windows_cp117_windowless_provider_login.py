import ast,base64,hashlib,inspect,json,os,unittest,shutil,subprocess
from pathlib import Path
from unittest.mock import patch
if os.name!='nt':
 from agent_tools import windows_cp117_windowless_provider_login as m

@unittest.skipIf(os.name=='nt','POSIX coordinator source checks')
class OriginalStdinTests(unittest.TestCase):
 def test_actual_creation_boundary_no_inherited_stdin_requires_owned_duplicate(self):
  old=m.role.secure._NATIVE
  self.assertIn('SI s=new SI();s.cb=Marshal.SizeOf(typeof(SI));s.desktop=',old)
  self.assertIn('IntPtr.Zero,false,0x08000004',old)
  self.assertNotIn('s.input=',old);self.assertNotIn('DuplicateInput',old)
  new=m.native_source();self.assertIn('Held(p);if(expired||inputDuplicated)',new)
  self.assertIn('Session(p)!=1||Birth(p)!=birth',new);self.assertIn('GetFileType(input)!=3',new)
  self.assertIn('p.process,out duplicate,0,false,2',new)
  self.assertLess(new.index('inputDuplicated=true;'),new.index('if(!DuplicateHandle('))
  self.assertIn('GetStdHandle(-10)!=input',new);self.assertIn(m.role.secure._NATIVE.split(' public static bool Cleanup()')[1].split(' public static uint Resume')[0],new)
 def test_framed_original_stdin_is_memory_only_and_bounded_utf8(self):
  secret='inert-κ-test'.encode();parent=m.bodies()[0];payload=m.private_stdin(parent,secret)
  n=int.from_bytes(payload[:4],'big');self.assertEqual(payload[4:4+n],parent.encode());left=payload[4+n:];childn=int.from_bytes(left[:4],'big');self.assertEqual(left[4:4+childn],m._parts()[3].encode());left=left[4+childn:];self.assertEqual(int.from_bytes(left[:4],'big'),len(secret));self.assertEqual(left[4:],secret)
  for bad in(b'',b'x'*513,b'bad\x00',b'bad\xff'):
   with self.assertRaises(ValueError):m.private_stdin('public',bad)
  with self.assertRaises(ValueError):m.private_stdin('x'*65537,b'inert')
 def test_modified_consumed_reader_refused_before_any_derived_native_source(self):
  with patch.object(m.role,'_factories',side_effect=ValueError('changed')):
   with self.assertRaises(ValueError):m.native_source()

@unittest.skipIf(os.name=='nt','POSIX fixed source generation')
class StagedChildTests(unittest.TestCase):
 def test_actual_full_child_uses_bound_public_stdin_stage_under_windows_command_cap(self):
  parent,child,sha=m.bodies()
  self.assertLessEqual(len(base64.b64encode(child.encode('utf-16le'))),30000)
  self.assertLessEqual(len(parent.encode()),65536)
  self.assertIn('PROVIDER_CHILD_SOURCE_HASH',child)
  self.assertIn('DuplicateInput($pi,$birth)',parent)

@unittest.skipIf(os.name=='nt','POSIX full transport coordinator')
class CompletePrivateFlowTests(unittest.TestCase):
 def answer(self):
  from agent_tools.tests.test_windows_cp117_windowless_gui_login import RoleTests
  a=RoleTests().answer(False);a['reader']['nonce']=a['birth']['nonce']=m.NONCE;a['reader']['sourceSha256']=a['birth']['sourceSha256']=m.CHILD_SHA
  a['facts']['providerWrite']={'cleared':True,'typed':True,'contentRead':False,'credentialLogged':False};return a
 def terminal(self,nonce=None):
  return {'exited':True,'exitcode':0,'out-data':base64.b64encode(('CP117-READ '+(nonce or m.NONCE)+' '+m.PARENT_SHA+' 456\n'+json.dumps(self.answer())).encode()).decode()}
 def execute(self,stale=False,foreign=False):
  import textwrap,io
  from agent_tools.tests.test_windows_cp117_secure_layout_observe import CompleteGeneratedFlowTests
  class Input:
   buffer=io.BytesIO((len(b'PUBLIC-INERT-PIPE')).to_bytes(4,'big')+b'PUBLIC-INERT-PIPE')
   def __init__(self,ack):self.ack=ack
   def readline(self):return self.ack+'\n'
  source=textwrap.dedent(inspect.getsource(CompleteGeneratedFlowTests.execute_flow)).replace('secure.program(record,secure.NONCE)','m.program(record)').replace('secure.CORRELATION','m.CORRELATION').replace('secure.NONCE','m.NONCE').replace("stdin=io.StringIO(ack+'\\n')","stdin=Input(ack)")
  # Explicit literal replacement checked so the fixture executes the real
  # binary secret read before original durable child/ACK/status composition.
  if 'stdin=Input(ack)' not in source:raise AssertionError('stdin fixture binding')
  ns={'ast':ast,'base64':base64,'json':json,'patch':patch,'secure':m.role.secure,'m':m,'Input':Input};exec(source,ns)
  return ns['execute_flow'](self,stale,foreign)
 def test_entire_generated_one_submit_original_pipe_frames_no_secret_source_or_output(self):
  result,calls,_=self.execute();self.assertEqual(result['state'],'observed');self.assertEqual(result['facts'],self.answer())
  self.assertEqual([op for op,_ in calls],['guest-exec','guest-exec-status']);self.assertEqual(calls[1][1],{'pid':456})
  actual=base64.b64decode(calls[0][1]['input-data']);self.assertEqual(actual,m.private_stdin(m.bodies()[0],b'PUBLIC-INERT-PIPE'))
  from agent_tools.tests.test_windows_cp117_windowless_dismiss_observe import DismissTests
  generated=m.program(DismissTests().record())[0]
  self.assertNotIn('PUBLIC-INERT-PIPE',generated);self.assertNotIn('PUBLIC-INERT-PIPE',json.dumps(result))
 def test_entire_generated_stale_terminal_exhausts_same_original_child_no_resubmit(self):
  result,calls,_=self.execute(stale=True);self.assertEqual(result['state'],'unknown');self.assertEqual(len(calls),81)
  self.assertEqual(sum(op=='guest-exec'for op,_ in calls),1);self.assertTrue(all(a=={'pid':456}for op,a in calls if op=='guest-exec-status'))
 def test_entire_generated_foreign_socket_zero_submit(self):
  result,calls,_=self.execute(foreign=True);self.assertEqual(result['state'],'unknown');self.assertEqual(calls,[])

@unittest.skipIf(os.name=='nt','POSIX original VM transport fixture')
class CompleteInertPipeFlowTests(CompletePrivateFlowTests):
 def test_retained_actual_parser_bytes_survive_named_source_exchange(self):
  import tempfile
  raw=Path(m.__file__).read_bytes();pin=hashlib.sha256(raw).hexdigest();_,_,child_sha,_=m._parts(True)
  value=self.terminal();parent_sha=hashlib.sha256(m._parts(True)[0].encode('utf-16le')).hexdigest()
  with tempfile.TemporaryDirectory()as tmp:
   path=Path(tmp)/'helper.py';path.write_bytes(raw);held=path.read_bytes()
   path.write_text("def _inert_terminal(*args): return {'foreign':True}\n")
   # Execute the exact former inspect.getsource call boundary with a held function.
   oldpath=Path(tmp)/'old-parser.py';original="def _inert_terminal(*args):\n return {'original':True}\n";oldpath.write_text(original)
   retained={};exec(compile(original,str(oldpath),'exec'),retained)
   oldpath.write_text("def _inert_terminal(*args):\n globals()['foreignExecuted']=True;return {'foreign':True}\n")
   namespace={};exec(compile(inspect.getsource(retained['_inert_terminal']),'old-reopen','exec'),namespace)
   self.assertEqual(namespace['_inert_terminal'](),{'foreign':True});self.assertTrue(namespace['foreignExecuted'])
   self.assertEqual(m._retained_inert_terminal(held,pin,child_sha,value,m.INERT_NONCE,parent_sha,456),self.answer())
   with self.assertRaises(ValueError):m._retained_inert_terminal(path.read_bytes(),pin,child_sha,value,m.INERT_NONCE,parent_sha,456)
 def test_actual_generated_native_uppercase_application_digest_is_hex_not_new_authority(self):
  answer=self.answer();answer['birth']['applicationSha256']='8BB6FA8C283B4D92120B1EF249A9B311B0F804D4CABBE9981159976C8BE76A5E'
  with patch.object(self,'answer',return_value=answer):
   result,calls,_=self.execute()
  self.assertEqual(result['state'],'observed');self.assertEqual(result['facts'],answer)
  self.assertEqual([op for op,_ in calls],['guest-exec','guest-exec-status'])
  for malformed in ('G'*64,'a'*63,'a'*65,'a'*63+' '):
   bad=json.loads(json.dumps(answer));bad['birth']['applicationSha256']=malformed
   with patch.object(self,'answer',return_value=bad):
    result,calls,_=self.execute()
   self.assertEqual(result['state'],'unknown');self.assertEqual(len(calls),2)
 def answer(self):
  _,_,sha,_=m._parts(True)
  return {'facts':{'version':1,'originalStdinPipe':True,'publicFramesPassed':True,'providerCompiled':True,'credentialInput':False,'providerInvoked':False,'keyboardAction':False},'reader':{'nonce':m.INERT_NONCE,'pid':789,'parentPid':456,'sessionId':1,'expectedSystem':True,'creationFileTime':'123','sourceSha256':sha},'birth':{'nonce':m.INERT_NONCE,'pid':789,'parentPid':456,'sessionId':1,'creationFileTime':'123','sourceSha256':sha,'applicationSha256':'a'*64}}
 def terminal(self,nonce=None):
  sha=hashlib.sha256(m._parts(True)[0].encode('utf-16le')).hexdigest()
  return {'exited':True,'exitcode':0,'out-data':base64.b64encode(('CP117-READ '+(nonce or m.INERT_NONCE)+' '+sha+' 456\n'+json.dumps(self.answer())).encode()).decode()}
 def execute(self,stale=False,foreign=False):
  import textwrap,io
  from agent_tools.tests.test_windows_cp117_secure_layout_observe import CompleteGeneratedFlowTests
  class Input:
   buffer=io.BytesIO(len(m.PUBLIC_SENTINEL).to_bytes(4,'big')+m.PUBLIC_SENTINEL)
   def __init__(self,ack):self.ack=ack
   def readline(self):return self.ack+'\n'
  source=textwrap.dedent(inspect.getsource(CompleteGeneratedFlowTests.execute_flow)).replace('secure.program(record,secure.NONCE)','m.inert_program(record)').replace('secure.CORRELATION','m.INERT_CORRELATION').replace('secure.NONCE','m.INERT_NONCE').replace("stdin=io.StringIO(ack+'\\n')","stdin=Input(ack)")
  ns={'ast':ast,'base64':base64,'json':json,'patch':patch,'secure':m.role.secure,'m':m,'Input':Input};exec(source,ns)
  return ns['execute_flow'](self,stale,foreign)
 def test_entire_generated_one_submit_original_pipe_frames_no_secret_source_or_output(self):
  result,calls,_=self.execute();self.assertEqual(result['state'],'observed');self.assertEqual(result['facts'],self.answer())
  self.assertEqual([op for op,_ in calls],['guest-exec','guest-exec-status']);self.assertEqual(calls[1][1],{'pid':456})
  parent,child,sha,public=m._parts(True);payload=base64.b64decode(calls[0][1]['input-data']);self.assertEqual(payload,m._public_frames(parent,True)+len(m.PUBLIC_SENTINEL).to_bytes(4,'big')+m.PUBLIC_SENTINEL)
  self.assertNotIn('::SetExact(',public);self.assertNotIn('::Read([',public);self.assertNotIn('LogonUser',public);self.assertIn('::ReadSecret($privateInput)',public)
  self.assertIn('SetValue(value)',public) # Compile only, never invoked.
 def test_fixed_mode_and_actual_parser_reject_poisoned_action_or_birth(self):
  from agent_tools.tests.test_windows_cp117_windowless_dismiss_observe import DismissTests
  src,sha=m.inert_program(DismissTests().record());tree=ast.parse(src);ns={}
  with patch('signal.signal'),patch('signal.setitimer'):exec(compile(ast.Module(body=tree.body[:-1],type_ignores=[]),'inert-definitions','exec'),ns)
  self.assertEqual(ns['_inert_terminal'](self.terminal(),m.INERT_NONCE,sha,456),self.answer())
  for key,val in [('credentialInput',True),('keyboardAction',True),('originalStdinPipe',1)]:
   a=self.answer();a['facts'][key]=val;t=self.terminal();t['out-data']=base64.b64encode(('CP117-READ '+m.INERT_NONCE+' '+sha+' 456\n'+json.dumps(a)).encode()).decode()
   with self.assertRaises(ValueError):ns['_inert_terminal'](t,m.INERT_NONCE,sha,456)
  with self.assertRaises(ValueError):m._parts('arbitrary')


def input_execution_script():
 # Windows does not import POSIX coordinator modules. Extract exact literal
 # production method bodies for the mandatory executable pipe regression.
 tree=ast.parse((Path(__file__).parents[1]/'windows_cp117_windowless_provider_login.py').read_text())
 constants={n.targets[0].id:ast.literal_eval(n.value)for n in tree.body if isinstance(n,ast.Assign)and len(n.targets)==1 and isinstance(n.targets[0],ast.Name)and n.targets[0].id in('_INPUT_CS','_DUPLICATE_CS')}
 fixture="""using System;using System.Runtime.InteropServices;
public static class CP117SessionRead{
 public struct PI{public IntPtr process;public uint pid;}static object ownership=new object();static bool expired=false;
 public static int Generation=1;public static int CurrentSession=1;
 static void Held(PI p){if(p.process!=GetCurrentProcess()||p.pid!=(uint)System.Diagnostics.Process.GetCurrentProcess().Id)throw new InvalidOperationException("FOREIGN_HELD");}
 static string Birth(PI p){return Generation.ToString();}static int Session(PI p){return CurrentSession;}
 [DllImport("kernel32.dll")]static extern IntPtr GetCurrentProcess();
 __METHOD__
 public static long Probe(){return DuplicateInput(new PI{process=GetCurrentProcess(),pid=(uint)System.Diagnostics.Process.GetCurrentProcess().Id},"1");}
}""".replace('__METHOD__',constants['_DUPLICATE_CS'])
 return "Add-Type -TypeDefinition @'\n"+constants['_INPUT_CS']+"\n'@\nAdd-Type -TypeDefinition @'\n"+fixture+"\n'@\n"+r"""
$ErrorActionPreference='Stop'
function Reject($raw){$f=[IO.MemoryStream]::new([byte[]]$raw);try{try{[CP117OriginalInput]::ReadSecret($f)|Out-Null;throw 'ACCEPTED_UNSAFE'}catch{if($_.Exception.GetBaseException().Message -cne 'PROVIDER_INPUT_FAILED'){throw}}}finally{$f.Dispose()}}
Reject ([byte[]]@(0,0,0,0));Reject ([byte[]]@(0,0,2,1));Reject ([byte[]]@(0,0,0,1));Reject ([byte[]]@(0,0,0,1,255));Reject ([byte[]]@(0,0,0,1,0));Reject ([byte[]]@(0,0,0,1,65,66))
[CP117SessionRead]::Generation=2;try{[CP117SessionRead]::Probe()|Out-Null;throw 'BAD_BIRTH_ACCEPTED'}catch{if($_.Exception.GetBaseException().Message -cne 'PROVIDER_INPUT_CHILD'){throw}}
[CP117SessionRead]::Generation=1;[CP117SessionRead]::CurrentSession=0;try{[CP117SessionRead]::Probe()|Out-Null;throw 'BAD_SESSION_ACCEPTED'}catch{if($_.Exception.GetBaseException().Message -cne 'PROVIDER_INPUT_CHILD'){throw}}
[CP117SessionRead]::CurrentSession=1;$handle=[CP117SessionRead]::Probe();$pipe=[CP117OriginalInput]::Open($handle)
try{$raw=[CP117OriginalInput]::ReadSecret($pipe);if([Text.Encoding]::UTF8.GetString($raw) -cne 'PIPE-OS-INERT'){throw 'PIPE_CONTENT'};[Array]::Clear($raw,0,$raw.Length)}finally{$pipe.Dispose()}
try{[CP117SessionRead]::Probe()|Out-Null;throw 'REPLAY_ACCEPTED'}catch{if($_.Exception.GetBaseException().Message -cne 'PROVIDER_INPUT_CONSUMED'){throw}}
[Console]::Out.WriteLine('CP117_PIPE_CASES_PASS')
"""

@unittest.skipUnless(os.name=='nt'and shutil.which('powershell'),'Windows pipe execution required')
class WindowsOriginalPipeExecutionTests(unittest.TestCase):
 def test_actual_duplicate_pipe_and_strict_input_source_negative_cases(self):
  import tempfile
  with tempfile.TemporaryDirectory()as d:
   path=Path(d)/'fixed.ps1';path.write_text(input_execution_script(),encoding='utf-8')
   public=b'PIPE-OS-INERT';r=subprocess.run(['powershell','-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',str(path)],input=len(public).to_bytes(4,'big')+public,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20)
  self.assertEqual(r.returncode,0,r.stderr.decode(errors='replace'));self.assertEqual(r.stdout.decode().strip(),'CP117_PIPE_CASES_PASS');self.assertEqual(r.stderr,b'')

@unittest.skipIf(os.name=='nt','POSIX local observer stream')
class ActualStreamNamespaceTests(unittest.TestCase):
 def test_actual_original_stream_time_nameerror_after_launch_before_private_write(self):
  from unittest.mock import MagicMock
  process=MagicMock();selector=MagicMock()
  self.assertNotIn('time',m.role._stream.__globals__)
  with patch('subprocess.Popen',return_value=process)as launch,patch('selectors.DefaultSelector',return_value=selector):
   with self.assertRaisesRegex(NameError,"time"):m.role._stream(['fixed-inert'],MagicMock(),m.INERT_CORRELATION,m.INERT_NONCE,'a'*64,{'pid':1},m.PUBLIC_SENTINEL)
  launch.assert_called_once();process.stdin.write.assert_not_called()
 def test_new_actual_stream_explicit_time_context_captures_exit_without_private_input_log(self):
  from unittest.mock import MagicMock
  process=MagicMock();process.wait.return_value=1;process.poll.return_value=1;selector=MagicMock();selector.get_map.return_value={};capture=MagicMock();capture.fd=1
  with patch('subprocess.Popen',return_value=process),patch('selectors.DefaultSelector',return_value=selector),patch.object(m.os,'fsync'):
   with self.assertRaisesRegex(ValueError,'gui-observer-exit'):m._stream(['fixed-inert'],capture,m.INERT_CORRELATION,m.INERT_NONCE,'a'*64,{'pid':1},m.PUBLIC_SENTINEL)
  process.stdin.write.assert_called_once_with(len(m.PUBLIC_SENTINEL).to_bytes(4,'big')+m.PUBLIC_SENTINEL)
  self.assertEqual([c.args[1]for c in capture.create.call_args_list],[b'',b''])
  process.kill.assert_not_called();process.stdin.close.assert_called_once()

@unittest.skipIf(os.name=='nt','POSIX actual stream assembly')
class ActualStreamPositiveTests(unittest.TestCase):
 def test_actual_fixed_stream_one_input_ack_same_child_raw_retention(self):
  import types
  from unittest.mock import MagicMock
  process=MagicMock();process.wait.return_value=0;process.poll.return_value=0;process.stdout.fileno.return_value=10;process.stderr.fileno.return_value=11
  class Selector:
   def __init__(self):self.keys={}
   def register(self,file,event,data):self.keys[file.fileno()]=types.SimpleNamespace(fileobj=file,data=data)
   def get_map(self):return self.keys
   def select(self,n):return [(k,1)for k in list(self.keys.values())]
   def unregister(self,k):del self.keys[k.fileno()]
   def close(self):pass
  sha='a'*64;qemu={'pid':1};base={'diagnosticId':m.INERT_CORRELATION,'nonce':m.INERT_NONCE,'sourceSha256':sha,'qemu':qemu,'pid':456}
  events=b''.join(b'CP117-OBSERVE '+json.dumps(dict(base,kind=k)).encode()+b'\n'for k in('submitted','terminal'))
  data={10:[b'{"state":"observed","facts":{"public":true}}',b''],11:[events,b'']};capture=MagicMock();capture.fd=1;capture.create.return_value={'retained':True}
  with patch('subprocess.Popen',return_value=process),patch('selectors.DefaultSelector',side_effect=Selector),patch.object(m.os,'fsync'),patch.object(m.os,'read',side_effect=lambda f,n:data[f].pop(0)):
   out,retained=m._stream(['fixed-public'],capture,m.INERT_CORRELATION,m.INERT_NONCE,sha,qemu,m.PUBLIC_SENTINEL)
  self.assertEqual(out,{'state':'observed','facts':{'public':True}});self.assertEqual([r['event']['kind']for r in retained],['submitted','terminal'])
  self.assertEqual(process.stdin.write.call_args_list[0].args[0],len(m.PUBLIC_SENTINEL).to_bytes(4,'big')+m.PUBLIC_SENTINEL)
  self.assertEqual(len(process.stdin.write.call_args_list),2);self.assertEqual(len(capture.create.call_args_list),4)
  self.assertNotIn(m.PUBLIC_SENTINEL,b''.join(c.args[1]for c in capture.create.call_args_list));process.kill.assert_not_called()

@unittest.skipIf(os.name=='nt','POSIX fixed parent generator')
class ExactStdinProtectionTests(unittest.TestCase):
 def test_actual_parent_protects_metadata_after_durable_create_before_resume(self):
  parent=m._parts(True)[0];create=parent.index("WritePrivate 'stdin.json'");protect=parent.index("[IO.File]::SetAccessControl((Join-Path $dir 'stdin.json')")
  self.assertLess(create,protect);self.assertLess(protect,parent.index('::Resume($pi)'))
  self.assertIn("$inputAcl.SetSecurityDescriptorSddlForm('O:SYG:SYD:P(A;;FA;;;SY)')",parent)


def stdin_acl_execution_script():
 tree=ast.parse((Path(__file__).parents[1]/'windows_cp117_windowless_provider_login.py').read_text());read=next(ast.literal_eval(n.value)for n in tree.body if isinstance(n,ast.Assign)and isinstance(n.targets[0],ast.Name)and n.targets[0].id=='_INPUT_READ')
 start=read.index('$acl=[IO.File]::GetAccessControl($inputPath);');end=read.index(' $info=[IO.FileInfo]')
 admission=read[start:end].replace('$acl=[IO.File]::GetAccessControl($inputPath);','')
 return "function Admission($acl){\n"+admission+"\n}\n"+r"""
$ErrorActionPreference='Stop'
$old=[Security.AccessControl.FileSecurity]::new();$old.SetSecurityDescriptorSddlForm('O:BAG:SYD:(A;;FA;;;SY)(A;;0x1200a9;;;BA)')
try{Admission $old;throw 'UNSAFE_ACCEPTED'}catch{if($_.Exception.GetBaseException().Message -cne 'PROVIDER_INPUT_ACL'){throw}}
$fixed=[Security.AccessControl.FileSecurity]::new();$fixed.SetSecurityDescriptorSddlForm('O:SYG:SYD:P(A;;FA;;;SY)');Admission $fixed
foreach($bad in @('O:BAG:SYD:P(A;;FA;;;SY)','O:SYG:BAD:P(A;;FA;;;SY)','O:SYG:SYD:(A;;FA;;;SY)','O:SYG:SYD:P(A;;FA;;;SY)(A;;FR;;;BA)','O:SYG:SYD:P(A;;FR;;;SY)')){$acl=[Security.AccessControl.FileSecurity]::new();$acl.SetSecurityDescriptorSddlForm($bad);try{Admission $acl;throw 'UNSAFE_ACCEPTED'}catch{if($_.Exception.GetBaseException().Message -cne 'PROVIDER_INPUT_ACL'){throw}}}
[Console]::Out.WriteLine('CP117_STDIN_ACL_CASES_PASS')
"""

@unittest.skipUnless(os.name=='nt'and shutil.which('powershell'),'Windows real FileSecurity required')
class WindowsActualStdinAclTests(unittest.TestCase):
 def test_measured_writer_descriptor_fails_actual_reader_explicit_parent_policy_passes(self):
  encoded=base64.b64encode(stdin_acl_execution_script().encode('utf-16le')).decode()
  r=subprocess.run(['powershell','-NoProfile','-NonInteractive','-EncodedCommand',encoded],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20)
  self.assertEqual(r.returncode,0,r.stderr.decode(errors='replace'));self.assertEqual(r.stdout.decode().strip(),'CP117_STDIN_ACL_CASES_PASS');self.assertEqual(r.stderr,b'')

@unittest.skipIf(os.name=='nt','POSIX complete login coordinator')
class CompleteLoginSequenceTests(unittest.TestCase):
 def auth(self):return {'state':'observed','credential':{'operation':'windows-credential-validity-v1','correlationId':m.AUTH_CORRELATION,'expectedSid':m.login.guest.SID,'success':True,'errorCategory':'none'},'qemu':{'pid':12},'guestChildPid':456}
 def typed(self):
  answer=CompletePrivateFlowTests().answer();answer['facts']['secureInput']['nodes']=answer['facts']['secureInput']['nodes'][:5]
  return {'state':'observed','facts':answer,'qemu':{'pid':12}}
 def run_flow(self,fault=None):
  calls=[];retained=[]
  def step(name,value):
   def call(*args):calls.append(name);return {'state':'unknown'}if fault==name else value
   return call
  result=m._login_sequence(step('auth',self.auth()),step('prepare',{'state':'observed','qemu':{'pid':12}}),step('write',self.typed()),step('enter',{'state':'observed','phase':'entered','qemu':{'pid':12}}),step('owner',{'state':'observed','qemu':{'pid':12}}),lambda name,v:retained.append(name),{'pid':12})
  return result,calls,retained
 def test_complete_sequence_positive_and_unknown_at_each_effect_boundary(self):
  result,calls,retained=self.run_flow();self.assertEqual(calls,['auth','prepare','write','enter','owner']);self.assertEqual(retained,calls);self.assertTrue(result['loginSubmitted']);self.assertFalse(result['installerAction'])
  for fault in('auth','prepare','write','enter','owner'):
   with self.assertRaises(ValueError):self.run_flow(fault)
 def test_auth_boolean_sid_and_correlation_are_actual_admission(self):
  for mutate in(lambda a:a['credential'].update(success=1),lambda a:a['credential'].update(expectedSid='foreign'),lambda a:a['credential'].update(correlationId=m.login.CREDENTIAL_CORRELATION),lambda a:a.update(qemu={'pid':999})):
   answer=self.auth();mutate(answer)
   with self.assertRaises(ValueError):m._validate_fresh_auth(answer,{'pid':12})
 def test_all_new_phase_sources_render_and_old_correlations_are_not_replayed(self):
  from agent_tools.tests.test_windows_cp117_recovered_login import ScreenTests
  root=Path(__file__).resolve().parents[2];record=ScreenTests().record();source,sha,_=m._credential_phase_program(root,record)
  tree=ast.parse(source);encoded=next(ast.literal_eval(n.value)for n in tree.body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='ENCODED'for t in n.targets));plain=base64.b64decode(encoded).decode('utf-16le')
  self.assertIn(m.AUTH_CORRELATION,plain);self.assertNotIn(m.login.CREDENTIAL_CORRELATION,plain);self.assertEqual(hashlib.sha256(plain.partition('\n')[2].encode('utf-16le')).hexdigest(),sha)
  for slot in m._LOGIN_SLOTS:
   source,sha=m._readonly_phase_program(record,slot);compile(source,'actual-fixed-source','exec');self.assertIn(repr(m._LOGIN_SLOTS[slot][0]),source);self.assertEqual(source.count("'guest-exec',"),1)
 def test_enter_current_role_and_staleness_gates_actual_selected_account(self):
  typed=self.typed();current=typed['facts'];prior={'reader':current['reader'],'roles':[n['runtimeId']for n in current['facts']['secureInput']['nodes']],'qemu':typed['qemu'],'writeSourceSha256':m.PARENT_SHA}
  m._submit_role_gate(current,prior,.5)
  for mutation in(lambda a:a['facts']['secureInput']['nodes'][1].update(accountName=False),lambda a:a['facts']['secureInput']['nodes'][3].update(keyboardFocus=False),lambda a:a['facts']['secureInput']['nodes'][3]['runtimeId'].append(999),lambda a:a['facts']['secureInput'].update(valuePatternReadOnly=True)):
   answer=json.loads(json.dumps(current));mutation(answer)
   with self.assertRaises(ValueError):m._submit_role_gate(answer,prior,.5)
  with self.assertRaises(ValueError):m._submit_role_gate(current,prior,5.001)
 def test_enter_source_actual_typed_receipt_and_only_one_finite_key(self):
  from agent_tools.tests.test_windows_cp117_recovered_login import ScreenTests
  record=ScreenTests().record();typed=self.typed();record['result']['qemu']=typed['qemu'];source,sha=m._enter_phase_program(record,typed)
  self.assertEqual(source.count("command('send-key'"),1);self.assertIn("'hold-time':100",source);self.assertIn("create('enter-attempt.json'",source);self.assertIn('focus_started=time.monotonic();child=call',source)
  for key in('Current.Value','ReadPassword','GetKeyState','SetValue'):
   self.assertNotIn(key,source)
 def test_consumed_full_login_does_not_read_secret_or_dispatch(self):
  import tempfile
  with tempfile.TemporaryDirectory()as temp:
   root=Path(temp);(root/'.runtime/parity-evidence'/('windows-cp117-provider-login-'+m.LOGIN_FLOW)).mkdir(parents=True)
   with patch.object(m.login,'_configured_secret')as secret,patch.object(m,'_stream')as stream:
    answer=m.start(root)
   self.assertEqual(answer['phase'],'provider-login-consumed');secret.assert_not_called();stream.assert_not_called()

@unittest.skipIf(os.name=='nt','POSIX compatibility and full credential composition')
class CurrentExecutionCompatibilityTests(unittest.TestCase):
 def pair(self,profile):
  mapping={'base':('_reserve','WindowsMsiBasePrepareError','Base preparation requires POSIX locking.'),'recovery':('_claim','RecoveryUnknown','posix-locking-unsupported'),'lease':('_locked','Cp117LeaseError','CP117 campaign locking is unsupported.')}
  if profile=='completion':
   old="def _readonly_unknown_archive(root,correlation=closure.base._UNKNOWN_CLOSURE_CORRELATION):\n base=closure.base\n return root\n"
   new="def _readonly_unknown_archive(root,correlation=None):\n base=closure.base\n if base is None:\n  return False\n if correlation is None:\n  correlation=base._UNKNOWN_CLOSURE_CORRELATION\n return root\n"
  else:
   name,error,message=mapping[profile]
   old='import fcntl\nREMOTE="import fcntl\\noriginal"\ndef '+name+'(root):\n return root\n'
   new='REMOTE="import fcntl\\noriginal"\ndef '+name+'(root):\n try:\n  import fcntl\n except ModuleNotFoundError as exc:\n  raise '+error+'('+repr(message)+') from exc\n return root\n'
  return old.encode(),new.encode()
 def test_closed_source_deltas_preserve_literals_and_refuse_any_extra_change(self):
  for profile in m._COMPAT_SOURCES:
   old,new=self.pair(profile);result=m._compatibility_ast(profile,old,new);self.assertTrue(result['nativeLiteralContinuity'])
   for mutated in(new+b'\nFOREIGN=True\n',new.replace(b'return root',b'return False'),new.replace(b'original',b'foreign'),new.replace(b'ModuleNotFoundError',b'ImportError')):
    if mutated==new:continue
    with self.assertRaises(ValueError):m._compatibility_ast(profile,old,mutated)
  with self.assertRaises(ValueError):m._compatibility_ast('foreign',b'',b'')
 def test_actual_fresh_credential_operation_preserves_original_child_and_no_replay(self):
  import tempfile,io,types,select,time,stat
  from agent_tools.tests.test_windows_cp117_recovered_login import ScreenTests
  source,sha,_=m._credential_phase_program(Path(__file__).resolve().parents[2],ScreenTests().record())
  parser=next(n for n in ast.parse(source).body if isinstance(n,ast.FunctionDef)and n.name=='_credential_terminal');namespace={'json':json,'base64':base64,'CREDENTIAL_CORRELATION':m.AUTH_CORRELATION};exec(compile(ast.Module([parser],type_ignores=[]),'actual-generated-parser','exec'),namespace)
  marker=' guards()\n import struct,base64';start=source.index(marker);operation=source[start:];answer=CompleteLoginSequenceTests().auth()['credential']
  for drift in(False,True):
   with tempfile.TemporaryDirectory()as temporary:
    parent=Path(temporary);os.chmod(parent,0o700);actual=operation.replace('parent='+repr(m.login.TRANSFER),'parent='+repr(str(parent)));calls=[];events=[];results=[]
    ack=m.login.guest.recovery._digest({'diagnosticId':m.AUTH_CORRELATION,'nonce':m.AUTH_NONCE,'sourceSha256':sha,'pid':456});stdin=types.SimpleNamespace(buffer=io.BytesIO((3).to_bytes(4,'big')+b'abc'+(ack+'\n').encode()))
    def need(ok,message):
     if not ok:raise ValueError(message)
    def call(path,method,args):
     calls.append((method,args))
     if method=='guest-exec':return {'pid':456}
     if drift:
      child=parent/('cp117-credential-'+m.AUTH_CORRELATION)/'child.json';child.write_text('{}');os.chmod(child,0o600)
     nonce='old'if len(calls)==2 else m.AUTH_NONCE
     return {'exited':True,'exitcode':0,'out-data':base64.b64encode(('CP117-READ '+nonce+' '+sha+' 456\n'+json.dumps(answer)).encode()).decode()}
    ns=dict(namespace,guards=lambda:None,os=os,stat=stat,fp=lambda info:{k:getattr(info,k)for k in('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')},need=need,hashlib=hashlib,D=m.AUTH_CORRELATION,NONCE=m.AUTH_NONCE,BODY_SHA=sha,ENCODED='fixed',LEAF='fixed',children=[{}, {'child':{'pid':12}}],sys=types.SimpleNamespace(stdin=stdin),call=call,event=events.append,result=results.append,digest=m.login.guest.recovery._digest,time=types.SimpleNamespace(sleep=lambda _:None))
    with patch.object(select,'select',return_value=([stdin],[],[])):exec('try:\n'+actual,ns)
    self.assertEqual(sum(method=='guest-exec'for method,_ in calls),1);self.assertTrue(all(args=={'pid':456}for method,args in calls if method=='guest-exec-status'))
    if drift:self.assertEqual(results[0]['state'],'unknown');self.assertEqual(len(calls),2)
    else:self.assertEqual(results[0]['state'],'observed');self.assertEqual(results[0]['credential'],answer);self.assertEqual(len(calls),3)
    self.assertNotIn(b'abc',b''.join(p.read_bytes()for p in(parent/('cp117-credential-'+m.AUTH_CORRELATION)).iterdir()))

@unittest.skipIf(os.name=='nt','POSIX QMP submit coordinator')
class ActualSubmitBoundaryTests(unittest.TestCase):
 def execute(self,fault=None):
  import tempfile,types,socket,struct,io,stat
  typed=CompleteLoginSequenceTests().typed();current=typed['facts'];prior={'reader':current['reader'],'roles':[n['runtimeId']for n in current['facts']['secureInput']['nodes']],'qemu':typed['qemu'],'writeSourceSha256':m.PARENT_SHA};calls=[]
  if fault=='foreign':current=json.loads(json.dumps(current));current['facts']['secureInput']['nodes'][1]['accountName']=False
  class Reader:
   def __init__(self):self.lines=[b'{"QMP":{}}\n']
   def readline(self,_):return self.lines.pop(0)
   def close(self):pass
  class Channel:
   def __init__(self):self.reader=Reader()
   def settimeout(self,_):pass
   def connect(self,_):pass
   def getsockopt(self,*_):return struct.pack('3i',12,os.geteuid(),os.getegid())
   def makefile(self,_):return self.reader
   def sendall(self,raw):
    packet=json.loads(raw);calls.append(packet['execute'])
    if packet['execute']=='screendump':Path(packet['arguments']['filename']).write_bytes(b'P6\n1280 800\n255\n'+b'\0'*(1280*800*3))
    if packet['execute']=='send-key'and fault=='lost':raise TimeoutError('lost-key-response')
    self.reader.lines.append(json.dumps({'id':packet['id'],'return':{}}).encode()+b'\n')
   def close(self):pass
  with tempfile.TemporaryDirectory()as tmp:
   root=Path(tmp);os.chmod(root,0o700)
   def need(ok,message):
    if not ok:raise ValueError(message)
   namespace={'_submit_role_gate':m._submit_role_gate,'time':types.SimpleNamespace(monotonic=lambda:1.,sleep=lambda _:None),'os':os,'stat':stat,'json':json,'hashlib':hashlib,'TRANSFER':str(root),'FLOW':m.LOGIN_FLOW,'NONCE':m._LOGIN_SLOTS['enter'][1],'BODY_SHA':m._READ_PHASE_HASHES['enter'][0],'LEAF':'fixed','children':[{}, {'child':{'pid':12}}],'pid':456,'guards':lambda:None,'need':need,'validate_ppm':m.login.validate_ppm,'fp':lambda info:{k:getattr(info,k)for k in('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')}}
   exec(inspect.getsource(m._remote_submit),namespace)
   with patch.object(socket,'socket',return_value=Channel()),patch.object(socket,'SO_PEERCRED',17,create=True):
    try:value=namespace['_remote_submit'](current,1.,prior);error=None
    except Exception as caught:value=None;error=caught
   entries=list(root.iterdir());attempts=list(root.glob('*/enter-attempt.json'));frames=list(root.glob('*/*.ppm'))
   return value,calls,error,len(entries),len(attempts),len(frames)
 def test_actual_qmp_function_positive_and_foreign_zero_key(self):
  value,calls,error,_,attempts,frames=self.execute();self.assertIsNone(error);self.assertEqual(value['phase'],'entered');self.assertEqual(calls.count('send-key'),1);self.assertEqual(attempts,1);self.assertEqual(frames,2)
  value,calls,error,entries,attempts,frames=self.execute('foreign');self.assertIsInstance(error,ValueError);self.assertEqual(calls,[]);self.assertEqual(entries,0)
 def test_actual_lost_key_response_consumed_once_and_preframe_retained(self):
  value,calls,error,_,attempts,frames=self.execute('lost');self.assertIsInstance(error,TimeoutError);self.assertEqual(calls.count('send-key'),1);self.assertEqual(attempts,1);self.assertEqual(frames,1);self.assertIn('enter-before.ppm',error.frameAuthority['frames'])


def provider_write_execution_script():
 """Execute the actual new SetExact method against managed inert providers."""
 tree=ast.parse((Path(__file__).resolve().parents[1]/'windows_cp117_windowless_provider_login.py').read_text())
 method=next(ast.literal_eval(n.value)for n in tree.body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='_WRITE_METHOD'for t in n.targets))
 fixture=r'''using System;
public class Node{public int[] runtimeId=new int[]{1};}
public class Facts{public Node[] nodes=new Node[]{new Node(),new Node(),new Node(),new Node(),new Node()};public bool valuePatternSupported=true,valuePatternReadOnly;public uint threadId=7;}
public static class ControlType{public static int Edit=50004;}
public class Properties{public int ProcessId=1096,ControlType=50004;public bool IsPassword=true,HasKeyboardFocus=true,IsKeyboardFocusable=true,IsEnabled=true,IsOffscreen;}
public class PatternProperties{public bool IsReadOnly;}
public class ValuePattern{public static object Pattern=new object();public PatternProperties Current=new PatternProperties();public int writes;public bool fail;public void SetValue(string value){writes++;if(fail)throw new Exception("untrusted provider input echo");}}
public class AutomationElement{public static AutomationElement FocusedElement;public Properties Current=new Properties();public ValuePattern pattern=new ValuePattern();public int[] id=new int[]{1};public int[] GetRuntimeId(){return id;}public bool TryGetCurrentPattern(object requested,out object result){result=pattern;return true;}}
public static class ProviderWriteFixture{
 static Facts fresh;static long window=65626;
 static void Need(bool ok,string message){if(!ok)throw new InvalidOperationException(message);}
 static bool Equal(int[] a,int[] b){if(a.Length!=b.Length)return false;for(int i=0;i<a.Length;i++)if(a[i]!=b[i])return false;return true;}
 static Facts Read(uint[] threads){return fresh;}
 static IntPtr Focus(uint[] threads,out uint thread){thread=7;return new IntPtr(window);}
 static void Reset(){fresh=new Facts();window=65626;AutomationElement.FocusedElement=new AutomationElement();}
 __METHOD__
 public static bool Run(){
  Reset();var prior=new Facts();SetExact(new uint[]{7},prior,"");SetExact(new uint[]{7},prior,"PUBLIC-INERT-WRITE");Need(AutomationElement.FocusedElement.pattern.writes==2,"positive");
  for(int kind=0;kind<4;kind++){Reset();prior=new Facts();if(kind==0)AutomationElement.FocusedElement.Current.ProcessId=999;if(kind==1)AutomationElement.FocusedElement.pattern.Current.IsReadOnly=true;if(kind==2)fresh.nodes[0].runtimeId=new int[]{999};if(kind==3)window=999;bool refused=false;try{SetExact(new uint[]{7},prior,"PUBLIC-INERT-WRITE");}catch(InvalidOperationException){refused=true;}Need(refused&&AutomationElement.FocusedElement.pattern.writes==0,"unsafe wrote");}
  Reset();AutomationElement.FocusedElement.pattern.fail=true;try{SetExact(new uint[]{7},new Facts(),"PUBLIC-INERT-WRITE");throw new Exception("accepted failure");}catch(InvalidOperationException error){Need(error.Message=="ROLE_WRITE_FAILED"&&error.InnerException==null,"private exception");}return true;
 }
}'''.replace('__METHOD__',method)
 return "$ErrorActionPreference='Stop'\nAdd-Type -TypeDefinition @'\n"+fixture+"\n'@\nif(-not [ProviderWriteFixture]::Run()){throw 'PROVIDER_WRITE_CASES'}\nWrite-Output 'PROVIDER_WRITE_CASES_PASS'\n"

class ActualProviderWriteExecutionTests(unittest.TestCase):
 @unittest.skipUnless(os.name=='nt'and shutil.which('powershell'),'actual Windows managed provider execution')
 def test_actual_write_method_managed_positive_unsafe_and_exception_cases(self):
  value=subprocess.run(['powershell','-NoProfile','-NonInteractive','-Command','-'],input=provider_write_execution_script().encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30,check=False)
  self.assertEqual(value.returncode,0,value.stderr.decode(errors='replace'));self.assertEqual(value.stdout.decode().strip(),'PROVIDER_WRITE_CASES_PASS')

@unittest.skipIf(os.name=='nt','POSIX transport composition')
class ReadonlyAckCompositionTests(unittest.TestCase):
 def test_actual_stream_to_generated_readonly_ack_has_no_private_header(self):
  import sys,tempfile
  from unittest.mock import MagicMock
  from agent_tools.tests.test_windows_cp117_recovered_login import ScreenTests
  for slot in m._LOGIN_SLOTS:
   record=ScreenTests().record()
   if slot=='enter':
    typed=CompleteLoginSequenceTests().typed();record['result']['qemu']=typed['qemu'];source,sha=m._enter_phase_program(record,typed)
   else:source,sha=m._readonly_phase_program(record,slot)
   tree=ast.parse(source)
   ack=next(n for n in ast.walk(tree)if isinstance(n,ast.Expr)and isinstance(n.value,ast.Call)and any(isinstance(a,ast.Constant)and a.value=='local-anchor-ack'for a in n.value.args))
   definitions=[n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name in('digest','need')]
   correlation,nonce=m._LOGIN_SLOTS[slot];qemu={'pid':1};pid=456
   event={'kind':'submitted','diagnosticId':correlation,'nonce':nonce,'sourceSha256':sha,'qemu':qemu,'pid':pid}
   script='import sys,json,hashlib\n'+ast.unparse(ast.Module(body=definitions,type_ignores=[]))+'\nD='+repr(correlation)+'\nNONCE='+repr(nonce)+'\nBODY_SHA='+repr(sha)+'\npid=456\n'
   script+='sys.stderr.write("CP117-OBSERVE "+'+repr(json.dumps(event))+'+"\\n");sys.stderr.flush()\n'+ast.unparse(ack)+'\nprint(json.dumps({"state":"observed"}))\n'
   with tempfile.TemporaryDirectory()as directory:
    fd=os.open(directory,os.O_RDONLY);capture=MagicMock();capture.fd=fd
    try:
     with self.assertRaisesRegex(ValueError,'gui-observer-exit'):
      m._stream([sys.executable,'-c',script],capture,correlation,nonce,sha,qemu,b'')
     raw=b''.join(call.args[1]for call in capture.create.call_args_list if call.args[0].endswith('stderr.private'))
     self.assertIn(b'local-anchor-ack',raw);capture.reset_mock()
     answer,events=m._stream([sys.executable,'-c',script],capture,correlation,nonce,sha,qemu,None)
    finally:os.close(fd)
   self.assertEqual(answer,{'state':'observed'});self.assertEqual(events[0]['event']['pid'],456)

 def test_actual_dispatch_defaults_ack_only_and_auth_write_are_framed(self):
  tree=ast.parse(inspect.getsource(m.start));dispatch=next(n for n in ast.walk(tree)if isinstance(n,ast.FunctionDef)and n.name=='dispatch')
  self.assertIsNone(ast.literal_eval(dispatch.args.defaults[-1]))
  calls=[n for n in ast.walk(tree)if isinstance(n,ast.Call)and isinstance(n.func,ast.Name)and n.func.id=='dispatch']
  self.assertEqual(sorted(len(n.args)for n in calls),[5,5,6,6])
  self.assertTrue(all(isinstance(n.args[-1],ast.Name)and n.args[-1].id=='secret'for n in calls if len(n.args)==6))

@unittest.skipIf(os.name=='nt','POSIX coordinator source context')
class TypedReceiptBoundaryTests(unittest.TestCase):
 def test_actual_verify_refuses_changed_typed_receipt_after_capture(self):
  import types
  from unittest.mock import MagicMock
  tree=ast.parse(inspect.getsource(m.start));verify=next(n for n in ast.walk(tree)if isinstance(n,ast.FunctionDef)and n.name=='verify')
  own={'generation':[1]};raw=b'original';inert_raw=b'proof';typed_bytes=b'typed';typed_pin={'generation':[2]}
  authority=MagicMock();authority._read_bound_file.return_value=own
  recovery=types.SimpleNamespace(authority=authority,_local_read=lambda leaf,name,pin:raw if name==m.login.guest.ORIGINAL['name']else inert_raw if name=='proof.json'else b'exchanged')
  namespace={'_sources':lambda:None,'_wake_check_factories':lambda:None,'r':recovery,'Path':Path,'__file__':m.__file__,'own':own,'pins':{},'original':'original-leaf','login':m.login,'raw':raw,'inert':'proof-leaf','_PIPE_PROOF_PIN':m._PIPE_PROOF_PIN,'inert_raw':inert_raw,'record':{'authority':[]},'_execution_source_proof':lambda root,record:{},'execution_sources':{},'root':Path('.'),'credential_path':Path('fixed'),'credential_pin':own,'outer':{},'typed_bytes':typed_bytes,'typed_pin':typed_pin,'capture':'typed-leaf'}
  exec(compile(ast.Module(body=[verify],type_ignores=[]),'actual-verify-boundary','exec'),namespace)
  with self.assertRaisesRegex(ValueError,'login-typed-local-authority'):namespace['verify']()
  recovery._local_read=lambda leaf,name,pin:raw if name==m.login.guest.ORIGINAL['name']else inert_raw if name=='proof.json'else typed_bytes
  namespace['verify']()

_MANAGED_INERT_TERMINAL_SOURCE="def parse_compile(value,nonce,sha,pid):\n    if value.get('exited')is not True:return None\n    if value.get('out-truncated')or value.get('err-truncated'):raise ValueError('compile-truncated')\n    raw=base64.b64decode(value.get('out-data',''),validate=True)\n    if len(raw)>32768:raise ValueError('compile-output-cap')\n    first,sep,body=raw.partition(b'\\n')\n    if not sep or first.rstrip(b'\\r')!=('CP117-READ %s %s %d'%(nonce,sha,pid)).encode():return None\n    if value.get('exitcode')!=0:raise ValueError('compile-exit')\n    answer=json.loads(body)\n    if not isinstance(answer,dict)or set(answer)!=set(EXPECTED)or type(answer.get('version'))is not int or answer['version']!=1 or any(type(answer.get(k))is not bool for k in EXPECTED if k!='version')or answer!=EXPECTED:raise ValueError('provider-case-result')\n    return answer\n"

class ManagedInertTerminalTypesTests(unittest.TestCase):
 def test_actual_emitted_parser_exact_types_and_same_execution_binding(self):
  expected={'version':1,'managedSetExactPassed':True,'inputFramingPassed':True,'credentialInput':False,'providerInvoked':False,'keyboardAction':False}
  namespace={'base64':base64,'json':json,'EXPECTED':expected};exec(_MANAGED_INERT_TERMINAL_SOURCE,namespace);parse=namespace['parse_compile'];nonce='fixed-public';sha='a'*64;pid=456
  def terminal(answer,header_nonce=nonce):return {'exited':True,'exitcode':0,'out-data':base64.b64encode(('CP117-READ '+header_nonce+' '+sha+' 456\n'+json.dumps(answer)).encode()).decode()}
  self.assertEqual(parse(terminal(expected),nonce,sha,pid),expected)
  for key in expected:
   wrong=dict(expected);wrong[key]=True if key=='version'else int(expected[key])
   with self.assertRaisesRegex(ValueError,'provider-case-result'):parse(terminal(wrong),nonce,sha,pid)
  for wrong in(dict(expected,extra=False),{k:v for k,v in expected.items()if k!='credentialInput'}):
   with self.assertRaisesRegex(ValueError,'provider-case-result'):parse(terminal(wrong),nonce,sha,pid)
  self.assertIsNone(parse(terminal(expected,'old'),nonce,sha,pid))

class ManagedPipeFixtureCompilerTests(unittest.TestCase):
 @unittest.skipUnless(os.name=='nt'and shutil.which('powershell'),'actual Windows Add-Type warning regression')
 def test_actual_old_fixture_warning_and_explicit_false_compiles(self):
  import re
  sources=re.findall(r"Add-Type -TypeDefinition @'\n(.*?)\n'@",input_execution_script(),re.S);self.assertEqual(len(sources),2)
  current=sources[1];old=current.replace('static bool expired=false;','static bool expired;')
  self.assertNotEqual(old,current)
  script="$ErrorActionPreference='Stop'\n$refused=$false;try{Add-Type -TypeDefinition @'\n"+old+"\n'@\n}catch{if($_.Exception.ToString() -notmatch 'expired'){throw};$refused=$true};if(-not $refused){throw 'OLD_WARNING_NOT_REFUSED'}\nAdd-Type -TypeDefinition @'\n"+current+"\n'@\nWrite-Output 'PIPE_FIXTURE_COMPILER_PASS'\n"
  result=subprocess.run(['powershell','-NoProfile','-NonInteractive','-Command','-'],input=script.encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20,check=False)
  self.assertEqual(result.returncode,0,result.stderr.decode(errors='replace'));self.assertEqual(result.stdout.decode().strip(),'PIPE_FIXTURE_COMPILER_PASS');self.assertEqual(result.stderr,b'')

_STALE_CS_FACTORY_SOURCE='def _parts(inert=False):\n    """Fixed derivative; source contains no credential bytes or credential hash."""\n    import re\n    if type(inert)is not bool:raise ValueError(\'provider-fixed-mode\')\n    correlation=INERT_CORRELATION if inert else CORRELATION;nonce=INERT_NONCE if inert else NONCE\n    _sources()\n    if hashlib.sha256(role.secure._NATIVE.encode()).hexdigest()!=_BASE_NATIVE_SHA or hashlib.sha256(role._SEMANTIC_CS.encode()).hexdigest()!=_ROLE_NATIVE_SHA:raise ValueError(\'provider-fixed-native\')\n    oldparent,oldchild,oldsha=role.bodies()\n    if oldsha!=_ROLE_CHILD_SHA or hashlib.sha256(oldparent.encode(\'utf-16le\')).hexdigest()!=_ROLE_PARENT_SHA:raise ValueError(\'provider-fixed-reader\')\n    match=re.search(r"FromBase64String\\(\'([^\']+)\'\\)",oldchild)\n    if match is None:raise ValueError(\'provider-reader-loader\')\n    with gzip.GzipFile(fileobj=__import__(\'io\').BytesIO(base64.b64decode(match.group(1))))as z:plain=z.read(16385)\n    if len(plain)>16384:raise ValueError(\'provider-original-bound\')\n    child=plain.decode(\'utf-8\').replace(role.CORRELATION,correlation).replace(role.NONCE,nonce)\n    head="if($sourceHash -cne $birth.sourceSha256){throw \'SECURE_READER_SOURCE\'}"\n    if child.count(head)!=1:raise ValueError(\'provider-input-placement\')\n    prefix,sep,child=child.partition(head)\n    if not sep:raise ValueError(\'provider-child-source-head\')\n    prefix+=sep+\'\\n\'\n    child=\'$privateBytes=[CP117OriginalInput]::ReadSecret($privateInput)\\n\'+child\n    native=role._SEMANTIC_CS[:-1]+_WRITE_METHOD+\'}\'\n    packed=base64.b64encode(gzip.compress(role._SEMANTIC_CS.encode(),mtime=0)).decode();newpacked=base64.b64encode(gzip.compress(native.encode(),mtime=0)).decode()\n    if child.count(packed)!=1 or child.count(_ROLE_NATIVE_SHA)!=1:raise ValueError(\'provider-native-placement\')\n    child=child.replace(packed,newpacked).replace(_ROLE_NATIVE_SHA,hashlib.sha256(native.encode()).hexdigest())\n    marker=\'$cf=[CP117InputRead]::Read([uint32[]]$ids)\' \n    if child.count(marker)!=1:raise ValueError(\'provider-write-placement\')\n    child=child.replace(marker,marker+\'\\n\'+_WRITE_PS)\n    child=child.replace(\'secureInput=$cf};WritePrivate\',\'secureInput=$cf;providerWrite=@{cleared=$true;typed=$true;contentRead=$false;credentialLogged=$false}};WritePrivate\')\n    # Provider exceptions may mention their input. Never persist error details\n    # from a secret-bearing execution, even in protected failure receipts.\n    detail="$d=($_|Out-String);if($d.Length -gt 2048){$d=$d.Substring(0,2048)};"\n    if child.count(detail)!=1:raise ValueError(\'provider-private-error-placement\')\n    child=child.replace(detail,"$d=\'\';")\n    if inert:child=_inert_public()\n    public=\'\\n\'.join(line.lstrip(\' \')for line in child.splitlines())+\'\\n\'\n    if not 0<len(public.encode())<=16384:raise ValueError(\'provider-child-public-source-bound\')\n    child=prefix+_INPUT_READ.replace(\'__INPUT_CS__\',_INPUT_CS)+_PUBLIC_STAGE.replace(\'__PUBLIC_SHA__\',hashlib.sha256(public.encode()).hexdigest())\n    childsha=hashlib.sha256(child.encode(\'utf-16le\')).hexdigest()\n    parent=oldparent.replace(role.CORRELATION,correlation).replace(role.NONCE,nonce).replace(_ROLE_CHILD_SHA,childsha).replace(base64.b64encode(oldchild.encode(\'utf-16le\')).decode(),base64.b64encode(child.encode(\'utf-16le\')).decode())\n    if parent.count(role.secure._NATIVE)!=1:raise ValueError(\'provider-parent-native-placement\')\n    parent=parent.replace(role.secure._NATIVE,native_source())\n    marker=" WritePrivate \'child.json\' $record;GuardUI"\n    if parent.count(marker)!=1:raise ValueError(\'provider-parent-input-placement\')\n    parent=parent.replace(marker,marker+"\\n $inputHandle=[CP117SessionRead]::DuplicateInput($pi,$birth);GuardUI;if([CP117SessionRead]::Birth($pi) -cne $birth){throw \'PROVIDER_INPUT_CHILD\'};WritePrivate \'stdin.json\' @{nonce=$nonce;sourceSha256=$childSha;pid=[int]$pi.pid;parentPid=$PID;creationFileTime=$birth;sessionId=1;handle=[long]$inputHandle};"+_STDIN_PROTECT+";GuardUI")\n    # Only finite source-controlled parent classifications may reach output.\n    old="phase=$_.Exception.Message;readerCreated="\n    if parent.count(old)!=1:raise ValueError(\'provider-parent-private-catch\')\n    parent=parent.replace(old,"phase=\'PROVIDER_PARENT_UNKNOWN\';readerCreated=")\n    if len(parent.encode())>65536 or len(base64.b64encode(child.encode(\'utf-16le\')))>30000:raise ValueError(\'provider-fixed-command-bound\')\n    return parent,child,childsha,public'

@unittest.skipIf(os.name=='nt','POSIX exact parent generator')
class ActualGeneratedCsLoaderTests(unittest.TestCase):
 def guard(self,public):
  import gzip,re
  packed=re.search(r"FromBase64String\('([^']+)'\)",public).group(1)
  actual=gzip.GzipFile(fileobj=__import__('io').BytesIO(base64.b64decode(packed,validate=True))).read(16385)
  count=int(re.search(r"if\(\$o -ne (\d+)\)\{throw 'CENSUS_CS_BOUND'\}",public).group(1))
  declared=re.search(r"if\(\$ca -cne '([a-f0-9]{64})'\)\{throw 'CENSUS_CS_HASH'\}",public).group(1)
  if len(actual)>16384 or len(actual)!=count:raise ValueError('CENSUS_CS_BOUND')
  if hashlib.sha256(actual).hexdigest()!=declared:raise ValueError('CENSUS_CS_HASH')
  return actual
 def test_actual_frozen_factory_loader_red_and_current_full_source_green(self):
  namespace=dict(m.__dict__);exec(_STALE_CS_FACTORY_SOURCE,namespace);oldpublic=namespace['_parts'](False)[3]
  with self.assertRaisesRegex(ValueError,'CENSUS_CS_BOUND'):self.guard(oldpublic)
  public=m._parts(False)[3];actual=self.guard(public)
  self.assertEqual(actual,(m.role._SEMANTIC_CS[:-1]+m._WRITE_METHOD+'}').encode())
  self.assertLessEqual(len(actual),16384)
 def test_actual_generated_loader_rejects_size_and_hash_drift(self):
  import re
  public=m._parts(False)[3];self.guard(public)
  poisoned=re.sub(r"if\(\$o -ne \d+\)","if($o -ne 1)",public)
  with self.assertRaisesRegex(ValueError,'CENSUS_CS_BOUND'):self.guard(poisoned)
  poisoned=re.sub(r"if\(\$ca -cne '[a-f0-9]{64}'\)","if($ca -cne '"+'0'*64+"')",public)
  with self.assertRaisesRegex(ValueError,'CENSUS_CS_HASH'):self.guard(poisoned)
