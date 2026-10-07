import ast,base64,hashlib,inspect,json,os,shutil,subprocess,tempfile,textwrap,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[2]
if os.name!='nt':
 from agent_tools import windows_cp117_secure_input_tuple_observe as m
 from agent_tools import windows_cp117_secure_input_observe as original
 from agent_tools.tests import test_windows_cp117_secure_layout_observe as layout

def native_source():
 tree=ast.parse((ROOT/'agent_tools/windows_cp117_secure_input_tuple_observe.py').read_text())
 return next(ast.literal_eval(n.value)for n in tree.body if isinstance(n,ast.Assign)and any(isinstance(x,ast.Name)and x.id=='_SEMANTIC_CS'for x in n.targets))

@unittest.skipIf(os.name=='nt','POSIX native transport composition tests run on the coordinator')
class TupleTests(unittest.TestCase):
 def answer(self):
  a=layout.SecureLayoutTests().answer();a['reader']['nonce']=m.NONCE;a['birth']['nonce']=m.NONCE;a['reader']['sourceSha256']=m.CHILD_SHA;a['birth']['sourceSha256']=m.CHILD_SHA
  a['facts']['secureInput']={'actualPid':1096,'controlTypeId':50004,'nativeHandle':123,'ownerMatches':True,'edit':True,'password':True,'keyboardFocus':True,'keyboardFocusable':True,'enabled':True,'onscreen':True,'passwordLabel':True,'supported':True,'keyboardAdmission':False,'threadId':111,'focusWindow':456,'hkl':'0000000004090409','windowStation':'WinSta0','desktop':'Winlogon'}
  return a
 def terminal(self,a=None,nonce=None):
  a=a or self.answer()
  raw=('CP117-READ '+(nonce or m.NONCE)+' '+m.PARENT_SHA+' 456\n'+json.dumps(a)).encode();return {'exited':True,'exitcode':0,'out-data':base64.b64encode(raw).decode()}
 def test_each_unsupported_property_remains_diagnostic_never_input_authority(self):
  for k in ('ownerMatches','edit','password','keyboardFocus','keyboardFocusable','enabled','onscreen','passwordLabel'):
   a=self.answer();s=a['facts']['secureInput'];s[k]=False;s['supported']=False
   if k=='ownerMatches':s['actualPid']=99
   if k=='edit':s['controlTypeId']=50000
   self.assertEqual(m.parse_terminal(self.terminal(a),m.NONCE,m.PARENT_SHA,456)['facts']['secureInput'],s)
   with self.assertRaises(ValueError):original.validate_semantic(a)
 def test_false_input_authority_and_property_inconsistency_are_refused(self):
  for k,v in [('keyboardAdmission',True),('supported',False),('actualPid',99),('controlTypeId',50000),('hkl','0000000004190419'),('desktop','Default'),('threadId',999),('passwordLabel','Password')]:
   a=self.answer();a['facts']['secureInput'][k]=v
   with self.subTest(k=k),self.assertRaises(ValueError):m.parse_terminal(self.terminal(a),m.NONCE,m.PARENT_SHA,456)
 def test_native_gate_precedes_provider_query_and_no_text_or_length_read(self):
  cs=native_source();self.assertLess(cs.index('IntPtr hwnd=Focus'),cs.index('AutomationElement e=AutomationElement.FocusedElement'))
  for banned in ('SendMessageTimeout','ValuePattern','TextPattern','GetClassName','GetKeyState','passwordLength'):
   self.assertNotIn(banned,cs)
  self.assertIn('PasswordLabel=p.Name=="Password"',cs);self.assertNotIn('controlName',cs)
  self.assertIn('keyboardAdmission=false',cs);self.assertIn('Same(before,Capture(e))',cs)
  parent,child,_=m.bodies();self.assertIn("WritePrivate 'failure.json'",child);self.assertIn('GuardFailureAcl',parent)
 def execute_flow(self,stale=False,foreign=False):
  src=textwrap.dedent(inspect.getsource(layout.CompleteGeneratedFlowTests.execute_flow)).replace('secure.program(record,secure.NONCE)','m.program(record)').replace('secure.CORRELATION','m.CORRELATION').replace('secure.NONCE','m.NONCE')
  ns={'ast':ast,'base64':base64,'json':json,'patch':patch,'secure':m.secure,'m':m};exec(src,ns);return ns['execute_flow'](self,stale,foreign)
 def observe_fixture(self,drift=False,history_drift=False):
  from contextlib import ExitStack
  from types import SimpleNamespace
  from agent_tools.tests.fixtures import historical_source
  historical=ROOT/'agent_tools/tests/fixtures/windows_cp117_recovery/short_socket_51538dad.source'
  recovery=historical_source.load(historical,m.login.guest.RECOVERY_SHA)
  authority=recovery.authority;calls=[];records={};generation=[0]
  raw=json.dumps({'authority':[],'request':{'sources':{'recovery':{'sha256':m.login.guest.RECOVERY_SHA}}},'result':{'qemu':{'pid':1}}}).encode()
  class Capture:
   def __init__(self,root,leaf):self.fd=os.open(root,os.O_RDONLY);self.leaf=leaf
   def close(self):os.close(self.fd)
   def create(self,name,value):records[(self.leaf,name)]=value;return {'sha256':hashlib.sha256(value).hexdigest()}
  def bound(path):
   path=Path(path);calls.append(str(path));v={'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
   if path==Path(original.__file__):v['generation']=generation[0]
   return v
  def stream(*args):
   if drift:generation[0]+=1
   return {'state':'observed','facts':{'diagnosticOnly':True}},[]
  with tempfile.TemporaryDirectory()as directory,ExitStack()as stack:
   root=Path(directory);(root/'.runtime/parity-evidence').mkdir(parents=True)
   if history_drift:
    changed=root/'historical-recovery.source';changed.write_bytes(historical.read_bytes()+b'\n# PUBLIC_FIXTURE_DRIFT\n')
    historical_source.load(changed,m.login.guest.RECOVERY_SHA)
   for target,name,value in [(m.login.guest,'recovery',recovery),(m,'_factories',lambda:None),(m,'AuthorityCapture',Capture),(recovery,'_local_read',lambda *a:raw),(authority,'_source_pins',lambda *a:{}),(authority,'_read_bound_file',bound),(authority,'_outer_authority',lambda *a:{}),(authority,'_verify_outer',lambda *a:None),(m,'program',lambda *a:('print("readonly")','a'*64)),(authority.closure.base,'_descriptor',lambda *a:(object(),None,None)),(authority.closure.base.ssh_transport,'build_ssh_argv',lambda *a,**k:['inert']),(m.login.guest,'_stream',stream)]:stack.enter_context(patch.object(target,name,value))
   result=m.observe(root)
  historical_source.verify(recovery,historical,m.login.guest.RECOVERY_SHA)
  self.fixture_recovery=recovery
  return result,calls,records
 def test_actual_fixture_methods_have_historical_namespace_and_filename(self):
  from agent_tools.tests.fixtures import historical_source
  self.observe_fixture()
  historical=ROOT/'agent_tools/tests/fixtures/windows_cp117_recovery/short_socket_51538dad.source'
  module=historical_source.verify(self.fixture_recovery,historical,m.login.guest.RECOVERY_SHA)
  self.assertEqual(module.recipe()['correlationId'],'10555d34-a4a8-4953-8ad7-f689e6c2ba33')
 def test_actual_historical_loader_rejects_current_and_mixed_methods(self):
  from agent_tools.tests.fixtures import historical_source
  from agent_tools import windows_cp117_fixture_recovery_short_socket as current
  historical=ROOT/'agent_tools/tests/fixtures/windows_cp117_recovery/short_socket_51538dad.source'
  with self.assertRaisesRegex(ValueError,'historical_source_binding_changed'):
   historical_source.load(current.__file__,m.login.guest.RECOVERY_SHA)
  module=historical_source.load(historical,m.login.guest.RECOVERY_SHA)
  module._digest=current._digest
  with self.assertRaisesRegex(ValueError,'historical_function_binding_changed'):
   historical_source.verify(module,historical,m.login.guest.RECOVERY_SHA)
 def test_actual_observe_wrapper_pins_original_module_before_and_after_dispatch(self):
  result,calls,records=self.observe_fixture();self.assertEqual(result['state'],'observed',result)
  self.assertGreaterEqual(calls.count(str(Path(original.__file__))),3)
  request=json.loads(next(v for (leaf,name),v in records.items()if name=='request.json'));self.assertEqual(request['originalSemantic']['sha256'],m.ORIGINAL_SEMANTIC_SHA);self.assertFalse(request['keyboardAdmission'])
 def test_actual_observe_wrapper_same_content_original_generation_drift_refused(self):
  result,_,_=self.observe_fixture(drift=True);self.assertEqual(result['state'],'unknown');self.assertEqual(result['phase'],'tuple-factory-source-drift')
 def test_actual_observe_rejects_changed_historical_recovery_before_dispatch(self):
  with self.assertRaisesRegex(ValueError,'historical_source_binding_changed'):
   self.observe_fixture(history_drift=True)
 def test_whole_generated_one_submit_same_child_positive_tuple(self):
  r,calls,_=self.execute_flow();self.assertEqual(r['state'],'observed');self.assertEqual(r['facts'],self.answer());self.assertEqual([x[0]for x in calls],['guest-exec','guest-exec-status']);self.assertEqual(calls[1][1],{'pid':456})
 def test_same_child_stale80_and_foreign_zero_dispatch(self):
  r,calls,_=self.execute_flow(stale=True);self.assertEqual(r['state'],'unknown');self.assertEqual(len(calls),81);self.assertEqual(sum(x[0]=='guest-exec'for x in calls),1)
  r,calls,_=self.execute_flow(foreign=True);self.assertEqual(r['state'],'unknown');self.assertEqual(calls,[])

@unittest.skipUnless(shutil.which('powershell.exe'),'Windows PowerShell unavailable')
class ExecutableProviderTests(unittest.TestCase):
 def test_actual_provider_interface_all_eight_gates_no_authority(self):
  cs=native_source()
  script=r"""$ErrorActionPreference='Stop';'UIAutomationClient','UIAutomationTypes','WindowsBase'|ForEach-Object {[void][Reflection.Assembly]::LoadWithPartialName($_)}
Add-Type -ReferencedAssemblies @('System.dll','System.Core.dll',[Windows.Automation.AutomationElement].Assembly.Location,[Windows.Automation.ControlType].Assembly.Location,[Windows.Rect].Assembly.Location) -TypeDefinition @'
"""+cs+r"""
'@
$p=[CP117InputRead+Snapshot]::new();$p.Pid=1096;$p.ControlId=[Windows.Automation.ControlType]::Edit.Id;$p.NativeHandle=123;$p.Password=$true;$p.Focused=$true;$p.Focusable=$true;$p.Enabled=$true;$p.Onscreen=$true;$p.PasswordLabel=$true
$f=[CP117InputRead]::Describe($p);if(-not $f.supported -or $f.keyboardAdmission){throw 'PROVIDER_POSITIVE'}
foreach($name in @('Pid','ControlId','Password','Focused','Focusable','Enabled','Onscreen','PasswordLabel')){
 $property=$p.GetType().GetProperty($name);$before=$property.GetValue($p,$null);$value=if($name -eq 'Pid'){99}elseif($name -eq 'ControlId'){50000}else{$false};$property.SetValue($p,$value,$null);$f=[CP117InputRead]::Describe($p);if($f.supported -or $f.keyboardAdmission){throw 'PROVIDER_UNSUPPORTED_AUTHORITY'};$property.SetValue($p,$before,$null)
}
$refused=$false;try{[CP117InputRead]::Describe($null)|Out-Null}catch{$refused=$true};if(-not $refused){throw 'PROVIDER_NULL'}
[Console]::Out.WriteLine('PROVIDER_EIGHT_GATES_PASS')
"""
  with tempfile.TemporaryDirectory()as directory:
   path=Path(directory)/'case.ps1';path.write_text(script,encoding='utf-8');r=subprocess.run([shutil.which('powershell.exe'),'-NoProfile','-NonInteractive','-File',str(path)],capture_output=True,text=True,timeout=30)
   Path(directory,'result.json').write_text(json.dumps({'exit':r.returncode,'stdout':r.stdout,'stderr':r.stderr}))
   self.assertEqual(r.returncode,0,r.stderr);self.assertIn('PROVIDER_EIGHT_GATES_PASS',r.stdout)
