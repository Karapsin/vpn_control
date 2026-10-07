import ast,base64,gzip,hashlib,inspect,json,os,shutil,subprocess,tempfile,textwrap,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[2]
if os.name!='nt':
 from agent_tools import windows_cp117_secure_input_descendants_observe as m
 from agent_tools import windows_cp117_secure_input_observe as original
 from agent_tools.tests import test_windows_cp117_secure_layout_observe as layout

def native_source():
 tree=ast.parse((ROOT/'agent_tools/windows_cp117_secure_input_descendants_observe.py').read_text())
 return next(ast.literal_eval(n.value)for n in tree.body if isinstance(n,ast.Assign)and any(isinstance(x,ast.Name)and x.id=='_SEMANTIC_CS'for x in n.targets))

def production_compile_fragment():
 tree=ast.parse((ROOT/'agent_tools/windows_cp117_secure_input_descendants_observe.py').read_text())
 native=native_source();ns={'base64':base64,'gzip':gzip,'_SEMANTIC_CS':native,'NATIVE_SHA':hashlib.sha256(native.encode()).hexdigest()}
 body=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='bodies')
 statements=[]
 for n in body.body:
  if isinstance(n,ast.Assign)and any(isinstance(x,ast.Name)and x.id in ('packed','insertion')for x in n.targets):statements.append(n)
  elif isinstance(n,ast.AugAssign)and isinstance(n.target,ast.Name)and n.target.id=='insertion':statements.append(n)
 exec(compile(ast.Module(body=statements,type_ignores=[]),'production-compressed-bootstrap','exec'),ns)
 fragment=ns['insertion'].split(' $cf=')[0]
 if '::Read' in fragment:raise ValueError('inert-read-boundary')
 return '\n'.join(line.lstrip(' ')for line in fragment.splitlines())+'\n'

def compressed_case_script():
 fixed=production_compile_fragment();typed='[IO.Compression.CompressionMode]0'
 if fixed.count(typed)!=1:raise ValueError('typed-compression-mode')
 old=fixed.replace(typed,'0')
 encoded=base64.b64encode(old.encode()).decode()
 return "$ErrorActionPreference='Stop';$old=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('"+encoded+"'));$rejected=$false;try{&([ScriptBlock]::Create($old));throw 'OLD_BOOTSTRAP_ACCEPTED'}catch{if($_.FullyQualifiedErrorId -cne 'MethodCountCouldNotFindBest'){throw};$rejected=$true}\n"+fixed+"\nif(-not $rejected -or [CP117InputRead].GetMethod('Collect') -eq $null){throw 'COMPRESSED_COMPILE_CASES'};[Console]::Out.WriteLine('CENSUS_COMPRESSED_CASES_PASS')\n"

@unittest.skipIf(os.name=='nt','POSIX native transport tests run on coordinator')
class CensusTests(unittest.TestCase):
 def node(self):
  return {'pid':1096,'controlId':50032,'nativeHandle':65626,'depth':0,'runtimeId':[42,99],'x':0,'y':0,'width':1024,'height':768,'ownerMatches':True,'edit':False,'password':False,'keyboardFocus':True,'keyboardFocusable':False,'enabled':True,'onscreen':True,'passwordLabel':False,'nativeEditCompatible':False,'nativeFocusMatches':True}
 def answer(self):
  a=layout.SecureLayoutTests().answer();a['reader']['nonce']=m.NONCE;a['birth']['nonce']=m.NONCE;a['reader']['sourceSha256']=m.CHILD_SHA;a['birth']['sourceSha256']=m.CHILD_SHA
  a['facts']['secureInput']={'threadId':111,'focusWindow':65626,'hkl':'0000000004090409','windowStation':'WinSta0','desktop':'Winlogon','maxNodes':64,'maxDepth':8,'keyboardAdmission':False,'nodes':[self.node()]};return a
 def terminal(self,a=None,nonce=None):
  a=a or self.answer();raw=('CP117-READ '+(nonce or m.NONCE)+' '+m.PARENT_SHA+' 456\n'+json.dumps(a)).encode();return {'exited':True,'exitcode':0,'out-data':base64.b64encode(raw).decode()}
 def test_actual_secure_host_window_remains_no_empty_or_input_authority(self):
  a=self.answer();self.assertEqual(m.parse_terminal(self.terminal(a),m.NONCE,m.PARENT_SHA,456),a)
  with self.assertRaises(ValueError):original.validate_semantic(a)
  self.assertFalse(a['facts']['secureInput']['keyboardAdmission']);self.assertNotIn('passwordLength',a['facts']['secureInput'])
 def test_parser_foreign_caps_runtime_duplicates_geometry_drift_refused(self):
  for k,v in [('pid',99),('depth',9),('runtimeId',[1]*33),('width',float('nan')),('nativeEditCompatible',True),('nativeFocusMatches',False),('ownerMatches',False)]:
   a=self.answer();a['facts']['secureInput']['nodes'][0][k]=v
   with self.subTest(k=k),self.assertRaises(ValueError):m.parse_terminal(self.terminal(a),m.NONCE,m.PARENT_SHA,456)
  a=self.answer();a['facts']['secureInput']['nodes']=[self.node()]*65
  with self.assertRaises(ValueError):m.parse_terminal(self.terminal(a),m.NONCE,m.PARENT_SHA,456)
  a=self.answer();child=self.node();child['depth']=1;a['facts']['secureInput']['nodes'].append(child)
  with self.assertRaises(ValueError):m.parse_terminal(self.terminal(a),m.NONCE,m.PARENT_SHA,456)
 def test_new_sources_do_not_read_text_length_or_change_focus(self):
  cs=native_source();self.assertIn('hwnd.ToInt64()==65626',cs);self.assertLess(cs.index('IntPtr hwnd=Focus'),cs.index('AutomationElement.FromHandle(hwnd)'))
  for banned in ('SendMessageTimeout','ValuePattern','TextPattern','SetFocus','GetKeyState','passwordLength'):
   self.assertNotIn(banned,cs)
  self.assertIn('passwordLabel=p.Name=="Password"',cs);self.assertIn('NodeFacts Freeze()',cs);self.assertIn('Stable(new UiNode(root))',cs)
  parent,child,_=m.bodies();self.assertLess(len(base64.b64encode(child.encode('utf-16le'))),30000);self.assertIn("WritePrivate 'failure.json'",child);self.assertIn('GuardFailureAcl',parent)
 def test_actual_generated_bootstrap_binds_enum_overload_and_compile_before_read(self):
  fragment=production_compile_fragment();self.assertIn('[IO.Compression.CompressionMode]0',fragment)
  parent,child,_=m.bodies();self.assertIn(fragment,child);self.assertNotIn('::Read([uint32[]]',fragment);self.assertIn('COMPRESSED_COMPILE_CASES',compressed_case_script())
 def execute_flow(self,stale=False,foreign=False):
  src=textwrap.dedent(inspect.getsource(layout.CompleteGeneratedFlowTests.execute_flow)).replace('secure.program(record,secure.NONCE)','m.program(record)').replace('secure.CORRELATION','m.CORRELATION').replace('secure.NONCE','m.NONCE')
  ns={'ast':ast,'base64':base64,'json':json,'patch':patch,'secure':m.secure,'m':m};exec(src,ns);return ns['execute_flow'](self,stale,foreign)
 def observe_fixture(self,drift=False):
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
   for target,name,value in [(m.login.guest,'recovery',recovery),(m,'_factories',lambda:None),(m,'AuthorityCapture',Capture),(recovery,'_local_read',lambda *a:raw),(authority,'_source_pins',lambda *a:{}),(authority,'_read_bound_file',bound),(authority,'_outer_authority',lambda *a:{}),(authority,'_verify_outer',lambda *a:None),(m,'program',lambda *a:('print("readonly")','a'*64)),(authority.closure.base,'_descriptor',lambda *a:(object(),None,None)),(authority.closure.base.ssh_transport,'build_ssh_argv',lambda *a,**k:['inert']),(m.login.guest,'_stream',stream)]:stack.enter_context(patch.object(target,name,value))
   result=m.observe(root)
  historical_source.verify(recovery,historical,m.login.guest.RECOVERY_SHA)
  return result,calls,records
 def test_actual_observe_wrapper_pins_original_module_before_and_after_dispatch(self):
  result,calls,records=self.observe_fixture();self.assertEqual(result['state'],'observed',result)
  self.assertGreaterEqual(calls.count(str(Path(original.__file__))),3)
  request=json.loads(next(v for (leaf,name),v in records.items()if name=='request.json'));self.assertEqual(request['originalSemantic']['sha256'],m.ORIGINAL_SEMANTIC_SHA);self.assertFalse(request['keyboardAdmission'])
 def test_actual_observe_wrapper_same_content_original_generation_drift_refused(self):
  result,_,_=self.observe_fixture(drift=True);self.assertEqual(result['state'],'unknown');self.assertEqual(result['phase'],'tuple-factory-source-drift')
 def test_whole_generated_one_submit_same_child_census(self):
  r,calls,_=self.execute_flow();self.assertEqual(r['state'],'observed');self.assertEqual(r['facts'],self.answer());self.assertEqual([x[0]for x in calls],['guest-exec','guest-exec-status']);self.assertEqual(calls[1][1],{'pid':456})
 def test_stale_same_child80_and_foreign_zero(self):
  r,calls,_=self.execute_flow(stale=True);self.assertEqual(r['state'],'unknown');self.assertEqual(len(calls),81)
  r,calls,_=self.execute_flow(foreign=True);self.assertEqual(r['state'],'unknown');self.assertEqual(calls,[])

_FAKE_CS=r"""
public static class CensusFixture {
 public class Fake:CP117InputRead.INode {public CP117InputRead.NodeFacts value;public Fake child,next;public int captures;public bool flip;public CP117InputRead.NodeFacts Capture(){captures++;if(flip&&captures==2)value.enabled=!value.enabled;return value;}public CP117InputRead.INode FirstChild(){return child;}public CP117InputRead.INode NextSibling(){return next;}}
 static Fake Node(int id){return new Fake{value=new CP117InputRead.NodeFacts{pid=1096,controlId=50032,runtimeId=new int[]{1,id},ownerMatches=true,enabled=true,width=1,height=1}};}
 static bool Refuse(Fake root,string code){try{CP117InputRead.Stable(root);return false;}catch(System.InvalidOperationException e){return e.Message==code;}}
 public static bool Run(){
  var root=Node(1);root.child=Node(2);root.child.next=Node(3);var rows=CP117InputRead.Stable(root);if(rows.Length!=3||rows[1].depth!=1||rows[2].depth!=1)return false;
  root=Node(1);root.child=Node(1);if(CP117InputRead.Stable(root).Length!=1)return false;
  root=Node(1);root.child=Node(1);root.child.value.enabled=false;if(!Refuse(root,"CENSUS_RUNTIME_DRIFT"))return false;
  root=Node(1);root.child=Node(2);root.child.flip=true;if(!Refuse(root,"CENSUS_TREE_DRIFT"))return false;
  root=Node(1);var current=root;for(int i=2;i<=10;i++){current.child=Node(i);current=current.child;}if(!Refuse(root,"CENSUS_DEPTH_BOUND"))return false;
  root=Node(1);root.child=Node(2);current=root.child;for(int i=3;i<=65;i++){current.next=Node(i);current=current.next;}if(!Refuse(root,"CENSUS_NODE_BOUND"))return false;
  root=Node(1);root.child=Node(2);root.child.next=root.child;if(!Refuse(root,"CENSUS_EDGE_BOUND"))return false;
  root=Node(1);root.value.runtimeId=new int[33];if(!Refuse(root,"CENSUS_RUNTIME_BOUND"))return false;
  root=Node(1);root.value.pid=99;if(!Refuse(root,"CENSUS_FOREIGN_NODE"))return false;
  return true;
 }
}
"""
@unittest.skipUnless(shutil.which('powershell.exe'),'Windows PowerShell unavailable')
class ExecutableTraversalTests(unittest.TestCase):
 def test_actual_provider_traversal_dedup_caps_and_mutable_drift(self):
  cs=native_source()+_FAKE_CS
  script=r"""$ErrorActionPreference='Stop';'UIAutomationClient','UIAutomationTypes','WindowsBase'|ForEach-Object {[void][Reflection.Assembly]::LoadWithPartialName($_)}
Add-Type -ReferencedAssemblies @('System.dll','System.Core.dll',[Windows.Automation.AutomationElement].Assembly.Location,[Windows.Automation.ControlType].Assembly.Location,[Windows.Rect].Assembly.Location) -TypeDefinition @'
"""+cs+r"""
'@
if(-not [CensusFixture]::Run()){throw 'CENSUS_INERT_CASES'}
[Console]::Out.WriteLine('CENSUS_PROVIDER_CASES_PASS')
"""
  with tempfile.TemporaryDirectory()as directory:
   p=Path(directory)/'case.ps1';p.write_text(script,encoding='utf-8');r=subprocess.run([shutil.which('powershell.exe'),'-NoProfile','-NonInteractive','-File',str(p)],capture_output=True,text=True,timeout=30)
   Path(directory,'result.json').write_text(json.dumps({'exit':r.returncode,'stdout':r.stdout,'stderr':r.stderr}));self.assertEqual(r.returncode,0,r.stderr);self.assertIn('CENSUS_PROVIDER_CASES_PASS',r.stdout)

@unittest.skipUnless(shutil.which('powershell.exe'),'Windows PowerShell unavailable')
class ExecutableCompressedBootstrapTests(unittest.TestCase):
 def test_actual_untyped_constructor_red_typed_production_compile_green(self):
  script=compressed_case_script()
  with tempfile.TemporaryDirectory()as directory:
   p=Path(directory)/'compressed.ps1';p.write_text(script,encoding='utf-8');r=subprocess.run([shutil.which('powershell.exe'),'-NoProfile','-NonInteractive','-File',str(p)],capture_output=True,text=True,timeout=30)
   Path(directory,'result.json').write_text(json.dumps({'exit':r.returncode,'stdout':r.stdout,'stderr':r.stderr}));self.assertEqual(r.returncode,0,r.stderr);self.assertIn('CENSUS_COMPRESSED_CASES_PASS',r.stdout)
