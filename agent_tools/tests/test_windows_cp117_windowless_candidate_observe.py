import ast,base64,gzip,re,hashlib,inspect,json,os,shutil,subprocess,tempfile,textwrap,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[2]
if os.name!='nt':
 from agent_tools import windows_cp117_windowless_candidate_observe as m
 from agent_tools import windows_cp117_secure_input_observe as original
 from agent_tools.tests import test_windows_cp117_secure_layout_observe as layout

def native_source():
 tree=ast.parse((ROOT/'agent_tools/windows_cp117_windowless_candidate_observe.py').read_text())
 return next(ast.literal_eval(n.value)for n in tree.body if isinstance(n,ast.Assign)and any(isinstance(x,ast.Name)and x.id=='_SEMANTIC_CS'for x in n.targets))

def production_compile_fragment():
 tree=ast.parse((ROOT/'agent_tools/windows_cp117_windowless_candidate_observe.py').read_text())
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
 def axis(self,value):return {'finite':True,'isNaN':False,'positiveInfinite':False,'negativeInfinite':False,'withinBound':True,'value':value}
 def node(self,rid=16):
  return {'pid':1096,'controlId':50020 if rid==19 else 50004,'nativeHandle':0,'depth':4 if rid==16 else 5,'runtimeId':[42,65626,4,rid],'isEmpty':False,'x':self.axis(100),'y':self.axis(200),'width':self.axis(200),'height':self.axis(40),'isPassword':rid!=19,'keyboardFocus':rid==17,'keyboardFocusable':rid!=19,'enabled':True,'offscreen':False,'passwordName':rid==19}
 def answer(self):
  a=layout.SecureLayoutTests().answer();a['reader']['nonce']=m.NONCE;a['birth']['nonce']=m.NONCE;a['reader']['sourceSha256']=m.CHILD_SHA;a['birth']['sourceSha256']=m.CHILD_SHA
  a['facts']['secureInput']={'threadId':111,'focusWindow':65626,'hkl':'0000000004090409','windowStation':'WinSta0','desktop':'Winlogon','maxNodes':64,'maxDepth':8,'keyboardAdmission':False,'nodes':[self.node(i)for i in(16,17,19)]};return a
 def terminal(self,a=None,nonce=None):
  a=a or self.answer();raw=('CP117-READ '+(nonce or m.NONCE)+' '+m.PARENT_SHA+' 456\n'+json.dumps(a)).encode();return {'exited':True,'exitcode':0,'out-data':base64.b64encode(raw).decode()}
 def test_supported_windowless_targets_are_diagnostic_not_password_empty_authority(self):
  a=self.answer();self.assertEqual(m.parse_terminal(self.terminal(a),m.NONCE,m.PARENT_SHA,456),a)
  with self.assertRaises(ValueError):original.validate_semantic(a)
  self.assertFalse(a['facts']['secureInput']['keyboardAdmission']);self.assertNotIn('passwordLength',a['facts']['secureInput'])
  # The placeholder boolean alone does not establish empty content or input authority.
  for n in a['facts']['secureInput']['nodes']:n['isPassword']=False;n['keyboardFocus']=False
  self.assertEqual(m.parse_terminal(self.terminal(a),m.NONCE,m.PARENT_SHA,456),a)
 def test_separate_observation_changed_ids_allowed_diagnostic_only_within_pair_unique(self):
  a=self.answer();b=self.answer()
  for n in b['facts']['secureInput']['nodes']:n['runtimeId'][-1]+=100
  for value in(a,b):self.assertEqual(m.parse_terminal(self.terminal(value),m.NONCE,m.PARENT_SHA,456),value);self.assertFalse(value['facts']['secureInput']['keyboardAdmission'])
  b['facts']['secureInput']['nodes'][1]['runtimeId']=b['facts']['secureInput']['nodes'][0]['runtimeId']
  with self.assertRaises(ValueError):m.parse_terminal(self.terminal(b),m.NONCE,m.PARENT_SHA,456)
 def test_foreign_caps_non_candidate_malformed_flags_refused_empty_tree_no_authority(self):
  for k,v in [('pid',99),('depth',9),('controlId',50032),('runtimeId',[1]*33),('isPassword',1),('passwordName','Password'),('x',{'value':0})]:
   a=self.answer();a['facts']['secureInput']['nodes'][0][k]=v
   with self.subTest(k=k),self.assertRaises(ValueError):m.parse_terminal(self.terminal(a),m.NONCE,m.PARENT_SHA,456)
  a=self.answer();a['facts']['secureInput']['nodes']=[];self.assertEqual(m.parse_terminal(self.terminal(a),m.NONCE,m.PARENT_SHA,456),a);self.assertFalse(a['facts']['secureInput']['keyboardAdmission'])
 def test_source_no_content_length_focus_changes_or_keyboard_actions(self):
  cs=native_source()
  for banned in('SendMessageTimeout','ValuePattern','TextPattern','SetFocus','GetKeyState','passwordLength','ValueProperty') :self.assertNotIn(banned,cs)
  self.assertIn('p.Name=="Password"',cs);self.assertIn('c&&p.IsPassword',cs);self.assertIn('c&&p.HasKeyboardFocus',cs);self.assertNotIn('id[3]==16',cs)
  self.assertIn('Candidates(Stable(new UiNode(root)))',cs);self.assertIn('keyboardAdmission=false',cs)
  parent,child,_=m.bodies();self.assertLess(len(base64.b64encode(child.encode('utf-16le'))),30000);self.assertIn("WritePrivate 'failure.json'",child);self.assertIn('GuardFailureAcl',parent)
 def test_actual_generated_bootstrap_preserves_typed_compile_before_read(self):
  fragment=production_compile_fragment();self.assertIn('[IO.Compression.CompressionMode]0',fragment)
  parent,child,_=m.bodies();self.assertIn(fragment,child);self.assertNotIn('::Read([uint32[]]',fragment)
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
public static class CandidateFixture {
 public class Fake:CP117InputRead.INode {public CP117InputRead.NodeFacts value;public Fake child,next;public int captures;public bool flip;public CP117InputRead.NodeFacts Capture(){captures++;if(flip&&captures==2)value.keyboardFocus=!value.keyboardFocus;return value;}public CP117InputRead.INode FirstChild(){return child;}public CP117InputRead.INode NextSibling(){return next;}}
 static Fake Node(int id,int type=50004){return new Fake{value=new CP117InputRead.NodeFacts{pid=1096,controlId=type,runtimeId=new int[]{42,65626,4,id},x=CP117InputRead.Axis(0,false),y=CP117InputRead.Axis(0,false),width=CP117InputRead.Axis(100,true),height=CP117InputRead.Axis(30,true),isPassword=type==50004,keyboardFocus=type==50004,keyboardFocusable=type==50004,enabled=true}};}
 static bool Refuse(Fake root,string code){try{CP117InputRead.Stable(root);return false;}catch(System.InvalidOperationException e){return e.Message==code;}}
 public static bool Run(){
  var root=Node(1,50032);root.child=Node(16);root.child.next=Node(19,50020);root.child.next.value.passwordName=true;var a=CP117InputRead.Candidates(CP117InputRead.Stable(root));if(a.Length!=2||!a[0].isPassword||!a[0].keyboardFocus||!a[1].passwordName)return false;
  root.child.value.runtimeId[3]=116;root.child.next.value.runtimeId[3]=119;var b=CP117InputRead.Candidates(CP117InputRead.Stable(root));if(b.Length!=2||b[0].runtimeId[3]!=116||a[0].runtimeId[3]!=16)return false;
  root=Node(1,50032);if(CP117InputRead.Candidates(CP117InputRead.Stable(root)).Length!=0)return false;
  root=Node(1);root.flip=true;if(!Refuse(root,"CENSUS_TREE_DRIFT"))return false;
  root=Node(1);root.child=Node(1);if(!Refuse(root,"CENSUS_RUNTIME_DUPLICATE"))return false;
  root=Node(1);root.value.pid=99;if(!Refuse(root,"CENSUS_FOREIGN_NODE"))return false;
  root=Node(1);var current=root;for(int i=2;i<=10;i++){current.child=Node(i);current=current.child;}if(!Refuse(root,"CENSUS_DEPTH_BOUND"))return false;
  root=Node(1);root.child=Node(2);current=root.child;for(int i=3;i<=65;i++){current.next=Node(i);current=current.next;}if(!Refuse(root,"CENSUS_NODE_BOUND"))return false;
  root=Node(1);root.value.runtimeId=new int[33];if(!Refuse(root,"CENSUS_RUNTIME_BOUND"))return false;
  root=Node(1);root.value.isEmpty=true;root.value.x=CP117InputRead.Axis(double.PositiveInfinity,false);var unavailable=CP117InputRead.Candidates(CP117InputRead.Stable(root));if(!unavailable[0].x.positiveInfinite||unavailable[0].x.value!=null)return false;
  return true;
 }
}
"""
def candidate_case_script():
 fragment=production_compile_fragment();marker='Add-Type -ReferencedAssemblies '
 if fragment.count(marker)!=1:raise ValueError('fixed-candidate-compiler')
 fragment=fragment.replace(marker,"$c+=@'\n"+_FAKE_CS+"\n'@\n"+marker)
 return "$ErrorActionPreference='Stop';\n"+fragment+"\nif(-not [CandidateFixture]::Run()){throw 'CANDIDATE_INERT_CASES'};[Console]::Out.WriteLine('CANDIDATE_CASES_PASS')\n"

@unittest.skipUnless(shutil.which('powershell.exe'),'Windows PowerShell unavailable')
class ExecutableCandidateTests(unittest.TestCase):
 def test_actual_production_compressed_dynamic_candidates_provider_cases(self):
  with tempfile.TemporaryDirectory()as directory:
   p=Path(directory)/'candidate.ps1';p.write_text(candidate_case_script(),encoding='utf-8');r=subprocess.run([shutil.which('powershell.exe'),'-NoProfile','-NonInteractive','-File',str(p)],capture_output=True,text=True,timeout=30)
   Path(directory,'result.json').write_text(json.dumps({'exit':r.returncode,'stdout':r.stdout,'stderr':r.stderr}));self.assertEqual(r.returncode,0,r.stderr);self.assertIn('CANDIDATE_CASES_PASS',r.stdout)
