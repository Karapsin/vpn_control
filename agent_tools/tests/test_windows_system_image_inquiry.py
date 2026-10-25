"""Public read-only image evidence and complete collector contracts.

The retained native result is an inquiry, not a signed-image or input policy.
No test launches the observer/client, invokes UI, or opens a credential/profile.
"""
import ast,base64,copy,hashlib,json,os,subprocess,tempfile,types,unittest
from pathlib import Path
F=Path(__file__).parent/'fixtures/windows_system_image_inquiry'
PINS={'child.fixed.source': '33399ec35b9a4fd8c5b9c5c3902830396d0b860bba77cda4c69b02b906a752b6', 'methods.fixed.source': '566cb7369354feeb41bacac57f6b9e10c1188bf8219b1a7617e80781406b3e13', 'native-before-stdout.json': 'c67622ce50bddb1db0fc7ded55a95e52830c834c2181d24bc735bfa29eee1dc8', 'native-closed-public.json': '3c1e87a16adbff2ec02f399892cafa13cf70c534e789009d7a5b69a5d4881e58', 'native-evidence-stdout.json': '73f92dfc5c005cca19e08b8e3f19d49f421f44bc56e741ccd780ff23b823966b', 'native.before.source': '21a0185c5bee3d0ec6045a64ba319ab396f4aceabd82f8b981cbd2aa503121b3', 'native.fixed.source': 'd761bc4c8e4c581af05559d27855562e9324d86b8839e5b63eac7eb9927cda5b', 'owner.fixed.source': '3ec1220bd38862f9edba1c622c21754b795a8da5b5b14c7536824e377b9cd07a', 'validator.fixed.source': 'ea2ed80e4c83957d636118993ddb3580805d6389fac5c501e2873e94433dc318'}
def raw(name):
 body=(F/name).read_bytes()
 if hashlib.sha256(body).hexdigest()!=PINS[name]:raise AssertionError('public fixture byte drift: '+name)
 return body

def validator():
 m=types.ModuleType('fixed_public_inquiry_validation');exec(compile(raw('validator.fixed.source'),'fixed public inquiry validation','exec'),m.__dict__);return m

def owner_decoder():
 # Full original module authenticated; only its complete pure decoder/helpers
 # execute in a test namespace. No archived dispatch/native function executes.
 source=raw('owner.fixed.source');tree=ast.parse(source);nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name in {'need','_load'}]
 if len(nodes)!=2:raise AssertionError('decoder boundary')
 m=types.ModuleType('fixed_public_inquiry_decoder');m.json=json;exec(compile(ast.Module(body=nodes,type_ignores=[]),'fixed complete decoder functions','exec'),m.__dict__);return m
V=validator();O=owner_decoder()
class Evidence(unittest.TestCase):
 def values(self):
  facts=O._load(raw('native-evidence-stdout.json'));native=O._load(raw('native-closed-public.json'));op=native['operationId'];machine=native['machine'];config={k:native[k]for k in ('operationId','machine','boot','nativeSha256')};config.update(accountName=facts['actualAccount']['name'],accountSid=facts['actualAccount']['sid']);packet={'config':config,'controllerSha256':native['controllerSha256'],'sourceSha256':native['parentSourceSha256']}
  g={'operationId':op,'state':'terminal','nativeSha256':config['nativeSha256'],'parent':native['parent'],'child':native['child'],'exitCode':0,'waitSignaled':True,'stdoutEOF':True,'stderrEOF':True,'overflow':False,'inputAuthority':False,'nativeQualified':False,'replayAllowed':False,'stderrBytes':0,'publicStreams':{'stdout':{'complete':True,'raw':base64.b64encode(raw('native-evidence-stdout.json')).decode()},'stderr':{'complete':True,'raw':''}}}
  reply={'state':'observed','operationId':op,'machine':machine,'provider':'raw-qemu-windows','guestAgent':True,'sessionFacts':g};value={'status':{'state':'terminal','terminal':{'programSha256':packet['controllerSha256'],'exitCode':0,'streamsClosed':True}},'stdout':base64.b64encode(json.dumps(reply).encode()).decode(),'stderr':''};return packet,value,reply,facts
 def update(self,value,reply,facts):reply['sessionFacts']['publicStreams']['stdout']['raw']=base64.b64encode(json.dumps(facts,separators=(',',':')).encode()).decode();value['stdout']=base64.b64encode(json.dumps(reply).encode()).decode()
 def qualify(self,p,v):return V.validate_complete(p,v,owner=O,operation=p['config']['operationId'],machine=p['config']['machine'])
 def test_actual_native_generic_pin_block_is_retained_not_weakened(self):
  before=O._load(raw('native-before-stdout.json'));self.assertEqual(before['reason'],'CLIENT_SOURCE_REPARSE');self.assertEqual(before['stage'],'file-id');self.assertEqual((before['imagePhysical']['links'],before['imagePhysical']['attributes']&0x410),(2,0));self.assertNotIn('console',before)
  old=raw('native.before.source');fixed=raw('native.fixed.source');self.assertIn(b'(directory||i.Links==1)',old);self.assertEqual(fixed,old.rstrip()[:-1]+raw('methods.fixed.source')+b'}\n')
 def test_actual_new_inquiry_retains_nonzero_signature_and_unavailable_intended_session(self):
  p,v,_,_=self.values();q=self.qualify(p,v);f=q['facts'];self.assertEqual(q['state'],'public-inquiry-evidence-collected');self.assertEqual(f['image']['signature']['verifyStatus'],-2146762496);self.assertEqual(f['image']['signature']['closeStatus'],0);self.assertEqual(f['session']['failure']['reason'],'INQUIRY_INTENDED_SESSION_UNAVAILABLE');self.assertNotIn('ordinaryToken',f['session'])
  for k in ('inputAuthority','imageAdmission','idleAuthority','compiledMethodAuthority'):self.assertIs(q[k],False)
 def test_actual_hardlink_fileids_acl_and_public_native_terminal_projection_match(self):
  _,_,_,f=self.values();i=f['image'];self.assertEqual(i['physical']['links'],2);self.assertEqual(len(i['hardlinks']['links']),2)
  for link in i['hardlinks']['links']:self.assertEqual(link['physical'],i['physical']);self.assertIs(link['sameFileIdAndGeneration'],True)
  self.assertEqual(i['acl']['ownerSid'],i['acl']['groupSid']);self.assertEqual(len(i['acl']['entries']),6);self.assertFalse(i['acl']['saclRequested']);n=O._load(raw('native-closed-public.json'));self.assertEqual(n['nativeSha256'],hashlib.sha256(raw('native.fixed.source')).hexdigest());self.assertTrue(n['actualStdoutEOF']and n['actualStderrEOF']);self.assertEqual((n['actualHostTerminalExit'],n['actualGuestTerminalExit'],n['actualStderrBytes']),(0,0,0))
 def test_whole_collector_refuses_foreign_actor_source_boot_and_bool_account(self):
  for mutate in (lambda f:f['selfBase'].update(birth='foreign'),lambda f:f.update(boot='foreign'),lambda f:f['source'].update(nativeSha256='0'*64),lambda f:f['actualAccount'].update(enabled=1),lambda f:f['selfToken'].update(sid='S-1-5-19')):
   p,v,r,f=self.values();mutate(f);self.update(v,r,f)
   with self.assertRaises(ValueError):self.qualify(p,v)
 def test_whole_collector_refuses_unknown_or_missing_full_stream_closure(self):
  for mutate in (lambda g:g.update(stdoutEOF=False),lambda g:g.update(stderrEOF=False),lambda g:g.update(overflow=True),lambda g:g['child'].update(session=1),lambda g:g['parent'].update(sourceSha256='0'*64)):
   p,v,r,f=self.values();mutate(r['sessionFacts']);self.update(v,r,f)
   with self.assertRaises(ValueError):self.qualify(p,v)
 def test_whole_decoder_rejects_duplicate_nonfinite_overflow_and_unrelated_fields(self):
  for body in (b'{"schemaVersion":1,"schemaVersion":1}',b'{"schemaVersion":NaN}',b'x'*1048577):
   with self.assertRaises(ValueError):O._load(body)
  p,v,r,f=self.values();f['secret']='never a recognized field';self.update(v,r,f)
  with self.assertRaises(ValueError):self.qualify(p,v)
 def test_evidence_cannot_be_promoted_by_false_signature_flags_or_admission(self):
  for mutate in (lambda f:f.update(imageAdmission=True),lambda f:f['image']['signature'].update(imageAdmission=True),lambda f:f['image']['signature'].update(cacheOnly=False),lambda f:f['image']['signature'].update(revocationChecked=True),lambda f:f['image']['signature'].update(closeStatus=1)):
   p,v,r,f=self.values();mutate(f);self.update(v,r,f)
   with self.assertRaises(ValueError):self.qualify(p,v)
 def test_foreign_or_escaping_link_and_acl_ambiguity_refuse(self):
  for mutate in (lambda f:f['image']['physical'].update(volume=1),lambda f:f['image']['hardlinks']['links'][0].update(volumeRelativeName='\\..\\other'),lambda f:f['image']['hardlinks']['links'][0]['physical'].update(indexLow=1),lambda f:f['image']['acl']['entries'][0].update(accessMask=True),lambda f:f['image']['acl'].update(saclRequested=True)):
   p,v,r,f=self.values();mutate(f);self.update(v,r,f)
   with self.assertRaises(ValueError):self.qualify(p,v)
 def test_token_unavailable_retains_console_but_does_not_adopt_ordinary_account(self):
  p,v,r,f=self.values();f['session']['failure']['stage']='ordinary-token';f['session']['failure']['reason']='INQUIRY_ORDINARY_TOKEN_UNAVAILABLE';self.update(v,r,f);q=self.qualify(p,v);self.assertEqual(q['facts']['session']['console']['session'],1);self.assertFalse(q['inputAuthority'])
 def test_controlled_intended_token_snapshot_still_cannot_authorize_input(self):
  p,v,r,f=self.values();c=f['session']['console'];c.update(state=0,intendedUserNameMatches=True,localDomainMatches=True,logon='1234');f['session'].update(state='observed',ordinaryToken={'sid':p['config']['accountSid'],'session':c['session'],'groups':[{'sid':'S-1-5-32-545','attributes':7}]});del f['session']['failure'];self.update(v,r,f);q=self.qualify(p,v);self.assertFalse(q['inputAuthority']);self.assertFalse(q['facts']['session']['stableRecipientAdmission'])
  f['session']['ordinaryToken']['groups'].append({'sid':'S-1-5-32-544','attributes':14});self.update(v,r,f)
  with self.assertRaises(ValueError):self.qualify(p,v)
 def test_fixed_emitted_child_is_current_account_epoch_guarded_and_has_no_input(self):
  child=raw('child.fixed.source').decode();call='[SecureCheckClientV3]::InquireSystemImageAndSession(';self.assertEqual(child.count(call),1);self.assertLess(child.index('READONLY_GUEST_EPOCH'),child.index(call));self.assertLess(child.index('READONLY_ORDINARY_ACCOUNT_CHANGED'),child.index(call));methods=raw('methods.fixed.source').decode()
  for forbidden in ('CreateProcess','DuplicateToken','AdjustToken','SetTokenInformation','NamedPipe','AutomationElement','ValuePattern','TextPattern','SendInput','File.Write','File.Delete'):self.assertNotIn(forbidden,methods)
 @unittest.skipUnless(os.name=='nt','Windows .NET Framework compiler only; no native method invocation')
 def test_windows_framework_compiles_exact_before_and_inquiry_without_invoking_methods(self):
  # Each full source compiles in its own process; no type/method/static field is
  # invoked/read by this test. Native API behavior belongs to retained fixture
  # acceptance, not to this ordinary Windows CI process.
  for name in ('native.before.source','native.fixed.source'):
   with self.subTest(source=name),tempfile.TemporaryDirectory()as td:
    path=Path(td)/'native.cs';path.write_bytes(raw(name))
    script="""$ErrorActionPreference='Stop';'UIAutomationClient','UIAutomationTypes','WindowsBase','System.Management','System.Web.Extensions'|ForEach-Object {[void][Reflection.Assembly]::LoadWithPartialName($_)}
$source=[IO.File]::ReadAllText($args[0]);$errors=@();Add-Type -ReferencedAssemblies @('System.dll','System.Core.dll','System.Management.dll','System.Web.Extensions.dll',[Windows.Automation.AutomationElement].Assembly.Location,[Windows.Automation.ControlType].Assembly.Location,[Windows.Rect].Assembly.Location) -TypeDefinition $source -ErrorAction Continue -ErrorVariable errors
if(@($errors).Count -ne 0){foreach($e in @($errors)){[Console]::Error.WriteLine($e.ToString())};exit 65};[Console]::WriteLine('COMPILED_NO_METHOD_INVOKED')
"""
    runner=Path(td)/'compile.ps1';runner.write_text(script,encoding='utf-8');result=subprocess.run(['powershell.exe','-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',str(runner),str(path)],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60,check=False)
    self.assertEqual(result.returncode,0,result.stderr[:4096]);self.assertIn(b'COMPILED_NO_METHOD_INVOKED',result.stdout)
if __name__=='__main__':unittest.main()
