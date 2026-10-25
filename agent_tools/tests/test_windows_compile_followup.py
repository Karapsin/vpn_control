"""Whole public compiler/source/capture causals; no infrastructure inventory."""
from pathlib import Path
import ast,base64,copy,hashlib,json,os,re,subprocess,tempfile,types,unittest
from agent_tools.tests.windows_powershell_script import json_reply,run_program
FIX=Path(__file__).resolve().parent/'fixtures/windows_compile_followup'
HASHES={'native.before.source': 'd6873f948fa50eabeb9ddf5507b9c3765d522abe5b4cdd25abcc023334699740', 'native.exit-fixed.source': '69158117dc5ca71234cec0b60bb07932863536da957a5df6114ef1d093bd5ff1', 'native.fixed.source': '813ef9554080dd4b4e2b2d82c1e56b73992d09b233b98ad1d53698fd885bbea3', 'parent.before.source': 'c9db69ccfddef08a283d010471109e760020d52a1bff8ba0a2bdc174da80fbbd', 'parent.fixed.source': 'bfa40e47cf66d42f301cdb86e84a63468391ffa6db466220b54c8415ee9d8c30', 'child.before.source': '3c132bcdbc9dd57fc1225ebdac39ca3eb56f0dbfcb313dd6db0512bb58ee20dc', 'child.fixed.source': 'a4a7d3a3262a839f890144cdf2fb40aaeb5388c3336868c78b8517389767e5fa', 'stream_capture.source': 'c03698567e7ed831a2f9ddb30b0b34dacfe8a5b7ab947d548a17c71fac61fe12', 'dispatch.before.source': 'db73848757d6b81834aa77a9378a0117504f602e0eba31150f49a8ab4905ae0b', 'dispatch.fixed.source': 'a5378094d881b495d80a41ee0dbb787c1bcde5c8f52e639a37dd0c730f79339d', 'validator.source': '9e34738a1e04ef0b8dc62d212c4a6b24c26815f05b9d5a6ccdf346948d0a437e', 'json_decoder.source': '25665d6e56326d2ff466dd2f029285a509e75f91292d423ecd48bb272c3ef058', 'result_gate.source': '35703df681e151a7bee0c7af5d31e5fd6371b150b3344ee5eab01507f26dd7f0'}
def raw(name):
 b=(FIX/name).read_bytes()
 if hashlib.sha256(b).hexdigest()!=HASHES[name]:raise AssertionError('authenticated public fixture changed: '+name)
 return b

def need(ok,reason):
 if not ok:raise ValueError(reason)

def code(name,extra=None):
 ns={'base64':base64,'hashlib':hashlib,'json':json,'re':re,'need':need,'NATIVE_SHA':HASHES['native.exit-fixed.source']}
 if extra:ns.update(extra)
 exec(compile(raw(name),name,'exec'),ns);return ns

class NativeCompiler(unittest.TestCase):
 def test_whole_source_chain_contains_exact_two_compiler_fixes(self):
  a=raw('native.before.source');b=raw('native.exit-fixed.source');c=raw('native.fixed.source');needle=b'uint exit;Need(WaitForSingleObject(helper.process,0)==0&&GetExitCodeProcess(helper.process,out exit),'
  self.assertEqual(a.count(needle),1);self.assertEqual(b,a.replace(needle,needle.replace(b'uint exit;',b'uint exit=0;')));self.assertEqual(c,b.replace(b'var value=CancelValue(claim);',b'var value=D(CancelValue(claim));'))
  self.assertIn(b'"OWNER_HELPER_EXIT_UNKNOWN");Save(',c);self.assertEqual(c.count(b'var value=D(CancelValue(claim));'),1)
 @unittest.skipUnless(os.name=='nt','Actual Framework Add-Type compiler requires Windows')
 def test_actual_complete_before_sources_RED_fixed_GREEN_without_methods_invoked(self):
  paths=[str((FIX/n).resolve())for n in ('native.before.source','native.exit-fixed.source','native.fixed.source')]
  # Each assembly is compiled in a separate interpreter script, never executed.
  # Add-Type writes each compiler diagnostic, then throws terminating COMPILER_ERRORS: both are collected.
  source=r'''$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
'UIAutomationClient','UIAutomationTypes','WindowsBase','System.Management','System.Web.Extensions'|ForEach-Object {[void][Reflection.Assembly]::LoadWithPartialName($_)}
$native=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__SOURCE__'))
$errors=@();$terminatingErrors=@()
try{Add-Type -ReferencedAssemblies @('System.dll','System.Core.dll','System.Management.dll','System.Web.Extensions.dll',[Windows.Automation.AutomationElement].Assembly.Location,[Windows.Automation.ControlType].Assembly.Location,[Windows.Rect].Assembly.Location) -TypeDefinition $native -ErrorAction Continue -ErrorVariable errors 2>$null}catch{$terminatingErrors=@($_)}
# Compiler diagnostics only. No newly compiled type/member is read/invoked.
$result=[ordered]@{compiled=(@($errors).Count -eq 0 -and @($terminatingErrors).Count -eq 0);errors=@($errors|ForEach-Object {$_.ToString()});terminatingErrors=@($terminatingErrors|ForEach-Object {$_.FullyQualifiedErrorId+': '+$_.ToString()});inputAuthority=$false;methodsInvoked=$false}
[Console]::WriteLine(($result|ConvertTo-Json -Compress))
'''
  ps=Path(os.environ['SystemRoot'])/'System32/WindowsPowerShell/v1.0/powershell.exe';self.assertTrue(ps.is_file());rows=[];details=[]
  for path in paths:
   program=source.replace('__SOURCE__',base64.b64encode(raw(Path(path).name)).decode()).encode();row,detail=json_reply(self,run_program(ps,program,60))
   rows.append(row);details.append(Path(path).name+': '+detail)
  detail='\n'.join(details)
  self.assertFalse(rows[0]['compiled'],detail);self.assertFalse(rows[1]['compiled'],detail);self.assertTrue(rows[2]['compiled'],detail);self.assertTrue(rows[0]['errors'],detail);self.assertTrue(rows[1]['errors'],detail);self.assertEqual(rows[2]['errors'],[],detail);self.assertTrue(all(not r['inputAuthority']and not r['methodsInvoked']for r in rows),detail)
  self.assertIn('uint exit;Need',json.dumps(rows[0]['errors']),detail);self.assertIn('Correlate(Read(path),value)',json.dumps(rows[1]['errors']),detail)
  self.assertTrue(all(r['terminatingErrors']and all(e.startswith('COMPILER_ERRORS,')for e in r['terminatingErrors'])for r in rows[:2]),detail);self.assertEqual(rows[2]['terminatingErrors'],[],detail)

class AllErrorsAndEnvelope(unittest.TestCase):
 def test_entire_child_add_type_change_preserves_all_diagnostics_before_success(self):
  old=raw('child.before.source').decode();new=raw('child.fixed.source').decode();line=next(s for s in old.splitlines()if s.startswith(' Add-Type -ReferencedAssemblies'))
  replacement=' $compileDiagnostics=@()\n'+line+' -ErrorAction Continue -ErrorVariable compileDiagnostics\n if(@($compileDiagnostics).Count -ne 0){foreach($diagnostic in @($compileDiagnostics)){[Console]::Error.WriteLine($diagnostic.ToString())};exit 65}'
  self.assertEqual(new,old.replace(line,replacement));self.assertLess(new.index('if(@($compileDiagnostics).Count'),new.index('[Console]::Out.Write("COMPILE_ONLY_OK'))
 def test_whole_parent_envelope_follows_independent_terminal_and_source_closure(self):
  old=raw('parent.before.source').decode();new=raw('parent.fixed.source').decode();i=new.index('# SOURCE-ONLY successor protocol:');self.assertEqual(new[:i],old[:old.index('[Console]::WriteLine(($terminal')]);self.assertIn("Save (Join-Path $job 'terminal.json')",new[:i]);self.assertIn('$source.Dispose()',new[:i]);self.assertIn('[Math]::Min($raw.Length,16384)',new[i:]);self.assertEqual(new.count('[Console]::WriteLine('),1)

class RawRetention(unittest.TestCase):
 def environment(self,stderr=b'public-compiler-error',stdout=b''):
  op='11111111-1111-4111-8111-111111111111';image=r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe';native=HASHES['native.exit-fixed.source'];parent={'pid':1,'birth':'123','session':0,'sid':'S-1-5-18','image':image,'sourceSha256':'a'*64};child={**parent,'pid':2,'birth':'124','sourceSha256':'b'*64}
  guest={'schemaVersion':1,'operationId':op,'state':'terminal','nativeSha256':native,'inputAuthority':False,'nativeQualified':False,'replayAllowed':False,'parent':parent,'child':child,'waitSignaled':True,'stdoutEOF':True,'stderrEOF':True,'overflow':False,'compileSucceeded':False,'exitCode':65,'publicStreams':{}}
  for role,data in [('stdout',stdout),('stderr',stderr)]:
   guest[role+'Bytes']=len(data);guest[role+'Sha256']=hashlib.sha256(data).hexdigest();p=data[:16384];guest['publicStreams'][role]={'bytes':len(data),'retainedBytes':len(p),'sha256':guest[role+'Sha256'],'prefixSha256':hashlib.sha256(p).hexdigest(),'complete':len(data)<=16384,'raw':base64.b64encode(p).decode()}
  reply={'state':'observed','operationId':op,'machine':'22222222-2222-4222-8222-222222222222','provider':'raw-qemu-windows','guest':'running','guestAgent':True,'sessionFacts':guest};packet={'config':{'operationId':op,'machine':reply['machine'],'nativeSha256':native},'sourceSha256':'a'*64,'controllerSha256':'c'*64};status={'state':'terminal','terminal':{'programSha256':'c'*64,'exitCode':0,'streamsClosed':True}};value={'status':status,'stdout':base64.b64encode(json.dumps(reply).encode()).decode(),'stderr':''};return packet,value,reply
 def functions(self):
  ns=code('json_decoder.source');exec(compile(raw('validator.source'),'whole-native-owner-validator','exec'),ns);owner=types.SimpleNamespace(validate_result=ns['validate_result']);gate=code('result_gate.source',{'fixed_owner':lambda:owner});capture=code('stream_capture.source');return types.SimpleNamespace(validate_complete=gate['validate_complete'],retain_public_streams=lambda cap,reply,p:capture['retain'](cap,reply,p))
 def boundary(self,role):
  tree=ast.parse(raw('dispatch.'+role+'.source'));reply=next(n for n in ast.walk(tree)if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='reply'for t in n.targets)and ast.unparse(n.value)=='D._json(out)');scope=next(n for n in ast.walk(tree)if isinstance(n,ast.Try)and reply in n.body);a=scope.body.index(reply);b=next(i for i,n in enumerate(scope.body[a:],a)if isinstance(n,ast.Expr)and "cap.save('qualification.json'"in ast.unparse(n));return compile(ast.fix_missing_locations(ast.Module(body=scope.body[a:b+1],type_ignores=[])),'whole-original-collect-boundary-'+role,'exec')
 def test_whole_before_loses_failed_child_raw_fixed_retains_before_same_refusal(self):
  for role in ('before','fixed'):
   packet,value,reply=self.environment();files={};cap=types.SimpleNamespace(save=lambda n,b:files.__setitem__(n,b));env={'out':json.dumps(reply).encode(),'D':types.SimpleNamespace(_json=json.loads),'p':packet,'value':value,'cap':cap,'module':self.functions()}
   with self.assertRaisesRegex(ValueError,'fixed_compiler_actual_compile_failed'):exec(self.boundary(role),env)
   if role=='before':self.assertEqual(files,{})
   else:self.assertEqual(files['original-compiler-stderr.public'],b'public-compiler-error');self.assertEqual(files['original-compiler-stdout.public'],b'');self.assertNotIn('qualification.json',files)
 def test_empty_and_overflow_remain_explicit_bounded_prefixes(self):
  for err,out in ((b'',b''),(b'e'*16385,b'o'*16386)):
   packet,_,reply=self.environment(err,out);files={};self.functions().retain_public_streams(types.SimpleNamespace(save=lambda n,b:files.__setitem__(n,b)),reply,packet)
   for role,data in [('stdout',out),('stderr',err)]:self.assertEqual(files['original-compiler-'+role+'.public'],data[:16384]);self.assertEqual(files['original-compiler-streams.json']['streams'][role]['complete'],len(data)<=16384)
 def test_foreign_operation_source_stream_or_bool_integer_refuses_without_save(self):
  for mutate in (lambda r:r.update(operationId='foreign'),lambda r:r['sessionFacts'].update(nativeSha256='f'*64),lambda r:r['sessionFacts']['publicStreams']['stderr'].update(raw='eA=='),lambda r:r['sessionFacts']['publicStreams']['stdout'].update(bytes=True)):
   packet,_,reply=self.environment();mutate(reply);files={}
   with self.assertRaises(ValueError):self.functions().retain_public_streams(types.SimpleNamespace(save=lambda n,b:files.__setitem__(n,b)),reply,packet)
   self.assertEqual(files,{})

if __name__=='__main__':unittest.main()
