"""Causal regressions for the Windows PowerShell 5.1 native harness delivery.

CI run 40187428207 (cc2873b5) piped both programs to `powershell.exe -Command -`,
which executes redirected input like typed console input. The stream program's
first multi-line function never met a blank line, so the host discarded the rest
of the program at end of input (exit 0, no output). The compiler program ran line
by line, so Add-Type's terminating COMPILER_ERRORS escaped its own statement to
stderr while later lines still ran; as one -File script the same uncaught error
ends the script with exit 1, so the fixed program also catches and records it. On
POSIX the preserved, current and catch-less current whole Windows methods run
against a shebang stand-in for powershell.exe: a public console-host intake model,
its Add-Type error-flow model or the recorded replies. Only the Windows runner
executes the real interpreter, the .NET Framework compiler and the programs'
native results.
"""
from pathlib import Path
import ast,base64,contextlib,hashlib,json,os,re,shlex,subprocess,sys,tempfile,unittest
from unittest import mock
from agent_tools.tests import windows_powershell_script as script
TESTS=Path(__file__).resolve().parent
FIX=TESTS/'fixtures/windows_powershell_script'
HOST=FIX/'fake_console_host.py'
PROVENANCE=TESTS/'fixtures/windows_powershell_script/provenance.json'
BEFORE={'compile':FIX/'compile_followup.before.source','stream':FIX/'public_compile_causals.before.source'}
BEFORE_SHA={'compile':'d6af8dddbcc0b24d1856e7c0490623bae4c1decb2ed8295bb0adc934f105f054','stream':'c75a5750d74d99740aac19e92ba102a1d3acaa74d0c4f94c90005ff86d4e5064'}
CURRENT={'compile':TESTS/'test_windows_compile_followup.py','stream':TESTS/'test_windows_public_compile_causals.py'}
METHOD={'compile':('NativeCompiler','test_actual_complete_before_sources_RED_fixed_GREEN_without_methods_invoked'),'stream':('StreamRetention','test_actual_windows_powershell_old_RED_fixed_GREEN')}
# CI kept only the shortened stderr repr of the compile reply; the replay uses the standard ErrorRecord layout around that prefix.
ADD_TYPE_ERROR=b"\r\n".join([b'Add-Type : Cannot add type. Compilation errors occurred.',b'At line:1 char:1',b"+ Add-Type -ReferencedAssemblies @('System.dll','System.Core.dll','Syst ...",b'+ '+b'~'*73,b'    + CategoryInfo          : InvalidData: (:) [Add-Type], InvalidOperationException',b'    + FullyQualifiedErrorId : COMPILER_ERRORS,Microsoft.PowerShell.Commands.AddTypeCommand',b''])
CI_REPLY={'compile':(0,b'{"compiled":false,"errors":["representative compiler diagnostic"],"inputAuthority":false,"methodsInvoked":false}\r\n',ADD_TYPE_ERROR),'stream':(0,b'',b'')}
CI_COMPILE_FAILURE=r'^b"Add-Type : Cannot add type\. Compilation \[\d+ chars\]\\r\\n" != b\'\'$'
COMPILER_ERRORS='COMPILER_ERRORS,Microsoft.PowerShell.Commands.AddTypeCommand: Cannot add type. Compilation errors occurred.'
CATCH=('try{','}catch{$terminatingErrors=@($_)}')

def source(role,name):
 if role=='current':return CURRENT[name].read_bytes()
 data=BEFORE[name].read_bytes()
 if hashlib.sha256(data).hexdigest()!=BEFORE_SHA[name]:raise AssertionError('preserved harness changed: '+name)
 return data

def windows_method(role,name,mutate=None):
 """Whole preserved or current module; only the Windows method's skip guard is removed (a mutant also rewrites its program template)."""
 tree=ast.parse(source(role,name));cls,method=METHOD[name]
 node=next(n for c in tree.body if isinstance(c,ast.ClassDef)and c.name==cls for n in c.body if isinstance(n,ast.FunctionDef)and n.name==method)
 constant=next((n.value for n in ast.walk(node)if isinstance(n,ast.Assign)and[ast.unparse(t)for t in n.targets]==['source']),None)
 if mutate:constant.value=mutate(constant.value)
 template=constant.value if constant else None
 node.decorator_list=[];namespace={'__name__':'windows_powershell_harness_'+role,'__file__':str(CURRENT[name])}
 exec(compile(tree,str(CURRENT[name]),'exec'),namespace)
 if name=='stream':program=namespace['StreamRetention'].program()
 else:program=template.replace('__SOURCE__',base64.b64encode(namespace['raw']('native.before.source')).decode()).encode()
 return namespace,getattr(namespace[cls](method),method),program

@contextlib.contextmanager
def windows_host(**environment):
 """SystemRoot whose powershell.exe is the public console-host intake model."""
 with tempfile.TemporaryDirectory(prefix='fake-windows-root-')as directory:
  root=Path(directory);exe=root/'System32/WindowsPowerShell/v1.0/powershell.exe';exe.parent.mkdir(parents=True)
  exe.write_text('#!/bin/sh\nexec %s -I %s "$@"\n'%(shlex.quote(sys.executable),shlex.quote(str(HOST))));exe.chmod(0o700)
  transcript=root/'transcript.json'
  with mock.patch.dict(os.environ,{'SystemRoot':str(root),'VPN_CONTROL_FAKE_PS51_TRANSCRIPT':str(transcript),**environment}):
   yield transcript

class Accepted(BaseException):
 """The harness accepted one JSON reply; stop before its native-result assertions."""

class StopAtReply:
 def __getattr__(self,name):return getattr(json,name)
 @staticmethod
 def loads(data,*args,**kwargs):raise Accepted(json.loads(data,*args,**kwargs))

def deliver(role,name):
 """Run the whole Windows method until the harness accepts or rejects its first reply."""
 namespace,method,program=windows_method(role,name)
 with windows_host()as transcript:
  namespace['json']=StopAtReply()
  with mock.patch.object(script,'json',StopAtReply()):
   try:method();outcome=None
   except Accepted as accepted:outcome=accepted
   except Exception as error:outcome=error
  record=json.loads(transcript.read_bytes())
 return outcome,record,program

def replay(role,name):
 """Run the whole Windows method against the reply that CI 40187428207 recorded for it."""
 _,method,_=windows_method(role,name);code,out,err=CI_REPLY[name]
 with tempfile.TemporaryDirectory()as directory:
  reply=Path(directory)/'reply.json';reply.write_text(json.dumps({'returncode':code,'stdout':base64.b64encode(out).decode(),'stderr':base64.b64encode(err).decode()}))
  with windows_host(VPN_CONTROL_FAKE_PS51_REPLY=str(reply)):
   try:method()
   except Exception as error:return error
 raise AssertionError('recorded failing reply was accepted')

def without_catch(template):
 """The current compile program with ONLY the try/catch around its Add-Type statement removed."""
 if [template.count(text)for text in CATCH]!=[1,1]:raise AssertionError('current compile program changed')
 return template.replace(CATCH[0],'').replace(CATCH[1],'')

def execute(role,name,mutate=None):
 """Run the whole Windows method against the Add-Type error-flow model; return its outcome and every reply."""
 _,method,_=windows_method(role,name,mutate);replies=[];run=subprocess.run
 def recorded(*args,**kwargs):
  replies.append(run(*args,**kwargs));return replies[-1]
 with windows_host(VPN_CONTROL_FAKE_PS51_EXECUTE='add-type',VPN_CONTROL_FAKE_PS51_TRANSCRIPT=''),mock.patch.object(subprocess,'run',recorded):
  try:method();outcome=None
  except Exception as error:outcome=error
 return outcome,replies

def units(record):return [base64.b64decode(unit)for unit in record['units']]

class ConsoleHostModel(unittest.TestCase):
 def host(self,arguments,stdin=b'',**environment):
  with tempfile.TemporaryDirectory()as directory:
   transcript=Path(directory)/'transcript.json'
   p=subprocess.run([sys.executable,'-I',str(HOST),*arguments],input=stdin,capture_output=True,timeout=30,env={**os.environ,'VPN_CONTROL_FAKE_PS51_TRANSCRIPT':str(transcript),**environment})
   return p,(json.loads(transcript.read_bytes())if transcript.exists()else None)
 def test_documented_stdin_examples_and_complete_file_script(self):
  # about_PowerShell_exe (5.1): blank lines end the multi-line pipeline, so three statements print in / hi there / out.
  p,record=self.host(['-NoProfile','-Command','-'],b'"in"\r\n\r\n"hi" |\r\n  % { "$_ there" }\r\n\r\n"out"\r\n')
  self.assertEqual((p.returncode,p.stderr),(0,b''));self.assertEqual(units(record),[b'"in"',b'"hi" |\n  % { "$_ there" }',b'"out"']);self.assertIsNone(record['discarded'])
  # PowerShell/PowerShell#21644 lf.ps1: without a trailing blank line the pipeline never runs; exit 0 and no output.
  issue=b"Get-Process |\nWhere-Object {$_.Name -ILike '*explorer*'}\n"
  p,record=self.host(['-Command','-'],issue)
  self.assertEqual((p.returncode,p.stdout,p.stderr),(0,b'',b''));self.assertEqual(units(record),[]);self.assertEqual(base64.b64decode(record['discarded']),issue[:-1])
  p,record=self.host(['-Command','-'],issue+b'\n');self.assertEqual(units(record),[issue[:-1]]);self.assertTrue(record['finalStatementRan'])
  with tempfile.TemporaryDirectory()as directory:
   path=Path(directory)/'issue.ps1';path.write_bytes(issue)
   p,record=self.host(['-NoLogo','-File',str(path)]);self.assertEqual(p.returncode,0);self.assertEqual(units(record),[issue]);self.assertTrue(record['finalStatementRan'])
   p,record=self.host(['-File',str(path.with_suffix('.txt'))]);self.assertEqual(p.returncode,64);self.assertIn(b"does not have a '.ps1' extension",p.stderr);self.assertIsNone(record)
 def test_add_type_error_flow_last_line_status_and_closed_statement_set(self):
  namespace,_,_=windows_method('current','compile');native=base64.b64encode(namespace['raw']('native.before.source')).decode();flow={'VPN_CONTROL_FAKE_PS51_EXECUTE':'add-type'}
  head="$ErrorActionPreference='Stop'\n$native=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%s'))\n"%native
  add='Add-Type -ReferencedAssemblies @() -TypeDefinition $native -ErrorAction Continue -ErrorVariable errors 2>$null\n'
  # DoRunspaceLoop: once redirected input ends, -Command - exits with $? of the last executed line.
  p,record=self.host(['-Command','-'],(head+add).encode(),**flow);self.assertEqual((p.returncode,p.stdout),(1,b''));self.assertTrue(p.stderr.startswith(b'Add-Type : Cannot add type. Compilation errors occurred.\r\nAt line:1 char:1\r\n'))
  self.assertEqual(record['errorFlow'],{'exitCode':1,'uncaught':[[3,'COMPILER_ERRORS,Microsoft.PowerShell.Commands.AddTypeCommand']]})
  p,record=self.host(['-Command','-'],(head+add+'$errors=@()\n').encode(),**flow);self.assertEqual((p.returncode,record['errorFlow']['exitCode']),(0,0))
  # Closed model: another statement, compiler source or error preference is refused before any transcript.
  for program in (head+'Write-Output 1\n',head.replace(native,base64.b64encode(b'public class X{}').decode())+add,head.replace("'Stop'","'Continue'")+add):
   p,record=self.host(['-Command','-'],program.encode(),**flow);self.assertEqual(p.returncode,64,p.stderr);self.assertTrue(p.stderr.startswith(b'fake console host: '),p.stderr);self.assertIsNone(record)

class ProgramRunner(unittest.TestCase):
 def test_empty_non_bytes_or_non_ascii_program_is_refused_before_any_process(self):
  with mock.patch.object(script,'subprocess')as process:
   for program in (b'','Write-Output 1',b'\xef\xbb\xbfWrite-Output 1',b'Write-Output \xe9'):
    with self.assertRaisesRegex(ValueError,'windows-powershell-program-ascii'):script.run_program('powershell.exe',program,1)
  self.assertEqual(process.mock_calls,[])
 def test_timeout_failure_keeps_partial_streams(self):
  expired=subprocess.TimeoutExpired(['powershell.exe'],60,output=b'partial-public-out',stderr=b'partial-public-err')
  with mock.patch.object(script.subprocess,'run',side_effect=expired),self.assertRaises(AssertionError)as caught:script.run_program('powershell.exe',b"'public'",60)
  for text in ('timed out after 60s','returncode=None','partial-public-out','partial-public-err'):self.assertIn(text,str(caught.exception))

class PreservedEvidence(unittest.TestCase):
 def test_provenance_names_the_preserved_harnesses_and_ci_run(self):
  value=json.loads(PROVENANCE.read_bytes());self.assertIs(value['nativeFailureClaimed'],False);self.assertEqual(value['ci']['runId'],40187428207)
  for name,path in BEFORE.items():
   entry=value['inputs'][path.name];self.assertEqual(entry['sha256'],BEFORE_SHA[name]);self.assertEqual(entry['sha256'],hashlib.sha256(source('before',name)).hexdigest());self.assertEqual(entry['sourcePath'],'agent_tools/tests/'+CURRENT[name].name);self.assertEqual(entry['testId'],'agent_tools.tests.'+CURRENT[name].stem+'.'+'.'.join(METHOD[name]))

@unittest.skipUnless(os.name=='posix','a POSIX shebang stand-in replaces powershell.exe; Windows runs the real interpreter')
class HarnessDelivery(unittest.TestCase):
 def test_preserved_harnesses_reproduce_ci_stdin_console_failures(self):
  # Stream: exactly the CI symptom (exit 0, empty streams, JSONDecodeError at char 0); 36 lines were discarded at end of input.
  outcome,record,program=deliver('before','stream');lines=program.decode().split('\n')[:-1]
  self.assertIsInstance(outcome,json.JSONDecodeError);self.assertEqual(str(outcome),'Expecting value: line 1 column 1 (char 0)')
  self.assertEqual(record['intake'],'stdin');self.assertEqual(units(record),[line.encode()for line in lines[:7]]);self.assertEqual(base64.b64decode(record['discarded']),'\n'.join(lines[7:]).encode());self.assertEqual(len(lines[7:]),36)
  # Compiler: every line ran as its own interactive statement, so an uncaught terminating error could not stop the program.
  outcome,record,program=deliver('before','compile');lines=program.decode().split('\n')[:-1]
  self.assertIsInstance(outcome,Accepted);self.assertEqual(record['intake'],'stdin');self.assertEqual(units(record),[line.encode()for line in lines]);self.assertIsNone(record['discarded'])
 def test_current_harnesses_run_exact_program_once_as_complete_private_script(self):
  for name in ('stream','compile'):
   with self.subTest(name=name):
    outcome,record,program=deliver('current',name)
    self.assertIsInstance(outcome,Accepted,repr(outcome));self.assertEqual(outcome.args[0]['programSha256'],hashlib.sha256(program).hexdigest())
    self.assertEqual(record['intake'],'file');self.assertEqual(units(record),[program]);self.assertIsNone(record['discarded'])
    path=Path(record['scriptPath']);self.assertEqual(record['arguments'],[*script.ARGUMENTS,str(path)]);self.assertEqual(path.suffix,'.ps1');self.assertTrue(record['stdinIsNull']);self.assertFalse(path.parent.exists())
    self.assertTrue(program.rstrip(b'\n').rsplit(b'\n',1)[-1].startswith(b'[Console]::WriteLine('))

@unittest.skipUnless(os.name=='posix','a POSIX shebang stand-in replaces powershell.exe; Windows runs the real interpreter')
class ReplyDiagnostics(unittest.TestCase):
 def test_preserved_harnesses_hide_the_recorded_ci_replies(self):
  error=replay('before','compile');self.assertIsInstance(error,AssertionError)
  self.assertRegex(str(error),CI_COMPILE_FAILURE);self.assertNotIn(ADD_TYPE_ERROR.decode(),str(error))
  error=replay('before','stream');self.assertIsInstance(error,json.JSONDecodeError);self.assertEqual(str(error),'Expecting value: line 1 column 1 (char 0)')
 def test_current_harnesses_report_complete_recorded_ci_replies(self):
  for name in ('compile','stream'):
   with self.subTest(name=name):
    error=replay('current',name);code,out,err=CI_REPLY[name];message=str(error)
    self.assertIsInstance(error,AssertionError,repr(error));self.assertIn(script.reply_detail(subprocess.CompletedProcess([],code,out,err)),message)
    for text in ('returncode=%d'%code,out.decode(),err.decode()):self.assertIn(text,message)

@unittest.skipUnless(os.name=='posix','a POSIX shebang stand-in replaces powershell.exe; Windows runs the real interpreter')
class CompilerErrorFlow(unittest.TestCase):
 def test_preserved_stdin_harness_reports_uncaught_compiler_errors_and_reads_on_RED(self):
  # The CI symptom: the Add-Type line's uncaught COMPILER_ERRORS goes to stderr, the later lines still print the JSON, exit 0.
  outcome,replies=execute('before','compile');self.assertEqual(len(replies),1);reply=replies[0]
  self.assertIsInstance(outcome,AssertionError);self.assertRegex(str(outcome),CI_COMPILE_FAILURE);self.assertEqual(reply.args[-2:],['-Command','-'])
  self.assertEqual(reply.returncode,0);self.assertTrue(reply.stderr.startswith(b'Add-Type : Cannot add type. Compilation errors occurred.\r\nAt line:1 char:1\r\n+ Add-Type '));self.assertEqual(reply.stderr.count(b'FullyQualifiedErrorId : COMPILER_ERRORS,'),1)
  row=json.loads(reply.stdout);self.assertFalse(row['compiled']);self.assertIn('uint exit;Need',json.dumps(row['errors']));self.assertTrue(row['errors'][-1].startswith('System.Management.Automation.CmdletInvocationException: '));self.assertNotIn('terminatingErrors',row)
 def test_current_program_without_its_catch_ends_the_file_script_with_exit_1_RED(self):
  outcome,replies=execute('current','compile',without_catch);self.assertEqual(len(replies),1);reply=replies[0]
  self.assertIn('-File',reply.args);self.assertEqual((reply.returncode,reply.stdout),(1,b''));self.assertRegex(reply.stderr,rb'\AAdd-Type : Cannot add type\. Compilation errors occurred\.\r\nAt .+program\.ps1:6 char:1\r\n')
  self.assertIsInstance(outcome,AssertionError);self.assertIn(script.reply_detail(reply),str(outcome))
 def test_current_harness_catches_and_records_compiler_errors_GREEN(self):
  outcome,replies=execute('current','compile');self.assertIsNone(outcome,str(outcome))
  self.assertEqual([(r.returncode,r.stderr,'-File'in r.args)for r in replies],[(0,b'',True)]*3);rows=[json.loads(r.stdout)for r in replies]
  self.assertEqual([r['compiled']for r in rows],[False,False,True]);self.assertEqual([r['terminatingErrors']for r in rows],[[COMPILER_ERRORS]]*2+[[]])
  # The modelled diagnostics sit exactly on the lines where each authenticated source differs from the compiling native.fixed.
  namespace,_,_=windows_method('current','compile');sources=[namespace['raw'](n).decode().split('\n')for n in ('native.before.source','native.exit-fixed.source','native.fixed.source')]
  self.assertEqual([[int(n)for e in r['errors']for n in re.findall(r'^\((\d+)\) : >>> ',e,re.M)]for r in rows],[[i for i,(a,b)in enumerate(zip(s,sources[2]),1)if a!=b]for s in sources])

if __name__=='__main__':unittest.main()
