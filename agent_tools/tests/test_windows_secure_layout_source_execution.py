"""Execute the actual diagnostic C# owner with inert native calls on Windows.

This module deliberately does not import POSIX repository helpers. Native calls
are replaced by managed fixtures; it never creates, terminates, or adopts a
real process. macOS/Linux skip the executable cases honestly.
"""
import ast,base64,json,os,re,shutil,subprocess,unittest
from pathlib import Path

SOURCE=Path(__file__).resolve().parents[1]/'windows_cp117_secure_layout_observe.py'

def native_source():
    tree=ast.parse(SOURCE.read_text())
    return next(ast.literal_eval(n.value)for n in tree.body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='_NATIVE'for t in n.targets))

def inert_native(legacy=False):
    source=native_source()
    mocks={
      'GetCurrentProcess':'return new IntPtr(100);',
      'OpenProcessToken':'token=new IntPtr(200);return true;',
      'LookupPrivilegeValue':'id=new LUID();return true;',
      'AdjustTokenPrivileges':'return true;',
      'DuplicateTokenEx':'result=new IntPtr(300);return true;',
      'SetTokenInformation':'return true;',
      'CreateProcessAsUser':'Entered.Set();Release.WaitOne(3000);process=new PI();process.process=new IntPtr(4567);process.thread=new IntPtr(4568);process.pid=999;process.tid=1000;Alive=true;return true;',
      'WaitForSingleObject':'if(process!=new IntPtr(4567))throw new Exception("foreign-wait");return Alive?258u:0u;',
      'TerminateProcess':'if(process!=new IntPtr(4567))throw new Exception("foreign-terminate");Terminations++;if(Refuse)return false;Alive=false;return true;',
      'CloseHandle':'if(h==new IntPtr(4567)||h==new IntPtr(4568))OwnedCloses++;return true;',
    }
    for name,body in mocks.items():
        pattern=r' \[DllImport\([^\n]+\)\] (public )?static extern ([^\n]+\b'+name+r'\([^\n]*\));'
        source,count=re.subn(pattern,lambda m:' '+(m[1]or'')+'static '+m[2]+' {'+body+'}',source)
        if count!=1:raise AssertionError('mock-count:'+name)
    # Last-error is an OS observation too; retain the actual branch with
    # deterministic success from the inert privilege calls.
    source=source.replace('int e=Marshal.GetLastWin32Error();','int e=0;')
    pattern=r'new System.Threading.Timer\(delegate \{ (.*?) \},null,40000,System.Threading.Timeout.Infinite\)'
    match=re.search(pattern,source)
    if not match:raise AssertionError('deadline-shape')
    body='Environment.Exit(124);'if legacy else match[1]
    body=body.replace('Environment.Exit(124)','RecordedExit=124')
    extra='''
 public static bool Alive,Refuse;public static int Terminations,OwnedCloses,RecordedExit;
 public static System.Threading.ManualResetEvent Entered=new System.Threading.ManualResetEvent(false),Release=new System.Threading.ManualResetEvent(true);
 public static void FireDeadline(){__BODY__}
'''.replace('__BODY__',body)
    return source[:source.rfind('}')]+extra+source[source.rfind('}'):]

class CompositionTests(unittest.TestCase):
    def test_mock_composition_retains_actual_owner_and_deadline(self):
        fixed=inert_native();old=inert_native(legacy=True)
        self.assertIn('owned=result;created=true;',fixed)
        self.assertIn('if(Cleanup())RecordedExit=124',fixed)
        self.assertIn('expired=true',fixed)
        self.assertIn('if(expired)throw',fixed)
        self.assertIn('public static void FireDeadline(){RecordedExit=124;}',old)
        self.assertNotIn('CreateProcessAsUser(',fixed.split('public static void FireDeadline(){')[1])

@unittest.skipUnless(os.name=='nt'and shutil.which('powershell'),'Windows PowerShell Add-Type required')
class ExecutableOwnershipTests(unittest.TestCase):
    def run_case(self,case,legacy=False):
        source=base64.b64encode(inert_native(legacy).encode()).decode()
        script="$ErrorActionPreference='Stop';Add-Type -TypeDefinition ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('"+source+"')))\n"+case
        process=subprocess.run([shutil.which('powershell'),'-NoProfile','-NonInteractive','-Command','-'],input=script,text=True,capture_output=True,timeout=20)
        self.assertEqual(process.returncode,0,process.stderr[:2000]);return json.loads(process.stdout.strip().splitlines()[-1])
    def test_measured_legacy_deadline_orphans_and_fixed_deadline_cleans(self):
        case="""$p=[CP117SessionRead]::Suspended('fixed','fixed','fixed');[CP117SessionRead]::FireDeadline();@{alive=[CP117SessionRead]::Alive;closed=[CP117SessionRead]::OwnedCloses;terminated=[CP117SessionRead]::Terminations;exit=[CP117SessionRead]::RecordedExit}|ConvertTo-Json -Compress"""
        old=self.run_case(case,legacy=True);self.assertTrue(old['alive']);self.assertEqual(old['exit'],124);self.assertEqual(old['closed'],0)
        fixed=self.run_case(case);self.assertFalse(fixed['alive']);self.assertEqual(fixed['closed'],2);self.assertEqual(fixed['terminated'],1);self.assertEqual(fixed['exit'],124)
    def test_deadline_before_birth_prohibits_late_child(self):
        case="""[CP117SessionRead]::FireDeadline();$rejected=$false;try{[CP117SessionRead]::Suspended('fixed','fixed','fixed')|Out-Null}catch{$rejected=$true};@{alive=[CP117SessionRead]::Alive;rejected=$rejected;exit=[CP117SessionRead]::RecordedExit}|ConvertTo-Json -Compress"""
        old=self.run_case(case,legacy=True);self.assertEqual(old,{'alive':True,'rejected':False,'exit':124})
        self.assertEqual(self.run_case(case),{'alive':False,'rejected':True,'exit':124})
    def test_cleanup_idempotence_and_closed_handle_authority(self):
        case="""$p=[CP117SessionRead]::Suspended('fixed','fixed','fixed');$first=[CP117SessionRead]::Cleanup();$second=[CP117SessionRead]::Cleanup();$rejected=$false;try{[CP117SessionRead]::Birth($p)|Out-Null}catch{$rejected=$true};[CP117SessionRead]::FireDeadline();@{first=$first;second=$second;rejected=$rejected;closed=[CP117SessionRead]::OwnedCloses;terminated=[CP117SessionRead]::Terminations}|ConvertTo-Json -Compress"""
        self.assertEqual(self.run_case(case),{'first':True,'second':True,'rejected':True,'closed':2,'terminated':1})
    def test_failed_cleanup_does_not_exit_or_close_live_handle(self):
        case="""$p=[CP117SessionRead]::Suspended('fixed','fixed','fixed');[CP117SessionRead]::Refuse=$true;[CP117SessionRead]::FireDeadline();@{alive=[CP117SessionRead]::Alive;closed=[CP117SessionRead]::OwnedCloses;exit=[CP117SessionRead]::RecordedExit}|ConvertTo-Json -Compress"""
        self.assertEqual(self.run_case(case),{'alive':True,'closed':0,'exit':0})
    def test_timeout_during_birth_waits_for_original_handle_registration(self):
        # Execute concurrent C# threads, avoiding PowerShell delegates without a runspace.
        source=inert_native();last=source.rfind('}');source=source[:last]+'''public static bool BirthRace(){Release.Reset();System.Threading.Thread a=new System.Threading.Thread(delegate(){Suspended("fixed","fixed","fixed");});a.Start();if(!Entered.WaitOne(3000))throw new Exception("birth-not-entered");System.Threading.Thread b=new System.Threading.Thread(delegate(){FireDeadline();});b.Start();System.Threading.Thread.Sleep(20);if(RecordedExit!=0)throw new Exception("exit-before-registration");Release.Set();if(!a.Join(3000)||!b.Join(3000))throw new Exception("race-timeout");return !Alive&&OwnedCloses==2&&Terminations==1&&RecordedExit==124;}'''+source[last:]
        encoded=base64.b64encode(source.encode()).decode();script="$ErrorActionPreference='Stop';Add-Type -TypeDefinition ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('"+encoded+"')));[CP117SessionRead]::BirthRace()|ConvertTo-Json -Compress"
        p=subprocess.run([shutil.which('powershell'),'-NoProfile','-NonInteractive','-Command','-'],input=script,text=True,capture_output=True,timeout=20)
        self.assertEqual(p.returncode,0,p.stderr[:2000]);self.assertTrue(json.loads(p.stdout.strip().splitlines()[-1]))
