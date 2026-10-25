"""Actual C#Control/SD ABI with controlled identity, ACL and launch boundaries."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import types
import unittest

from agent_tools import readiness_windows_jobs as jobs

FIXTURE = Path(__file__).parent / 'fixtures/windows_jobs_default_owner'
FILES = ('before.source', 'native-failure.json', 'native-owner-diagnostic.json')


def authenticated_before():
    provenance = json.loads((FIXTURE / 'provenance.json').read_bytes())
    if provenance['schemaVersion'] != 1 or set(provenance['sourceSha256']) != set(FILES):
        raise AssertionError('directory security fixture scope changed')
    values = {}
    for name in FILES:
        raw = (FIXTURE / name).read_bytes()
        if hashlib.sha256(raw).hexdigest() != provenance['sourceSha256'][name]:
            raise AssertionError('directory security fixture changed: ' + name)
        values[name] = raw
    return values


def replace_method(source, signature, body):
    if source.count(signature) != 1:
        raise AssertionError('controlled boundary signature changed')
    start = source.index(signature)
    opening = source.index('{', start)
    depth, cursor = 1, opening+1
    # These finite selected methods have no braces in strings/comments.
    while depth:
        depth += (source[cursor] == '{') - (source[cursor] == '}')
        cursor += 1
    return source[:opening] + '{' + body + '}' + source[cursor:]


def controlled_class(module, name):
    prefix = module._prefix()
    source = prefix[prefix.index("@'\n")+3:prefix.rindex("\n'@")]
    source = source.replace('public static class NativeJob {', 'public static class ' + name + ' {', 1)
    probe = r'''
 public static string ProbeRoot;public static int ProbeLaunches,ProbeCreations;public static bool ProbeDescriptorValid;
 static Dictionary<string,string> ProbeOwners=new Dictionary<string,string>();
 [StructLayout(LayoutKind.Sequential)]struct ProbeAttributes {public int Length;public IntPtr Descriptor;[MarshalAs(UnmanagedType.Bool)]public bool Inherit;}
 [DllImport("advapi32.dll")]static extern UInt32 GetSecurityDescriptorLength(IntPtr descriptor);
 public static void ProbeReset(string root){ProbeRoot=root;ProbeLaunches=ProbeCreations=0;ProbeDescriptorValid=false;ProbeOwners.Clear();Directory.CreateDirectory(root);Directory.CreateDirectory(Path.Combine(root,"admissions"));Directory.CreateDirectory(Path.Combine(root,"operations"));}
 static bool ProbeCreateDirectory(string path,IntPtr attributes){
  ProbeCreations++;if(Directory.Exists(path)||File.Exists(path))return false;
  string owner="S-1-5-32-544"; // Native SYSTEM fixture's positively observed default token owner.
  if(attributes!=IntPtr.Zero){
   var a=(ProbeAttributes)Marshal.PtrToStructure(attributes,typeof(ProbeAttributes));
   Need(a.Length==Marshal.SizeOf(typeof(ProbeAttributes))&&!a.Inherit&&a.Descriptor!=IntPtr.Zero,"PROBE_SECURITY_ATTRIBUTES");
   UInt32 length=GetSecurityDescriptorLength(a.Descriptor);Need(length>=20&&length<=4096,"PROBE_DESCRIPTOR_BOUND");
   byte[] raw=new byte[(int)length];Marshal.Copy(a.Descriptor,raw,0,raw.Length);
   var descriptor=new RawSecurityDescriptor(raw,0);owner=descriptor.Owner.Value;
   var allowed=new HashSet<string>();bool valid=(descriptor.ControlFlags&ControlFlags.DiscretionaryAclProtected)!=0&&descriptor.DiscretionaryAcl!=null&&descriptor.DiscretionaryAcl.Count==2;
   foreach(GenericAce row in descriptor.DiscretionaryAcl){var ace=row as CommonAce;valid=valid&&ace!=null&&ace.AceQualifier==AceQualifier.AccessAllowed&&ace.AccessMask==(int)FileSystemRights.FullControl&&ace.AceFlags==(AceFlags.ObjectInherit|AceFlags.ContainerInherit);if(ace!=null)allowed.Add(ace.SecurityIdentifier.Value);}
   ProbeDescriptorValid=valid&&owner=="S-1-5-18"&&allowed.SetEquals(new[]{"S-1-5-18","S-1-5-32-544"});
  }
  Directory.CreateDirectory(path);ProbeOwners[path]=owner;return true;
 }
'''
    source = source.replace('public static class '+name+' {', 'public static class '+name+' {'+probe, 1)
    source = replace_method(source, 'static bool Machine(', 'return true;')
    source = replace_method(source, 'static string RootGuard(', 'return ProbeRoot;')
    source = replace_method(source, 'static void Private(', 'Need(Directory.Exists(path)&&ProbeOwners.ContainsKey(path)&&ProbeOwners[path]=="S-1-5-18","ROOT_OWNER");')
    directory = '[DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern bool CreateDirectoryW(string path,IntPtr security);'
    process = '[DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern bool CreateProcessW(string app,StringBuilder command,IntPtr processSecurity,IntPtr threadSecurity,bool inherit,UInt32 flags,IntPtr environment,string directory,ref Startup startup,out ProcessInfo result);'
    if source.count(directory) != 1 or source.count(process) != 1:
        raise AssertionError('controlled process/directory boundary changed')
    source = source.replace(directory, 'static bool CreateDirectoryW(string path,IntPtr security){return ProbeCreateDirectory(path,security);}')
    source = source.replace(process, 'static bool CreateProcessW(string app,StringBuilder command,IntPtr processSecurity,IntPtr threadSecurity,bool inherit,UInt32 flags,IntPtr environment,string directory,ref Startup startup,out ProcessInfo result){ProbeLaunches++;Need(!inherit&&flags==0x08000000,"PROBE_LAUNCH_PARAMETERS");result=new ProcessInfo();return false;}')
    return source


def abi_script(before):
    script = "$ErrorActionPreference='Stop'\n[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)\n"
    for producer, name in ((before, 'BeforeJob'), (jobs, 'FixedJob')):
        script += "Add-Type -TypeDefinition @'\n" + controlled_class(producer, name) + "\n'@ -ReferencedAssemblies @('System','System.Core','System.Management','System.Web.Extensions')\n"
    owner = b'# Fixed public boundary owner; never executed.\n'
    import base64
    encoded, digest = base64.b64encode(owner).decode(), hashlib.sha256(owner).hexdigest()
    config = {'schemaVersion':1,'operationId':'abcdef78-1234-4234-9234-123456789012','machine':'abcdef78-1234-4234-9234-123456789013',
              'boot':'2026-10-20T12:51:49.5000000Z','rootGeneration':'fixture-root','admissionGeneration':'fixture-index',
              'count':3,'intervalMilliseconds':10}
    script += "$scope=Join-Path ([IO.Path]::GetTempPath()) ('vc-job-security-abi-'+[Guid]::NewGuid().ToString('N'))\ntry{\n"
    script += "$config='" + json.dumps(config,separators=(',',':')) + "'\n"
    for name in ('BeforeJob', 'FixedJob'):
        script += '['+name+"]::ProbeReset((Join-Path $scope '"+name+"'))\n"
        script += '$'+name+"=(["+name+"]::Control('start',$config,'"+encoded+"','"+digest+"')|ConvertFrom-Json)\n"
    script += r'''
 if($BeforeJob.reason -ne 'windows_job_root_owner' -or [BeforeJob]::ProbeLaunches -ne 0 -or [BeforeJob]::ProbeCreations -ne 1){throw 'actual_old_control_red_missing'}
 if($FixedJob.reason -ne 'original_evidence_unavailable' -or [FixedJob]::ProbeLaunches -ne 1 -or [FixedJob]::ProbeCreations -ne 1 -or -not [FixedJob]::ProbeDescriptorValid){throw 'actual_fixed_control_green_missing'}
 $out=@{schemaVersion=1;causalRed=$true;causalGreen=$true;oldLaunches=[BeforeJob]::ProbeLaunches;fixedLaunches=[FixedJob]::ProbeLaunches;explicitSystemDescriptor=[FixedJob]::ProbeDescriptorValid}
}finally{if([IO.Directory]::Exists($scope)){[IO.Directory]::Delete($scope,$true)}}
[Console]::WriteLine(($out|ConvertTo-Json -Compress))
'''
    return script


class WindowsDirectorySecurityTests(unittest.TestCase):
    def before(self):
        raw = authenticated_before()['before.source']
        module = types.ModuleType('agent_tools._windows_directory_before')
        module.__package__, module.__file__ = 'agent_tools', str(FIXTURE / 'before.source')
        sys.modules[module.__name__] = module
        self.addCleanup(sys.modules.pop, module.__name__, None)
        exec(compile(raw,module.__file__,'exec'),module.__dict__)
        return module

    def test_native_default_owner_failure_has_authenticated_exact_prelaunch_evidence(self):
        source = authenticated_before()
        failure = json.loads(source['native-failure.json'])
        facts = json.loads(source['native-owner-diagnostic.json'])['sessionFacts']
        self.assertEqual('windows_job_root_owner', failure['reason'])
        self.assertEqual({}, failure['identity'])
        for key in ('operationId','machine','boot','rootGeneration','admissionGeneration'):
            self.assertEqual(failure[key], facts[key])
        self.assertEqual('S-1-5-18', facts['tokenUserSid'])
        self.assertEqual('S-1-5-32-544', facts['tokenDefaultOwnerSid'])
        self.assertEqual(facts['tokenDefaultOwnerSid'], facts['jobOwnerSid'])
        self.assertEqual([], facts['entries'])
        self.assertIs(True, facts['controllerAbsent'])
        self.assertIs(True, facts['visibilityComplete'])
        self.assertEqual([], facts['matchingActors'])
        self.assertEqual(0, facts['actorCount'])
        self.assertIs(False, facts['replayAllowed'])
        self.assertIn(b'Need(CreateDirectoryW(job,IntPtr.Zero),"ADMISSION_CREATE");Private(job);', source['before.source'])

    def test_complete_control_native_projection_keeps_only_identity_acl_and_process_boundaries_controlled(self):
        before = self.before()
        script = abi_script(before)
        self.assertIn('CreateDirectoryW(path,attributes)', script)
        self.assertIn('O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)', script)
        self.assertEqual(2, script.count('public static string Control('))
        self.assertEqual(2, script.count('ProbeLaunches++;Need(!inherit&&flags==0x08000000'))
        self.assertNotIn('static extern bool CreateProcessW', script)
        self.assertNotIn('static extern bool CreateDirectoryW', script)

    @unittest.skipUnless(os.name == 'nt', 'Actual Windows PowerShell/C# security descriptor ABI required')
    def test_actual_full_csharp_control_red_green_and_security_descriptor_marshaling(self):
        script = abi_script(self.before()).encode()
        powershell = Path(os.environ['SystemRoot']) / 'System32/WindowsPowerShell/v1.0/powershell.exe'
        result = subprocess.run([str(powershell),'-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-Command',
            '$s=[Console]::In.ReadToEnd(); & ([ScriptBlock]::Create($s))'],input=script,
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=40,check=False)
        self.assertEqual(0,result.returncode,result.stderr.decode(errors='replace'))
        self.assertEqual({'schemaVersion':1,'causalRed':True,'causalGreen':True,'oldLaunches':0,
                          'fixedLaunches':1,'explicitSystemDescriptor':True},json.loads(result.stdout))


if __name__ == '__main__':
    unittest.main()
