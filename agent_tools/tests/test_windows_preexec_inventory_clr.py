"""Complete CLR idle inventory with controlled machine, ACL and census boundaries."""
import json
import os
from pathlib import Path
import subprocess
import unittest

from agent_tools import readiness_windows_jobs as jobs
from agent_tools import readiness_windows_preexec as preexec


def replace_method(source, signature, body):
    if source.count(signature) != 1:
        raise AssertionError('finite inventory boundary changed')
    opening = source.index('{', source.index(signature))
    cursor, depth = opening + 1, 1
    while depth:
        depth += (source[cursor] == '{') - (source[cursor] == '}')
        cursor += 1
    return source[:opening] + '{' + body + '}' + source[cursor:]


def inventory_script():
    prefix = jobs._prefix()
    native = prefix[prefix.index("@'\n")+3:prefix.rindex("\n'@")]
    native = native.replace('public static class NativeJob {', 'public static class NativeJobProbe {', 1)
    native = native.replace('public static class NativeJobProbe {', '''public static class NativeJobProbe {
 public static string ProbeRoot,ProbeBoot;
 public static string ProbeTag(string path){return Tag(path);}
 public static string ProbeBirth(int pid){return Birth(pid);}
''', 1)
    native = replace_method(native, 'static bool Machine(', 'bool same=S(c,"boot")==ProbeBoot;Need(terminalHistory||same,"GUEST_IDENTITY_CHANGED");return same;')
    native = replace_method(native, 'static string Root(', 'return ProbeRoot;')
    native = replace_method(native, 'static string RootGuard(', 'return ProbeRoot;')
    native = replace_method(native, 'static void Private(', 'Need(Directory.Exists(path),"ROOT_GENERATION_CHANGED");if(Path.GetDirectoryName(path)==Path.Combine(ProbeRoot,"operations"))throw new Exception("ROOT_OWNER");')
    projected = preexec._INVENTORY.replace('NativePreexecInventory', 'ProjectedPreexecInventory')
    projected = projected.replace('public sealed class ProjectedPreexecInventory {', 'public sealed class ProjectedPreexecInventory {public static bool ProbeAclInvalid,ProbeCensusActive;', 1)
    projected = replace_method(projected, 'void JobAcl(', 'Need(!ProbeAclInvalid);')
    projected = replace_method(projected, 'void Census(', 'Need(!ProbeCensusActive);')
    script = "$ErrorActionPreference='Stop';[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)\n"
    for source in (native, projected):
        script += "Add-Type -TypeDefinition @'\n" + source + "\n'@ -ReferencedAssemblies @('System','System.Core','System.Management','System.Web.Extensions')\n"
    script += r'''
$scope=Join-Path ([IO.Path]::GetTempPath()) ('vc-preexec-inventory-'+[Guid]::NewGuid().ToString('N'))
try{
 [IO.Directory]::CreateDirectory($scope)|Out-Null
 foreach($name in @('admissions','operations')){[IO.Directory]::CreateDirectory((Join-Path $scope $name))|Out-Null}
 $op='12345678-1234-4234-8234-123456789012';$machine='12345678-1234-4234-8234-123456789013'
 $boot='2026-10-20T12:51:49.5000000Z';[NativeJobProbe]::ProbeRoot=$scope;[NativeJobProbe]::ProbeBoot=$boot
 $job=Join-Path (Join-Path $scope 'operations') $op;[IO.Directory]::CreateDirectory($job)|Out-Null
 $index=Join-Path $scope 'admissions';$claim=Join-Path $index ($op+'.json')
 [IO.File]::WriteAllBytes((Join-Path $scope 'admission.lock'),[byte[]]@())
 $intent=@{schemaVersion=1;machine=$machine;boot=$boot;rootGeneration=[NativeJobProbe]::ProbeTag($scope);admissionGeneration=[NativeJobProbe]::ProbeTag($index);operationId=$op;count=3;intervalMilliseconds=10;nonce='12345678-1234-4234-8234-123456789014';programSha256=('a'*64)}
 function HashBytes([byte[]]$raw){$h=[Security.Cryptography.SHA256]::Create();try{return ([BitConverter]::ToString($h.ComputeHash($raw))).Replace('-','').ToLowerInvariant()}finally{$h.Dispose()}}
 $claimBytes=[Text.Encoding]::UTF8.GetBytes(($intent|ConvertTo-Json -Compress));[IO.File]::WriteAllBytes($claim,$claimBytes)
 $proof=@{};foreach($key in $intent.Keys){$proof[$key]=$intent[$key]}
 $proof.claimGeneration=[NativeJobProbe]::ProbeTag($claim);$proof.claimSha256=HashBytes $claimBytes
 $proof.jobGeneration=[NativeJobProbe]::ProbeTag($job);$proof.controllerPid=2000000000;$proof.controllerBirth='1';$proof.proofSha256=('b'*64)
 $c=@{schemaVersion=1;machine=$machine;boot=$boot;rootGeneration=$intent.rootGeneration;admissionGeneration=$intent.admissionGeneration;rejections=@($proof)}
 function CheckBlocked($value){if($value.visibilityComplete -or $value.blockers.Count -eq 0){throw 'changed_custody_did_not_block'}}
 $old=[NativeJobProbe]::Inventory(($c|ConvertTo-Json -Depth 10 -Compress))|ConvertFrom-Json
 CheckBlocked $old
 $fixed=[ProjectedPreexecInventory]::Run([NativeJobProbe],($c|ConvertTo-Json -Depth 10 -Compress))|ConvertFrom-Json
 if(-not $fixed.visibilityComplete -or $fixed.blockers.Count -ne 0 -or $fixed.terminalCount -ne 0){throw 'fixed_inventory_incomplete'}
 $negatives=0
 foreach($key in @('claimGeneration','claimSha256','jobGeneration','programSha256','nonce')){
  $saved=$proof[$key];$proof[$key]='changed'
  CheckBlocked ([ProjectedPreexecInventory]::Run([NativeJobProbe],($c|ConvertTo-Json -Depth 10 -Compress))|ConvertFrom-Json)
  $proof[$key]=$saved;$negatives++
 }
 [ProjectedPreexecInventory]::ProbeAclInvalid=$true
 CheckBlocked ([ProjectedPreexecInventory]::Run([NativeJobProbe],($c|ConvertTo-Json -Depth 10 -Compress))|ConvertFrom-Json)
 [ProjectedPreexecInventory]::ProbeAclInvalid=$false;$negatives++
 [ProjectedPreexecInventory]::ProbeCensusActive=$true
 CheckBlocked ([ProjectedPreexecInventory]::Run([NativeJobProbe],($c|ConvertTo-Json -Depth 10 -Compress))|ConvertFrom-Json)
 [ProjectedPreexecInventory]::ProbeCensusActive=$false;$negatives++
 $proof.controllerPid=$PID;$proof.controllerBirth=[NativeJobProbe]::ProbeBirth($PID)
 CheckBlocked ([ProjectedPreexecInventory]::Run([NativeJobProbe],($c|ConvertTo-Json -Depth 10 -Compress))|ConvertFrom-Json)
 $proof.controllerPid=2000000000;$proof.controllerBirth='1';$negatives++
 $c.boot='2026-10-21T00:00:00.0000000Z';[NativeJobProbe]::ProbeBoot=$c.boot
 CheckBlocked ([ProjectedPreexecInventory]::Run([NativeJobProbe],($c|ConvertTo-Json -Depth 10 -Compress))|ConvertFrom-Json)
 $negatives++
 $out=@{schemaVersion=1;beforeBlocked=$true;fixedVisibility=$true;negativeCount=$negatives}
}finally{if([IO.Directory]::Exists($scope)){[IO.Directory]::Delete($scope,$true)}}
[Console]::WriteLine(($out|ConvertTo-Json -Compress))
'''
    return script


class PreexecInventoryClrTests(unittest.TestCase):
    def test_complete_inventory_projection_keeps_finite_external_boundaries(self):
        source = inventory_script()
        self.assertIn('Observe', source)
        self.assertIn('JobAcl(jobPath)', source)
        self.assertIn('Need(intent.Count==10', source)
        self.assertIn('new FileStream(claim,FileMode.Open,FileAccess.Read,FileShare.Read)', source)
        self.assertIn('Call("Machine",c,false)', source)
        self.assertIn('beforeBlocked=$true', source)
        self.assertIn('negativeCount=$negatives', source)

    @unittest.skipUnless(os.name == 'nt', 'actual CLR/NTFS qualification runs on Windows')
    def test_actual_clr_before_blocked_current_exactproof_and_negative_custody(self):
        import tempfile
        with tempfile.TemporaryDirectory() as scope:
            script = Path(scope) / 'inventory.ps1'
            script.write_bytes(inventory_script().encode())
            result = subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',str(script)],
                                    stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=90,check=False)
        self.assertEqual(0, result.returncode, result.stderr.decode(errors='replace'))
        output = json.loads(result.stdout.decode('utf-8-sig'))
        self.assertEqual({'schemaVersion':1,'beforeBlocked':True,'fixedVisibility':True,'negativeCount':9}, output)


if __name__ == '__main__':
    unittest.main()
