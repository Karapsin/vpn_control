"""Exact compile-ACL failure and fix on owned files, without VM/admin/input.

Native e4ca proved the original SYSTEM/session0 scenario. The Windows routine
projection replaces only the constant SYSTEM ACL subject with the actual current
token SID: file operations, requested handle rights and held-ACL checks stay exact.
This does not qualify the compile owner, secure desktop or protected input.
"""
from pathlib import Path
import hashlib
import json
import os
import subprocess
import tempfile
import unittest

FIXTURE = Path(__file__).parent / 'fixtures/windows_compile_acl_creation'
PARENT_SHA = '665b3d850627c5c01c669a5c9245f1df2a81d838ba7b28a940bdccdce483dd81'
CREATE_SHA = 'c9dad79f0f3abbeebb3cf7e02b36cf93ed2a5aed78b60aedad5c7a862cf1c026'
SDDL = 'O:SYG:SYD:P(A;;FA;;;SY)'


def sources():
    parent = (FIXTURE / 'parent-665b.before.ps1').read_bytes()
    fixed = (FIXTURE / 'create-c9dad.fixed.ps1').read_bytes()
    if hashlib.sha256(parent).hexdigest() != PARENT_SHA or hashlib.sha256(fixed).hexdigest() != CREATE_SHA:
        raise ValueError('compile_acl_fixture_changed')
    parent = parent.decode('utf-8')
    begin = parent.index('function Save(')
    end = parent.index('function Hash(', begin)
    return parent[begin:end], fixed.decode('utf-8')


def program():
    old, fixed = sources()
    # SID is runtime configuration DATA. No operation/right/order is changed.
    old = old.replace("'" + SDDL + "'", '$SubjectSddl')
    fixed = fixed.replace("'" + SDDL + "'", '$SubjectSddl').replace("'S-1-5-18'", '$SubjectSid')
    return """$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$SubjectSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$SubjectSddl='O:'+$SubjectSid+'G:'+$SubjectSid+'D:P(A;;FA;;;'+$SubjectSid+')'
$root=Join-Path $env:VC_ACL_TEST_ROOT 'owned'
$dirAcl=[Security.AccessControl.DirectorySecurity]::new()
$dirAcl.SetSecurityDescriptorSddlForm('O:'+$SubjectSid+'G:'+$SubjectSid+'D:P(A;OICI;FA;;;'+$SubjectSid+')')
[void][IO.Directory]::CreateDirectory($root,$dirAcl)
""" + old + fixed + """
$value=[ordered]@{publicSentinel='compile-acl-causal';inputAuthority=$false}
$oldFailure=$null
try{Save (Join-Path $root 'old.json') $value}catch{$oldFailure=$_.Exception.GetBaseException()}
if($null -eq $oldFailure -or $oldFailure.GetType().FullName -cne 'System.UnauthorizedAccessException' -or $oldFailure.HResult -ne -2147024891){throw 'OLD_ACL_CAUSAL_NOT_REPRODUCED'}
if([IO.File]::Exists((Join-Path $root 'old.json'))){throw 'OLD_UNEXPECTED_PUBLISH'}
$path=Join-Path $root 'new.json';$bytes=[Text.Encoding]::UTF8.GetBytes(($value|ConvertTo-Json -Depth 16 -Compress))
$f=NewPrivateCompileFile $path ([IO.FileShare]::None)
try{$f.Write($bytes,0,$bytes.Length);$f.Flush($true)}finally{$f.Dispose()}
$actual=[IO.File]::ReadAllBytes($path)
if([Convert]::ToBase64String($actual) -cne [Convert]::ToBase64String($bytes)){throw 'NEW_ACL_DATA_CHANGED'}
$duplicate=$false
try{$f=NewPrivateCompileFile $path ([IO.FileShare]::None);$f.Dispose()}catch{if($_.Exception.GetBaseException() -is [IO.IOException]){$duplicate=$true}else{throw}}
if(-not $duplicate -or [Convert]::ToBase64String([IO.File]::ReadAllBytes($path)) -cne [Convert]::ToBase64String($bytes)){throw 'NEW_ACL_DUPLICATE_CHANGED'}
[Console]::WriteLine(([ordered]@{oldDenied=$true;oldHresult=$oldFailure.HResult;newHeldAclChecked=$true;readbackMatched=$true;duplicateRefused=$true;systemProjection=$false;inputAuthority=$false}|ConvertTo-Json -Compress))
"""


class CompileAclCreation(unittest.TestCase):
    def test_exact_before_and_fixed_fixture_sha(self):
        old, fixed = sources()
        self.assertIn('[IO.FileAccess]::Write,[IO.FileShare]::None)', old)
        self.assertLess(old.index('$f.SetAccessControl($a)'), old.index('$f.Write('))
        self.assertIn('[IO.FileStream]::new($path,[IO.FileMode]::CreateNew,$rights,$share,4096,[IO.FileOptions]::None,$acl)', fixed)
        self.assertLess(fixed.index('$file.GetAccessControl()'), fixed.index('return $file'))

    def test_finite_actual_system_projection_retains_causal_failure(self):
        provenance = json.loads((FIXTURE / 'provenance.json').read_bytes())
        native = json.loads((FIXTURE / 'native-public-projection.json').read_bytes())
        self.assertEqual(provenance['sources']['parent-665b.before.ps1']['sha256'], PARENT_SHA)
        self.assertEqual(provenance['sources']['create-c9dad.fixed.ps1']['sha256'], CREATE_SHA)
        self.assertEqual((native['actualToken'], native['actualSession']), ('SYSTEM', 0))
        self.assertEqual(native['old'], {'completed': False, 'errorClass': 'System.UnauthorizedAccessException',
            'failed': True, 'hresult': -2147024891})
        self.assertTrue(native['new']['completed'] and native['new']['duplicateRefused'] and native['causalQualified'])
        self.assertFalse(native['inputAuthority'] or native['nativeCompilerQualified'] or native['wholeCompileAllowed'])

    def test_projection_changes_only_constant_sid_data(self):
        old, fixed = sources()
        generated = program()
        self.assertIn(old.replace("'" + SDDL + "'", '$SubjectSddl'), generated)
        self.assertIn(fixed.replace("'" + SDDL + "'", '$SubjectSddl').replace("'S-1-5-18'", '$SubjectSid'), generated)
        self.assertEqual(old.count(SDDL), 1)
        self.assertEqual(fixed.count(SDDL), 1)
        self.assertEqual(fixed.count("'S-1-5-18'"), 3)
        for right in ('Write', 'ReadPermissions', 'ChangePermissions', 'Synchronize'):
            self.assertIn('[Security.AccessControl.FileSystemRights]::' + right, generated)
        for forbidden in ('Add-Type', 'Start-Process', 'Invoke-Command', 'Set-Acl', 'schtasks', 'VMROOT', 'guest-exec'):
            self.assertNotIn(forbidden, generated)

    @unittest.skipUnless(os.name == 'nt', 'requires actual Windows .NET Framework FileStream ACL handle rights')
    def test_actual_windows_old_handle_denied_new_atomic_acl_and_duplicate_refusal(self):
        powershell = Path(os.environ['SystemRoot']) / 'System32/WindowsPowerShell/v1.0/powershell.exe'
        self.assertTrue(powershell.is_file(), 'Windows PowerShell .NET Framework required')
        with tempfile.TemporaryDirectory(prefix='compile-acl-causal-') as directory:
            env = dict(os.environ, VC_ACL_TEST_ROOT=directory)
            result = subprocess.run([str(powershell), '-NoLogo', '-NoProfile', '-NonInteractive', '-Command',
                "$s=[Console]::In.ReadToEnd(); & ([ScriptBlock]::Create($s))"],
                input=program().encode('utf-8'), stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, timeout=45)
            self.assertLessEqual(len(result.stdout), 65536)
            self.assertLessEqual(len(result.stderr), 65536)
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
            self.assertEqual(result.stderr, b'')
            self.assertEqual(json.loads(result.stdout), {'oldDenied': True, 'oldHresult': -2147024891,
                'newHeldAclChecked': True, 'readbackMatched': True, 'duplicateRefused': True,
                'systemProjection': False, 'inputAuthority': False})


if __name__ == '__main__':
    unittest.main()
