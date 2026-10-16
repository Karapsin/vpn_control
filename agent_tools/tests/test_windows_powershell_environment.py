"""Actual inert-child controls for the PowerShell fixture environment seam.

Portable children execute this Python runtime and stop the actual retained
caller at its native boundary. A Windows-only control invokes Windows
PowerShell against owned inert files. The original failed module-path value
was not retained; controlled missing-command proof remains distinct from it.
"""
import argparse
import ast
import builtins
from collections import UserDict
from contextlib import ExitStack
import hashlib
import inspect
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import types
import unittest

from agent_tools.tests.fixtures.windows_powershell_environment import windows_powershell_environment


PUBLIC_MODULE_PATH = 'PUBLIC inherited module directory'
PUBLIC_SENTINEL = 'PUBLIC environment forwarding sentinel'
ROOT = Path(__file__).resolve().parents[2]
AUTHENTIC_FIXTURE = Path(__file__).parent / 'fixtures/windows_powershell_environment'
AUTHENTIC_BEFORE_SHA256 = '903bcbb3eba1d92e50baec2243ed0788f616942c64a02eb6284aac583a98bb38'
AUTHENTIC_STAGE_SHA256 = 'fb2dab95628f1d03e30711d5bcdd0eb2440ef75c3b2cd900ad5e3ffda09bef05'
CHILD_OBSERVER = (
    "import json,os;print(json.dumps({"
    "'modulePaths':{key.upper():value for key,value in os.environ.items() "
    "if key.upper()=='PSMODULEPATH'},"
    "'sentinel':os.environ.get('VPN_FIXTURE_ENV_SENTINEL')},sort_keys=True))"
)
NATIVE_MODULE_SCRIPT = r'''$ErrorActionPreference='Stop'
$actor=[Security.Principal.WindowsIdentity]::GetCurrent().User;if($null -eq $actor){throw 'PUBLIC_NATIVE_ACTOR_MISSING'}
$missing=@();foreach($name in @('Get-Acl','Get-FileHash')){try{$null=Get-Command -Name $name -CommandType Cmdlet -ErrorAction Stop}catch{$missing+=,$name}}
if($missing.Count){[Console]::Error.WriteLine(('PUBLIC_NATIVE_MISSING:'+($missing -join ',')));exit 11}
$path=$args[0];$expectedHash=$args[1]
$acl=Get-Acl -LiteralPath $path -ErrorAction Stop;$physical=[IO.File]::GetAccessControl($path)
$sections=[Security.AccessControl.AccessControlSections]::All;$sidType=[Security.Principal.SecurityIdentifier]
if($acl.Sddl -cne $physical.GetSecurityDescriptorSddlForm($sections) -or $acl.GetOwner($sidType).Value -cne $physical.GetOwner($sidType).Value){throw 'PUBLIC_NATIVE_ACL_MISMATCH'}
$actualHash=(Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
if($actualHash -cne $expectedHash){throw 'PUBLIC_NATIVE_HASH_MISMATCH'}
[Console]::Out.WriteLine('PUBLIC_NATIVE_MODULE_ACL_HASH_PASS')
'''


def legacy_copied_environment(executable, inherited):
    """Model of copied-environment passthrough; not a native execution model."""
    return dict(inherited)


def observed_child_environment(factory, executable, key='PsMoDuLePaTh'):
    """Observe the actual child env without changing the real parent env."""
    parent_before = dict(os.environ)
    inherited = {name: value for name, value in parent_before.items()
                 if name.casefold() != 'psmodulepath'}
    inherited[key] = PUBLIC_MODULE_PATH
    inherited['VPN_FIXTURE_ENV_SENTINEL'] = PUBLIC_SENTINEL
    supplied_before = dict(inherited)
    child_environment = factory(executable, inherited)
    if inherited != supplied_before or dict(os.environ) != parent_before:
        raise AssertionError('parent-environment-mutated')
    completed = subprocess.run([sys.executable, '-I', '-B', '-c', CHILD_OBSERVER],
                               env=child_environment, capture_output=True,
                               text=True, timeout=20, check=False)
    if completed.returncode != 0:
        raise AssertionError({'exit': completed.returncode, 'stdout': completed.stdout,
                              'stderr': completed.stderr})
    if completed.stderr or inherited != supplied_before or dict(os.environ) != parent_before:
        raise AssertionError('child-environment-observation-not-closed')
    value = json.loads(completed.stdout)
    if type(value) is not dict or set(value) != {'modulePaths', 'sentinel'}:
        raise AssertionError('child-environment-observation-schema')
    return value


def authentic_native_owner_boundary(before):
    """Run the genuine unwrapped method only up to its native-call boundary."""
    from agent_tools import source_module_loader
    before_path = (AUTHENTIC_FIXTURE / 'native_owner.before.source').resolve()
    current_path = ROOT / 'agent_tools/tests/test_windows_tertiary_guest_stage.py'
    stage_path = ROOT / 'agent_tools/windows_tertiary_guest_stage.py'
    with ExitStack() as held:
        sources = {path: held.enter_context(source_module_loader._bootstrap_source(path))
                   for path in (before_path, current_path, stage_path)}
        if (hashlib.sha256(sources[before_path][0]).hexdigest() != AUTHENTIC_BEFORE_SHA256
                or hashlib.sha256(sources[stage_path][0]).hexdigest() != AUTHENTIC_STAGE_SHA256):
            raise ValueError('authentic-environment-source-changed')
        path = before_path if before else current_path
        tree = ast.parse(sources[path][0])
        imports = []
        for node in tree.body:
            if isinstance(node, (ast.Import, ast.ImportFrom)) or (
                    not imports and isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant)
                    and isinstance(node.value.value, str)):
                imports.append(node)
            else:
                break
        classes = [node for node in tree.body if isinstance(node, ast.ClassDef)
                   and node.name == 'NativeTargetOwnerTests']
        if len(classes) != 1:
            raise ValueError('authentic-environment-method-identity')
        namespace = {'__name__': 'owned_native_owner_boundary', '__file__': str(path)}
        class BoundaryReached(BaseException):
            pass
        def boundary_run(argv, **options):
            stage = namespace['stage']
            generator = inspect.unwrap(stage.target_owner_probe_script)
            if (Path(stage.__file__).resolve() != stage_path or generator.__globals__ is not vars(stage)
                    or generator.__code__.co_filename != str(stage_path)):
                raise ValueError('authentic-stage-generator-identity')
            for unused, guard in sources.values():
                guard()
            script = generator()
            if argv != ['powershell.exe', '-NoLogo', '-NoProfile', '-NonInteractive', '-Command', script]:
                raise ValueError('authentic-native-call-changed')
            observed = subprocess.run([sys.executable, '-I', '-B', '-c', CHILD_OBSERVER],
                                      env=options.get('env'), capture_output=True,
                                      text=True, timeout=20, check=False)
            if observed.returncode or observed.stderr:
                raise AssertionError((observed.returncode, observed.stdout, observed.stderr))
            raise BoundaryReached({'environment': json.loads(observed.stdout),
                                   'scriptSha256': hashlib.sha256(script.encode()).hexdigest(),
                                   'methodFilename': str(path), 'environmentExplicit': 'env' in options,
                                   'nativePowerShellExecuted': False, 'stoppedBeforeNativeAssertions': True})
        view = types.ModuleType('subprocess')
        view.__getattr__ = lambda name: getattr(subprocess, name)
        view.run = boundary_run
        def importing(name, globals=None, locals=None, fromlist=(), level=0):
            if name == 'subprocess' and level == 0:
                return view
            return builtins.__import__(name, globals, locals, fromlist, level)
        namespace['__builtins__'] = {**vars(builtins), '__import__': importing}
        exec(compile(ast.Module(body=[*imports, classes[0]], type_ignores=[]),
                     str(path), 'exec', dont_inherit=True), namespace)
        method = inspect.unwrap(namespace['NativeTargetOwnerTests'].
                                test_actual_windows_creation_time_owner_and_inherited_custody)
        if method.__globals__ is not namespace or method.__code__.co_filename != str(path):
            raise ValueError('authentic-method-source-binding')
        try:
            method(unittest.TestCase())
        except BoundaryReached as stopped:
            answer = stopped.args[0]
        else:
            raise AssertionError('authentic-native-boundary-not-reached')
        for unused, guard in sources.values():
            guard()
        answer['sourceClosing'] = True
        return answer


class AuthenticNativeOwnerEnvironmentPositive(unittest.TestCase):
    before = False

    def test_actual_native_owner_method_forwards_its_environment(self):
        parent_before = dict(os.environ)
        environment = {key: value for key, value in parent_before.items()
                       if key.casefold() != 'psmodulepath'}
        environment.update(PsMoDuLePaTh=PUBLIC_MODULE_PATH, VPN_FIXTURE_ENV_SENTINEL=PUBLIC_SENTINEL)
        wrapper = ("import json,sys;sys.path.insert(0,sys.argv[1]);"
                   "from agent_tools.tests.test_windows_powershell_environment import authentic_native_owner_boundary;"
                   "print(json.dumps(authentic_native_owner_boundary(sys.argv[2]=='before'),sort_keys=True))")
        # Isolated mode ignores inherited PYTHONPYCACHEPREFIX; select a fresh
        # cache explicitly so another Python patch's valid-tag cache is absent.
        with tempfile.TemporaryDirectory(prefix='native-owner-boundary-cache-') as temporary:
            cache = Path(temporary) / 'pycache'
            cache.mkdir(mode=0o700)
            self.assertEqual(list(cache.iterdir()), [])
            child = subprocess.run([sys.executable, '-I', '-B', '-X',
                                    'pycache_prefix=' + str(cache), '-c', wrapper, str(ROOT),
                                    'before' if self.before else 'current'], env=environment,
                                   capture_output=True, text=True, timeout=30, check=False)
        self.assertEqual(child.returncode, 0, (child.stdout, child.stderr))
        self.assertEqual(child.stderr, '')
        self.assertEqual(dict(os.environ), parent_before)
        self.observation = json.loads(child.stdout)
        self.assertIs(self.observation['sourceClosing'], True)
        self.assertIs(self.observation['nativePowerShellExecuted'], False)
        self.assertIs(self.observation['stoppedBeforeNativeAssertions'], True)
        self.assertEqual(self.observation['environment']['sentinel'], PUBLIC_SENTINEL)
        self.assertEqual(self.observation['environment']['modulePaths'], {},
                         'AUTHENTIC_NATIVE_OWNER_MUST_REMOVE_INHERITED_MODULE_PATH')


class WindowsPowerShellEnvironmentPositive(unittest.TestCase):
    environment_factory = staticmethod(windows_powershell_environment)

    def test_windows_powershell_child_rebuilds_its_module_path(self):
        actual = observed_child_environment(self.environment_factory, 'powershell.exe')
        self.assertEqual(actual['sentinel'], PUBLIC_SENTINEL)
        self.assertEqual(actual['modulePaths'], {},
                         'PSMODULEPATH_MUST_BE_REBUILT_BY_WINDOWS_POWERSHELL')


class WindowsPowerShellEnvironmentTests(unittest.TestCase):
    def test_only_exact_windows_runtime_basenames_remove_all_key_spellings(self):
        inherited = UserDict({'PSModulePath': 'PUBLIC one', 'PsMoDuLePaTh': 'PUBLIC two',
                              'PSMODULEPATH': 'PUBLIC three', 'OTHER': 'PUBLIC unchanged',
                              'EMPTY_VALUE': ''})
        original = dict(inherited)
        for executable in ('powershell', 'powershell.exe', 'POWERSHELL.EXE',
                           'public/runtime/powershell', r'public\runtime\powershell.exe',
                           r'public\runtime with spaces\PoWeRsHeLl.ExE'):
            with self.subTest(executable=executable):
                actual = windows_powershell_environment(executable, inherited)
                self.assertIs(type(actual), dict)
                self.assertEqual(actual, {'OTHER': 'PUBLIC unchanged', 'EMPTY_VALUE': ''})
                self.assertEqual(dict(inherited), original)

    def test_actual_child_receives_alias_cleanup_and_other_runtime_passthrough(self):
        for key in ('PSModulePath', 'PsMoDuLePaTh'):
            with self.subTest(key=key):
                actual = observed_child_environment(windows_powershell_environment,
                                                    'public/runtime/powershell', key)
                self.assertEqual(actual, {'modulePaths': {}, 'sentinel': PUBLIC_SENTINEL})
        for executable in ('pwsh', r'public\runtime\pwsh.exe', 'other-public-runtime'):
            with self.subTest(executable=executable):
                actual = observed_child_environment(windows_powershell_environment, executable)
                self.assertEqual(actual, {'modulePaths': {'PSMODULEPATH': PUBLIC_MODULE_PATH},
                                          'sentinel': PUBLIC_SENTINEL})

    def test_absent_module_path_still_returns_an_independent_copy(self):
        inherited = {'OTHER': 'PUBLIC unchanged'}
        for executable in ('powershell', 'pwsh.exe'):
            with self.subTest(executable=executable):
                actual = windows_powershell_environment(executable, inherited)
                self.assertEqual(actual, inherited)
                self.assertIsNot(actual, inherited)
                actual['OTHER'] = 'PUBLIC modified copy'
                self.assertEqual(inherited, {'OTHER': 'PUBLIC unchanged'})

    def test_malformed_inputs_refuse_without_mutating_parent_or_mapping(self):
        parent_before = dict(os.environ)
        inherited = {'PSModulePath': PUBLIC_MODULE_PATH, 'OTHER': 'PUBLIC unchanged'}
        for executable in (None, True, 1, b'powershell', Path('powershell'), '', 'power\0shell'):
            with self.subTest(executable=repr(executable)):
                with self.assertRaisesRegex(ValueError, '^windows-powershell-executable$'):
                    windows_powershell_environment(executable, inherited)
        for malformed in (None, [], [('PSModulePath', PUBLIC_MODULE_PATH)],
                          {1: 'PUBLIC'}, {'PUBLIC': 1}, {'': 'PUBLIC'},
                          {'PUBLIC\0KEY': 'PUBLIC'}, {'PUBLIC': 'PUBLIC\0VALUE'}):
            with self.subTest(kind=repr(malformed)):
                with self.assertRaisesRegex(ValueError, '^windows-powershell-environment$'):
                    windows_powershell_environment('powershell.exe', malformed)
        self.assertEqual(inherited, {'PSModulePath': PUBLIC_MODULE_PATH, 'OTHER': 'PUBLIC unchanged'})
        self.assertEqual(dict(os.environ), parent_before)

    def test_same_actual_child_positive_is_passthrough_red_then_current_green(self):
        observations = []
        for factory in (legacy_copied_environment, windows_powershell_environment):
            case = WindowsPowerShellEnvironmentPositive('test_windows_powershell_child_rebuilds_its_module_path')
            case.environment_factory = factory
            result = unittest.TestResult()
            case.run(result)
            observations.append(result)
        old, current = observations
        self.assertEqual((old.testsRun, len(old.failures), len(old.errors), len(old.skipped)),
                         (1, 1, 0, 0))
        self.assertIn('PSMODULEPATH_MUST_BE_REBUILT_BY_WINDOWS_POWERSHELL', old.failures[0][1])
        self.assertEqual((current.testsRun, len(current.failures), len(current.errors), len(current.skipped)),
                         (1, 0, 0, 0))

    def test_actual_preserved_native_owner_method_red_then_current_green(self):
        cases = []
        for before in (True, False):
            case = AuthenticNativeOwnerEnvironmentPositive('test_actual_native_owner_method_forwards_its_environment')
            case.before = before
            result = unittest.TestResult()
            case.run(result)
            cases.append((case, result))
        (old_case, old), (current_case, current) = cases
        self.assertEqual((old.testsRun, len(old.failures), len(old.errors), len(old.skipped)), (1, 1, 0, 0))
        self.assertIn('AUTHENTIC_NATIVE_OWNER_MUST_REMOVE_INHERITED_MODULE_PATH', old.failures[0][1])
        self.assertEqual((current.testsRun, len(current.failures), len(current.errors), len(current.skipped)), (1, 0, 0, 0))
        self.assertEqual(old_case.observation['scriptSha256'], current_case.observation['scriptSha256'])
        self.assertIs(old_case.observation['environmentExplicit'], False)
        self.assertIs(current_case.observation['environmentExplicit'], True)


@unittest.skipUnless(os.name == 'nt', 'Actual Windows PowerShell module/ACL/hash control')
class NativeWindowsPowerShellEnvironmentTests(unittest.TestCase):
    def test_owned_missing_module_path_old_refuses_current_acl_and_hash_complete(self):
        # Controlled missing-command mechanism only. The original failed job's
        # module-path value was not retained, so this does not reconstruct it.
        executable = shutil.which('powershell.exe')
        self.assertIsNotNone(executable, 'Windows requires the real PowerShell module/ACL/hash control')
        public = b'PUBLIC native module byte oracle\r\n'
        digest = hashlib.sha256(public).hexdigest()
        script_bytes = b'\xef\xbb\xbf' + NATIVE_MODULE_SCRIPT.encode('utf-8', errors='strict')
        parent_before = dict(os.environ)
        records = []
        with tempfile.TemporaryDirectory(prefix='windows-native-module-path-') as directory:
            for index, factory in enumerate((legacy_copied_environment, windows_powershell_environment)):
                case = Path(directory) / str(index)
                case.mkdir(mode=0o700)
                empty_modules = case / 'empty-modules'
                empty_modules.mkdir(mode=0o700)
                script, data = case / 'control.ps1', case / 'PUBLIC.bytes'
                with script.open('xb') as stream:
                    stream.write(script_bytes)
                with data.open('xb') as stream:
                    stream.write(public)
                inherited = {key: value for key, value in parent_before.items()
                             if key.casefold() != 'psmodulepath'}
                inherited['PSModulePath'] = str(empty_modules)
                supplied_before = dict(inherited)
                result = subprocess.run([executable, '-NoLogo', '-NoProfile', '-NonInteractive',
                                         '-File', str(script), str(data), digest],
                                        env=factory(executable, inherited), capture_output=True,
                                        timeout=30, check=False)
                for name, raw in (('stdout.private', result.stdout), ('stderr.private', result.stderr),
                                  ('exit.private', str(result.returncode).encode('ascii'))):
                    with (case / name).open('xb') as stream:
                        stream.write(raw)
                records.append({'exit': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr})
                self.assertEqual(inherited, supplied_before)
                self.assertEqual(dict(os.environ), parent_before)
                self.assertEqual(script.read_bytes(), script_bytes)
                self.assertEqual(data.read_bytes(), public)
            old, current = records
            # Full original streams remain in the assertion if either real
            # native case fails; neither command nor ACL/hash is substituted.
            self.assertEqual(old['exit'], 11, records)
            self.assertIn(b'PUBLIC_NATIVE_MISSING:Get-Acl,Get-FileHash', old['stderr'], records)
            self.assertNotIn(b'PUBLIC_NATIVE_MODULE_ACL_HASH_PASS', old['stdout'], records)
            self.assertEqual(current['exit'], 0, records)
            self.assertEqual(current['stdout'].splitlines(), [b'PUBLIC_NATIVE_MODULE_ACL_HASH_PASS'], records)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--legacy-red', action='store_true')
    parser.add_argument('--authentic-before-red', action='store_true')
    arguments, remaining = parser.parse_known_args()
    if arguments.authentic_before_red:
        if remaining or arguments.legacy_red:
            parser.error('The authentic causal mode accepts no other selectors')
        case = AuthenticNativeOwnerEnvironmentPositive('test_actual_native_owner_method_forwards_its_environment')
        case.before = True
        result = unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite([case]))
        expected_red = ((result.testsRun, len(result.failures), len(result.errors), len(result.skipped))
                        == (1, 1, 0, 0) and
                        'AUTHENTIC_NATIVE_OWNER_MUST_REMOVE_INHERITED_MODULE_PATH' in result.failures[0][1])
        raise SystemExit(1 if expected_red else 2)
    if arguments.legacy_red:
        if remaining:
            parser.error('The causal passthrough mode accepts no unittest selectors')
        case = WindowsPowerShellEnvironmentPositive('test_windows_powershell_child_rebuilds_its_module_path')
        case.environment_factory = legacy_copied_environment
        result = unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite([case]))
        expected_red = ((result.testsRun, len(result.failures), len(result.errors), len(result.skipped))
                        == (1, 1, 0, 0) and
                        'PSMODULEPATH_MUST_BE_REBUILT_BY_WINDOWS_POWERSHELL' in result.failures[0][1])
        raise SystemExit(1 if expected_red else 2)
    unittest.main(argv=[sys.argv[0], *remaining])
