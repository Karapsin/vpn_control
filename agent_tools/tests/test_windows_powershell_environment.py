"""Actual inert-child controls for the PowerShell fixture environment seam.

Portable children execute this Python runtime and stop the actual retained
caller at its native boundary. A Windows-only control invokes Windows
PowerShell against owned inert files. The original failed module-path value
was not retained; controlled missing-command proof remains distinct from it.
"""
import argparse
import ast
import base64
import builtins
from collections import UserDict
from contextlib import ExitStack, redirect_stdout
import hashlib
import inspect
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import textwrap
import types
import unittest
import uuid

from agent_tools.tests.fixtures.windows_powershell_environment import windows_powershell_environment


PUBLIC_MODULE_PATH = 'PUBLIC inherited module directory'
PUBLIC_SENTINEL = 'PUBLIC environment forwarding sentinel'
ROOT = Path(__file__).resolve().parents[2]
AUTHENTIC_FIXTURE = Path(__file__).parent / 'fixtures/windows_powershell_environment'
AUTHENTIC_BEFORE_SHA256 = '903bcbb3eba1d92e50baec2243ed0788f616942c64a02eb6284aac583a98bb38'
AUTHENTIC_STAGE_SHA256 = 'fb2dab95628f1d03e30711d5bcdd0eb2440ef75c3b2cd900ad5e3ffda09bef05'
NATIVE_C_SCRIPT_SHA256 = '4fc533a02a779ae4c00691837ba95d3077486c53c474e1ba3576deaa978ffe39'
NATIVE_DOCUMENT_CA1_SHA256 = 'e10c6535655a51c3244f93dfb29c819789bb69247a14e021d850703422080924'
CHILD_OBSERVER = (
    "import json,os;print(json.dumps({"
    "'modulePaths':{key.upper():value for key,value in os.environ.items() "
    "if key.upper()=='PSMODULEPATH'},"
    "'sentinel':os.environ.get('VPN_FIXTURE_ENV_SENTINEL')},sort_keys=True))"
)
NATIVE_MODULE_SCRIPT = r'''$ErrorActionPreference='Stop'
$actor=[Security.Principal.WindowsIdentity]::GetCurrent().User;if($null -eq $actor){throw 'PUBLIC_NATIVE_ACTOR_MISSING'}
# A fresh -NoProfile child can begin with Utility loaded. Remove only the
# authentic module from this runtime so both cases actually exercise autoload.
$runtimeRoot=[IO.Path]::GetFullPath([string]$PSHOME).TrimEnd('\')+'\'
$utilityRoot=[IO.Path]::GetFullPath([IO.Path]::Combine([string]$PSHOME,'Modules\Microsoft.PowerShell.Utility')).TrimEnd('\')
if(-not [IO.Directory]::Exists($utilityRoot)){throw 'PUBLIC_NATIVE_UTILITY_ROOT_MISSING'}
$utility=@(Get-Module -Name Microsoft.PowerShell.Utility -All -ErrorAction Stop)
if($utility.Count -gt 8){throw 'PUBLIC_NATIVE_UTILITY_MODULE_COUNT'}
foreach($module in $utility){if($module.Name -cne 'Microsoft.PowerShell.Utility' -or [IO.Path]::GetFullPath($module.ModuleBase).TrimEnd('\') -ine $utilityRoot){throw 'PUBLIC_NATIVE_UTILITY_MODULE_IDENTITY'};Remove-Module -ModuleInfo $module -Force -ErrorAction Stop}
if(@(Get-Module -Name Microsoft.PowerShell.Utility -All -ErrorAction Stop).Count -or @(Get-Command -Name Get-FileHash -ListImported -ErrorAction SilentlyContinue).Count){throw 'PUBLIC_NATIVE_UTILITY_NOT_COLD'}
[Console]::Out.WriteLine(('PUBLIC_NATIVE_UTILITY_COLD:'+([string]$utility.Count)))
$missing=@();foreach($name in @('Get-Acl','Get-FileHash')){
    try{$commands=@(Get-Command -Name $name -CommandType Cmdlet,Function -ErrorAction Stop)}catch{$missing+=,$name;continue}
    if($commands.Count -ne 1){throw 'PUBLIC_NATIVE_COMMAND_COUNT'}
    $command=$commands[0];$kind=[string]$command.CommandType;$moduleName=[string]$command.ModuleName;$runtimeType=$command.GetType().FullName
    $expectedModule=if($name -ceq 'Get-Acl'){'Microsoft.PowerShell.Security'}else{'Microsoft.PowerShell.Utility'}
    if($moduleName -cne $expectedModule -or $null -eq $command.Module){throw 'PUBLIC_NATIVE_COMMAND_MODULE'}
    if(($kind -ceq 'Cmdlet' -and $runtimeType -ceq 'System.Management.Automation.CmdletInfo' -and $command -is [Management.Automation.CmdletInfo]) -or ($kind -ceq 'Function' -and $runtimeType -ceq 'System.Management.Automation.FunctionInfo' -and $command -is [Management.Automation.FunctionInfo])){}else{throw 'PUBLIC_NATIVE_COMMAND_TYPE'}
    $modulePath=[IO.Path]::GetFullPath($command.Module.Path)
    if(-not $modulePath.StartsWith($runtimeRoot,[StringComparison]::OrdinalIgnoreCase) -or -not [IO.File]::Exists($modulePath)){throw 'PUBLIC_NATIVE_COMMAND_RUNTIME'}
    if($name -ceq 'Get-FileHash' -and [IO.Path]::GetFullPath($command.Module.ModuleBase).TrimEnd('\') -ine $utilityRoot){throw 'PUBLIC_NATIVE_HASH_MODULE_RUNTIME'}
    [Console]::Out.WriteLine(('PUBLIC_NATIVE_COMMAND:'+$name+':'+$moduleName+':'+$kind+':'+$runtimeType))
}
if($missing.Count){[Console]::Error.WriteLine(('PUBLIC_NATIVE_MISSING:'+($missing -join ',')));exit 11}
$path=$args[0];$expectedHash=$args[1]
$acl=Get-Acl -LiteralPath $path -ErrorAction Stop;$physical=[IO.File]::GetAccessControl($path)
$sections=[Security.AccessControl.AccessControlSections]::All;$sidType=[Security.Principal.SecurityIdentifier]
if($acl.Sddl -cne $physical.GetSecurityDescriptorSddlForm($sections) -or $acl.GetOwner($sidType).Value -cne $physical.GetOwner($sidType).Value){throw 'PUBLIC_NATIVE_ACL_MISMATCH'}
$actualHash=(Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
if($actualHash -cne $expectedHash){throw 'PUBLIC_NATIVE_HASH_MISMATCH'}
[Console]::Out.WriteLine('PUBLIC_NATIVE_MODULE_ACL_HASH_PASS')
'''


def _emit_native_public_json(value):
    """One bounded public diagnostic line; never an execution receipt."""
    line = 'PUBLIC_NATIVE_ENV_DIAGNOSTIC_JSON:' + json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(',', ':'))
    if len(line.encode('utf-8', errors='strict')) + 1 > 16384:
        raise ValueError('native-public-line-bound')
    print(line, flush=True)


def emit_native_capture_marker(case, stdout, stderr, returncode, *, stdout_eof,
                               stderr_eof, completed_process_returned, source_closing):
    """Retain exact existing controlled streams in ordered bounded chunks."""
    if type(case) is not str or case not in ('bad_module_path', 'sanitized', 'exact_c'):
        raise ValueError('native-public-case')
    if type(stdout) is not bytes or type(stderr) is not bytes:
        raise ValueError('native-public-stream-type')
    flags = (stdout_eof, stderr_eof, completed_process_returned, source_closing)
    if any(type(value) is not bool for value in flags):
        raise ValueError('native-public-terminal-type')
    if completed_process_returned:
        if (type(returncode) is not int or not -(2 ** 31) <= returncode < 2 ** 32
                or not stdout_eof or not stderr_eof or not source_closing):
            raise ValueError('native-public-terminal-closure')
    elif returncode is not None or stdout_eof or stderr_eof or source_closing:
        raise ValueError('native-public-terminal-closure')
    capture_id = uuid.uuid4().hex
    streams = {'stdout': stdout, 'stderr': stderr}
    summaries = {name: {'bytes': len(value), 'sha256': hashlib.sha256(value).hexdigest(),
                        'chunks': (len(value) + 8191) // 8192}
                 for name, value in streams.items()}
    _emit_native_public_json(
        {'schemaVersion': 1, 'kind': 'capture', 'captureId': capture_id, 'case': case,
         'returncode': returncode, 'stdoutEof': stdout_eof, 'stderrEof': stderr_eof,
         'completedProcessReturned': completed_process_returned, 'sourceClosing': source_closing,
         'stdout': summaries['stdout'], 'stderr': summaries['stderr']})
    for name, value in streams.items():
        summary = summaries[name]
        for index in range(summary['chunks']):
            offset = index * 8192
            chunk = value[offset:offset + 8192]
            _emit_native_public_json(
                {'schemaVersion': 1, 'kind': 'streamChunk', 'captureId': capture_id,
                 'case': case, 'stream': name, 'chunkIndex': index,
                 'chunkCount': summary['chunks'], 'rawOffset': offset,
                 'bytes': len(chunk), 'chunkSha256': hashlib.sha256(chunk).hexdigest(),
                 'streamBytes': summary['bytes'], 'streamSha256': summary['sha256'],
                 'base64': base64.b64encode(chunk).decode('ascii')})
    return capture_id


def emit_native_causal_marker(proof):
    """Emit the existing persisted proof unchanged inside a fixed envelope."""
    flags = ('sourceClosing', 'allThreeCompletedProcessReturned', 'allThreeStdoutEof',
             'allThreeStderrEof', 'historicalCActualCommandTypeStillUnknown',
             'sameSanitizedEnvironment', 'sameOwnedDataBytesAndHash',
             'sameOwnedDataFileArgument', 'physicalAclAndHashOracleCompleted')
    keys = {'schemaVersion', 'state', 'cExit', 'correctedExit', 'observedHashCommand', 'cMissing', *flags}
    if (type(proof) is not dict or set(proof) != keys
            or type(proof['schemaVersion']) is not int or proof['schemaVersion'] != 1
            or proof['state'] != 'EXACT_C_PRECHECK_RED_CORRECTED_PHYSICAL_ORACLE_GREEN'
            or type(proof['cExit']) is not int or proof['cExit'] != 11
            or type(proof['correctedExit']) is not int or proof['correctedExit'] != 0
            or any(type(proof[key]) is not bool or proof[key] is not True for key in flags)):
        raise ValueError('native-public-proof-schema')
    expected_command = {'name': 'Get-FileHash', 'moduleName': 'Microsoft.PowerShell.Utility',
                        'commandType': 'Function', 'runtimeType': 'System.Management.Automation.FunctionInfo'}
    if (type(proof['observedHashCommand']) is not dict
            or proof['observedHashCommand'] != expected_command
            or any(type(value) is not str for value in proof['observedHashCommand'].values())
            or type(proof['cMissing']) is not tuple
            or proof['cMissing'] not in (('Get-FileHash',), ('Get-Acl', 'Get-FileHash'))):
        raise ValueError('native-public-proof-observation')
    _emit_native_public_json({'schemaVersion': 1, 'kind': 'causalProof', 'proof': proof})


def native_c_before_script():
    """Read the exact retained C script; it is evidence, not executable Python."""
    from agent_tools import source_module_loader
    path = (AUTHENTIC_FIXTURE / 'native_module_script_c.before.ps1').resolve()
    with source_module_loader._bootstrap_source(path) as (raw, closing):
        if hashlib.sha256(raw).hexdigest() != NATIVE_C_SCRIPT_SHA256:
            raise ValueError('native-command-c-before-source')
        script = raw.decode('utf-8', errors='strict')
        closing()
        return script


def modeled_native_precheck_missing(script, observations):
    """Execute the exact source-selected CommandType filter on typed facts.

    This portable model neither runs PowerShell nor predicts autoload, native
    command availability, module provenance, ACLs, or file hashing. Native
    observations and the physical oracle remain required on Windows.
    """
    marker = 'Get-Command -Name $name -CommandType '
    if type(script) is not str or script.count(marker) != 1:
        raise ValueError('native-command-model-selector')
    selected, separator, unused = script.split(marker, 1)[1].partition(' -ErrorAction Stop')
    if not separator or selected not in ('Cmdlet', 'Cmdlet,Function'):
        raise ValueError('native-command-model-selector')
    allowed_types = tuple(selected.split(','))
    if type(observations) is not tuple:
        raise ValueError('native-command-model-observations')
    by_name = {}
    expected = {'Get-Acl': 'Microsoft.PowerShell.Security',
                'Get-FileHash': 'Microsoft.PowerShell.Utility'}
    for observation in observations:
        if (type(observation) is not dict
                or set(observation) != {'name', 'moduleName', 'commandType', 'runtimeType'}
                or any(type(value) is not str for value in observation.values())):
            raise ValueError('native-command-model-observation')
        name, kind = observation['name'], observation['commandType']
        if (name not in expected or name in by_name
                or observation['moduleName'] != expected[name]
                or kind not in ('Cmdlet', 'Function')
                or observation['runtimeType'] != 'System.Management.Automation.' + kind + 'Info'):
            raise ValueError('native-command-model-observation')
        by_name[name] = observation
    return tuple(name for name in expected
                 if name not in by_name or by_name[name]['commandType'] not in allowed_types)


def native_command_observations(stdout):
    """Strictly decode bounded public facts from the actual native child."""
    if type(stdout) is not bytes or len(stdout) > 4096:
        raise ValueError('native-command-observation-bound')
    lines = stdout.decode('ascii', errors='strict').splitlines()
    if not lines or not lines[0].startswith('PUBLIC_NATIVE_UTILITY_COLD:'):
        raise ValueError('native-command-utility-observation')
    loaded = lines.pop(0).removeprefix('PUBLIC_NATIVE_UTILITY_COLD:')
    if loaded not in tuple(str(index) for index in range(9)):
        raise ValueError('native-command-utility-observation')
    passed = bool(lines and lines[-1] == 'PUBLIC_NATIVE_MODULE_ACL_HASH_PASS')
    if passed:
        lines.pop()
    observations = []
    for line in lines:
        fields = line.split(':')
        if len(fields) != 5 or fields[0] != 'PUBLIC_NATIVE_COMMAND':
            raise ValueError('native-command-observation-schema')
        observations.append(dict(zip(('name', 'moduleName', 'commandType', 'runtimeType'), fields[1:])))
    facts = tuple(observations)
    modeled_native_precheck_missing(NATIVE_MODULE_SCRIPT, facts)
    if [item['name'] for item in facts] not in ([], ['Get-Acl'], ['Get-FileHash'], ['Get-Acl', 'Get-FileHash']):
        raise ValueError('native-command-observation-order')
    return {'utilityModulesUnloaded': int(loaded), 'commands': facts, 'oraclePassed': passed}


class NativeCommandDiscoveryModelPositive(unittest.TestCase):
    """Portable typed Function filter model; no native result is implied."""
    script = NATIVE_MODULE_SCRIPT

    def test_exact_source_selected_precheck_accepts_typed_function_model(self):
        self.observations = (
            {'name': 'Get-Acl', 'moduleName': 'Microsoft.PowerShell.Security',
             'commandType': 'Cmdlet', 'runtimeType': 'System.Management.Automation.CmdletInfo'},
            {'name': 'Get-FileHash', 'moduleName': 'Microsoft.PowerShell.Utility',
             'commandType': 'Function', 'runtimeType': 'System.Management.Automation.FunctionInfo'},
        )
        self.missing = modeled_native_precheck_missing(self.script, self.observations)
        self.assertEqual(self.missing, (), 'NATIVE_FUNCTION_DISCOVERY_MUST_BE_ACCEPTED')


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
    def test_exact_c_selector_typed_function_model_red_then_current_green(self):
        cases = []
        for script in (native_c_before_script(), NATIVE_MODULE_SCRIPT):
            case = NativeCommandDiscoveryModelPositive(
                'test_exact_source_selected_precheck_accepts_typed_function_model')
            case.script = script
            result = unittest.TestResult()
            case.run(result)
            cases.append((case, result))
        (old_case, old), (current_case, current) = cases
        self.assertEqual((old.testsRun, len(old.failures), len(old.errors), len(old.skipped)), (1, 1, 0, 0))
        self.assertIn('NATIVE_FUNCTION_DISCOVERY_MUST_BE_ACCEPTED', old.failures[0][1])
        self.assertEqual(old_case.missing, ('Get-FileHash',))
        self.assertEqual((current.testsRun, len(current.failures), len(current.errors), len(current.skipped)), (1, 0, 0, 0))
        self.assertEqual(old_case.observations, current_case.observations)

    def test_typed_filter_model_refuses_malformed_facts_and_unknown_selector(self):
        valid = {'name': 'Get-FileHash', 'moduleName': 'Microsoft.PowerShell.Utility',
                 'commandType': 'Function', 'runtimeType': 'System.Management.Automation.FunctionInfo'}
        for wrong in (None, [], ({},), ({**valid, 'commandType': True},),
                      ({**valid, 'commandType': 'Alias'},), ({**valid, 'moduleName': 'PUBLIC foreign'},),
                      ({**valid, 'runtimeType': 'System.Management.Automation.CmdletInfo'},), (valid, valid)):
            with self.subTest(observations=wrong):
                with self.assertRaisesRegex(ValueError, '^native-command-model-observation'):
                    modeled_native_precheck_missing(NATIVE_MODULE_SCRIPT, wrong)
        for wrong in ('', NATIVE_MODULE_SCRIPT.replace('Cmdlet,Function -ErrorAction Stop',
                                                      'All -ErrorAction Stop', 1)):
            with self.subTest(selector=wrong):
                with self.assertRaisesRegex(ValueError, '^native-command-model-selector$'):
                    modeled_native_precheck_missing(wrong, (valid,))

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
        from agent_tools import source_module_loader
        c_path = (AUTHENTIC_FIXTURE / 'native_module_script_c.before.ps1').resolve()
        with tempfile.TemporaryDirectory(prefix='windows-native-module-path-') as directory, \
                source_module_loader._bootstrap_source(c_path) as (c_raw, c_closing):
            self.assertEqual(hashlib.sha256(c_raw).hexdigest(), NATIVE_C_SCRIPT_SHA256)
            self.assertEqual(len(c_raw), 1076)
            c_script_bytes = b'\xef\xbb\xbf' + c_raw
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
                child_environment = factory(executable, inherited)
                result = subprocess.run([executable, '-NoLogo', '-NoProfile', '-NonInteractive',
                                         '-File', str(script), str(data), digest],
                                        env=child_environment, capture_output=True,
                                        timeout=30, check=False)
                if index == 1:
                    current_environment = child_environment
                    current_data = data
                for name, raw in (('stdout.private', result.stdout), ('stderr.private', result.stderr),
                                  ('exit.private', str(result.returncode).encode('ascii'))):
                    with (case / name).open('xb') as stream:
                        stream.write(raw)
                records.append({'exit': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr})
                self.assertEqual(inherited, supplied_before)
                self.assertEqual(dict(os.environ), parent_before)
                self.assertEqual(script.read_bytes(), script_bytes)
                self.assertEqual(data.read_bytes(), public)
            # A third fresh child runs the authenticated exact C script with
            # the same sanitized environment as the corrected physical oracle.
            # The only source carrier transformation is the same UTF-8 BOM.
            case = Path(directory) / 'exact-c-counterfactual'
            case.mkdir(mode=0o700)
            script, data = case / 'control.ps1', current_data
            with script.open('xb') as stream:
                stream.write(c_script_bytes)
            self.assertEqual(data.read_bytes(), public)
            self.assertEqual(current_environment, windows_powershell_environment(executable, inherited))
            environment_before = dict(current_environment)
            argv = [executable, '-NoLogo', '-NoProfile', '-NonInteractive',
                    '-File', str(script), str(data), digest]
            self.assertLessEqual(sum(len(part.encode('utf-8', errors='strict')) + 1 for part in argv), 60000)
            runtime = ROOT / '.runtime'
            runtime.mkdir(mode=0o700, exist_ok=True)
            evidence = Path(tempfile.mkdtemp(prefix='windows-powershell-native-c-', dir=str(runtime)))
            def preserve(name, value):
                fd = os.open(evidence / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(value)
                    stream.flush()
                    os.fsync(stream.fileno())
            def document(name, value):
                preserve(name, (json.dumps(value, sort_keys=True, indent=2) + '\n').encode('utf-8'))
                if name == 'causal-proof.private.json':
                    emit_native_causal_marker(value)
            preserve('exact-c-control.ps1', c_script_bytes)
            preserve('corrected-control.ps1', script_bytes)
            preserve('PUBLIC.bytes', public)
            for index, record in enumerate(records):
                preserve(str(index) + '.stdout.private', record['stdout'])
                preserve(str(index) + '.stderr.private', record['stderr'])
                document(str(index) + '.terminal.private.json',
                         {'exit': record['exit'], 'stdoutEof': True, 'stderrEof': True,
                          'completedProcessReturned': True})
            c_closing()
            for label, record in zip(('bad_module_path', 'sanitized'), records):
                emit_native_capture_marker(label, record['stdout'], record['stderr'], record['exit'],
                                           stdout_eof=True, stderr_eof=True,
                                           completed_process_returned=True, source_closing=True)
            document('exact-c.intent.private.json',
                     {'schemaVersion': 1, 'state': 'SINGLE_OWNED_NATIVE_SUBMISSION_INTENT_NO_REPLAY',
                      'argv': argv, 'sourceSha256': NATIVE_C_SCRIPT_SHA256,
                      'carrierSha256': hashlib.sha256(c_script_bytes).hexdigest(),
                      'dataSha256': digest, 'sameSanitizedEnvironmentAsCorrectedOracle': True,
                      'sourceHeld': True, 'coldUtilityPrefixAddedToC': False,
                      'historicalCActualCommandTypesRetained': False})
            try:
                result = subprocess.run(argv, env=current_environment, capture_output=True,
                                        timeout=30, check=False)
            except subprocess.TimeoutExpired as failure:
                preserve('exact-c.stdout.private', failure.stdout or b'')
                preserve('exact-c.stderr.private', failure.stderr or b'')
                document('exact-c.terminal.private.json',
                         {'state': 'TIMEOUT_NO_REPLAY', 'exit': None, 'stdoutEof': False,
                          'stderrEof': False, 'completedProcessReturned': False,
                          'sourceClosing': False})
                emit_native_capture_marker('exact_c', failure.stdout or b'', failure.stderr or b'', None,
                                           stdout_eof=False, stderr_eof=False,
                                           completed_process_returned=False, source_closing=False)
                raise
            preserve('exact-c.stdout.private', result.stdout)
            preserve('exact-c.stderr.private', result.stderr)
            preserve('exact-c.exit.private', str(result.returncode).encode('ascii'))
            c_closing()
            self.assertEqual(current_environment, environment_before)
            self.assertEqual(dict(os.environ), parent_before)
            self.assertEqual(script.read_bytes(), c_script_bytes)
            self.assertEqual(data.read_bytes(), public)
            document('exact-c.terminal.private.json',
                     {'schemaVersion': 1, 'state': 'NATIVE_C_COUNTERFACTUAL_CAPTURED_NO_PASS_CLAIM',
                      'exit': result.returncode, 'stdoutEof': True, 'stderrEof': True,
                      'completedProcessReturned': True, 'sourceClosing': True,
                      'sourceSha256': NATIVE_C_SCRIPT_SHA256,
                      'carrierSha256': hashlib.sha256(script.read_bytes()).hexdigest(),
                      'dataSha256': hashlib.sha256(data.read_bytes()).hexdigest()})
            emit_native_capture_marker('exact_c', result.stdout, result.stderr, result.returncode,
                                       stdout_eof=True, stderr_eof=True,
                                       completed_process_returned=True, source_closing=True)
            counterfactual = {'exit': result.returncode, 'stdout': result.stdout,
                              'stderr': result.stderr, 'stdoutEof': True, 'stderrEof': True,
                              'evidence': str(evidence)}
            records.append(counterfactual)
            old, current = records[:2]
            # Full original streams remain in the assertion if either real
            # native case fails; neither command nor ACL/hash is substituted.
            self.assertEqual(old['exit'], 11, records)
            self.assertIn(old['stderr'].splitlines(),
                          ([b'PUBLIC_NATIVE_MISSING:Get-FileHash'],
                           [b'PUBLIC_NATIVE_MISSING:Get-Acl,Get-FileHash']), records)
            old_facts = native_command_observations(old['stdout'])
            self.assertIs(old_facts['oraclePassed'], False, records)
            self.assertNotIn('Get-FileHash', [item['name'] for item in old_facts['commands']], records)
            self.assertEqual(current['exit'], 0, records)
            self.assertEqual(current['stderr'], b'', records)
            current_facts = native_command_observations(current['stdout'])
            self.assertIs(current_facts['oraclePassed'], True, records)
            self.assertEqual([item['name'] for item in current_facts['commands']],
                             ['Get-Acl', 'Get-FileHash'], records)
            self.assertEqual(modeled_native_precheck_missing(NATIVE_MODULE_SCRIPT,
                                                            current_facts['commands']), (), records)
            # A genuine Function result is required to explain the rejected C
            # Cmdlet-only predicate. A different native kind fails this proof.
            current_hash = next(item for item in current_facts['commands']
                                if item['name'] == 'Get-FileHash')
            self.assertEqual((current_hash['moduleName'], current_hash['commandType'],
                              current_hash['runtimeType']),
                             ('Microsoft.PowerShell.Utility', 'Function',
                              'System.Management.Automation.FunctionInfo'), records)
            c_missing = modeled_native_precheck_missing(c_raw.decode('utf-8', errors='strict'),
                                                       current_facts['commands'])
            self.assertIn('Get-FileHash', c_missing, records)
            self.assertEqual(counterfactual['exit'], 11, records)
            self.assertEqual(counterfactual['stdout'], b'', records)
            self.assertEqual(counterfactual['stderr'].splitlines(),
                             [('PUBLIC_NATIVE_MISSING:' + ','.join(c_missing)).encode('ascii')], records)
            self.assertIs(counterfactual['stdoutEof'], True, records)
            self.assertIs(counterfactual['stderrEof'], True, records)
            document('causal-proof.private.json',
                     {'schemaVersion': 1, 'state': 'EXACT_C_PRECHECK_RED_CORRECTED_PHYSICAL_ORACLE_GREEN',
                      'cExit': counterfactual['exit'], 'correctedExit': current['exit'],
                      'observedHashCommand': current_hash, 'cMissing': c_missing,
                      'sourceClosing': True, 'allThreeCompletedProcessReturned': True,
                      'allThreeStdoutEof': True, 'allThreeStderrEof': True,
                      'historicalCActualCommandTypeStillUnknown': True,
                      'sameSanitizedEnvironment': True, 'sameOwnedDataBytesAndHash': True, 'sameOwnedDataFileArgument': True,
                      'physicalAclAndHashOracleCompleted': True})


def _native_causal_proof_control_value():
    """Typed local codec model only; callers must capture its diagnostic text."""
    return {'schemaVersion': 1, 'state': 'EXACT_C_PRECHECK_RED_CORRECTED_PHYSICAL_ORACLE_GREEN',
            'cExit': 11, 'correctedExit': 0,
            'observedHashCommand': {'name': 'Get-FileHash', 'moduleName': 'Microsoft.PowerShell.Utility',
                                    'commandType': 'Function', 'runtimeType': 'System.Management.Automation.FunctionInfo'},
            'cMissing': ('Get-FileHash',), 'sourceClosing': True,
            'allThreeCompletedProcessReturned': True, 'allThreeStdoutEof': True,
            'allThreeStderrEof': True, 'historicalCActualCommandTypeStillUnknown': True,
            'sameSanitizedEnvironment': True, 'sameOwnedDataBytesAndHash': True,
            'sameOwnedDataFileArgument': True, 'physicalAclAndHashOracleCompleted': True}


def actual_native_document_boundary(before):
    """Execute actual retained/current nested IO with owned closed inputs.

    All synthetic proof text remains inside StringIO. This local control does
    not run PowerShell or assert that a native proof happened.
    """
    from agent_tools import source_module_loader
    producer = Path(__file__).resolve()
    fragment = (AUTHENTIC_FIXTURE / 'native_capture_document_ca1.before.fragment').resolve()
    with ExitStack() as held:
        sources = {path: held.enter_context(source_module_loader._bootstrap_source(path))
                   for path in (producer, fragment)}
        if hashlib.sha256(sources[fragment][0]).hexdigest() != NATIVE_DOCUMENT_CA1_SHA256:
            raise ValueError('native-document-before-source')
        tree = ast.parse(sources[producer][0], filename=str(producer))
        imports = []
        for node in tree.body:
            if isinstance(node, (ast.Import, ast.ImportFrom)) or (
                    not imports and isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant)
                    and isinstance(node.value.value, str)):
                imports.append(node)
            else:
                break
        helper_names = ('_emit_native_public_json', 'emit_native_capture_marker', 'emit_native_causal_marker')
        emitters = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in helper_names]
        if tuple(node.name for node in emitters) != helper_names:
            raise ValueError('native-document-emitter-identity')
        classes = [node for node in tree.body if isinstance(node, ast.ClassDef)
                   and node.name == 'NativeWindowsPowerShellEnvironmentTests']
        if len(classes) != 1:
            raise ValueError('native-document-producer-class')
        methods = [node for node in classes[0].body if isinstance(node, ast.FunctionDef)
                   and node.name == 'test_owned_missing_module_path_old_refuses_current_acl_and_hash_complete']
        if len(methods) != 1:
            raise ValueError('native-document-producer-method')
        path = fragment if before else producer
        if before:
            nested = ast.parse(textwrap.dedent(sources[fragment][0].decode('utf-8', errors='strict')),
                               filename=str(fragment)).body
        else:
            nested = [node for node in ast.walk(methods[0]) if isinstance(node, ast.FunctionDef)
                      and node.name in ('preserve', 'document')]
        if [node.name for node in nested if isinstance(node, ast.FunctionDef)] != ['preserve', 'document'] or len(nested) != 2:
            raise ValueError('native-document-definitions')
        value = _native_causal_proof_control_value()
        with tempfile.TemporaryDirectory(prefix='native-document-local-codec-') as directory:
            evidence = Path(directory)
            if list(evidence.iterdir()):
                raise ValueError('native-document-owned-input')
            namespace = {'__name__': 'owned_native_document_boundary', '__file__': str(path), 'evidence': evidence}
            exec(compile(ast.Module(body=[*imports, *emitters], type_ignores=[]),
                         str(producer), 'exec', dont_inherit=True), namespace)
            exec(compile(ast.Module(body=nested, type_ignores=[]),
                         str(path), 'exec', dont_inherit=True), namespace)
            if any(namespace[name].__globals__ is not namespace or namespace[name].__code__.co_filename != str(path)
                   for name in ('preserve', 'document')):
                raise ValueError('native-document-source-binding')
            for unused, closing in sources.values():
                closing()
            captured = io.StringIO()
            with redirect_stdout(captured):
                namespace['document']('causal-proof.private.json', value)
            persisted = (evidence / 'causal-proof.private.json').read_bytes()
            for unused, closing in sources.values():
                closing()
            return {'stdout': captured.getvalue(), 'persisted': persisted,
                    'expected': (json.dumps(value, sort_keys=True, indent=2) + '\n').encode('utf-8'),
                    'sourceClosing': True, 'nativePowerShellExecuted': False}


class NativeCaptureDocumentPositive(unittest.TestCase):
    """Same local positive against genuine retained/current nested document."""
    before = False

    def test_actual_persisted_document_emits_public_causal_marker(self):
        self.observation = actual_native_document_boundary(self.before)
        self.assertEqual(self.observation['persisted'], self.observation['expected'])
        self.assertIs(self.observation['sourceClosing'], True)
        self.assertIs(self.observation['nativePowerShellExecuted'], False)
        lines = self.observation['stdout'].splitlines()
        self.assertEqual(len(lines), 1, 'PERSISTED_NATIVE_CAUSAL_RECEIPT_MUST_BE_PUBLICLY_RETAINED')
        self.assertLessEqual(len(lines[0].encode('utf-8')) + 1, 16384)
        prefix = 'PUBLIC_NATIVE_ENV_DIAGNOSTIC_JSON:'
        self.assertTrue(lines[0].startswith(prefix))
        envelope = json.loads(lines[0][len(prefix):])
        self.assertEqual(set(envelope), {'schemaVersion', 'kind', 'proof'})
        self.assertEqual(envelope['schemaVersion'], 1)
        self.assertEqual(envelope['kind'], 'causalProof')
        self.assertEqual(envelope['proof'], json.loads(self.observation['persisted']))


class NativePublicCaptureControlTests(unittest.TestCase):
    """Local diagnostic transport controls; no Windows execution is implied."""
    def _decode(self, text):
        prefix = 'PUBLIC_NATIVE_ENV_DIAGNOSTIC_JSON:'
        lines = text.splitlines()
        self.assertTrue(lines)
        records = []
        for line in lines:
            self.assertLessEqual(len(line.encode('utf-8')) + 1, 16384)
            self.assertTrue(line.startswith(prefix))
            records.append(json.loads(line[len(prefix):]))
        manifest = records.pop(0)
        self.assertEqual(set(manifest), {'schemaVersion', 'kind', 'captureId', 'case', 'returncode',
                                        'stdoutEof', 'stderrEof', 'completedProcessReturned',
                                        'sourceClosing', 'stdout', 'stderr'})
        self.assertEqual((manifest['schemaVersion'], manifest['kind']), (1, 'capture'))
        self.assertIs(type(manifest['captureId']), str)
        identity = uuid.UUID(hex=manifest['captureId'])
        self.assertEqual((identity.hex, identity.version), (manifest['captureId'], 4))
        self.assertIn(manifest['case'], ('bad_module_path', 'sanitized', 'exact_c'))
        for key in ('stdoutEof', 'stderrEof', 'completedProcessReturned', 'sourceClosing'):
            self.assertIs(type(manifest[key]), bool)
        if manifest['completedProcessReturned']:
            self.assertIs(type(manifest['returncode']), int)
            self.assertTrue(manifest['stdoutEof'] and manifest['stderrEof'] and manifest['sourceClosing'])
        else:
            self.assertIsNone(manifest['returncode'])
            self.assertFalse(manifest['stdoutEof'] or manifest['stderrEof'] or manifest['sourceClosing'])
        streams = {}
        position = 0
        for name in ('stdout', 'stderr'):
            summary = manifest[name]
            self.assertEqual(set(summary), {'bytes', 'sha256', 'chunks'})
            self.assertIs(type(summary['bytes']), int)
            self.assertGreaterEqual(summary['bytes'], 0)
            self.assertIs(type(summary['chunks']), int)
            self.assertEqual(summary['chunks'], (summary['bytes'] + 8191) // 8192)
            self.assertIs(type(summary['sha256']), str)
            self.assertEqual(len(summary['sha256']), 64)
            self.assertEqual(set(summary['sha256']) - set('0123456789abcdef'), set())
            parts = []
            for index in range(summary['chunks']):
                record = records[position]
                position += 1
                self.assertEqual(set(record), {'schemaVersion', 'kind', 'captureId', 'case', 'stream',
                                               'chunkIndex', 'chunkCount', 'rawOffset', 'bytes',
                                               'chunkSha256', 'streamBytes', 'streamSha256', 'base64'})
                self.assertEqual((record['schemaVersion'], record['kind'], record['captureId'],
                                  record['case'], record['stream'], record['chunkIndex'],
                                  record['chunkCount'], record['rawOffset']),
                                 (1, 'streamChunk', manifest['captureId'], manifest['case'], name,
                                  index, summary['chunks'], index * 8192))
                self.assertEqual((record['streamBytes'], record['streamSha256']),
                                 (summary['bytes'], summary['sha256']))
                self.assertIs(type(record['base64']), str)
                part = base64.b64decode(record['base64'], validate=True)
                self.assertEqual((record['bytes'], record['chunkSha256']),
                                 (len(part), hashlib.sha256(part).hexdigest()))
                self.assertGreater(len(part), 0)
                self.assertLessEqual(len(part), 8192)
                parts.append(part)
            streams[name] = b''.join(parts)
            self.assertEqual((len(streams[name]), hashlib.sha256(streams[name]).hexdigest()),
                             (summary['bytes'], summary['sha256']))
        self.assertEqual(position, len(records))
        return manifest, streams

    def test_actual_retained_document_marker_red_then_current_green(self):
        cases = []
        for before in (True, False):
            case = NativeCaptureDocumentPositive('test_actual_persisted_document_emits_public_causal_marker')
            case.before = before
            result = unittest.TestResult()
            case.run(result)
            cases.append((case, result))
        (old_case, old), (current_case, current) = cases
        self.assertEqual((old.testsRun, len(old.failures), len(old.errors), len(old.skipped)), (1, 1, 0, 0))
        self.assertIn('PERSISTED_NATIVE_CAUSAL_RECEIPT_MUST_BE_PUBLICLY_RETAINED', old.failures[0][1])
        self.assertEqual((current.testsRun, len(current.failures), len(current.errors), len(current.skipped)), (1, 0, 0, 0))
        self.assertEqual(old_case.observation['persisted'], current_case.observation['persisted'])
        self.assertEqual(old_case.observation['stdout'], '')

    def test_saved_inert_python_child_streams_roundtrip_multiple_chunks(self):
        # Saved owned Python only; binary public stream patterns exercise full
        # chunking, including NUL/non-UTF8 bytes and CRLF without normalization.
        program = ("import os\n"
                   "for fd,pattern,count in ((1,b'PUBLIC stdout\\x00\\xff\\r\\n',4000),(2,b'PUBLIC stderr\\r\\n',5000)):\n"
                   " value=memoryview(pattern*count)\n"
                   " while value:value=value[os.write(fd,value):]\n"
                   "raise SystemExit(7)\n")
        with tempfile.TemporaryDirectory(prefix='native-public-codec-child-') as directory:
            path = Path(directory) / 'owned-public-child.py'
            with path.open('xb') as stream:
                stream.write(program.encode('utf-8'))
            argv = [sys.executable, '-I', '-B', str(path)]
            self.assertLessEqual(sum(len(part.encode('utf-8')) + 1 for part in argv), 60000)
            child = subprocess.run(argv, capture_output=True, timeout=20, check=False)
            self.assertEqual(path.read_bytes(), program.encode('utf-8'))
        self.assertEqual(child.returncode, 7)
        self.assertEqual(child.stdout, b'PUBLIC stdout\x00\xff\r\n' * 4000)
        self.assertEqual(child.stderr, b'PUBLIC stderr\r\n' * 5000)
        captured = io.StringIO()
        with redirect_stdout(captured):
            identity = emit_native_capture_marker('sanitized', child.stdout, child.stderr, child.returncode,
                                                  stdout_eof=True, stderr_eof=True,
                                                  completed_process_returned=True, source_closing=True)
        manifest, streams = self._decode(captured.getvalue())
        self.assertEqual((manifest['captureId'], manifest['returncode']), (identity, child.returncode))
        self.assertEqual(streams, {'stdout': child.stdout, 'stderr': child.stderr})
        self.assertGreater(manifest['stdout']['chunks'], 1)
        self.assertGreater(manifest['stderr']['chunks'], 1)

    def test_partial_frame_model_and_typed_refusals(self):
        # Codec-only partial frame; no native or actual process closure claim.
        arguments = {'case': 'exact_c', 'stdout': b'PUBLIC partial stdout\r',
                     'stderr': b'PUBLIC partial stderr', 'returncode': None,
                     'stdout_eof': False, 'stderr_eof': False,
                     'completed_process_returned': False, 'source_closing': False}
        captured = io.StringIO()
        with redirect_stdout(captured):
            emit_native_capture_marker(**arguments)
        manifest, streams = self._decode(captured.getvalue())
        self.assertIsNone(manifest['returncode'])
        self.assertFalse(manifest['stdoutEof'] or manifest['stderrEof']
                         or manifest['completedProcessReturned'] or manifest['sourceClosing'])
        self.assertEqual(streams, {'stdout': arguments['stdout'], 'stderr': arguments['stderr']})
        for change in ({'case': 'foreign'}, {'case': True}, {'stdout': 'PUBLIC text'}, {'stderr': None},
                       {'returncode': True}, {'stdout_eof': 1}, {'source_closing': True},
                       {'stderr_eof': True}, {'completed_process_returned': True}):
            with self.subTest(change=change):
                captured = io.StringIO()
                with redirect_stdout(captured), self.assertRaisesRegex(ValueError, '^native-public-'):
                    emit_native_capture_marker(**{**arguments, **change})
                self.assertEqual(captured.getvalue(), '')
        proof = _native_causal_proof_control_value()
        for wrong in ({**proof, 'argv': ['PUBLIC forbidden field']}, {**proof, 'sourceClosing': 1},
                      {**proof, 'observedHashCommand': {**proof['observedHashCommand'], 'commandType': 'Cmdlet'}}):
            captured = io.StringIO()
            with redirect_stdout(captured), self.assertRaisesRegex(ValueError, '^native-public-'):
                emit_native_causal_marker(wrong)
            self.assertEqual(captured.getvalue(), '')


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
