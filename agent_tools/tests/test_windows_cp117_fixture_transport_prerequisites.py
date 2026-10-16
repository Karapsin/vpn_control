"""Causal test-harness prerequisites with the original positive assertions.

The portable child deliberately projects Windows text stdout. The native cases
retain the original complete copy-loop methods, native handles, mutation, and
closing checks. The Write-Progress case is an explicit mechanics control; the
original compiler test's truncated CLIXML is not reconstructed here.

An uncaught same-positive RED is available after the source freeze, for example:
  python -m agent_tools.tests.test_windows_cp117_fixture_transport_prerequisites \
      --causal remote --variant before --evidence-directory NEW_OWNED_DIRECTORY
Native copy-old, copy-current, and progress require Windows PowerShell.
"""
import argparse
import ast
import base64
import builtins
from contextlib import ExitStack, contextmanager
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import types
import unittest


_TESTS = Path(__file__).resolve().parent
_FIXTURES = _TESTS / 'fixtures' / 'windows_cp117_fixture_transport_prerequisites'
_PROVENANCE_SHA256 = 'd7ccf0dc331e20d5b543e4764e74f161bf96d610b131a54a3d9bfcacf66d9c63'
_SOURCE_COMMIT = 'a5cd9b73d49ff0b52f4a04a29a9122d4fe48b173'
_FILES = ('copy_loop.before.source', 'remote_public.before.source', 'carrier.before.source')
_SOURCE_PATHS = {
    'copy': _TESTS / 'test_windows_cp117_server_read_binding.py',
    'base': _TESTS / 'test_windows_cp117_base_source_refresh.py',
    'loader': _TESTS.parent / 'windows_cp117_base_source_refresh.py',
    'environment': _TESTS / 'fixtures' / 'windows_powershell_environment.py',
    'successor': _TESTS / 'test_windows_cp117_server_read_binding.py',
    'stage': _TESTS.parent / 'windows_update_fixture_stage.py',
    'acl': _TESTS.parents[1] / 'scripts' / 'windows_fixture_stage_acl.py',
    'history_context': _TESTS / 'fixtures' / 'windows_cp117_historical_factory' / 'context.py',
    'attributes': _TESTS.parents[1] / '.gitattributes',
}
_COPY_METHODS = (
    'test_actual_old_copy_loop_can_publish_stale_earlier_destination',
    'test_actual_current_copy_loop_blocks_mutation_and_closes_all_outputs',
)
_REMOTE_METHOD = 'test_actual_legacy_remote_command_exceeds_linux_argument_bound_new_roundtrip'
_COPY_CONSTANTS = (
    'COMPLETE_STAGE_OLD_COPY_LOOP', 'COMPLETE_STAGE_CURRENT_COPY_LOOP',
    'COMPLETE_STAGE_CURRENT_OUTPUT_CLOSING',
)
_REMOTE_CONSTANT = 'SHORTCUT_COMPRESSED_REMOTE_COMMAND_SOURCE'
_WINDOWS = os.name == 'nt'
_PROJECTION = (
    "import io,sys\n"
    "sys.stdout=io.TextIOWrapper(sys.stdout.buffer,encoding='utf-8',"
    "errors='strict',newline='\\r\\n',write_through=True)\n"
)
_PROGRESS_PUBLIC = (
    "$ErrorActionPreference='Stop';"
    "if($PSVersionTable.PSVersion.Major -ne 5){throw 'WINDOWS_POWERSHELL_5_REQUIRED'};"
    "Write-Progress -Activity 'CP117_PUBLIC_PROGRESS' -Status 'PUBLIC';"
    "[Console]::Out.WriteLine('PROGRESS_CARRIER_PASS')"
).encode('utf-8')


def _generation(value):
    return [getattr(value, name) for name in (
        'st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
        'st_size', 'st_mtime_ns', 'st_ctime_ns')]


@contextmanager
def _inputs(pins):
    """Hold finite real source/fixture files until every child has terminated."""
    from agent_tools.source_module_loader import _bootstrap_source
    with ExitStack() as stack:
        guards = []

        def read(path, limit):
            raw, guard = stack.enter_context(_bootstrap_source(path))
            if not 0 < len(raw) <= limit:
                raise ValueError('prerequisite-source-bound')
            guard()
            pins[str(path)] = {'sha256': hashlib.sha256(raw).hexdigest(),
                               'generation': _generation(path.stat())}
            guards.append(guard)
            return raw

        try:
            metadata = read(_FIXTURES / 'provenance.json', 16384)
            if hashlib.sha256(metadata).hexdigest() != _PROVENANCE_SHA256:
                raise ValueError('prerequisite-provenance-sha256')
            provenance = json.loads(metadata)
            if (provenance['schemaVersion'] != 1
                    or provenance['sourceCommit'] != _SOURCE_COMMIT
                    or set(provenance['files']) != set(_FILES)):
                raise ValueError('prerequisite-provenance-schema')
            retained = {}
            for name in _FILES:
                raw = read(_FIXTURES / name, 16384)
                expected = provenance['files'][name]
                if (len(raw) != expected['bytes']
                        or hashlib.sha256(raw).hexdigest() != expected['sha256']):
                    raise ValueError('prerequisite-retained-source')
                retained[name] = raw
            current = {name: read(path, 2097152)
                       for name, path in _SOURCE_PATHS.items()}
            yield retained, current
        finally:
            for guard in reversed(guards):
                guard()


def _node_source(raw, node):
    lines = raw.decode('utf-8').splitlines(keepends=True)
    first = min([node.lineno] + [item.lineno for item in node.decorator_list]) \
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)) else node.lineno
    return ''.join(lines[first - 1:node.end_lineno])


def _unique(tree, kind, name):
    values = [node for node in tree.body
              if isinstance(node, kind) and getattr(node, 'name', None) == name]
    if len(values) != 1:
        raise ValueError('prerequisite-source-definition')
    return values[0]


def _class_source(raw, name, methods, constants):
    tree = ast.parse(raw)
    selected = []
    for constant in constants:
        matches = [node for node in tree.body if isinstance(node, ast.Assign)
                   and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
                   and node.targets[0].id == constant]
        if len(matches) != 1:
            raise ValueError('prerequisite-source-constant')
        selected.append(_node_source(raw, matches[0]))
    cls = _unique(tree, ast.ClassDef, name)
    header = raw.decode('utf-8').splitlines(keepends=True)[cls.lineno - 1]
    if header.strip() != 'class ' + name + '(HistoryCase):':
        raise ValueError('prerequisite-original-class')
    selected.append(header)
    for method in methods:
        selected.append(_node_source(raw, _unique(cls, ast.FunctionDef, method)))
    return '\n'.join(selected).encode('utf-8')


def _carrier_source(raw):
    tree = ast.parse(raw)
    return '\n'.join(_node_source(raw, _unique(tree, ast.FunctionDef, name))
                     for name in ('_complete_windows_fixture_carrier',
                                  '_run_complete_windows_fixture')).encode('utf-8')


def _assertions(raw, clsname, method):
    cls = _unique(ast.parse(raw), ast.ClassDef, clsname)
    node = _unique(cls, ast.FunctionDef, method)
    return [ast.dump(call, include_attributes=False) for call in ast.walk(node)
            if isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
            and isinstance(call.func.value, ast.Name) and call.func.value.id == 'self'
            and call.func.attr.startswith('assert')]


def _recorder(captures, *, windows_projection):
    from agent_tools.tests.fixtures.windows_powershell_environment import windows_powershell_environment

    def run(argv, **options):
        argv = list(argv)
        if windows_projection:
            if len(argv) != 3 or argv[:2] != [sys.executable, '-c']:
                raise ValueError('prerequisite-projected-child-shape')
            argv = [sys.executable, '-I', '-B', '-c', _PROJECTION + argv[2]]
        elif argv and Path(argv[0]).name.casefold() in {'powershell', 'powershell.exe'}:
            # Both before/current source get the same explicit runtime policy.
            # The native compiler reference/progress change is the causal factor.
            environment = windows_powershell_environment(argv[0], os.environ)
            if 'env' in options and options['env'] != environment:
                raise ValueError('prerequisite-native-environment-mismatch')
            options['env'] = environment
        if not argv or not all(type(part) is str for part in argv):
            raise ValueError('prerequisite-child-command-shape')
        command_bytes = sum(len(part.encode('utf-8')) + 1 for part in argv)
        if (command_bytes > 60000
                or options.get('capture_output') is not True):
            raise ValueError('prerequisite-child-command-bound')
        record = {'returnCode': None, 'stdout': b'', 'stderr': b'',
                  'complete': False, 'stdoutEof': False, 'stderrEof': False,
                  'replayAllowed': False,
                  'argvSha256': hashlib.sha256(json.dumps(argv).encode()).hexdigest(),
                  'commandBytes': command_bytes,
                  'maxArgumentBytes': max(len(part.encode()) for part in argv)}
        captures.append(record)
        try:
            result = subprocess.run(argv, **options)
        except subprocess.TimeoutExpired as error:
            record['stdout'] = error.stdout or b''
            record['stderr'] = error.stderr or b''
            raise
        record.update(returnCode=result.returncode, stdout=result.stdout,
                      stderr=result.stderr, complete=True,
                      stdoutEof=True, stderrEof=True)
        return result
    return run


def _owned_importer(run):
    # Only code compiled in this owned namespace sees the view. No global
    # subprocess, import hook, platform value, or product module is replaced.
    view = types.SimpleNamespace(run=run)

    def importing(name, globals=None, locals=None, fromlist=(), level=0):
        if name == 'subprocess' and level == 0:
            return view
        return builtins.__import__(name, globals, locals, fromlist, level)
    return importing


def _progress_case(carrier):
    class Positive(unittest.TestCase):
        def runTest(self):
            if not _WINDOWS:
                self.skipTest('actual Windows PowerShell 5 progress stream required')
            result = carrier(_PROGRESS_PUBLIC, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
            self.assertEqual(result.stdout, b'PROGRESS_CARRIER_PASS\r\n')
            self.assertEqual(result.stderr, b'')
    return Positive()


@contextmanager
def _owned_sources(selected, test_filename, loader, pins):
    """Compile only bytes held at their actual owned physical filenames."""
    from agent_tools.source_module_loader import _bootstrap_source
    with tempfile.TemporaryDirectory(prefix='cp117-prerequisite-source-') as folder:
        root = Path(folder).resolve()
        tests = root / 'agent_tools' / 'tests'
        tests.mkdir(parents=True, mode=0o700)
        test_path = tests / test_filename
        loader_path = tests.parent / 'windows_cp117_base_source_refresh.py'
        for path, raw in ((test_path, selected), (loader_path, loader)):
            with path.open('xb') as output:
                output.write(raw)
        with ExitStack() as stack:
            guards = []
            held_selected = None
            try:
                for path, expected in ((test_path, selected), (loader_path, loader)):
                    raw, guard = stack.enter_context(_bootstrap_source(path))
                    if raw != expected:
                        raise ValueError('prerequisite-owned-source-bytes')
                    if path == test_path:
                        held_selected = raw
                    guard()
                    guards.append(guard)
                    pins[str(path)] = {'sha256': hashlib.sha256(raw).hexdigest(),
                                       'generation': _generation(path.stat())}
                yield test_path, held_selected
            finally:
                for guard in reversed(guards):
                    guard()


@contextmanager
def _case(which, variant, captures, pins):
    if which not in {'remote', 'copy-old', 'copy-current', 'progress', 'successor-template'} \
            or variant not in {'before', 'current'}:
        raise ValueError('prerequisite-causal-case')
    if which == 'successor-template':
        yield _successor_positive(variant, captures, pins)
        return
    with _inputs(pins) as (retained, current):
        from agent_tools.tests import test_windows_cp117_base_source_refresh as fixture
        from agent_tools.tests.fixtures.windows_powershell_environment import windows_powershell_environment
        namespace = dict(vars(fixture))
        namespace.update(__name__=__name__, Path=Path, unittest=unittest,
                         fixture=fixture, os=os,
                         windows_powershell_environment=windows_powershell_environment)
        namespace['__builtins__'] = {
            **vars(builtins),
            '__import__': _owned_importer(_recorder(
                captures, windows_projection=which == 'remote')),
        }
        if which.startswith('copy-'):
            raw = retained['copy_loop.before.source'] if variant == 'before' else current['copy']
            selected = raw if variant == 'before' else _class_source(
                raw, 'CompleteStageOutputCustodyTests', _COPY_METHODS, _COPY_CONSTANTS)
            with _owned_sources(selected, _SOURCE_PATHS['copy'].name,
                                current['loader'], pins) as (path, held):
                namespace['__file__'] = str(path)
                exec(compile(held, str(path), 'exec', dont_inherit=True), namespace)
                method = _COPY_METHODS[which == 'copy-current']
                yield namespace['CompleteStageOutputCustodyTests'](method)
        elif which == 'remote':
            raw = retained['remote_public.before.source'] if variant == 'before' else current['base']
            selected = raw if variant == 'before' else _class_source(
                raw, 'ShortcutRemoteEnvelopeTests', ('command', 'public', _REMOTE_METHOD),
                (_REMOTE_CONSTANT,))
            with _owned_sources(selected, _SOURCE_PATHS['base'].name,
                                current['loader'], pins) as (path, held):
                namespace['__file__'] = str(path)
                exec(compile(held, str(path), 'exec', dont_inherit=True), namespace)
                yield namespace['ShortcutRemoteEnvelopeTests'](_REMOTE_METHOD)
        else:
            raw = retained['carrier.before.source'] if variant == 'before' else current['base']
            selected = raw if variant == 'before' else _carrier_source(raw)
            with _owned_sources(selected, _SOURCE_PATHS['base'].name,
                                current['loader'], pins) as (path, held):
                namespace.update(ast=ast, hashlib=hashlib, base64=base64, __file__=str(path))
                exec(compile(held, str(path), 'exec', dont_inherit=True), namespace)
                yield _progress_case(namespace['_run_complete_windows_fixture'])


def _run(which, variant):
    captures, pins = [], {}
    with _case(which, variant, captures, pins) as case:
        result = unittest.TestResult()
        case.run(result)
    return result, captures


class FixtureTransportPrerequisiteTests(unittest.TestCase):
    def test_exact_before_fragments_keep_current_original_positive_assertions(self):
        with _inputs({}) as (before, current):
            for method in _COPY_METHODS:
                self.assertEqual(_assertions(before['copy_loop.before.source'],
                                             'CompleteStageOutputCustodyTests', method),
                                 _assertions(current['copy'],
                                             'CompleteStageOutputCustodyTests', method))
            self.assertEqual(_assertions(before['remote_public.before.source'],
                                         'ShortcutRemoteEnvelopeTests', _REMOTE_METHOD),
                             _assertions(current['base'],
                                         'ShortcutRemoteEnvelopeTests', _REMOTE_METHOD))

    def test_actual_whole_envelope_windows_text_stdout_before_red_current_bytes_green(self):
        old, old_capture = _run('remote', 'before')
        self.assertEqual((old.testsRun, len(old.failures), len(old.errors), len(old.skipped)),
                         (1, 1, 0, 0), old.failures + old.errors)
        self.assertEqual(len(old_capture), 1)
        self.assertEqual(old_capture[0]['returnCode'], 0)
        self.assertEqual(old_capture[0]['stdout'], b'PUBLIC_REMOTE_PASS\r\n')
        self.assertEqual(old_capture[0]['stderr'], b'')
        current, current_capture = _run('remote', 'current')
        self.assertEqual((current.testsRun, current.failures, current.errors, current.skipped),
                         (1, [], [], []))
        self.assertEqual(current_capture[0]['stdout'], b'PUBLIC_REMOTE_PASS\n')
        self.assertTrue(all(row['complete'] and row['stdoutEof'] and row['stderrEof']
                            for row in old_capture + current_capture))

    def _zip_archive_pair(self, which, marker):
        old, old_capture = _run(which, 'before')
        self.assertEqual((old.testsRun, len(old.failures), len(old.errors), len(old.skipped)),
                         (1, 1, 0, 0), old.failures + old.errors)
        self.assertEqual(len(old_capture), 1)
        self.assertNotEqual(old_capture[0]['returnCode'], 0)
        self.assertIn(b'ZipArchive', old_capture[0]['stderr'])
        self.assertNotIn(marker, old_capture[0]['stdout'])
        current, current_capture = _run(which, 'current')
        self.assertEqual((current.testsRun, current.failures, current.errors, current.skipped),
                         (1, [], [], []))
        self.assertEqual(len(current_capture), 1)
        self.assertEqual(current_capture[0]['returnCode'], 0)
        self.assertIn(marker, current_capture[0]['stdout'])
        self.assertTrue(all(row['complete'] and row['stdoutEof'] and row['stderrEof']
                            for row in old_capture + current_capture))

    @unittest.skipUnless(_WINDOWS, 'actual Windows Add-Type and native output sharing required')
    def test_actual_old_copy_loop_missing_reference_red_full_original_scenario_green(self):
        self._zip_archive_pair('copy-old', b'OLD_STALE_ROW_REPRODUCED')

    @unittest.skipUnless(_WINDOWS, 'actual Windows Add-Type and native output sharing required')
    def test_actual_current_copy_loop_missing_reference_red_full_original_scenario_green(self):
        self._zip_archive_pair('copy-current', b'CURRENT_HELD_OUTPUTS_CLOSED')

    @unittest.skipUnless(_WINDOWS, 'actual Windows PowerShell 5 progress stream required')
    def test_explicit_native_progress_before_red_current_carrier_empty_stderr_green(self):
        old, old_capture = _run('progress', 'before')
        self.assertEqual((old.testsRun, len(old.failures), len(old.errors), len(old.skipped)),
                         (1, 1, 0, 0), old.failures + old.errors)
        self.assertEqual(len(old_capture), 1)
        self.assertEqual(old_capture[0]['returnCode'], 0)
        self.assertEqual(old_capture[0]['stdout'], b'PROGRESS_CARRIER_PASS\r\n')
        self.assertIn(b'#< CLIXML', old_capture[0]['stderr'])
        self.assertIn(b'CP117_PUBLIC_PROGRESS', old_capture[0]['stderr'])
        current, current_capture = _run('progress', 'current')
        self.assertEqual((current.testsRun, current.failures, current.errors, current.skipped),
                         (1, [], [], []))
        self.assertEqual(current_capture[0]['stderr'], b'')


def _save_evidence(directory, captures, pins, *, source_closing, successful):
    observations = []
    for index, captured in enumerate(captures):
        row = {key: value for key, value in captured.items() if key not in {'stdout', 'stderr'}}
        for stream in ('stdout', 'stderr'):
            raw = captured[stream]
            name = '%02d-%s.raw' % (index, stream)
            with (directory / name).open('xb') as output:
                output.write(raw)
            row[stream] = {'file': name, 'bytes': len(raw),
                           'sha256': hashlib.sha256(raw).hexdigest()}
        observations.append(row)
    terminal = {'schemaVersion': 1, 'sourceClosing': source_closing,
                'positiveAssertionPassed': successful, 'sources': pins,
                'children': observations, 'replayAllowed': False}
    with (directory / 'terminal.json').open('x', encoding='utf-8') as output:
        json.dump(terminal, output, sort_keys=True, indent=2)
        output.write('\n')


def _main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--causal', choices=('remote', 'copy-old', 'copy-current', 'progress', 'successor-template'))
    parser.add_argument('--variant', choices=('before', 'current'))
    parser.add_argument('--evidence-directory')
    args = parser.parse_args()
    if args.causal is None:
        if args.variant is not None or args.evidence_directory is not None:
            parser.error('variant/evidence-directory require a causal case')
        unittest.main(argv=[sys.argv[0]])
        return
    if args.variant is None:
        parser.error('causal case requires variant')
    if args.evidence_directory is None:
        parser.error('causal case requires a new owned evidence directory')
    directory = Path(args.evidence_directory).absolute()
    directory.mkdir(mode=0o700, exist_ok=False)
    with (directory / 'intent.json').open('x', encoding='utf-8') as intent:
        json.dump({'schemaVersion': 1, 'case': args.causal, 'variant': args.variant,
                   'replayAllowed': False}, intent, sort_keys=True)
        intent.write('\n')
        intent.flush()
        os.fsync(intent.fileno())
    captures, pins, source_closing, successful = [], {}, False, False
    try:
        with _case(args.causal, args.variant, captures, pins) as case:
            result = unittest.TextTestRunner(verbosity=2).run(case)
            successful = result.wasSuccessful() and not result.skipped
        source_closing = True
    finally:
        _save_evidence(directory, captures, pins,
                       source_closing=source_closing, successful=successful)
    raise SystemExit(0 if successful else 1)


# Block99 controls. This is source to append to the existing prerequisite
# module, not a standalone programme or a portable missing-fcntl simulation.
_SUCCESSOR_SOURCE_SHA256 = '26f46ec2a8c9c58299b6f263cb87397e622c2f8b31baacd395e6ceecac3df449'
_SUCCESSOR_CHILD = r'''import importlib.util,json,os,sys
if os.name!='nt':raise RuntimeError('successor-native-absence-requires-Windows')
# This runs before any repository import in a fresh isolated interpreter.
if 'fcntl' in sys.modules or importlib.util.find_spec('fcntl') is not None:
 raise RuntimeError('successor-native-fcntl-not-absent')
if len(sys.argv)!=3 or sys.argv[2] not in ('before','current'):
 raise ValueError('successor-child-input')
sys.path.insert(0,sys.argv[1])
from agent_tools.tests.test_windows_cp117_fixture_transport_prerequisites import _successor_constructor
value=_successor_constructor(sys.argv[2],{})
sys.stdout.buffer.write(b'SUCCESSOR_TEMPLATE_PASS '+json.dumps(value,sort_keys=True,separators=(',',':')).encode()+b'\n')
'''


def _successor_constructor(variant, pins):
    """Actual guarded constructors only; no PowerShell, guest or native action."""
    if variant not in {'before', 'current'}:
        raise ValueError('successor-constructor-variant')
    with _inputs(pins):
        from agent_tools.tests import test_windows_cp117_server_read_binding as source
        from agent_tools.tests.fixtures.windows_cp117_historical_factory import context
        from agent_tools.source_module_loader import _bootstrap_source
        with context.historical_factories(), context.inert_repository_source_reads():
            case = source.PublisherSuccessorStageTests()
            public = case.read_source().encode('utf-8', errors='strict')
            if (len(public) != 169632
                    or hashlib.sha256(public).hexdigest() != _SUCCESSOR_SOURCE_SHA256):
                raise ValueError('successor-original-sealed-source')
            with tempfile.TemporaryDirectory(prefix='cp117-successor-constructor-') as folder:
                path = Path(folder).resolve() / 'factory.py'
                with path.open('xb') as output:
                    output.write(public)
                path.chmod(0o600)
                with _bootstrap_source(path) as (held, guard):
                    if held != public:
                        raise ValueError('successor-owned-factory-source')
                    pins[str(path)] = {'sha256': _SUCCESSOR_SOURCE_SHA256,
                                       'generation': _generation(path.stat())}
                    try:
                        namespace = case.factory(path)
                        original = namespace['_fixture_original_successor_scripts']
                        selected = original if variant == 'before' else namespace['successor_scripts']
                        # On native Windows the exact original function fails
                        # importing fcntl here. The fixed function imports no
                        # coordinator; all actual producer bytes remain held.
                        actual = selected()
                        templates, acl = namespace['stage_templates']()
                        sid = namespace['installed'].precise.owner.SID
                        expected = (
                            templates['_create_script'](namespace['SUCCESSOR_CORRELATION'], sid),
                            acl.stage_acl_powershell(namespace['SUCCESSOR_ROOT'] + '\\content', sid),
                            acl.stage_acl_powershell(namespace['SUCCESSOR_ROOT'], sid),
                        )
                        if (type(actual) is not tuple or len(actual) != 3
                                or actual != expected or any(type(script) is not str
                                or not 0 < len(script.encode('utf-8')) <= 65536 for script in actual)):
                            raise AssertionError('successor-actual-constructor-bytes')
                        return {'sourceSha256': _SUCCESSOR_SOURCE_SHA256,
                                'scriptSha256': [hashlib.sha256(script.encode('utf-8')).hexdigest()
                                                 for script in actual],
                                'scriptBytes': [len(script.encode('utf-8')) for script in actual]}
                    finally:
                        guard()


def _successor_observation(raw, attributes_sha):
    """Two complete public records, never a prefix or a native-action receipt."""
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value: raise ValueError('successor-duplicate-key')
            value[key] = item
        return value
    if type(raw) is not bytes or not 0 < len(raw) <= 262144:
        raise ValueError('successor-output-bound')
    lines = raw.splitlines()
    prefixes = (b'CP117_STAGE_SOURCE_WITNESS ', b'SUCCESSOR_TEMPLATE_PASS ')
    if len(lines) != 2 or any(not line.startswith(prefix) for line, prefix in zip(lines, prefixes)):
        raise ValueError('successor-output-order')
    witness, value = [json.loads(line[len(prefix):], object_pairs_hook=unique)
                      for line, prefix in zip(lines, prefixes)]
    if (type(witness) is not dict or set(witness) != {'sources','attributesSha256','aclByteRulePresent','constructorAction'}
            or witness['attributesSha256'] != attributes_sha
            or witness['aclByteRulePresent'] is not True or witness['constructorAction'] is not False
            or type(witness['sources']) is not dict or set(witness['sources']) != {'stage','acl'}):
        raise ValueError('successor-source-witness')
    for label, digest, size in (
            ('stage','3e37a30445a3ea14057b010d205b92ac9907d278c0a57164fabeb63f49d07bed',55712),
            ('acl','30dcda8a0708a1d07465993485cb3ec8a995ae93e68b2d46e5327ca4b3dd953e',10358)):
        row = witness['sources'][label]
        if (type(row) is not dict or set(row) != {'expectedSha256','observedSha256','bytes'}
                or row['expectedSha256'] != digest or row['observedSha256'] != digest
                or type(row['bytes']) is not int or row['bytes'] != size):
            raise ValueError('successor-source-pin')
    if (type(value) is not dict or set(value) != {'sourceSha256','scriptSha256','scriptBytes'}
            or value['sourceSha256'] != _SUCCESSOR_SOURCE_SHA256
            or type(value['scriptSha256']) is not list or len(value['scriptSha256']) != 3
            or any(type(item) is not str or len(item) != 64 or any(c not in '0123456789abcdef' for c in item)
                   for item in value['scriptSha256'])
            or type(value['scriptBytes']) is not list or len(value['scriptBytes']) != 3
            or any(type(size) is not int or not 0 < size <= 65536 for size in value['scriptBytes'])):
        raise ValueError('successor-terminal-shape')
    return value


def _public_native_child_capture(variant, completed, kind='successor-constructor'):
    """Retain complete public streams after the owned child returned."""
    import uuid
    if (variant not in ('before','current') or kind not in ('successor-constructor','shortcut-task-consumer','owned-failure-control')
            or type(completed.returncode) is not int or type(completed.stdout) is not bytes
            or type(completed.stderr) is not bytes or len(completed.stdout)+len(completed.stderr)>262144):
        raise ValueError('successor-capture-input')
    value = {'variant':variant,'kind':kind,'returnCode':completed.returncode,
             'stdoutBase64':base64.b64encode(completed.stdout).decode('ascii'),
             'stderrBase64':base64.b64encode(completed.stderr).decode('ascii')}
    for channel in ('stdout','stderr'):
        raw = getattr(completed,channel)
        value[channel+'Bytes'] = len(raw); value[channel+'Sha256'] = hashlib.sha256(raw).hexdigest()
    raw = json.dumps(value,sort_keys=True,separators=(',',':')).encode('ascii')
    if not 0<len(raw)<=524288: raise ValueError('successor-capture-bound')
    capture = uuid.uuid4().hex; chunks = [raw[start:start+8192] for start in range(0,len(raw),8192)]
    for index, part in enumerate(chunks):
        line = 'CP117_PUBLIC_NATIVE_CHILD_CAPTURE_CHUNK '+json.dumps({'captureId':capture,'index':index,'count':len(chunks),
            'dataBytes':len(part),'sha256':hashlib.sha256(part).hexdigest(),
            'dataBase64':base64.b64encode(part).decode('ascii')},sort_keys=True)
        if len(line.encode('ascii'))>16384:raise ValueError('successor-capture-line-bound')
        print(line,flush=True)
    print('CP117_PUBLIC_NATIVE_CHILD_CAPTURE_MANIFEST '+json.dumps({'captureId':capture,'variant':variant,'kind':kind,
        'chunks':len(chunks),'payloadBytes':len(raw),'payloadSha256':hashlib.sha256(raw).hexdigest(),
        'childReturned':True,'stdoutEof':True,'stderrEof':True},sort_keys=True),flush=True)


def _retained_public_native_child_capture(text, variant, kind):
    def need(value):
        if not value: raise ValueError('successor-retained-capture')
    def unique(pairs):
        answer={}
        for key,value in pairs:
            need(key not in answer);answer[key]=value
        return answer
    lines=text.splitlines();need(2<=len(lines)<=65);parts=[];capture=None;count=None
    for index,line in enumerate(lines[:-1]):
        prefix='CP117_PUBLIC_NATIVE_CHILD_CAPTURE_CHUNK ';need(line.startswith(prefix)and len(line.encode('ascii'))<=16384)
        row=json.loads(line[len(prefix):],object_pairs_hook=unique)
        need(type(row)is dict and set(row)=={'captureId','index','count','dataBytes','sha256','dataBase64'})
        need(type(row['captureId'])is str and len(row['captureId'])==32 and all(c in '0123456789abcdef' for c in row['captureId']))
        if capture is None:capture=row['captureId'];count=row['count']
        need(row['captureId']==capture and type(row['index'])is int and row['index']==index
             and type(row['count'])is int and row['count']==count and 1<=count<=64)
        part=base64.b64decode(row['dataBase64'],validate=True)
        need(type(row['dataBytes'])is int and row['dataBytes']==len(part)and 0<len(part)<=8192
             and hashlib.sha256(part).hexdigest()==row['sha256']);parts.append(part)
    prefix='CP117_PUBLIC_NATIVE_CHILD_CAPTURE_MANIFEST ';need(lines[-1].startswith(prefix)and len(lines[-1].encode('ascii'))<=16384)
    final=json.loads(lines[-1][len(prefix):],object_pairs_hook=unique);raw=b''.join(parts)
    need(type(final)is dict and set(final)=={'captureId','variant','kind','chunks','payloadBytes','payloadSha256','childReturned','stdoutEof','stderrEof'})
    need(final['captureId']==capture and final['variant']==variant and final['kind']==kind
         and type(final['chunks'])is int and final['chunks']==count==len(parts)
         and type(final['payloadBytes'])is int and final['payloadBytes']==len(raw)<=524288
         and hashlib.sha256(raw).hexdigest()==final['payloadSha256']
         and all(final[key]is True for key in ('childReturned','stdoutEof','stderrEof')))
    value=json.loads(raw,object_pairs_hook=unique)
    need(type(value)is dict and set(value)=={'variant','kind','returnCode','stdoutBase64','stderrBase64','stdoutBytes','stderrBytes','stdoutSha256','stderrSha256'})
    need(value['variant']==variant and value['kind']==kind and type(value['returnCode'])is int)
    for channel in ('stdout','stderr'):
        data=base64.b64decode(value[channel+'Base64'],validate=True)
        need(type(value[channel+'Bytes'])is int and value[channel+'Bytes']==len(data)
             and hashlib.sha256(data).hexdigest()==value[channel+'Sha256']);value[channel]=data
    need(len(value['stdout'])+len(value['stderr'])<=262144)
    return value


def _successor_positive(variant, captures, pins):
    class Positive(unittest.TestCase):
        def runTest(self):
            if not _WINDOWS:
                self.skipTest('genuine missing fcntl requires a fresh native Windows interpreter')
            from agent_tools.source_module_loader import _bootstrap_source
            with _inputs(pins) as (_, current_inputs):
                attributes_sha = hashlib.sha256(current_inputs['attributes']).hexdigest()
                with tempfile.TemporaryDirectory(prefix='cp117-successor-native-') as folder:
                    root = Path(folder).resolve()
                    child = root / 'constructor.py'
                    cache = root / 'fresh-pycache'
                    cache.mkdir(mode=0o700)
                    raw = _SUCCESSOR_CHILD.encode('utf-8')
                    with child.open('xb') as output:
                        output.write(raw)
                    with _bootstrap_source(child) as (held, guard):
                        if held != raw:
                            raise ValueError('successor-owned-child-source')
                        pins[str(child)] = {'sha256': hashlib.sha256(raw).hexdigest(),
                                            'generation': _generation(child.stat())}
                        try:
                            argv = [sys.executable, '-I', '-B', '-X', 'pycache_prefix=' + str(cache),
                                    str(child), str(_TESTS.parents[1]), variant]
                            completed = _recorder(captures, windows_projection=False)(
                                argv, cwd=_TESTS.parents[1], capture_output=True, timeout=40)
                        finally:
                            guard()
            # The exact same positive assertions execute for old/current.
            _public_native_child_capture(variant, completed)
            self.assertEqual(completed.returncode, 0, completed.stderr.decode(errors='replace'))
            self.assertLessEqual(len(completed.stdout) + len(completed.stderr), 262144)
            value = _successor_observation(completed.stdout, attributes_sha)
            self.assertEqual(set(value), {'sourceSha256', 'scriptSha256', 'scriptBytes'})
            self.assertEqual(value['sourceSha256'], _SUCCESSOR_SOURCE_SHA256)
            self.assertEqual(len(value['scriptSha256']), 3)
            self.assertTrue(all(type(size) is int and 0 < size <= 65536
                                for size in value['scriptBytes']))
    return Positive()


class SuccessorConstructorPrerequisiteTests(unittest.TestCase):
    def _constructor_protocol(self):
        import io
        from contextlib import redirect_stdout
        from agent_tools.source_module_loader import _bootstrap_source
        path=Path(__file__).resolve()
        with _inputs({}), _bootstrap_source(path) as (source,guard), _bootstrap_source(_TESTS.parents[1]/'.gitattributes') as (attributes,attributes_guard):
            attributes_sha = hashlib.sha256(attributes).hexdigest()
            witness = io.StringIO()
            with redirect_stdout(witness): value = _successor_constructor('current', {})
            # Execute only the actual child's final public serializer. Its
            # native capability checks and constructor remain separate cases.
            constants=[node for node in ast.parse(source).body if isinstance(node,ast.Assign)
                       and any(isinstance(target,ast.Name)and target.id=='_SUCCESSOR_CHILD'for target in node.targets)]
            self.assertEqual(len(constants),1);self.assertEqual(ast.literal_eval(constants[0].value),_SUCCESSOR_CHILD)
            terminal = ast.parse(_SUCCESSOR_CHILD,filename=str(path)).body[-1]
            self.assertIsInstance(terminal, ast.Expr)
            output = io.BytesIO()
            namespace = dict(globals(), value=value, sys=types.SimpleNamespace(stdout=types.SimpleNamespace(buffer=output)))
            exec(compile(ast.Module(body=[terminal], type_ignores=[]), str(path), 'exec'), namespace)
            guard();attributes_guard()
            return witness.getvalue().encode('utf-8') + output.getvalue(), attributes_sha

    def _actual_successor_assertions(self, completed, attributes_sha):
        from agent_tools.source_module_loader import _bootstrap_source
        path = Path(__file__).resolve()
        with _bootstrap_source(path) as (raw, guard):
            tree = ast.parse(raw, filename=str(path))
            function = _unique(tree, ast.FunctionDef, '_successor_positive')
            cls = _unique(function, ast.ClassDef, 'Positive')
            method = _unique(cls, ast.FunctionDef, 'runTest')
            starts = [index for index,node in enumerate(method.body) if isinstance(node,ast.Expr)
                      and isinstance(node.value,ast.Call) and isinstance(node.value.func,ast.Attribute)
                      and node.value.func.attr=='assertEqual' and node.value.args
                      and ast.dump(node.value.args[0])==ast.dump(ast.parse('completed.returncode',mode='eval').body)]
            self.assertEqual(len(starts),1)
            namespace = dict(globals(), self=self, completed=completed, attributes_sha=attributes_sha)
            exec(compile(ast.Module(body=method.body[starts[0]:],type_ignores=[]),str(path),'exec'),namespace)
            guard()

    def _actual_successor_outer_assertion(self, current):
        from agent_tools.source_module_loader import _bootstrap_source
        path = Path(__file__).resolve()
        with _bootstrap_source(path) as (raw, guard):
            tree = ast.parse(raw, filename=str(path))
            cls = _unique(tree, ast.ClassDef, 'SuccessorConstructorPrerequisiteTests')
            method = _unique(cls, ast.FunctionDef, 'test_actual_original_coordinator_import_red_pure_constructor_green')
            calls = [node for node in ast.walk(method) if isinstance(node,ast.Call)
                     and isinstance(node.func,ast.Attribute) and node.func.attr=='assertEqual'
                     and node.args and isinstance(node.args[0],ast.Tuple)
                     and ast.dump(node.args[0].elts[0])==ast.dump(ast.parse('current.testsRun',mode='eval').body)]
            self.assertEqual(len(calls),1)
            node=ast.copy_location(ast.Expr(value=calls[0]),calls[0])
            exec(compile(ast.Module(body=[node],type_ignores=[]),str(path),'exec'),dict(globals(),self=self,current=current))
            guard()

    def test_actual_successor_stdout_observer_accepts_its_complete_source_witness(self):
        raw, attributes_sha = self._constructor_protocol()
        completed = subprocess.CompletedProcess(['public-constructor-protocol'],0,raw,b'')
        self._actual_successor_assertions(completed,attributes_sha)

    def test_successor_observer_refuses_partial_foreign_duplicate_and_wrong_type_records(self):
        raw, attributes_sha = self._constructor_protocol()
        witness, terminal = raw.splitlines()
        self.assertEqual(_successor_observation(raw,attributes_sha)['sourceSha256'],_SUCCESSOR_SOURCE_SHA256)
        value=json.loads(witness[len(b'CP117_STAGE_SOURCE_WITNESS '):])
        bad=[]
        for changed in (dict(value,unknown=True),dict(value,constructorAction=True),dict(value,attributesSha256='0'*64)):
            bad.append(b'CP117_STAGE_SOURCE_WITNESS '+json.dumps(changed).encode()+b'\n'+terminal+b'\n')
        changed=json.loads(json.dumps(value));changed['sources']['stage']['bytes']=True
        bad.append(b'CP117_STAGE_SOURCE_WITNESS '+json.dumps(changed).encode()+b'\n'+terminal+b'\n')
        changed=json.loads(json.dumps(value));changed['sources']['acl']['observedSha256']='0'*64
        bad.append(b'CP117_STAGE_SOURCE_WITNESS '+json.dumps(changed).encode()+b'\n'+terminal+b'\n')
        duplicate=witness[:-1]+b',"constructorAction":false}'
        bad.extend((terminal+b'\n',witness+b'\n',terminal+b'\n'+witness+b'\n',raw+raw,duplicate+b'\n'+terminal+b'\n'))
        for number,body in enumerate(bad):
            with self.subTest(refusal=number),self.assertRaises(ValueError):_successor_observation(body,attributes_sha)

    def test_actual_successor_outer_assertion_retains_complete_owned_child_diagnostics(self):
        import io
        from contextlib import redirect_stdout
        from agent_tools.source_module_loader import _bootstrap_source
        public=b"import sys\nsys.stdout.buffer.write(b'O'*6000+b'PUBLIC_SUCCESSOR_STDOUT_RETAINED\\n')\nsys.stderr.buffer.write(b'E'*6000+b'PUBLIC_SUCCESSOR_STDERR_RETAINED\\n')\nraise SystemExit(7)\n"
        with tempfile.TemporaryDirectory(prefix='successor-owned-diagnostic-') as folder:
            programme=Path(folder).resolve()/'public-failure.py';programme.write_bytes(public)
            with _bootstrap_source(programme) as (raw,guard):
                self.assertEqual(public,raw)
                completed=subprocess.run([sys.executable,'-I','-B',str(programme)],capture_output=True,timeout=20)
                guard()
        self.assertEqual(completed.returncode,7)
        retained=io.StringIO()
        with redirect_stdout(retained):_public_native_child_capture('current',completed,'owned-failure-control')
        text=retained.getvalue();sys.stdout.write(text);sys.stdout.flush()
        saved=_retained_public_native_child_capture(text,'current','owned-failure-control')
        self.assertEqual((saved['stdout'],saved['stderr']),(completed.stdout,completed.stderr))
        owner=self
        class Inner(unittest.TestCase):
            def runTest(self):self.assertEqual(completed.returncode,0,repr((completed.stdout,completed.stderr)))
        inner=unittest.TestResult();Inner().run(inner)
        class Outer(unittest.TestCase):
            def runTest(self):owner._actual_successor_outer_assertion(inner)
        outer=unittest.TestResult();Outer().run(outer)
        self.assertEqual((outer.testsRun,len(outer.failures),len(outer.errors)),(1,1,0))
        for marker in ('PUBLIC_SUCCESSOR_STDOUT_RETAINED','PUBLIC_SUCCESSOR_STDERR_RETAINED'):
            self.assertIn(marker,outer.failures[0][1],'successor-complete-owned-child-diagnostics')
        lines=text.splitlines()
        for changed in ('\n'.join(lines[1:]),'\n'.join(lines[:-1]),text+text,'\n'.join(reversed(lines))):
            with self.assertRaises(ValueError):_retained_public_native_child_capture(changed,'current','owned-failure-control')

    def test_actual_guarded_pure_constructor_keeps_archived_creation_and_acl_bytes(self):
        value = _successor_constructor('current', {})
        self.assertEqual(value['sourceSha256'], _SUCCESSOR_SOURCE_SHA256)
        self.assertEqual(len(value['scriptSha256']), 3)

    @unittest.skipUnless(_WINDOWS, 'genuine native Windows fcntl absence required')
    def test_actual_original_coordinator_import_red_pure_constructor_green(self):
        old, old_capture = _run('successor-template', 'before')
        self.assertEqual((old.testsRun, len(old.failures), len(old.errors), len(old.skipped)),
                         (1, 1, 0, 0), old.failures + old.errors)
        self.assertEqual(len(old_capture), 1)
        self.assertNotEqual(old_capture[0]['returnCode'], 0)
        self.assertIn(b"ModuleNotFoundError: No module named 'fcntl'", old_capture[0]['stderr'])
        self.assertNotIn(b'SUCCESSOR_TEMPLATE_PASS ', old_capture[0]['stdout'])
        current, current_capture = _run('successor-template', 'current')
        self.assertEqual((current.testsRun, current.failures, current.errors, current.skipped),
                         (1, [], [], []), '\n'.join(text for _,text in current.errors or current.failures))
        self.assertEqual(len(current_capture), 1)
        self.assertTrue(all(row['complete'] and row['stdoutEof'] and row['stderrEof']
                            for row in old_capture + current_capture))

if __name__ == '__main__':
    _main()
