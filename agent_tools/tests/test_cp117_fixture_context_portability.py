"""Causal inert CP117 fixture controls; no native Windows or VM admission.

Only a private import function and private remote-path namespace are supplied.
The actual source-reader context and frozen recipe code execute unchanged.
"""
import ast
import builtins
from contextlib import contextmanager, nullcontext
import hashlib
import inspect
import json
import ntpath
import os
from pathlib import Path
import posixpath
import sys
import types
from typing import Any
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = Path(__file__).parent / 'fixtures/cp117_fixture_context_portability'
CONTEXT = ROOT / 'agent_tools/tests/fixtures/windows_cp117_historical_factory/context.py'
RECOVERY = ROOT / 'agent_tools/tests/fixtures/windows_cp117_recovery/short_socket_51538dad.source'
CAMPAIGN = ROOT / 'agent_tools/windows_cp117_source_campaign.py'
SOURCE_NAMES = ('windows_fixture_credentials.py', 'windows_update_fixture_server.py')


def provenance():
    return json.loads((FIXTURE / 'provenance.json').read_bytes())


def preserved(name):
    raw = (FIXTURE / name).read_bytes()
    expected = provenance()['resources'][name]
    if len(raw) != expected['bytes'] or hashlib.sha256(raw).hexdigest() != expected['sha256']:
        raise ValueError('cp117_portability_beforeimage_changed')
    return raw.decode('utf-8')


def standard_identities():
    return (builtins.__import__, os.name, os.path, os.fsencode, sys.platform,
            ntpath.normpath, posixpath.normpath)


def context_functions(source, importer=None):
    """Execute only the actual context definitions in their own namespace."""
    names = {'inert_repository_source_reads', 'remote_posix_recipe_context'}
    nodes = [node for node in ast.parse(source).body
             if isinstance(node, ast.FunctionDef) and node.name in names]
    namespace = {'__file__': str(CONTEXT), 'Path': Path, 'os': os,
                 'hashlib': hashlib, 'patch': patch, 'posixpath': posixpath,
                 'contextmanager': contextmanager}
    if importer is not None:
        namespace['__builtins__'] = {**vars(builtins), '__import__': importer}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(CONTEXT), 'exec',
                 dont_inherit=True), namespace)
    return namespace


def source_context_observation(source):
    # The binding implementation is real; refuse only the two needless source
    # imports in this extracted function's private builtins, never globally.
    from agent_tools import windows_cp117_bound_absence_completion as binding
    forbidden = []
    original_import = builtins.__import__
    def importing(name, globals=None, locals=None, fromlist=(), level=0):
        endpoints = {'windows_fixture_credentials', 'windows_update_fixture_server'}
        if name == 'agent_tools' and level == 0 and endpoints.intersection(fromlist):
            forbidden.append((name, tuple(fromlist)))
            raise ImportError('coordinator_source_import_forbidden')
        return original_import(name, globals, locals, fromlist, level)
    namespace = context_functions(source, importing)
    before = standard_identities()
    reader = binding._read_bound_file
    contents = {}
    error = None
    try:
        with namespace['inert_repository_source_reads']():
            historical = Path('/Users/karapsin_de/Nextcloud/projects/vpn_control/agent_tools')
            for name in SOURCE_NAMES:
                pin, raw = binding._read_bound_file(historical / name, retain_bytes=True)
                expected = (ROOT / 'agent_tools' / name).read_bytes()
                if raw != expected or pin['sha256'] != hashlib.sha256(expected).hexdigest():
                    raise AssertionError('fixed source label lost its actual bytes or digest')
                contents[name] = pin['sha256']
    except Exception as observed:
        error = observed
    finally:
        if binding._read_bound_file is not reader or standard_identities() != before:
            raise AssertionError('source context did not restore reader or stdlib identities')
    return error, forbidden, contents


def assert_source_context(case, source):
    error, forbidden, contents = source_context_observation(source)
    case.assertIsNone(error, repr(error))
    case.assertEqual([], forbidden)
    case.assertEqual(set(SOURCE_NAMES), set(contents))


def frozen_recovery():
    """Retain the exact pure recipe definitions and literal frozen inputs.

    No imports or operational entry points from the historical file execute.
    This proves remote recipe grammar, not native inventory or file custody.
    """
    raw = RECOVERY.read_bytes()
    if hashlib.sha256(raw).hexdigest() != provenance()['recoverySourceSha256']:
        raise ValueError('cp117_portability_recovery_source_changed')
    constants = {'ROOT', 'DISK', 'BACKING', 'VARS', 'TPM_STATE', 'CODE', 'QEMU',
                 'SWTPM', 'BOOT_ID', 'SSH_PORT', 'VNC_PORT', 'MEMORY_BYTES',
                 'HEADROOM_BYTES', 'CORRELATION', 'BASELINE'}
    definitions = {'_need', '_validate_socket_leaf', 'recipe'}
    nodes = []
    for node in ast.parse(raw).body:
        if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name)
                and target.id in constants for target in node.targets):
            nodes.append(node)
        elif isinstance(node, ast.ClassDef) and node.name == 'RecoveryUnknown':
            nodes.append(node)
        elif isinstance(node, ast.FunctionDef) and node.name in definitions:
            nodes.append(node)
    module = types.ModuleType('private_frozen_cp117_recipe')
    module.__file__ = str(RECOVERY)
    module.__dict__.update(os=os, Any=Any)
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(RECOVERY), 'exec',
                 dont_inherit=True), module.__dict__)
    return module


def remote_recipe_observation(source):
    recovery = frozen_recovery()
    original = recovery.os
    class HostGrammarView:
        path = ntpath
        def __getattr__(self, name):
            return getattr(original, name)
    before = standard_identities()
    methods = (recovery.recipe, recovery._validate_socket_leaf, recovery._need)
    error = None
    recipe = None
    namespace = context_functions(source)
    host_view = HostGrammarView()
    with patch.object(recovery, 'os', host_view):
        # The old context has no remote grammar adapter; its callers executed
        # the unchanged recipe directly. The fixed context supplies POSIX paths.
        manager = (namespace['remote_posix_recipe_context'](recovery)
                   if 'remote_posix_recipe_context' in namespace else nullcontext())
        try:
            with manager:
                recipe = recovery.recipe()
        except Exception as observed:
            error = observed
        if recovery.os is not host_view:
            raise AssertionError('remote context did not restore its caller namespace')
    if (recovery.os is not original or standard_identities() != before
            or methods != (recovery.recipe, recovery._validate_socket_leaf, recovery._need)):
        raise AssertionError('remote context changed original functions or stdlib identities')
    return error, recipe


def assert_remote_recipe(case, source):
    error, recipe = remote_recipe_observation(source)
    case.assertIsNone(error, repr(error))
    encoded = json.dumps(recipe, sort_keys=True, separators=(',', ':')).encode()
    case.assertEqual(provenance()['expectedRecipeSha256'], hashlib.sha256(encoded).hexdigest())


def campaign_observation(legacy=False):
    from agent_tools.tests import test_windows_cp117_source_campaign as fixture
    expected = provenance()
    if hashlib.sha256(CAMPAIGN.read_bytes()).hexdigest() != expected['sourceCampaignSourceSha256']:
        raise ValueError('cp117_campaign_source_changed')
    retirement = ROOT / 'agent_tools/windows_cp117_staged_fixture_retire.py'
    if hashlib.sha256(retirement.read_bytes()).hexdigest() != expected['retirementLiteralSourceSha256']:
        raise ValueError('cp117_retirement_literal_source_changed')
    forbidden = []
    original_import = builtins.__import__
    def importing(name, globals=None, locals=None, fromlist=(), level=0):
        endpoints = {'windows_cp117_staged_fixture_retire', 'windows_update_fixture_stage'}
        if (name == '' and level == 1 and globals is not None
                and globals.get('__package__') == 'agent_tools'
                and endpoints.intersection(fromlist)):
            forbidden.append((name, tuple(fromlist), level))
            raise ImportError('campaign_coordinator_import_forbidden')
        return original_import(name, globals, locals, fromlist, level)
    private_builtins = {**vars(builtins), '__import__': importing}
    before = standard_identities()
    error = None
    emitter = None
    try:
        if legacy:
            source = preserved('source-campaign.before.source')
            namespace = {'__name__': 'agent_tools._inert_campaign_before',
                         '__package__': 'agent_tools', '__file__': str(CAMPAIGN),
                         '__builtins__': private_builtins}
            exec(compile(source, str(CAMPAIGN), 'exec', dont_inherit=True), namespace)
            emitter = types.SimpleNamespace(**namespace)
        else:
            # Execute the actual current fixture helper, with identical code and
            # globals except this private import capability recorder. The helper
            # retains its held source guards and omits only its reviewed peers.
            original = fixture._source_only_campaign
            globals_view = {**original.__globals__, '__builtins__': private_builtins}
            helper = types.FunctionType(original.__code__, globals_view,
                                        original.__name__, original.__defaults__, original.__closure__)
            emitter = helper()
    except Exception as observed:
        error = observed
    finally:
        if standard_identities() != before:
            raise AssertionError('campaign fixture changed stdlib identities')
    return error, forbidden, emitter


def assert_campaign_emitter(case, legacy=False):
    error, forbidden, emitter = campaign_observation(legacy)
    case.assertIsNone(error, repr(error))
    case.assertEqual([], forbidden)
    actual_source = CAMPAIGN.read_text(encoding='utf-8')
    node = next(node for node in ast.parse(actual_source).body
                if isinstance(node, ast.FunctionDef) and node.name == '_replacement_task')
    expected_function = ast.get_source_segment(actual_source, node)
    case.assertEqual(ast.dump(ast.parse(expected_function)),
                     ast.dump(ast.parse(inspect.getsource(emitter._replacement_task))))
    case.assertEqual(str(CAMPAIGN), emitter._replacement_task.__code__.co_filename)
    pair = {'baseArtifactId': emitter._BASE, 'baseVersion': '2.1.19',
            'baseCliSha256': 'a' * 64, 'baseAppJarSha256': 'b' * 64,
            'baseHelperSha256': 'c' * 64, 'baseAppJarName': 'desktopApp-2.1.19.jar'}
    task = emitter._replacement_task('f18df6cb-2c43-4265-b1ba-4bbadf9b708a', pair,
                                     'S-1-5-21-1-2-3-1002')
    case.assertIn("/x '+$oldCode", task)
    case.assertIn('$none.Count -ne 0', task)
    case.assertIn("PSDrive.Name -cne 'HKCU'", task)
    case.assertIn("throw 'WORKSPACE'", task)
    case.assertIn(emitter._BASE.removeprefix('sha256-'), task)
    # Only literal data from the real retirement source is supplied; operational
    # coordinator entry points do not become fixture capabilities.
    case.assertEqual('.rag_index/windows-cp117-staged-fixture-retire', emitter.retirement._DIR)
    case.assertFalse(hasattr(emitter.retirement, 'start'))
    case.assertFalse(hasattr(emitter, 'stage'))


def assert_counterfactual(case, assertion, expected_failure):
    result = unittest.TestResult()
    unittest.FunctionTestCase(assertion).run(result)
    case.assertEqual(1, len(result.failures))
    case.assertEqual([], result.errors)
    case.assertEqual([], result.skipped)
    case.assertIn(expected_failure, result.failures[0][1])


class FixtureContextPortabilityTests(unittest.TestCase):
    def test_source_labels_read_actual_bytes_without_importing_coordinator_modules(self):
        assert_source_context(self, CONTEXT.read_text(encoding='utf-8'))

    def test_preserved_source_context_has_same_assertion_red(self):
        assert_counterfactual(self, lambda: assert_source_context(
            self, preserved('context.before.source')), 'coordinator_source_import_forbidden')

    def test_actual_frozen_linux_recipe_uses_remote_posix_grammar(self):
        assert_remote_recipe(self, CONTEXT.read_text(encoding='utf-8'))

    def test_preserved_context_has_same_remote_recipe_assertion_red(self):
        assert_counterfactual(self, lambda: assert_remote_recipe(
            self, preserved('context.before.source')), 'unix-socket-path')

    def test_remote_grammar_context_restores_after_failure_and_preserves_socket_guards(self):
        recovery = frozen_recovery()
        before = standard_identities()
        original = recovery.os
        manager = context_functions(CONTEXT.read_text(encoding='utf-8'))['remote_posix_recipe_context']
        with self.assertRaisesRegex(RuntimeError, 'owned-context-failure'):
            with manager(recovery):
                self.assertIs(recovery.os.path, posixpath)
                self.assertIs(recovery.os.open, original.open)
                self.assertIs(recovery.os.fsencode, original.fsencode)
                for leaf in ('relative', '/a/../b', '/a\0b', '/' + 'a' * 107):
                    with self.subTest(leaf=leaf), self.assertRaisesRegex(
                            recovery.RecoveryUnknown, 'unix-socket-path'):
                        recovery._validate_socket_leaf(leaf)
                raise RuntimeError('owned-context-failure')
        self.assertIs(recovery.os, original)
        self.assertEqual(before, standard_identities())

    def test_private_and_other_source_paths_keep_original_reader_authority(self):
        from agent_tools import windows_cp117_bound_absence_completion as binding
        calls = []
        def original(path, private=False, retain_bytes=False):
            calls.append((path, private, retain_bytes))
            raise ValueError('original-reader-refusal')
        namespace = context_functions(CONTEXT.read_text(encoding='utf-8'))
        historical = Path('/Users/karapsin_de/Nextcloud/projects/vpn_control/agent_tools')
        with patch.object(binding, '_read_bound_file', side_effect=original):
            with namespace['inert_repository_source_reads']():
                for path, private in ((historical / SOURCE_NAMES[0], True),
                                      (historical / 'other.py', False)):
                    with self.assertRaisesRegex(ValueError, 'original-reader-refusal'):
                        binding._read_bound_file(path, private=private, retain_bytes=True)
        self.assertEqual([(historical / SOURCE_NAMES[0], True, True),
                          (historical / 'other.py', False, True)], calls)

    def test_current_pure_geometry_and_windowless_answers_have_real_imports(self):
        from agent_tools.tests import test_windows_cp117_secure_input_geometry_observe as geometry
        from agent_tools.tests import test_windows_cp117_windowless_edit_observe as windowless
        before = standard_identities()
        for fixture in (geometry, windowless):
            with self.subTest(fixture=fixture.__name__):
                answer = fixture.CensusTests().answer()
                self.assertFalse(answer['facts']['secureInput']['keyboardAdmission'])
                self.assertEqual(answer['facts']['secureInput'], fixture.m.validate_semantic(answer))
                with self.assertRaises(ValueError):
                    fixture.original.validate_semantic(answer)
                self.assertIs(fixture.CensusTests.answer.__globals__['layout'], fixture.layout)
                self.assertIs(fixture.CensusTests.answer.__globals__['m'], fixture.m)
        self.assertEqual(before, standard_identities())

    def test_source_only_campaign_emits_actual_task_without_coordinator_imports(self):
        assert_campaign_emitter(self)

    def test_preserved_full_campaign_import_has_same_assertion_red(self):
        assert_counterfactual(self, lambda: assert_campaign_emitter(self, legacy=True),
                              'campaign_coordinator_import_forbidden')

    def test_exact_old_conditional_import_fragments_remain_preserved(self):
        # These are provenance, not simulated native Windows execution. Direct
        # current pure helper calls above catch missing globals on every host.
        for name in ('geometry-imports.before.fragment', 'windowless-imports.before.fragment'):
            source = preserved(name)
            nodes = ast.parse(source).body
            self.assertEqual(1, len(nodes))
            self.assertIsInstance(nodes[0], ast.If)
            self.assertEqual(3, len(nodes[0].body))
            self.assertTrue(all(isinstance(node, ast.ImportFrom) for node in nodes[0].body))


if __name__ == '__main__':
    if '--legacy-red' in sys.argv:
        suite = unittest.TestSuite([
            unittest.FunctionTestCase(lambda: assert_source_context(
                unittest.TestCase(), preserved('context.before.source'))),
            unittest.FunctionTestCase(lambda: assert_remote_recipe(
                unittest.TestCase(), preserved('context.before.source'))),
            unittest.FunctionTestCase(lambda: assert_campaign_emitter(unittest.TestCase(), legacy=True)),
        ])
        outcome = unittest.TextTestRunner(verbosity=2).run(suite)
        raise SystemExit(not outcome.wasSuccessful())
    unittest.main()
