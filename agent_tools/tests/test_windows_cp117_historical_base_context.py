"""Inert historical package factories keep their complete original base source."""
from contextlib import contextmanager, nullcontext
import errno
import hashlib
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

from agent_tools import windows_msi_base_prepare as current_base
from agent_tools import windows_cp117_installed_base_observe as current_installed
from agent_tools.tests.fixtures import historical_source
from agent_tools.tests.fixtures.windows_cp117_historical_factory import context


FIXTURE = Path(__file__).with_name('fixtures') / 'windows_cp117_historical_factory'
BASE_SHA = '5d06ef745bbaba0208f08907a9b1c8ed7a3c8c549a940ecf5a4f127744d47cb7'
BEFORE_SHA = 'e75ff49fdc5b8ec73c5e0738a4e44aa41062bbad5128317ad329724218e7c216'
COMMIT = 'c68058eb64f8452207bf2091bd2950e5a06231da'


def retained_sources():
    provenance = json.loads((FIXTURE / 'base_provenance.json').read_bytes())
    raw = (FIXTURE / 'base_5d06ef74.source').read_bytes()
    before = (FIXTURE / 'context.before.source').read_bytes()
    if (len(raw) != 200141 or hashlib.sha256(raw).hexdigest() != BASE_SHA
            or len(before) != 5226 or hashlib.sha256(before).hexdigest() != BEFORE_SHA
            or provenance['base']['sourcePath'] != 'agent_tools/windows_msi_base_prepare.py'
            or provenance['base']['sourceCommit'] != COMMIT
            or provenance['base']['sha256'] != BASE_SHA or provenance['base']['bytes'] != len(raw)
            or provenance['contextBefore']['sha256'] != BEFORE_SHA
            or provenance['contextBefore']['bytes'] != len(before)
            or provenance['historicalPinsChanged'] is not False
            or provenance['nativeEvidence'] is not False):
        raise AssertionError('Complete historical base provenance changed')
    return raw


def before_context():
    retained_sources()
    return historical_source.load(FIXTURE / 'context.before.source', BEFORE_SHA)


def assert_installed_body(case, family):
    """The original package body admission is the same before and after repair."""
    with family.historical_factories():
        installed = family.installed()
        body = installed.body(installed.PAIR_EXPECTED)
        base = installed.precise.owner.guest.recovery.authority.closure.base
        case.assertEqual(BASE_SHA, hashlib.sha256(Path(base.__file__).read_bytes()).hexdigest())
        readiness = base._readiness_script('2.1.19', installed.precise.owner.SID)
        case.assertEqual(installed.READINESS_SHA256,
                         hashlib.sha256(readiness.encode('utf-16le')).hexdigest())
        case.assertIn("$script:cp117OwnerDiagStage='package'", body)
        case.assertEqual(BASE_SHA, installed.BASE_SHA)
        return body


def assert_current_package_body(case, family):
    with family.historical_current_package() as installed:
        case.assertIs(current_installed, installed)
        body = installed.body_current(installed.PAIR_EXPECTED)
        base = installed.precise.owner.guest.recovery.authority.closure.base
        case.assertEqual(BASE_SHA, hashlib.sha256(Path(base.__file__).read_bytes()).hexdigest())
        case.assertEqual(str(context.BASE_SOURCE.absolute()), base.__file__)
        case.assertIn("$script:cp117OwnerDiagStage='package'", body)
        return body


@contextmanager
def current_base_prerequisite(case, closure):
    """Supply the real mismatched producer for an inert source-refusal case."""
    path = Path(current_base.__file__).resolve()
    case.assertEqual(Path(__file__).resolve().parents[1] / 'windows_msi_base_prepare.py', path)
    raw = path.read_bytes()
    case.assertNotEqual(BASE_SHA, hashlib.sha256(raw).hexdigest())
    original_reference = closure.base
    try:
        with patch.object(closure, 'base', current_base):
            yield
    finally:
        case.assertIs(original_reference, closure.base)
        case.assertEqual(raw, path.read_bytes())


@contextmanager
def observed_source_descriptors(path):
    """Observe real opens in this loader namespace; stdlib OS calls stay intact."""
    from agent_tools import source_module_loader
    expected = path.stat()
    descriptors = []
    original_open = os.open
    def opened(*args, **kwargs):
        fd = original_open(*args, **kwargs)
        info = os.fstat(fd)
        if (info.st_dev, info.st_ino) == (expected.st_dev, expected.st_ino):
            descriptors.append(fd)
        return fd
    view = types.SimpleNamespace(**vars(os))
    view.open = opened
    with patch.object(source_module_loader, 'os', view):
        yield descriptors


class HistoricalBaseContextTests(unittest.TestCase):
    family = context

    def test_exact_installed_package_body_keeps_its_original_base_source(self):
        retained_sources()
        current_path = Path(current_base.__file__)
        current_raw = current_path.read_bytes()
        current_namespace = dict(vars(current_base))
        closure = context.diagnostic().owner.guest.recovery.authority.closure
        original_reference = closure.base
        try:
            assert_installed_body(self, self.family)
        finally:
            self.assertIs(original_reference, closure.base)
            self.assertEqual(current_raw, current_path.read_bytes())
            self.assertEqual(set(current_namespace), set(vars(current_base)))
            self.assertTrue(all(vars(current_base)[name] is value
                                for name, value in current_namespace.items()))

    def test_retained_original_context_reproduces_the_package_source_refusal(self):
        closure = context.diagnostic().owner.guest.recovery.authority.closure
        with current_base_prerequisite(self, closure):
            with self.assertRaisesRegex(ValueError, '^package-fixed-source$'):
                assert_installed_body(self, before_context())

    def test_current_producer_keeps_its_explicit_historical_package_scope(self):
        closure = current_installed.precise.owner.guest.recovery.authority.closure
        original_reference = closure.base
        original_public = current_installed.public
        current_namespace = dict(vars(current_base))
        current_raw = Path(current_base.__file__).read_bytes()
        try:
            assert_current_package_body(self, self.family)
        finally:
            self.assertIs(original_reference, closure.base)
            self.assertIs(original_public, current_installed.public)
            self.assertEqual(current_raw, Path(current_base.__file__).read_bytes())
            self.assertEqual(set(current_namespace), set(vars(current_base)))
            self.assertTrue(all(vars(current_base)[name] is value
                                for name, value in current_namespace.items()))

    def test_retained_current_package_context_refuses_the_incomplete_family(self):
        closure = current_installed.precise.owner.guest.recovery.authority.closure
        with current_base_prerequisite(self, closure):
            with self.assertRaisesRegex(ValueError, '^package-fixed-source$'):
                assert_current_package_body(self, before_context())

    def test_source_refusals_restore_an_unavailable_coordinator_dependency(self):
        cases = (
            ('test_retained_original_context_reproduces_the_package_source_refusal',
             context.diagnostic().owner.guest.recovery.authority.closure),
            ('test_retained_current_package_context_refuses_the_incomplete_family',
             current_installed.precise.owner.guest.recovery.authority.closure),
        )
        for method, closure in cases:
            with self.subTest(method=method):
                original_reference = closure.base
                try:
                    # Windows imports legitimately leave this POSIX coordinator
                    # dependency unavailable. No global platform state changes.
                    with patch.object(closure, 'base', None):
                        result = unittest.TestResult()
                        unittest.TestSuite([type(self)(method)]).run(result)
                        self.assertEqual(1, result.testsRun)
                        self.assertEqual([], result.errors)
                        self.assertEqual([], result.failures)
                        self.assertEqual([], result.skipped)
                        self.assertIsNone(closure.base)
                        with self.assertRaisesRegex(RuntimeError, '^inert prerequisite failure$'):
                            with current_base_prerequisite(self, closure):
                                self.assertIs(current_base, closure.base)
                                raise RuntimeError('inert prerequisite failure')
                        self.assertIsNone(closure.base)
                finally:
                    self.assertIs(original_reference, closure.base)

    def test_archive_keeps_actual_named_file_and_function_origin(self):
        raw = retained_sources()
        with context.historical_base() as archived:
            path = (FIXTURE / 'base_5d06ef74.source').absolute()
            self.assertEqual(str(path), archived.__file__)
            self.assertEqual(str(path), archived._readiness_script.__code__.co_filename)
            self.assertEqual(raw, Path(archived.__file__).read_bytes())
            self.assertIsNot(current_base, archived)
            self.assertIs(archived.__dict__, archived._readiness_script.__globals__)

    def test_nested_and_exceptional_scopes_restore_each_actual_dependency(self):
        closure = context.diagnostic().owner.guest.recovery.authority.closure
        original_reference = closure.base
        with context.historical_factories():
            outer = closure.base
            self.assertIsNot(original_reference, outer)
            with self.assertRaisesRegex(RuntimeError, '^inert nested failure$'):
                with context.historical_factories():
                    self.assertIsNot(outer, closure.base)
                    assert_installed_body(self, context)
                    raise RuntimeError('inert nested failure')
            self.assertIs(outer, closure.base)
            assert_installed_body(self, context)
            with context.historical_current_package():
                current_package_base = closure.base
                self.assertIsNot(outer, current_package_base)
                assert_current_package_body(self, context)
                self.assertIs(current_package_base, closure.base)
            self.assertIs(outer, closure.base)
        self.assertIs(original_reference, closure.base)

    def test_source_tamper_refuses_before_historical_code_loading(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary).resolve() / 'base.source'
            path.write_bytes(retained_sources() + b'\n')
            with patch.object(context.historical_source, 'load') as load:
                with self.assertRaisesRegex(ValueError, '^historical_base_source_changed$'):
                    with context.historical_base(path):
                        self.fail('Changed base source was admitted')
                load.assert_not_called()

    def test_same_byte_name_exchange_is_refused_or_prevented_by_held_handles(self):
        raw = retained_sources()
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary).resolve() / 'base.source'
            replacement = Path(temporary).resolve() / 'replacement.source'
            path.write_bytes(raw)
            replacement.write_bytes(raw)
            if os.name == 'nt':
                with context.historical_base(path):
                    with self.assertRaises(PermissionError):
                        replacement.replace(path)
                replacement.replace(path)
            else:
                with self.assertRaisesRegex(ValueError, '^bootstrap_source_generation_changed$'):
                    with context.historical_base(path):
                        replacement.replace(path)
            self.assertEqual(raw, path.read_bytes())

    def test_exceptional_scope_closes_its_exact_owned_source_handles(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary).resolve() / 'base.source'
            moved = Path(temporary).resolve() / 'closed.source'
            path.write_bytes(retained_sources())
            observer = nullcontext([]) if os.name == 'nt' else observed_source_descriptors(path)
            with observer as descriptors:
                with self.assertRaisesRegex(RuntimeError, '^inert scope failure$'):
                    with context.historical_base(path):
                        raise RuntimeError('inert scope failure')
            if os.name != 'nt':
                self.assertEqual(1, len(descriptors))
                for fd in descriptors:
                    with self.assertRaises(OSError) as error:
                        os.fstat(fd)
                    self.assertEqual(errno.EBADF, error.exception.errno)
            path.replace(moved)
            self.assertEqual(BASE_SHA, hashlib.sha256(moved.read_bytes()).hexdigest())

    def test_loader_failure_still_checks_and_closes_held_source(self):
        raw = retained_sources()
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary).resolve() / 'base.source'
            moved = Path(temporary).resolve() / 'closed.source'
            path.write_bytes(raw)
            def refuse_load(supplied, expected):
                self.assertEqual(path, supplied)
                self.assertEqual(BASE_SHA, expected)
                if os.name == 'nt':
                    with self.assertRaises(PermissionError):
                        path.write_bytes(raw + b'\n')
                else:
                    path.write_bytes(raw + b'\n')
                raise RuntimeError('inert load failure')
            error = '^inert load failure$' if os.name == 'nt' else '^bootstrap_source_bytes_changed$'
            expected_type = RuntimeError if os.name == 'nt' else ValueError
            with patch.object(context.historical_source, 'load', side_effect=refuse_load):
                with self.assertRaisesRegex(expected_type, error):
                    with context.historical_base(path):
                        self.fail('Refused loader yielded a module')
            path.replace(moved)
            self.assertEqual(raw if os.name == 'nt' else raw + b'\n', moved.read_bytes())




class PublicSourceContextTests(unittest.TestCase):
    """Real source gates without the coordinator's POSIX API; no native claim."""
    public_context = staticmethod(context.inert_repository_source_reads)
    fixtures = Path(__file__).with_name('fixtures') / 'cp117_public_source_context'

    @contextmanager
    def definitions(self, path, expected, names, globals_):
        import ast
        from agent_tools import source_module_loader
        with source_module_loader._bootstrap_source(path) as (raw, guard):
            self.assertEqual(expected, hashlib.sha256(raw).hexdigest())
            tree = ast.parse(raw.decode('utf-8'), filename=str(path))
            nodes = []
            for name in names:
                parent, _, member = name.partition('.')
                node = next(n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.ClassDef)) and n.name == parent)
                if member:
                    node = next(n for n in node.body if isinstance(n, ast.FunctionDef) and n.name == member)
                # The preserved method body is the subject, not its testcase decorators.
                if member:
                    node.decorator_list = []
                nodes.append(node)
            namespace = dict(globals_)
            exec(compile(ast.Module(body=nodes, type_ignores=[]), str(path), 'exec'), namespace)
            guard()
            try:
                yield namespace
            finally:
                guard()

    @contextmanager
    def absent_posix_reader(self):
        from agent_tools import windows_cp117_bound_absence_completion as binding
        class MissingFlag:
            def __getattr__(self, name):
                if name == 'O_NOFOLLOW':
                    raise AttributeError("module 'os' has no attribute 'O_NOFOLLOW'")
                return getattr(os, name)
        path = Path(binding.__file__)
        with self.definitions(path, '48234c12de9d48e61919fa981daacd03bf681ce56348bae2f381e9ab84b15ee0',
                              ('_read_bound_file',), dict(binding.__dict__, os=MissingFlag())) as ns:
            with patch.object(binding, '_read_bound_file', ns['_read_bound_file']):
                yield binding

    @contextmanager
    def before_public_context(self):
        path = self.fixtures / 'context.before.source'
        with self.definitions(path, 'fe886e20f2238db0ac7518c67f3c8169e5325ce426fe1a10dd9b1336630d79f8',
                              ('inert_repository_source_reads',), dict(context.__dict__, __file__=str(path))) as ns:
            with ns['inert_repository_source_reads']():
                yield

    def source_gate(self, chosen):
        from agent_tools import windows_cp117_windowless_dismiss_observe as dismiss
        from agent_tools.tests.test_windows_cp117_recovered_login import ScreenTests
        with context.historical_factories(), self.absent_posix_reader(), chosen(), context.remote_posix_recipe_context(dismiss.login.guest.recovery):
            dismiss._check_factories()
            source, parent = dismiss.slot_program(ScreenTests().record(), 'before1')
            self.assertTrue(source)
            self.assertEqual(dismiss.SLOT_HASHES['before1'][0], parent)
            self.assertIn('guest-exec-status', source)
            return source

    def test_actual_source_gate_without_posix_flag(self):
        problem = None
        try:
            self.source_gate(self.public_context)
        except AttributeError:
            import traceback
            problem = traceback.format_exc()
        self.assertIsNone(problem, 'actual public source gate refused: ' + str(problem))

    def test_preserved_two_label_context_refuses_same_actual_gate(self):
        with self.assertRaisesRegex(AttributeError, 'O_NOFOLLOW'):
            self.source_gate(self.before_public_context)

    def test_registered_owned_source_is_exact_and_generation_bound(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td).resolve() / 'factory.py'
            raw = b"def public_value():\n return 'PUBLIC_DECLARED_SOURCE'\n"
            path.write_bytes(raw)
            with self.absent_posix_reader() as binding, self.public_context():
                context.register_inert_public_source(path, raw)
                pin, actual = binding._read_bound_file(path, retain_bytes=True)
                self.assertEqual(raw, actual)
                self.assertEqual(hashlib.sha256(raw).hexdigest(), pin['sha256'])
                ns = {}
                exec(compile(actual, str(path), 'exec'), ns)
                self.assertEqual('PUBLIC_DECLARED_SOURCE', ns['public_value']())
                path.write_bytes(raw + b'#changed\n')
                with self.assertRaisesRegex(ValueError, 'inert-public-source-changed'):
                    binding._read_bound_file(path)

    def test_private_and_undeclared_sources_keep_original_refusal(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td).resolve() / 'private.py'
            path.write_bytes(b'PRIVATE_NOT_DECLARED\n')
            with self.absent_posix_reader() as binding, self.public_context():
                with self.assertRaisesRegex(AttributeError, 'O_NOFOLLOW'):
                    binding._read_bound_file(path)
                context.register_inert_public_source(path, path.read_bytes())
                with self.assertRaisesRegex(AttributeError, 'O_NOFOLLOW'):
                    binding._read_bound_file(path, private=True)
            with self.assertRaisesRegex(ValueError, 'inert-public-source-registration'):
                context.register_inert_public_source(path, path.read_bytes())

    def test_direct_recipe_helpers_apply_only_the_remote_path_grammar(self):
        from agent_tools import windows_cp117_fixture_recovery_short_socket as recovery
        from agent_tools.tests import test_windows_cp117_recovered_login as screen
        from agent_tools.tests import test_windows_cp117_installed_base_observe as installed
        original = recovery.os
        # Model only incoming inert recipe grammar; local OS and Path stay real.
        import ntpath
        class IncomingPath:
            path = ntpath
            def __getattr__(self, name):
                return getattr(original, name)
        with self.definitions(self.fixtures / 'recovered-login.before.source',
                              'b5c1469e6f541e43b3ba16811353ad41511ac071cb009f357efb1f7d94fd7236',
                              ('ScreenTests.record',), screen.__dict__) as old_screen:
            with self.definitions(self.fixtures / 'installed-base.before.source',
                                  '39991f9b53906727564ab31b0e6430f6ea9cb08ff88437f5e76a9bc38f53dfbc',
                                  ('InstalledTests.execute_flow',), installed.__dict__) as old_installed:
                with context.historical_factories(), context.inert_repository_source_reads(), patch.object(recovery, 'os', IncomingPath()):
                    with self.assertRaisesRegex(Exception, 'unix-socket-path'):
                        old_screen['record'](screen.ScreenTests())
                    record = screen.ScreenTests().record()
                    self.assertRegex(record['request']['recipeSha256'], r'^[a-f0-9]{64}$')
                    self.assertEqual('running', record['result']['state'])
                    self.assertIs(recovery.os.path, ntpath)
                    with self.assertRaisesRegex(Exception, 'unix-socket-path'):
                        old_installed['execute_flow'](installed.InstalledTests())
                    if os.name == 'nt':
                        import importlib.util
                        import sys
                        self.assertNotIn('fcntl', sys.modules)
                        self.assertIsNone(importlib.util.find_spec('fcntl'))
                        with context.remote_posix_recipe_context(recovery):
                            with self.assertRaises(ModuleNotFoundError) as missing:
                                old_installed['execute_flow'](installed.InstalledTests())
                        self.assertEqual('fcntl', missing.exception.name)
                        print('CP117_INERT_PREFIX_COUNTERFACTUAL_RED ' + json.dumps({
                            'testsRun': 1, 'errors': 1, 'failures': 0, 'skipped': 0,
                            'exceptionType': type(missing.exception).__name__,
                            'missingModule': missing.exception.name,
                            'beforeSourceSha256': '39991f9b53906727564ab31b0e6430f6ea9cb08ff88437f5e76a9bc38f53dfbc',
                            'genuineNativeCapability': True}), flush=True)
                    value, calls, anchors = installed.InstalledTests().execute_flow()
                    self.assertEqual(value['state'], 'observed')
                    self.assertEqual(['guest-exec','guest-exec-status'], [operation for operation, _ in calls])
                    self.assertTrue(anchors)
                    self.assertIs(recovery.os.path, ntpath)
        self.assertIs(original, recovery.os)
        self.assertIs(original.path, os.path)

    def test_preserved_screen_generator_refuses_unsupported_base_current_scope_restores(self):
        from agent_tools.tests import test_windows_cp117_recovered_login as fixture
        closure = fixture.login.guest.recovery.authority.closure
        path = self.fixtures / 'recovered-login.before.source'
        with self.definitions(path, 'b5c1469e6f541e43b3ba16811353ad41511ac071cb009f357efb1f7d94fd7236',
                              ('ScreenTests.test_readonly_program_has_no_guest_execution_or_keyboard',), fixture.__dict__) as ns:
            with patch.object(closure, 'base', None), context.remote_posix_recipe_context(fixture.login.guest.recovery):
                with self.assertRaisesRegex(AttributeError, '_QGA'):
                    ns['test_readonly_program_has_no_guest_execution_or_keyboard'](fixture.ScreenTests())
                self.assertIsNone(closure.base)
                fixture.ScreenTests().test_readonly_program_has_no_guest_execution_or_keyboard()
                self.assertIsNone(closure.base)


if __name__ == '__main__':
    unittest.main()
