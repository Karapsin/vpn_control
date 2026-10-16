"""Inert historical package factories keep their complete original base source."""
from contextlib import ExitStack, contextmanager, nullcontext
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
from agent_tools.tests.fixtures.cp117_gzip_runtime import historical_gzip_context
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


class CompleteInertContextLifetimeTests(unittest.TestCase):
    """Actual source gates with modeled missing POSIX flags/remote path grammar.

    These controls do not emulate Windows file custody or claim native execution.
    The unchanged original Windows scenarios remain required on Windows CI.
    """
    family_variant = 'current'
    definitions = PublicSourceContextTests.definitions
    absent_posix_reader = PublicSourceContextTests.absent_posix_reader
    c_commit = '30901b9f793f72534dae3441e45b67c3587719e8'
    c_sources = {'context.py': {'sha256': '91922a4930035c2fb66f84a9e8035070d12308d457615a0030540f6251bfa4b8', 'bytes': 12127, 'sourcePath': 'agent_tools/tests/fixtures/windows_cp117_historical_factory/context.py'}, 'test_windows_cp117_windowless_dismiss_observe.py': {'sha256': '6995a4af23fc328995e8586aee6b5d858286bae3e7f534a8544993349b4465ef', 'bytes': 13712, 'sourcePath': 'agent_tools/tests/test_windows_cp117_windowless_dismiss_observe.py'}, 'test_windows_cp117_recovered_owner_diagnostic.py': {'sha256': 'a0245b49b3f72c47b94be3b6ca5449dc2458447015252504a2bae7c50e37c6eb', 'bytes': 21826, 'sourcePath': 'agent_tools/tests/test_windows_cp117_recovered_owner_diagnostic.py'}, 'test_windows_cp117_installed_base_observe.py': {'sha256': 'ed9c7b4463354e830b7834a55e87af15ca8006fa870475ea1ead211df7021857', 'bytes': 16537, 'sourcePath': 'agent_tools/tests/test_windows_cp117_installed_base_observe.py'}}

    @contextmanager
    def family(self, variant=None):
        from agent_tools import source_module_loader
        selected = self.family_variant if variant is None else variant
        self.assertIn(selected, ('before', 'current'))
        path = (FIXTURE / 'context_30901b9f.before.source' if selected == 'before'
                else Path(context.__file__).resolve())
        with source_module_loader._bootstrap_source(path) as (raw, guard):
            if selected == 'before':
                expected = self.c_sources['context.py']
                self.assertEqual(expected['sha256'], hashlib.sha256(raw).hexdigest())
                self.assertEqual(expected['bytes'], len(raw))
                family = historical_source.load(path, expected['sha256'])
            else:
                family = historical_source.verify(context, path, hashlib.sha256(raw).hexdigest())
            guard()
            try:
                yield family
            finally:
                guard()

    @contextmanager
    def incoming_remote_path_grammar(self):
        import ntpath
        from agent_tools import windows_cp117_fixture_recovery_short_socket as recovery
        original = recovery.os
        class IncomingPath:
            path = ntpath
            def __getattr__(self, name):
                return getattr(original, name)
        with patch.object(recovery, 'os', IncomingPath()):
            supplied = recovery.os
            try:
                yield recovery, supplied
            finally:
                self.assertIs(supplied, recovery.os)
        self.assertIs(original, recovery.os)

    def producer(self, variant=None, current=False):
        from agent_tools import windows_cp117_base_source_refresh as refresh
        from agent_tools.tests.test_windows_cp117_recovered_login import ScreenTests
        original_os_path = os.path
        with self.family(variant) as family, self.incoming_remote_path_grammar() as (recovery, supplied):
            chosen = family.historical_current_package if current else family.historical_factories
            with chosen(), family.inert_repository_source_reads():
                record = ScreenTests().record()
                if current:
                    source, sha = current_installed.program_current(record, current_installed.PAIR_EXPECTED)
                    body = current_installed.body_current(current_installed.PAIR_EXPECTED)
                else:
                    source, sha = refresh.program(record, refresh.PAIR_EXPECTED)
                    body = refresh.body(refresh.PAIR_EXPECTED)
                self.assertEqual(hashlib.sha256(body.encode('utf-16le')).hexdigest(), sha)
                self.assertEqual(record['request']['recipeSha256'], recovery._digest(recovery.recipe()))
                self.assertGreater(len(source), 10000)
                self.assertIn('guest-exec-status', source)
                self.assertIsNot(supplied, recovery.os)
            self.assertIs(supplied, recovery.os)
        self.assertIs(original_os_path, os.path)
        return source, sha

    def http_source(self, variant=None):
        from agent_tools import windows_cp117_base_source_refresh as refresh
        with self.family(variant) as family, family.historical_factories(), self.absent_posix_reader(), family.inert_repository_source_reads():
            source, sha = refresh.download_body(refresh.SUBMITTED_PORT)
            self.assertTrue(source)
            self.assertRegex(sha, r'^[0-9a-f]{64}$')
            self.assertIn('DOWNLOAD_ACTION_SOURCE', source)
            return source, sha

    def run_module_hook_case(self, key, variant=None):
        import ast
        import importlib
        from agent_tools import source_module_loader
        selected = self.family_variant if variant is None else variant
        self.assertIn(selected, ('before', 'current'))
        module_name, class_name, method = {
            'test_windows_cp117_windowless_dismiss_observe.py': (
                'agent_tools.tests.test_windows_cp117_windowless_dismiss_observe',
                'AuthoritySchemaTests', 'test_generated_actual_pre_key_guard_pins_preframe_attempt_after_read'),
            'test_windows_cp117_recovered_owner_diagnostic.py': (
                'agent_tools.tests.test_windows_cp117_recovered_owner_diagnostic',
                'DiagnosticTests', 'test_complete_generated_blocked_transport_is_diagnosis_not_admission'),
            'test_windows_cp117_installed_base_observe.py': (
                'agent_tools.tests.test_windows_cp117_installed_base_observe',
                'InstalledTests', 'test_complete_compressed_source_roundtrip_hash_size_and_fixed_catalog'),
        }[key]
        module = importlib.import_module(module_name)
        current_path = Path(module.__file__).resolve()
        before_path = FIXTURE / (Path(key).stem + '_30901b9f.before.source')
        with source_module_loader._bootstrap_source(before_path) as (before, before_guard), source_module_loader._bootstrap_source(current_path) as (actual, actual_guard):
            expected = self.c_sources[key]
            self.assertEqual(expected['sha256'], hashlib.sha256(before).hexdigest())
            self.assertEqual(expected['bytes'], len(before))
            before_tree = ast.parse(before, filename=str(before_path))
            actual_tree = ast.parse(actual, filename=str(current_path))
            def body(tree):
                cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == class_name)
                return next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == method)
            self.assertEqual(ast.dump(body(before_tree)), ast.dump(body(actual_tree)))
            chosen_tree = before_tree if selected == 'before' else actual_tree
            chosen_path = before_path if selected == 'before' else current_path
            hooks = [n for n in chosen_tree.body if isinstance(n, ast.FunctionDef)
                     and n.name in ('setUpModule', 'tearDownModule')]
            self.assertEqual([] if selected == 'before' else ['setUpModule', 'tearDownModule'],
                             [n.name for n in hooks])
            # The actual producer namespace supplies its imports. Only the exact
            # selected module-hook definitions execute under their real filename.
            namespace = dict(module.__dict__, __file__=str(chosen_path))
            exec(compile(ast.Module(body=hooks, type_ignores=[]), str(chosen_path), 'exec'), namespace)
            with context.historical_factories(), self.absent_posix_reader() as binding:
                original_reader = binding._read_bound_file
                original_registry = context._PUBLIC_SOURCE_REGISTRY.get()
                entered = False
                try:
                    if hooks:
                        namespace['setUpModule']()
                        entered = True
                    result = unittest.TestResult()
                    getattr(module, class_name)(method).run(result)
                finally:
                    if entered:
                        namespace['tearDownModule']()
                self.assertIs(original_reader, binding._read_bound_file)
                self.assertIs(original_registry, context._PUBLIC_SOURCE_REGISTRY.get())
            before_guard()
            actual_guard()
            return result

    def assert_case_success(self, result):
        self.assertEqual(1, result.testsRun)
        self.assertEqual([], result.errors, result.errors)
        self.assertEqual([], result.failures, result.failures)
        self.assertEqual([], result.skipped)

    def test_complete_historical_producer_keeps_remote_posix_scope(self):
        self.producer()

    def test_complete_current_package_producer_keeps_remote_posix_scope(self):
        self.producer(current=True)

    def test_exact_c_context_refuses_both_complete_producers(self):
        from agent_tools import windows_cp117_fixture_recovery_short_socket as recovery
        for current in (False, True):
            with self.subTest(current=current):
                with self.assertRaisesRegex(recovery.RecoveryUnknown, '^unix-socket-path$'):
                    self.producer('before', current=current)
                self.producer('current', current=current)

    def test_http_source_uses_declared_genuine_held_bytes(self):
        self.http_source()

    def test_exact_c_context_does_not_admit_the_missing_http_origin(self):
        with self.assertRaisesRegex(AttributeError, 'O_NOFOLLOW'):
            self.http_source('before')
        self.http_source('current')

    def test_actual_three_module_lifetimes_cover_source_emission(self):
        for key in self.c_sources:
            if key != 'context.py':
                with self.subTest(module=key):
                    self.assert_case_success(self.run_module_hook_case(key))

    def test_exact_c_missing_hooks_refuse_the_same_unchanged_test_bodies(self):
        for key in self.c_sources:
            if key != 'context.py':
                with self.subTest(module=key):
                    result = self.run_module_hook_case(key, 'before')
                    self.assertEqual(1, result.testsRun)
                    self.assertEqual([], result.failures, result.failures)
                    self.assertEqual([], result.skipped)
                    self.assertEqual(1, len(result.errors), result.errors)
                    self.assertIn('O_NOFOLLOW', result.errors[0][1])
                    self.assert_case_success(self.run_module_hook_case(key, 'current'))

    def credential_source(self, variant=None, supply_validity=False):
        from agent_tools import source_module_loader
        from agent_tools import windows_cp117_recovered_login as login
        from agent_tools.tests.test_windows_cp117_recovered_login import ScreenTests
        root = Path(__file__).resolve().parents[2]
        validity = root / 'scripts/windows_credential_validity_qga.py'
        task = root / 'scripts/windows_task_admission.ps1'
        with self.family(variant) as family, family.historical_factories(), self.absent_posix_reader(), family.inert_repository_source_reads():
            # The second exact-C counterfactual supplies only the first genuine
            # public prerequisite, so the unchanged next read reaches Task PS1.
            # Both registered bytes and the unchanged producer hash must agree.
            with source_module_loader._bootstrap_source(validity) as (raw, guard):
                self.assertEqual(login._VALIDITY_SHA, hashlib.sha256(raw).hexdigest())
                if supply_validity:
                    family.register_inert_public_source(validity, raw)
                try:
                    source, sha, pins = login.credential_program(root, ScreenTests().record(),
                        'fb0a9a9d-eac2-43b0-a332-5fd766ce65a4')
                    self.assertEqual(login._BOOTSTRAP_SHA, sha)
                    self.assertEqual({str(validity), str(task)}, set(pins))
                    self.assertEqual(login._VALIDITY_SHA, pins[str(validity)]['sha256'])
                    self.assertEqual(login._TASK_HELPER_SHA, pins[str(task)]['sha256'])
                    self.assertIn('credential-helper', source)
                    self.assertIn('private-input-cap', source)
                    self.assertIn('probe-record-generation', source)
                    compile(source, 'inert-complete-credential-source', 'exec')
                    return source, sha, pins
                finally:
                    guard()

    def test_complete_credential_source_keeps_both_exact_public_script_inputs(self):
        self.credential_source()

    def test_exact_c_registry_refuses_the_original_validity_input(self):
        with self.assertRaisesRegex(AttributeError, 'O_NOFOLLOW'):
            self.credential_source('before')
        self.credential_source('current')

    def test_exact_c_registry_refuses_task_after_the_validity_prerequisite(self):
        with self.assertRaisesRegex(AttributeError, 'O_NOFOLLOW'):
            self.credential_source('before', supply_validity=True)
        self.credential_source('current', supply_validity=True)

    def test_declared_task_input_keeps_the_original_private_reader_refusal(self):
        from agent_tools import windows_cp117_recovered_login as login
        task = Path(__file__).resolve().parents[2] / 'scripts/windows_task_admission.ps1'
        with self.absent_posix_reader() as binding, context.inert_repository_source_reads():
            pin, raw = binding._read_bound_file(task, retain_bytes=True)
            self.assertEqual(login._TASK_HELPER_SHA, pin['sha256'])
            self.assertEqual(login._TASK_HELPER_SHA, hashlib.sha256(raw).hexdigest())
            self.assertEqual(9, len(pin['generation']))
            with self.assertRaisesRegex(AttributeError, 'O_NOFOLLOW'):
                binding._read_bound_file(task, private=True)


    def test_nested_exceptional_recipe_and_source_contexts_restore_references(self):
        from agent_tools import windows_cp117_bound_absence_completion as binding
        original_reader = binding._read_bound_file
        original_registry = context._PUBLIC_SOURCE_REGISTRY.get()
        original_os_path = os.path
        with self.incoming_remote_path_grammar() as (recovery, supplied):
            with context.historical_factories(), context.inert_repository_source_reads():
                outer_os = recovery.os
                outer_reader = binding._read_bound_file
                outer_registry = context._PUBLIC_SOURCE_REGISTRY.get()
                with self.assertRaisesRegex(RuntimeError, '^inert nested context failure$'):
                    with context.historical_current_package(), context.inert_repository_source_reads():
                        self.assertIsNot(outer_os, recovery.os)
                        self.assertIsNot(outer_reader, binding._read_bound_file)
                        self.assertIsNot(outer_registry, context._PUBLIC_SOURCE_REGISTRY.get())
                        raise RuntimeError('inert nested context failure')
                self.assertIs(outer_os, recovery.os)
                self.assertIs(outer_reader, binding._read_bound_file)
                self.assertIs(outer_registry, context._PUBLIC_SOURCE_REGISTRY.get())
            self.assertIs(supplied, recovery.os)
        self.assertIs(original_reader, binding._read_bound_file)
        self.assertIs(original_registry, context._PUBLIC_SOURCE_REGISTRY.get())
        self.assertIs(original_os_path, os.path)




class InertRemoteDefinitionBoundaryTests(unittest.TestCase):
    """Actual complete inert fixtures under explicit missing-import projections.

    The adapter only subtracts generated-namespace capabilities. It changes no
    global OS, signal module, import cache, production source or native authority.
    """
    variant = None
    sources = {'diagnostic': {'sourcePath': 'agent_tools/tests/test_windows_cp117_recovered_owner_diagnostic.py', 'resource': 'diagnostic.before.source', 'bytes': 22182, 'sha256': 'f384a61f8cd4d77048843514e11a74e1bfbc8dfd529c512b062b24a55d107db9'}, 'dismiss': {'sourcePath': 'agent_tools/tests/test_windows_cp117_windowless_dismiss_observe.py', 'resource': 'dismiss.before.source', 'bytes': 14068, 'sha256': '6816aad43259a28c2aa67482a65d2fcb823b2efdaca251d4eed802c1502da3b4'}, 'secure_layout': {'sourcePath': 'agent_tools/tests/test_windows_cp117_secure_layout_observe.py', 'resource': 'secure_layout.before.source', 'bytes': 15698, 'sha256': 'b9930147565736a1d3f412dbe2dc9e4b4e2cfd89e497f217ad6262d3d764b364'}}
    folder = FIXTURE.parent / 'windows_inert_remote_definitions'

    @contextmanager
    def modules(self, variant):
        import importlib
        from agent_tools import source_module_loader
        with ExitStack() as stack:
            metadata, close_metadata = stack.enter_context(source_module_loader._bootstrap_source(self.folder / 'provenance.json'))
            provenance = json.loads(metadata)
            self.assertEqual('fd4a3c77e8935c4c5669e61a26bbfca41e171850', provenance['sourceCommit'])
            self.assertEqual(self.sources, provenance['files'])
            self.assertIs(provenance['rawProgramAndProductionPinsChanged'], False)
            self.assertIs(provenance['nativeEvidenceFabricated'], False)
            close_metadata(); stack.callback(close_metadata)
            modules = {}
            for label, row in self.sources.items():
                if variant == 'before':
                    path = self.folder / row['resource']
                    raw, guard = stack.enter_context(source_module_loader._bootstrap_source(path))
                    self.assertEqual((row['bytes'], row['sha256']), (len(raw), hashlib.sha256(raw).hexdigest()))
                    modules[label] = historical_source.load(path, row['sha256'])
                    self.assertEqual(str(path.absolute()), modules[label].__file__)
                    guard()
                    stack.callback(guard)
                else:
                    name = row['sourcePath'][:-3].replace('/', '.')
                    modules[label] = importlib.import_module(name)
            if variant == 'before':
                # Dismiss copies this actual D helper; current helper bytes must
                # not silently become the preserved old programme's input.
                stack.enter_context(patch.object(modules['dismiss'], 'layout', modules['secure_layout']))
            stack.enter_context(historical_gzip_context(*modules.values()))
            yield modules

    @contextmanager
    def missing_target_capabilities(self, modules, capability):
        import builtins
        self.assertIn(capability, ('fcntl', 'signal'))
        original_import = builtins.__import__
        class SignalView:
            def __init__(self, actual): self.actual = actual
            def __getattr__(self, name):
                if name in ('SIGALRM', 'ITIMER_REAL', 'setitimer'):
                    raise AttributeError('projected target-only signal capability: ' + name)
                return getattr(self.actual, name)
        def importing(name, *args, **kwargs):
            if capability == 'fcntl' and name == 'fcntl':
                raise ModuleNotFoundError("No module named 'fcntl'", name='fcntl')
            actual = original_import(name, *args, **kwargs)
            return SignalView(actual) if name == 'signal' else actual
        def executing(code, namespace, local=None):
            self.assertIs(type(namespace), dict)
            view = dict(vars(builtins), __import__=importing, exec=executing)
            namespace['__builtins__'] = view
            return builtins.exec(code, namespace) if local is None else builtins.exec(code, namespace, local)
        actual_patch = patch
        def inert_patch(name, *args, **kwargs):
            # Historical test stubs for target alarms stay local and cannot
            # create or alter coordinator signal attributes during this model.
            if isinstance(name, str) and name in ('signal.signal', 'signal.setitimer', 'signal.SIGALRM', 'signal.ITIMER_REAL'):
                return nullcontext()
            return actual_patch(name, *args, **kwargs)
        with ExitStack() as stack:
            for module in modules.values():
                stack.enter_context(patch.object(module, 'exec', executing, create=True))
                stack.enter_context(patch.object(module, 'patch', inert_patch))
            yield

    def positive(self, family, capability='fcntl', variant=None):
        selected = variant if variant is not None else self.variant
        if selected is None:
            selected = 'current'
        self.assertIn(selected, ('before', 'current'))
        selector = {
            'diagnostic': ('diagnostic', 'DiagnosticTests', 'test_complete_generated_blocked_transport_is_diagnosis_not_admission'),
            'direct': ('dismiss', 'DismissTests', 'test_fixed_catalog_sources_parent_child_and_unknown_slot_refusal'),
            'copied': ('dismiss', 'DismissTests', 'test_each_actual_generated_slot_one_submit_same_pid_and_stale_exhaustion'),
        }[family]
        with self.modules(selected) as modules, context.inert_repository_source_reads(), self.missing_target_capabilities(modules, capability):
            module = modules[selector[0]]
            result = unittest.TestResult()
            getattr(module, selector[1])(selector[2]).run(result)
        self.assertEqual((1, [], [], []), (result.testsRun, result.failures, result.errors, result.skipped), '\n'.join(text for _, text in result.errors or result.failures))

    def test_actual_complete_diagnostic_uses_inert_target_definitions(self):
        self.positive('diagnostic')

    def test_actual_direct_slot_definitions_use_inert_target_view(self):
        self.positive('direct')

    def test_actual_copied_slot_flow_uses_inert_target_view(self):
        self.positive('copied')

    def test_preserved_D_imports_refuse_the_same_positive_cases(self):
        for family, method in (
                ('diagnostic', 'test_actual_complete_diagnostic_uses_inert_target_definitions'),
                ('direct', 'test_actual_direct_slot_definitions_use_inert_target_view'),
                ('copied', 'test_actual_copied_slot_flow_uses_inert_target_view')):
            with self.subTest(family=family):
                case = type(self)(method); case.variant = 'before'
                result = unittest.TestResult(); case.run(result)
                self.assertEqual((1, 1, 0, []), (result.testsRun, len(result.failures), len(result.errors), result.skipped))
                self.assertIn("ModuleNotFoundError: No module named 'fcntl'", result.failures[0][1])
                self.positive(family, variant='current')

    @unittest.skipIf(os.name == 'nt', 'Separate signal-only causal model needs genuine POSIX fcntl; complete original Windows fixtures remain required')
    def test_posix_signal_absence_is_independent_from_real_locking_support(self):
        import fcntl
        self.assertTrue(callable(fcntl.flock))
        for family in ('direct', 'copied'):
            with self.subTest(family=family):
                with self.assertRaisesRegex(AssertionError, 'SIGALRM'):
                    self.positive(family, capability='signal', variant='before')
                self.positive(family, capability='signal', variant='current')

    def test_actual_emitted_view_omits_only_the_admitted_target_effects(self):
        from agent_tools.tests.fixtures.windows_replacement_fixture_sections import inert_remote_definitions
        import ast
        import copy
        seen = []
        with self.modules('current') as modules, context.inert_repository_source_reads(), self.missing_target_capabilities(modules, 'fcntl'):
            def observing(tree):
                before = ast.dump(tree)
                view = inert_remote_definitions(tree)
                self.assertEqual(before, ast.dump(tree))
                original = copy.deepcopy(tree.body[:-1])
                original[0].names = original[0].names[:-1]
                original = [node for node in original if not (
                    isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)
                    and isinstance(node.value.func, ast.Attribute)
                    and isinstance(node.value.func.value, ast.Name)
                    and node.value.func.value.id == 'signal'
                    and node.value.func.attr in ('signal', 'setitimer'))]
                self.assertEqual(ast.dump(ast.Module(body=original, type_ignores=[])), ast.dump(view))
                seen.append(copy.deepcopy(tree))
                return view
            with patch.object(modules['diagnostic'], 'inert_remote_definitions', observing):
                result = unittest.TestResult()
                modules['diagnostic'].DiagnosticTests('test_complete_generated_blocked_transport_is_diagnosis_not_admission').run(result)
                self.assertEqual((1, [], [], []), (result.testsRun, result.failures, result.errors, result.skipped), result.errors)
        self.assertEqual(1, len(seen))
        original = seen[0]
        variants = []
        used = copy.deepcopy(original); used.body[-1].body.append(ast.Expr(value=ast.Name(id='fcntl', ctx=ast.Load()))); variants.append(used)
        imported = copy.deepcopy(original); imported.body.insert(1, ast.Import(names=[ast.alias(name='fcntl')])); variants.append(imported)
        foreign = copy.deepcopy(original); foreign.body[0].names[-1].asname = 'foreign'; variants.append(foreign)
        alarm = copy.deepcopy(original)
        call = next(node for node in ast.walk(alarm) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == 'setitimer')
        call.args[-1] = ast.Constant(value=51); variants.append(alarm)
        for number, tree in enumerate(variants):
            with self.subTest(refusal=number), self.assertRaisesRegex(ValueError, 'inert-remote-'):
                inert_remote_definitions(tree)


    @unittest.skipUnless(os.name == 'nt', 'Actual Windows coordinator missing fcntl, with unprojected authentic D diagnostic')
    def test_actual_windows_observed_D_diagnostic_import_red_current_green(self):
        import base64
        selector = 'test_complete_generated_blocked_transport_is_diagnosis_not_admission'
        with self.modules('before') as modules, context.inert_repository_source_reads():
            # Run the complete immutable D original directly. There is no
            # generated-namespace import projection or local patch adapter here.
            old = unittest.TestResult()
            modules['diagnostic'].DiagnosticTests(selector).run(old)
        self.assertEqual((1, 0, 1, []), (old.testsRun, len(old.failures), len(old.errors), old.skipped))
        self.assertIn("ModuleNotFoundError: No module named 'fcntl'", old.errors[0][1])
        before_trace = old.errors[0][1].encode('utf-8', errors='strict')
        self.assertLessEqual(len(before_trace), 8192, 'complete native diagnostic traceback bound')
        from agent_tools import source_module_loader
        with self.modules('current') as modules, context.inert_repository_source_reads():
            with source_module_loader._bootstrap_source(Path(modules['diagnostic'].__file__)) as (current_raw, current_guard):
                current_sha = hashlib.sha256(current_raw).hexdigest()
                current = unittest.TestResult()
                modules['diagnostic'].DiagnosticTests(selector).run(current)
                current_guard()
        evidence = {'sourceCommit': 'fd4a3c77e8935c4c5669e61a26bbfca41e171850',
                    'beforeSourceSha256': self.sources['diagnostic']['sha256'],
                    'beforeTracebackBytes': len(before_trace),
                    'beforeTracebackSha256': hashlib.sha256(before_trace).hexdigest(),
                    'beforeTracebackBase64': base64.b64encode(before_trace).decode('ascii'),
                    'currentSourceSha256': current_sha, 'actualWindowsCoordinator': True,
                    'before': {'testsRun': old.testsRun, 'failures': len(old.failures), 'errors': len(old.errors)},
                    'current': {'testsRun': current.testsRun, 'failures': len(current.failures), 'errors': len(current.errors), 'skipped': len(current.skipped)},
                    'importProjectionUsed': False, 'nativeProductAcceptance': False,
                    'nativeTransportExecuted': False}
        line = 'CP117_NATIVE_INERT_DEFINITION_DIAGNOSTIC ' + json.dumps(evidence, sort_keys=True)
        self.assertLessEqual(len(line.encode('ascii')), 16384, 'native diagnostic evidence line bound')
        print(line, flush=True)
        self.assertEqual((1, [], [], []), (current.testsRun, current.failures, current.errors, current.skipped), current.errors or current.failures)


if __name__ == '__main__':
    unittest.main()
