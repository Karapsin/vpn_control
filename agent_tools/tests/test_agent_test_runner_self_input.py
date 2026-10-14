"""Actual runner/MCP source-self-input regressions; no SSH or native actors."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import py_compile
import socket
import subprocess
import sys
import unittest
import uuid
from unittest import mock
from agent_tools.tests import test_agent_test_runner as fixtures

ROOT = Path(__file__).resolve().parents[2]
RUNNER = 'agent_tools/agent_test_runner.py'
MCP = 'agent_tools/mcp_server.py'
PREFIX = 'agent_tools/tests/fixtures/runner_self_input/'
BEFORE_FILES = {
    'runner_original.source': '87d819fbe4a94e9e3a590ca34c74f13ab189782794fa6a7a96f9bcbe2f830c88',
    'runner_generation_before.source': 'fd382d712542d6002489f4717f013e1c02ea5ab67a5f69a0101083d6c044611d',
    'runner_code_auth_before.source': '42051da3f8a0ed744006853e009d570a5cd7a602ea1c3be6a93041210d181ccf',
    'runner_merge_before.source': 'c14933128e44428af71c96a455876b2a43e21f58e7ad54eec0d0a3699a2bcff7',
    'mcp_import_before.source': '88cd8e169c468e248b46f4a2e6a2f8b601a7b7b5aa719e06e6b80511eb5800d6',
}
SOURCE_FILES = ('agent_tools/affected_agent_test_dependencies.json', 'agent_tools/affected_agent_tests.py', 'agent_tools/agent_test_runner.py', 'agent_tools/check_output_retention.py', 'agent_tools/docs_assistant.py', 'agent_tools/local_build_environment.py', 'agent_tools/managed_check_lease.py', 'agent_tools/mcp_server.py', 'agent_tools/native_review_source_closure.py', 'agent_tools/private_inventory_lock.py', 'agent_tools/ssh_channel_inventory_diagnostics.py', 'agent_tools/ssh_channel_selection.py', 'agent_tools/ssh_connection_recovery.py', 'agent_tools/ssh_connection_session.py', 'agent_tools/ssh_direct_nested_channel.py', 'agent_tools/ssh_expired_recovery_retirement.py', 'agent_tools/ssh_fresh_nested_channel.py', 'agent_tools/ssh_nested_socket_noninteractive_observation.py', 'agent_tools/ssh_nested_socket_owned_home_observation.py', 'agent_tools/ssh_nested_socket_retirement.py', 'agent_tools/ssh_nested_socket_route_diagnostic.py', 'agent_tools/ssh_recovery_adoption.py', 'agent_tools/ssh_transport.py', 'agent_tools/tests/__init__.py', 'agent_tools/tests/test_ssh_connection_session.py', 'agent_tools/tests/test_ssh_direct_nested_channel.py', 'agent_tools/tests/test_ssh_fresh_nested_channel.py')
CAPABLE = (os.name == 'posix' and hasattr(socket, 'AF_UNIX')
           and all(hasattr(os, name) for name in ('O_NOFOLLOW', 'O_DIRECTORY', 'getuid', 'getgid', 'killpg'))
           and importlib.util.find_spec('fcntl') is not None and callable(getattr(sys, '_getframe', None)))
IMPORT_CASE = """import unittest
class Import(unittest.TestCase):
 def test_real_mcp_runner_dependency(self):
  from agent_tools import mcp_server
  from pathlib import Path
  self.assertIn(Path(mcp_server.__file__).resolve().with_name('agent_test_runner.py'),mcp_server._CHECK_RUNNER_SOURCE_DIGESTS)
"""


@unittest.skipUnless(CAPABLE, 'POSIX protected source/child sessions, fcntl, Unix sockets and executing-frame authentication required')
class RunnerSelfInputTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.AgentTestRunnerTests('runTest')
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.sequence = 0

    def before(self, name):
        expected = BEFORE_FILES[name]  # Reject unknown fixture names before reading.
        raw = (ROOT / PREFIX / name).read_bytes()
        self.assertEqual(expected, hashlib.sha256(raw).hexdigest())
        return raw

    def load(self, source):
        spec = importlib.util.spec_from_file_location('owned_runner_' + uuid.uuid4().hex, source / RUNNER)
        runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runner)
        return runner

    def source(self, before=None, mcp_before=False):
        self.sequence += 1
        source = self.fixture.root / str(self.sequence)
        source.mkdir(mode=0o700)
        for relative in SOURCE_FILES:
            target = source / relative
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            target.write_bytes((ROOT / relative).read_bytes())
        if before:
            (source / RUNNER).write_bytes(self.before(before))
        if mcp_before:
            (source / MCP).write_bytes(self.before('mcp_import_before.source'))
        (source / 'agent_tools/__init__.py').write_text('')
        return source

    def group(self, source, body=IMPORT_CASE, *, token=True, omit_runner=False, name='self_input_fixture'):
        # Reuse the existing049 fixture writer and module naming contract.
        self.fixture.root = source
        module = self.fixture.module(name, body)
        relative = module.replace('.', '/') + '.py'
        runner = self.load(source)
        sources = {path: runner.digest(source / path) for path in SOURCE_FILES if path != RUNNER}
        sources[relative] = runner.digest(source / relative)
        if not omit_runner:
            sources[RUNNER] = runner.RUNNER_SELF_INPUT if token else runner.digest(source / RUNNER)
        runner.ISOLATED_SOURCES[module] = sources
        return runner, module, sources

    def invoke(self, source, runner, modules):
        self.fixture.root = source
        launches = []
        fd_directory = Path('/dev/fd') if Path('/dev/fd').is_dir() else Path('/proc/self/fd')
        self.assertTrue(fd_directory.is_dir(), 'declared POSIX descriptor census required')
        before_fds = len(os.listdir(fd_directory))
        real_popen = subprocess.Popen
        def launch(argv, **kwargs):
            launches.append(list(argv))
            return real_popen(argv, **kwargs)
        with self.fixture.environment(), mock.patch.dict(runner.ISOLATED_SOURCES, runner.ISOLATED_SOURCES.copy(), clear=True), mock.patch.object(subprocess, 'Popen', side_effect=launch):
            report = runner.run_plan({'schemaVersion': 1, 'sourceFingerprint': 'a' * 64,
                                     'modules': modules, 'maxWorkers': 1}, source / 'run', stream=io.StringIO())
        self.assertEqual(before_fds, len(os.listdir(fd_directory)), 'parent source/worker descriptors leaked')
        self.assertTrue(all(row['sessionAbsent'] and row['fixtureRootRemoved'] and not row['descendantLeak'] for row in report['workers']))
        for index, argv in enumerate(launches):
            context = source / 'run' / ('worker-%04d' % index) / 'sources'
            plan = json.loads((context.parent / 'plan.json').read_text())
            if RUNNER in plan['isolationSources'] and hasattr(runner, 'RUNNER_SELF_INPUT'):
                self.assertEqual(context / RUNNER, Path(argv[2]))
                self.assertEqual(runner._RUNNER_SOURCE_SHA256, runner.digest(context / RUNNER))
                self.assertEqual(runner._RUNNER_SOURCE_SHA256, plan['isolationSources'][RUNNER])
                self.assertNotIn(runner.RUNNER_SELF_INPUT, plan['isolationSources'].values())
        return report, launches

    def test_actual_historical_mcp_dependency_red_current_frozen_launch_green(self):
        source = self.source('runner_original.source', mcp_before=True)
        runner, module, sources = self.group(source, token=False, omit_runner=True)
        red, launches = self.invoke(source, runner, [module])
        self.assertFalse(red['successful'])
        self.assertEqual(1, red['counts']['errors'])
        diagnostic = (source / 'run/worker-0000/stderr.txt').read_text()
        self.assertIn('FileNotFoundError', diagnostic)
        self.assertIn('agent_test_runner.py', diagnostic)
        source = self.source()
        runner, module, _ = self.group(source)
        self.assertTrue(runner._RUNNER_IMPLEMENTATION_MATCH)
        green, launches = self.invoke(source, runner, [module])
        self.assertTrue(green['successful'])
        self.assertEqual(1, green['counts']['testsRun'])
        self.assertEqual(0, green['counts']['errors'])
        self.assertEqual(1, len(launches))

    def test_original_literal_self_pin_red(self):
        source = self.source('runner_original.source')
        # Adding a literal runner pin into that runner changes the bytes pinned.
        original = (source / RUNNER).read_bytes()
        literal = hashlib.sha256(original).hexdigest()
        raw = original.decode().replace('def digest(path: Path) -> str:', "ISOLATED_SOURCES['agent_tools.tests.test_self_literal']={" + repr(RUNNER) + ':' + repr(literal) + "}\n\ndef digest(path: Path) -> str:", 1)
        (source / RUNNER).write_text(raw)
        runner = self.load(source)
        with self.assertRaisesRegex(AssertionError, 'literal self pin'):
            self.assertTrue(runner.sources_match(source, {RUNNER: literal}), 'literal self pin cannot equal changed complete source')
        self.assertEqual([(False, ['agent_tools.tests.test_self_literal'])], runner.worker_groups(source, ['agent_tools.tests.test_self_literal']))

    def test_ordinary_sha_pins_keep_existing_semantics(self):
        source = self.source()
        runner = self.load(source)
        path = source / 'plain.py'
        path.write_bytes(b'original')
        declared = {'plain.py': runner.digest(path)}
        self.assertTrue(runner.sources_match(source, declared))
        leaf = source / 'freeze'
        leaf.mkdir(mode=0o700)
        context = runner.source_context(source, leaf, declared)
        self.assertEqual(b'original', (context / 'plain.py').read_bytes())
        path.rename(source / 'plain.before')
        path.write_bytes(b'original')
        self.assertTrue(runner.sources_match(source, declared))
        path.write_bytes(b'changed')
        self.assertFalse(runner.sources_match(source, declared))

    def test_predispatch_byte_and_foreign_generation_refuse_without_child(self):
        for foreign in (False, True):
            with self.subTest(foreign=foreign):
                source = self.source()
                runner, module, declared = self.group(source)
                path = source / RUNNER
                raw = path.read_bytes()
                if foreign:
                    path.rename(path.with_suffix('.preserved'))
                    path.write_bytes(raw)
                else:
                    path.write_bytes(raw + b'\n# owned drift\n')
                self.assertFalse(runner.sources_match(source, declared))
                self.fixture.root = source
                with self.fixture.environment(), mock.patch.object(subprocess, 'Popen', side_effect=AssertionError('effect after stale self input')) as actor:
                    with self.assertRaisesRegex(ValueError, 'generation changed'):
                        runner.run_plan({'schemaVersion': 1, 'sourceFingerprint': 'a' * 64, 'modules': [module], 'maxWorkers': 1}, source / 'run', stream=io.StringIO())
                    actor.assert_not_called()

    def test_unknown_misplaced_and_unavailable_frame_tokens_refuse(self):
        source = self.source()
        runner = self.load(source)
        for relative, token in ((RUNNER, '@unknown'), (MCP, runner.RUNNER_SELF_INPUT)):
            declared = {relative: token}
            self.assertFalse(runner.sources_match(source, declared))
            leaf = source / uuid.uuid4().hex
            leaf.mkdir(mode=0o700)
            with self.assertRaises(ValueError):
                runner.source_context(source, leaf, declared)
            self.assertFalse((leaf / 'sources').exists())
            runner.ISOLATED_SOURCES['agent_tools.tests.test_bad_token'] = declared
            with self.assertRaises(ValueError):
                runner.worker_groups(source, ['agent_tools.tests.test_bad_token'])
        with mock.patch.object(runner, '_RUNNER_IMPLEMENTATION_MATCH', False):
            self.assertFalse(runner.sources_match(source, {RUNNER: runner.RUNNER_SELF_INPUT}))

    def test_digest_boundary_same_bytes_generation_exchange_red_green(self):
        for before in ('runner_generation_before.source', None):
            source = self.source(before)
            runner = self.load(source)
            path = source / RUNNER
            raw = path.read_bytes()
            original = runner.digest
            calls = []
            def exchange(target):
                calls.append(target)
                if len(calls) == 1:
                    path.rename(path.with_suffix('.preserved'))
                    path.write_bytes(raw)
                return original(target)
            with mock.patch.object(runner, 'digest', side_effect=exchange):
                result = runner.sources_match(source, {RUNNER: runner.RUNNER_SELF_INPUT})
            if before:
                with self.assertRaises(AssertionError):
                    self.assertFalse(result, 'historical generation read accepted foreign inode')
            else:
                self.assertFalse(result)

    def test_real_timestamp_valid_stale_pyc_red_green(self):
        for before in ('runner_code_auth_before.source', None):
            source = self.source(before)
            path = source / RUNNER
            raw = path.read_bytes()
            stamp = path.stat()
            cache = Path(importlib.util.cache_from_source(str(path)))
            py_compile.compile(str(path), cfile=str(cache), doraise=True, invalidation_mode=py_compile.PycInvalidationMode.TIMESTAMP)
            changed = raw.replace(b'Loaded runner source generation changed', b'Loaded runner source GENERATION changed')
            self.assertNotEqual(raw, changed)
            self.assertEqual(len(raw), len(changed))
            path.write_bytes(changed)
            os.utime(path, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
            runner = self.load(source)
            self.assertIn('Loaded runner source generation changed', runner.resolved_sources.__code__.co_consts, 'the actual old cached body must execute')
            result = runner.sources_match(source, {RUNNER: runner.RUNNER_SELF_INPUT})
            if before:
                with self.assertRaises(AssertionError):
                    self.assertFalse(result, 'historical reader adopted newer file under stale executing bytecode')
            else:
                self.assertFalse(result)
                self.assertFalse(runner._RUNNER_IMPLEMENTATION_MATCH)
                runner.ISOLATED_SOURCES['agent_tools.tests.test_stale'] = {RUNNER: runner.RUNNER_SELF_INPUT}
                with mock.patch.object(subprocess, 'Popen', side_effect=AssertionError('stale bytecode effect')) as actor:
                    with self.assertRaises(ValueError):
                        runner.worker_groups(source, ['agent_tools.tests.test_stale'])
                    actor.assert_not_called()

    def mixed(self, before, reverse, byte_drift=False):
        source = self.source(before)
        path = source / RUNNER
        actor = "import unittest\nfrom pathlib import Path\nclass Owned(unittest.TestCase):\n def test_foreign_generation(self):\n  origin=Path(" + repr(str(path)) + ");raw=origin.read_bytes();ACT\n"
        action = "origin.write_bytes(raw+b'\\n# owned drift\\n')" if byte_drift else "origin.rename(origin.with_suffix('.preserved'));origin.write_bytes(raw)"
        actor = actor.replace('ACT', action)
        harmless = "import unittest\nclass Owned(unittest.TestCase):\n def test_owned(self):self.assertTrue(True)\n"
        # Mutate only in the second worker; both declaration orders reach closing.
        self.fixture.root = source
        first = self.fixture.module('self_first', harmless)
        second = self.fixture.module('self_second', actor)
        runner = self.load(source)
        loaded = runner._RUNNER_SOURCE_SHA256
        for index, module in enumerate((first, second)):
            relative = module.replace('.', '/') + '.py'
            token = (index == 1) if reverse else (index == 0)
            runner.ISOLATED_SOURCES[module] = {relative: runner.digest(source / relative), RUNNER: runner.RUNNER_SELF_INPUT if token else loaded}
        report, launches = self.invoke(source, runner, [first, second])
        self.assertEqual(2, report['counts']['testsRun'])
        self.assertEqual(0, report['counts']['errors'])
        self.assertEqual(2, len(launches))
        self.assertFalse(runner.sources_match(source, {RUNNER: runner.RUNNER_SELF_INPUT}))
        if not byte_drift:
            self.assertTrue(runner.sources_match(source, {RUNNER: loaded}))
        return report

    def test_actual_two_workers_merge_before_red_fixed_both_orders_green(self):
        original = self.mixed('runner_merge_before.source', False)
        with self.assertRaisesRegex(AssertionError, 'closing authority'):
            self.assertFalse(original['successful'], 'typed closing authority lost under later ordinary SHA')
        for reverse in (False, True):
            fixed = self.mixed(None, reverse)
            self.assertFalse(fixed['successful'])
            self.assertEqual('incomplete', fixed['state'])

    def test_actual_two_workers_preserve_ordinary_byte_constraints_both_orders(self):
        for reverse in (False, True):
            fixed = self.mixed(None, reverse, byte_drift=True)
            self.assertFalse(fixed['successful'])
            self.assertEqual('incomplete', fixed['state'])


if __name__ == '__main__':
    unittest.main()
