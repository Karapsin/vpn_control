"""Actual interrupted FreshChannelTests setup; local TempFS custody, no SSH actors."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import types
import unittest
import uuid
from agent_tools import agent_test_runner as runner

ROOT = Path(__file__).resolve().parents[2]
BEFORE = 'agent_tools/tests/fixtures/ssh_fresh_fixture_custody_before.source'
BEFORE_SHA256 = '80e9fd0e34cd98e67826acdd065796695c67307948083c1e65df428c4114cef6'
# Exact executed setup-only import closure observed in actual child custody replay.
# This finite source-copy fixture grants no complete DIRECT-group admission.
SETUP_SOURCES = (
    'agent_tools/agent_test_runner.py',
    'agent_tools/private_inventory_lock.py',
    'agent_tools/readiness.py',
    'agent_tools/ssh_channel_inventory_diagnostics.py',
    'agent_tools/ssh_connection_recovery.py',
    'agent_tools/ssh_connection_session.py',
    'agent_tools/ssh_fresh_nested_channel.py',
    'agent_tools/ssh_nested_socket_noninteractive_observation.py',
    'agent_tools/ssh_nested_socket_owned_home_observation.py',
    'agent_tools/ssh_nested_socket_retirement.py',
    'agent_tools/ssh_nested_socket_route_diagnostic.py',
    'agent_tools/ssh_recovery_adoption.py',
    'agent_tools/ssh_transport.py',
    'agent_tools/tests/test_ssh_connection_session.py',
    'agent_tools/tests/test_ssh_fresh_nested_channel.py',
    'agent_tools/tests/fixtures/ssh_fresh_fixture_custody_before.source',
)
CAPABLE = (os.name == 'posix' and hasattr(socket, 'AF_UNIX')
           and all(hasattr(os, name) for name in ('O_NOFOLLOW', 'O_DIRECTORY', 'getuid', 'getgid', 'killpg'))
           and importlib.util.find_spec('fcntl') is not None)

CHILD = r'''import hashlib,json,os,sys,tempfile
from pathlib import Path
from unittest import mock
context=Path(sys.argv[1]).resolve();sys.path.insert(0,str(context))
from agent_tools.tests import test_ssh_fresh_nested_channel as helper
if sys.argv[2]=='before':
 source=context/'agent_tools/tests/fixtures/ssh_fresh_fixture_custody_before.source'
 raw=source.read_bytes()
 assert hashlib.sha256(raw).hexdigest()=='80e9fd0e34cd98e67826acdd065796695c67307948083c1e65df428c4114cef6'
 namespace=dict(vars(helper));exec(compile(raw,str(source),'exec'),namespace)
 helper.FreshChannelTests.setUp=namespace['setUp']
def emit(value):os.write(1,(json.dumps(value,sort_keys=True)+'\n').encode())
real_temporary=tempfile.TemporaryDirectory
def tracked(*args,**kwargs):
 temp=real_temporary(*args,**kwargs);p=Path(temp.name).resolve();s=p.stat()
 emit({'event':'created','path':str(p),'generation':[s.st_dev,s.st_ino,s.st_uid]})
 return temp
case=helper.FreshChannelTests('runTest')
with mock.patch.object(tempfile,'TemporaryDirectory',side_effect=tracked):case.setUp()
loaded={name:str(Path(module.__file__).resolve()) for name,module in sys.modules.items()
        if (name=='agent_tools' or name.startswith('agent_tools.')) and getattr(module,'__file__',None)}
assert all(Path(path).is_relative_to(context) for path in loaded.values()),loaded
sockets=[argv[argv.index('-S')+1] for argv in case.f.spawns]
emit({'event':'setup','pid':os.getpid(),'root':str(case.root),'vcfRoot':str(case.root.parent),
      'sourceImports':loaded,'socketPaths':sockets,'socketPathBytes':[len(os.fsencode(p)) for p in sockets],
      'managedMarker':os.environ.get('VPN_CONTROL_TEST_RUNTIME_ROOT'),'tempdir':tempfile.gettempdir()})
os._exit(0)
'''


@unittest.skipUnless(CAPABLE, 'POSIX owned child sessions, protected directory FDs, fcntl and Unix sockets required')
class FreshFixtureCustodyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.evidence = Path(self.temporary.name).resolve()
        self.evidence.chmod(0o700)
        self.sequence = 0

    def release_known(self, path, pin):
        if os.path.lexists(path):
            self.assertTrue(runner.cleanup_fixture_root(path, pin), 'refused owned fixture cleanup; preserve evidence')

    def child(self, *, before=False, managed=True):
        self.sequence += 1
        leaf = self.evidence / str(self.sequence)
        leaf.mkdir(mode=0o700)
        sources = {path: runner.digest(ROOT / path) for path in SETUP_SOURCES}
        self.assertEqual(BEFORE_SHA256, sources[BEFORE])
        context = runner.source_context(ROOT, leaf, sources)
        plan = {'schemaVersion': 1, 'sourceFingerprint': 'a' * 64,
                'modules': ['agent_tools.tests.test_ssh_fresh_fixture_custody'], 'maxWorkers': 1}
        fixture, pin = runner.worker_fixture_root(ROOT, leaf, plan)
        self.addCleanup(self.release_known, fixture, pin)
        env = {**os.environ, 'TMPDIR': str(fixture / 'tmp'), 'TMP': str(fixture / 'tmp'), 'TEMP': str(fixture / 'tmp'),
               'VPN_CONTROL_TEST_RUNTIME_ROOT': str(fixture / 'runtime'), 'VPN_CONTROL_TEST_LOCK_ROOT': str(fixture / 'locks'),
               'PYTHONDONTWRITEBYTECODE': '1'}
        env.pop('DYLD_INSERT_LIBRARIES', None)
        if not managed:
            env.pop('VPN_CONTROL_TEST_RUNTIME_ROOT')
        process = subprocess.Popen([sys.executable, '-I', '-B', '-c', CHILD, str(context), 'before' if before else 'current'],
                                   cwd=context, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        timed_out = False
        try:
            out, err = process.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            timed_out = True
            runner._stop_workers([{'process': process}])
            out, err = process.communicate()
        (leaf / 'stdout.raw').write_bytes(out)
        (leaf / 'stderr.raw').write_bytes(err)
        (leaf / 'child-terminal.json').write_text(json.dumps({'pid': process.pid, 'exitCode': process.returncode,
                'timeout': timed_out, 'fixtureRoot': str(fixture), 'fixtureGeneration': pin}) + '\n')
        rows = [json.loads(line) for line in out.splitlines()]
        # Every actual created temporary root is published immediately, including
        # a setup failure. Cleanup authority comes only from recorded generations.
        for row in rows:
            if row['event'] == 'created':
                self.addCleanup(self.release_known, Path(row['path']), row['generation'])
        self.assertFalse(timed_out, 'owned local helper setup exceeded bound')
        self.assertEqual(0, process.returncode, err.decode())
        closed, leaked = runner.close_session(process)
        self.assertTrue(closed)
        self.assertFalse(leaked)
        setup = next(row for row in rows if row['event'] == 'setup')
        self.assertEqual(process.pid, setup['pid'])
        self.assertTrue(setup['socketPaths'], 'actual fixture must bind its Unix socket')
        self.assertTrue(all(Path(path).exists() for path in setup['socketPaths']))
        return fixture, pin, setup

    def criterion(self, fixture, facts):
        self.assertTrue(Path(facts['vcfRoot']).is_relative_to(fixture), 'actual helper escaped managed fixture custody')

    def test_whole_before_missing_readiness_red_current_custody_green(self):
        path = ROOT / 'agent_tools/tests/fixtures/ssh_generated_dependency_closure_before/fresh_fixture.before.source'
        raw = path.read_bytes()
        self.assertEqual('5c5fd77f2903b3e7a729fa29612191515f91e30c60e5d94e969ac393cee66d72', hashlib.sha256(raw).hexdigest())
        original = types.ModuleType('_fresh_dependency_before_' + uuid.uuid4().hex)
        original.__file__ = __file__
        exec(compile(raw, str(path), 'exec'), original.__dict__)
        result = unittest.TestResult()
        original.FreshFixtureCustodyTests('test_actual_interrupted_foreign_generation_refused').run(result)
        self.assertEqual(1, len(result.failures))
        self.assertFalse(result.errors)
        self.assertIn("cannot import name 'readiness'", result.failures[0][1])
        current = unittest.TestResult()
        FreshFixtureCustodyTests('test_actual_interrupted_foreign_generation_refused').run(current)
        self.assertTrue(current.wasSuccessful(), current.failures + current.errors)

    def test_actual_interrupted_before_red_current_green(self):
        fixture, pin, original = self.child(before=True)
        with self.assertRaisesRegex(AssertionError, 'escaped managed fixture custody'):
            self.criterion(fixture, original)
        self.assertTrue(runner.cleanup_fixture_root(fixture, pin))
        self.assertTrue(Path(original['vcfRoot']).exists(), 'original escape must survive managed cleanup')
        fixed_root, fixed_pin, current = self.child()
        self.criterion(fixed_root, current)
        self.assertEqual(str(fixed_root / 'tmp'), current['tempdir'])
        self.assertEqual(str(fixed_root / 'runtime'), current['managedMarker'])
        self.assertEqual(original['socketPathBytes'], current['socketPathBytes'])
        self.assertTrue(runner.cleanup_fixture_root(fixed_root, fixed_pin))
        self.assertFalse(Path(current['vcfRoot']).exists())
        self.assertTrue(all(not Path(path).exists() for path in current['socketPaths']))

    def test_actual_interrupted_foreign_generation_refused(self):
        fixture, pin, current = self.child()
        self.criterion(fixture, current)
        moved = fixture.with_name(fixture.name + '-moved-' + uuid.uuid4().hex)
        fixture.rename(moved)
        self.addCleanup(self.release_known, moved, pin)
        fixture.mkdir(mode=0o700)
        replacement_pin = runner.fixture_generation(fixture)
        self.addCleanup(self.release_known, fixture, replacement_pin)
        sentinel = fixture / 'foreign-sentinel'
        sentinel.write_bytes(b'owned inert foreign replacement')
        self.assertFalse(runner.cleanup_fixture_root(fixture, pin))
        self.assertEqual(b'owned inert foreign replacement', sentinel.read_bytes())
        self.assertTrue(moved.exists())
        self.assertTrue(runner.cleanup_fixture_root(moved, pin))
        self.assertTrue(runner.cleanup_fixture_root(fixture, replacement_pin))

    def test_actual_standalone_parent_is_system_short_tmp(self):
        fixture, pin, current = self.child(managed=False)
        self.assertIsNone(current['managedMarker'])
        self.assertEqual(Path('/tmp').resolve(), Path(current['vcfRoot']).parent)
        self.assertFalse(Path(current['vcfRoot']).is_relative_to(fixture))
        self.assertTrue(runner.cleanup_fixture_root(fixture, pin))
        self.assertTrue(Path(current['vcfRoot']).exists())


if __name__ == '__main__':
    unittest.main()
