"""Physical fixture ownership regression; never execute QEMU or start a guest."""
import ast
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import textwrap
from types import SimpleNamespace
import unittest
import uuid
from unittest.mock import patch

from agent_tools.tests import test_windows_parallel_vm_launch as subject

FIXTURE = Path(__file__).with_name('fixtures') / 'whole_observer_binary'
BEFORE_SHA256 = '26c0f22608797c55fe2fbc54c617078dd9deb27646a868ece332771d68d70e4b'
ORIGINAL_TEST_SHA256 = 'bccde1f485c81b12c1493d3362918e6d52ff8cb782034e3e73e1e075ad09bc59'
_USE_BEFORE = False


class _IntentReached(RuntimeError):
    pass


def _initializer(case, source, before):
    raw = (FIXTURE / 'fixture.before.fragment').read_bytes()
    provenance = json.loads((FIXTURE / 'provenance.json').read_bytes())
    if (hashlib.sha256(raw).hexdigest() != BEFORE_SHA256
            or provenance['fragmentSha256'] != BEFORE_SHA256
            or provenance['originalTestSha256'] != ORIGINAL_TEST_SHA256):
        raise ValueError('whole-observer-before-source')
    if before:
        code = compile(textwrap.dedent(raw.decode()), 'sha256:' + BEFORE_SHA256, 'exec')
    else:
        tree = ast.parse(Path(subject.__file__).read_bytes())
        owner = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'WholeObserverTest')
        setup = next(n for n in owner.body if isinstance(n, ast.FunctionDef) and n.name == 'setUp')
        assignments = [n for n in setup.body if isinstance(n, ast.Assign)
                       and any(isinstance(t, ast.Attribute) and isinstance(t.value, ast.Name)
                               and t.value.id == 'self' and t.attr == 'binary' for t in n.targets)]
        if (len(assignments) != 1 or not isinstance(assignments[0].value, ast.Call)
                or not isinstance(assignments[0].value.func, ast.Name)
                or assignments[0].value.func.id != '_owned_observer_binary'):
            raise ValueError('whole-observer-current-initializer')
        code = compile(ast.Module(body=assignments, type_ignores=[]), 'actual WholeObserverTest binary initializer', 'exec')
    def discover(name):
        if name != 'qemu-img':
            raise ValueError('fixture-discovery-name')
        return str(source)
    namespace = {'self': case, 'Path': Path, 'shutil': SimpleNamespace(which=discover),
                 'installed_binary': source, '_owned_observer_binary': subject._owned_observer_binary}
    exec(code, namespace)


def _foreign_executable(case):
    for name in ('/bin/echo', '/usr/bin/true', '/bin/true'):
        path = Path(name).resolve()
        try:
            info = path.lstat()
        except FileNotFoundError:
            continue
        if (stat.S_ISREG(info.st_mode) and info.st_uid != os.getuid()
                and not info.st_mode & 0o022 and os.access(path, os.X_OK)):
            return path
    case.skipTest('Physical installed executable with a different UID required for the ownership counterfactual')


def _strict_boundary(case, before):
    launch = subject.launch
    source = _foreign_executable(case)
    source_before = launch.inventory.generation(source.lstat())
    temporary = tempfile.TemporaryDirectory()
    case.addCleanup(temporary.cleanup)
    root = Path(temporary.name).resolve();root.chmod(0o700)
    state = SimpleNamespace(root=root)
    _initializer(state, source, before)
    parent = root / 'template';parent.mkdir(mode=0o750)
    image = parent / 'template.qcow2';image.write_bytes(b'INERT_IMAGE_NEVER_SUBMITTED_TO_QEMU');image.chmod(0o440)
    guests = tuple(root / slot for slot in ('secondary', 'tertiary'))
    for guest in guests:
        guest.mkdir(mode=0o700);overlay=guest/'disk.qcow2';overlay.write_bytes(b'OWNED_OVERLAY');overlay.chmod(0o600)
    proc = root / 'proc';proc.mkdir();(proc/'net').mkdir()
    for name in ('tcp', 'tcp6'):
        (proc/'net'/name).write_text('header\n')
    correlation = str(uuid.uuid4())
    expected = {'state':'prepared','correlationId':str(uuid.uuid4()),'template':str(image),
        'templateGeneration':launch.inventory.generation(image.lstat()),
        'templateSha256':hashlib.sha256(image.read_bytes()).hexdigest(),
        'overlays':[{'path':str(g/'disk.qcow2'),'generation':launch.inventory.generation((g/'disk.qcow2').lstat()),
                     'guestGeneration':launch.inventory.parent_identity(g.lstat())} for g in guests],
        'nativeGuestStarted':False,'launchAdmitted':False,'productAcceptance':False}
    observed = {'phase':None,'intentCount':0,'installedGeneration':source_before,
                'readerGeneration':launch.inventory.generation(state.binary.lstat()),'trustedUid':os.getuid()}
    writer = launch.prepare.record_at
    def at_intent(fd, name, value):
        writer(fd, name, value)
        if name == 'intent.json':
            observed['intentCount'] += 1
            observed['intentBinaryGeneration'] = value['qemuImg']['generation']
            observed['phase'] = 'intent-recorded'
            raise _IntentReached('Physical strict binary guard passed; stop before any executable dispatch')
    with patch.object(launch.prepare, 'record_at', side_effect=at_intent), patch.object(
            launch, 'held_virtual_prefix', side_effect=AssertionError('No native executable may be dispatched')) as reader:
        try:
            launch.observed_boot((image,guests,proc,state.binary,root,os.getuid()),expected,correlation)
        except _IntentReached:
            pass
        except ValueError as error:
            observed['phase'] = str(error)
        case.assertEqual(reader.call_count, 0)
    case.assertEqual(source_before, launch.inventory.generation(source.lstat()))
    evidence = parent / ('boot-read-' + correlation)
    case.assertFalse((evidence/'result.json').exists())
    case.assertFalse((evidence/'boot-prefix.private').exists())
    if not before:
        unknown = json.loads((evidence/'unknown.json').read_bytes())
        case.assertEqual(unknown['state'], 'unknown')
        case.assertFalse(unknown['nativeGuestStarted']);case.assertFalse(unknown['launchAdmitted'])
    print(json.dumps({'wholeObserverBinaryCounterfactual':observed,'before':before,
                      'nativeExecutableDispatched':False},sort_keys=True),flush=True)
    return observed


def _assert_positive(case, observed):
    case.assertEqual(observed['phase'], 'intent-recorded')
    case.assertEqual(observed['intentCount'], 1)
    case.assertEqual(observed['readerGeneration'][3], observed['trustedUid'])
    case.assertNotEqual(observed['readerGeneration'][:2], observed['installedGeneration'][:2])
    case.assertEqual(observed['readerGeneration'], observed['intentBinaryGeneration'])


@unittest.skipUnless(os.name == 'posix', 'Actual POSIX UID and no-follow fixture ownership required')
class WholeObserverBinaryFixtureTests(unittest.TestCase):
    def test_actual_initializer_reaches_strict_intent_boundary(self):
        _assert_positive(self, _strict_boundary(self, _USE_BEFORE))

    def test_preserved_initializer_is_rejected_by_same_actual_guard(self):
        _foreign_executable(self)
        observations = []
        class Before(unittest.TestCase):
            def runTest(inner):
                value = _strict_boundary(inner, True);observations.append(value)
                _assert_positive(inner, value)
        result = unittest.TestResult()
        unittest.TestSuite([Before()]).run(result)
        self.assertEqual(result.testsRun, 1);self.assertEqual(len(result.failures), 1)
        self.assertEqual(result.errors, []);self.assertEqual(result.skipped, [])
        self.assertEqual(len(observations), 1)
        self.assertEqual(observations[0]['phase'], 'boot-binary-trust')
        self.assertEqual(observations[0]['intentCount'], 0)
        self.assertNotEqual(observations[0]['readerGeneration'][3], observations[0]['trustedUid'])

    def test_owned_copy_keeps_source_bytes_generation_and_current_uid(self):
        source = _foreign_executable(self)
        before = subject.launch.inventory.generation(source.lstat())
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve();root.chmod(0o700)
            target=subject._owned_observer_binary(root,source)
            info=target.lstat()
            self.assertEqual(target.parent,root);self.assertTrue(stat.S_ISREG(info.st_mode))
            self.assertEqual(info.st_uid,os.getuid());self.assertEqual(info.st_nlink,1)
            self.assertEqual(stat.S_IMODE(info.st_mode),0o500)
            self.assertNotEqual((info.st_dev,info.st_ino),tuple(before[:2]))
            self.assertEqual(target.read_bytes(),source.read_bytes())
        self.assertEqual(before,subject.launch.inventory.generation(source.lstat()))

    def test_existing_owned_destination_is_preserved(self):
        source=_foreign_executable(self)
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve();target=root/'owned-qemu-img-reader';target.write_bytes(b'KEEP_EXISTING')
            pin=subject.launch.inventory.generation(target.lstat())
            with self.assertRaises(FileExistsError):subject._owned_observer_binary(root,source)
            self.assertEqual(target.read_bytes(),b'KEEP_EXISTING')
            self.assertEqual(pin,subject.launch.inventory.generation(target.lstat()))

    def test_destination_symlink_is_preserved_without_touching_source(self):
        source=_foreign_executable(self);pin=subject.launch.inventory.generation(source.lstat())
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve();target=root/'owned-qemu-img-reader';target.symlink_to(source)
            with self.assertRaises(FileExistsError):subject._owned_observer_binary(root,source)
            self.assertTrue(target.is_symlink());self.assertEqual(target.resolve(),source)
        self.assertEqual(pin,subject.launch.inventory.generation(source.lstat()))

    def test_oversized_physical_source_refuses_before_destination_creation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve();source=root/'oversized-source'
            with source.open('wb') as output:output.truncate(33554433)
            source.chmod(0o500)
            with self.assertRaisesRegex(ValueError,'fixture-reader-source'):
                subject._owned_observer_binary(root,source)
            self.assertFalse((root/'owned-qemu-img-reader').exists())


if __name__ == '__main__':
    if '--fixture-red' in sys.argv:
        _USE_BEFORE=True;sys.argv.remove('--fixture-red')
        unittest.main(defaultTest='WholeObserverBinaryFixtureTests.test_actual_initializer_reaches_strict_intent_boundary')
    else:
        unittest.main()
