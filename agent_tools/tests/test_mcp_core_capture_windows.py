"""Core capture retains generations without comparing different Windows clocks."""
import ast
import errno
import hashlib
import importlib.util
import json
import os
import stat
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path


FIXTURES = Path(__file__).parent / 'fixtures/mcp_core_capture_windows'
CURRENT = Path(__file__).resolve().parents[1] / 'mcp_server.py'
BEFORE = FIXTURES / 'captured_core.before.source'
FIELDS = ('st_dev', 'st_ino', 'st_mode', 'st_size', 'st_mtime_ns', 'st_ctime_ns')


def capture_function(source, root, os_view):
    """Execute only the explicit capture function, with an owned policy directory."""
    node = next(n for n in ast.parse(source.read_bytes()).body
                if isinstance(n, ast.FunctionDef) and n.name == '_captured_core')
    namespace = {'Path': Path, 'os': os_view, 'stat': stat,
                 'importlib': importlib, 'sys': sys, 'hashlib': hashlib,
                 '__file__': str(root / 'mcp_server.py'),
                 '_MCP_BOOT_TIME_NS': time.monotonic_ns(), '_CORE_IMPORT_DIGESTS': {}}
    exec(compile(ast.Module(body=[node], type_ignores=[]), str(source), 'exec'), namespace)
    return namespace


class CaptureFixture:
    def __init__(self, root, *, windows=True, mutations=None):
        self.root = root.resolve()
        self.path = self.root / 'policy.py'
        self.raw = b"VALUE = 'captured actual policy bytes'\n"
        self.path.write_bytes(self.raw)
        self.descriptors = []
        self.calls = {'stat': 0, 'fstat': 0}
        self.mutations = mutations or {}
        self.birthtime = 1_500_000_000_000_000_000
        self.windows = windows
        self.view = types.SimpleNamespace(
            name='nt' if windows else 'posix', open=self.open, read=os.read,
            close=os.close, fstat=self.fstat, stat=self.named_stat,
            O_RDONLY=os.O_RDONLY, O_NOFOLLOW=getattr(os, 'O_NOFOLLOW', 0))

    def open(self, *args, **kwargs):
        fd = os.open(*args, **kwargs)
        self.descriptors.append(fd)
        return fd

    def metadata(self, kind, actual):
        self.calls[kind] += 1
        values = {field: getattr(actual, field) for field in FIELDS}
        # CPython 3.12.10: named stat exposes CreationTime as ctime;
        # fstat exposes ChangeTime. All other physical fields remain real.
        if self.windows:
            values['st_birthtime_ns'] = self.birthtime
            values['st_ctime_ns'] = self.birthtime if kind == 'stat' else self.birthtime + 100
        values.update(self.mutations.get((kind, self.calls[kind]), {}))
        return types.SimpleNamespace(**values)

    def named_stat(self, *args, **kwargs):
        return self.metadata('stat', os.stat(*args, **kwargs))

    def fstat(self, *args, **kwargs):
        return self.metadata('fstat', os.fstat(*args, **kwargs))

    def assert_closed(self, testcase):
        for fd in self.descriptors:
            with testcase.assertRaises(OSError) as error:
                os.fstat(fd)
            testcase.assertEqual(errno.EBADF, error.exception.errno)


class CoreCaptureWindowsTests(unittest.TestCase):
    source = CURRENT

    def invoke(self, fixture, source=None):
        namespace = capture_function(source or self.source, fixture.root, fixture.view)
        module = namespace['_captured_core']('policy')
        self.addCleanup(sys.modules.pop, module.__name__, None)
        return module, namespace

    def test_unchanged_windows_creation_and_change_times_capture_actual_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = CaptureFixture(Path(temporary))
            try:
                module, namespace = self.invoke(fixture)
                self.assertEqual('captured actual policy bytes', module.VALUE)
                self.assertEqual({fixture.path: hashlib.sha256(fixture.raw).hexdigest()},
                                 namespace['_CORE_IMPORT_DIGESTS'])
            finally:
                fixture.assert_closed(self)

    def test_preserved_original_refuses_the_same_unchanged_windows_metadata(self):
        provenance = json.loads((FIXTURES / 'provenance.json').read_bytes())
        self.assertEqual(provenance['fragmentSha256'], hashlib.sha256(BEFORE.read_bytes()).hexdigest())
        with tempfile.TemporaryDirectory() as temporary:
            fixture = CaptureFixture(Path(temporary))
            with self.assertRaisesRegex(ValueError, 'Core source capture changed'):
                self.invoke(fixture, BEFORE)
            fixture.assert_closed(self)

    def test_each_api_generation_field_still_refuses_changes(self):
        for kind in ('stat', 'fstat'):
            for field in FIELDS:
                with self.subTest(api=kind, field=field), tempfile.TemporaryDirectory() as temporary:
                    fixture = CaptureFixture(Path(temporary))
                    actual = getattr(os.stat(fixture.path), field)
                    replacement = fixture.birthtime + 200 if field == 'st_ctime_ns' else actual + 1
                    fixture.mutations[(kind, 2)] = {field: replacement}
                    with self.assertRaisesRegex(ValueError, 'Core source capture changed'):
                        self.invoke(fixture)
                    fixture.assert_closed(self)

    def test_cross_api_object_fields_still_refuse_stable_different_objects(self):
        for field in FIELDS[:-1]:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temporary:
                fixture = CaptureFixture(Path(temporary))
                replacement = getattr(os.stat(fixture.path), field) + 1
                fixture.mutations = {('stat', n): {field: replacement} for n in (1, 2)}
                with self.assertRaisesRegex(ValueError, 'Core source capture changed'):
                    self.invoke(fixture)
                fixture.assert_closed(self)

    def test_birthtime_difference_or_one_sided_presence_refuses(self):
        for missing in (False, True):
            with self.subTest(missing=missing), tempfile.TemporaryDirectory() as temporary:
                fixture = CaptureFixture(Path(temporary))
                original = fixture.view.stat
                def named(*args, **kwargs):
                    value = original(*args, **kwargs)
                    if missing:
                        del value.st_birthtime_ns
                    else:
                        value.st_birthtime_ns += 1
                    return value
                fixture.view.stat = named
                with self.assertRaisesRegex(ValueError, 'Core source capture changed'):
                    self.invoke(fixture)
                fixture.assert_closed(self)

    def test_posix_cross_api_ctime_difference_still_refuses(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = CaptureFixture(Path(temporary), windows=False)
            changed = os.stat(fixture.path).st_ctime_ns + 100
            fixture.mutations = {('stat', n): {'st_ctime_ns': changed} for n in (1, 2)}
            with self.assertRaisesRegex(ValueError, 'Core source capture changed'):
                self.invoke(fixture)
            fixture.assert_closed(self)

    def test_empty_oversize_and_short_reads_still_refuse_before_execution(self):
        for raw, short in ((b'', False), (b'#' * (1024**2 + 1), False), (b'VALUE=1\n', True)):
            with self.subTest(size=len(raw), short=short), tempfile.TemporaryDirectory() as temporary:
                fixture = CaptureFixture(Path(temporary))
                fixture.path.write_bytes(raw)
                if short:
                    fixture.view.read = lambda fd, size: os.read(fd, 1)
                namespace = capture_function(self.source, fixture.root, fixture.view)
                with self.assertRaisesRegex(ValueError, 'Core source capture changed'):
                    namespace['_captured_core']('policy')
                self.assertEqual({}, namespace['_CORE_IMPORT_DIGESTS'])
                fixture.assert_closed(self)

    def test_actual_platform_file_capture_and_preserved_native_counterfactual(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            path = root / 'policy.py'
            raw = b"VALUE = 'native stable file'\n"
            path.write_bytes(raw)
            metadata = path.stat()
            os.utime(path, ns=(metadata.st_atime_ns, metadata.st_mtime_ns - 1_000_000_000))
            descriptor = os.open(path, os.O_RDONLY)
            try:
                named = os.stat(path, follow_symlinks=False)
                held = os.fstat(descriptor)
            finally:
                os.close(descriptor)
            namespace = capture_function(self.source, root, os)
            module = namespace['_captured_core']('policy')
            self.addCleanup(sys.modules.pop, module.__name__, None)
            self.assertEqual('native stable file', module.VALUE)
            self.assertEqual(hashlib.sha256(raw).hexdigest(), namespace['_CORE_IMPORT_DIGESTS'][path])
            different = [field for field in FIELDS if getattr(named, field) != getattr(held, field)]
            if os.name == 'nt':
                print(json.dumps({'nativeCoreCaptureMetadata': {
                    'python': sys.version.split()[0], 'differentFields': different,
                    'named': {field: getattr(named, field) for field in FIELDS},
                    'descriptor': {field: getattr(held, field) for field in FIELDS}}}), flush=True)
                if sys.implementation.name == 'cpython' and sys.version_info[:3] == (3, 12, 10):
                    self.assertEqual(['st_ctime_ns'], different,
                                     'The original Windows CI runtime must prove the ctime mechanism')
            if os.name == 'nt' and different:
                self.assertEqual(['st_ctime_ns'], different)
                original = capture_function(BEFORE, root, os)
                with self.assertRaisesRegex(ValueError, 'Core source capture changed'):
                    original['_captured_core']('policy')
                print(json.dumps({'nativeCoreCapture': 'preserved_original_RED_fixed_GREEN',
                                  'python': sys.version.split()[0], 'differentFields': different}), flush=True)


if __name__ == '__main__':
    unittest.main()
