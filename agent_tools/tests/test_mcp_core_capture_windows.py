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
NATIVE_SETUP = Path(__file__).parent / 'fixtures/mcp_core_capture_native_setup'
FIELDS = ('st_dev', 'st_ino', 'st_mode', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
FILETIME_EPOCH = 116_444_736_000_000_000
FILE_BASIC_FIELDS = ('CreationTime', 'LastAccessTime', 'LastWriteTime',
                     'ChangeTime', 'FileAttributes')


def file_basic_info_api():
    """Use the documented native handle API only for the owned inert fixture."""
    import ctypes
    import msvcrt

    class BasicInfo(ctypes.Structure):
        _fields_ = [(name, ctypes.c_int64) for name in FILE_BASIC_FIELDS[:-1]] + [
            ('FileAttributes', ctypes.c_uint32)]

    if ctypes.sizeof(BasicInfo) != 40 or [getattr(BasicInfo, name).offset for name in
                                        FILE_BASIC_FIELDS] != [0, 8, 16, 24, 32]:
        raise AssertionError('Unexpected FILE_BASIC_INFO ABI')
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    functions = (kernel.GetFileInformationByHandleEx, kernel.SetFileInformationByHandle)
    for function in functions:
        function.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
        function.restype = ctypes.c_int

    class Api:
        def read(self, descriptor):
            value = BasicInfo()
            if not functions[0](msvcrt.get_osfhandle(descriptor), 0, ctypes.byref(value),
                                ctypes.sizeof(value)):
                raise ctypes.WinError(ctypes.get_last_error())
            return {name: getattr(value, name) for name in FILE_BASIC_FIELDS}

        def write(self, descriptor, values):
            value = BasicInfo(**values)
            if not functions[1](msvcrt.get_osfhandle(descriptor), 0, ctypes.byref(value),
                                ctypes.sizeof(value)):
                raise ctypes.WinError(ctypes.get_last_error())

    return Api()


def establish_native_change_time(path):
    """Set and re-read ChangeTime without relying on creation/write clock ticks."""
    api = file_basic_info_api()
    identity = lambda value: tuple(getattr(value, field) for field in FIELDS[:-1])
    descriptor = os.open(path, os.O_RDWR | getattr(os, 'O_BINARY', 0))
    try:
        original_identity = identity(os.fstat(descriptor))
        before = api.read(descriptor)
        target = max(before['CreationTime'], before['ChangeTime']) + 10_000_000
        if not 0 < target < 2**63:
            raise AssertionError('Fixture ChangeTime is out of range')
        requested = dict(before, ChangeTime=target)
        api.write(descriptor, requested)
        if api.read(descriptor) != requested:
            raise AssertionError('Fixture ChangeTime did not persist on the held handle')
        if identity(os.fstat(descriptor)) != original_identity:
            raise AssertionError('Fixture identity or content generation changed')
    finally:
        os.close(descriptor)
    descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_BINARY', 0))
    try:
        after = api.read(descriptor)
        if after != requested:
            raise AssertionError('Fixture ChangeTime did not persist after handle closure')
        if (identity(os.fstat(descriptor)) != original_identity or
                identity(os.stat(path, follow_symlinks=False)) != original_identity):
            raise AssertionError('Fixture named file differs from the held object')
    finally:
        os.close(descriptor)
    return {'before': before, 'after': after, 'requestedChangeTime': target,
            'attributeHandleClosed': True, 'readbackHandleClosed': True}


class PhysicalWindowsClockModel:
    """Model only documented Windows clocks; all file bytes/descriptors are real.

    A metadata-only utime can leave CreationTime and ChangeTime equal, as the
    retained c680 native failure did. The explicit FileBasicInfo operation is
    the sole modeled operation that establishes the requested change clock.
    This portable control does not substitute for the strict native CI case.
    """
    def __init__(self, *, fail=None):
        self.creation = FILETIME_EPOCH + 15_000_000_000_000_000
        self.change = self.creation
        self.fail = fail
        self.descriptors = []
        self.reads = 0
        self.writes = []
        self.path = None
        self.view = types.SimpleNamespace(
            name='nt', open=self.open, close=os.close, read=os.read,
            fstat=self.fstat, stat=self.named_stat, utime=self.utime,
            O_RDONLY=os.O_RDONLY, O_RDWR=os.O_RDWR, O_BINARY=getattr(os, 'O_BINARY', 0),
            O_NOFOLLOW=getattr(os, 'O_NOFOLLOW', 0))

    def open(self, path, flags):
        self.path = Path(path)
        descriptor = os.open(path, flags)
        self.descriptors.append(descriptor)
        return descriptor

    def utime(self, path, **kwargs):
        # Real metadata IO is retained. No unsupported guarantee about changing
        # the separate Windows ChangeTime is added to os.utime's contract.
        os.utime(path, **kwargs)

    def metadata(self, actual, *, named):
        values = {field: getattr(actual, field) for field in FIELDS}
        values['st_ctime_ns'] = ((self.creation if named else self.change) - FILETIME_EPOCH) * 100
        values['st_birthtime_ns'] = (self.creation - FILETIME_EPOCH) * 100
        return types.SimpleNamespace(**values)

    def named_stat(self, *args, **kwargs):
        return self.metadata(os.stat(*args, **kwargs), named=True)

    def fstat(self, descriptor):
        return self.metadata(os.fstat(descriptor), named=False)

    def read(self, descriptor):
        self.reads += 1
        actual = os.fstat(descriptor)
        result = {'CreationTime': self.creation,
                  'LastAccessTime': FILETIME_EPOCH + actual.st_atime_ns // 100,
                  'LastWriteTime': FILETIME_EPOCH + actual.st_mtime_ns // 100,
                  'ChangeTime': self.change, 'FileAttributes': 128}
        if self.fail == 'closed_readback' and self.reads == 3:
            result['ChangeTime'] -= 1
        if self.fail == 'other_field' and self.reads == 2:
            result['LastWriteTime'] += 1
        return result

    def write(self, descriptor, values):
        os.fstat(descriptor)  # A model write must target a genuinely held file.
        self.writes.append(dict(values))
        if self.fail == 'write_error':
            raise OSError('Synthetic FileBasicInfo write failure')
        if self.fail != 'noop':
            self.change = values['ChangeTime']

    def assert_closed(self, testcase):
        for descriptor in self.descriptors:
            with testcase.assertRaises(OSError) as error:
                os.fstat(descriptor)
            testcase.assertEqual(errno.EBADF, error.exception.errno)


def isolated_native_case(model, *, preserved=False):
    """Use the exact original method or current method in explicit local views."""
    source = NATIVE_SETUP / 'before.source' if preserved else Path(__file__)
    if preserved:
        provenance = json.loads((NATIVE_SETUP / 'provenance.json').read_bytes())
        raw = source.read_bytes()
        if (hashlib.sha256(raw).hexdigest() != provenance['sourceSha256'] or
                len(raw) != provenance['sourceBytes']):
            raise AssertionError('Preserved native setup source changed')
    tree = ast.parse(source.read_bytes())
    owner = next(node for node in tree.body if isinstance(node, ast.ClassDef) and
                 node.name == 'CoreCaptureWindowsTests')
    case = next(node for node in owner.body if isinstance(node, ast.FunctionDef) and
                node.name == 'test_actual_platform_file_capture_and_preserved_native_counterfactual')
    local_sys = types.SimpleNamespace(
        version='3.12.10 physical IO clock model', version_info=(3, 12, 10),
        implementation=types.SimpleNamespace(name='cpython'), modules=sys.modules)
    namespace = {'Path': Path, 'tempfile': tempfile, 'os': model.view, 'sys': local_sys,
                 'json': json, 'hashlib': hashlib, 'capture_function': capture_function,
                 'BEFORE': BEFORE, 'FIELDS': FIELDS, 'file_basic_info_api': lambda: model}
    namespace['establish_native_change_time'] = types.FunctionType(
        establish_native_change_time.__code__, namespace)
    exec(compile(ast.Module(body=[case], type_ignores=[]), str(source), 'exec'), namespace)
    return namespace[case.name]


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
            if os.name == 'nt':
                setup = establish_native_change_time(path)
                self.assertEqual(raw, path.read_bytes())
                print(json.dumps({'nativeCoreCaptureSetup': setup}), flush=True)
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


class NativeSetupClockTests(unittest.TestCase):
    source = CURRENT
    preserved_setup = False

    def test_physical_windows_setup_keeps_strict_native_assertions(self):
        model = PhysicalWindowsClockModel()
        try:
            # The causal driver can run this same positive assertion against the
            # exact retained c680 method. No production metadata is patched.
            isolated_native_case(model, preserved=self.preserved_setup)(self)
            self.assertEqual(1, len(model.writes))
            self.assertEqual(model.creation + 10_000_000, model.change)
        finally:
            model.assert_closed(self)

    def test_preserved_setup_does_not_establish_the_required_clock_split(self):
        model = PhysicalWindowsClockModel()
        try:
            with self.assertRaisesRegex(AssertionError, 'st_ctime_ns'):
                isolated_native_case(model, preserved=True)(self)
            self.assertEqual([], model.writes)
            self.assertEqual(model.creation, model.change)
        finally:
            model.assert_closed(self)

    def test_failed_noop_or_corrupt_native_readback_refuses_and_closes(self):
        for failure in ('write_error', 'noop', 'closed_readback', 'other_field'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary).resolve() / 'policy.py'
                raw = b"VALUE = 'physical private fixture'\n"
                path.write_bytes(raw)
                model = PhysicalWindowsClockModel(fail=failure)
                namespace = {'os': model.view, 'FIELDS': FIELDS, 'file_basic_info_api': lambda: model}
                helper = types.FunctionType(establish_native_change_time.__code__, namespace)
                try:
                    with self.assertRaises((OSError, AssertionError)):
                        helper(path)
                    self.assertEqual(raw, path.read_bytes())
                finally:
                    model.assert_closed(self)

    def test_requested_clock_is_distinct_even_when_clocks_already_differ(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary).resolve() / 'policy.py'
            raw = b"VALUE = 'same owned file bytes'\n"
            path.write_bytes(raw)
            original = path.stat()
            model = PhysicalWindowsClockModel()
            model.change += 20_000_000
            namespace = {'os': model.view, 'FIELDS': FIELDS, 'file_basic_info_api': lambda: model}
            helper = types.FunctionType(establish_native_change_time.__code__, namespace)
            try:
                evidence = helper(path)
                self.assertEqual(model.creation + 30_000_000, evidence['requestedChangeTime'])
                self.assertEqual(evidence['requestedChangeTime'], evidence['after']['ChangeTime'])
                self.assertEqual(evidence['before']['CreationTime'], evidence['after']['CreationTime'])
                self.assertTrue(evidence['attributeHandleClosed'])
                self.assertTrue(evidence['readbackHandleClosed'])
                self.assertEqual((original.st_dev, original.st_ino), (path.stat().st_dev, path.stat().st_ino))
                self.assertEqual(raw, path.read_bytes())
            finally:
                model.assert_closed(self)


if __name__ == '__main__':
    unittest.main()
