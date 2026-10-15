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
        with self.assertRaisesRegex(ValueError, '^package-fixed-source$'):
            assert_current_package_body(self, before_context())

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


if __name__ == '__main__':
    unittest.main()
