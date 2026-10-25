"""Whole-before RED/GREEN for the staged API35 update worker's readiness tail.

The unfixed factory compiled the current lifecycle main() unchanged after its
readiness tail was added, so the staged component namespace re-admitted through
agent_tools.readiness_entrypoints and failed with ImportError. The current
factory replaces only that exact tail with the actor's outer task guard. Real
staged bundle modules; `_run_admitted` is a recorder, so no device effects.
"""
import hashlib, json, os, types, unittest
from pathlib import Path
from unittest import mock
from agent_tools import android_installer_component_bundle as bundle
from agent_tools.tests import test_android_installer_component_bundle as bf

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).parent / 'fixtures/android_update_staged_readiness'
BEFORE = FIXTURES / 'android_installer_outer_transport.before.source'
CURRENT = ROOT / 'agent_tools/android_installer_outer_transport.py'
LIFECYCLE = ROOT / 'scripts/android_installer_lifecycle.py'


class Guard:
    def __init__(self):
        self.calls = 0

    def _task_guard(self):
        self.calls += 1


@unittest.skipUnless(os.name == 'posix', 'POSIX staged component bundle fixture')
class StagedReadiness(unittest.TestCase):
    def setUp(self):
        self.fixture = bf.BundleTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        self.selected, self.backend, self.args, *_ = self.fixture.api35_fixture()
        self.args.device_port = 45635
        self.args.reconciliation_timeout_seconds = 5.0
        self.args.reconciliation_poll_seconds = 0.01
        self.lifecycle = self.selected['lifecycle']
        self.calls = []

    def entry(self, path, component_bundle=bundle):
        scope = {'__name__': 'staged_update_entry', 'COMPONENT_BUNDLE': component_bundle,
                 'COMPONENT_RECEIPT': self.fixture.receipt}
        exec(compile(path.read_bytes(), str(path), 'exec'), scope)
        return scope

    def record(self, args):
        self.calls.append((args.readiness_admission, dict(args.cli_environment)))

    def test_whole_before_staged_main_reimports_unstaged_readiness(self):
        scope = self.entry(BEFORE)
        with mock.patch.object(self.lifecycle, '_run_admitted', side_effect=self.record):
            main = scope['update_main_factory'](self.selected, self.args, self.backend)
            with self.assertRaisesRegex(ImportError, 'readiness_entrypoints'):
                main()
        self.assertEqual(self.calls, [])

    def test_current_staged_main_binds_outer_guard_without_second_admission(self):
        scope = self.entry(CURRENT)
        guard = Guard()
        environment = self.selected['tls'].public_cli_environment(
            self.args.adb, self.args.cli, self.backend['LAUNCH']['environment'])
        with mock.patch.object(self.lifecycle, '_run_admitted', side_effect=self.record):
            scope['update_main_factory'](self.selected, self.args, self.backend, guard)()
        [(admission, observed)] = self.calls
        self.assertIs(type(admission), scope['UpdateOuterAdmission'])
        self.assertEqual(observed, environment)
        self.assertEqual(guard.calls, 0)
        with self.assertRaisesRegex(ValueError, 'update_readiness_admission_closed'):
            admission.revalidate()
        self.assertFalse((Path(self.lifecycle.__file__).resolve().parents[1] / '.rag_index').exists())

    def test_current_outer_admission_revalidates_only_the_task_guard(self):
        guard = Guard()
        admission = self.entry(CURRENT)['UpdateOuterAdmission'](guard)
        admission.revalidate(); admission.revalidate()
        self.assertEqual(guard.calls, 2)
        admission.close()
        with self.assertRaisesRegex(ValueError, 'update_readiness_admission_closed'):
            admission.revalidate()
        self.assertEqual(guard.calls, 2)

    def test_changed_or_missing_readiness_tail_refuses_before_compile(self):
        source = LIFECYCLE.read_text()
        changed = source.replace('"serverPort": int(port)}', '"serverPort": 5037}')
        missing = source.replace('        _run_admitted(args)\n    finally:', '        pass\n    finally:')
        self.assertNotEqual(changed, source)
        self.assertNotEqual(missing, source)
        for variant in (changed, missing):
            with self.subTest(variant=hashlib.sha256(variant.encode()).hexdigest()[:8]):
                staged = types.SimpleNamespace(load=lambda receipt, raw=variant: {'scripts/android_installer_lifecycle.py': raw})
                scope = self.entry(CURRENT, staged)
                with self.assertRaisesRegex(ValueError, 'update_main_readiness_changed'):
                    scope['update_main_factory'](self.selected, self.args, self.backend, Guard())


class Provenance(unittest.TestCase):
    def test_retained_whole_before_artifact_has_exact_custody(self):
        provenance = json.loads((FIXTURES / 'provenance.json').read_bytes())
        self.assertFalse(provenance['nativeFailureClaimed'])
        for leaf, pin in provenance['files'].items():
            self.assertEqual(pin['sha256'], hashlib.sha256((FIXTURES / leaf).read_bytes()).hexdigest(), leaf)


if __name__ == '__main__':
    unittest.main()
