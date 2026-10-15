"""Real Git checkout bytes through the unchanged Windows specimen readers.

The old attributes and exact reader functions come from the failed pushed
commit. These local checkouts contain only public inert fixtures. They do not
execute PowerShell or substitute for the native Windows TLS/reader scenarios.
"""
import argparse
import ast
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = Path(__file__).parent / 'fixtures/windows_fixture_checkout_bytes'
SOURCE_COMMIT = '9a6d4b3cf4850750253af8339a12b9d7b425e5f1'
RETAINED = {
    'attributes.before': '24292b5225a15661aa7fcbac6f2d3f5735f19059b7f1b8a5b35aad6021f06645',
    'https_reader.before.source': '68c97624a654cf24d18264ff1b6ee19ca77348faeb5c430c1eeb687405116f32',
    'cleanup_reader.before.source': '17f32cd53627ba387912bc7e730ca6bd854bc7e2fdfe6827b1782bf43d7be4c8',
}
HTTPS_FOLDER = 'agent_tools/tests/fixtures/windows_ordinary_https'
CLEANUP_FOLDER = 'agent_tools/tests/fixtures/windows_secondary_cleanup'
HTTPS_PINS = {
    'prior-direct-tls.cs': (2500, 'bda3e81054461b7b2f865d9de9638981181fc2ee799058f142defc8a2eaccdb6'),
    'before-total-deadline.cs': (3128, '3339630834fc13674df1e6ba833a792de3772995aa0b5cd7918ddc90befd0e19'),
}
CLEANUP_PROVENANCE_SHA256 = '3eb5efdca7385e8980d6aa9d20d315d468237ca32357e0d4fdb45c713f47eaff'
CLEANUP_NAMES = (
    'current_file_binding.ps1', 'current_publication.source',
    'decision_consumer.source', 'delete_native.cs',
    'legacy_admission_guards.source', 'legacy_file_binding.ps1',
    'legacy_interfaces.source', 'legacy_publication.source',
    'legacy_resources.source', 'reader_handles.ps1',
    'reviewed_admission_consumer.source', 'sdk_consumer.source',
)


def retained(name):
    raw = (FIXTURE / name).read_bytes()
    metadata = json.loads((FIXTURE / 'provenance.json').read_bytes())
    rows = [row for row in metadata['sources'] if row['file'] == name]
    if (len(rows) != 1 or rows[0]['sourceCommit'] != SOURCE_COMMIT
            or rows[0]['sha256'] != RETAINED[name] or len(raw) != rows[0]['bytes']
            or hashlib.sha256(raw).hexdigest() != RETAINED[name]):
        raise ValueError('checkout_reader_beforeimage_changed')
    return raw


def reader(kind, checkout):
    """Execute only the exact unchanged raw reader, never its surrounding module."""
    path, function, before = {
        'https': ('agent_tools/tests/test_windows_ordinary_https.py', 'specimen', 'https_reader.before.source'),
        'cleanup': ('agent_tools/tests/test_windows_secondary_ordinary_read.py', 'cleanup_fixture', 'cleanup_reader.before.source'),
    }[kind]
    preserved = retained(before)
    source = (ROOT / path).read_bytes()
    tree = ast.parse(source)
    selected = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == function]
    if len(selected) != 1 or ast.get_source_segment(source.decode(), selected[0]).rstrip('\n') != preserved.decode().rstrip('\n'):
        raise ValueError('actual_checkout_reader_changed')
    if kind == 'cleanup':
        pins = [ast.literal_eval(node.value) for node in tree.body
                if isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and node.targets[0].id == 'CLEANUP_PROVENANCE_SHA256']
        if pins != [CLEANUP_PROVENANCE_SHA256]:
            raise ValueError('actual_cleanup_provenance_pin_changed')
    namespace = {'hashlib': hashlib, 'json': json,
                 'FIXTURES': checkout / HTTPS_FOLDER,
                 'CLEANUP_FIXTURES': checkout / CLEANUP_FOLDER,
                 'CLEANUP_PROVENANCE_SHA256': CLEANUP_PROVENANCE_SHA256}
    exec(compile(preserved, str(FIXTURE / before), 'exec', dont_inherit=True), namespace)
    return namespace[function]


def public_payloads():
    result = {}
    manifest = (ROOT / HTTPS_FOLDER / 'provenance.json').read_bytes()
    facts = json.loads(manifest)
    result[HTTPS_FOLDER + '/provenance.json'] = manifest
    for name, (size, digest) in HTTPS_PINS.items():
        raw = (ROOT / HTTPS_FOLDER / name).read_bytes()
        if facts['files'][name]['sha256'] != digest or len(raw) != size or hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError('actual_https_fixture_pin_changed')
        result[HTTPS_FOLDER + '/' + name] = raw
    manifest = (ROOT / CLEANUP_FOLDER / 'provenance.json').read_bytes()
    if hashlib.sha256(manifest).hexdigest() != CLEANUP_PROVENANCE_SHA256:
        raise ValueError('actual_cleanup_fixture_manifest_changed')
    facts = json.loads(manifest)
    if set(facts['files']) != set(CLEANUP_NAMES):
        raise ValueError('actual_cleanup_fixture_members_changed')
    result[CLEANUP_FOLDER + '/provenance.json'] = manifest
    for name in CLEANUP_NAMES:
        raw = (ROOT / CLEANUP_FOLDER / name).read_bytes()
        pin = facts['files'][name]
        if len(raw) != pin['bytes'] or hashlib.sha256(raw).hexdigest() != pin['sha256']:
            raise ValueError('actual_cleanup_fixture_payload_changed')
        result[CLEANUP_FOLDER + '/' + name] = raw
    return result


@contextmanager
def physical_checkout(before):
    payloads = public_payloads()
    attributes = retained('attributes.before') if before else (ROOT / '.gitattributes').read_bytes()
    control = b'PUBLIC ordinary text\nsecond line\n'
    unlisted_pin = HTTPS_PINS['prior-direct-tls.cs']
    unlisted_name = HTTPS_FOLDER + '/unlisted-public.cs'
    payloads[unlisted_name] = payloads[HTTPS_FOLDER + '/prior-direct-tls.cs']
    payloads['ordinary-public.txt'] = control
    payloads['binary-public.bin'] = b'PUBLIC\0\nraw\r\n'
    payloads['.gitattributes'] = attributes
    with tempfile.TemporaryDirectory(prefix='raw-fixture-checkout-') as directory:
        checkout = Path(directory).resolve()
        # Inherited Git directory/index/config/template variables must never
        # redirect add/commit/reset outside this newly owned checkout.
        environment = {name: value for name, value in os.environ.items()
                       if not name.startswith('GIT_')}
        environment.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull,
                           GIT_ATTR_NOSYSTEM='1')
        environment.pop('DYLD_INSERT_LIBRARIES', None)

        def git(*arguments):
            completed = subprocess.run(['git', *arguments], cwd=checkout, env=environment,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
            if completed.returncode != 0:
                raise AssertionError((arguments, completed.returncode, completed.stdout, completed.stderr))
            return completed.stdout

        git('init', '-q')
        empty_attributes = checkout / '.git/empty-global-attributes'
        empty_attributes.write_bytes(b'')
        git('config', 'core.attributesFile', str(empty_attributes))
        git('config', 'core.autocrlf', 'false')
        for name, raw in payloads.items():
            path = checkout / name
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open('xb') as stream:
                stream.write(raw)
        git('add', '--all')
        git('-c', 'user.name=Public fixture', '-c', 'user.email=fixture@example.invalid',
            '-c', 'commit.gpgsign=false', 'commit', '-qm', 'Owned raw byte checkout')
        for name, raw in payloads.items():
            if git('show', 'HEAD:' + name) != raw:
                raise AssertionError('Owned original Git blob changed: ' + name)
        git('config', 'core.autocrlf', 'true')
        for name in payloads:
            (checkout / name).unlink()
        git('reset', '--hard', '--quiet', 'HEAD')
        if (checkout / 'ordinary-public.txt').read_bytes() != control.replace(b'\n', b'\r\n'):
            raise AssertionError('Actual Git CRLF checkout control did not convert')
        raw = (checkout / unlisted_name).read_bytes()
        if raw != payloads[unlisted_name].replace(b'\n', b'\r\n'):
            raise AssertionError('Unlisted source was unexpectedly exempt from conversion')
        if hashlib.sha256(raw).hexdigest() == unlisted_pin[1]:
            raise AssertionError('Unlisted raw-byte negative did not change')
        if (checkout / 'binary-public.bin').read_bytes() != payloads['binary-public.bin']:
            raise AssertionError('Git binary control bytes changed')
        yield checkout, payloads


class WindowsFixtureCheckoutBytesTests(unittest.TestCase):
    before_attributes = False

    def https_positive(self, name):
        with physical_checkout(self.before_attributes) as (checkout, payloads):
            actual = reader('https', checkout)(name)
            self.assertEqual(actual.encode(), payloads[HTTPS_FOLDER + '/' + name])

    def test_current_attributes_preserve_prior_tls_specimen(self):
        self.https_positive('prior-direct-tls.cs')

    def test_current_attributes_preserve_deadline_specimen(self):
        self.https_positive('before-total-deadline.cs')

    def test_current_attributes_preserve_complete_cleanup_family(self):
        with physical_checkout(self.before_attributes) as (checkout, payloads):
            actual = reader('cleanup', checkout)
            # This is the exact original native reader's first guarded input.
            self.assertEqual(actual('legacy_file_binding.ps1').encode(),
                             payloads[CLEANUP_FOLDER + '/legacy_file_binding.ps1'])
            for name in CLEANUP_NAMES:
                self.assertEqual(actual(name).encode(), payloads[CLEANUP_FOLDER + '/' + name])

    def test_preserved_attributes_reproduce_each_same_positive_raw_guard_refusal(self):
        for method, error, message in (
            ('test_current_attributes_preserve_prior_tls_specimen', 'failures', 'public specimen changed'),
            ('test_current_attributes_preserve_deadline_specimen', 'failures', 'public specimen changed'),
            ('test_current_attributes_preserve_complete_cleanup_family', 'errors', 'cleanup-fixture-provenance'),
        ):
            with self.subTest(method=method):
                case = type(self)(method)
                case.before_attributes = True
                result = unittest.TestResult()
                case.run(result)
                self.assertEqual(1, result.testsRun)
                self.assertEqual([], result.skipped)
                self.assertEqual(1, len(getattr(result, error)))
                self.assertEqual(1, len(result.failures) + len(result.errors))
                self.assertIn(message, getattr(result, error)[0][1])

    def test_old_checkout_payloads_refuse_even_after_only_manifest_is_restored(self):
        with physical_checkout(True) as (checkout, payloads):
            manifest = checkout / CLEANUP_FOLDER / 'provenance.json'
            manifest.write_bytes(payloads[CLEANUP_FOLDER + '/provenance.json'])
            actual = reader('cleanup', checkout)
            for name in ('current_file_binding.ps1', 'legacy_file_binding.ps1',
                         'reader_handles.ps1', 'delete_native.cs'):
                with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'cleanup-fixture-source'):
                    actual(name)

    def test_all_payload_pins_and_manifest_guard_continue_to_refuse_tampering(self):
        with physical_checkout(False) as (checkout, payloads):
            https = reader('https', checkout)
            cleanup = reader('cleanup', checkout)
            for folder, names, actual, error, message in (
                (HTTPS_FOLDER, tuple(HTTPS_PINS), https, AssertionError, 'public specimen changed'),
                (CLEANUP_FOLDER, CLEANUP_NAMES, cleanup, ValueError, 'cleanup-fixture-source'),
            ):
                for name in names:
                    path = checkout / folder / name
                    raw = path.read_bytes()
                    try:
                        path.write_bytes(raw + b'PUBLIC changed authenticated bytes\n')
                        with self.subTest(name=name), self.assertRaisesRegex(error, message):
                            actual(name)
                    finally:
                        path.write_bytes(raw)
            path = checkout / CLEANUP_FOLDER / 'provenance.json'
            raw = path.read_bytes()
            try:
                path.write_bytes(raw + b'\n')
                with self.assertRaisesRegex(ValueError, 'cleanup-fixture-provenance'):
                    cleanup('legacy_file_binding.ps1')
            finally:
                path.write_bytes(raw)

    def test_normal_text_binary_and_unlisted_source_keep_their_git_checkout_policy(self):
        with physical_checkout(False) as (checkout, payloads):
            for folder, names in ((HTTPS_FOLDER, HTTPS_PINS), (CLEANUP_FOLDER, CLEANUP_NAMES)):
                for name in names:
                    self.assertEqual((checkout / folder / name).read_bytes(), payloads[folder + '/' + name])

    def test_inherited_git_directory_index_and_config_cannot_redirect_the_owned_checkout(self):
        with tempfile.TemporaryDirectory(prefix='git-redirect-negative-') as directory:
            foreign = Path(directory).resolve()
            marker = foreign / 'PUBLIC-original-marker'
            marker.write_bytes(b'unchanged owned negative control\n')
            before = {path.name: path.read_bytes() for path in foreign.iterdir()}
            with patch.dict(os.environ, {
                'GIT_DIR': str(foreign / 'foreign.git'),
                'GIT_COMMON_DIR': str(foreign / 'common'),
                'GIT_WORK_TREE': str(foreign),
                'GIT_INDEX_FILE': str(foreign / 'index'),
                'GIT_TEMPLATE_DIR': str(foreign / 'templates'),
                'GIT_CONFIG_COUNT': 'not-an-integer',
                'GIT_CONFIG_KEY_0': 'core.worktree',
                'GIT_CONFIG_VALUE_0': str(foreign),
                'GIT_TRACE': str(foreign / 'unexpected-trace'),
            }):
                with physical_checkout(False) as (checkout, payloads):
                    self.assertNotEqual(checkout, foreign)
                    self.assertEqual(reader('https', checkout)('prior-direct-tls.cs').encode(),
                                     payloads[HTTPS_FOLDER + '/prior-direct-tls.cs'])
            self.assertEqual(before, {path.name: path.read_bytes() for path in foreign.iterdir()})


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--legacy-red', action='store_true')
    arguments, remaining = parser.parse_known_args()
    if arguments.legacy_red:
        methods = ('test_current_attributes_preserve_prior_tls_specimen',
                   'test_current_attributes_preserve_deadline_specimen',
                   'test_current_attributes_preserve_complete_cleanup_family')
        cases = []
        for method in methods:
            case = WindowsFixtureCheckoutBytesTests(method)
            case.before_attributes = True
            cases.append(case)
        result = unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(cases))
        raise SystemExit(0 if result.wasSuccessful() else 1)
    unittest.main(argv=[sys.argv[0], *remaining])
