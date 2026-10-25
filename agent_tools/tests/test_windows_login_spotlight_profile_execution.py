"""Execute full captured screen gates on the precredential native pixels.

The committed frame is the original native capture with only the
location-derived Spotlight weather card filled; that card lies outside every
gate crop, so both gate decisions equal those on the original pixels.
"""
import ast
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
import unittest
import zlib

FIXTURE = Path(__file__).parent / 'fixtures/windows_login_spotlight_profile'


def captured(name):
    source = (FIXTURE / name).read_bytes()
    tree = ast.parse(source)
    namespace = {'os': os, 're': re, 'hashlib': hashlib, 'json': json}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            try:
                namespace[node.targets[0].id] = ast.literal_eval(node.value)
            except (TypeError, ValueError):
                pass
    for name in ('_rename_create_only', 'validate_session', 'ppm', 'screen_gate', '_profile_known_screen', '_fixture_profile'):
        node = next(row for row in tree.body if isinstance(row, ast.FunctionDef) and row.name == name)
        exec(compile(ast.Module(body=[node], type_ignores=[]), str(FIXTURE / name), 'exec'), namespace)
    return source, namespace


class SpotlightProfileExecution(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.provenance = json.loads((FIXTURE / 'provenance.json').read_text())
        packed = (FIXTURE / 'native-before-return.ppm.zlib').read_bytes()
        assert hashlib.sha256(packed).hexdigest() == cls.provenance['compressedFixtureSha256']
        cls.pixels = zlib.decompress(packed)
        assert hashlib.sha256(cls.pixels).hexdigest() == cls.provenance['privacyRedaction']['committedPpmSha256']
        assert len(cls.pixels) == cls.provenance['cachedNativePpmBytes']

    def gate(self, namespace, raw=None, profile=None):
        requests = []
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            def monitor(command, arguments):
                requests.append(command)
                self.assertEqual(command, 'screendump')
                target = Path(arguments['filename'])
                target.write_bytes(self.pixels if raw is None else raw)
                target.chmod(0o600)

            namespace['_profile_known_screen'](root, 'native-fixture', monitor, lambda: None,
                                                namespace['LOCKSCREEN_PROFILE'] if profile is None else profile)
        self.assertEqual(requests, ['screendump'])

    def test_actual_before_gate_red_and_current_gate_green(self):
        before_source, before = captured('before.source')
        after_source, after = captured('after.source')
        self.assertEqual(hashlib.sha256(before_source).hexdigest(), self.provenance['beforeSourceSha256'])
        self.assertEqual(hashlib.sha256(after_source).hexdigest(), self.provenance['afterSourceSha256'])
        # The initial large crops include asynchronously populated Spotlight
        # overlays in these native pixels. The gate fails closed.
        with self.assertRaisesRegex(ValueError, '^instance_login_screen_unrecognized$'):
            self.gate(before)
        self.gate(after)

    def test_privacy_redaction_is_uniform_and_outside_every_gate_crop(self):
        redaction = self.provenance['privacyRedaction']
        self.assertNotEqual(redaction['committedPpmSha256'], self.provenance['cachedNativePpmSha256'])
        _, after = captured('after.source')
        width, _, _ = after['ppm'](self.pixels)
        header = self.pixels.index(b'\n255\n') + len(b'\n255\n')
        x0, y0, x1, y1 = redaction['rect']
        fill = bytes(redaction['fill'])
        for y in range(y0, y1):
            row = self.pixels[header + (y * width + x0) * 3:header + (y * width + x1) * 3]
            self.assertEqual(row, fill * (x1 - x0), y)
        # The gates hash only their crops, so pixels outside them cannot change
        # either decision.
        for name in ('before.source', 'after.source'):
            for crop in captured(name)[1]['LOCKSCREEN_PROFILE']['crops']:
                left, top, right, bottom = crop['rect']
                with self.subTest(source=name, crop=crop['rect']):
                    self.assertTrue(x1 <= left or right <= x0 or y1 <= top or bottom <= y0)

    def test_exact_stable_crop_tamper_is_rejected(self):
        _, after = captured('after.source')
        width, _, _ = after['ppm'](self.pixels)
        header = self.pixels.index(b'\n255\n') + len(b'\n255\n')
        changed = bytearray(self.pixels)
        rectangle = after['LOCKSCREEN_PROFILE']['crops'][0]['rect']
        changed[header + (rectangle[1] * width + rectangle[0]) * 3] ^= 1
        with self.assertRaisesRegex(ValueError, '^instance_login_screen_unrecognized$'):
            self.gate(after, bytes(changed))

    def test_foreign_profile_is_rejected(self):
        _, after = captured('after.source')
        foreign = copy.deepcopy(after['LOCKSCREEN_PROFILE'])
        foreign['crops'][0]['sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, '^instance_login_screen_unrecognized$'):
            self.gate(after, profile=foreign)

    def test_foreign_actual_account_never_submits_input(self):
        _, namespace = captured('after.source')
        expected = namespace['FIXTURE_EXPECTED']
        sid = namespace['FIXTURE_SID']
        session = {'SessionId': expected['console'], 'State': 0, 'Flags': 0, 'Station': 'Console',
                   'User': expected['user'], 'Domain': 'FIXTURE', 'Logon': expected['logon'],
                   **{key: 0 for key in ('Connect', 'Disconnect', 'LastInput', 'Current', 'InBytes',
                                        'OutBytes', 'InFrames', 'OutFrames', 'InCompressed', 'OutCompressed')}}
        facts = {'machine': namespace['SPEC']['deploymentId'], 'boot': expected['boot'],
                 'console': expected['console'], 'infoLevel': 1, 'session': session,
                 'tokenSid': 'S-1-5-21-1-2-3-1000', 'expectedSid': sid, 'ordinary': True,
                 'sessions': [{'Id': 0, 'Name': 'Services', 'State': 4},
                              {'Id': expected['console'], 'Name': 'Console', 'State': 0}], 'explorers': []}
        requests = []
        # The predecessor observer is a separate authenticated host protocol;
        # this test supplies its successful boundary without changing the
        # captured phase body, then tests the real native-account admission.
        namespace['_close_profile_predecessor'] = lambda *args: None
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / 'intent.json'
            path.write_text('{}')
            path.chmod(0o600)
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                info = os.fstat(descriptor)
                generation = [info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
                              info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns]
                namespace['LOCK_TERMINAL'] = copy.deepcopy(namespace['LOCK_TERMINAL'])
                namespace['LOCK_TERMINAL']['identity']['rootFlockGeneration'] = generation
                for suffix, value in (('.intent.json', namespace['LOCK_TERMINAL']['identity']),
                                      ('.terminal.json', namespace['LOCK_TERMINAL'])):
                    (root / ('fixture-lock-1dde6cf8-092c-4277-8159-2deb588a889e' + suffix)).write_text(json.dumps(value))
                before = {key: expected[key] for key in ('actor', 'hostBoot', 'controlConnection')}
                with self.assertRaisesRegex(ValueError, '^instance_fixture_session_changed$'):
                    namespace['_fixture_profile'](root, lambda name: json.loads((root / name).read_text()),
                        lambda *args: requests.append(args), lambda: None,
                        lambda *args: copy.deepcopy(facts), before, descriptor, lambda _: 12345)
            finally:
                os.close(descriptor)
        self.assertEqual(requests, [])


if __name__ == '__main__':
    unittest.main()
