"""Exact one-column caret exclusion on authenticated precredential native pixels."""
import copy
import hashlib
import json
from pathlib import Path
import unittest
import zlib
from agent_tools import readiness_windows_login as login

FIXTURE = Path(__file__).parent / 'fixtures/windows_login_caret_profile'


class CaretProfileExecution(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.provenance = json.loads((FIXTURE / 'provenance.json').read_text())
        packed = (FIXTURE / 'native-empty-field.ppm.zlib').read_bytes()
        assert hashlib.sha256(packed).hexdigest() == cls.provenance['compressedFixtureSha256']
        cls.raw = zlib.decompress(packed)
        assert hashlib.sha256(cls.raw).hexdigest() == cls.provenance['nativePpmSha256']
        cls.width, cls.height, _ = login.ppm(cls.raw)
        cls.header = len(cls.raw) - cls.width * cls.height * 3
        cls.before = json.loads((FIXTURE / 'before-profile.json').read_text())
        cls.after = json.loads((FIXTURE / 'after-profile.json').read_text())

    def changed(self, points):
        raw = bytearray(self.raw)
        for x, y in points:
            start = self.header + (y * self.width + x) * 3
            for component in range(3):
                raw[start + component] ^= 255
        return bytes(raw)

    def test_actual_frame_and_caret_only_before_red_after_green(self):
        self.assertTrue(login.screen_gate(self.raw, self.before))
        self.assertTrue(login.screen_gate(self.raw, self.after))
        caret_only_change = self.changed((502, y) for y in range(450, 469))
        with self.assertRaisesRegex(ValueError, '^instance_login_screen_unrecognized$'):
            login.screen_gate(caret_only_change, self.before)
        self.assertTrue(login.screen_gate(caret_only_change, self.after))

    def test_partition_retains_every_other_password_box_pixel(self):
        self.assertEqual(len(self.after['crops']), 8)
        left, top, right, bottom = self.provenance['originalPasswordBox']
        original = {(x, y) for x in range(left, right) for y in range(top, bottom)}
        covered = set()
        for crop in self.after['crops'][4:]:
            x0, y0, x1, y1 = crop['rect']
            covered.update((x, y) for x in range(x0, x1) for y in range(y0, y1))
        self.assertFalse(covered - original)
        self.assertEqual(original - covered, {(502, y) for y in range(450, 469)})

    def test_retained_placeholder_dot_border_focus_account_warning_changes_refused(self):
        points = {'placeholder': (503, 456), 'first_dot_area': (507, 459),
                  'top_border': (520, 441), 'left_border': (492, 458),
                  'right_border': (787, 458), 'blue_focus': (600, 477),
                  'selected_account': (100, 680), 'username_left': (600, 395),
                  'username_right': (680, 395), 'caps_or_error_warning': (520, 500)}
        for label, point in points.items():
            with self.subTest(guard=label), self.assertRaisesRegex(ValueError, '^instance_login_screen_unrecognized$'):
                login.screen_gate(self.changed([point]), self.after)

    def test_each_exact_region_remains_an_enforced_guard(self):
        for row in self.after['crops']:
            x0, y0, x1, y1 = row['rect']
            with self.subTest(rect=row['rect']), self.assertRaisesRegex(ValueError, '^instance_login_screen_unrecognized$'):
                login.screen_gate(self.changed([((x0 + x1) // 2, (y0 + y1) // 2)]), self.after)

    def test_foreign_region_digest_is_not_accepted(self):
        altered = copy.deepcopy(self.after)
        altered['crops'][0]['sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, '^instance_login_screen_unrecognized$'):
            login.screen_gate(self.raw, altered)


if __name__ == '__main__':
    unittest.main()
