"""Actual selected-tile soft-edge refusal with exact interior guards."""
import copy
import hashlib
import json
from pathlib import Path
import unittest
import zlib
from agent_tools import readiness_windows_login as login

FIXTURE = Path(__file__).parent / 'fixtures/windows_login_selected_tile'


class SelectedTileExecution(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.provenance = json.loads((FIXTURE / 'provenance.json').read_text())
        packed = (FIXTURE / 'native-refused-field.ppm.zlib').read_bytes()
        assert hashlib.sha256(packed).hexdigest() == cls.provenance['compressedFixtureSha256']
        cls.current = zlib.decompress(packed)
        assert hashlib.sha256(cls.current).hexdigest() == cls.provenance['nativePpmSha256']
        assert cls.provenance['baselineFixtureRelative'] == '../windows_login_caret_profile/native-empty-field.ppm.zlib'
        cls.baseline = zlib.decompress((FIXTURE.parent / 'windows_login_caret_profile/native-empty-field.ppm.zlib').read_bytes())
        assert hashlib.sha256(cls.baseline).hexdigest() == cls.provenance['baselinePpmSha256']
        cls.before = json.loads((FIXTURE / 'before-profile.json').read_text())
        cls.after = json.loads((FIXTURE / 'after-profile.json').read_text())
        cls.width, cls.height, _ = login.ppm(cls.current)
        cls.header = len(cls.current) - cls.width * cls.height * 3

    def changed(self, x, y):
        raw = bytearray(self.current)
        start = self.header + (y * self.width + x) * 3
        raw[start] ^= 255
        return bytes(raw)

    def test_actual_complete_original_profile_red_interior_profile_green(self):
        self.assertTrue(login.screen_gate(self.baseline, self.before))
        with self.assertRaisesRegex(ValueError, '^instance_login_screen_unrecognized$'):
            login.screen_gate(self.current, self.before)
        self.assertTrue(login.screen_gate(self.baseline, self.after))
        self.assertTrue(login.screen_gate(self.current, self.after))
        self.assertEqual(len(self.after['crops']), 8)
        self.assertEqual(self.before['crops'][:2] + self.before['crops'][3:],
                         self.after['crops'][:2] + self.after['crops'][3:])
        self.assertEqual(self.after['crops'][2]['rect'], [24, 658, 201, 708])

    def test_actual_difference_is_only_soft_horizontal_edge_rows(self):
        _, _, left = login.ppm(self.baseline)
        _, _, right = login.ppm(self.current)
        changes = []
        for y in range(649, 713):
            for x in range(24, 201):
                offset = (y * self.width + x) * 3
                a, b = left[offset:offset + 3], right[offset:offset + 3]
                if a != b:
                    changes.append((x, y, max(abs(p - q) for p, q in zip(a, b))))
        self.assertEqual(len(changes), 19)
        self.assertEqual({row[1] for row in changes}, {656, 657, 708})
        self.assertEqual(max(row[2] for row in changes), 1)
        self.assertEqual(self.provenance['pixelTolerance'], 0)

    def test_selected_avatar_name_highlight_and_other_guards_remain_exact(self):
        points = {'selected_avatar': (59, 681), 'selected_name': (110, 684),
                  'highlight_interior': (188, 690), 'highlight_left': (24, 680),
                  'username_left': (600, 395), 'username_right': (680, 395),
                  'placeholder': (510, 456), 'first_dot': (507, 459),
                  'field_border': (492, 458), 'blue_focus': (600, 477),
                  'warning': (520, 500)}
        for label, (x, y) in points.items():
            with self.subTest(guard=label), self.assertRaisesRegex(ValueError, '^instance_login_screen_unrecognized$'):
                login.screen_gate(self.changed(x, y), self.after)

    def test_foreign_unselected_tile_and_foreign_digest_refused(self):
        raw = bytearray(self.current)
        # The actually unselected recoveryadmin tile cannot replace selected recovery.
        for y in range(658, 708):
            source = self.header + ((y + 60) * self.width + 24) * 3
            target = self.header + (y * self.width + 24) * 3
            raw[target:target + 177 * 3] = self.current[source:source + 177 * 3]
        with self.assertRaisesRegex(ValueError, '^instance_login_screen_unrecognized$'):
            login.screen_gate(bytes(raw), self.after)
        foreign = copy.deepcopy(self.after)
        foreign['crops'][2]['sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, '^instance_login_screen_unrecognized$'):
            login.screen_gate(self.current, foreign)


if __name__ == '__main__':
    unittest.main()
