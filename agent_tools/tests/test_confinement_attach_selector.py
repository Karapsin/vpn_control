"""Actual native plist failure; execute only authenticated selector/parser AST.

The full private runner before/fixed sources are evidence, never imported or run.
No image allocation, native command, compiler, or private contents are involved.
"""
import ast
import copy
import hashlib
import json
from pathlib import Path
import plistlib
import unittest

FIXTURE = Path(__file__).parent / 'fixtures/confinement_attach_selector'
FILES = ('runner.before.source', 'runner.fixed.source', 'attach-2gib.plist',
         'attach-64mib.plist', 'hdi-2gib-info.plist')


def need(value, reason):
    if not value:
        raise ValueError(reason)


class ConfinementAttachSelectorTests(unittest.TestCase):
    def setUp(self):
        provenance = json.loads((FIXTURE / 'provenance.json').read_bytes())
        self.assertEqual(set(FILES), set(provenance['files']))
        self.raw = {}
        for name in FILES:
            raw = (FIXTURE / name).read_bytes()
            self.assertEqual(provenance['files'][name], hashlib.sha256(raw).hexdigest())
            self.raw[name] = raw
        old = ast.parse(self.raw['runner.before.source'])
        main = next(node for node in old.body if isinstance(node, ast.FunctionDef) and node.name == 'main')
        # Authentic complete selector sequence, including both original guards.
        first = next(i for i, node in enumerate(main.body)
                     if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name)
                     and node.targets[0].id == 'entities')
        last = next(i for i, node in enumerate(main.body[first:], first)
                    if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name)
                    and node.targets[0].id == 'device')
        self.old_selector = compile(ast.Module(body=main.body[first:last + 1], type_ignores=[]),
                                    'authenticated-old-selector', 'exec')
        current = ast.parse(self.raw['runner.fixed.source'])
        nodes = [node for node in current.body if isinstance(node, ast.FunctionDef)
                 and node.name in ('select_attached_device', 'validate_image_association')]
        self.assertEqual(2, len(nodes))
        self.current = {'need': need}
        exec(compile(ast.Module(body=nodes, type_ignores=[]), 'authenticated-pure-parser', 'exec'), self.current)
        self.attached = plistlib.loads(self.raw['attach-2gib.plist'])
        self.info = plistlib.loads(self.raw['hdi-2gib-info.plist'])
        self.mount = next(row['mount-point'] for row in self.attached['system-entities'] if 'mount-point' in row)
        self.image = next(row['image-path'] for row in self.info['images']
                          if any(entity.get('mount-point') == self.mount for entity in row['system-entities']))
        owned = next(row for row in self.info['images'] if row['image-path'] == self.image)
        self.uid = owned['owner-uid']
        self.capacity = owned['blockcount'] * owned['blocksize']

    def old(self, attached, mount):
        scope = {'attached': attached, 'MOUNT': mount, 'need': need}
        exec(self.old_selector, scope)
        return scope['device']

    def select(self, attached=None):
        return self.current['select_attached_device'](attached or self.attached, self.mount)

    def association(self, info=None, device=None):
        return self.current['validate_image_association'](
            info or self.info, self.attached, self.image, self.mount,
            device or self.select(), self.uid, self.capacity)

    def test_actual_whole_before_selector_64mib_passes_2gib_red_fixed_green(self):
        small = plistlib.loads(self.raw['attach-64mib.plist'])
        small_mount = next(row['mount-point'] for row in small['system-entities'] if 'mount-point' in row)
        self.assertEqual('/dev/disk4', self.old(small, small_mount))
        self.assertEqual('/dev/disk4', self.current['select_attached_device'](small, small_mount))
        with self.assertRaisesRegex(ValueError, 'attach_device_absent'):
            self.old(self.attached, self.mount)
        self.assertEqual('/dev/disk4', self.association())

    def test_unrelated_metadata_does_not_change_device_selection(self):
        attached = copy.deepcopy(self.attached)
        for row in attached['system-entities']:
            row['future-public-metadata'] = {'native-key': 1}
        self.assertEqual('/dev/disk4', self.select(attached))
        info = copy.deepcopy(self.info)
        for row in info['images']:
            row['future-public-metadata'] = True
        self.assertEqual('/dev/disk4', self.association(info))

    def test_wrong_or_ambiguous_raw_devices_are_refused(self):
        for change in ('partition', 'mountable-integer', 'duplicate', 'second-raw', 'wrong-mounted-kind'):
            with self.subTest(change=change):
                attached = copy.deepcopy(self.attached)
                raw = next(row for row in attached['system-entities'] if row.get('content-hint') == 'GUID_partition_scheme')
                if change == 'partition': raw['dev-entry'] += 's1'
                elif change == 'mountable-integer': raw['potentially-mountable'] = 0
                elif change == 'duplicate': attached['system-entities'].append(copy.deepcopy(raw))
                elif change == 'second-raw': attached['system-entities'].append(dict(raw, **{'dev-entry': '/dev/disk999'}))
                else:
                    next(row for row in attached['system-entities'] if 'mount-point' in row)['volume-kind'] = 'hfs'
                with self.assertRaises(ValueError): self.select(attached)

    def test_wrong_image_device_owner_geometry_or_ambiguous_association_blocks(self):
        for change in ('wrong-image', 'duplicate-image', 'wrong-device', 'foreign-device', 'wrong-owner', 'wrong-geometry', 'wrong-mount'):
            with self.subTest(change=change):
                info = copy.deepcopy(self.info)
                own = next(row for row in info['images'] if row['image-path'] == self.image)
                device = None
                if change == 'wrong-image': own['image-path'] += '.foreign'
                elif change == 'duplicate-image': info['images'].append(copy.deepcopy(own))
                elif change == 'wrong-device': device = '/dev/disk999'
                elif change == 'foreign-device': info['images'].append({'image-path': '/controlled/other.dmg', 'system-entities': copy.deepcopy(own['system-entities'])})
                elif change == 'wrong-owner': own['owner-uid'] += 1
                elif change == 'wrong-geometry': own['blockcount'] -= 1
                else: next(row for row in own['system-entities'] if 'mount-point' in row)['mount-point'] += '.foreign'
                with self.assertRaises(ValueError): self.association(info, device)


if __name__ == '__main__':
    unittest.main()
