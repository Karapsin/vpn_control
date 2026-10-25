"""New close source qualification after the reviewed package import correction."""
import hashlib
import json
import os
from pathlib import Path
import types
import unittest
from unittest import mock

from agent_tools import ssh_connection_session_close as current
from agent_tools import ssh_transport
from agent_tools.tests import test_ssh_connection_session_close as controls

FIXTURE = Path(__file__).with_name('fixtures')/'ssh_close_import_dependency'


def before_module():
    provenance = json.loads((FIXTURE/'provenance.json').read_bytes())
    for name, digest in provenance['files'].items():
        if hashlib.sha256((FIXTURE/name).read_bytes()).hexdigest() != digest:
            raise AssertionError('changed close qualification beforeimage')
    path = FIXTURE/'before.source'
    module = types.ModuleType('agent_tools._close_import_dependency_before')
    module.__file__ = str(path)
    module.__package__ = 'agent_tools'
    exec(compile(path.read_bytes(), str(path), 'exec'), module.__dict__)
    return module


@unittest.skipUnless(os.name == 'posix', 'POSIX held master custody')
class CloseImportDependencyTests(unittest.TestCase):
    def fixture(self):
        case = controls.CloseTests('test_actual_current_source_pin_closes_only_original_outer_master')
        case.setUp()
        self.addCleanup(case.doCleanups)
        return case

    def test_actual_complete_before_refuses_current_transport_new_qualification_closes_once(self):
        old = before_module()
        case = self.fixture()
        ready = case.ready()
        original = {path.name: path.read_bytes() for path in case.journal().iterdir()}
        with case.control(ready, ''):
            self.assertEqual('unknown', old.close(case.root, 'archlinux', ready['receiptSha256'])['state'])
            self.assertEqual([], case.controls)
            self.assertFalse(current._paths(case.root, 'archlinux', ready['receiptSha256'])[3].exists())
            self.assertEqual('exit_sent', current.close(case.root, 'archlinux', ready['receiptSha256'])['state'])
            self.assertEqual(1, len(case.controls))
        with case.absence():
            self.assertEqual('closed', current.status(case.root, 'archlinux', ready['receiptSha256'])['state'])
        self.assertEqual(original, {path.name: path.read_bytes() for path in case.journal().iterdir()})

    def test_old_and_unreviewed_transport_cannot_use_new_close_qualification(self):
        old_transport = Path(__file__).with_name('fixtures')/'ssh_adapter_context'/'ssh_transport.py.before.source'
        old_digest = before_module()._TRANSPORT_SOURCE
        self.assertEqual(old_digest, hashlib.sha256(old_transport.read_bytes()).hexdigest())
        self.assertNotEqual(old_digest, current._TRANSPORT_SOURCE)
        for label, body in [('old', old_transport.read_bytes()),
                            ('future', Path(ssh_transport.__file__).read_bytes() + b'\n# unreviewed dependency\n')]:
            with self.subTest(label=label):
                case = self.fixture()
                ready = case.ready()
                dependency = case.root/(label + '-transport.py')
                dependency.write_bytes(body)
                dependency.chmod(0o600)
                with mock.patch.object(ssh_transport, '__file__', str(dependency)), \
                     mock.patch.object(current.subprocess, 'Popen', side_effect=AssertionError('no control child')):
                    self.assertEqual('unknown', current.close(case.root, 'archlinux', ready['receiptSha256'])['state'])
                self.assertFalse(current._paths(case.root, 'archlinux', ready['receiptSha256'])[3].exists())


if __name__ == '__main__':
    unittest.main()
