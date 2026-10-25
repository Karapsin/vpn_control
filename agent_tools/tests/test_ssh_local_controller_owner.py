"""Authenticated fixed local source regressions; no SSH, VM or private inputs."""
import hashlib
import json
import os
from pathlib import Path
import sys
from types import ModuleType
import unittest

FIXTURE = Path(__file__).parent / 'fixtures/ssh_local_controller_owner'
PROVENANCE_SHA = 'bbff49bd44d7bae579dbc875ed1ec141c5cb456e3e36742bbb838e010058b493'
FILES = ['controller.4674.before.source', 'local-owner-source/local_owner.pre-deadline.before.source', 'local-owner-source/local_owner.py', 'local-owner-source/local_owner_v2.py', 'local-owner-source/test_local_owner_v2.py', 'ordinary_retention.py']


def load_fixture(name, alias):
    raw = (FIXTURE / 'provenance.json').read_bytes()
    if hashlib.sha256(raw).hexdigest() != PROVENANCE_SHA:
        raise AssertionError('fixture provenance changed')
    record = json.loads(raw)
    if record['schemaVersion'] != 1 or set(record['files']) != set(FILES):
        raise AssertionError('finite fixture scope changed')
    for leaf in FILES:
        if hashlib.sha256((FIXTURE / leaf).read_bytes()).hexdigest() != record['files'][leaf]:
            raise AssertionError('fixture bytes changed: ' + leaf)
    module = ModuleType(alias)
    module.__file__ = str((FIXTURE / name).resolve())
    module.__package__ = None
    sys.modules[alias] = module
    exec(compile((FIXTURE / name).read_bytes(), module.__file__, 'exec'), module.__dict__)
    return module


SUPPORTED = os.name == 'posix' and hasattr(os, 'O_NOFOLLOW') and hasattr(os, 'pread')

if SUPPORTED:
    fixture = load_fixture('local-owner-source/test_local_owner_v2.py', '_routine_local_controller_tests')
    LocalOwnerTests = fixture.LocalOwnerTests
    AdmissionDeadlineBoundaryTests = fixture.AdmissionDeadlineBoundaryTests
    HeldIndexCausalTests = fixture.HeldIndexCausalTests
else:
    @unittest.skip('requires POSIX process generation and private file descriptors')
    class LocalOwnerTests(unittest.TestCase):
        def test_supported_platform(self):
            pass
