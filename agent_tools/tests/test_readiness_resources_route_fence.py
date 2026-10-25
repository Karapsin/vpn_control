"""Whole-before RED/GREEN: the proof-free generic routes never touch ResourceAdmission rows.

Root ruling R3 (Stage 2b). vm_workflow environment-reserve and environment-release
accept caller-built requests and identities without any proof. Rows whose
operator is 'readiness-resources' belong to readiness_resources.ResourceAdmission
(prepare, submit, release_stopped and reviewed source-owned closures such as the
creator pre-VM closure). These tests drive the real generic routes of mcp_server
with the real native_environment over a temporary inventory.

RED on the whole-before mcp_server (075d8726 in the agent base and a6424d0a on the
recovery head both reproduce it): the routes re-mint a claim in a recovery
environment, re-book an existing claim with a complete receipt, release it, and
create the inventory for such a request. GREEN: each request or identity of
operator readiness-resources refuses with readiness_resources_owned_reservation
before any inventory read or write. Every other operator, including near-miss
spellings, behaves exactly as before. The fenced mcp_server digest is recorded at
landing (it depends on the head the two-branch hunk lands on).
"""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from uuid import uuid4

from agent_tools import mcp_server, native_environment as environments, readiness_resources as resources

GIB = 1024**3
MEASUREMENT = {'physicalMemoryBytes': 128 * GIB, 'runningConfiguredMemoryBytes': 2 * GIB, 'swapUsedBytes': 0, 'pressure': 'normal'}
REASON = 'readiness_resources_owned_reservation'


class GenericEnvironmentRouteFence(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(dir=Path('/tmp').resolve())
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.root.chmod(0o700)
        (self.root / '.rag_index').mkdir(mode=0o700)
        patch = mock.patch.object(mcp_server, 'REPO_ROOT', self.root)
        patch.start()
        self.addCleanup(patch.stop)

    def route(self, action, inputs):
        """The real generic route: action policy, dispatch and the native adapter."""
        return mcp_server._vm_workflow_impl(action, copy.deepcopy(inputs))

    def inventory(self):
        path = self.root / '.rag_index/native-environments/reservations.json'
        return path.read_bytes() if path.exists() else None

    def request(self, operator, environment):
        return {'hostAlias': 'archlinux', 'environment': environment, 'operator': operator, 'requestedMemoryBytes': 4 * GIB,
                'headroomBytes': 8 * GIB, 'allocationState': 'pending', 'measurement': MEASUREMENT}

    def claim(self):
        """One ResourceAdmission-shaped pending claim, minted by the real native code (not a route)."""
        request = self.request('readiness-resources', 'recovery-' + str(uuid4()))
        return request, environments.reserve_environment(self.root, request)['identity']

    def test_generic_routes_refuse_resource_admission_rows_before_any_inventory_write(self):
        request, identity = self.claim()
        before = self.inventory()
        complete = [resources._receipt(identity, 'complete')]
        cases = (
            # RED: a proof-free re-mint of the prepared request in a recovery environment.
            ('re-mint', 'environment-reserve', {**request, 'environment': 'recovery-' + str(uuid4())}),
            # RED: re-booking the exact claim with a complete receipt (the release precondition).
            ('re-book', 'environment-reserve', {**request, 'observations': complete}),
            # RED: releasing the claim by its identity.
            ('release', 'environment-release', identity),
            # Defense in depth (native code already refuses this one without a write).
            ('foreign-operator-naming-the-claim', 'environment-reserve',
             {**self.request('windows-vm-deploy', identity['environment']), 'reservationIdentity': identity}),
        )
        for label, action, inputs in cases:
            with self.subTest(label):
                result = self.route(action, inputs)
                self.assertEqual((result['ok'], result.get('summary')), (False, REASON), result)
                self.assertEqual(self.inventory(), before)
        self.assertNotIn(identity['token'], json.dumps([self.route(action, inputs) for _, action, inputs in cases]))

    def test_refusal_precedes_any_inventory_read_or_creation(self):
        identity = {'reservationId': 'env-' + '0' * 32, 'token': 'x' * 32, 'hostAlias': 'archlinux',
                    'environment': 'recovery-' + str(uuid4()), 'operator': 'readiness-resources'}
        for action, inputs in (('environment-reserve', self.request('readiness-resources', identity['environment'])),
                               ('environment-release', identity)):
            with self.subTest(action):
                result = self.route(action, inputs)
                self.assertEqual((result['ok'], result.get('summary')), (False, REASON), result)
        # RED: the whole-before reserve route creates the private inventory, lock and row.
        self.assertFalse((self.root / '.rag_index/native-environments').exists())
        # The public tool entry returns the same typed refusal.
        public = mcp_server.vm_workflow('environment-reserve', self.request('readiness-resources', identity['environment']))
        self.assertEqual((public['ok'], public.get('summary')), (False, REASON), public)
        self.assertFalse((self.root / '.rag_index/native-environments').exists())

    def test_other_operators_keep_the_generic_routes_unchanged(self):
        # Preservation (passes before and after): only the exact readiness-resources
        # operator is fenced; near-miss spellings are other operators.
        for operator in ('windows-vm-deploy', 'readiness-resources-x', 'Readiness-Resources', 'readiness_resources'):
            with self.subTest(operator):
                request = self.request(operator, 'windows-' + str(uuid4()))
                reserved = self.route('environment-reserve', request)
                self.assertEqual((reserved['ok'], reserved['state'], reserved['idempotent']), (True, 'reserved', False), reserved)
                again = self.route('environment-reserve', request)
                self.assertEqual((again['ok'], again['idempotent'], again['identity']), (True, True, reserved['identity']), again)
                rows = json.loads(self.inventory())['reservations']
                self.assertEqual([row['operator'] for row in rows], [operator])
                released = self.route('environment-release', reserved['identity'])
                self.assertEqual((released['ok'], released['state']), (True, 'released'), released)
                self.assertEqual(json.loads(self.inventory())['reservations'], [])
        # A readiness-resources claim next to it stays untouched by the other operator's routes.
        _, identity = self.claim()
        before = self.inventory()
        other = self.route('environment-reserve', self.request('windows-vm-deploy', 'windows-' + str(uuid4())))
        self.assertTrue(other['ok'], other)
        self.assertEqual(self.route('environment-release', other['identity'])['state'], 'released')
        self.assertEqual(self.inventory(), before)
        self.assertEqual([row['id'] for row in json.loads(self.inventory())['reservations']], [identity['reservationId']])


if __name__ == '__main__':
    unittest.main()
