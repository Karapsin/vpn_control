"""A stopped or rebooted-away clone gives its reservation back only on fresh proof.

Physical private coordinator state with the real start, _prepare_reservation,
_mark_running, status, stop, reservation ledger and capacity admission of the
unchanged windows_vm_deploy. Only the Arch host is simulated: its boot epoch,
its QEMU census and the original instances' start/status/stop replies. No SSH,
VM, MCP transport or credential leaves the process.

The causal pair drives the public CLI route. On the unfixed tool (70ed16cc)
there is no such route, the generic ledger release refuses a running row, and
the same new clone's start stays refused with the native text (RED); with the
fix, one release on proof (a) or (b) admits that start (GREEN).
"""
import contextlib
import hashlib
import importlib
import io
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest import mock
import uuid

from agent_tools import native_environment as environments
from agent_tools import windows_vm_deploy as deploy
from agent_tools.tests import test_native_vm_spec as specs

MIB = 1024**2
GIB = 1024**3
PHYSICAL = 64670162944  # The Arch host: 61674 MiB.
SETUP = {'imageName': 'Windows 11 Pro', 'locale': 'en-US', 'user': 'ordinary', 'administrator': 'fixtureAdmin'}
REFUSAL = 'configured guest memory plus build headroom exceeds physical host memory (65536MiB > 61674MiB)'
# The native deployments of 2026-11-09, in an order whose admissions all pass.
REBOOTED_FIRST = '34e354eb-397f-4697-ba46-01426b94d9d5'
REBOOTED = ('7bb1f0c0-57bf-4fa0-bb72-e4cf5eef542c', '7039b09d-e0d5-4497-8c14-68c9d82a4d11',
            '60dc6c97-a7bc-490f-970b-f5ab26e92a8c', 'ffef40d7-b5e2-497c-a863-38ce53e4cae6')
STOPPED_EARLY = ('4b28776f-cde8-4497-90d6-a40223bae2e4', '66ad4aad-703d-4957-9f20-d149349394c4',
                 'db6df990-06b8-4ffc-b820-58ea34f02896')
ALIVE = ('be766f0c-bdb2-4c63-bd76-e3576f2af10c', '9059be98-c816-47bf-8cbd-e9e1439d4dc9')
STOPPED_LAST = 'a218e890-9ca1-4ed1-8f64-1cbafb353973'
NEW = 'f69643fe-064a-4d2a-b745-06fa50ce17d1'


def releases():
    """The release module; the unfixed tool has none."""
    return importlib.import_module('agent_tools.windows_vm_reservation_release')


def spec(deployment, index):
    value = specs.request()
    value.update(deploymentId=deployment, host='archlinux', root='/home/owner/vpn-control-windows/clone-%02d' % index,
                 memoryMiB=4096, headroomMiB=8192, vncPort=5901+index)
    return value


class Host:
    """The Arch host as the coordinator sees it: boot epoch, QEMU census, original instances."""

    def __init__(self):
        self.boot = str(uuid.uuid4())
        self.instances = {}
        self.calls = []
        self.pid = 4000
        self.replies = {}
        self.unreachable = False
        self.start_unknown = False
        self.during = {}

    def reboot(self):
        # A host reboot ends every VM of the old epoch.
        self.boot = str(uuid.uuid4())
        for item in self.instances.values():
            item['alive'] = False

    def census(self):
        return [{'pid': item['qemu']['pid'], 'startTicks': item['qemu']['startTicks'], 'sessionId': item['qemu']['pid'],
                 'uid': 1000, 'commandSha256': hashlib.sha256(identity.encode()).hexdigest(),
                 'executableGeneration': [1]*9, 'configuredMemoryBytes': item['memory']}
                for identity, item in sorted(self.instances.items()) if item['alive'] and not item.get('hidden')]

    def execute(self, root, spec, mode, **kwargs):
        self.calls.append((spec.deployment_id, mode))
        hook = self.during.pop((spec.deployment_id, mode), None)
        if hook is not None:
            hook()
        base = {'schemaVersion': 1, 'deploymentId': spec.deployment_id, 'mode': mode, 'reason': None,
                'nativeActionAllowed': False, 'replayAllowed': False}
        if mode == 'media':
            return {**base, 'state': 'media-observed', 'installerSha256': spec.installer.sha256,
                    'images': [{'index': 1, 'name': 'Windows 11 Pro', 'editionId': 'Professional',
                                'architecture': 'amd64', 'languages': ['en-US']}]}
        if mode == 'host-resources':
            if self.unreachable:
                raise ValueError('deployment_observation_unknown')
            now = time.time_ns()//1_000_000
            sample = lambda at: {'observedAtUnixMs': at, 'availableMemoryBytes': 40*GIB, 'psi': 'normal', 'psiSomeAvg10': 0.0,
                                 'psiFullAvg10': 0.0, 'vmstat': {'pswpin': 0, 'pswpout': 0, 'oomKill': 0}}
            return {**base, 'state': 'resources-observed', 'hostBootId': self.boot, 'vms': self.census(),
                    'physicalMemoryBytes': PHYSICAL, 'swapUsedBytes': 0, 'samples': [sample(now-100), sample(now)],
                    'freeDiskBytes': 800*GIB, 'inventoryComplete': True}
        if mode == 'start':
            return self.start(root, spec, base, **kwargs)
        if mode in ('status', 'stop'):
            return self.observe(root, spec, mode, base, **kwargs)
        raise AssertionError('unexpected native mode ' + mode)

    def unknown(self, base, phase, check):
        return {**base, 'state': 'unknown', 'reason': 'instance_effect_or_observation_unknown',
                'failurePhase': phase, 'failureClass': 'ValueError', 'failureCheck': check}

    def start(self, root, spec, base, *, credential_file, setup, context, payload, before_submit):
        # The real _execute retains the saved caller and the immutable start intent before submission.
        correlation = uuid.uuid4().hex
        directory = deploy._runtime_group(root, 'windows-vm-deploy')/correlation
        directory.mkdir(mode=0o700)
        source = ('SPEC='+repr(spec.as_dict())+'\nSETUP='+repr(setup)+'\nCONTEXT='+repr(context)+"\nMODE='start'\n").encode()
        deploy.stage._retain(directory, 'caller.py', source)
        claims = root/'.rag_index/windows-vm-deploy-intents'
        claims.mkdir(mode=0o700, exist_ok=True)
        deploy.stage._retain(claims, spec.deployment_id+'.intent.json',
                             {'spec': spec.as_dict(), 'setup': setup, 'context': context, 'correlationId': correlation,
                              'mode': 'start', 'callerSha256': hashlib.sha256(source).hexdigest()})
        before_submit()
        if self.start_unknown or context['hostBootId'] != self.boot:
            return self.unknown(base, 'qemu', None)
        self.pid += 2
        item = {'qemu': {'pid': self.pid, 'startTicks': self.pid*10}, 'swtpm': {'pid': self.pid-1, 'startTicks': self.pid*10-1},
                'memory': spec.memory_mib*MIB, 'alive': True, 'stopped': False}
        self.instances[spec.deployment_id] = item
        return {**base, 'state': 'booted-observed', 'qemu': dict(item['qemu']), 'swtpm': dict(item['swtpm']),
                'qemuStatus': 'running', 'guestAgentReady': False, 'ordinarySessionObserved': False, 'osName': None,
                'productReady': False}

    def observe(self, root, spec, mode, base, *, credential_file, setup, context):
        if mode == 'stop':
            # The real _execute refuses a consumed stop claim before transport: never a replay.
            claims = root/'.rag_index/windows-vm-deploy-stops'
            claims.mkdir(mode=0o700, exist_ok=True)
            if os.path.lexists(claims/(spec.deployment_id+'.intent.json')):
                raise ValueError('policy_original_exists')
            deploy.stage._retain(claims, spec.deployment_id+'.intent.json', {'mode': 'stop'})
        item = self.instances.get(spec.deployment_id)
        if item is None or context['hostBootId'] != self.boot:
            return self.unknown(base, 'resources', 'instance_host_epoch')
        reply = self.replies.get((spec.deployment_id, mode))
        if reply is not None:
            return {**base, **reply}
        if mode == 'stop' and item['alive']:
            item['alive'] = False
            item['stopped'] = True
        if item['alive']:
            return {**base, 'state': 'booted-observed', 'qemu': dict(item['qemu']), 'swtpm': dict(item['swtpm']),
                    'qemuStatus': 'running', 'guestAgentReady': True, 'ordinarySessionObserved': True, 'osName': None,
                    'productReady': False}
        if item['stopped']:
            return {**base, 'state': 'stopped-observed', 'qemu': dict(item['qemu']), 'swtpm': dict(item['swtpm']),
                    'positiveAbsence': True, 'productReady': False}
        # Died on the same boot without a stop intent: the original actor cannot be reidentified.
        return self.unknown(base, 'observation', 'instance_process_changed')


@unittest.skipUnless(os.name == 'posix', 'POSIX coordinator state and flock')
class ReservationReleaseTests(unittest.TestCase):
    def setUp(self):
        authority = SimpleNamespace(config=SimpleNamespace(hosts={'archlinux': object()}), guard=lambda: None)
        guard = mock.MagicMock()
        guard.__enter__.return_value = authority
        patch = mock.patch.object(deploy.direct, 'Guard', return_value=guard)
        patch.start()
        self.addCleanup(patch.stop)
        temporary = tempfile.TemporaryDirectory(dir=Path('/tmp').resolve())
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.root.chmod(0o700)
        self.credential = self.root/'host-sudo.secret'
        self.credential.write_text('INERT_LOCAL_FIXTURE\n')
        self.credential.chmod(0o600)
        self.host = Host()
        self.index = 0

    @contextlib.contextmanager
    def native(self):
        with mock.patch.object(deploy, '_execute', side_effect=self.host.execute):
            yield

    def start(self, deployment):
        self.index += 1
        with self.native():
            return deploy.start(self.root, spec(deployment, self.index), SETUP, str(self.credential))

    def stop(self, deployment):
        with self.native():
            return deploy.stop(self.root, deployment, str(self.credential))

    def release(self, deployment):
        with self.native():
            return releases().release(self.root, deployment, str(self.credential))

    def history(self):
        """The native history: 11 running claims of 4096 MiB, of which only 2 VMs are alive."""
        self.assertEqual('booted-observed', self.start(REBOOTED_FIRST)['state'])
        self.host.reboot()
        for deployment in REBOOTED:
            self.assertEqual('booted-observed', self.start(deployment)['state'])
        self.host.reboot()
        for deployment in REBOOTED[0], REBOOTED[3]:
            # Their later stops end UNKNOWN on the new epoch and consume their only stop claim.
            value = self.stop(deployment)
            self.assertEqual(('unknown', 'instance_host_epoch'), (value['state'], value['failureCheck']))
        for deployment in STOPPED_EARLY:
            self.assertEqual('booted-observed', self.start(deployment)['state'])
            self.assertEqual('stopped-observed', self.stop(deployment)['state'])
        for deployment in ALIVE:
            self.assertEqual('booted-observed', self.start(deployment)['state'])
        self.assertEqual('booted-observed', self.start(STOPPED_LAST)['state'])
        value = self.stop(STOPPED_LAST)
        self.assertEqual(('stopped-observed', True), (value['state'], value['positiveAbsence']))
        rows = self.rows()
        self.assertEqual((11, {'running'}, {4096*MIB}),
                         (len(rows), {row['allocationState'] for row in rows}, {row['requestedMemoryBytes'] for row in rows}))
        self.assertEqual(2, len(self.host.census()))

    def inventory(self):
        return (self.root/'.rag_index/native-environments/reservations.json').read_bytes()

    def rows(self):
        return json.loads(self.inventory())['reservations']

    def identity(self, deployment):
        path = self.root/'.runtime/windows-vm-credentials'/deployment/'reservation.private.json'
        return json.loads(path.read_bytes())['reservation']['identity']

    def admission(self):
        """The same new clone's start; a refusal returns the retained native detail."""
        self.index = 20
        value = self.start(NEW)
        if value['state'] == 'blocked':
            self.assertEqual(('reservation_admission_refused', False), (value['reason'], value['vmSubmitted']))
            failures = sorted((self.root/'.runtime/windows-vm-preparation-failures').glob(NEW+'-*.json'))
            return value['state'], json.loads(failures[-1].read_bytes())['detail']
        return value['state'], None

    def public_release(self, deployment):
        """The tool's public CLI route, as the coordinator invokes it, on this private root."""
        from agent_tools import mcp_server
        from agent_tools.tests.route_adapter import bind_cached_routes
        try:
            releases()  # Present the module the route loads; the unfixed tool has none.
        except ModuleNotFoundError:
            pass
        # Inert readiness admission; the route's release module is this process's own.
        bind_cached_routes(self, mcp_server, 'windows_vm_reservation_release')
        path = self.root/'release-inputs.json'
        path.write_text(json.dumps({'deploymentId': deployment, 'credentialFile': str(self.credential)}))
        output, errors = io.StringIO(), io.StringIO()
        with mock.patch.object(mcp_server, 'REPO_ROOT', self.root), self.native(), \
             contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            try:
                code = mcp_server.main(['vm-workflow', 'windows-vm-deploy-release', '--inputs-file', str(path)])
            except SystemExit as exit:
                code = exit.code
        return code, (json.loads(output.getvalue()) if output.getvalue().strip() else None)

    def causal(self, deployment):
        self.history()
        self.assertEqual(('blocked', REFUSAL), self.admission())
        # The generic ledger release refuses a running row without a fresh terminal receipt.
        with self.assertRaisesRegex(environments.NativeEnvironmentError, 'active or unknown job evidence'):
            environments.release_environment(self.root, self.identity(deployment))
        before = len(self.host.calls)
        code, value = self.public_release(deployment)
        calls = self.host.calls[before:]
        # The same new clone's admission after that public release: RED keeps the native refusal.
        self.assertEqual(('booted-observed', None), self.admission())
        self.assertEqual((0, True, 'released'), (code, value['ok'], value['state']))
        self.assertNotIn(self.identity(deployment)['reservationId'], {row['id'] for row in self.rows()})
        self.assertNotIn(self.identity(deployment)['token'], json.dumps(value))
        return value, calls

    def test_clean_stop_same_boot_RED_no_release_route_keeps_start_refused_GREEN_proof_a_admits(self):
        value, calls = self.causal(STOPPED_LAST)
        self.assertEqual('clean-absence-same-boot', value['proof'])
        self.assertEqual([(STOPPED_LAST, 'host-resources'), (STOPPED_LAST, 'status')], calls)

    def test_reboot_ended_epoch_RED_no_release_route_keeps_start_refused_GREEN_proof_b_admits(self):
        claim = self.root/'.rag_index/windows-vm-deploy-stops'/(REBOOTED[0]+'.intent.json')
        value, calls = self.causal(REBOOTED[0])
        self.assertEqual('ended-host-epoch', value['proof'])
        self.assertNotEqual(value['reservationHostBootId'], value['observedHostBootId'])
        # Proof (b) neither needs nor replays the consumed UNKNOWN stop: no status, no stop.
        self.assertEqual([(REBOOTED[0], 'host-resources')], calls)
        self.assertEqual(b'{"mode": "stop"}\n', claim.read_bytes())

    def test_every_finished_native_clone_releases_and_live_clones_keep_their_claims(self):
        self.history()
        live = {self.identity(item)['reservationId']: row for item in ALIVE for row in self.rows()
                if row['id'] == self.identity(item)['reservationId']}
        for deployment in (REBOOTED_FIRST, *REBOOTED):
            self.assertEqual('ended-host-epoch', self.release(deployment)['proof'])
        for deployment in (*STOPPED_EARLY, STOPPED_LAST):
            self.assertEqual('clean-absence-same-boot', self.release(deployment)['proof'])
        for deployment in ALIVE:
            value = self.release(deployment)
            self.assertEqual(('blocked', 'release_instance_running'), (value['state'], value['reason']))
        self.assertEqual(live, {row['id']: row for row in self.rows()})
        self.assertEqual(('booted-observed', None), self.admission())

    def assert_released_nothing(self, deployment, inventory):
        self.assertEqual(inventory, self.inventory())
        self.assertFalse(os.path.lexists(self.root/'.rag_index/windows-vm-deploy-releases'/(deployment+'.released.json')))
        self.assertEqual([], list((self.root/'.rag_index/windows-vm-deploy-releases').glob(deployment+'.authorized.*')))

    def blocked(self, deployment, reason):
        inventory = self.inventory()
        value = self.release(deployment)
        self.assertEqual(('blocked', reason, False, False),
                         (value['state'], value['reason'], value['nativeActionAllowed'], value['replayAllowed']))
        self.assert_released_nothing(deployment, inventory)
        return value

    def test_unknown_unreachable_or_running_status_blocks_and_releases_nothing(self):
        self.history()
        self.host.replies[(STOPPED_LAST, 'status')] = {'state': 'unknown', 'reason': 'instance_effect_or_observation_unknown',
                                                       'failurePhase': 'observation', 'failureClass': 'OSError', 'failureCheck': None}
        self.blocked(STOPPED_LAST, 'release_status_unknown')
        del self.host.replies[(STOPPED_LAST, 'status')]
        self.host.unreachable = True
        self.blocked(STOPPED_LAST, 'release_observation_unknown')
        self.blocked(REBOOTED_FIRST, 'release_observation_unknown')
        self.host.unreachable = False
        before = len(self.host.calls)
        self.blocked(ALIVE[0], 'release_instance_running')
        self.assertEqual([(ALIVE[0], 'host-resources')], self.host.calls[before:])
        # A census that missed the live actor still meets the running original at status.
        self.host.instances[ALIVE[1]]['hidden'] = True
        self.blocked(ALIVE[1], 'release_instance_running')
        self.host.instances[ALIVE[1]]['hidden'] = False
        self.assertNotIn('stop', {mode for _, mode in self.host.calls[before:]})
        self.assertEqual(('blocked', REFUSAL), self.admission())

    def test_same_epoch_without_positive_absence_blocks(self):
        self.history()
        # Died on its own boot without a stop: status cannot reidentify the original actor.
        self.host.instances[ALIVE[0]]['alive'] = False
        self.blocked(ALIVE[0], 'release_status_unknown')
        item = self.host.instances[STOPPED_LAST]
        self.host.replies[(STOPPED_LAST, 'status')] = {'state': 'stopped-observed', 'qemu': dict(item['qemu']),
                                                       'swtpm': dict(item['swtpm']), 'positiveAbsence': False,
                                                       'productReady': False}
        self.blocked(STOPPED_LAST, 'release_status_unknown')

    def test_foreign_or_mismatched_identity_blocks(self):
        self.history()
        # A stopped-observed reply about other actors is not this deployment's original.
        item = self.host.instances[STOPPED_LAST]
        self.host.replies[(STOPPED_LAST, 'status')] = {'state': 'stopped-observed', 'qemu': {'pid': 7, 'startTicks': 70},
                                                       'swtpm': dict(item['swtpm']), 'positiveAbsence': True,
                                                       'productReady': False}
        self.blocked(STOPPED_LAST, 'release_original_actor_mismatch')
        del self.host.replies[(STOPPED_LAST, 'status')]
        # A foreign row under the same reservation id (another token) is never released.
        reservation = self.identity(STOPPED_LAST)['reservationId']
        with environments._LockedState(self.root) as locked:
            row = next(row for row in locked.state['reservations'] if row['id'] == reservation)
            original, row['token'] = row['token'], 'FOREIGN_INERT_TOKEN'
            locked.save()
        self.blocked(STOPPED_LAST, 'release_identity_mismatch')
        with environments._LockedState(self.root) as locked:
            next(row for row in locked.state['reservations'] if row['id'] == reservation)['token'] = original
            locked.save()
        # Another deployment's private reservation file never names this deployment's row.
        private = self.root/'.runtime/windows-vm-credentials'/STOPPED_EARLY[0]/'reservation.private.json'
        foreign = self.root/'.runtime/windows-vm-credentials'/STOPPED_EARLY[1]/'reservation.private.json'
        kept = private.read_bytes()
        private.unlink()
        private.write_bytes(foreign.read_bytes())
        private.chmod(0o600)
        self.blocked(STOPPED_EARLY[0], 'release_original_unbound')
        private.unlink()
        private.write_bytes(kept)
        private.chmod(0o600)
        self.assertEqual('released', self.release(STOPPED_LAST)['state'])
        self.assertEqual('released', self.release(STOPPED_EARLY[0])['state'])

    def test_pending_row_blocks(self):
        self.host.start_unknown = True
        self.assertEqual('unknown', self.start(NEW)['state'])
        self.assertEqual(['pending'], [row['allocationState'] for row in self.rows()])
        self.blocked(NEW, 'release_reservation_pending')

    def test_repeat_is_idempotent_and_only_reads_the_retained_terminal(self):
        self.history()
        first = self.release(STOPPED_LAST)
        inventory, calls = self.inventory(), list(self.host.calls)
        second = self.release(STOPPED_LAST)
        self.assertEqual({**first, 'idempotent': True}, second)
        self.assertFalse(first['idempotent'])
        self.assertEqual((inventory, calls), (self.inventory(), self.host.calls))

    def test_inventory_change_between_observation_and_release_blocks(self):
        self.history()
        def concurrent():
            # Another ledger writer commits while this release is observing.
            with environments._LockedState(self.root) as locked:
                row = next(row for row in locked.state['reservations'] if row['id'] == self.identity(ALIVE[0])['reservationId'])
                row['activeJobEvidence']['observedAtUnixMs'] += 1
                locked.save()
        for mode, deployment in (('status', STOPPED_LAST), ('host-resources', REBOOTED_FIRST)):
            with self.subTest(mode=mode):
                self.host.during[(deployment, mode)] = concurrent
                value = self.release(deployment)
                self.assertEqual(('blocked', 'release_inventory_changed'), (value['state'], value['reason']))
                self.assertIn(self.identity(deployment)['reservationId'], {row['id'] for row in self.rows()})
                self.assertEqual([], list((self.root/'.rag_index/windows-vm-deploy-releases').glob(deployment+'.authorized.*')))
                self.assertEqual('released', self.release(deployment)['state'])

    def test_lost_reply_reconciles_by_reading_and_never_releases_twice(self):
        self.history()
        module = releases()
        terminal = module._terminal
        lost = []
        def once(*args):
            if not lost:
                lost.append(True)
                raise OSError('inert lost terminal acknowledgement')
            return terminal(*args)
        release = mock.Mock(side_effect=environments.release_environment)
        with mock.patch.object(module, '_terminal', side_effect=once), \
             mock.patch.object(environments, 'release_environment', release):
            with self.assertRaises(OSError):
                self.release(STOPPED_LAST)
            self.assertNotIn(self.identity(STOPPED_LAST)['reservationId'], {row['id'] for row in self.rows()})
            calls = list(self.host.calls)
            value = self.release(STOPPED_LAST)
            self.assertEqual(('released', True, False, 'clean-absence-same-boot'),
                             (value['state'], value['reconciled'], value['idempotent'], value['proof']))
            self.assertEqual(calls, self.host.calls)
            self.assertTrue(self.release(STOPPED_LAST)['idempotent'])
        self.assertEqual(1, release.call_count)

    def test_interrupted_release_effect_retains_the_row_and_reproves(self):
        self.history()
        with mock.patch.object(environments, 'release_environment', side_effect=OSError('inert interrupted release')):
            value = self.release(REBOOTED_FIRST)
        self.assertEqual(('blocked', 'release_incomplete'), (value['state'], value['reason']))
        self.assertIn(self.identity(REBOOTED_FIRST)['reservationId'], {row['id'] for row in self.rows()})
        calls = len(self.host.calls)
        value = self.release(REBOOTED_FIRST)
        self.assertEqual(('released', False), (value['state'], value['reconciled']))
        self.assertEqual([(REBOOTED_FIRST, 'host-resources')], self.host.calls[calls:])

    def test_absent_row_without_own_authorization_and_held_lock_block(self):
        self.history()
        import fcntl
        group = self.root/'.rag_index/windows-vm-deploy-releases'
        group.mkdir(mode=0o700)
        lock = os.open(group/(STOPPED_LAST+'.lock'), os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            calls = len(self.host.calls)
            self.blocked(STOPPED_LAST, 'release_in_progress')
            self.assertEqual(calls, len(self.host.calls))
        finally:
            os.close(lock)
        with environments._LockedState(self.root) as locked:
            locked.state['reservations'] = [row for row in locked.state['reservations']
                                            if row['id'] != self.identity(STOPPED_EARLY[0])['reservationId']]
            locked.save()
        self.blocked(STOPPED_EARLY[0], 'release_reservation_absent')

    def test_identity_is_validated_before_any_file_or_transport(self):
        for value in ('../escape', STOPPED_LAST.upper(), None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                releases().release(self.root, value, str(self.credential))
        self.assertFalse((self.root/'.rag_index').exists())
        self.assertFalse((self.root/'.runtime').exists())
        self.assertEqual([], self.host.calls)


class ReleaseRouteTests(unittest.TestCase):
    def setUp(self):
        from agent_tools import readiness_vm_dispatch
        admission = mock.patch.object(readiness_vm_dispatch, 'admitted_dispatch', return_value=contextlib.nullcontext())
        admission.start()
        self.addCleanup(admission.stop)
        from agent_tools.tests.route_adapter import bind_cached_routes
        from agent_tools import mcp_server
        releases()
        bind_cached_routes(self, mcp_server, 'readiness_vm_dispatch', 'windows_vm_reservation_release')

    def test_route_passes_only_the_original_identity_and_rejects_extra_authority(self):
        from agent_tools import mcp_server
        inputs = {'deploymentId': STOPPED_LAST, 'credentialFile': '/INERT_PRIVATE_PATH'}
        released = {'schemaVersion': 1, 'deploymentId': STOPPED_LAST, 'mode': 'release', 'state': 'released', 'reason': None,
                    'reservationId': 'env-inert', 'proof': 'ended-host-epoch', 'nativeActionAllowed': False, 'replayAllowed': False}
        with mock.patch.object(releases(), 'release', return_value=released) as operation:
            value = mcp_server._vm_workflow_impl('windows-vm-deploy-release', inputs)
            self.assertTrue(value['ok'])
            self.assertEqual('owned-windows-vm-reservation-release', value['evidenceClass'])
            operation.assert_called_once_with(mcp_server.REPO_ROOT, STOPPED_LAST, inputs['credentialFile'])
            operation.reset_mock()
            for extra in ({'force': True}, {'reservationId': 'env-inert'}, {'proof': 'ended-host-epoch'}):
                self.assertFalse(mcp_server._vm_workflow_impl('windows-vm-deploy-release', {**inputs, **extra})['ok'])
            self.assertFalse(mcp_server._vm_workflow_impl('windows-vm-deploy-release', {'deploymentId': STOPPED_LAST})['ok'])
            operation.assert_not_called()
        blocked = {**released, 'state': 'blocked', 'reason': 'release_status_unknown'}
        with mock.patch.object(releases(), 'release', return_value=blocked):
            self.assertFalse(mcp_server._vm_workflow_impl('windows-vm-deploy-release', inputs)['ok'])
        with mock.patch.object(releases(), 'release', side_effect=OSError('inert')):
            value = mcp_server._vm_workflow_impl('windows-vm-deploy-release', inputs)
        self.assertEqual(('unknown', 'deployment_release_unavailable', False),
                         (value['state'], value['reason'], value['replayAllowed']))

    def test_cli_accepts_the_closed_action_with_an_inputs_file(self):
        from agent_tools import mcp_server
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'inputs.json'
            path.write_text(json.dumps({'deploymentId': STOPPED_LAST, 'credentialFile': '/INERT_PRIVATE_PATH'}))
            output = io.StringIO()
            with mock.patch.object(mcp_server, 'vm_workflow', return_value={'ok': True}) as workflow, \
                 contextlib.redirect_stdout(output):
                self.assertEqual(0, mcp_server.main(['vm-workflow', 'windows-vm-deploy-release', '--inputs-file', str(path)]))
        workflow.assert_called_once_with('windows-vm-deploy-release', {'deploymentId': STOPPED_LAST, 'credentialFile': '/INERT_PRIVATE_PATH'})

    def test_deployment_reservation_and_resource_sources_stay_unchanged(self):
        # The sources pinned by readiness_windows._source_pins() (frozen sign-in packets and
        # enrollment evidence bind them) are only read and called by the release module.
        frozen = {'windows_vm_deploy.py': 'bca2bba738ae3ee277f8190b2ca8c35b4f0e7c2ee5f0e5db68a7eb40a356fc76',
                  'native_environment.py': 'e842650c8308d5b2cd8d9770afcd86d930556c0ae0836dea9b76d4cb864147cf',
                  'windows_vm_resources.py': '7cc0abe35919350e7309e3ec21136892fe68728bdc65259bfc7590c7a32570c7',
                  'windows_vm_deploy_remote.py': '36d39cca455244445f1c4d654d96b0f7634f99e6545af8e0464aa5f486eb101a'}
        directory = Path(deploy.__file__).parent
        self.assertEqual(frozen, {name: hashlib.sha256((directory/name).read_bytes()).hexdigest() for name in frozen})
