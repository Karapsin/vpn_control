"""Declared native/file peers only; no Windows, guest, socket or network action.

The causal oracle calls the authentic preserved V2 ordinary-handle guard. Its
before branch models the missing caller barrier, not an unrecorded native run.
"""
from __future__ import annotations
import base64
import copy
import ctypes
import hashlib
import importlib.util
import json
from pathlib import Path, PureWindowsPath
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

B=_canonical_root/'agent_tools/windows_system_collector'


def module(name, path, expected=None):
    return _load_source(Path(path), expected)


P = module('_declared_hold_protocol', B / 'failing_msi_hold_protocol.py')
H = module('_declared_caller_hold', B / 'failing_msi_caller_hold.py')
V2 = module('_preserved_v2_system_worker_caller_barrier', _fixture_root/'before/v2/system_collector_worker.py',
    'd3ab44e9a7d5cd521069f407ffbf7c6a33cae3e237b48cb5dc0750ffecc4bb9a')
OP = '12345678-1234-4234-8234-123456789abc'
COLLECTOR = 'abcdef01-2345-4678-9234-56789abcdef0'
BOOT = '11111111-2222-4333-8444-555555555555'
SID = 'S-1-5-21-1-2-3-1001'
SELF = r'C:\AdmittedSources\failing_msi_caller_hold.py'
PROTOCOL = r'C:\AdmittedSources\failing_msi_hold_protocol.py'
OWNER_SOURCE = r'C:\AdmittedSources\ordinary_owner.py'
RECEIPTS = r'C:\AdmittedSources\receipts.py'
PYTHON = r'C:\AdmittedPython\python.exe'
ROOT = r'C:\OrdinaryOperation'
SYSTEM_ROOT = r'C:\ProgramData\VpnControlOrdinaryTask-' + OP + '\\system-collector-' + COLLECTOR
MACHINE = {'ownerSid': 'S-1-5-18', 'sddl': 'declared-protected-machine-policy'}


def identity(size, index=4):
    return {'volumeSerial': 7, 'fileIndex': index, 'attributes': 32, 'sizeBytes': size, 'links': 1,
        'creationFileTime': '133000000000000001', 'lastWriteFileTime': '133000000000000002'}


def pin(path, raw=b'declared source', sha=None):
    return {'path': path, 'nativeIdentity': identity(len(raw)), 'security': MACHINE.copy(),
        'sha256': sha or H.digest(raw)}


class Parked(Exception):
    pass


class Function:
    def __init__(self, function): self.function = function
    def __call__(self, *a): return self.function(*a)


class Pin:
    def __init__(self, record, raw=b''):
        self.record, self.raw, self.path, self.directory = record, raw, PureWindowsPath(record['path']), False
    def digest(self, return_bytes=False, maximum=8 * 1024 * 1024):
        if return_bytes:
            assert len(self.raw) <= maximum
            return self.raw
        return self.record['sha256']


class Peer:
    def __init__(self):
        self.files = {}; self.handles = {}; self.created = []; self.calls = []
        self.alive = True; self.release_delay = 0; self.release_factory = None; self.write_counts = []
        self.fail_write = False; self.fail_flush = False; self.fail_close = False; self.fail_policy = False
        self.guards = 0
        records = [pin(SELF, (B / PureWindowsPath(SELF).name).read_bytes()), pin(PROTOCOL, (B / PureWindowsPath(PROTOCOL).name).read_bytes()),
            pin(OWNER_SOURCE), pin(RECEIPTS, sha=P.RECEIPTS_SHA), pin(PYTHON)]
        self.pins = [Pin(x) for x in records]
        self.by_path = {str(x.path).casefold(): x for x in self.pins}
        directories = set(PureWindowsPath(SYSTEM_ROOT).parents) | {PureWindowsPath(ROOT)}
        self.pins += [SimpleNamespace(path=p, directory=True) for p in directories]
        self.request = {'context': {'ordinarySid': SID, 'ordinarySessionId': 2, 'bootIdentifier': BOOT,
            'machineGuid': OP}, 'pythonRuntime': {'interpreterPath': PYTHON}, 'operationId': OP,
            'operationRoot': ROOT, 'filePins': records}
        raw = P.encoded(self.request)
        self.worker_request = pin(ROOT + '\\worker-request.json', raw)
        self.pins.insert(0, Pin(self.worker_request, raw))
        self.operation = OP; self.root = PureWindowsPath(ROOT); self.children = []
        self.native = SimpleNamespace(k=SimpleNamespace(GetCurrentProcess=lambda: 47,
            CreateFileW=Function(self.create), WriteFile=Function(self.write),
            FlushFileBuffers=Function(lambda h: not self.fail_flush), CloseHandle=Function(self.close)),
            birth=lambda h: '133000000000000077', identity=self.native_identity)
        peer = self
        class Observation:
            def __init__(self, owner, path, *, directory=False):
                self.path = path; self.directory = directory; self.handle = H.INVALID_HANDLE
                if path == SYSTEM_ROOT:
                    self.opening = {'path': path, 'nativeIdentity': {'volumeSerial': 7, 'fileIndex': 3,
                        'attributes': 16}, 'security': MACHINE.copy()}; self.handle = 200; return
                if path.endswith('close-release.json') and path not in peer.files:
                    if peer.release_delay:
                        peer.release_delay -= 1
                    elif peer.release_factory:
                        peer.store(path, P.encoded(peer.release_factory()))
                if path not in peer.files:
                    error = OSError('declared missing file'); error.winerror = 2; raise error
                self.handle = 201; self.opening = copy.deepcopy(peer.files[path]['opening'])
            def read(self, maximum):
                raw = bytes(peer.files[self.path]['raw'])
                if len(raw) > maximum: raise ValueError('declared observation bound')
                return raw
            def describe(self): return self.opening
            def _canonical(self): pass
        def machine_security(security, directory):
            if security != MACHINE or peer.fail_policy: raise ValueError('declared untrusted machine policy')
        self.receipts = SimpleNamespace(FileObservation=Observation, machine_security=machine_security)
        self.inputs = {'schemaVersion': 1, 'collectorOperationId': COLLECTOR, 'collectorRoot': SYSTEM_ROOT,
            'scope': 'update', 'stage': 'returned-cleanup', 'sourceSha': 'f' * 40,
            'systemContractSourceSha256': 'c' * 64, 'systemWorkerSourceSha256': 'd' * 64,
            'collectorSourceSha256': P.COLLECTORS['update'], 'receiptsPath': RECEIPTS}

    def module(self, path, name):
        self.calls.append(('module', path))
        return P if path == PROTOCOL else self.receipts

    def guard(self):
        self.guards += 1
        if not self.alive: raise ValueError('declared ordinary worker exited')

    def park(self, reason, error): raise Parked((reason, str(error)))

    def store(self, path, raw):
        self.files[path] = {'raw': raw, 'opening': {'path': path, 'nativeIdentity': identity(len(raw)),
            'security': MACHINE.copy()}}

    def create(self, path, access, share, security, disposition, flags, template):
        self.calls.append(('create', path, disposition))
        if path in self.files: return H.INVALID_HANDLE
        self.created.append(path); self.store(path, bytearray()); handle = 100 + len(self.handles)
        self.handles[handle] = path
        return handle

    def write(self, handle, buffer, length, count, overlapped):
        self.calls.append(('write', length))
        if self.fail_write:
            count._obj.value = 0; return True
        size = min(length, self.write_counts.pop(0)) if self.write_counts else length
        f = self.files[self.handles[handle.value]]; f['raw'].extend(ctypes.string_at(buffer, size))
        f['opening']['nativeIdentity']['sizeBytes'] = len(f['raw']); count._obj.value = size
        return True

    def close(self, handle):
        self.calls.append(('close', handle.value))
        return not self.fail_close

    def native_identity(self, handle):
        return copy.deepcopy(self.files[self.handles[handle]]['opening']['nativeIdentity'])

    def arm(self):
        with patch.object(H, '__file__', SELF), patch.object(H.sys, 'executable', PYTHON), \
                patch.object(H, 'owner_source_path', lambda owner: OWNER_SOURCE), \
                patch.dict(H.os.environ, {'ProgramData': r'C:\ProgramData'}), patch.object(H.os, 'getpid', lambda: 77):
            self.hold = H.CallerCollectionHold(self, self.inputs)
        self.binding()
        return self.hold

    def binding(self):
        h = self.hold
        request = {'schemaVersion': 1, 'operationId': COLLECTOR, 'ordinaryTaskOperationId': OP,
            'operationRoot': SYSTEM_ROOT, 'requestPath': SYSTEM_ROOT + '\\collector-request.json',
            'scope': 'update', 'context': self.request['context'],
            'pythonRuntime': {'interpreterPath': PYTHON},
            'modules': {'worker': {'path': r'C:\SystemSources\worker.py', 'sha256': 'd' * 64},
                'contract': {'sha256': 'c' * 64}, 'collector': {'sha256': P.COLLECTORS['update']}},
            'collectorRequest': {'ordinaryTaskOperationId': OP, 'sourceSha': 'f' * 40,
                'collectorSourceSha256': P.COLLECTORS['update'], 'stage': 'returned-cleanup'},
            'ordinaryTask': {'workerActor': {'pid': 77, 'creationFileTime': 133000000000000077,
                'image': PYTHON, 'sha256': self.by_path[PYTHON.casefold()].record['sha256'], 'sid': SID, 'sessionId': 2},
                'workerSourcePin': self.by_path[OWNER_SOURCE.casefold()].record, 'workerRequestPin': self.worker_request},
            'closeHold': h.close_hold}
        self.system_request = request
        self.publish_binding()

    def publish_binding(self):
        r = self.system_request; raw = P.encoded(r); rec = pin(r['requestPath'], raw)
        self.store(r['requestPath'], raw)
        common = {'schemaVersion': 1, 'operationId': COLLECTOR, 'ownerPid': 88,
            'ownerBirthFileTimeUtc': '133000000000000088'}
        args = ['-I', '-S', '-B', r['modules']['worker']['path'], '--request', r['requestPath'],
            '--request-sha256', H.digest(raw), '--request-pin-base64', base64.b64encode(P.encoded(rec)).decode()]
        self.store(SYSTEM_ROOT + '\\task-event-000000-submission-intent.json', P.encoded({**common,
            'ordinal': 0, 'kind': 'submission-intent', 'value': {'scope': 'update', 'fileName': PYTHON, 'argv': args,
                'sourceAndRuntimePinsHeld': True, 'nativeToken': ['S-1-5-18', '0', '1', '1'],
                'requestSha256': H.digest(raw), 'replayAllowed': False}}))
        self.store(SYSTEM_ROOT + '\\task-event-000001-submitted.json', P.encoded({**common,
            'ordinal': 1, 'kind': 'submitted', 'value': {'pid': 99, 'birthFileTimeUtc': '133000000000000099',
                'originalHandleRetained': True}}))

    def release(self):
        h = self.hold
        return {**P.common_from_ready(h.ready), 'kind': 'collector-close-release',
            'holdReadySha256': h.ready_sha256, 'holdReadyNativeIdentity': h.ready_lease.opening['nativeIdentity'],
            'closure': {'systemExitCode': 0, 'childExitCode': 0, 'bothChildEof': True, 'sourceClosing': True,
                'qgaStdoutSha256': '1' * 64, 'qgaStderrSha256': P.EMPTY_SHA256,
                'childStdoutSha256': '2' * 64, 'childStderrSha256': P.EMPTY_SHA256, 'systemSourceSha256': '3' * 64}}

    def context(self):
        return patch.multiple(H, owner_source_path=lambda owner: OWNER_SOURCE)


class HoldTests(unittest.TestCase):
    def setUp(self):
        self.patchers = [patch.object(H, '__file__', SELF), patch.object(H.sys, 'executable', PYTHON),
            patch.object(H, 'owner_source_path', lambda owner: OWNER_SOURCE), patch.object(H.os, 'getpid', lambda: 77),
            patch.dict(H.os.environ, {'ProgramData': r'C:\ProgramData'}), patch.object(H.time, 'sleep', lambda _: None)]
        for p in self.patchers: p.start(); self.addCleanup(p.stop)

    def test_protocol_refuses_duplicate_fields_and_nonfinite_stage(self):
        with self.assertRaisesRegex(ValueError, 'duplicate'): P.decode(b'{"schemaVersion":1,"schemaVersion":1}')
        peer = Peer(); peer.inputs['stage'] = 'authorization'
        with self.assertRaises(Parked): peer.arm()

    def test_hold_arms_without_publication_or_ready_before_known_zero(self):
        p = Peer(); h = p.arm(); self.assertEqual(h.state, 'armed'); self.assertFalse(p.created)
        with self.assertRaisesRegex(ValueError, 'known-driver-required'): h.wait_for_release()
        self.assertFalse(p.created)

    def test_nonzero_bool_unknown_or_live_children_never_publish(self):
        for result in (1, None, False, True):
            p = Peer(); h = p.arm()
            with self.assertRaises(Parked): h.driver_completed(result)
            self.assertFalse(p.created)
        p = Peer(); h = p.arm(); p.children = [SimpleNamespace(terminal=None)]
        with self.assertRaises(Parked): h.driver_completed(0)
        self.assertFalse(p.created)

    def test_missing_original_eof_never_publishes(self):
        p = Peer(); h = p.arm(); p.children = [SimpleNamespace(pid=9, birth='1', eof={'stdout': True, 'stderr': False},
            terminal={'pid': 9, 'birthFileTimeUtc': '1', 'eof': {'stdout': True, 'stderr': False}})]
        with self.assertRaises(Parked): h.driver_completed(0)
        self.assertFalse(p.created)

    def test_changed_task_source_scope_request_or_hold_contract_refuses(self):
        for mutation in ('worker', 'source', 'stage', 'contract', 'caller'):
            p = Peer(); h = p.arm(); r = p.system_request
            if mutation == 'worker': r['ordinaryTask']['workerActor']['pid'] = 66
            elif mutation == 'source': r['collectorRequest']['sourceSha'] = '0' * 40
            elif mutation == 'stage': r['collectorRequest']['stage'] = 'terminal-actors'
            elif mutation == 'contract': r['modules']['contract']['sha256'] = '0' * 64
            else: r['closeHold'] = {**r['closeHold'], 'releasePath': SYSTEM_ROOT + '\\other.json'}
            p.publish_binding(); h.driver_completed(0)
            with self.assertRaises(Parked): h.wait_for_release()
            self.assertFalse(p.created)

    def test_unprotected_system_root_or_file_is_not_authority(self):
        p = Peer(); p.fail_policy = True
        with self.assertRaises(Parked): p.arm()
        p = Peer(); h = p.arm(); p.files[SYSTEM_ROOT + '\\collector-request.json']['opening']['security'] = {'ownerSid': SID}
        h.driver_completed(0)
        with self.assertRaises(Parked): h.wait_for_release()
        self.assertFalse(p.created)

    def test_missing_request_is_unknown_without_native_write(self):
        p = Peer(); h = p.arm(); del p.files[SYSTEM_ROOT + '\\collector-request.json']; h.driver_completed(0)
        with self.assertRaises(Parked): h.wait_for_release()
        self.assertFalse(p.created)

    def test_short_positive_writes_complete_once_and_wait_missing_release(self):
        p = Peer(); h = p.arm(); p.write_counts = [1, 3, 17]; p.release_delay = 2; p.release_factory = p.release
        h.driver_completed(0); release = h.wait_for_release()
        self.assertEqual(h.state, 'released'); self.assertEqual(release['collectorOperationId'], COLLECTOR)
        self.assertEqual(len(p.created), 1); self.assertGreater(len([x for x in p.calls if x[0] == 'write']), 1)
        self.assertEqual(bytes(p.files[h.ready_path]['raw']), P.encoded(h.ready))
        self.assertGreater(p.guards, 5); self.assertIsNotNone(h.ready_lease); self.assertIsNotNone(h.release_lease)
        with self.assertRaisesRegex(ValueError, 'known-driver-required'): h.wait_for_release()
        self.assertEqual(len(p.created), 1)

    def test_create_conflict_never_overwrites_or_replays(self):
        p = Peer(); h = p.arm(); p.store(h.ready_path, b'preexisting'); h.driver_completed(0)
        with self.assertRaises(Parked): h.wait_for_release()
        self.assertEqual(bytes(p.files[h.ready_path]['raw']), b'preexisting'); self.assertFalse(p.created)

    def test_partial_write_flush_and_close_failures_retain_custody(self):
        for flag in ('fail_write', 'fail_flush', 'fail_close'):
            p = Peer(); h = p.arm(); setattr(p, flag, True); h.driver_completed(0)
            with self.assertRaises(Parked): h.wait_for_release()
            self.assertEqual(h.state, 'unknown'); self.assertIs(p.caller_collection_hold, h)
            self.assertIsNotNone(h.publication['handle']); self.assertFalse(h.publication['closed'])
            self.assertEqual(len(p.created), 1)
            with self.assertRaises(ValueError): h.wait_for_release()
            self.assertEqual(len(p.created), 1)

    def test_wrong_release_boot_ready_bytes_generation_or_closure_parks(self):
        for mutation in ('boot', 'hash', 'generation', 'closure', 'stderr', 'child'):
            p = Peer(); h = p.arm()
            def release():
                r = copy.deepcopy(p.release())
                if mutation == 'boot': r['bootIdentifier'] = OP
                elif mutation == 'hash': r['holdReadySha256'] = '0' * 64
                elif mutation == 'generation': r['holdReadyNativeIdentity']['fileIndex'] += 1
                elif mutation == 'closure': r['closure']['sourceClosing'] = False
                elif mutation == 'stderr': r['closure']['childStderrSha256'] = '0' * 64
                else: r['collectorChild']['pid'] += 1
                return r
            p.release_factory = release; h.driver_completed(0)
            with self.assertRaises(Parked): h.wait_for_release()
            self.assertEqual(len(p.created), 1); self.assertEqual(h.state, 'unknown')

    def test_absent_and_other_owner_never_release_original(self):
        p = Peer(); h = p.arm(); p.release_factory = p.release; h.driver_completed(0)
        p.alive = False
        with self.assertRaises(Parked): h.wait_for_release()
        self.assertFalse(p.created)


BARRIER_SOURCE = 'held'


class BarrierCausalControl(unittest.TestCase):
    setUp = HoldTests.setUp
    def test_original_v2_guard_sees_live_driver_through_system_closure(self):
        p = Peer(); h = p.arm(); closed_while_live = []
        process = SimpleNamespace(describe=lambda: {'token': {'elevated': 0, 'elevationType': 1}},
            wait=lambda: 258 if p.alive else 0)
        original_guard_owner = SimpleNamespace(ordinary_handles=[{'process': process, 'expected': {}}],
            task_observer=SimpleNamespace(require_identity=lambda actual, expected: None))
        def system_closes():
            try:
                V2.guard_ordinary_handles(original_guard_owner)
                closed_while_live.append(True)
            except ValueError:
                closed_while_live.append(False)
            return p.release()
        if BARRIER_SOURCE == 'held':
            p.release_factory = system_closes
            h.driver_completed(0); h.wait_for_release(); p.alive = False
        else:
            # The complete preserved V2 guard exists, but V2 had no caller
            # hold. A known driver return can precede this final guard.
            p.alive = False
            try: V2.guard_ordinary_handles(original_guard_owner)
            except ValueError: closed_while_live.append(False)
            else: closed_while_live.append(True)
        self.assertEqual(closed_while_live, [True], 'original SYSTEM closing must observe the held ordinary generation')


if __name__ == '__main__':
    causal_only = '--causal-only' in sys.argv
    if causal_only: sys.argv.remove('--causal-only')
    if '--barrier-source' in sys.argv:
        index = sys.argv.index('--barrier-source'); BARRIER_SOURCE = sys.argv[index + 1]; del sys.argv[index:index + 2]
        if BARRIER_SOURCE not in {'before', 'held'}: raise ValueError('finite-causal-source-selector')
    unittest.main(defaultTest='BarrierCausalControl.test_original_v2_guard_sees_live_driver_through_system_closure'
        if causal_only else None)
