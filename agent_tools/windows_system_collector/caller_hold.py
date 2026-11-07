"""Fixed close barrier owned by the original ordinary task, before its cases run.

No launcher, installer, process stop, task restart or arbitrary publication API.
All uncertain objects remain reachable from the original Owner while it parks.
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes as W
import hashlib
import os
from pathlib import PureWindowsPath
import sys
import time

PROTOCOL_SHA = 'b8dac389ad80345109d6e8678c45347224ef2c6c9da634ccbe82ab6ac3a064ad'
RECEIPTS_SHA = '5e2e406b82d4a446ab971f27918b3b0f110e67e3eb8cae971b0bfe4256aa71ec'
INVALID_HANDLE = ctypes.c_void_p(-1).value


def require(value, reason):
    if not value:
        raise ValueError(reason)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def owner_source_path(owner):
    # module() is the actual held canonical Owner implementation, even when a
    # reviewed entrypoint subclasses Owner for a finite case dispatcher.
    return owner.module.__func__.__globals__['__file__']


class CallerCollectionHold:
    def __init__(self, owner, inputs):
        require(not hasattr(owner, 'caller_collection_hold'), 'one-caller-collection-hold')
        self.owner = owner
        self.inputs = inputs
        self.state = 'arming'
        self.observations = []
        self.pending_observation = None
        self.publication = None
        self.ready_lease = None
        self.release_lease = None
        self.driver_result = None
        self.failure = None
        owner.caller_collection_hold = self  # Custody before any module/file IO.
        try:
            owner.guard()
            self.self_pin = self._pin(str(PureWindowsPath(__file__)))
            protocol_path = str(PureWindowsPath(__file__).with_name('hold_protocol.py'))
            require(self._pin(protocol_path)['sha256'] == PROTOCOL_SHA, 'held-fixed-hold-protocol')
            self.protocol = owner.module(protocol_path, '_caller_hold_protocol_' + owner.operation.replace('-', ''))
            p = self.protocol
            p.validate_inputs(inputs, ordinary_task_operation_id=owner.operation,
                program_data=os.environ.get('ProgramData', ''))
            # Make independent immutable data: the harness must not alter an
            # armed operation's scope, stage, source or destination.
            self.inputs = p.decode(p.encoded(inputs))
            receipts_path = self.inputs['receiptsPath']
            require(self._pin(receipts_path)['sha256'] == RECEIPTS_SHA, 'held-fixed-hold-receipts')
            self.receipts = owner.module(receipts_path, '_caller_hold_receipts_' + owner.operation.replace('-', ''))
            self.worker_source_pin = self._pin(owner_source_path(owner))
            self.worker = self._worker_actor()
            self.ready_path = str(PureWindowsPath(str(owner.root)) /
                ('collector-hold-' + self.inputs['collectorOperationId'] + '.ready.json'))
            self.release_path = str(PureWindowsPath(self.inputs['collectorRoot']) / 'close-release.json')
            self.close_hold = p.validate_close_hold({'schemaVersion': 1, 'callerSourcePin': self.self_pin,
                'holdReadyPath': self.ready_path, 'releasePath': self.release_path,
                **{key: self.inputs[key] for key in ('scope', 'stage', 'sourceSha')}})
            root = p.path(self.inputs['collectorRoot'])
            have = {str(pin.path).casefold() for pin in owner.pins if pin.directory}
            require(all(str(a).casefold() in have for a in root.parents), 'hold-admitted-system-root-ancestry')
            self.root_lease = self._open(str(root), directory=True)
            self.receipts.machine_security(self.root_lease.opening['security'], True)
            self._guard()
            self.state = 'armed'
        except BaseException as error:
            self._park('caller-collection-hold-arm-unknown', error)

    def _pin(self, path):
        pin = self.owner.by_path[str(PureWindowsPath(path)).casefold()]
        pin.digest()
        return pin.record

    def _worker_actor(self):
        o = self.owner
        image = str(PureWindowsPath(sys.executable))
        require(image.casefold() == o.request['pythonRuntime']['interpreterPath'].casefold(),
            'hold-actual-ordinary-interpreter')
        image_pin = self._pin(image)
        return {'pid': os.getpid(), 'birthFileTimeUtc': o.native.birth(o.native.k.GetCurrentProcess()),
            'image': image, 'sha256': image_pin['sha256'], 'sid': o.request['context']['ordinarySid'],
            'sessionId': o.request['context']['ordinarySessionId']}

    def _park(self, reason, error):
        self.state = 'unknown'
        self.failure = {'reason': reason, 'error': error}
        # Actual Owner.park never returns, releases pins, cleans or reruns code.
        return self.owner.park(reason, error)

    def _open(self, path, *, directory=False):
        cls = self.receipts.FileObservation
        lease = cls.__new__(cls)
        self.pending_observation = lease
        try:
            cls.__init__(lease, self.owner, path, directory=directory)
        except OSError:
            # CreateFile failure produced no handle. It is safe to retry only
            # that absent/temporarily shared read, never a mutation or a live FD.
            if getattr(lease, 'handle', None) == INVALID_HANDLE:
                self.pending_observation = None
            raise
        self.observations.append(lease)
        self.pending_observation = None
        return lease

    def _read_protected(self, path, maximum):
        lease = self._open(path)
        self.receipts.machine_security(lease.opening['security'], False)
        raw = lease.read(maximum)
        return self.protocol.decode(raw, maximum), raw, lease

    def _guard(self):
        self.owner.guard()
        require(self._worker_actor() == self.worker, 'hold-same-original-ordinary-worker')
        if self.driver_result == 0:
            self._children_terminal()
        for lease in self.observations:
            require(lease.describe() == lease.opening, 'hold-retained-observation-generation')
            lease._canonical()

    def _children_terminal(self):
        for child in self.owner.children:
            terminal = child.terminal
            require(type(terminal) is dict and terminal.get('pid') == child.pid
                and terminal.get('birthFileTimeUtc') == child.birth
                and terminal.get('eof') == {'stdout': True, 'stderr': True}
                and terminal.get('sourceClosing') is True and terminal.get('originalHandleRetained') is True
                and child.eof == {'stdout': True, 'stderr': True}
                and child.process.poll() is not None, 'hold-all-original-children-terminal-and-eof')

    def driver_completed(self, result):
        require(self.state == 'armed', 'hold-driver-result-already-consumed')
        try:
            require(type(result) is int and result == 0, 'hold-known-driver-result-zero')
            self._guard(); self._children_terminal()
            self.driver_result = result
            self.state = 'driver-terminal'
        except BaseException as error:
            self._park('caller-collection-driver-unknown', error)

    def _collector_binding(self):
        p = self.protocol
        root = PureWindowsPath(self.inputs['collectorRoot'])
        request, raw, request_lease = self._read_protected(str(root / 'collector-request.json'), 4 * 1024 * 1024)
        i = self.inputs
        require(request.get('schemaVersion') == 1 and request.get('operationId') == i['collectorOperationId']
            and request.get('ordinaryTaskOperationId') == self.owner.operation
            and request.get('operationRoot') == i['collectorRoot']
            and request.get('requestPath') == str(root / 'collector-request.json')
            and request.get('scope') == i['scope'], 'hold-current-system-request')
        c = request.get('context', {})
        require(c.get('bootIdentifier') == self.owner.request['context']['bootIdentifier']
            and c.get('ordinarySid') == self.worker['sid'] and c.get('ordinarySessionId') == self.worker['sessionId']
            and c.get('machineGuid') == self.owner.request['context']['machineGuid'], 'hold-system-request-current-context')
        modules = request.get('modules', {})
        for role, key in (('collector', 'collectorSourceSha256'), ('contract', 'systemContractSourceSha256'),
                          ('worker', 'systemWorkerSourceSha256')):
            require(modules.get(role, {}).get('sha256') == i[key], 'hold-fixed-system-request-source-' + role)
        cr = request.get('collectorRequest', {})
        require(cr.get('ordinaryTaskOperationId') == self.owner.operation and cr.get('sourceSha') == i['sourceSha']
            and cr.get('collectorSourceSha256') == i['collectorSourceSha256']
            and (cr.get('stage') if i['scope'] == 'update' else 'off') == i['stage'], 'hold-exact-collected-stage-source')
        p.validate_close_hold(request.get('closeHold'), self.close_hold)
        task = request.get('ordinaryTask', {})
        expected_actor = {'pid': self.worker['pid'], 'creationFileTime': int(self.worker['birthFileTimeUtc']),
            'image': self.worker['image'], 'sha256': self.worker['sha256'], 'sid': self.worker['sid'],
            'sessionId': self.worker['sessionId']}
        require(task.get('workerActor') == expected_actor and task.get('workerSourcePin') == self.worker_source_pin,
            'hold-system-request-actual-original-owner-worker')
        worker_record = p.source_pin(task.get('workerRequestPin'))
        worker_pin = next((pin for pin in self.owner.pins if not pin.directory and pin.record == worker_record), None)
        require(worker_pin is not None, 'hold-original-worker-request-native-pin')
        worker_doc = p.decode(worker_pin.digest(True, 4 * 1024 * 1024), 4 * 1024 * 1024)
        require(worker_doc.get('operationId') == self.owner.operation
            and self.self_pin in worker_doc.get('filePins', []), 'hold-caller-source-in-original-worker-request')
        intent, _, _ = self._read_protected(str(root / 'task-event-000000-submission-intent.json'), 256 * 1024)
        submitted, _, _ = self._read_protected(str(root / 'task-event-000001-submitted.json'), 256 * 1024)
        event_fields = {'schemaVersion', 'operationId', 'ownerPid', 'ownerBirthFileTimeUtc', 'ordinal', 'kind', 'value'}
        for event, ordinal, kind in ((intent, 0, 'submission-intent'), (submitted, 1, 'submitted')):
            require(set(event) == event_fields and type(event['schemaVersion']) is int and event['schemaVersion'] == 1
                and event['operationId'] == i['collectorOperationId'] and type(event['ordinal']) is int
                and event['ordinal'] == ordinal and event['kind'] == kind, 'hold-original-system-event')
            p._actor({'pid': event['ownerPid'], 'birthFileTimeUtc': event['ownerBirthFileTimeUtc']})
        require(intent['ownerPid'] == submitted['ownerPid']
            and intent['ownerBirthFileTimeUtc'] == submitted['ownerBirthFileTimeUtc'], 'hold-same-original-system-ps')
        v = intent['value']
        require(type(v) is dict and set(v) == {'scope', 'fileName', 'argv', 'sourceAndRuntimePinsHeld',
            'nativeToken', 'requestSha256', 'replayAllowed'} and v['scope'] == i['scope']
            and v['requestSha256'] == digest(raw) and v['sourceAndRuntimePinsHeld'] is True
            and v['replayAllowed'] is False and v['fileName'] == request.get('pythonRuntime', {}).get('interpreterPath')
            and type(v['argv']) is list and len(v['argv']) == 10
            and v['argv'][:5] == ['-I', '-S', '-B', modules['worker']['path'], '--request']
            and v['argv'][5] == request['requestPath'] and v['argv'][6:8] == ['--request-sha256', digest(raw)]
            and v['argv'][8] == '--request-pin-base64', 'hold-system-submission-source-request')
        import base64
        actual_request_pin = p.decode(base64.b64decode(v['argv'][9], validate=True))
        p.source_pin(actual_request_pin)
        require(actual_request_pin == {**request_lease.opening, 'sha256': digest(raw)},
            'hold-system-submission-native-request-pin')
        require(type(v['nativeToken']) is list and len(v['nativeToken']) == 4
            and v['nativeToken'][:3] == ['S-1-5-18', '0', '1'] and v['nativeToken'][3] in {'1', '2'},
            'hold-system-submission-token')
        v = submitted['value']
        require(type(v) is dict and set(v) == {'pid', 'birthFileTimeUtc', 'originalHandleRetained'}
            and v['originalHandleRetained'] is True, 'hold-original-system-child-event')
        p._actor({key: v[key] for key in ('pid', 'birthFileTimeUtc')})
        self.collector_request = request
        return {'collectorRequestSha256': digest(raw),
            'systemActor': {'pid': intent['ownerPid'], 'birthFileTimeUtc': intent['ownerBirthFileTimeUtc']},
            'collectorChild': {key: v[key] for key in ('pid', 'birthFileTimeUtc')}}

    def _publish_ready(self, ready):
        raw = self.protocol.encoded(ready)
        require(len(raw) <= 256 * 1024, 'hold-ready-byte-bound')
        publication = {'path': self.ready_path, 'raw': raw, 'handle': None, 'confirmedBytes': 0,
            'closeAttempted': False, 'closed': False}
        self.publication = publication  # Retain before the create-only native call.
        k = self.owner.native.k
        handle = k.CreateFileW(self.ready_path, 0xC0020000, 1, None, 1, 0x02200000, None)
        publication['handle'] = handle
        if handle == INVALID_HANDLE:
            publication['nativeError'] = getattr(ctypes, 'get_last_error', lambda: None)()
        require(handle != INVALID_HANDLE, 'hold-ready-create-only')
        buffer = ctypes.create_string_buffer(raw)
        publication['buffer'] = buffer
        write = k.WriteFile
        write.argtypes, write.restype = (W.HANDLE, W.LPVOID, W.DWORD, ctypes.POINTER(W.DWORD), W.LPVOID), W.BOOL
        while publication['confirmedBytes'] < len(raw):
            offset = publication['confirmedBytes']; count = W.DWORD()
            ok = write(W.HANDLE(handle), ctypes.byref(buffer, offset), len(raw) - offset, ctypes.byref(count), None)
            if not ok or not 0 < count.value <= len(raw) - offset:
                publication['failedWrite'] = {'result': bool(ok), 'reportedBytes': count.value,
                    'nativeError': getattr(ctypes, 'get_last_error', lambda: None)()}
                require(False, 'hold-ready-positive-full-native-write')
            publication['confirmedBytes'] += count.value
        flush = k.FlushFileBuffers
        flush.argtypes, flush.restype = (W.HANDLE,), W.BOOL
        publication['flushResult'] = bool(flush(W.HANDLE(handle)))
        if not publication['flushResult']:
            publication['nativeError'] = getattr(ctypes, 'get_last_error', lambda: None)()
        require(publication['flushResult'], 'hold-ready-native-flush')
        publication['nativeIdentityBeforeClose'] = self.owner.native.identity(handle)
        publication['closeAttempted'] = True
        publication['closeResult'] = bool(k.CloseHandle(W.HANDLE(handle)))
        if not publication['closeResult']:
            publication['nativeError'] = getattr(ctypes, 'get_last_error', lambda: None)()
        require(publication['closeResult'], 'hold-ready-native-close')
        publication['closed'] = True
        self.ready_lease = self._open(self.ready_path)
        require(self.ready_lease.read(256 * 1024) == raw, 'hold-ready-exact-created-bytes')
        old = publication['nativeIdentityBeforeClose']; new = self.ready_lease.opening['nativeIdentity']
        # Windows may commit last-write time when the writing handle closes.
        require({k: v for k, v in old.items() if k != 'lastWriteFileTime'} ==
            {k: v for k, v in new.items() if k != 'lastWriteFileTime'}, 'hold-ready-same-created-native-file')
        self.ready = ready
        self.ready_sha256 = digest(raw)

    def wait_for_release(self):
        require(self.state == 'driver-terminal' and self.driver_result == 0, 'hold-known-driver-required-before-ready')
        try:
            self._guard(); self._children_terminal()
            joins = self._collector_binding()
            ready = {'schemaVersion': 1, 'kind': 'caller-collector-close-ready',
                'ordinaryTaskOperationId': self.owner.operation,
                **{key: self.inputs[key] for key in ('collectorOperationId', 'sourceSha', 'scope', 'stage')},
                'bootIdentifier': self.owner.request['context']['bootIdentifier'], 'ordinaryWorker': self.worker,
                'callerSourcePin': self.self_pin, **joins, 'driverKnownResult': 0,
                'allOriginalChildrenTerminalAndEof': True}
            self.protocol.validate_ready(ready)
            self.state = 'ready-publishing'
            self._publish_ready(ready)
            self.state = 'waiting-release'
            while True:
                self._guard()
                try:
                    value, _, self.release_lease = self._read_protected(self.release_path, 8 * 1024 * 1024)
                except OSError as error:
                    if self.pending_observation is not None or getattr(error, 'winerror', None) not in {2, 3, 32}:
                        raise
                    time.sleep(0.1)
                    continue
                self.protocol.validate_release(value, self.ready, self.ready_sha256,
                    self.ready_lease.opening['nativeIdentity'])
                self._guard()
                self.release = value
                self.state = 'released'
                return value
        except BaseException as error:
            return self._park('caller-collection-close-hold-unknown', error)
