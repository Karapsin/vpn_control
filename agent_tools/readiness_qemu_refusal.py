"""Held local proof of one completed, source-owned QEMU power refusal.

A carrier returning is not VM admission. Only the exact terminal exception path
of the reviewed controller can attest refusal while holding its original lock.
The proof never authorizes legacy foreground replay or unknown controllers.
"""
import ast
from contextlib import contextmanager, ExitStack
import hashlib
import inspect
import json
import os
from pathlib import Path
import re
import stat
from uuid import UUID, uuid5

from . import readiness_fixture_registry as registry
from . import private_inventory_lock as private
from . import readiness_qemu_remote as packets

SOURCE_NAMES = ('readiness_qemu.py', 'readiness_qemu_remote.py', 'readiness_qemu_guest.py',
                'readiness_qemu_idle.py', 'readiness_qemu_jobs.py', 'durable_remote_job.py',
                'readiness_resources.py', 'windows_vm_resources.py', 'readiness_qemu_refusal.py')


def _need(value, reason):
    if not value:
        raise ValueError(reason)


def snapshot_sha256(value):
    return None if value is None else hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def _json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            _need(key not in result, 'qemu_refusal_duplicate_field'); result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs)


def _generation(info):
    return [info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns]


class HeldFile:
    def __init__(self, path, *, private_file=True):
        self.path = Path(path)
        _need(self.path.is_absolute() and self.path == self.path.resolve(strict=True), 'qemu_refusal_path')
        self.presented = private.PresentedPath(self.path.parent)
        self.directory = private.Directory(self.presented.canonical)
        self.directory.__enter__()
        try:
            self.fd = os.open(self.path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self.directory.fd)
            info = os.fstat(self.fd)
            _need(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and info.st_nlink == 1
                  and not info.st_mode & 0o022 and 0 < info.st_size <= 2 * 1024**2
                  and (not private_file or stat.S_IMODE(info.st_mode) == 0o600), 'qemu_refusal_file_unsafe')
            self.raw = os.read(self.fd, 2 * 1024**2 + 1)
            _need(len(self.raw) == info.st_size, 'qemu_refusal_file_bound')
            self.pin = {'generation': _generation(info), 'sha256': hashlib.sha256(self.raw).hexdigest()}
            self.guard()
        except BaseException:
            if hasattr(self, 'fd'): os.close(self.fd)
            self.directory.__exit__(None, None, None)
            raise
    def guard(self):
        _need(_generation(os.fstat(self.fd)) == self.pin['generation'] ==
              _generation(os.stat(self.path.name, dir_fd=self.directory.fd, follow_symlinks=False)), 'qemu_refusal_file_changed')
        self.presented.guard(); self.directory.guard()
    def close(self):
        os.close(self.fd); self.directory.__exit__(None, None, None)


def _parameters(raw):
    wanted = {'BINDING', 'PINS', 'ACTION', 'RECOVERY_ID', 'EXPECTED', 'ADMISSION', 'NAMESPACE', 'IDLE_CONTEXT', 'IDLE_OPERATION', 'DISPATCH_IDENTITY'}
    result = {}
    for node in ast.parse(raw).body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) and node.targets[0].id in wanted:
            key = node.targets[0].id
            _need(key not in result, 'qemu_refusal_packet_duplicate')
            for child in ast.walk(node.value):
                if isinstance(child, ast.Dict):
                    keys = [item.value if isinstance(item, ast.Constant) and type(item.value) is str else None for item in child.keys]
                    _need(None not in keys and len(keys) == len(set(keys)), 'qemu_refusal_packet_duplicate')
            result[key] = ast.literal_eval(node.value)
    _need(set(result) == wanted, 'qemu_refusal_packet_fields')
    return result


def _remote(value, parameters):
    keys = {'schemaVersion', 'provider', 'reason', 'action', 'recoveryId', 'attempt', 'dispatchDigest', 'controllerSourceSha256',
            'controller', 'fixture', 'assets', 'expected', 'actual', 'rootGeneration', 'operatorGeneration', 'managerGeneration',
            'originalActor', 'cleanStop', 'powerIntentAbsent', 'noVmEffectAdmitted', 'resourceSnapshotSha256', 'phase'}
    _need(type(value) is dict and set(value) == keys and type(value['schemaVersion']) is int and value['schemaVersion'] == 1
          and value['provider'] == 'raw-qemu-linux' and value['reason'] == 'prepared_context_stale'
          and value['action'] == parameters['ACTION'] and value['fixture'] == parameters['BINDING']
          and value['assets'] == parameters['PINS'] and value['expected'] == parameters['EXPECTED']
          and value['powerIntentAbsent'] is True and value['noVmEffectAdmitted'] is True
          and value['resourceSnapshotSha256'] == snapshot_sha256(parameters['ADMISSION'])
          and value['controllerSourceSha256'] == hashlib.sha256(inspect.getsource(packets._main).encode()).hexdigest(), 'qemu_refusal_remote_binding')
    _need({key: value[key] for key in ('recoveryId', 'attempt', 'dispatchDigest')} == parameters['DISPATCH_IDENTITY']
          and type(value['attempt']) is int and 1 <= value['attempt'] <= 3, 'qemu_refusal_remote_dispatch')
    pins = parameters['PINS']; owner = value['expected']['owner']; actual = value['actual']
    _need(type(actual) is dict and set(actual) == {'owner', 'boot', 'guest'} and actual != value['expected']
          and actual['owner'] == owner and type(owner) is dict and owner['preparationId'] == parameters['BINDING']['machine']
          and owner['hostBootId'] == pins['hostBoot'] and actual['guest'] in {'running', 'booting', 'paused', 'suspended', 'unhealthy', 'stopped'},
          'qemu_refusal_actor_binding')
    for state in (actual, value['expected']):
        _need(state['boot'] is None or (type(state['boot']) is str and str(UUID(state['boot'])) == state['boot']), 'qemu_refusal_guest_boot')
    controller = value['controller']
    _need(type(controller) is dict and set(controller) == {'pid', 'startTicks', 'uid', 'hostBootId'}
          and all(type(controller[key]) is int and controller[key] > 0 for key in ('pid', 'startTicks'))
          and type(controller['uid']) is int and controller['uid'] == pins['root'][3]
          and controller['hostBootId'] == pins['hostBoot'] and controller['pid'] != owner['pid'], 'qemu_refusal_controller')
    for key in ('rootGeneration', 'operatorGeneration', 'managerGeneration'):
        generation = value[key]
        if key == 'managerGeneration' and generation is None: continue
        _need(type(generation) is list and len(generation) == 9 and all(type(item) is int and item >= 0 for item in generation), 'qemu_refusal_barrier')
        _need(generation[3] == controller['uid'], 'qemu_refusal_barrier_owner')
        if key == 'operatorGeneration':
            _need(stat.S_ISREG(generation[2]) and stat.S_IMODE(generation[2]) == 0o600 and generation[5] == 1, 'qemu_refusal_operator')
        else:
            _need(stat.S_ISDIR(generation[2]) and stat.S_IMODE(generation[2]) == 0o700, 'qemu_refusal_directory')
    _need(value['rootGeneration'][:5] == pins['root'], 'qemu_refusal_original_root')
    _need(value['phase'] in {'operator', 'qmp', 'guest_ssh', 'guest_agent'}, 'qemu_refusal_phase')
    if value['originalActor'] == 'alive':
        _need(actual['guest'] != 'stopped' and value['cleanStop'] is None, 'qemu_refusal_original_actor')
    else:
        stopped = value['cleanStop']
        _need(value['originalActor'] == 'absent' and parameters['ACTION'] == 'start' and actual['guest'] == 'stopped'
              and type(stopped) is dict and set(stopped) == {'machineUuid', 'hostBootId', 'actor', 'cleanPoweroffOperationId', 'cleanPoweroff', 'guestJobsAbsent'}
              and stopped['machineUuid'] == parameters['BINDING']['machine'] and stopped['hostBootId'] == pins['hostBoot']
              and stopped['actor'] == {key: owner[key] for key in ('pid', 'startTicks')}
              and stopped['cleanPoweroff'] is True and stopped['guestJobsAbsent'] is True
              and str(UUID(stopped['cleanPoweroffOperationId'])) == stopped['cleanPoweroffOperationId'], 'qemu_refusal_original_actor')


@contextmanager
def validated_remote_refusal(root, *, attestation_path, attestation_sha256, machine_uuid, operation_id, recovery_id,
                             attempt, dispatch_digest, packet_sha256, resource_snapshot, fixture_host, fixture_root):
    """Pure local inspection with held descriptors through the caller's record."""
    root = Path(root).resolve(strict=True)
    _need(str(UUID(machine_uuid)) == machine_uuid and str(uuid5(UUID(machine_uuid), recovery_id)) == operation_id
          and type(attempt) is int and 1 <= attempt <= 3
          and all(type(value) is str and re.fullmatch('[a-f0-9]{64}', value) for value in (attestation_sha256, recovery_id, dispatch_digest, packet_sha256)),
          'qemu_refusal_expected_identity')
    expected_path = root / '.runtime/readiness-qemu/unsubmitted-remote' / recovery_id / (str(attempt) + '.json')
    _need(Path(attestation_path) == expected_path, 'qemu_refusal_attestation_path')
    held = []
    def take(path, **kwargs):
        file = HeldFile(path, **kwargs); held.append(file); return file
    try:
        attestation_file = take(expected_path)
        _need(attestation_file.pin['sha256'] == attestation_sha256, 'qemu_refusal_attestation_changed')
        envelope = _json(attestation_file.raw)
        fields = {'schemaVersion', 'provider', 'action', 'machineUuid', 'operationId', 'recoveryId', 'attempt', 'dispatchDigest',
                  'resourceSnapshotSha256', 'sourceClosure', 'packet', 'capture', 'remote'}
        _need(type(envelope) is dict and set(envelope) == fields and type(envelope['schemaVersion']) is int and envelope['schemaVersion'] == 1
              and envelope['provider'] == 'raw-qemu-linux' and envelope['action'] in {'start', 'resume', 'reboot'}
              and envelope['machineUuid'] == machine_uuid and envelope['operationId'] == operation_id
              and envelope['recoveryId'] == recovery_id and type(envelope['attempt']) is int and envelope['attempt'] == attempt
              and envelope['dispatchDigest'] == dispatch_digest and envelope['resourceSnapshotSha256'] == snapshot_sha256(resource_snapshot),
              'qemu_refusal_envelope_binding')
        _need((resource_snapshot is not None) == (envelope['action'] == 'start'), 'qemu_refusal_start_snapshot')
        sources = {}
        for name in SOURCE_NAMES:
            file = take(Path(__file__).with_name(name), private_file=False); sources[name] = file.pin['sha256']
        _need(envelope['sourceClosure'] == sources, 'qemu_refusal_source_changed')
        item = envelope['packet']; capture_item = envelope['capture']
        _need(type(item) is dict and set(item) == {'path', 'pin'} and type(capture_item) is dict and set(capture_item) == {'path', 'pin'}, 'qemu_refusal_artifact_fields')
        packet_path = Path(item['path']);capture_path = Path(capture_item['path'])
        _need(packet_path.parent == root / '.runtime/readiness-qemu' / operation_id
              and re.fullmatch(r'[1-9][0-9]{8,24}-' + envelope['action'] + r'\.py', packet_path.name)
              and capture_path == packet_path.with_suffix('.capture.json'), 'qemu_refusal_original_artifacts')
        packet = take(packet_path); capture_file = take(capture_path)
        _need(packet.pin == item['pin'] and packet.pin['sha256'] == packet_sha256 and capture_file.pin == capture_item['pin'], 'qemu_refusal_original_changed')
        capture = _json(capture_file.raw)
        _need(type(capture) is dict and set(capture) == {'returnCode', 'stdout', 'stderrBytes', 'sourceSha256', 'executionComplete', 'stdoutEof', 'stderrEof'}
              and type(capture['returnCode']) is int and capture['returnCode'] == 0 and type(capture['stderrBytes']) is int and capture['stderrBytes'] == 0
              and capture['executionComplete'] is True and capture['stdoutEof'] is True and capture['stderrEof'] is True
              and capture['sourceSha256'] == packet_sha256 and type(capture['stdout']) is str
              and 0 < len(capture['stdout'].encode('utf-8')) <= 262144, 'qemu_refusal_terminal_capture')
        response = _json(capture['stdout'])
        _need(type(response) is dict and set(response) == {'state', 'reason', 'phase', 'errorClass', 'vmSubmitted', 'completedRefusal'}
              and response['state'] == 'blocked' and response['reason'] == 'prepared_context_stale' and response['errorClass'] == 'ValueError'
              and response['vmSubmitted'] is False and response['completedRefusal'] == envelope['remote']
              and response['phase'] == envelope['remote']['phase'], 'qemu_refusal_terminal_response')
        parameters = _parameters(packet.raw)
        binding = parameters['BINDING']
        _need(binding == {'host':fixture_host, 'root':fixture_root, 'machine':machine_uuid, 'target':'qemu-linux:'+machine_uuid}
              and parameters['ACTION'] == envelope['action'] and parameters['RECOVERY_ID'] == recovery_id
              and parameters['DISPATCH_IDENTITY'] == {'recoveryId':recovery_id, 'attempt':attempt, 'dispatchDigest':dispatch_digest}
              and parameters['ADMISSION'] == resource_snapshot and parameters['IDLE_OPERATION'] is None, 'qemu_refusal_packet_binding')
        expected = packets.program(binding, parameters['PINS'], parameters['ACTION'], recovery_id, parameters['EXPECTED'],
                                   resource_snapshot, parameters['NAMESPACE'], idle_context=parameters['IDLE_CONTEXT'],
                                   dispatch_identity=parameters['DISPATCH_IDENTITY'])
        _need(packet.raw == expected.encode(), 'qemu_refusal_packet_source')
        _remote(envelope['remote'], parameters)
        def guard():
            for file in held: file.guard()
        guard()
        yield type('VerifiedRemoteRefusal', (), {'guard': staticmethod(guard), 'data': envelope})()
        guard()
    finally:
        for file in reversed(held): file.close()
