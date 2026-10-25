"""SOURCE-ONLY ordinary reliability helper; no transport or native implementation.

Callbacks supply fresh normal-SDK public status and fixed harmless counter data.
This file cannot start/replay a job, create a connection, inject a fault, read a
credential or signal a process. A later reviewed adapter must bind every callback
to its current source capsule before any actual qualification is authorized.
"""
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time
from uuid import UUID


STDOUT_LIMIT = 2 * 1024 * 1024
STDERR_LIMIT = 65536
OLD_OPERATION = '61bd241b-5633-46d8-9a7f-0e90d74bf5c0'


class QualificationBlocked(ValueError):
    pass


_RUNNING_ISSUER = object()


@dataclass(frozen=True, repr=False)
class _ObservedRunning:
    issuer: object
    operation: str
    host: str
    owner: tuple


def _identity(operation, host):
    if (type(operation) is not str or str(UUID(operation)) != operation or operation == OLD_OPERATION or
            type(host) is not str or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', host) is None):
        raise QualificationBlocked('qualification_identity_invalid')


def wait_running(operation, host, fresh_sdk_status, *, deadline, pause=time.sleep, clock=time.monotonic):
    """Only the actual observed-running schema permits a later counter probe."""
    _identity(operation, host)
    while clock() < deadline:
        value = fresh_sdk_status('program-status', {'host': host, 'identity': {'operationId': operation}})
        if (type(value) is not dict or value.get('operationId') != operation or value.get('host') != host or
                type(value.get('schemaVersion')) is not int or value['schemaVersion'] != 1 or
                value.get('replayAllowed') is not False):
            raise QualificationBlocked('qualification_status_identity_mismatch')
        if value.get('state') == 'terminal':
            raise QualificationBlocked('qualification_original_terminal_collect_only')
        owner = value.get('remoteOwner')
        owner_valid = (type(owner) is dict and set(owner) == {'pid', 'birth'} and
                       type(owner['pid']) is int and owner['pid'] > 0 and type(owner['birth']) is str and
                       re.fullmatch(r'(?:linux:[1-9][0-9]*|darwin:[1-9][0-9]*:[0-9]{1,6})', owner['birth']) is not None)
        if (value.get('state') == 'pending' and value.get('reason') == 'original_remote_owner_observed' and
                value.get('remoteState') == 'running' and value.get('remoteOperationId') == operation and
                type(value.get('durableProtocol')) is int and value['durableProtocol'] == 1 and owner_valid):
            return _ObservedRunning(_RUNNING_ISSUER, operation, host, tuple(sorted(owner.items())))
        if value.get('state') not in ('pending', 'running'):
            raise QualificationBlocked('qualification_original_state_unresolved')
        remaining = deadline - clock()
        if remaining > 0:
            pause(min(.15, remaining))
    raise QualificationBlocked('qualification_running_not_observed')


def _generation(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


class _OutputCapture:
    """Private FD custody remains independent of source/transport guards."""
    def __init__(self, root, label):
        self.chain, self.files, self.leaf = [], [], None
        root = Path(root)
        if (not root.is_absolute() or '..' in root.parts or
                re.fullmatch(r'counter-[0-9]{6}', label) is None):
            raise QualificationBlocked('qualification_retention_root_invalid')
        self.label = label
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        try:
            descriptor = os.open('/', flags)
            self.chain.append((descriptor, None, _generation(os.fstat(descriptor))))
            for name in root.parts[1:]:
                descriptor = os.open(name, flags, dir_fd=self.chain[-1][0])
                self.chain.append((descriptor, name, _generation(os.fstat(descriptor))))
            self.root = self.chain[-1][0]
            info = os.fstat(self.root)
            if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700 or not self.named_custody():
                raise QualificationBlocked('qualification_retention_root_invalid')
            os.mkdir(label, 0o700, dir_fd=self.root)
            os.fsync(self.root)
            self.leaf = os.open(label, flags, dir_fd=self.root)
            self.root_generation = _generation(os.fstat(self.root))
            self.leaf_generation = _generation(os.fstat(self.leaf))
            self.leaf_admission_generation = self.leaf_generation
            info = os.fstat(self.leaf)
            if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise QualificationBlocked('qualification_output_custody_changed')
            self.guard_data()
        except BaseException:
            self.close()
            raise

    def named_custody(self):
        try:
            for index, (descriptor, name, initial) in enumerate(self.chain):
                held = _generation(os.fstat(descriptor))
                named = _generation(os.stat('/', follow_symlinks=False) if index == 0 else
                    os.stat(name, dir_fd=self.chain[index - 1][0], follow_symlinks=False))
                # Shared ancestor membership timestamps may change independently;
                # names, kernel objects, type, mode and ownership may never drift.
                if held[:5] != initial[:5] or named[:5] != held[:5] or not stat.S_ISDIR(named[2]):
                    return False
            return not hasattr(self, 'root_generation') or _generation(os.fstat(self.root)) == self.root_generation
        except OSError:
            return False

    def guard_data(self):
        for descriptor, _, initial in self.chain:
            if _generation(os.fstat(descriptor))[:5] != initial[:5]:
                raise QualificationBlocked('qualification_output_custody_changed')
        if (_generation(os.fstat(self.leaf)) != self.leaf_generation or
                _generation(os.stat(self.label, dir_fd=self.root, follow_symlinks=False)) != self.leaf_generation or
                set(os.listdir(self.leaf)) != {name for _, name, _, _ in self.files}):
            raise QualificationBlocked('qualification_output_custody_changed')
        for descriptor, name, initial, raw in self.files:
            if (_generation(os.fstat(descriptor)) != initial or
                    _generation(os.stat(name, dir_fd=self.leaf, follow_symlinks=False)) != initial or
                    os.pread(descriptor, len(raw) + 1, 0) != raw):
                raise QualificationBlocked('qualification_output_file_changed')

    def write(self, name, raw):
        self.guard_data()
        descriptor = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=self.leaf)
        try:
            offset = 0
            while offset < len(raw):
                count = os.write(descriptor, raw[offset:])
                if count <= 0:
                    raise QualificationBlocked('qualification_output_write_incomplete')
                offset += count
            os.fsync(descriptor)
            info = os.fstat(descriptor)
            initial = _generation(info)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid() or
                    stat.S_IMODE(info.st_mode) != 0o600 or
                    _generation(os.stat(name, dir_fd=self.leaf, follow_symlinks=False)) != initial):
                raise QualificationBlocked('qualification_output_file_changed')
            self.files.append((descriptor, name, initial, raw))
            descriptor = None
            current = _generation(os.fstat(self.leaf))
            if current[:5] != self.leaf_generation[:5]:
                raise QualificationBlocked('qualification_output_custody_changed')
            self.leaf_generation = current  # Only this owned file creation changed the private leaf.
            os.fsync(self.leaf)
            self.guard_data()
        finally:
            if descriptor is not None:
                os.close(descriptor)

    def close(self):
        for descriptor, _, _, _ in reversed(self.files):
            os.close(descriptor)
        self.files.clear()
        if self.leaf is not None:
            os.close(self.leaf)
            self.leaf = None
        for descriptor, _, _ in reversed(self.chain):
            os.close(descriptor)
        self.chain.clear()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        try:
            self.guard_data()
        finally:
            self.close()


def _retain(capture, operation, result):
    if type(result) is not subprocess.CompletedProcess:
        raise QualificationBlocked('qualification_completed_result_invalid')
    if type(result.stdout) is not bytes or type(result.stderr) is not bytes or type(result.returncode) is not int:
        raise QualificationBlocked('qualification_completed_binary_result_invalid')
    capped = len(result.stdout) > STDOUT_LIMIT or len(result.stderr) > STDERR_LIMIT
    capture.write('stdout.bin', result.stdout[:STDOUT_LIMIT])
    capture.write('stderr.bin', result.stderr[:STDERR_LIMIT])
    receipt = {'schemaVersion': 1, 'operationId': operation, 'purpose': 'ordinary-fixed-counter-observation',
               'returnCode': result.returncode, 'complete': not capped, 'streamCapped': capped,
               'countsObserved': {'stdout': len(result.stdout), 'stderr': len(result.stderr)},
               'countsRetained': {'stdout': min(len(result.stdout), STDOUT_LIMIT),
                                  'stderr': min(len(result.stderr), STDERR_LIMIT)},
               'namedCustody': capture.named_custody(),
               'outputRootAdmissionGeneration': capture.root_generation,
               'outputLeafAdmissionGeneration': capture.leaf_admission_generation,
               'replayAllowed': False, 'nativeAcceptanceClaim': False}
    capture.write('receipt.json', json.dumps(receipt, sort_keys=True).encode() + b'\n')
    return receipt


def _counter_probe(running, public_probe, closing_guard, output_root, *,
                  label='counter-000001', submitted_result_error_type=None):
    """Retain completed public bytes before assertions and post-return guards."""
    if type(running) is not _ObservedRunning or running.issuer is not _RUNNING_ISSUER:
        raise QualificationBlocked('qualification_running_proof_invalid')
    operation, host, owner = running.operation, running.host, dict(running.owner)
    _identity(operation, host)
    if submitted_result_error_type is not None and not (
            isinstance(submitted_result_error_type, type) and issubclass(submitted_result_error_type, Exception)):
        raise QualificationBlocked('qualification_completed_error_type_invalid')
    with _OutputCapture(output_root, label) as capture:
        return _captured_counter_probe(capture, operation, owner, public_probe, closing_guard, submitted_result_error_type)


def _captured_counter_probe(capture, operation, owner, public_probe, closing_guard, submitted_result_error_type):
    closing_guard()
    try:
        result = public_probe()
    except Exception as error:
        if submitted_result_error_type is not None and type(error) is submitted_result_error_type:
            # A reviewed adapter may pass ONLY the exact current transport class,
            # never a general exception/duck-typed getter. CompletedProcess.args
            # is never retained, hashed, rendered or used to select a new call.
            result = error.take_submitted_result()
            _retain(capture, operation, result)
            raise QualificationBlocked('qualification_completed_public_result_readiness_refused') from None
        raise QualificationBlocked('qualification_public_probe_outcome_unknown') from None
    receipt = _retain(capture, operation, result)
    if not receipt['namedCustody'] or not capture.named_custody():
        raise QualificationBlocked('qualification_output_named_custody_changed')
    try:
        closing_guard()
    except BaseException:
        raise QualificationBlocked('qualification_public_probe_closing_guard_refused') from None
    capture.guard_data()
    if not capture.named_custody():
        raise QualificationBlocked('qualification_output_named_custody_changed')
    if not receipt['complete']:
        raise QualificationBlocked('qualification_public_probe_stream_limit')
    if result.returncode or result.stderr:
        raise QualificationBlocked('qualification_public_probe_failed')
    try:
        value = json.loads(result.stdout)
    except (ValueError, UnicodeError):
        raise QualificationBlocked('qualification_counter_reply_malformed') from None
    if (type(value) is not dict or set(value) != {'operationId', 'owner', 'executions', 'lines'} or
            value['operationId'] != operation or value['owner'] != owner or
            type(value['executions']) is not int or value['executions'] != 1 or
            type(value['lines']) is not int or value['lines'] < 0):
        raise QualificationBlocked('qualification_counter_reply_mismatch')
    return value


def observe_ordinary(operation, host, fresh_sdk_status, public_probe, closing_guard, output_root, *, deadline,
                     submitted_result_error_type=None, pause=time.sleep, clock=time.monotonic):
    running = wait_running(operation, host, fresh_sdk_status, deadline=deadline, pause=pause, clock=clock)
    if clock() >= deadline:
        raise QualificationBlocked('qualification_deadline_before_counter_probe')
    return _counter_probe(running, public_probe, closing_guard, output_root,
                         submitted_result_error_type=submitted_result_error_type)
