"""Give one Windows test clone's own host-capacity reservation back, on fresh proof.

windows_vm_deploy reserves capacity before a start and marks it running after
boot; stop and status keep it. This closed action releases only the row whose
identity is the deployment's own private reservation file, and only when a fresh
read proves that the VM cannot run:

(a) clean absence on the reservation's own host boot: a fresh census of that boot
    lists no original QEMU, and the read-only status (never a stop) reports
    stopped-observed with positive absence of the bound original actors;
(b) ended host epoch: a fresh census reports another boot than the
    reservation's and no original QEMU. A reboot ends every VM of the old epoch
    and a deployment is create-only, so (b) never needs or replays a stop,
    including one that ended UNKNOWN.

Anything else is BLOCKED with a finite reason and releases nothing. A repeat
returns the retained terminal; a lost reply reconciles by reading the inventory,
so nothing is released twice or replayed. This module reads and calls the
deployment, reservation and resource modules; it never changes their sources.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import time
import uuid
from pathlib import Path

from . import native_environment as environments
from . import windows_vm_deploy as deploy
from . import windows_vm_resources as facts
from .native_vm_spec import FreshWindowsVmSpec

# Finite BLOCKED reasons; each one releases nothing.
REASONS = ('release_identity_mismatch', 'release_in_progress', 'release_incomplete', 'release_instance_running',
           'release_inventory_changed', 'release_observation_unknown', 'release_original_actor_mismatch',
           'release_original_actor_present', 'release_original_unbound', 'release_reservation_absent',
           'release_reservation_pending', 'release_reservation_state_unknown', 'release_status_unknown')
GROUP = 'windows-vm-deploy-releases'
_IDENTITY = ('reservationId', 'token', 'hostAlias', 'environment', 'operator')


def _result(deployment_id, state, reason=None, **facts_):
    if state == 'blocked' and reason not in REASONS:
        raise ValueError('release_reason')
    return {'schemaVersion': 1, 'deploymentId': deployment_id, 'mode': 'release', 'state': state, 'reason': reason,
            **facts_, 'nativeActionAllowed': False, 'replayAllowed': False}


def _private_directory(path, mask=0o077):
    # The owner rules of windows_vm_deploy._runtime_group: .runtime itself only refuses group/world write.
    info = os.lstat(path)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & mask:
        raise ValueError('release_private_directory')


def _private_json(path, limit=1048576):
    """Read one owner-only, single-link regular JSON file, never through a link."""
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_nlink != 1 or not 0 < info.st_size <= limit):
            raise ValueError('release_private_metadata')
        chunks, size = [], 0
        while True:
            block = os.read(descriptor, min(65536, limit + 1 - size))
            if not block:
                break
            chunks.append(block)
            size += len(block)
            if size > limit:
                raise ValueError('release_private_metadata')
        generation = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        if (size != info.st_size or generation(os.fstat(descriptor)) != generation(info)
                or generation(os.stat(path, follow_symlinks=False)) != generation(info)):
            raise ValueError('release_private_changed')
        return json.loads(b''.join(chunks), object_pairs_hook=deploy.transport._reject_duplicate_keys)
    finally:
        os.close(descriptor)


def _actor(value):
    if type(value) is not dict or set(value) != {'pid', 'startTicks'} or any(type(v) is not int or v <= 0 for v in value.values()):
        raise ValueError('release_original_actor')
    return dict(value)


def _identity(root, deployment_id):
    """The deployment's own start intent and private reservation identity."""
    intent = _private_json(root/'.rag_index/windows-vm-deploy-intents'/(deployment_id+'.intent.json'), 65536)
    if (type(intent) is not dict or set(intent) != {'spec', 'setup', 'context', 'correlationId', 'mode', 'callerSha256'}
            or intent['mode'] != 'start'):
        raise ValueError('release_intent')
    spec = FreshWindowsVmSpec.parse(intent['spec'])
    context = intent['context']
    if spec.deployment_id != deployment_id or type(context) is not dict:
        raise ValueError('release_intent')
    boot = context.get('hostBootId')
    if type(boot) is not str or str(uuid.UUID(boot)) != boot:
        raise ValueError('release_intent')
    directory = root/'.runtime/windows-vm-credentials'/deployment_id
    _private_directory(root/'.runtime', 0o022)
    _private_directory(directory.parent)
    _private_directory(directory)
    prepared = _private_json(directory/'reservation.private.json')
    reservation = prepared.get('reservation') if type(prepared) is dict else None
    identity = reservation.get('identity') if type(reservation) is dict else None
    if (type(identity) is not dict or set(identity) != set(_IDENTITY) or any(type(identity[k]) is not str or not identity[k] for k in _IDENTITY)
            or identity['environment'] != 'windows-'+deployment_id or identity['operator'] != 'windows-vm-deploy'
            or identity['hostAlias'] != spec.host or prepared.get('hostBootId') != boot):
        raise ValueError('release_reservation_binding')
    return spec, identity, boot, directory


def _original_actor(spec, identity, deployment_id, directory):
    """The running binding of that same identity and the original start's actors."""
    bound = _private_json(directory/'running-reservation.private.json', 65536)
    started = _private_json(directory/'boot-result.private.json', 65536)
    if (type(bound) is not dict or bound.get('identity') != identity or type(bound.get('reservation')) is not dict
            or bound['reservation'].get('allocationState') != 'running'
            or bound['reservation'].get('memoryBytes') != spec.memory_mib*1024**2):
        raise ValueError('release_running_binding')
    if (type(started) is not dict or started.get('state') != 'booted-observed' or started.get('mode') != 'start'
            or started.get('deploymentId') != deployment_id):
        raise ValueError('release_original_actor')
    return {'qemu': _actor(started.get('qemu')), 'swtpm': _actor(started.get('swtpm'))}


def _inventory(root):
    with environments._LockedState(root) as locked:
        raw = environments._read_private(locked.path).encode() if locked.path.exists() else b''
        rows = json.loads(json.dumps(locked.state['reservations']))
    return rows, hashlib.sha256(raw).hexdigest()


def _own(rows, identity):
    return [row for row in rows if type(row) is dict and row.get('id') == identity['reservationId']]


def _terminal(releases, deployment_id, identity, boot, authorization, reconciled):
    value = {'schemaVersion': 1, 'deploymentId': deployment_id, 'mode': 'release', 'state': 'released', 'reason': None,
             'reservationId': identity['reservationId'], 'proof': authorization['proof']['kind'],
             'reservationHostBootId': boot, 'observedHostBootId': authorization['proof']['observedHostBootId'],
             'correlationId': authorization['correlationId'], 'reconciled': reconciled,
             'nativeActionAllowed': False, 'replayAllowed': False}
    deploy.stage._retain(releases, deployment_id+'.released.json', value)
    return {**value, 'idempotent': False}


def _reconciled(releases, deployment_id, identity, boot):
    """A lost reply after this action's own exact release: read, never release again."""
    records = []
    for name in sorted(os.listdir(releases)):
        if re.fullmatch(re.escape(deployment_id)+r'\.authorized\.[0-9a-f]{32}\.json', name) is None:
            continue
        value = _private_json(releases/name, 65536)
        if (type(value) is not dict or value.get('deploymentId') != deployment_id
                or value.get('reservationId') != identity['reservationId'] or type(value.get('proof')) is not dict
                or value['proof'].get('reservationHostBootId') != boot
                or name != deployment_id+'.authorized.'+str(value.get('correlationId'))+'.json'
                or type(value.get('authorizedAtUnixMs')) is not int):
            raise ValueError('release_authorization_changed')
        records.append(value)
    if not records:
        return None
    latest = max(records, key=lambda value: (value['authorizedAtUnixMs'], value['correlationId']))
    return _terminal(releases, deployment_id, identity, boot, latest, True)


def release(root, deployment_id, credential_file):
    """Release this deployment's own reservation only on fresh proof that its VM cannot run."""
    if not deploy.direct.coordinator_capable():
        raise ValueError('unsupported_deployment_coordinator')
    if type(deployment_id) is not str or str(uuid.UUID(deployment_id)) != deployment_id:
        raise ValueError('deployment_identity')
    import fcntl
    root = Path(root).resolve(strict=True)
    releases = root/'.rag_index'/GROUP
    releases.mkdir(mode=0o700, parents=True, exist_ok=True)
    _private_directory(releases)
    correlation = uuid.uuid4().hex
    journal = deploy._runtime_group(root, GROUP)/correlation
    journal.mkdir(mode=0o700)
    deploy.stage._retain(journal, 'request.json', {'schemaVersion': 1, 'deploymentId': deployment_id, 'mode': 'release',
                                                    'correlationId': correlation})
    descriptor = os.open(releases/(deployment_id+'.lock'), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
            raise ValueError('release_lock_owner')
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            result = _result(deployment_id, 'blocked', 'release_in_progress')
        else:
            result = _release_locked(root, deployment_id, credential_file, releases, journal, correlation)
    finally:
        os.close(descriptor)
    deploy.stage._retain(journal, 'result.json', result)
    return result


def _release_locked(root, deployment_id, credential_file, releases, journal, correlation):
    terminal = releases/(deployment_id+'.released.json')
    if os.path.lexists(terminal):
        value = _private_json(terminal, 65536)
        if type(value) is not dict or value.get('deploymentId') != deployment_id or value.get('state') != 'released':
            raise ValueError('release_terminal_changed')
        return {**value, 'idempotent': True}
    try:
        spec, identity, boot, directory = _identity(root, deployment_id)
    except (OSError, ValueError, KeyError, TypeError):
        return _result(deployment_id, 'blocked', 'release_original_unbound')
    known = lambda **extra: {'reservationId': identity['reservationId'], 'reservationHostBootId': boot, **extra}
    rows, digest = _inventory(root)
    own = _own(rows, identity)
    if not own:
        value = _reconciled(releases, deployment_id, identity, boot)
        return value if value is not None else _result(deployment_id, 'blocked', 'release_reservation_absent', **known())
    try:
        same = (len(own) == 1 and environments._identity(own[0]) == identity
                and own[0].get('requestedMemoryBytes') == spec.memory_mib*1024**2)
    except (KeyError, TypeError):
        same = False
    if not same:
        return _result(deployment_id, 'blocked', 'release_identity_mismatch', **known())
    if own[0].get('allocationState') == 'pending':
        return _result(deployment_id, 'blocked', 'release_reservation_pending', **known())
    if own[0].get('allocationState') != 'running':
        return _result(deployment_id, 'blocked', 'release_reservation_state_unknown', **known())
    try:
        actor = _original_actor(spec, identity, deployment_id, directory)
    except (OSError, ValueError, KeyError, TypeError):
        return _result(deployment_id, 'blocked', 'release_original_unbound', **known())
    # A fresh read-only census of the deployment's own host; no stop is ever submitted.
    try:
        observation = deploy.resources(root, spec.as_dict(), credential_file)
        if type(observation) is not dict or observation.get('state') != 'resources-observed':
            raise ValueError('release_observation_state')
        facts.measurement(observation)
    except Exception:
        return _result(deployment_id, 'blocked', 'release_observation_unknown', **known())
    deploy.stage._retain(journal, 'observation.json', {
        'hostBootId': observation['hostBootId'],
        'vms': [{key: row[key] for key in ('pid', 'startTicks', 'configuredMemoryBytes')} for row in observation['vms']]})
    current = observation['hostBootId']
    qemu = (actor['qemu']['pid'], actor['qemu']['startTicks'])
    present = any((row['pid'], row['startTicks']) == qemu for row in observation['vms'])
    if current != boot:
        if present:
            return _result(deployment_id, 'blocked', 'release_original_actor_present', **known(observedHostBootId=current))
        proof = {'kind': 'ended-host-epoch', 'reservationHostBootId': boot, 'observedHostBootId': current}
    else:
        if present:
            return _result(deployment_id, 'blocked', 'release_instance_running', **known(observedHostBootId=current))
        # The same read status uses: it refuses any other boot with instance_host_epoch.
        try:
            value = deploy.status(root, deployment_id, credential_file)
        except Exception:
            return _result(deployment_id, 'blocked', 'release_status_unknown', **known(observedHostBootId=current))
        deploy.stage._retain(journal, 'status.json', {key: value.get(key) for key in ('state', 'reason', 'positiveAbsence', 'qemu', 'swtpm')}
                             if type(value) is dict else None)
        state = value.get('state') if type(value) is dict else None
        if state == 'booted-observed':
            return _result(deployment_id, 'blocked', 'release_instance_running', **known(observedHostBootId=current))
        if state != 'stopped-observed' or value.get('positiveAbsence') is not True:
            return _result(deployment_id, 'blocked', 'release_status_unknown', **known(observedHostBootId=current))
        if value.get('qemu') != actor['qemu'] or value.get('swtpm') != actor['swtpm']:
            return _result(deployment_id, 'blocked', 'release_original_actor_mismatch', **known(observedHostBootId=current))
        proof = {'kind': 'clean-absence-same-boot', 'reservationHostBootId': boot, 'observedHostBootId': current}
    authorization = {'schemaVersion': 1, 'deploymentId': deployment_id, 'reservationId': identity['reservationId'],
                     'correlationId': correlation, 'proof': proof, 'inventorySha256': digest,
                     'authorizedAtUnixMs': time.time_ns()//1_000_000}
    with environments._LockedState(root) as locked:
        raw = environments._read_private(locked.path).encode() if locked.path.exists() else b''
        rows = _own(locked.state['reservations'], identity)
        changed = hashlib.sha256(raw).hexdigest() != digest or len(rows) != 1 or environments._identity(rows[0]) != identity
        if not changed:
            # Authorize before the only inventory effect, then close the job with a
            # correlated terminal receipt under the lock, as release_stopped does.
            deploy.stage._retain(releases, deployment_id+'.authorized.'+correlation+'.json', authorization)
            rows[0]['activeJob'] = 'absent'
            rows[0]['activeJobEvidence'] = {'kind': 'active-job', 'source': 'windows-vm-deploy',
                                            'observedAtUnixMs': time.time_ns()//1_000_000, 'outcome': 'complete',
                                            'reservationId': identity['reservationId'], 'reservationToken': identity['token']}
            rows[0]['observationMaximumAgeMs'] = 60_000
            locked.save()
    if changed:
        return _result(deployment_id, 'blocked', 'release_inventory_changed', **known(observedHostBootId=current))
    try:
        released = environments.release_environment(root, identity)
        if type(released) is not dict or released.get('state') != 'released':
            raise ValueError('release_environment_state')
        reconciled = False
    except (ValueError, OSError):
        if _own(_inventory(root)[0], identity):
            return _result(deployment_id, 'blocked', 'release_incomplete', **known(observedHostBootId=current))
        reconciled = True
    return _terminal(releases, deployment_id, identity, boot, authorization, reconciled)
