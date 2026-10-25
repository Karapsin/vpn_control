"""Capacity admission for owned existing Linux/KVM fixtures.

This internal facade observes hosts and records reservations. It never starts,
reboots, stops, or replaces a VM. Lifecycle adapters supply their source-bound
original actor and clean shutdown evidence; UNKNOWN claims retain capacity.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field, replace
import hashlib
import json
import os
from pathlib import Path
import re
import time
import subprocess
from uuid import UUID, uuid5

from . import native_environment as environments
from . import readiness
from . import vm_workflow
from . import windows_vm_deploy as deploy
from . import windows_vm_resources as facts
from . import windows_vm_deploy_remote as producer
from . import ssh_transport as transport
from .private_credential_file import SecretFile


def _uuid(value):
    if type(value) is not str or str(UUID(value)) != value:
        raise ValueError('resource_identity')
    return value


@dataclass(frozen=True)
class ResourceTarget:
    deployment_id: str
    host: str
    root: str

    def __post_init__(self):
        _uuid(self.deployment_id)
        if type(self.host) is not str or re.fullmatch('[A-Za-z0-9][A-Za-z0-9._-]{0,127}', self.host) is None:
            raise ValueError('resource_host')
        if (type(self.root) is not str or not self.root.startswith('/') or
                any(c in self.root for c in ('\0', '\r', '\n')) or
                str(Path(self.root)) != self.root or '..' in Path(self.root).parts):
            raise ValueError('resource_root')

    def as_dict(self):
        return {'deploymentId': self.deployment_id, 'host': self.host, 'root': self.root}


def _remote_observation(root, target, mode, credential_file=None, *, deadline=None):
    """Render after readiness and dispatch through the framed central carrier.

    Only the fixed resource/peer producers are supported. Private input is
    never retained, hashed, or included in an exception. A malformed reply is
    discarded before any caller can save it as evidence.
    """
    if mode not in ('host-resources', 'peer') or (mode == 'host-resources') != (credential_file is not None):
        raise ValueError('resource_observation_mode')
    operation = target.deployment_id
    def remaining():
        value = 60.0 if deadline is None else min(60.0, deadline-time.monotonic())
        if value <= 0:
            raise TimeoutError('resource_deadline')
        return value
    with transport.admitted_transport(root, target.host, operation, deadline=deadline) as admitted:
        with deploy.direct.Guard(root, host=target.host) as authority:
            source = producer.program(target, mode).decode('utf-8')
            command = ('python3', '-I', '-B', '-c', 'exec('+repr(source)+')')
            if credential_file is not None:
                command = ('sudo', '-S', '-p', '', '--', *command)
            argv = transport.build_ssh_argv(authority.config, target.host, 60, command=command)
            private_input = None
            try:
                if credential_file is None:
                    admitted.revalidate(); authority.guard()
                    result = transport.run_ssh(argv, input=b'', stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                               timeout=remaining(), cwd=root)
                    streams = (result.stdout, result.stderr)
                else:
                    with SecretFile(str(credential_file)) as credential:
                        credential.guard(); admitted.revalidate(); authority.guard()
                        private_input = credential.text.encode('utf-8')+b'\n'
                        result = transport.run_ssh(argv, input=private_input, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                                   timeout=remaining(), cwd=root)
                        credential.guard()
                        streams = (result.stdout, result.stderr)
                        # Even an unexpected infrastructure echo cannot escape
                        # as a JSON error, saved evidence, or exception payload.
                        if any(credential.text.encode('utf-8') in stream for stream in streams):
                            raise ValueError('resource_private_input_echo')
                if result.returncode != 0 or any(type(stream) is not bytes or len(stream) > 262144 for stream in streams) or streams[1]:
                    raise ValueError('resource_observation_unknown')
                value = json.loads(streams[0], object_pairs_hook=transport._reject_duplicate_keys)
                value = producer.validate_result(target, mode, value)
                admitted.revalidate(); authority.guard()
                return value
            except Exception:
                raise ValueError('resource_observation_unknown') from None
            finally:
                private_input = None


def observe(root, target, credential_file, *, deadline=None):
    """Read the complete fixed Linux census without granting lifecycle access."""
    value = _remote_observation(root, target, 'host-resources', credential_file, deadline=deadline)
    facts.measurement(value)
    if value['deploymentId'] != target.deployment_id or value['mode'] != 'host-resources' or value['state'] != 'resources-observed':
        raise ValueError('resource_observation_identity')
    return value


def _inventory(root):
    with environments._LockedState(root) as locked:
        rows = json.loads(json.dumps(locked.state['reservations']))
        raw = environments._read_private(locked.path).encode() if locked.path.exists() else b''
    return rows, hashlib.sha256(raw).hexdigest()


def _sample(root, target, credential_file, deadline):
    if time.monotonic() >= deadline:
        raise TimeoutError('resource_deadline')
    rows, inventory_sha = _inventory(root)
    aliases = sorted({target.host} | {alias for row in rows for alias in row.get('resourceAliases', [row['hostAlias']])})
    if len(aliases) > 64:
        raise ValueError('resource_alias_capacity')
    with deploy.direct.Guard(root, host=target.host) as authority:
        observation = observe(root, target, credential_file, deadline=deadline)
        selected = [target.host]
        for alias in aliases:
            if alias == target.host:
                continue
            if time.monotonic() >= deadline:
                raise TimeoutError('resource_deadline')
            if alias not in authority.config.hosts:
                raise ValueError('resource_claimed_alias_unconfigured')
            peer = _remote_observation(root, replace(target, host=alias), 'peer', deadline=deadline)
            if peer['state'] != 'peer-observed':
                raise ValueError('resource_peer_unknown')
            if peer['platform'] == 'linux' and peer['hostBootId'] == observation['hostBootId']:
                selected.append(alias)
        if len(aliases) > 1:
            closing = observe(root, target, credential_file, deadline=deadline)
            if closing['hostBootId'] != observation['hostBootId']:
                raise ValueError('resource_host_epoch_changed')
            observation = closing
        authority.guard()
    selected = sorted(selected)
    same = environments._host_records(rows, selected)
    # Count every claim in addition to the live census. This intentionally
    # double-counts known running reservations: an UNKNOWN running claim cannot
    # disappear merely because some unrelated QEMU happens to fit its memory.
    reservations = []
    for row in same:
        if row.get('allocationState') not in ('pending', 'running'):
            raise ValueError('resource_claim_state_unknown')
        reservations.append({'id': row['id'], 'memoryBytes': row['requestedMemoryBytes']})
    measurement = facts.measurement(observation)
    deploy._wait_for_resource_clock(measurement, deadline)
    if time.monotonic() >= deadline:
        raise TimeoutError('resource_deadline')
    return observation, measurement, selected, same, reservations, inventory_sha


def _actor(value):
    if type(value) is not dict or set(value) != {'pid', 'startTicks'} or any(type(v) is not int or v <= 0 for v in value.values()):
        raise ValueError('resource_actor_identity')
    return dict(value)


def _receipt(identity, outcome):
    return {'kind': 'active-job', 'source': 'readiness-resources',
            'observedAtUnixMs': time.time_ns() // 1_000_000, 'outcome': outcome,
            'reservationId': identity['reservationId'], 'reservationToken': identity['token']}


@dataclass(frozen=True)
class ResourceAdmission:
    root: Path
    target: ResourceTarget
    machine_uuid: str
    operation_id: str
    directory: Path
    credential_file: str = field(repr=False, compare=False)
    deadline: float = field(repr=False, compare=False)

    def _journal(self):
        return readiness.RecoveryJournal(self.directory)

    def _prepared(self, journal):
        value = journal.lookup('prepared')
        if value is None or value.get('machineUuid') != self.machine_uuid or value.get('operationId') != self.operation_id or value.get('target') != self.target.as_dict():
            raise ValueError('resource_admission_binding')
        identity = value['reservation']['identity']
        if (identity.get('hostAlias') != self.target.host or identity.get('environment') != 'recovery-'+self.operation_id or
                identity.get('operator') != 'readiness-resources'):
            raise ValueError('resource_admission_binding')
        return value

    @property
    def host_boot_id(self):
        with self._journal().locked(deadline=self.deadline) as journal:
            return self._prepared(journal)['hostBootId']

    @property
    def reservation_identity(self):
        with self._journal().locked(deadline=self.deadline) as journal:
            return dict(self._prepared(journal)['reservation']['identity'])

    def _fresh(self, prepared, *, running_actor=None):
        sample = _sample(self.root, self.target, self.credential_file, self.deadline)
        observation, measurement, aliases, same, reservations, digest = sample
        if observation['hostBootId'] != prepared['hostBootId']:
            raise ValueError('resource_host_epoch_changed')
        own = [r for r in same if r['id'] == prepared['reservation']['identity']['reservationId']]
        if len(own) != 1 or environments._identity(own[0]) != prepared['reservation']['identity']:
            raise ValueError('resource_original_reservation_absent')
        others = [row for row in reservations if row['id'] != own[0]['id']]
        admission_measurement = measurement
        if running_actor is not None:
            # Only post-dispatch bookkeeping can project its positively matched
            # original actor out of the live total before adding this request.
            # Preserve the complete census for exact runningAllocationMapping.
            actor = _actor(running_actor)
            matches = [row for row in observation['vms']
                       if (row['pid'], row['startTicks']) == (actor['pid'], actor['startTicks'])]
            requested = prepared['requestedMemoryBytes']
            running = measurement['runningConfiguredMemoryBytes']
            if (len(matches) != 1 or matches[0]['configuredMemoryBytes'] != requested
                    or type(running) is not int or running < requested):
                raise ValueError('resource_original_actor_unobserved')
            admission_measurement = {**measurement, 'runningConfiguredMemoryBytes': running-requested}
        vm_workflow.admit_plan(admission_measurement, requested_memory_bytes=prepared['requestedMemoryBytes'],
                              headroom_bytes=prepared['headroomBytes'], reservations=others)
        return observation, measurement, aliases, same, others, digest

    def _submission_key(self, attempt):
        if type(attempt) is not int or not 1 <= attempt <= readiness.MAX_DISPATCH_ATTEMPTS:
            raise ValueError('resource_dispatch_attempt')
        return 'submitting' if attempt == 1 else 'submitting:'+str(attempt)

    def _retry_ready(self, journal, attempt):
        self._submission_key(attempt)
        for prior in range(1, attempt):
            consumed = journal.lookup(self._submission_key(prior))
            proof = journal.lookup('unsubmitted:'+str(prior))
            if proof is None or proof.get('resourceDispatchConsumed') is not (consumed is not None):
                raise ValueError('resource_previous_dispatch_unknown')

    def reconcile_unsubmitted(self, proof, *, core_journal_directory, proof_file):
        """Authorize the next attempt from both original durable proof owners.

        Read the core's append-only records without taking its lock: the core
        already holds that lock while invoking adapters. All reads pin private
        file identities and the actual retained no-launch evidence bytes.
        """
        if type(proof) is not readiness.RecoveryUnsubmitted:
            raise ValueError('resource_unsubmitted_proof_required')
        if str(uuid5(UUID(self.machine_uuid), proof.recovery_id)) != self.operation_id:
            raise ValueError('resource_unsubmitted_operation')
        expected_file = self.root/'.runtime/readiness-qemu/unsubmitted'/proof.recovery_id/(str(proof.attempt)+'.json')
        if Path(proof_file).absolute() != expected_file:
            raise ValueError('resource_unsubmitted_evidence_path')
        core_path = Path(core_journal_directory).absolute()
        if core_path.parent != self.root/'.rag_index/readiness-targets' or re.fullmatch('[0-9a-f]{64}', core_path.name) is None:
            raise ValueError('resource_unsubmitted_core_path')
        with readiness.private.Directory(expected_file.parent) as directory:
            with readiness.private.Snapshot(directory, expected_file.name) as snapshot:
                raw = snapshot.body
                native = json.loads(raw, object_pairs_hook=transport._reject_duplicate_keys)
                if hashlib.sha256(raw).hexdigest() != proof.proof_sha256:
                    raise ValueError('resource_unsubmitted_evidence_changed')
        fields = {'schemaVersion', 'recoveryId', 'attempt', 'dispatchDigest', 'packetSha256',
                  'mutationExecutableStarted', 'popenCalled', 'evidence'}
        remote = type(native) is dict and type(native.get('schemaVersion')) is int and native['schemaVersion'] == 2
        if remote:
            fields = fields | {'remoteAttestationSha256'}
        digest = lambda value: type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None
        if (type(native) is not dict or set(native) != fields or type(native['schemaVersion']) is not int or native['schemaVersion'] not in {1, 2} or
                native['recoveryId'] != proof.recovery_id or type(native['attempt']) is not int or native['attempt'] != proof.attempt or
                native['dispatchDigest'] != proof.dispatch_digest or native['mutationExecutableStarted'] is not False or
                native['packetSha256'] is not None and not digest(native['packetSha256'])):
            raise ValueError('resource_unsubmitted_evidence')
        if (remote and (native['popenCalled'] is not True or native['evidence'] != 'remote_complete_power_refusal'
                        or not digest(native['packetSha256']) or not digest(native['remoteAttestationSha256'])) or
                not remote and (native['popenCalled'] is not False or
                                native['evidence'] not in {'prelaunch_e2big', 'admission_before_mutation_dispatch'})):
            raise ValueError('resource_unsubmitted_evidence')
        with readiness.private.Directory(core_path) as directory:
            core = readiness.RecoveryJournal(core_path); core.directory = directory
            dispatch = core._read_named('dispatch-'+proof.recovery_id+'-'+str(proof.attempt)+'.json')
            retained = core._read_named('unsubmitted-'+proof.recovery_id+'-'+str(proof.attempt)+'.json')
            expected = {'version': 2, 'recoveryId': proof.recovery_id, 'attempt': proof.attempt,
                        'dispatchDigest': proof.dispatch_digest, 'proofSha256': proof.proof_sha256}
            if dispatch is None or retained != expected or not proof.matches(dispatch) or dispatch.get('machine') != self.machine_uuid or dispatch.get('action') != 'start':
                raise ValueError('resource_unsubmitted_core_proof')
            body = {key: value for key, value in dispatch.items() if key != 'dispatchDigest'}
            if hashlib.sha256(json.dumps(body, sort_keys=True, separators=(',', ':')).encode()).hexdigest() != proof.dispatch_digest:
                raise ValueError('resource_unsubmitted_dispatch_changed')
        with self._journal().locked(deadline=self.deadline) as journal:
            prepared = self._prepared(journal)
            consumed = journal.lookup(self._submission_key(proof.attempt))
            if (consumed is not None and (consumed.get('recoveryId') != proof.recovery_id or consumed.get('attempt') != proof.attempt or
                    consumed.get('dispatchDigest') != proof.dispatch_digest) or journal.lookup('running') is not None or journal.lookup('released') is not None):
                raise ValueError('resource_unsubmitted_consumed_binding')
            if remote:
                if (consumed is None or not {'census', 'pending', 'resourceAliases'} <= set(consumed) or
                        consumed.get('operationId') != self.operation_id or consumed.get('hostBootId') != prepared['hostBootId']):
                    raise ValueError('resource_unsubmitted_remote_snapshot')
                snapshot = {'hostBootId': consumed['hostBootId'], 'census': consumed['census'],
                            'inventorySha256': consumed['inventorySha256'], 'resourceAliases': consumed['resourceAliases'],
                            'pending': consumed['pending'], 'requestedMemoryBytes': prepared['requestedMemoryBytes'],
                            'headroomBytes': prepared['headroomBytes']}
                from . import readiness_qemu_refusal
                attestation = self.root/'.runtime/readiness-qemu/unsubmitted-remote'/proof.recovery_id/(str(proof.attempt)+'.json')
                with readiness_qemu_refusal.validated_remote_refusal(self.root, attestation_path=attestation,
                        attestation_sha256=native['remoteAttestationSha256'], machine_uuid=self.machine_uuid,
                        operation_id=self.operation_id, recovery_id=proof.recovery_id, attempt=proof.attempt,
                        dispatch_digest=proof.dispatch_digest, packet_sha256=native['packetSha256'],
                        resource_snapshot=snapshot, fixture_host=self.target.host, fixture_root=self.target.root) as verified:
                    verified.guard()
                    journal.record('unsubmitted:'+str(proof.attempt), {**expected, 'resourceDispatchConsumed': True})
                    verified.guard()
            else:
                journal.record('unsubmitted:'+str(proof.attempt), {**expected, 'resourceDispatchConsumed': consumed is not None})
        return True

    def validate_before_dispatch(self, *, attempt=1):
        """Read-only fresh admission. A consumed dispatch is never rearmed."""
        with self._journal().locked(deadline=self.deadline) as journal:
            prepared = self._prepared(journal)
            self._retry_ready(journal, attempt)
            if journal.lookup('released') is not None or journal.lookup(self._submission_key(attempt)) is not None:
                raise ValueError('resource_original_dispatch_consumed')
            observation, measurement, aliases, same, reservations, digest = self._fresh(prepared)
            return {'hostBootId': observation['hostBootId'], 'census': observation,
                    'inventorySha256': digest, 'resourceAliases': aliases,
                    'pending': reservations, 'requestedMemoryBytes': prepared['requestedMemoryBytes'],
                    'headroomBytes': prepared['headroomBytes']}

    def mark_submitting(self, *, attempt=1, recovery_id=None, dispatch_digest=None):
        """Consume once before power dispatch; lost acknowledgement means UNKNOWN."""
        with self._journal().locked(deadline=self.deadline) as journal:
            prepared = self._prepared(journal)
            if journal.lookup('released') is not None:
                raise ValueError('resource_original_released')
            self._retry_ready(journal, attempt)
            if journal.lookup(self._submission_key(attempt)) is not None:
                return False
            if (recovery_id is None) != (dispatch_digest is None) or (recovery_id is not None and any(type(value) is not str or re.fullmatch('[0-9a-f]{64}', value) is None for value in (recovery_id, dispatch_digest))):
                raise ValueError('resource_dispatch_binding')
            if (attempt > 1 and recovery_id is None) or (recovery_id is not None and str(uuid5(UUID(self.machine_uuid), recovery_id)) != self.operation_id):
                raise ValueError('resource_dispatch_binding')
            observation, measurement, aliases, same, reservations, digest = self._fresh(prepared)
            journal.record(self._submission_key(attempt), {'operationId': self.operation_id, 'hostBootId': observation['hostBootId'],
                                         'inventorySha256': digest, 'state': 'UNKNOWN', 'attempt': attempt,
                                         'recoveryId': recovery_id, 'dispatchDigest': dispatch_digest,
                                         'census': observation, 'pending': reservations, 'resourceAliases': aliases})
            request = dict(prepared['request'])
            request.update(measurement=measurement, resourceAliases=aliases, expectedInventorySha256=digest,
                           observations=[_receipt(prepared['reservation']['identity'], 'unknown')])
            environments.reserve_environment(self.root, request)
            return True

    def submission_snapshot(self, *, attempt=1):
        """Return only the exact full facts retained at the consumed fence.

        This is local metadata. It makes no new freshness claim: the fixed
        remote lifecycle producer must still enforce its sample age bounds.
        """
        with self._existing_journal() as journal:
            prepared = self._prepared(journal)
            consumed = journal.lookup(self._submission_key(attempt))
            if consumed is None or journal.lookup('unsubmitted:'+str(attempt)) is not None or journal.lookup('released') is not None:
                raise ValueError('resource_original_dispatch_unavailable')
            if 'census' not in consumed:
                raise ValueError('resource_original_snapshot_unavailable')
            return {'hostBootId': consumed['hostBootId'], 'census': consumed['census'],
                    'inventorySha256': consumed['inventorySha256'], 'resourceAliases': consumed['resourceAliases'],
                    'pending': consumed['pending'], 'requestedMemoryBytes': prepared['requestedMemoryBytes'],
                    'headroomBytes': prepared['headroomBytes']}

    @contextmanager
    def _existing_journal(self):
        """Take only an already-published cooperative lock; never initialize."""
        presented = readiness.private.PresentedPath(self.directory)
        with readiness.private.Directory(presented.canonical) as directory:
            with readiness.private.Snapshot(directory, readiness.RecoveryJournal.Lock.name) as lock:
                if lock.body != readiness.RecoveryJournal.Lock.body or readiness.private.fcntl is None:
                    raise ValueError('resource_journal_lock_integrity')
                while True:
                    if time.monotonic() >= self.deadline:
                        raise TimeoutError('resource_deadline')
                    try:
                        readiness.private.fcntl.flock(lock.fd, readiness.private.fcntl.LOCK_EX | readiness.private.fcntl.LOCK_NB)
                        break
                    except BlockingIOError:
                        presented.guard(); lock.guard()
                        time.sleep(min(.1, max(0., self.deadline-time.monotonic())))
                journal = self._journal(); journal.directory = directory
                try:
                    presented.guard(); lock.guard()
                    yield journal
                    presented.guard(); lock.guard()
                finally:
                    del journal.directory

    def _observed_inventory(self):
        directory, path = environments._root_paths(self.root)
        presented = readiness.private.PresentedPath(directory)
        with readiness.private.Directory(presented.canonical) as held:
            with readiness.private.Snapshot(held, path.name) as snapshot:
                value = json.loads(snapshot.body, object_pairs_hook=transport._reject_duplicate_keys)
                if (type(value) is not dict or set(value) != {'version', 'reservations'}
                        or type(value['version']) is not int or value['version'] != 1
                        or type(value['reservations']) is not list
                        or any(type(row) is not dict or type(row.get('id')) is not str for row in value['reservations'])):
                    raise ValueError('resource_inventory_integrity')
                presented.guard(); snapshot.guard()
                return value['reservations']

    def running_binding(self, original_actor_receipt, host_boot_id):
        """Inspect committed original bookkeeping; never probe or mutate."""
        actor = _actor(original_actor_receipt)
        _uuid(host_boot_id)
        try:
            with self._existing_journal() as journal:
                prepared = self._prepared(journal)
                running = journal.lookup('running')
                active = [attempt for attempt in range(1, readiness.MAX_DISPATCH_ATTEMPTS+1)
                          if journal.lookup(self._submission_key(attempt)) is not None and journal.lookup('unsubmitted:'+str(attempt)) is None]
                if (len(active) != 1 or journal.lookup('released') is not None or running is None
                        or running != {'operationId': self.operation_id, 'actor': actor, 'hostBootId': host_boot_id}
                        or prepared['hostBootId'] != host_boot_id):
                    return False
                identity = prepared['reservation']['identity']
                rows = self._observed_inventory()
                own = [row for row in rows if row['id'] == identity['reservationId']]
                if (len(own) != 1 or environments._identity(own[0]) != identity
                        or own[0]['requestedMemoryBytes'] != prepared['requestedMemoryBytes']
                        or own[0]['allocationState'] != 'running' or own[0].get('activeJob') != 'active'):
                    return False
                evidence = own[0].get('activeJobEvidence')
                return (type(evidence) is dict and evidence.get('kind') == 'active-job'
                        and evidence.get('source') == 'readiness-resources' and evidence.get('outcome') == 'active'
                        and evidence.get('reservationId') == identity['reservationId']
                        and evidence.get('reservationToken') == identity['token'])
        except FileNotFoundError:
            return False

    def mark_running(self, original_actor_receipt):
        actor = _actor(original_actor_receipt)
        with self._journal().locked(deadline=self.deadline) as journal:
            prepared = self._prepared(journal)
            active = [attempt for attempt in range(1, readiness.MAX_DISPATCH_ATTEMPTS+1)
                      if journal.lookup(self._submission_key(attempt)) is not None and journal.lookup('unsubmitted:'+str(attempt)) is None]
            if len(active) != 1 or journal.lookup('released') is not None:
                raise ValueError('resource_original_not_submitted')
            existing = journal.lookup('running')
            if existing is not None and existing['actor'] != actor:
                raise ValueError('resource_original_actor_changed')
            observation, measurement, aliases, same, reservations, digest = self._fresh(prepared, running_actor=actor)
            journal.record('running', {'operationId': self.operation_id, 'actor': actor, 'hostBootId': observation['hostBootId']})
            identity = prepared['reservation']['identity']
            mapping = [{'reservationId': row['id'], 'memoryBytes': row['requestedMemoryBytes']} for row in same if row['allocationState'] == 'running']
            if not any(row['reservationId'] == identity['reservationId'] for row in mapping):
                mapping.append({'reservationId': identity['reservationId'], 'memoryBytes': prepared['requestedMemoryBytes']})
            request = dict(prepared['request'])
            request.update(allocationState='running', measurement=measurement, resourceAliases=aliases,
                           expectedInventorySha256=digest, runningAllocationMapping=mapping,
                           reservationIdentity=identity, observations=[_receipt(identity, 'active')])
            return environments.reserve_environment(self.root, request)

    def release_stopped(self, proof):
        """Reconcile clean shutdown only; absence alone never closes guest jobs."""
        with self._journal().locked(deadline=self.deadline) as journal:
            prepared = self._prepared(journal)
            released = journal.lookup('released')
            if released is not None:
                return released
            running = journal.lookup('running')
            expected = {'machineUuid', 'hostBootId', 'actor', 'cleanPoweroffOperationId', 'cleanPoweroff', 'guestJobsAbsent'}
            if (running is None or type(proof) is not dict or set(proof) != expected or
                    proof['machineUuid'] != self.machine_uuid or proof['hostBootId'] != prepared['hostBootId'] or
                    proof['actor'] != running['actor'] or proof['cleanPoweroff'] is not True or proof['guestJobsAbsent'] is not True):
                raise ValueError('resource_clean_stopped_proof_required')
            _uuid(proof['cleanPoweroffOperationId'])
            observation, measurement, aliases, same, reservations, digest = _sample(self.root, self.target, self.credential_file, self.deadline)
            if observation['hostBootId'] != prepared['hostBootId']:
                raise ValueError('resource_host_epoch_changed')
            if any((row['pid'], row['startTicks']) == (running['actor']['pid'], running['actor']['startTicks']) for row in observation['vms']):
                raise ValueError('resource_original_actor_still_present')
            identity = prepared['reservation']['identity']
            # A lost terminal acknowledgement can close only after the
            # original clean shutdown proof was durably authorized. A missing
            # row without that proof remains UNKNOWN.
            authorized = journal.lookup('release-authorized')
            own = [row for row in same if row['id'] == identity['reservationId']]
            if authorized is not None and authorized != proof:
                raise ValueError('resource_clean_stopped_proof_changed')
            if not own:
                if authorized is None:
                    raise ValueError('resource_original_reservation_absent')
                result = {'ok': True, 'state': 'released', 'identity': identity, 'nativeActionAllowed': False,
                          'operationId': self.operation_id, 'cleanPoweroffOperationId': authorized['cleanPoweroffOperationId']}
                journal.record('released', result)
                return result
            if len(own) != 1 or environments._identity(own[0]) != identity:
                raise ValueError('resource_original_reservation_absent')
            journal.record('release-authorized', proof)
            # Reconciliation does not admit a new VM. Preserve old running
            # mapping using an explicit zero-effect terminal update under lock.
            with environments._LockedState(self.root) as locked:
                raw = environments._read_private(locked.path).encode()
                if hashlib.sha256(raw).hexdigest() != digest:
                    raise ValueError('resource_inventory_changed')
                rows = locked.state['reservations']
                row = next((row for row in rows if environments._identity(row) == identity), None)
                if row is None:
                    raise ValueError('resource_original_reservation_absent')
                row['activeJob'] = 'absent'
                row['activeJobEvidence'] = _receipt(identity, 'complete')
                row['observationMaximumAgeMs'] = 60_000
                locked.save()
            result = environments.release_environment(self.root, identity)
            result = {**result, 'operationId': self.operation_id, 'cleanPoweroffOperationId': proof['cleanPoweroffOperationId']}
            journal.record('released', result)
            return result


def prepare_start(root, *, host, machine_uuid, fixture_root, credential_file,
                  requested_memory_bytes=2*1024**3, headroom_bytes=16*1024**3,
                  deadline=None, operation_id=None):
    """Retain one bounded admission; repeated operation IDs preserve its claim."""
    root = Path(root).resolve(strict=True)
    machine_uuid = _uuid(machine_uuid)
    operation_id = _uuid(operation_id or machine_uuid)
    deadline = min(deadline if deadline is not None else float('inf'), time.monotonic()+180)
    for amount in (requested_memory_bytes, headroom_bytes):
        if type(amount) is not int or amount <= 0:
            raise ValueError('resource_memory')
    target = ResourceTarget(operation_id, host, fixture_root)
    parent = root/'.rag_index'/'readiness-resources'
    environments._secure_directory(parent)
    directory = parent/operation_id
    environments._secure_directory(directory)
    admitted = ResourceAdmission(root, target, machine_uuid, operation_id, directory, str(credential_file), deadline)
    with admitted._journal().locked(deadline=deadline) as journal:
        existing = journal.lookup('prepared')
        if existing is not None:
            admitted._prepared(journal)
            if existing['requestedMemoryBytes'] != requested_memory_bytes or existing['headroomBytes'] != headroom_bytes:
                raise ValueError('resource_admission_changed')
            return admitted
        observation, measurement, aliases, same, reservations, digest = _sample(root, target, credential_file, deadline)
        plan = vm_workflow.admit_plan(measurement, requested_memory_bytes=requested_memory_bytes,
                                     headroom_bytes=headroom_bytes, reservations=reservations)
        mapping = [{'reservationId': row['id'], 'memoryBytes': row['requestedMemoryBytes']} for row in same if row['allocationState'] == 'running']
        request = {'hostAlias': host, 'resourceAliases': aliases, 'environment': 'recovery-'+operation_id,
                   'operator': 'readiness-resources', 'requestedMemoryBytes': requested_memory_bytes,
                   'headroomBytes': headroom_bytes, 'allocationState': 'pending', 'measurement': measurement,
                   'runningAllocationMapping': mapping, 'expectedInventorySha256': digest}
        reservation = environments.reserve_environment(root, request)
        journal.record('prepared', {'version': 1, 'operationId': operation_id, 'machineUuid': machine_uuid,
                                   'target': target.as_dict(), 'hostBootId': observation['hostBootId'],
                                   'requestedMemoryBytes': requested_memory_bytes, 'headroomBytes': headroom_bytes,
                                   'reservation': reservation, 'request': request, 'plan': plan, 'census': observation})
    return admitted
