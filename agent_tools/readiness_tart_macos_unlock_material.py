"""Internal unlock material and append-only original resolution.

No public tool or registry imports this module yet. A historical component
result cannot mint material: the opaque qualification loader also requires the
new complete native once case and closed legacy GUI inventory.
"""
from __future__ import annotations

from contextlib import contextmanager, ExitStack
from copy import deepcopy
import hashlib
import os
from pathlib import Path
import re
import sys
import time
from uuid import UUID, uuid5

from . import private_inventory_lock as private
from . import readiness_tart_macos as backend_module
from . import readiness_tart_macos_registry as registry
from . import readiness_tart_macos_unlock as unlock
from . import readiness_tart_macos_unlock_qualification as qualification
from . import readiness_tart_macos_unlock_observer as observer

_EXECUTING_CODE = sys._getframe().f_code
_ORIGINAL_PRODUCERS = frozenset({'ba316162d6191922253ba7d3a03a3bea1599a1612cffe2e0049fcdea4706f135'})
_ORIGINAL = re.compile(r'macos-unlock-([0-9a-f-]{36})\.json')
_CURRENT_TOKEN = object()


def _need(value, reason):
    if not value:
        raise qualification.QualificationBlocked(reason)


def _backend(backend):
    _need(type(backend) is backend_module.MacTartBackend and type(backend.custody) is registry.MacCustody
          and backend.custody.binding is backend.binding, 'macos_unlock_material_unqualified')
    backend.custody._operator.guard()
    return backend.custody


@contextmanager
def _source():
    path = Path(__file__)
    raw = path.read_bytes()
    _need(_EXECUTING_CODE == compile(raw, __file__, 'exec', dont_inherit=True,
          optimize=sys.flags.optimize), 'macos_unlock_material_source_changed')
    pin = {'generation': list(private._generation(path.lstat())), 'sha256': hashlib.sha256(raw).hexdigest()}
    with registry.PublicProof(path, pin, private_file=False) as held:
        _need(held.body == raw, 'macos_unlock_material_source_changed')
        yield held


def _read(directory, name):
    try:
        with private.Snapshot(directory, name) as held:
            return qualification._json(held.body), held.pin()
    except (FileNotFoundError, OSError, ValueError):
        raise qualification.QualificationBlocked('macos_unlock_incident_unresolved') from None


def _original_records(directory, operation):
    """Read only finite source-owned metadata, never an image or credential."""
    operation = unlock._uuid(operation)
    original, pin = _read(directory, 'macos-unlock-' + operation + '.json')
    _need(set(original) == {'schemaVersion', 'operationId', 'recipient', 'state', 'sourceSha256'}
          and type(original['schemaVersion']) is int and original['schemaVersion'] == 1
          and original['operationId'] == operation and original['state'] == 'unknown_no_replay'
          and type(original['sourceSha256']) is str and original['sourceSha256'] in _ORIGINAL_PRODUCERS,
          'macos_unlock_original_source_unqualified')
    secret, submit = (str(uuid5(UUID(operation), phase)) for phase in ('secret', 'return'))
    secret_record, secret_pin = _read(directory, secret + '.json')
    password, password_pin = _read(directory, 'macos-unlock-password-' + secret + '.json')
    returned, return_pin = _read(directory, 'macos-unlock-return-' + submit + '.json')
    _need(secret_record == {'schemaVersion': 1, 'operationId': secret, 'bindingId': operation,
                            'action': 'secret_input', 'state': 'unknown'}
          and password == {'operationId': secret, 'state': 'transport_complete_not_unlock_receipt'}
          and returned == {'operationId': submit, 'state': 'unknown_no_replay'},
          'macos_unlock_original_phase_unresolved')
    return original, {'original': pin, 'secret': secret_pin, 'password': password_pin, 'return': return_pin}, secret, submit


def _resolution(records, operation, proof, binding, source_sha):
    """Only a live recollection of the actual original guest owner closes it."""
    _need(type(proof) is observer.NativeObservation and proof.operation == operation,
          'macos_unlock_original_observer_required')
    proof.guard(); actual = proof.observation
    original, pins, secret, submit = records
    expected = unlock._identity(original['recipient'], binding)
    unlock._identity(actual, binding, expected, allow_sleeping=True)
    _need(expected['console']['locked'] is True and actual['console']['locked'] is False,
          'macos_unlock_original_not_observed_unlocked')
    return {'schemaVersion': 1, 'operationId': operation, 'secretOperationId': secret, 'returnOperationId': submit,
            'state': 'observed_unlocked', 'replacementForbidden': True, 'originalPins': pins,
            'recipient': deepcopy(expected), 'observation': deepcopy(actual), 'observerSourceSha256': source_sha,
            'observerOperationId': proof.observer, 'observerTerminalSha256': hashlib.sha256(
                __import__('json').dumps(proof.terminal, sort_keys=True, separators=(',', ':')).encode()).hexdigest()}


def resolve_original(backend, operation_id, *, deadline):
    """Append once after independent actual same-original unlocked observation.

    No caller-provided observation, credential reader, GUI material, input,
    recovery, replacement job or generic success flag is accepted.
    """
    operation = unlock._uuid(operation_id); unlock._deadline(deadline)
    custody = _backend(backend)
    with _source() as source, private.Directory(custody.lifecycle_root) as directory:
        custody.guard(deadline=deadline); source.guard(); directory.guard()
        records = _original_records(directory, operation)
        name = 'macos-unlock-resolution-' + operation + '.json'
        source_sha = hashlib.sha256(source.body).hexdigest()
        # Existing JSON is never a proof. Every fresh agent recollects the SAME
        # admitted deterministic guest owner; no new input or observer replay.
        proof = observer.reconcile(backend, operation, records, deadline=deadline)
        try:
            custody.guard(deadline=deadline); source.guard(); directory.guard()
            _need(_original_records(directory, operation) == records, 'macos_unlock_original_changed')
            value = _resolution(records, operation, proof, backend.binding, source_sha)
            try:
                unlock._record(directory, name, value)
            except FileExistsError:
                previous, _ = _read(directory, name)
                _need(previous == value, 'macos_unlock_original_resolution_conflict')
        finally:
            proof.close()
        source.guard(); directory.guard()
        return {'operationId': operation, 'state': 'observed_unlocked', 'replacementForbidden': True}


class _CurrentIncident:
    """Only one live material scope may continue its own partial submission."""
    def __init__(self, token, directory, operation, recipient):
        _need(token is _CURRENT_TOKEN, 'macos_unlock_material_unqualified')
        self.directory, self.operation, self.recipient = directory, operation, deepcopy(recipient)
        self.live = True
        secret, submit = (str(uuid5(UUID(operation), phase)) for phase in ('secret', 'return'))
        self.records = {
            'macos-unlock-' + operation + '.json': None,
            secret + '.json': {'schemaVersion': 1, 'operationId': secret, 'bindingId': operation,
                              'action': 'secret_input', 'state': 'unknown'},
            'macos-unlock-password-' + secret + '.json': {'operationId': secret, 'state': 'transport_complete_not_unlock_receipt'},
            'macos-unlock-return-' + submit + '.json': {'operationId': submit, 'state': 'unknown_no_replay'}}
        names = set(os.listdir(directory.fd))
        _need(not names.intersection(self.records), 'macos_unlock_original_pending')
        self.seen = {}

    def guard(self):
        _need(self.live, 'macos_unlock_material_closed')
        self.directory.guard()
        names = set(os.listdir(self.directory.fd))
        present = names.intersection(self.records)
        original_name = 'macos-unlock-' + self.operation + '.json'
        _need(not present or original_name in present, 'macos_unlock_orphan_incident_unresolved')
        _need(present == set(list(self.records)[:len(present)]), 'macos_unlock_original_phase_unresolved')
        for name in present:
            value, pin = _read(self.directory, name)
            if self.records[name] is None:
                _need(set(value) == {'schemaVersion', 'operationId', 'recipient', 'state', 'sourceSha256'}
                      and type(value['schemaVersion']) is int and value['schemaVersion'] == 1
                      and value['operationId'] == self.operation and value['recipient'] == self.recipient
                      and value['state'] == 'unknown_no_replay' and type(value['sourceSha256']) is str
                      and value['sourceSha256'] in _ORIGINAL_PRODUCERS,
                      'macos_unlock_original_changed')
            else:
                _need(value == self.records[name], 'macos_unlock_original_phase_unresolved')
            _need(name not in self.seen or self.seen[name] == pin, 'macos_unlock_original_changed')
            self.seen[name] = pin
        _need(set(self.seen) <= present, 'macos_unlock_original_changed')


def _new_incidents(directory, current_operation, binding, observations, current=None):
    """Every new production incident, including another UUID, is accounted for."""
    directory.guard(); names = set(os.listdir(directory.fd))
    _need(len(names) <= 10000, 'macos_unlock_incident_inventory_overflow')
    original_ids, related = set(), set()
    for name in names:
        match = _ORIGINAL.fullmatch(name)
        if match:
            original_ids.add(unlock._uuid(match[1]))
    for operation in original_ids:
        if (type(current) is _CurrentIncident and current.directory is directory
                and current.operation == operation == current_operation):
            current.guard(); related.update(current.records)
            continue
        original, pins, secret, submit = _original_records(directory, operation)
        related.update({'macos-unlock-' + operation + '.json', secret + '.json',
                        'macos-unlock-password-' + secret + '.json', 'macos-unlock-return-' + submit + '.json',
                        'macos-unlock-resolution-' + operation + '.json'})
        _need(operation != current_operation, 'macos_unlock_original_pending')
        resolution, _ = _read(directory, 'macos-unlock-resolution-' + operation + '.json')
        proof = observations.get(operation) if type(observations) is dict else None
        _need(type(proof) is observer.NativeObservation, 'macos_unlock_original_observer_required')
        _need(type(resolution.get('observerSourceSha256')) is str,
              'macos_unlock_resolution_source_unqualified')
        expected = _resolution((original, pins, secret, submit), operation, proof, binding,
                               resolution['observerSourceSha256'])
        _need(resolution == expected, 'macos_unlock_incident_unresolved')
    # Orphan phase/modifier/unknown records must not disappear from the fence.
    _need(not {name for name in names if name.startswith('macos-unlock-')
               or re.fullmatch(r'[0-9a-f-]{36}\.json', name)} - related,
          'macos_unlock_orphan_incident_unresolved')
    _need(set(os.listdir(directory.fd)) == names, 'macos_unlock_incident_inventory_changed')
    directory.guard()


def _fast_guard(custody, admitted, source, *, deadline):
    """Pure per-event physical/source/metadata guard; no full guest census."""
    _need(time.monotonic() < deadline, 'macos_unlock_material_deadline')
    custody._operator.guard(); admitted.guard(); source.guard()
    custody._check_source_custody(custody.descriptor)
    for held in (*custody._records, *custody._artifact_holders, *custody._credentials.values()):
        held.guard()
    custody._public_share.guard(); custody._public_actor.guard(deadline=deadline)
    _need(registry.jobs._birth(custody.wrapper_actor['pid']) == custody.wrapper_actor['birth']
          and registry._parent(custody.actor['pid'], deadline) == custody.wrapper_actor['pid'],
          'macos_unlock_original_actor_changed')
    _need(registry._listener(custody.actor['pid'], custody.actor['birth'], custody.endpoint['port'], deadline)
          == custody.descriptor['listener'], 'macos_unlock_original_endpoint_changed')
    admitted.guard(); source.guard(); custody._operator.guard()
    _need(time.monotonic() < deadline, 'macos_unlock_material_deadline')


@contextmanager
def material(backend, operation_id, *, deadline):
    """Future custody delegation. Currently no native case can admit it."""
    operation = unlock._uuid(operation_id); unlock._deadline(deadline)
    custody = _backend(backend)
    with _source() as source:
        admitted = qualification.load(custody)
        label_epoch = None
        try:
            label_epoch = qualification.load_label_epoch(custody)
            _need(type(admitted) is qualification.QualifiedUnlock, 'macos_unlock_material_unqualified')
            custody.guard(deadline=deadline)
            with private.Directory(custody.lifecycle_root) as directory, ExitStack() as proof_stack:
                # Live proofs are collected once before the logical group and
                # held through each event; cached local JSON never supplies one.
                proofs = {}
                for name in os.listdir(directory.fd):
                    match = _ORIGINAL.fullmatch(name)
                    if match and match[1] != operation:
                        previous = unlock._uuid(match[1]); records = _original_records(directory, previous)
                        proof = observer.reconcile(backend, previous, records, deadline=deadline)
                        proofs[previous] = proof; proof_stack.callback(proof.close)
                _new_incidents(directory, operation, backend.binding, proofs)
                expected = unlock._snapshot(backend, deadline)
                _need(expected['console']['locked'] is True, 'macos_unlock_session_not_locked')
                _need((expected['boot'], expected['console']['session']) == admitted._binding,
                      'macos_unlock_native_profile_session_changed')
                current = _CurrentIncident(_CURRENT_TOKEN, directory, operation, expected)
                with private.Directory(admitted._baseline.path.parent) as parent:
                    with private.Snapshot(parent, admitted._baseline.path.name) as baseline:
                        _need(baseline.body == admitted._baseline.body, 'macos_unlock_baseline_changed')
                        if label_epoch is not None:
                            qualification._label_epoch_guard(label_epoch, custody, admitted._profile)
                            qualification._label_epoch_mask(label_epoch, unlock._white_label_mask(unlock._image(baseline.body, admitted._profile['dimensions']), admitted._profile))
                            _need((expected['boot'], expected['console']['session']) == label_epoch._binding, 'macos_unlock_native_profile_session_changed')
                        def guard():
                            _fast_guard(custody, admitted, source, deadline=deadline)
                            _new_incidents(directory, operation, backend.binding, proofs, current)
                        try:
                            with unlock._held_material(backend, operation, baseline_snapshot=baseline,
                                    profile=admitted._profile, expected=expected, guard=guard, label_epoch=label_epoch) as value:
                                yield value
                        finally:
                            current.live = False
        finally:
            if label_epoch is not None: label_epoch.close()
            admitted.close()
