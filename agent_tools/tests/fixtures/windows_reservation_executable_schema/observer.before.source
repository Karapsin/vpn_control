"""Pure, retained reservation proof for one original Windows fixture.

The caller supplies its source-bound full host census and instance observation.
This module opens only finite local metadata. It never connects, recovers,
reserves, releases, starts, stops or reboots anything. Missing visibility blocks.
"""
from contextlib import ExitStack
import ast
import hashlib
import json
from pathlib import Path
import re
import sys
import time
from uuid import UUID

from . import native_environment as allocations
from . import private_inventory_lock as private
from . import windows_vm_resources as resources
from .native_review_source_closure import _Held
from .native_vm_spec import FreshWindowsVmSpec

_EXECUTING_CODE = sys._getframe().f_code
_MAX_AGE_MS = 60_000


def _need(value):
    if not value:
        raise ValueError('reservation_visibility_unavailable')


def _pairs(rows):
    result = {}
    for key, value in rows:
        _need(key not in result)
        result[key] = value
    return result


class ReservationProof:
    """Keep original private file generations held through the power fence."""
    def __init__(self, machine, boot, actor, *, clock):
        self.machine, self.boot, self.actor = machine, boot, actor
        self.clock = clock
        self.visibility_complete = False
        self.blockers = frozenset({'reservations'})
        self._stack = ExitStack()
        self._guards = []
        self._timestamps = ()
        self._closed = False

    def _read(self, path, *, json_value=True):
        presented = private.PresentedPath(path.parent)
        directory = self._stack.enter_context(private.Directory(presented.canonical))
        snapshot = self._stack.enter_context(private.Snapshot(directory, path.name))
        self._guards.extend((presented.guard, snapshot.guard))
        return json.loads(snapshot.body, object_pairs_hook=_pairs) if json_value else snapshot.body

    def _fresh(self):
        now = self.clock()
        _need(type(now) is int and now > 0 and len(self._timestamps) == 2)
        _need(all(type(value) is int and 0 < value <= now and now-value <= _MAX_AGE_MS for value in self._timestamps))

    def guard(self):
        """Recheck exact local generations and unchanged sample age; no probe."""
        _need(not self._closed and self.visibility_complete and not self.blockers)
        self._fresh()
        for guard in self._guards:
            guard()

    def as_dict(self):
        return {'machine': self.machine, 'hostBoot': self.boot, 'actor': dict(self.actor),
                'visibilityComplete': self.visibility_complete, 'blockers': sorted(self.blockers)}

    def close(self):
        self._stack.close()
        self._closed = True

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def observe(root, binding, facts, *, census=None, clock=lambda: time.time_ns()//1_000_000):
    """Authenticate one original reservation without publishing its token.

    ``facts`` and ``census`` are internal results of fixed source-bound callers,
    never public ownership booleans. A blocked proof may be inspected and closed;
    it cannot pass guard() or authorize a power dispatch.
    """
    machine = binding.get('spec', {}).get('deploymentId') if type(binding) is dict else None
    boot = binding.get('context', {}).get('hostBootId') if type(binding) is dict else None
    row = facts.get('actor') if type(facts) is dict else None
    actor = {key: row.get(key) for key in ('pid', 'startTicks')} if type(row) is dict else {}
    proof = ReservationProof(machine, boot, actor, clock=clock)
    try:
        root = Path(root).resolve(strict=True)
        _need(type(machine) is str and str(UUID(machine)) == machine)
        _need(type(boot) is str and str(UUID(boot)) == boot)
        _need(set(actor) == {'pid', 'startTicks'} and all(type(v) is int and v > 0 for v in actor.values()))
        _need(type(binding) is dict and set(binding) == {'provider', 'spec', 'setup', 'context', 'uri', 'domain', 'xmlSha256'})
        _need(binding['provider'] in {'raw-qemu-windows', 'libvirt-windows'})
        spec = FreshWindowsVmSpec.parse(binding['spec'])
        _need(spec.deployment_id == machine)
        _need(facts.get('provider') == binding['provider'] and facts.get('machine') == machine and facts.get('hostBoot') == boot)
        _need(facts.get('guest') == 'running' and type(facts.get('controlConnection')) is str and bool(facts['controlConnection']))
        source_path = Path(__file__).absolute()
        raw = source_path.read_bytes()
        _need(_EXECUTING_CODE == compile(raw, str(source_path), 'exec', dont_inherit=True))
        held = _Held(); proof._stack.callback(held.close)
        held.read(str(source_path), hashlib.sha256(raw).hexdigest(), max_bytes=131072)
        proof._guards.extend((held.finish, held.final_identity_pass))
        intent = proof._read(root/'.rag_index/windows-vm-deploy-intents'/(machine+'.intent.json'))
        _need(type(intent) is dict and set(intent) == {'spec', 'setup', 'context', 'correlationId', 'mode', 'callerSha256'})
        _need(intent['mode'] == 'start' and intent['spec'] == binding['spec'] and intent['setup'] == binding['setup'] and intent['context'] == binding['context'])
        _need(type(intent['correlationId']) is str and re.fullmatch('[0-9a-f]{32}', intent['correlationId']) is not None)
        _need(type(intent['callerSha256']) is str and re.fullmatch('[0-9a-f]{64}', intent['callerSha256']) is not None)
        directory = root/'.runtime/windows-vm-deploy'/intent['correlationId']
        source = proof._read(directory/'caller.py', json_value=False)
        _need(hashlib.sha256(source).hexdigest() == intent['callerSha256'])
        wanted = {'SPEC': intent['spec'], 'SETUP': intent['setup'], 'CONTEXT': intent['context'], 'MODE': 'start'}
        bindings = {}
        for node in ast.parse(source).body:
            if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) and node.targets[0].id in wanted:
                name = node.targets[0].id
                _need(name not in bindings); bindings[name] = ast.literal_eval(node.value)
        _need(bindings == wanted)
        request = proof._read(directory/'request.json')
        _need(type(request) is dict and request.get('spec') == binding['spec'] and request.get('mode') == 'start'
              and request.get('correlationId') == intent['correlationId'] and request.get('callerSha256') == intent['callerSha256'])
        closing = proof._read(directory/'closing.json')
        _need(closing == {'sourceClosing': True, 'correlationId': intent['correlationId']})
        credentials = root/'.runtime/windows-vm-credentials'/machine
        prepared = proof._read(credentials/'reservation.private.json')
        running = proof._read(credentials/'running-reservation.private.json')
        original = proof._read(credentials/'boot-result.private.json')
        _need(type(prepared) is dict and prepared.get('hostBootId') == boot)
        identity = prepared['reservation']['identity']
        _need(set(identity) == {'reservationId', 'token', 'hostAlias', 'environment', 'operator'})
        _need(identity['hostAlias'] == spec.host and identity['environment'] == 'windows-'+machine and identity['operator'] == 'windows-vm-deploy')
        _need(running.get('identity') == identity and running.get('state') == 'reserved'
              and running.get('reservation') == {'memoryBytes': spec.memory_mib*1024**2, 'allocationState': 'running'})
        _need(original.get('deploymentId') == machine and original.get('state') == 'booted-observed'
              and original.get('mode') == 'start' and type(original.get('qemu')) is dict)
        # A migrated libvirt actor is admitted by the caller's exact original
        # domain UUID/XML/disk proof. Never force adoption of its old raw PID.
        if binding['provider'] == 'raw-qemu-windows':
            _need(original['qemu'] == actor)
        inventory = proof._read(root/'.rag_index/native-environments/reservations.json')
        _need(type(inventory) is dict and set(inventory) == {'version', 'reservations'} and inventory['version'] == 1
              and type(inventory['reservations']) is list and len(inventory['reservations']) <= 1024)
        records = inventory['reservations']
        ids = set()
        for claim in records:
            _need(type(claim) is dict and type(claim.get('id')) is str and claim['id'] not in ids)
            ids.add(claim['id'])
        same = allocations._host_records(records, [spec.host])
        # An unassociated claimed alias cannot silently be declared another
        # physical host. The caller must provide a qualified alias route first.
        _need(len(same) == len(records))
        own = [claim for claim in same if claim['environment'] == identity['environment']]
        _need(len(own) == 1 and allocations._identity(own[0]) == identity)
        _need(own[0]['allocationState'] == 'running' and own[0]['requestedMemoryBytes'] == spec.memory_mib*1024**2)
        own_evidence = own[0].get('activeJobEvidence')
        _need(own[0].get('activeJob') == 'active' and type(own_evidence) is dict
              and own_evidence.get('kind') == 'active-job' and own_evidence.get('source') == 'windows-vm-deploy'
              and own_evidence.get('outcome') == 'active' and own_evidence.get('reservationId') == identity['reservationId']
              and own_evidence.get('reservationToken') == identity['token'])
        _need(type(census) is dict and census.get('deploymentId') == machine and census.get('mode') == 'host-resources'
              and census.get('state') == 'resources-observed' and census.get('hostBootId') == boot)
        resources.measurement(census)
        proof._timestamps = tuple(sample['observedAtUnixMs'] for sample in census['samples'])
        proof._fresh()
        matches = [item for item in census['vms'] if (item['pid'], item['startTicks']) == (actor['pid'], actor['startTicks'])]
        _need(len(matches) == 1 and matches[0]['configuredMemoryBytes'] == spec.memory_mib*1024**2)
        _need(matches[0]['commandSha256'] == row.get('commandSha256') and matches[0]['executableGeneration'] == row.get('executableGeneration'))
        blockers = set()
        # A stable running allocation occupies capacity. Guest work is proved
        # separately by the Windows idle observer; pending/UNKNOWN allocations
        # are competing lifecycle phases and cannot authorize this reboot.
        for claim in same:
            _need(claim.get('allocationState') in {'pending', 'running'} and claim.get('activeJob') in {'absent', 'active', 'unknown'})
            _need(type(claim.get('requestedMemoryBytes')) is int and claim['requestedMemoryBytes'] > 0)
            if claim['allocationState'] == 'pending' or claim['activeJob'] == 'unknown':
                blockers.add('reservations')
        _need(sum(claim['requestedMemoryBytes'] for claim in same if claim['allocationState'] == 'running') <= sum(item['configuredMemoryBytes'] for item in census['vms']))
        proof.visibility_complete = True
        proof.blockers = frozenset(blockers)
        for guard in proof._guards:
            guard()
        return proof
    except (OSError, ValueError, KeyError, TypeError, OverflowError, SyntaxError):
        proof.visibility_complete = False
        proof.blockers = frozenset({'reservations'})
        proof.close()
        return proof
