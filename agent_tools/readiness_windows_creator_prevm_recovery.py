"""Source-owned closure of creator pre-VM refusal 7e8b2dcd, then one linked attempt.

Original 7e8b2dcd consumed its readiness-resources claim (prepared + submitting
attempt 1, UNKNOWN), then its creator bound credentials.sock through a 141-byte
canonical path beyond the Linux AF_UNIX limit and printed a typed BLOCKED result
in phase credential-listener. Phase alone is never proof: a fixed read-only
observer re-authenticates the complete original job, the absence of every
acceptance/handoff/create marker, the VM root, storage plan and both libvirt
lookups on the same host epoch. Only then the exact EXISTING pending row is
re-booked with a complete receipt and released once. Create-only journal
records retain authorization, result and the derived next-attempt link. Nothing
is replayed, no secret is opened, the old job and records are never changed,
and nothing is claimed as a clean shutdown or as unsubmitted proof.

Outcomes: a refusal before any effect of a run is positive. Once a run released
the claim or recorded its released result, every later failure is UNKNOWN. A
claim this source did not produce (absent without authorization, unexplained
receipt, foreign or re-minted row, a row that is no longer exactly the one the
authorization bound, or an absent row without this source's own durable
release-attempt record) stays UNKNOWN and stops for root review. Every
re-entry over an existing authorization needs its exact digest, supplied by
root after a fresh read-only proof (root ruling R1). Each root-approved resume
over this source's own complete bookkeeping receipt re-books that exact row
once more (check-and-set on the whole inventory, never a mint) so that the
guard before the release always has the full receipt window.

Source epoch: until the link, every re-entry needs the whole epoch A bound
(this module, the reader and the 16 pinned sources). After the durable link
only the custody publication remains; it is bound to the sources it uses.

Holder census (root ruling R5): the ordinary observer scans every same-account
process (cmdline, descriptors, cwd, root, exe, maps, bound AF_UNIX sockets)
except its own transport chain. Only an actual /proc permission denial admits
one fixed, bounded root census through the reviewed sudo password carrier with
the protected credential; it excludes only itself. A zombie is a non-holder
bound into the proof. Refusals retain one bounded diagnostic in the receipt,
and every step records its monotonic start and end. History drops the scan.
"""
import ast
import base64
import copy
from dataclasses import dataclass
import hashlib
import inspect
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import time
import uuid
from uuid import UUID
import weakref
import zlib

from . import durable_remote_job as jobs
from . import native_environment as environments
from . import private_inventory_lock as private
from . import readiness_resources as resources
from . import readiness_windows_creator_attempts as attempts
from . import readiness_windows_creator_registry as registry
from . import readiness_windows_lifecycle as lifecycle
from . import readiness_windows_managed_create as creator
from . import ssh_transport as transport
from . import windows_vm_deploy as deploy
from . import windows_vm_instance as instance
from . import windows_vm_media as media
from . import windows_vm_resources as resource_facts
from . import windows_vm_unattend as unattended
from . import windows_vm_virt_firmware_install as sudo_credential
from .private_credential_file import SecretFile

_EXECUTING_CODE = inspect.currentframe().f_code
HOST = 'archlinux'
REPO = Path(__file__).resolve().parents[1]
AUTHORIZATION, RELEASED, LINK, CAUSE = attempts.AUTHORIZATION, attempts.RELEASED, attempts.LINK, attempts.CAUSE
# Written create-only immediately before the one release (safety review F1).
RELEASING = attempts.RELEASE_SUBMITTING
canonical, sha = attempts.canonical, attempts.sha
REASONS = frozenset({
 'inputs_invalid', 'source_epoch_changed', 'local_evidence_changed', 'local_handoff_present', 'program_derivation_mismatch',
 'phase_region_mismatch', 'registry_unresolved', 'resource_records_changed', 'resource_later_attempt_present',
 'resource_unsubmitted_present', 'record_integrity', 'reservation_absent_without_authorization', 'reservation_evidence_unexplained',
 'reservation_foreign', 'reservation_row_changed', 'reservation_absent_without_release', 'inventory_changed', 'environment_row_present', 'other_machine_journal_present',
 'readiness_target_dispatch_present', 'deploy_intent_present', 'observation_unknown', 'observation_invalid', 'host_epoch_changed',
 'namespace_changed', 'namespace_busy', 'other_attempt_present', 'admission_index_mismatch', 'job_entries_unexpected',
 'credentials_socket_present', 'creator_listener_present', 'credentials_accepted_present', 'credentials_handoff_present',
 'create_intent_present', 'program_source_mismatch', 'owner_source_mismatch', 'terminal_foreign', 'terminal_truncated',
 'terminal_not_blocked_credential_listener', 'owner_alive', 'actor_reference_present', 'actor_descriptor_limit',
 'actor_scan_incomplete', 'actors_changed', 'privileged_census_unavailable', 'privileged_census_unknown', 'vm_root_parent_unsafe',
 'vm_root_present', 'storage_unenrolled', 'storage_ledger_busy', 'storage_plan_present', 'storage_plan_under_root',
 'manager_unavailable', 'manager_changed', 'domain_read_only_unavailable', 'domain_visible', 'domain_unknown', 'proof_mismatch',
 'proof_expired', 'facts_changed', 'resume_required', 'resume_unexpected', 'authorization_mismatch', 'budget_insufficient',
 'reserve_result_unexpected', 'release_unknown', 'record_unknown', 'attempt_custody_unresolved', 'link_mismatch'})


class Refused(ValueError):
 """Positive finite refusal: this run changed no ledger row and wrote no released or link record.

 A close that knows an authorization record returns its digest and this resume action.
 """
 action = 'read-only proof, then one explicit close with resumeAuthorizationSha256'
 def __init__(self, reason, authorization=None):
  self.reason = reason if type(reason) is str and reason in REASONS else 'observation_invalid'
  self.authorization = authorization
  super().__init__(self.reason)


class _Unknown(Refused):
 """A durable effect may have happened in this run; its outcome stays UNKNOWN."""


class _Stop(_Unknown):
 """The original claim changed outside this source: UNKNOWN; no close may proceed (contract step 7)."""
 action = 'stop: the original reservation changed outside this source; root review before any further close'


def _need(value, reason):
 if not value:raise Refused(reason)


def _need_unknown(value, reason):
 if not value:raise _Unknown(reason)


def _need_stop(value, reason):
 if not value:raise _Stop(reason)


@dataclass(frozen=True)
class _Expected:
 op: str; machine: str; rid: str; vm_root: str; domain: str; uri: str; host_binding: dict; transport_machine: str
 program_sha: str; owner_sha: str; intent_generation: str; owner: dict; stdout: tuple; stderr: tuple; typed: dict
 prepared_sha: str; submitting_sha: str; reservation_id: str; memory: int; headroom: int
 registry: dict; evidence: dict; absent: tuple; sources: dict; manager_executable: str = '/usr/bin/virtqemud'


_OP = '7e8b2dcd-63c1-58fc-b382-f64695bacf11'
_DIRECT = '.runtime/tool-recovery-windows/direct/'
_SUCCESSOR = _DIRECT + 'new-libvirt-create-successor-' + _OP
_COLLECT = _SUCCESSOR + '/original-collect-7093f151-c85a-4dab-b8c8-a51cc1c43270/'
_BEFORE = _SUCCESSOR + '/native-record-unavailable-before/'
_PREPARE = _DIRECT + 'new-libvirt-source-prepare-' + _OP + '/'
_ONCE = _DIRECT + 'new-libvirt-create-once-' + _OP
_PRODUCTION = _Expected(
 op=_OP, machine='a3aec884-5e5c-47c6-b1c6-378d88045d72', rid='142e4db1bbd672d1be706c61f3269ce1770675c8398cc4f88ffb675831f94769',
 vm_root='/home/kardinal/vc-lw-a3aec884', domain='vc-recovery-libvirt-a3aec884',
 uri='qemu+unix:///session?socket=/home/kardinal/.cache/libvirt/virtqemud-sock',
 host_binding={'target': 'archlinux', 'machine': 'ffddef3b032d466c9b2d4087293fd282', 'boot': '25515f23-b966-4c3a-ae63-d38452375578', 'account': '1000'},
 transport_machine='19b91c80626b7e9a63556f88bce2f48707e87801411c21bee7e1cc6226d32bb6',
 program_sha='9d22ead3438381ae5413606e4aae118c3bdad98cb151760dad7976950d17f2e3',
 owner_sha='f3b4707528c16f176b80781dd86208c324c1e10d6eb2c14451dcf4be08d0e734',
 intent_generation='42399790-0238-43c1-a427-2c42687e4edb', owner={'pid': 1445334, 'birth': 'linux:156243015'},
 stdout=(185, '63b22dd1676e83ed84091bef84c02b9f9c0a96d838eb187bd7940f8dc6523f90'),
 stderr=(222, '05be7b88a77714dc3b8cc4baeb69ecd01cdb05eecf9379ec6c1d4e386d82ec4b'),
 typed={'state': 'blocked', 'operationId': _OP, 'reason': 'windows_managed_create_original_unknown', 'phase': 'credential-listener', 'replayAllowed': False},
 prepared_sha='c911475e1e4275ad267262692e756644b84163affcb00784bbd48a50db1b79fb',
 submitting_sha='4cc872e45146880f368604a62bd2386ef2e656e92b83a0b86b39e89e5d0bb0c0',
 reservation_id='env-07ae333a994a7c9465b53e6c3f67b664', memory=4294967296, headroom=8589934592,
 registry={'creator-original.json': '791d8ca141fe96e12cd24275999f059d36672bb4e2d248a1c5e96df63873799d',
 'creator-custody.json': '0c9744dcbd3ba61bd788044965dceb020c2fea6bce9c24e931dd7743f1fd3067',
 'creator-observer.source': 'f30b8bb3a38d4c13de6cdc82dc0fda255e495eb9e80ef6c884da8788c59a73a5',
 'creator-owner.source': 'f3b4707528c16f176b80781dd86208c324c1e10d6eb2c14451dcf4be08d0e734'},
 evidence={
 'program': (_SUCCESSOR + '/program.py', '9d22ead3438381ae5413606e4aae118c3bdad98cb151760dad7976950d17f2e3'),
 'once': (_SUCCESSOR + '/submission.once.json', 'dcbfc8621baff5a51facf3b7e11abc596d5e0f5b3cdee2a5f0af3b52e28d1684'),
 'caller': (_SUCCESSOR + '/caller.py', '9916233962f53ccbff427ae49fda05fbaedc63d45fcc58982b6220ee17b67b73'),
 'submissionResult': (_SUCCESSOR + '/submission.result.json', 'facf07ece2e643a63c00f1cc8599cc9e212e0c9e0a1a9aea88c1d9b83ecdf06b'),
 'submissionCallback': (_SUCCESSOR + '/submission.callback.json', 'f0c124f1bfe9b9698f149037b2a64e50e2e8ab1384b7aa8d9347bda238450752'),
 'onceUnknown': (_ONCE + '/unknown.json', '26b61d676d96f80d6e47b509e62bef7c8ecd1f8b8a11e657ddbba44c5bf78376'),
 'onceCaller': (_ONCE + '/caller.py', '085c009c595853d8428627b038e3afc348ac5fe8734c90b3184ab800747b9c17'),
 'stdout': (_COLLECT + 'owner.stdout.public', '63b22dd1676e83ed84091bef84c02b9f9c0a96d838eb187bd7940f8dc6523f90'),
 'stderr': (_COLLECT + 'owner.stderr.public', '05be7b88a77714dc3b8cc4baeb69ecd01cdb05eecf9379ec6c1d4e386d82ec4b'),
 'collect': (_COLLECT + 'result.json', '726ffdbd7dc63b664762f1351c37af28d0343234ce5eae2ab7e3d068c758020c'),
 'callback': (_COLLECT + 'collect.callback.json', '2a7f6922d37e3b0fcf7601a8598228b96291e0a9473cc8f3fc0a58b1f94e669e'),
 'closure': (_COLLECT + 'source-closure.after.json', '603cbce159bb16e208190317d5faac1f16572f9151ca8d695241fb30060d11b2'),
 'collectIntent': (_COLLECT + 'intent.json', 'b6cf0dca4142853a67f684a7407e3db476e80023a59bd02ede9fe63292bf9d54'),
 'status': (_SUCCESSOR + '/status-1/result.json', '9af66943fd952786975e8c7a1939da81844c5efd26a9ca05775f626ebe67e73b'),
 'unknown': (_SUCCESSOR + '/unknown.json', '71da92a4fb2d95055e4e50aaf2ba689964a6e1f0ed5cc86a4cdaa19e2c86da09'),
 'packet': (_SUCCESSOR + '/packet.json', '8dc05901ee17aa5390626584ef79050e6d2ffd6754220b105caebff5aaf9064c'),
 'unsubmitted': (_SUCCESSOR + '/original-unsubmitted.proof.json', 'b47cd36057960366b5814d1c84d8ebec62c8bfedae25b98d33f101eeda039491'),
 'socket': (_BEFORE + 'socket-path-causal.json', 'aa66555f6f6d3196587fce1fa9d42f093cbb972f1680ac07014b50da10ebda7d'),
 'retained': (_BEFORE + 'retained.json', 'da360f1b5d7bbeff662bd75279a3358252e5793a047a49d0a670a932cc09f8e6'),
 'oldCreator': (_BEFORE + 'sources/readiness_windows_managed_create.py.before.source', '8aeb4c0153ea840c595a5996295e62f6ef6b5504df2cb4845cbbab953955d218'),
 'namespace': (_DIRECT + 'new-libvirt-namespace-current-' + _OP + '/namespace.actual.json', 'f733881f025bcc001733ef6f9413542f9fc9e50943cbe593d0043958ec076581'),
 'plan': (_PREPARE + 'plan.json', '3a94c3f38dc68c45525f5a7eba2514d41d2472edd9e4277e9598a76b0e40bb18'),
 'hostBinding': (_PREPARE + 'host-binding.json', 'f3587d5530b0e40a878c5145513d3a83458ee27cd4ad0b9d1872a23637823c3d')},
 # Both drivers that could hand a private frame to this OP: successor and once.
 absent=tuple(driver + '/handoff.' + leaf for driver in (_SUCCESSOR, _ONCE) for leaf in ('once.json', 'public-ack.json', 'unknown.json')),
 sources={'scripts/native_fixture_storage.py': 'ea150bdc67fca6c862f361adf4959d05419ff18d31bd1066b6cdfef1f6bff1ca', **{'agent_tools/' + leaf: digest for leaf, digest in (
 ('readiness_resources.py', '45cc6144e9f330c288576214d9f92d96641ee615421ab3b0e43c620d420cc05a'),
 ('native_environment.py', 'e842650c8308d5b2cd8d9770afcd86d930556c0ae0836dea9b76d4cb864147cf'),
 ('readiness.py', 'eda12770d2141a1933159d0151eb8e512effb04663e6475a29dca90ea0a39a23'),
 ('readiness_windows_creator_registry.py', 'd1f06ac9df5f1ce232570b0fb077d7fbf857fdacf643ff93d23ed6e985f0ef7c'),
 ('readiness_windows_managed_create.py', 'e778dda736c7752038ec599df43e79593334202cc8683b8e992e7fdcf8f758cc'),
 ('durable_remote_job.py', 'f3b4707528c16f176b80781dd86208c324c1e10d6eb2c14451dcf4be08d0e734'),
 ('private_inventory_lock.py', '0ef6e2dda29a396a201368e1c3bce2ad52c441a3c9cc8647d8cadce198b73d42'),
 ('readiness_windows_host_jobs.py', 'b66e54ff485416422a4cfcf7fabe959fa0f8f2b117de0cbb614d6feeff56c0cb'),
 ('readiness_windows_remote.py', 'ad81b2ad7a94316c40380cf6da898c780ea0d073655ef9e1f3965f285195b684'),
 ('readiness_windows_lifecycle.py', '1bfcba28623cc710b12dc869f2b2fe364d608833b229c4dbda714ea801ceb694'),
 ('windows_vm_instance.py', '655ff7f04760dc44b0aebd23b5327a419cbc43a2ab0569417ef8b5ac4b86ed3a'),
 ('windows_vm_media.py', '1f3b2e1139a4caf0e2b1bcc6c90daa42af1a2c24032ed341dfa16b7e9503f20c'),
 ('windows_vm_resources.py', '2659a18cd8683c8d3b1b5ff749803c052fcf7e17dc1e669d2d57fb67c67396a0'),
 ('windows_vm_unattend.py', '1023536d57f860d40146710f09ad08fae19da1dc8adb7f3cb5d7911b74445d11'),
 ('native_vm_spec.py', '3430850bae6095d690eb5067ad70426b283ef9bafc8e36bf083a588edfd7bbe3'))}})
_PHASES = ('original-owner', 'public-assets', 'manager', 'credential-listener', 'capacity', 'blank-root', 'firmware', 'disk', 'private-seed', 'define', 'start')
_REGION = ("credentials=_receive_credentials(job,module,PLAN['operationId'])", "answer=private_answer(PLAN['binding']['setup'],credentials)",
 'credentials.clear()', 'credentials=None')
_PRECAPACITY_FORBIDDEN = frozenset({'save', 'mkdir', 'reserve', '_publish', '_create', 'run', 'Popen', 'defineXML', 'createWithFlags', 'unlink',
 'rename', 'replace', 'chmod', 'rmtree', 'submit', 'write'})
_JOB_ENTRIES = ['child-admission', 'intent.json', 'owner.json', 'owner.py', 'program.py', 'stderr.bin', 'stdout.bin', 'terminal.json']
_STORAGE = 'scripts/native_fixture_storage.py'
# One remote step: the admitted transport deadline (<= 30 s) also bounds the
# submission (readiness, any saved-program transfer and the run itself); the run
# alone is <= 25 s and 5 s cover the local retention around the step.
_ADMISSION_SECONDS, _RUN_SECONDS, _STEP_SECONDS = 30., 25., 35
# Worst case: the ordinary observer, then the root holder census its measured denial admits.
_OBSERVATION_SECONDS = 2 * _STEP_SECONDS
# Guard, bookkeeping, guard, release and the records must all fit before guard #1.
_RELEASE_SECONDS = 2 * _OBSERVATION_SECONDS + 10
# The create-only authorization and the locked inventory read come first.
_AUTHORIZE_SECONDS = _RELEASE_SECONDS + 10
# The smallest close leaves the local facts and the minting observation that budget.
_CLOSE_SECONDS = (_AUTHORIZE_SECONDS + _OBSERVATION_SECONDS + 15, 300)
_PROOF_SECONDS = (_OBSERVATION_SECONDS + 15, 300)
_HISTORY_SECONDS = (_STEP_SECONDS + 15, 300)
# native_environment releases only while the bookkeeping receipt is younger than
# its observationMaximumAgeMs (60 s): guard #2 must end within this window.
_RECEIPT_SECONDS = 50
# The fields one exact-row bookkeeping may rewrite; everything else stays bound.
_BOOKKEEPING_FIELDS = frozenset({'activeJob', 'activeJobEvidence', 'observationMaximumAgeMs', 'lastObservation', 'resourceAliases'})
_AUTHORIZATION_BOUND = frozenset({'proofSha256', 'factsSha256', 'sourceEpoch', 'observerSourceSha256', 'reservationRow'})
_ROOT_REASONS = frozenset({'actor_reference_present', 'actor_descriptor_limit', 'actor_scan_incomplete', 'host_epoch_changed',
 'privileged_census_unknown'})
# A census refusal may carry one bounded diagnostic; it is retained raw in the
# receipt only and never enters a result, N or P.
_DETAIL_REASONS = frozenset({'actor_reference_present', 'actor_descriptor_limit', 'actor_scan_incomplete', 'privileged_census_unknown'})
_DETAIL_STEPS = frozenset({'proc-list', 'proc-list-limit', 'file-oversize', 'stat-schema', 'zombie-threads', 'zombie-command',
 'zombie-resources', 'zombie-postcheck', 'kernel-command', 'identity-changed', 'privileged-denied', 'scan-deadline', 'proc-io',
 'descriptor-limit', 'reference-bound-socket', 'reference-cmdline', 'reference-descriptor', 'reference-socket', 'reference-cwd',
 'reference-root', 'reference-exe', 'reference-maps', 'root-identity', 'root-exception'})
_ERRNO_CLASSES = (None, 'EPERM', 'ENOENT', 'EIO', 'EACCES', 'OTHER')
# After the durable link only the attempt custody remains to (re)publish; these
# are the sources that publication and its validation run (safety review F4).
_CUSTODY_SOURCES = ('agent_tools/durable_remote_job.py', 'agent_tools/private_inventory_lock.py', 'agent_tools/readiness_windows_creator_attempts.py',
 'agent_tools/readiness_windows_creator_registry.py', 'agent_tools/readiness_windows_managed_create.py')


def _boot(expected):return str(UUID(expected.host_binding['boot']))


def _record(directory, key):
 try:value = attempts._read(directory, attempts.record_name(key))
 except attempts.AttemptUnresolved:raise Refused('record_integrity') from None
 return None if value is None else (value[0], sha(value[1]))


# ---------------------------------------------------------------- local facts

def _epoch(expected):
 _need(_EXECUTING_CODE == compile(Path(__file__).read_bytes(), __file__, 'exec', dont_inherit=True), 'source_epoch_changed')
 pins = {}
 for relpath, digest in sorted(expected.sources.items()):
  try:pins[relpath] = sha((REPO / relpath).read_bytes())
  except OSError:raise Refused('source_epoch_changed') from None
  _need(pins[relpath] == digest, 'source_epoch_changed')
 for module in (resources, environments, registry, creator, jobs, private, instance, media, unattended, lifecycle, resource_facts):
  _need(Path(module.__file__).resolve() == REPO / 'agent_tools' / Path(module.__file__).name, 'source_epoch_changed')
 for path in (Path(__file__).resolve(), Path(attempts.__file__).resolve()):pins[str(path.relative_to(REPO))] = sha(path.read_bytes())
 return pins


def _evidence(root, expected):
 held, pins = {}, {}
 for role, (relpath, digest) in sorted(expected.evidence.items()):
  path = root / relpath
  try:
   with private.Directory(path.parent) as directory, private.Snapshot(directory, path.name) as snapshot:held[role], pins[role] = snapshot.body, snapshot.digest
  except (OSError, ValueError):raise Refused('local_evidence_changed') from None
  _need(pins[role] == digest, 'local_evidence_changed')
 for relpath in expected.absent:_need(not os.path.lexists(root / relpath), 'local_handoff_present')
 return held, pins


def _segments(text):
 tree, lines = ast.parse(text), text.splitlines(keepends=True)
 return tree, {n.name: ''.join(lines[n.lineno - 1:n.end_lineno]) for n in tree.body if isinstance(n, ast.FunctionDef)}


def _phase_region(text):
 """Data-only: which durable effects the executing source could reach before 'capacity'."""
 phase = lambda n: isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name) and n.targets[0].id == 'phase' and isinstance(n.value, ast.Constant)
 try:
  main = next(n for n in _segments(text)[0].body if isinstance(n, ast.FunctionDef) and n.name == '_creator_main')
  marks = sorted((n.lineno, n.col_offset, n.value.value) for n in ast.walk(main) if phase(n))
  guarded = next(n for n in main.body if isinstance(n, ast.Try));body = guarded.body
  index = {s.value.value: i for i, s in enumerate(body) if phase(s)}
  region = tuple(ast.get_source_segment(text, s) for s in body[index['credential-listener'] + 1:index['capacity']])
  called = {c.func.attr if isinstance(c.func, ast.Attribute) else getattr(c.func, 'id', None)
   for s in [*main.body[:main.body.index(guarded)], *body[:index['capacity']]] for c in ast.walk(s) if isinstance(c, ast.Call)}
 except (StopIteration, KeyError, SyntaxError, ValueError):raise Refused('phase_region_mismatch') from None
 _need(tuple(m[2] for m in marks) == _PHASES and region == _REGION and not called & _PRECAPACITY_FORBIDDEN, 'phase_region_mismatch')


def _derive(held, snapshot, plan, namespace, host):
 """Regenerate the exact executing Program bytes from retained source; never exec it."""
 try:
  text, literal = held['program'].decode('utf-8'), {}
  for node in ast.parse(text).body:
   if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
    try:literal.setdefault(node.targets[0].id, []).append(ast.literal_eval(node.value))
    except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):pass
  spec, marker = plan['binding']['spec'], 'Stop-Transcript\n'
  _need(unattended.INITIALIZE.count(marker) == 1, 'program_derivation_mismatch')
  constants = {'SPEC': spec, 'SETUP': plan['binding']['setup'], 'CONTEXT': plan['binding']['context'], 'PLAN': plan, 'CREATOR_ADMISSION': snapshot,
   'CREATOR_JOB_ROOT': namespace['root'], 'CREATOR_ROOT_GENERATION': namespace['generation'], 'CREATOR_NAMESPACE': namespace,
   'CREATOR_HOST_BINDING': jobs.asdict(host), 'CREATOR_OWNER_SOURCE': jobs.owner_source(),
   'URI_SOCKET': str(PurePosixPath(spec['root']).parent / '.cache/libvirt/virtqemud-sock'),
   'CREATOR_INITIALIZE': unattended.INITIALIZE.replace(marker, "Start-ScheduledTask -TaskName 'VpnControlFixtureInitialize'\n" + marker),
   'CREATOR_INSTALL_AGENT': unattended.INSTALL_AGENT}
  _need(all(len(literal.get(n, ())) == 1 and literal[n][0] == v for n, v in constants.items()), 'program_derivation_mismatch')
  capsule = literal.get('MEDIA_READER', [None])[0]
  _need(type(capsule) is dict and set(capsule) == {'base64', 'sha256'} and sha(base64.b64decode(capsule['base64'], validate=True)) == capsule['sha256'],
   'program_derivation_mismatch')
  old, legacy = _segments(held['oldCreator'].decode('utf-8'))[1], inspect.getsource(instance._vm_main)
  names = {'require', 'generation', 'structure', 'chain', 'closing', 'pin', 'private', 'save', 'birth'}
  definitions = '\n'.join(ast.get_source_segment(legacy, row) for row in ast.parse(legacy).body[0].body
   if isinstance(row, (ast.Import, ast.ImportFrom, ast.Assign)) or isinstance(row, ast.FunctionDef) and row.name in names)
  main, hook = old['_creator_main'], '    _CANONICAL_CREATE_DEFINITIONS()\n'
  _need(main.count(hook) == 1, 'program_derivation_mismatch')
  main = main.replace(hook, ''.join('    ' + line + '\n' for line in definitions.splitlines()))
  source = lambda *functions: ''.join(inspect.getsource(f) + '\n' for f in functions)
  prefix = ("_CREATOR_EXECUTING_CODE=__import__('inspect').currentframe().f_code\nimport types,sys\n" + '\n'.join(n + '=' + repr(literal[n][0]) for n in constants)
   + "\nCREATOR_STORAGE=types.ModuleType('fixed_creator_storage');sys.modules[CREATOR_STORAGE.__name__]=CREATOR_STORAGE\nexec(compile("
   + repr((REPO / _STORAGE).read_bytes()) + ",'fixed-creator-storage','exec'),CREATOR_STORAGE.__dict__)\n"
   + 'MEDIA_READER=' + repr(capsule) + '\n' + source(media.read_wim_images, media.installer_images, media.select_image)
   + 'FIELDS=set(' + repr(sorted(unattended.FIELDS)) + ')\nimport re\nfrom xml.etree import ElementTree as ET\n' + source(unattended.parse_setup)
   + source(unattended.answer_file).replace('def answer_file(', 'def _legacy_answer(')
   + ''.join(old[n] + '\n' for n in ('host_machine', 'validate_canonical_xml', 'private_answer', 'credential_frame', '_creator_admission',
   '_channel_identity', '_receive_credentials'))
   + source(lifecycle._start_capacity, lifecycle._storage_vm_coverage)
   + source(resource_facts.measurement).replace('def measurement(', 'def _lifecycle_measurement('))
  derived = (prefix + main + '\n_creator_main()\n').encode()
 except Refused:raise
 except (KeyError, TypeError, ValueError, SyntaxError, UnicodeError, OSError):raise Refused('program_derivation_mismatch') from None
 _need(derived == held['program'], 'program_derivation_mismatch')


def _resources(expected, directory):
 extra = set(os.listdir(directory.fd)) - {'readiness.lock'} - {attempts.record_name(k) for k in ('prepared', 'submitting', AUTHORIZATION, RELEASING, RELEASED, LINK)}
 names = lambda *keys: {attempts.record_name(k) for k in keys}
 _need(not extra & names('submitting:2', 'submitting:3'), 'resource_later_attempt_present')
 _need(not extra & names('unsubmitted:1', 'unsubmitted:2', 'unsubmitted:3'), 'resource_unsubmitted_present')
 _need(not extra & names('running', 'release-authorized'), 'record_integrity');_need(not extra, 'resource_records_changed')
 prepared, submitting = _record(directory, 'prepared'), _record(directory, 'submitting')
 _need(prepared and submitting and prepared[1] == expected.prepared_sha and submitting[1] == expected.submitting_sha, 'resource_records_changed')
 prepared, submitting = prepared[0], submitting[0]
 try:
  identity = dict(prepared['reservation']['identity'])
  _need(prepared['machineUuid'] == expected.machine and prepared['operationId'] == expected.op and prepared['hostBootId'] == _boot(expected)
   and prepared['target'] == {'deploymentId': expected.op, 'host': HOST, 'root': expected.vm_root}
   and (prepared['requestedMemoryBytes'], prepared['headroomBytes']) == (expected.memory, expected.headroom)
   and identity == {**identity, 'reservationId': expected.reservation_id, 'hostAlias': HOST, 'environment': 'recovery-' + expected.op, 'operator': 'readiness-resources'}
   and set(identity) == {'reservationId', 'token', 'hostAlias', 'environment', 'operator'}
   and {k: submitting[k] for k in ('state', 'attempt', 'recoveryId', 'dispatchDigest', 'operationId', 'hostBootId')}
   == {'state': 'UNKNOWN', 'attempt': 1, 'recoveryId': None, 'dispatchDigest': None, 'operationId': expected.op, 'hostBootId': _boot(expected)},
   'resource_records_changed')
 except (KeyError, TypeError):raise Refused('resource_records_changed') from None
 return prepared, submitting, identity, {key: _record(directory, key) for key in (AUTHORIZATION, RELEASING, RELEASED, LINK)}


def _now_ms():return time.time_ns() // 1_000_000


def _own(rows, expected):
 own = [r for r in rows if type(r) is dict and r.get('id') == expected.reservation_id]
 return own[0] if len(own) == 1 else None


def _row_binding(row):
 """The exact row (U0 resume, ruling R1) and its bookkeeping-stable projection (own complete receipt)."""
 if row is None:return None
 stable = {key: value for key, value in row.items() if key not in _BOOKKEEPING_FIELDS}
 return {'sha256': sha(canonical(row).encode()), 'stableSha256': sha(canonical(stable).encode())}


def _bound_row(value):
 return type(value) is dict and set(value) == {'sha256', 'stableSha256'} and all(attempts._digest(value[key]) for key in value)


def _row_matches(row, binding, bound, releasing=False):
 """U0 must be exactly the bound snapshot and an own receipt its stable projection.

 A foreign row never matches. An absent row matches only after this source's
 own durable release-attempt record: a deletion it did not make is never its
 release (safety review F1).
 """
 if row == 'foreign':return False
 if row == 'absent':return releasing
 key = 'sha256' if row == 'unknown' else 'stableSha256'
 return _bound_row(bound) and binding is not None and binding[key] == bound[key]


def _classify(rows, expected, identity, now_ms):
 own = [r for r in rows if type(r) is dict and r.get('id') == expected.reservation_id]
 same = [r for r in rows if type(r) is dict and r.get('environment') == identity['environment']]
 # A re-minted or second claim in the original environment is foreign even when the own row is gone (L6).
 if any(r.get('id') != expected.reservation_id for r in same):return 'foreign'
 if not own:return 'absent'
 row = own[0]
 try:exact = len(own) == 1 and len(same) == 1 and environments._identity(row) == identity
 except (KeyError, TypeError):return 'foreign'
 evidence = row.get('activeJobEvidence')
 if (not exact or row.get('requestedMemoryBytes') != expected.memory or row.get('allocationState') != 'pending' or type(evidence) is not dict
  or (evidence.get('kind'), evidence.get('source'), evidence.get('reservationId'), evidence.get('reservationToken'))
  != ('active-job', 'readiness-resources', identity['reservationId'], identity['token'])):return 'foreign'
 if (evidence.get('outcome'), row.get('activeJob')) == ('unknown', 'unknown'):return 'unknown'
 if (evidence.get('outcome'), row.get('activeJob')) != ('complete', 'absent'):return 'foreign'
 observed, maximum = evidence.get('observedAtUnixMs'), row.get('observationMaximumAgeMs')
 return 'fresh' if type(observed) is int and type(maximum) is int and observed <= now_ms and now_ms - observed <= maximum else 'stale'


def _inventory_rows(root):
 try:
  with private.Directory(root / '.rag_index' / 'native-environments') as directory:value = attempts._read(directory, 'reservations.json')
 except (OSError, ValueError):raise Refused('inventory_changed') from None
 _need(value is not None and type(value[0].get('reservations')) is list, 'inventory_changed')
 return value[0]['reservations']


def _census(root, expected):
 base = root / '.rag_index' / 'readiness-resources'
 for name in sorted(set(os.listdir(base)) - {expected.op}):
  try:
   with private.Directory(base / name) as directory:value = attempts._read(directory, attempts.record_name('prepared'))
  except (OSError, ValueError):raise Refused('other_machine_journal_present') from None
  _need(value is not None and value[0].get('machineUuid') != expected.machine, 'other_machine_journal_present')
 targets = root / '.rag_index' / 'readiness-targets'
 for name in sorted(os.listdir(targets)) if os.path.isdir(targets) else ():
  try:
   with private.Directory(targets / name) as directory:
    for entry in sorted(os.listdir(directory.fd)):
     value = attempts._read(directory, entry) if entry.endswith('.json') else None
     _need(value is None or value[0].get('machine') != expected.machine, 'readiness_target_dispatch_present')
  except (OSError, attempts.AttemptUnresolved):raise Refused('readiness_target_dispatch_present') from None
 _need(not os.path.lexists(root / '.rag_index/windows-vm-deploy-intents' / (expected.machine + '.intent.json'))
  and not os.path.lexists(root / '.runtime/windows-vm-credentials' / expected.machine), 'deploy_intent_present')


def _registry(root, expected, plan, namespace):
 """Pinned original creator custody: the unchanged registry load plus exact file digests."""
 try:
  record, files = registry.load(root, plan['binding']).guard(), {}
  with private.Directory(root / '.rag_index' / 'windows-managed-creators' / attempts.SCOPE) as scope:
   for name in sorted(expected.registry):
    with private.Snapshot(scope, name) as snapshot_file:files[name] = snapshot_file.digest
 except (OSError, ValueError, AttributeError):raise Refused('registry_unresolved') from None
 _need(files == expected.registry and (record['plan'], record['hostBinding'], record['namespace']) == (plan, expected.host_binding, namespace), 'registry_unresolved')
 return files


def _precensus(root, expected, rows):
 """Before the link nothing else may exist for this VM: rows, journals, dispatches, intents, attempt roots."""
 _need(not any(type(r) is dict and r.get('environment') == 'windows-' + expected.machine for r in rows), 'environment_row_present')
 _census(root, expected)
 _need(not os.path.lexists(attempts.attempts_parent(root)), 'attempt_custody_unresolved')


def _local(ctx, directory, *, history=False):
 """Held local facts L1-L7; no transport, secret, journal write or initialization.

 Before the durable link the full census binds the claim. The history action and
 every post-link action re-authenticate only the original 7e8 facts: the linked
 attempt legitimately adds its own targets, credentials, rows and actors.
 """
 root, expected = ctx['root'], ctx['expected']
 _need((expected.op, expected.machine, expected.rid) == (attempts.OP, attempts.MACHINE, attempts.RID), 'inputs_invalid')
 epoch = _epoch(expected);held, pins = _evidence(root, expected)
 try:
  plan, host = creator._plan(json.loads(held['plan'])), jobs.MachineBinding.from_dict(json.loads(held['hostBinding']))
  namespace, typed, once = creator._namespace_reply(plan, host, json.loads(held['namespace'])), json.loads(held['stdout']), json.loads(held['once'])
 except (ValueError, TypeError, KeyError):raise Refused('local_evidence_changed') from None
 binding = plan['binding']
 _need((plan['operationId'], plan['recoveryId'], binding['spec']['deploymentId'], binding['spec']['root'], binding['domain'], binding['uri'], binding['spec']['host'])
  == (expected.op, expected.rid, expected.machine, expected.vm_root, expected.domain, expected.uri, HOST)
  and jobs.asdict(host) == expected.host_binding and binding['context']['hostBootId'] == _boot(expected)
  and ((len(held['stdout']), pins['stdout']), (len(held['stderr']), pins['stderr'])) == (tuple(expected.stdout), tuple(expected.stderr))
  and typed == expected.typed and once == {'operationId': expected.op, 'programSha256': expected.program_sha, 'replayAllowed': False}
  and pins['program'] == expected.program_sha and namespace['marker']['ownerSourceSha256'] == expected.owner_sha, 'local_evidence_changed')
 prepared, submitting, identity, chain = _resources(expected, directory)
 try:validated = attempts.chain(root)
 except (OSError, ValueError):raise Refused('record_integrity') from None
 _need(validated == {'authorization': chain[AUTHORIZATION], 'releaseSubmitting': chain[RELEASING], 'released': chain[RELEASED], 'link': chain[LINK]},
  'record_integrity')
 snapshot = {**{k: submitting[k] for k in ('hostBootId', 'census', 'inventorySha256', 'resourceAliases', 'pending')},
  'requestedMemoryBytes': prepared['requestedMemoryBytes'], 'headroomBytes': prepared['headroomBytes']}
 _derive(held, snapshot, plan, namespace, host);_phase_region(held['oldCreator'].decode('utf-8'))
 files, history = _registry(root, expected, plan, namespace), history or chain[LINK] is not None
 linked = () if chain[LINK] is None else (chain[LINK][0]['next']['operationId'],)
 rows = _inventory_rows(root)
 if not history:_precensus(root, expected, rows)
 identity_sha = sha(canonical(identity).encode())
 stable = {'identity': {'operationId': expected.op, 'machineUuid': expected.machine, 'recoveryId': expected.rid, 'vmRoot': expected.vm_root,
  'domain': expected.domain, 'uri': expected.uri, 'hostBinding': expected.host_binding},
  'sources': {'programSha256': expected.program_sha, 'ownerSourceSha256': expected.owner_sha, 'oldCreatorSha256': pins['oldCreator']},
  'evidence': pins, 'registry': files,
  'resources': {'preparedRecordSha256': expected.prepared_sha, 'submittingRecordSha256': expected.submitting_sha, 'reservationId': expected.reservation_id,
  'reservationIdentitySha256': identity_sha, 'requestedMemoryBytes': expected.memory}}
 return {'epoch': epoch, 'pins': pins, 'plan': plan, 'host': host, 'namespace': namespace, 'prepared': prepared, 'identity': identity, 'identitySha': identity_sha,
  'chain': chain, 'linked': linked, 'stable': stable, 'history': history, 'row': _classify(rows, expected, identity, _now_ms()),
  'rowBinding': _row_binding(_own(rows, expected))}


def _recheck(ctx, local):
 """Re-establish the held local facts before each durable step (C5).

 Source epoch, retained evidence and handoff absence, the original registry
 custody and, before the link, the census read under the native inventory lock
 (whose rows are returned; history returns None and takes no lock).
 """
 root, expected = ctx['root'], ctx['expected']
 _need(_epoch(expected) == local['epoch'], 'source_epoch_changed')
 _need(_evidence(root, expected)[1] == local['pins'], 'local_evidence_changed')
 _need(_registry(root, expected, local['plan'], local['namespace']) == local['stable']['registry'], 'registry_unresolved')
 if local['history']:return None
 try:rows = resources._inventory(root)[0]
 except Exception:raise Refused('inventory_changed') from None
 _precensus(root, expected, rows)
 return rows


# ------------------------------------------------------------ remote observer

def _host_epoch():
 import os, pathlib
 return {'machine': host_machine(), 'boot': pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(), 'account': str(os.geteuid())}


def _actor_census(paths, proc='/proc', privileged=False, denied=()):
 """Bounded /proc holder census of the given paths.

 Each process (ordinary: the same account only) is matched by command-line
 tokens, descriptor links, cwd, root, exe and mapped files against every path
 and every AF_UNIX socket bound under one; such a bound socket is itself a
 reference, and a command-line match is a reference even when the descriptors
 are denied. A zombie must show one thread and no command line (the root
 census also requires no descriptor, map, cwd or root) and keep its start and
 state across those checks: a non-holder whose pid, ppid, state and start are
 reported. An actual EACCES/EPERM on a same-account process (non-dumpable,
 such as (sd-pam)) is reported denied, never skipped: only the fixed root
 census may complete it. The ordinary scan excludes its own transport chain
 (this program and its ancestors; its non-dumpable sshd-session would
 otherwise be a new denial on every connection). The root census excludes
 only itself (precedent: the privileged terminal-closure census), reads every
 account, must never be denied, requires a kernel thread to have no command
 line and reports each earlier denied process as examined or exited. More
 than 8192 descriptors in one process is actor_descriptor_limit; every other
 anomaly is actor_scan_incomplete. A refusal or reference carries one bounded
 detail (finite substep, pid, start ticks, errno class) for the receipt only.
 A process that vanished mid-scan holds nothing any more.
 """
 import os, time
 class Incomplete(Exception):pass
 end, euid, targets, current = time.monotonic() + 10, os.geteuid(), [os.fsencode(p) for p in paths], [0, 0]
 def detail(step, error=None):
  code = getattr(error, 'errno', None)
  return {'substep': step, 'pid': current[0], 'startTicks': current[1],
   'errno': None if error is None else {1: 'EPERM', 2: 'ENOENT', 5: 'EIO', 13: 'EACCES'}.get(code, 'OTHER')}
 def fault(step, error=None):raise Incomplete(detail(step, error))
 inside = lambda raw: any(raw == t or raw.startswith(t + b'/') for t in targets)
 def read(path, limit):
  fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
  try:
   raw = b''
   while True:
    part = os.read(fd, 65536)
    if not part:return raw
    raw += part
    if len(raw) > limit:fault('file-oversize')
  finally:os.close(fd)
 def fields(base):
  try:
   tail = read(base + '/stat', 8192).rsplit(b')', 1)[1].split()
   return tail[0].decode('ascii'), int(tail[1]), int(tail[6]), int(tail[19])
  except (IndexError, ValueError, UnicodeError):fault('stat-schema')
 def link(path):
  try:return os.fsencode(os.readlink(path)).removesuffix(b' (deleted)')
  except FileNotFoundError:return None
 def holds(base):
  return bool(os.listdir(base + '/fd') or read(base + '/maps', 65536) or link(base + '/cwd') is not None or link(base + '/root') is not None)
 def zombie(pid, base, parent, start):
  if [line.split(b':', 1)[1].strip() for line in read(base + '/status', 65536).splitlines() if line.startswith(b'Threads:')] != [b'1']:
   fault('zombie-threads')
  if read(base + '/cmdline', 65536):fault('zombie-command')
  if privileged and holds(base):fault('zombie-resources')
  again = fields(base)
  if again[3] != start or again[0] != 'Z':fault('identity-changed')
  if privileged and holds(base):fault('zombie-postcheck')
  zombies.append([pid, parent, 'Z', start])
 own, references, seen, zombies, hidden, sockets, first = {os.getpid()}, 0, set(), [], [], set(), None
 try:
  pid = os.getpid()
  for _ in range(0 if privileged else 64):
   try:pid = fields(proc + '/' + str(pid))[1]
   except (OSError, Incomplete):break
   if pid <= 1:break
   own.add(pid)
  try:names = [name for name in os.listdir(proc) if name.isdigit()]
  except OSError as error:fault('proc-list', error)
  if len(names) > 65536:fault('proc-list-limit')
  for row in read(proc + '/net/unix', 4194304).splitlines()[1:]:
   cols = row.split(None, 7)
   if len(cols) == 8 and inside(cols[7]):references += 1;sockets.add(b'socket:[' + cols[6] + b']');first = first or detail('reference-bound-socket')
  for name in names:
   pid, base = int(name), proc + '/' + name
   current[:] = [pid, 0]
   if time.monotonic() > end:fault('scan-deadline')
   if pid in own:continue
   try:
    if not privileged and os.stat(base).st_uid != euid:continue
    state, parent, flags, start = fields(base);current[1] = start;seen.add((pid, start))
    if state == 'Z':
     zombie(pid, base, parent, start);continue
    tokens = read(base + '/cmdline', 1048576).split(b'\0')
    if flags & 0x00200000:
     if tokens != [b'']:fault('kernel-command')
     continue
    kind = 'cmdline' if any(inside(token) for token in tokens) else None
    if kind is None:
     try:
      descriptors = os.listdir(base + '/fd')
      if len(descriptors) > 8192:return {'reason': 'actor_descriptor_limit', 'detail': detail('descriptor-limit')}
      for descriptor in descriptors:
       target = link(base + '/fd/' + descriptor)
       if kind is None and target is not None:kind = 'descriptor' if inside(target) else 'socket' if target in sockets else None
      for leaf in ('cwd', 'root', 'exe'):
       target = link(base + '/' + leaf)
       if kind is None and target is not None and inside(target):kind = leaf
      for row in read(base + '/maps', 16777216).splitlines():
       cols = row.split(None, 5)
       if kind is None and len(cols) == 6 and inside(cols[5].removesuffix(b' (deleted)')):kind = 'maps'
     except PermissionError as error:
      if privileged:fault('privileged-denied', error)
      again = fields(base)
      if again[3] != start:fault('identity-changed')
      if again[0] == 'Z':zombie(pid, base, again[1], start)
      else:hidden.append([pid, start])
      continue
    if fields(base)[3] != start:fault('identity-changed')
    if kind is not None:references += 1;first = first or detail('reference-' + kind)
   except (FileNotFoundError, ProcessLookupError):continue
 except Incomplete as error:return {'reason': 'actor_scan_incomplete', 'detail': error.args[0]}
 except OSError as error:return {'reason': 'actor_scan_incomplete', 'detail': detail('proc-io', error)}
 result = {'reason': None, 'references': references, 'denied': sorted(hidden), 'zombies': sorted(zombies), **({'detail': first} if first else {})}
 if privileged:result['covered'] = [[pid, start, 'examined' if (pid, start) in seen else 'exited'] for pid, start in denied]
 return result


def _root_identity():
 import os
 return {'euid': os.geteuid(), 'uid': os.getuid(), 'sudoUid': os.environ.get('SUDO_UID')}


def _manager_identity(socket_path, executable):
 """Ordinary session manager peer identity, by the old creator manager() rules."""
 import os, socket, stat, struct
 generation = lambda i: [i.st_dev, i.st_ino, i.st_mode, i.st_uid, i.st_gid, i.st_nlink, i.st_size, i.st_mtime_ns, i.st_ctime_ns]
 structure = lambda i: [i.st_dev, i.st_ino, i.st_mode, i.st_uid, i.st_gid]
 try:named, binary = os.lstat(socket_path), os.open(executable, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
 except OSError:return None
 try:
  exe = os.fstat(binary)
  if (not stat.S_ISSOCK(named.st_mode) or named.st_uid != os.geteuid() or named.st_mode & 0o077 or os.path.realpath(executable) != executable
   or exe.st_uid != 0 or exe.st_mode & 0o022):return None
  with socket.socket(socket.AF_UNIX) as client:
   client.settimeout(5);client.connect(socket_path);peer = struct.unpack('3i', client.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
  pid = peer[0]
  if peer[1] != os.geteuid() or os.path.realpath('/proc/%d/exe' % pid) != executable or generation(os.stat('/proc/%d/exe' % pid)) != generation(exe):return None
  with open('/proc/%d/stat' % pid) as stream:row = stream.read(8193).rsplit(')', 1)[1].split()
  if row[0] in ('Z', 'X') or structure(os.lstat(socket_path)) != structure(named):return None
  return {'pid': pid, 'birth': int(row[19]), 'executableGeneration': generation(exe), 'socketIdentity': structure(named)}
 except (OSError, IndexError, ValueError, AttributeError):return None
 finally:os.close(binary)


def _domain_lookups(uri, machine, domain):
 """Read-only connection; both lookups must return exact VIR_ERR_NO_DOMAIN.

 Without libvirt's read-only open there is no fallback to a writable open: refuse.
 """
 import os
 os.environ['LIBVIRT_AUTOSTART'] = '0'
 import libvirt
 libvirt.registerErrorHandler(lambda context, error: None, None)
 read_only = getattr(libvirt, 'openReadOnly', None)
 if not callable(read_only):return {'uuid': 'read-only-unavailable', 'name': 'read-only-unavailable'}
 try:connection = read_only(uri)
 except libvirt.libvirtError:return {'uuid': 'unavailable', 'name': 'unavailable'}
 try:
  if connection is None or connection.getURI() != uri:return {'uuid': 'unavailable', 'name': 'unavailable'}
  codes = {}
  for key, lookup, value in (('uuid', connection.lookupByUUIDString, machine), ('name', connection.lookupByName, domain)):
   try:lookup(value)
   except libvirt.libvirtError as error:codes[key] = 'VIR_ERR_NO_DOMAIN' if error.get_error_code() == libvirt.VIR_ERR_NO_DOMAIN else 'other'
   else:codes[key] = 'visible'
  return codes
 finally:
  if connection is not None:connection.close()


def _observer_main():
 import fcntl, hashlib, json, os, pathlib, stat, sys, time, types
 E, held = EXPECTED, []
 base = {'kind': 'windows-creator-prevm-observation-v1', 'mode': E['mode']}
 class Refusal(Exception):pass
 def need(value, reason):
  if not value:raise Refusal(reason)
 pin = lambda i: [i.st_dev, i.st_ino, i.st_mode, i.st_uid, i.st_gid, i.st_nlink, i.st_size, i.st_mtime_ns, i.st_ctime_ns]
 digest = lambda raw: hashlib.sha256(raw).hexdigest()
 try:
  os.environ['LIBVIRT_AUTOSTART'] = '0'
  need(digest(OWNER) == E['ownerSha256'], 'owner_source_mismatch')
  owner = types.ModuleType('prevm_observer_owner');sys.modules[owner.__name__] = owner
  exec(compile(OWNER, 'fixed prevm observer owner', 'exec'), owner.__dict__);owner.owner_source = lambda: OWNER
  epoch = _host_epoch();need(epoch == E['host'], 'host_epoch_changed')
  bound, space = owner.MachineBinding.from_dict(E['binding']), E['namespace']
  root = pathlib.Path(space['root']);marker, job = root / 'creator-namespace.json', root / E['op']
  try:owner._root(root, tuple(space['generation']));owner._root(root / 'admissions', tuple(space['admissionsGeneration']));fd = os.open(marker, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
  except (OSError, owner.DurableJobError):raise Refusal('namespace_changed')
  held.append(fd)
  need(pin(os.fstat(fd)) == space['markerGeneration'] == pin(os.lstat(marker)) and owner._record(marker) == space['marker'], 'namespace_changed')
  if E['mode'] == 'proof':
   try:fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
   except BlockingIOError:raise Refusal('namespace_busy')
  operations, names, indices = [E['op'], *E['linked']], sorted(os.listdir(root)), sorted(os.listdir(root / 'admissions'))
  need(set(names) <= {'creator-namespace.json', 'admissions', *operations} and {'creator-namespace.json', 'admissions', E['op']} <= set(names)
   and set(indices) <= {op + '.json' for op in operations} and E['op'] + '.json' in indices
   and [n for n in os.listdir(root.parent) if E['machine'] in n] == [root.name], 'other_attempt_present')
  index = root / 'admissions' / (E['op'] + '.json')
  need(owner._record(index) == E['index'], 'admission_index_mismatch')
  index_pin = pin(owner._private(index, directory=False))
  try:owner._private(job, directory=True)
  except owner.DurableJobError:raise Refusal('job_entries_unexpected')
  for name, reason in (('credentials-accepted.json', 'credentials_accepted_present'), ('credentials-handoff.intent.json', 'credentials_handoff_present'),
   ('creator-listener.json', 'creator_listener_present'), ('credentials.sock', 'credentials_socket_present'), ('create.intent.json', 'create_intent_present')):
   need(not os.path.lexists(job / name), reason)
  entries = sorted(os.listdir(job));need(entries == E['jobEntries'], 'job_entries_unexpected')
  try:pins = {name: pin(owner._private(job / name, directory=False)) for name in entries}
  except owner.DurableJobError:raise Refusal('job_entries_unexpected')
  try:intent = owner._intent(job, E['op'], bound)
  except owner.DurableJobError:raise Refusal('terminal_foreign')
  need(digest(owner._read(job / 'program.py', owner.MAX_PROGRAM_BYTES)) == E['programSha256'], 'program_source_mismatch')
  need(owner._read(job / 'owner.py', owner.MAX_PROGRAM_BYTES) == OWNER, 'owner_source_mismatch')
  need(owner._read(job / 'child-admission', 64) == b'consumed\n', 'job_entries_unexpected')
  need(all(intent[key] == value for key, value in E['intent'].items()), 'terminal_foreign')
  status = owner.observe(root, E['op'], bound, generation=tuple(space['generation']))
  need(status['state'] != 'running', 'owner_alive');need(status['reason'] != 'output_overflow', 'terminal_truncated')
  need(status['state'] == 'terminal' and status['reason'] == 'correlated_terminal', 'terminal_foreign')
  terminal = status['terminal']
  need((terminal['generation'], terminal['exitCode'], terminal['owner'], terminal['programSha256']) == (E['intent']['generation'], 0, E['owner'], E['programSha256']), 'terminal_foreign')
  for name in ('stdout', 'stderr'):
   need(terminal[name]['retainedBytes'] == terminal[name]['totalBytes'] and terminal[name]['overflow'] is False, 'terminal_truncated')
   need([terminal[name]['totalBytes'], terminal[name]['sha256']] == E[name], 'terminal_foreign')
  try:_, stdout, stderr = owner.collect(root, E['op'], bound, generation=tuple(space['generation']))
  except owner.DurableJobError:raise Refusal('terminal_truncated')
  need([len(stdout), digest(stdout)] == E['stdout'] and [len(stderr), digest(stderr)] == E['stderr'], 'terminal_truncated')
  try:typed = json.loads(stdout)
  except ValueError:typed = None
  need(typed == E['typed'], 'terminal_not_blocked_credential_listener')
  need(owner._birth(E['owner']['pid']) != E['owner']['birth'], 'owner_alive')
  actors, processes = {'owner': {**E['owner'], 'alive': False}, 'child': 'unrecorded'}, None
  if E['mode'] == 'proof':
   # The shared namespace, the original job and the VM root. History (post-link
   # reporting) drops the scan: a linked attempt legitimately holds all three.
   census = _actor_census([str(job), str(root), E['vmRoot']])
   need(type(census) is dict, 'actor_scan_incomplete')
   if census.get('reason') is not None or census.get('references') != 0:
    reason = census.get('reason') or 'actor_reference_present'
    raise Refusal(reason if reason in ('actor_descriptor_limit', 'actor_scan_incomplete', 'actor_reference_present') else 'actor_scan_incomplete',
     census.get('detail'))
   actors['references'], processes = 0, {'denied': census['denied'], 'zombies': census['zombies']}
  else:actors['scan'] = 'history-dropped'
  facts = {'host': epoch, 'index': index_pin, 'job': pins, 'absent': ['create.intent.json', 'creator-listener.json', 'credentials-accepted.json', 'credentials-handoff.intent.json', 'credentials.sock'],
   'namespace': {**{k: space[k] for k in ('root', 'generation', 'admissionsGeneration', 'markerGeneration')}, 'names': names, 'admissions': indices},
   'terminal': {'generation': terminal['generation'], 'exitCode': 0, 'owner': terminal['owner'], 'stdout': terminal['stdout'], 'stderr': terminal['stderr'], 'typed': typed},
   'actors': actors}
  volatile, manager = {}, None
  if E['mode'] == 'proof':
   vm, fd = pathlib.Path(E['vmRoot']), os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW);held.append(fd)
   try:
    for part in vm.parent.parts[1:]:fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd);held.append(fd)
   except OSError:raise Refusal('vm_root_parent_unsafe')
   parent = os.fstat(fd);need(parent.st_uid == os.geteuid() and not parent.st_mode & 0o022, 'vm_root_parent_unsafe')
   try:os.stat(vm.name, dir_fd=fd, follow_symlinks=False)
   except FileNotFoundError:pass
   else:raise Refusal('vm_root_present')
   ledger = pathlib.Path(E['ledger'])
   try:info, lock = os.lstat(ledger), os.open(ledger / 'storage-plans.lock', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
   except OSError:raise Refusal('storage_unenrolled')
   held.append(lock);row = os.fstat(lock)
   need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and not info.st_mode & 0o022 and ledger.resolve() == ledger and stat.S_ISREG(row.st_mode)
    and row.st_uid == os.geteuid() and row.st_nlink == 1 and stat.S_IMODE(row.st_mode) == 0o600, 'storage_unenrolled')
   end = time.monotonic() + 5
   while True:
    try:fcntl.flock(lock, fcntl.LOCK_SH | fcntl.LOCK_NB);break
    except BlockingIOError:need(time.monotonic() < end, 'storage_ledger_busy');time.sleep(.05)
   need(not any(n.startswith('storage-') and n.endswith('.tmp') for n in os.listdir(ledger)), 'storage_ledger_busy')
   plans = types.ModuleType('prevm_observer_storage');sys.modules[plans.__name__] = plans
   exec(compile(STORAGE, 'fixed prevm observer storage', 'exec'), plans.__dict__)
   try:ledger_value = plans.StoragePlans(ledger)._read()
   except plans.FixtureStorageError:raise Refusal('storage_unenrolled')
   need(E['storagePlan'] not in ledger_value['plans'], 'storage_plan_present')
   inside = lambda text: text == E['vmRoot'] or text.startswith(E['vmRoot'] + '/')
   need(not any(inside(p['directory']) or any(inside(d['path']) for d in p['disks']) for p in ledger_value['plans'].values()), 'storage_plan_under_root')
   try:
    with open(ledger / 'storage-plans.json', 'rb') as stream:volatile['ledgerSha256'] = digest(stream.read(1048577))
   except FileNotFoundError:volatile['ledgerSha256'] = None
   volatile['plans'] = len(ledger_value['plans'])
   manager = _manager_identity(E['managerSocket'], E['managerExecutable']);need(manager is not None, 'manager_unavailable')
   try:codes = _domain_lookups(E['uri'], E['machine'], E['domain'])
   except Exception:raise Refusal('domain_unknown')
   need('read-only-unavailable' not in codes.values(), 'domain_read_only_unavailable')
   need('unavailable' not in codes.values(), 'manager_unavailable');need('visible' not in codes.values(), 'domain_visible')
   need(codes == {'uuid': 'VIR_ERR_NO_DOMAIN', 'name': 'VIR_ERR_NO_DOMAIN'}, 'domain_unknown')
   need(_manager_identity(E['managerSocket'], E['managerExecutable']) == manager, 'manager_changed')
   facts.update(vmRoot={'parent': pin(parent)[:5], 'absent': True}, storage={'plan': 'absent'}, domain=codes)
  need(pin(os.lstat(marker)) == space['markerGeneration'] and {n: pin(os.lstat(job / n)) for n in sorted(os.listdir(job))} == pins
   and pin(os.lstat(index)) == index_pin, 'namespace_changed')
  need(_host_epoch() == epoch, 'host_epoch_changed')
  print(json.dumps({**base, 'state': 'observed', 'facts': facts, 'volatile': volatile,
   **({'manager': manager, 'processes': processes} if E['mode'] == 'proof' else {})}, sort_keys=True))
 except Refusal as refusal:
  extra = refusal.args[1] if len(refusal.args) > 1 and refusal.args[1] else None
  print(json.dumps({**base, 'state': 'refused', 'reason': str(refusal.args[0]), **({'detail': extra} if extra else {})}, sort_keys=True))
 except BaseException:print(json.dumps({**base, 'state': 'refused', 'reason': 'observation_unknown'}, sort_keys=True))
 finally:
  for descriptor in reversed(held):os.close(descriptor)


def _root_census_main():
 """Fixed root holder census, admitted only after a measured same-account /proc denial.

 Refusals of the census itself carry its bounded detail for the receipt only.
 """
 import json
 E, base = ROOT, {'kind': 'windows-creator-prevm-root-census-v1'}
 emit = lambda value: print(json.dumps({**base, **value}, sort_keys=True))
 step = lambda name: {'detail': {'substep': name, 'pid': 0, 'startTicks': 0, 'errno': None}}
 try:
  if _root_identity() != {'euid': 0, 'uid': 0, 'sudoUid': E['account']}:
   return emit({'state': 'refused', 'reason': 'privileged_census_unknown', **step('root-identity')})
  epoch = lambda: (lambda value: (value['machine'], value['boot']))(_host_epoch())
  if epoch() != (E['machine'], E['boot']):return emit({'state': 'refused', 'reason': 'host_epoch_changed'})
  census = _actor_census(E['paths'], privileged=True, denied=E['denied'])
  if type(census) is not dict or census.get('reason') not in (None, 'actor_descriptor_limit', 'actor_scan_incomplete'):
   return emit({'state': 'refused', 'reason': 'privileged_census_unknown', **step('root-exception')})
  found = {'detail': census['detail']} if census.get('detail') else {}
  if census['reason'] is not None:return emit({'state': 'refused', 'reason': census['reason'], **found})
  if census['references']:return emit({'state': 'refused', 'reason': 'actor_reference_present', **found})
  if epoch() != (E['machine'], E['boot']):return emit({'state': 'refused', 'reason': 'host_epoch_changed'})
  emit({'state': 'complete', 'scope': 'all-uids', 'references': 0, 'covered': census['covered']})
 except BaseException:emit({'state': 'refused', 'reason': 'privileged_census_unknown', **step('root-exception')})


_BOUNDARIES = ('_host_epoch', '_actor_census', '_manager_identity', '_domain_lookups')
_ROOT_BOUNDARIES = ('_host_epoch', '_root_identity', '_actor_census')


def _remote(expected, local, mode):
 parent = str(PurePosixPath(expected.vm_root).parent)
 host = {k: expected.host_binding[k] for k in ('machine', 'boot', 'account')}
 return {'mode': mode, 'op': expected.op, 'machine': expected.machine, 'linked': list(local['linked']), 'vmRoot': expected.vm_root, 'domain': expected.domain,
  'uri': expected.uri, 'host': host, 'binding': expected.host_binding, 'namespace': local['namespace'], 'jobEntries': _JOB_ENTRIES,
  'index': {'operationId': expected.op, 'binding': expected.host_binding, 'programSha256': expected.program_sha, 'streamLimit': 262144, 'schemaVersion': 1,
  'purpose': 'windows-managed-first-create'},
  'intent': {'purpose': 'windows-managed-first-create', 'programSha256': expected.program_sha, 'streamLimit': 262144, 'generation': expected.intent_generation},
  'owner': expected.owner, 'stdout': list(expected.stdout), 'stderr': list(expected.stderr), 'typed': expected.typed, 'ownerSha256': expected.owner_sha,
  'programSha256': expected.program_sha, 'ledger': parent + '/.cache/vpn-control-fixture-storage', 'storagePlan': 'windows-' + expected.machine,
  'managerSocket': parent + '/.cache/libvirt/virtqemud-sock', 'managerExecutable': expected.manager_executable}


def _observer_source(expected, local, mode, boundaries=None):
 """Fixed read-only program; production embeds only this module's own boundaries."""
 parts = ['EXPECTED=' + repr(_remote(expected, local, mode)), 'OWNER=' + repr(jobs.owner_source()), 'STORAGE=' + repr((REPO / _STORAGE).read_bytes()),
  inspect.getsource(creator.host_machine), *[(boundaries or {}).get(n) or inspect.getsource(globals()[n]) for n in _BOUNDARIES],
  inspect.getsource(_observer_main), '_observer_main()\n']
 source = '\n'.join(parts);compile(source, 'fixed prevm observer', 'exec')
 return source


def _root_census_source(expected, local, denied, boundaries=None):
 """Fixed root holder census over the same three paths; test boundaries use 'root:' keys."""
 root = str(local['namespace']['root'])
 census = {'paths': [root + '/' + expected.op, root, expected.vm_root], 'denied': [list(row) for row in denied],
  'machine': expected.host_binding['machine'], 'boot': expected.host_binding['boot'], 'account': expected.host_binding['account']}
 parts = ['ROOT=' + repr(census), inspect.getsource(creator.host_machine),
  *[(boundaries or {}).get('root:' + n) or inspect.getsource(globals()[n]) for n in _ROOT_BOUNDARIES], inspect.getsource(_root_census_main), '_root_census_main()\n']
 source = '\n'.join(parts);compile(source, 'fixed prevm root census', 'exec')
 return source


def _command(source):
 """The exact observer source, deflated: one inline argv below ssh_transport's 60,000-byte bound."""
 packed = base64.b64encode(zlib.compress(source.encode(), 9)).decode('ascii')
 return ('python3', '-I', '-B', '-c', "import base64,zlib;exec(zlib.decompress(base64.b64decode('" + packed + "')))")


def _ready(expected, ready):
 _need((ready.machine, ready.boot, str(ready.account).split(':', 1)[0]) == (expected.transport_machine, expected.host_binding['boot'], expected.host_binding['account']),
  'host_epoch_changed')


def _transport_runner(expected):
 """Ordinary observer: inline argv, empty stdin; the admission deadline bounds the whole step."""
 def run(root, source, deadline):
  budget = deadline - time.monotonic();_need(budget > 1, 'proof_expired')
  with transport.admitted_transport(root, HOST, str(uuid.uuid4()), deadline=time.monotonic() + min(_ADMISSION_SECONDS, budget)) as admitted:
   _ready(expected, admitted.ready)
   with deploy.direct.Guard(root, host=HOST) as authority:
    argv = transport.build_ssh_argv(authority.config, HOST, 30, command=_command(source))
    admitted.revalidate();authority.guard();changed = False
    try:result = transport.run_ssh(argv, input=b'', stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=max(.1, min(_RUN_SECONDS, deadline - time.monotonic())), cwd=root)
    except transport.SubmittedResultReadinessChanged as error:result, changed = error.take_submitted_result(), True
    try:admitted.revalidate();authority.guard()
    except Exception:changed = True
    return {'returnCode': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr, 'readinessChanged': changed}
 return run


def _privileged_runner(expected):
 """Root holder census through the reviewed sudo password carrier (precedent: the readiness host census).

 The protected credential (.codex/arch-sudo.local, the precedent's path) is
 opened only here, held for this one run, sent only on stdin and never placed
 in argv, records, logs or digests. Streams that echo it are discarded whole;
 a timed-out run returns no partial stream. The password carrier always uses
 the saved-program transfer, which the same admission deadline bounds.
 """
 def run(root, source, deadline):
  budget = deadline - time.monotonic();_need(budget > 1, 'proof_expired')
  try:credential = SecretFile(str(sudo_credential._credential_path(root)))
  except (OSError, ValueError):raise Refused('privileged_census_unavailable') from None
  with credential:
   private_input = None
   try:
    with transport.admitted_transport(root, HOST, str(uuid.uuid4()), deadline=time.monotonic() + min(_ADMISSION_SECONDS, budget)) as admitted:
     _ready(expected, admitted.ready)
     with deploy.direct.Guard(root, host=HOST) as authority:
      argv = transport.build_ssh_argv(authority.config, HOST, 30, command=('sudo', '-S', '-p', '', '--', 'python3', '-I', '-B', '-c', 'exec(' + repr(source) + ')'))
      credential.guard();admitted.revalidate();authority.guard();changed = False
      private_input = credential.text.encode('utf-8') + b'\n'
      try:result = transport.run_ssh(argv, input=private_input, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
       timeout=max(.1, min(_RUN_SECONDS, deadline - time.monotonic())), cwd=root)
      except transport.SubmittedResultReadinessChanged as error:result, changed = error.take_submitted_result(), True
      credential.guard();streams = (result.stdout, result.stderr)
      _need(all(type(stream) is bytes and len(stream) <= 65536 for stream in streams)
       and not any(credential.text.encode('utf-8') in stream for stream in streams), 'privileged_census_unknown')
      try:admitted.revalidate();authority.guard()
      except Exception:changed = True
      return {'returnCode': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr, 'readinessChanged': changed}
   except Refused:raise
   except Exception:raise Refused('privileged_census_unknown') from None
   finally:private_input = None
 return run


def _owned(path):
 try:os.mkdir(path, 0o700)
 except FileExistsError:pass
 jobs._private(path, directory=True)
 return path


def _run(ctx, runner, source, deadline, kind='observer'):
 """Retain raw stdout/stderr/callback create-only BEFORE any parse.

 The callback records the step's monotonic start and end (seconds, this
 coordinator's clock) so a native run measures each ordinary and root step.
 """
 reason = 'privileged_census_unknown' if kind == 'root-census' else 'observation_unknown'
 base = _owned(_owned(ctx['root'] / '.rag_index' / 'windows-managed-creator-prevm') / ctx['expected'].op)
 program = _owned(base / 'programs') / (sha(source.encode()) + '.py')
 try:jobs._create(program, source.encode())
 except FileExistsError:_need(jobs._read(program, jobs.MAX_PROGRAM_BYTES) == source.encode(), reason)
 receipt = _owned(base / 'observations') / str(uuid.uuid4());os.mkdir(receipt, 0o700)
 started = time.monotonic()
 timing = lambda: (lambda ended: {'startedMonotonic': round(started, 3), 'endedMonotonic': round(ended, 3), 'elapsedSeconds': round(ended - started, 3)})(time.monotonic())
 try:
  result = runner(ctx['root'], source, deadline)
  out, err, code = result['stdout'], result['stderr'], result['returnCode']
  _need(type(out) is bytes and type(err) is bytes and type(code) is int, reason)
 except Exception as error:
  # Partial streams of a timed-out ordinary run are retained raw, never parsed
  # or trusted. A privileged run never yields partial streams (input echo).
  timed = isinstance(error, subprocess.TimeoutExpired) and kind == 'observer'
  for leaf, raw in (('stdout.partial.bin', error.stdout), ('stderr.partial.bin', error.stderr)) if timed else ():
   if type(raw) is bytes and raw:jobs._create(receipt / leaf, raw)
  jobs._create(receipt / 'callback.json', canonical({'kind': kind, 'complete': False, 'timedOut': timed, 'errorClass': type(error).__name__,
   **timing()}).encode())
  raise Refused(error.reason if isinstance(error, Refused) else reason) from None
 measured = timing()
 jobs._create(receipt / 'stdout.bin', out);jobs._create(receipt / 'stderr.bin', err)
 changed = result.get('readinessChanged') is True
 jobs._create(receipt / 'callback.json', canonical({'kind': kind, 'complete': True, 'returnCode': code, 'stdoutBytes': len(out), 'stderrBytes': len(err),
  'readinessChanged': changed, **measured}).encode())
 _need(code == 0 and not err and 0 < len(out) <= 262144 and not changed, reason)
 return out


def _pairs(rows):
 value = {}
 for key, item in rows:_need(key not in value, 'observation_invalid');value[key] = item
 return value


def _rows(value, width, limit=4096):
 """Sorted unique int rows (state 'Z' in a zombie row's third column)."""
 valid = lambda row: (type(row) is list and len(row) == width and all(type(item) is int and item >= 0 for i, item in enumerate(row) if not (width == 4 and i == 2))
  and (width != 4 or row[2] == 'Z') and row[0] > 0)
 return type(value) is list and len(value) <= limit and all(valid(row) for row in value) and value == sorted(value) and len({row[0] for row in value}) == len(value)


def _detail(value):
 """One bounded census diagnostic: finite substep, pid, start ticks and errno class."""
 return (type(value) is dict and set(value) == {'substep', 'pid', 'startTicks', 'errno'} and type(value['substep']) is str and value['substep'] in _DETAIL_STEPS
  and all(type(value[key]) is int and value[key] >= 0 for key in ('pid', 'startTicks')) and value['errno'] in _ERRNO_CLASSES)


def _privileged_census(ctx, local, denied, deadline):
 """The fixed root census, run only because the ordinary scan measured a denial."""
 source = _root_census_source(ctx['expected'], local, denied, ctx['boundaries'])
 try:reply = json.loads(_run(ctx, ctx['privileged'], source, deadline, 'root-census'), object_pairs_hook=_pairs)
 except (ValueError, UnicodeError) as error:raise Refused(error.reason if isinstance(error, Refused) else 'privileged_census_unknown') from None
 _need(type(reply) is dict and reply.get('kind') == 'windows-creator-prevm-root-census-v1', 'privileged_census_unknown')
 if reply.get('state') == 'refused':
  _need(set(reply) - {'detail'} == {'kind', 'state', 'reason'} and type(reply['reason']) is str and reply['reason'] in _ROOT_REASONS
   and ('detail' not in reply or reply['reason'] in _DETAIL_REASONS and _detail(reply['detail'])), 'privileged_census_unknown')
  raise Refused(reply['reason'])
 covered = reply.get('covered')
 _need(set(reply) == {'kind', 'state', 'scope', 'references', 'covered'} and (reply['state'], reply['scope'], reply['references']) == ('complete', 'all-uids', 0)
  and type(covered) is list and [row[:2] for row in covered if type(row) is list] == denied
  and all(len(row) == 3 and row[2] in ('examined', 'exited') for row in covered), 'privileged_census_unknown')
 return {'scope': 'all-uids', 'covered': covered, 'sourceSha256': sha(source.encode())}


def _observe(ctx, local, mode, deadline=None):
 expected = ctx['expected'];deadline = ctx['deadline'] if deadline is None else min(deadline, ctx['deadline'])
 source = _observer_source(expected, local, mode, ctx['boundaries'])
 try:value = json.loads(_run(ctx, ctx['runner'], source, deadline), object_pairs_hook=_pairs)
 except (ValueError, UnicodeError) as error:raise Refused(error.reason if isinstance(error, Refused) else 'observation_invalid') from None
 _need(type(value) is dict and value.get('kind') == 'windows-creator-prevm-observation-v1' and value.get('mode') == mode, 'observation_invalid')
 if value.get('state') == 'refused':
  # A census refusal may carry its bounded detail; it stays in the retained receipt only.
  _need(set(value) - {'detail'} == {'kind', 'mode', 'state', 'reason'} and type(value['reason']) is str
   and ('detail' not in value or value['reason'] in _DETAIL_REASONS and _detail(value['detail'])), 'observation_invalid')
  raise Refused(value['reason'])
 facts = value.get('facts');actors = facts.get('actors') if type(facts) is dict else None
 owner = {'owner': {**expected.owner, 'alive': False}, 'child': 'unrecorded'}
 _need(value.get('state') == 'observed' and set(value) == {'kind', 'mode', 'state', 'facts', 'volatile'} | ({'manager', 'processes'} if mode == 'proof' else set())
  and type(facts) is dict and facts.get('host') == {k: expected.host_binding[k] for k in ('machine', 'boot', 'account')}
  and facts.get('terminal', {}).get('typed') == expected.typed
  and actors == {**owner, **({'references': 0} if mode == 'proof' else {'scan': 'history-dropped'})}, 'observation_invalid')
 if mode == 'proof':
  processes = value['processes']
  _need(facts.get('domain') == {'uuid': 'VIR_ERR_NO_DOMAIN', 'name': 'VIR_ERR_NO_DOMAIN'} and facts.get('vmRoot', {}).get('absent') is True
   and facts.get('storage') == {'plan': 'absent'} and type(value['manager']) is dict and type(processes) is dict and set(processes) == {'denied', 'zombies'}
   and _rows(processes['denied'], 2) and _rows(processes['zombies'], 4), 'observation_invalid')
  # Only a measured same-account denial admits the root census (ruling R5).
  value['processes'] = {**processes, 'root': _privileged_census(ctx, local, processes['denied'], deadline) if processes['denied'] else None}
 return value, sha(source.encode())


# ------------------------------------------------------------ proof capability

_PROOFS = weakref.WeakKeyDictionary()


class CreatorTerminalPreVMRefusal:
 """Opaque current source-owned capability; never a DTO, flag or receipt."""
 __slots__ = ('__weakref__',)
 def __new__(cls, *args, **kwargs):raise TypeError('windows_creator_prevm_proof_opaque')
 def __reduce__(self):raise TypeError('windows_creator_prevm_proof_opaque')
 def __copy__(self):raise TypeError('windows_creator_prevm_proof_opaque')
 def __deepcopy__(self, memo):raise TypeError('windows_creator_prevm_proof_opaque')


def _digests(local, value, observer):
 """N binds the stable no-VM facts; P adds the manager peer, the process facts
 (denied and zombie rows, the root census coverage), the observer source and the
 source epoch. Volatile process rows never enter N, so a reaped zombie or a new
 session can change only P, which root reviews again; it never strands A.
 """
 facts = sha(b'windows-creator-prevm-novm-v1\n' + canonical({'local': local['stable'], 'remote': value['facts']}).encode())
 return sha(b'windows-creator-prevm-proof-v1\n' + canonical({'facts': facts, 'manager': value['manager'], 'processes': value['processes'],
  'observerSourceSha256': observer, 'sourceEpoch': local['epoch']}).encode()), facts


def _mint(ctx, local):
 value, observer = _observe(ctx, local, 'proof')
 proof_sha, facts_sha = _digests(local, value, observer)
 proof, now = object.__new__(CreatorTerminalPreVMRefusal), ctx['clock']()
 _PROOFS[proof] = {'ctx': ctx, 'local': local, 'P': proof_sha, 'N': facts_sha, 'observer': observer, 'manager': value['manager'],
  'processes': value['processes'], 'minted': now, 'guarded': now}
 return proof


def _state(proof):
 _need(type(proof) is CreatorTerminalPreVMRefusal and proof in _PROOFS, 'proof_mismatch')
 return _PROOFS[proof]


def _guard(proof, deadline=None):
 state = _state(proof);ctx = state['ctx'];limit = ctx['deadline'] if deadline is None else min(deadline, ctx['deadline'])
 _need(ctx['clock']() - state['minted'] <= 120 and ctx['clock']() < limit, 'proof_expired')
 _recheck(ctx, state['local'])
 value, observer = _observe(ctx, state['local'], 'proof', limit)
 _need(ctx['clock']() <= limit, 'proof_expired')
 proof_sha, facts_sha = _digests(state['local'], value, observer)
 _need(facts_sha == state['N'], 'facts_changed');_need(value['manager'] == state['manager'], 'manager_changed')
 _need(value['processes'] == state['processes'], 'actors_changed');_need(proof_sha == state['P'], 'proof_mismatch')
 state['guarded'] = ctx['clock']()


def _fresh(proof):
 state = _state(proof);_need(state['ctx']['clock']() - state['guarded'] <= 20, 'proof_expired')


# ------------------------------------------------------------------ records

def _authorization_fields(expected, local):
 stream = lambda row: {'bytes': row[0], 'sha256': row[1]}
 return {'schemaVersion': 1, 'kind': 'windows-creator-prevm-release-authorization-v1', 'operationId': expected.op, 'machineUuid': expected.machine, 'attempt': 1,
  'cause': CAUSE, 'preparedRecordSha256': expected.prepared_sha, 'submittingRecordSha256': expected.submitting_sha,
  'creatorSubmissionOnceSha256': local['pins']['once'], 'programSha256': expected.program_sha, 'ownerSourceSha256': expected.owner_sha,
  'hostBootId': _boot(expected), 'terminal': {'generation': expected.intent_generation, 'exitCode': 0, 'stdout': stream(expected.stdout), 'stderr': stream(expected.stderr)},
  'reservationId': expected.reservation_id, 'reservationIdentitySha256': local['identitySha'], 'requestedMemoryBytes': expected.memory,
  'cleanShutdownClaimed': False, 'unsubmittedClaimed': False, 'replayAllowed': False}


def _authorization(expected, local, proof, row):
 """A binds the proof, the epoch and the exact U0 row it authorizes (token-free digests only)."""
 state = _state(proof)
 return {**_authorization_fields(expected, local), 'proofSha256': state['P'], 'factsSha256': state['N'], 'sourceEpoch': local['epoch'],
  'observerSourceSha256': state['observer'], 'reservationRow': row}


def _releasing(expected, local, authorization):
 """S: durable proof that THIS source attempted the one release, written right before it.

 Deterministic from A, so the create-only re-write on a resume is a no-op.
 """
 value, digest = authorization
 return {'schemaVersion': 1, 'kind': 'windows-creator-prevm-release-submitting-v1', 'operationId': expected.op, 'cause': CAUSE,
  'reservationId': expected.reservation_id, 'reservationIdentitySha256': local['identitySha'], 'authorizationKey': AUTHORIZATION,
  'authorizationSha256': digest, 'proofSha256': value['proofSha256'], 'factsSha256': value['factsSha256'], 'cleanShutdownClaimed': False,
  'nativeActionAllowed': False, 'replayAllowed': False}


def _released(expected, local, authorization, releasing):
 value, digest = authorization
 return {'ok': True, 'state': 'released', 'operationId': expected.op, 'cause': CAUSE, 'reservationId': expected.reservation_id,
  'reservationIdentitySha256': local['identitySha'], 'authorizationKey': AUTHORIZATION, 'authorizationSha256': digest, 'proofSha256': value['proofSha256'],
  'factsSha256': value['factsSha256'], 'releaseSubmittingKey': RELEASING, 'releaseSubmittingSha256': releasing[1], 'cleanShutdownClaimed': False,
  'nativeActionAllowed': False, 'replayAllowed': False}


def _next_plan(local, proof_sha):
 rid, op = attempts.derive(attempts.RID, proof_sha);binding = local['plan']['binding']
 plan = creator.plan(binding['spec'], binding['setup'], binding['context'], binding['uri'], binding['domain'], op, rid)
 _need(plan['binding'] == binding, 'link_mismatch')
 return plan


def _link(expected, local, authorization, released):
 plan, value = _next_plan(local, authorization[0]['proofSha256']), authorization[0]
 return {'schemaVersion': 1, 'kind': 'windows-managed-creator-generation-link-v1', 'machineUuid': expected.machine,
  'parent': {'operationId': expected.op, 'recoveryId': expected.rid, 'programSha256': expected.program_sha, 'attempt': 1,
  'registryRecordSha256': expected.registry['creator-original.json'], 'preparedRecordSha256': expected.prepared_sha,
  'submittingRecordSha256': expected.submitting_sha},
  'closure': {'authorizationSha256': authorization[1], 'releasedSha256': released[1], 'proofSha256': value['proofSha256'], 'factsSha256': value['factsSha256'], 'cause': CAUSE},
  'next': {'attempt': 2, 'recoveryId': plan['recoveryId'], 'operationId': plan['operationId'], 'planSha256': sha(canonical(plan).encode()),
  'bindingSha256': sha(canonical(plan['binding']).encode()),
  'attemptRoot': '.rag_index/windows-managed-creator-attempts/' + attempts.SCOPE + '/' + plan['recoveryId']},
  'replayAllowed': False, 'inputAuthority': False}


def _custody(root, local, authorization):
 """Append-only attempt custody: the unchanged registry.retain inside a private staging root."""
 try:
  plan = _next_plan(local, authorization[0]['proofSha256']);rid = plan['recoveryId']
  parent = _owned(_owned(root / '.rag_index' / 'windows-managed-creator-attempts') / attempts.SCOPE)
  if not os.path.lexists(parent / rid):
   staging = parent / ('.staging-' + rid[:16] + '-' + uuid.uuid4().hex);os.mkdir(staging, 0o700)
   _need(registry.retain(staging, plan, local['host'], local['namespace']).guard()['plan'] == plan, 'attempt_custody_unresolved')
   with private.Directory(parent) as directory:
    try:private._rename_create_only(directory.fd, staging.name, rid)
    except FileExistsError:pass
    os.fsync(directory.fd)
  custody = attempts.current(root)
  _need(custody.operation_id == plan['operationId'] and custody.plan() == json.loads(canonical(plan)), 'attempt_custody_unresolved')
 except Exception:raise _Unknown('attempt_custody_unresolved') from None
 return custody


def _write(journal, key, value):
 try:journal.record(key, value);written = _record(journal.directory, key)
 except Exception:raise _Unknown('record_unknown') from None
 _need_unknown(written is not None and written[0] == json.loads(canonical(value)), 'record_unknown')
 return written


# ------------------------------------------------------------------- actions

def _inputs(inputs, action):
 required, optional = ({'host', 'timeoutSeconds', 'expectedProofSha256'}, {'resumeAuthorizationSha256'}) if action == 'close' else ({'host', 'timeoutSeconds'}, set())
 bounds = {'close': _CLOSE_SECONDS, 'proof': _PROOF_SECONDS, 'history': _HISTORY_SECONDS}[action]
 _need(type(inputs) is dict and required <= set(inputs) <= required | optional and inputs['host'] == HOST and type(inputs['timeoutSeconds']) is int
  and bounds[0] <= inputs['timeoutSeconds'] <= bounds[1] and all(attempts._digest(inputs[k]) for k in set(inputs) & {'expectedProofSha256', 'resumeAuthorizationSha256'}),
  'inputs_invalid')


def _context(root, inputs, expected, runner, privileged, boundaries, clock):
 expected = _PRODUCTION if expected is None else expected
 return {'root': Path(root).resolve(strict=True), 'expected': expected, 'runner': runner or _transport_runner(expected),
  'privileged': privileged or _privileged_runner(expected), 'boundaries': boundaries, 'clock': clock, 'deadline': clock() + inputs['timeoutSeconds']}


def _summary(local, facts_sha=None):
 """What root reviews before approving a resume digest: the authorization, its facts and its bound row.

 A foreign row never matches; an absent row matches only after this source's
 own durable release-attempt record (releaseSubmitted).
 """
 authorization, chain = local['chain'][AUTHORIZATION], local['chain']
 releasing = chain[RELEASING] is not None
 return {'authorization': authorization is not None, 'authorizationSha256': authorization and authorization[1],
  'factsMatchAuthorization': None if authorization is None or facts_sha is None else facts_sha == authorization[0]['factsSha256'],
  'rowMatchesAuthorization': None if authorization is None else _row_matches(local['row'], local['rowBinding'], authorization[0].get('reservationRow'),
  releasing),
  'row': local['row'], 'releaseSubmitted': releasing, 'released': chain[RELEASED] is not None, 'link': chain[LINK] is not None}


def _result(state, reason=None, **values):
 return {'state': state, 'reason': reason, **values, 'evidenceClass': 'creator-prevm-claim-closure', 'productAction': False, 'nativeActionAllowed': False, 'replayAllowed': False}


def _closed(chain, reconciled):
 authorization, link = chain[AUTHORIZATION], chain[LINK][0]['next']
 return _result('closed', proofSha256=authorization[0]['proofSha256'], factsSha256=authorization[0]['factsSha256'], authorizationSha256=authorization[1],
  releasedSha256=chain[RELEASED][1], linkSha256=chain[LINK][1], reconciled=reconciled,
  nextAttempt={'attempt': 2, 'recoveryId': link['recoveryId'], 'operationId': link['operationId']})


def _close(root, inputs, *, expected=None, runner=None, privileged=None, boundaries=None, clock=time.monotonic):
 """C0-C11 under the ORIGINAL existing journal lock; no in-run retry.

 A refusal before any effect of this run stays positive. Once this run released
 the claim or recorded its released result, every later failure is UNKNOWN. A
 known authorization digest is always returned so root can review a resume.
 """
 _inputs(inputs, 'close')
 ctx = _context(root, inputs, expected, runner, privileged, boundaries, clock);expected, root = ctx['expected'], ctx['root']
 sentinel = root / '.rag_index' / 'windows-managed-creator-prevm' / expected.op / 'no-credential-sentinel'
 admission = resources.ResourceAdmission(root, resources.ResourceTarget(expected.op, HOST, expected.vm_root), expected.machine, expected.op,
  root / '.rag_index' / 'readiness-resources' / expected.op, str(sentinel), time.monotonic() + max(1., min(30., ctx['deadline'] - clock())))
 run = {'authorization': None, 'effected': False}
 try:
  with admission._existing_journal() as journal:return _closing(ctx, journal, inputs, run)
 except Refused as error:
  if run['effected'] and not isinstance(error, _Unknown):error = _Unknown(error.reason)
  error.authorization = error.authorization or run['authorization']
  raise error from None
 except Exception:
  if run['authorization'] is None and not run['effected']:raise
  raise _Unknown('observation_unknown', run['authorization']) from None


def _closing(ctx, journal, inputs, run):
 expected, root = ctx['expected'], ctx['root']
 existing = _record(journal.directory, AUTHORIZATION);run['authorization'] = existing and existing[1]
 local = _local(ctx, journal.directory);chain, row, resume = local['chain'], local['row'], inputs.get('resumeAuthorizationSha256')
 authorization, releasing, released = chain[AUTHORIZATION], chain[RELEASING], chain[RELEASED]
 # A claim this source did not produce: UNKNOWN, stop (contract closePrepared step 7).
 _need_stop(row != 'foreign', 'reservation_foreign')
 _need(not released or row == 'absent', 'record_integrity')
 if authorization is None:
  _need(resume is None, 'resume_unexpected')
  _need_stop(row != 'absent', 'reservation_absent_without_authorization')
  _need_stop(row == 'unknown', 'reservation_evidence_unexplained')
 else:
  fields = _authorization_fields(expected, local)
  _need({k: authorization[0].get(k) for k in fields} == fields and set(authorization[0]) == {*fields, *_AUTHORIZATION_BOUND}
   and _bound_row(authorization[0]['reservationRow']) and type(authorization[0]['sourceEpoch']) is dict, 'record_integrity')
  # Until the link the whole epoch A bound; after it only the custody sources (F4).
  bound = authorization[0]['sourceEpoch']
  _need(bound == local['epoch'] if chain[LINK] is None else
   all(local['epoch'].get(key) is not None and bound.get(key) == local['epoch'][key] for key in _CUSTODY_SOURCES), 'source_epoch_changed')
  _need(resume is not None, 'resume_required')
  _need(resume == authorization[1], 'authorization_mismatch')
  # Ruling R1: the same authorized closure continues only over the row it bound,
  # and over an absent row only after this source's own durable release attempt (F1).
  _need_stop(row != 'absent' or releasing is not None, 'reservation_absent_without_release')
  _need_stop(_row_matches(row, local['rowBinding'], authorization[0]['reservationRow'], releasing is not None), 'reservation_row_changed')
 if chain[LINK] is not None:
  # Custody-only reconcile (S10): no observation runs, so only the closure's own proof may be named.
  _need(inputs['expectedProofSha256'] == authorization[0]['proofSha256'], 'proof_mismatch')
  _custody(root, local, authorization)
  return _closed(chain, True)
 request = _release_request(expected, local) if released is None and row != 'absent' else None
 proof = _mint(ctx, local);state = _state(proof)
 _need(state['P'] == inputs['expectedProofSha256'], 'proof_mismatch')
 # The derived link is a pure function of the authorized proof; check it before any effect.
 _next_plan(local, state['P'] if authorization is None else authorization[0]['proofSha256'])
 if authorization is not None:_need(state['N'] == authorization[0]['factsSha256'], 'facts_changed')
 else:
  # Every deterministic precondition of the release runs before the create-only authorization.
  _need(ctx['deadline'] - ctx['clock']() >= _AUTHORIZE_SECONDS, 'budget_insufficient')
  rows = _recheck(ctx, local);_fresh(proof)
  # A binds the exact U0 row, re-read under the native lock right before it.
  _need(_classify(rows, expected, local['identity'], _now_ms()) == 'unknown' and _row_binding(_own(rows, expected)) == local['rowBinding'], 'inventory_changed')
  authorization = _write(journal, AUTHORIZATION, _authorization(expected, local, proof, local['rowBinding']));run['authorization'] = authorization[1]
 if released is None:
  if request is not None:releasing = _release(ctx, journal, local, proof, request, authorization);run['effected'] = True
  # The release already happened (here, or in the run that recorded S): record it at once, ungated by local facts.
  _require_absent(ctx, local)
  released = _write(journal, RELEASED, _released(expected, local, authorization, releasing));run['effected'] = True
 # Positive closure is durable. The link still needs a fresh durable absence and the held local facts.
 _require_absent(ctx, local);_recheck(ctx, local)
 link = _write(journal, LINK, _link(expected, local, authorization, released))
 _custody(root, local, authorization)
 return _closed({AUTHORIZATION: authorization, RELEASED: released, LINK: link}, False)


def _release_request(expected, local):
 """The original prepared request, checked before any authorization: bookkeeping only, never a new admission."""
 identity, request = local['identity'], copy.deepcopy(local['prepared'].get('request'))
 _need(type(request) is dict and (request.get('hostAlias'), request.get('environment'), request.get('operator'), request.get('requestedMemoryBytes'),
  request.get('allocationState')) == (identity['hostAlias'], identity['environment'], identity['operator'], expected.memory, 'pending'), 'resource_records_changed')
 return request


def _require_absent(ctx, local):
 """The own claim is durably absent, read under the native inventory lock; otherwise UNKNOWN."""
 try:rows, _ = resources._inventory(ctx['root'])
 except Exception:raise _Unknown('release_unknown') from None
 row = _classify(rows, ctx['expected'], local['identity'], _now_ms())
 _need_stop(row != 'foreign', 'reservation_foreign');_need_unknown(row == 'absent', 'release_unknown')


def _release(ctx, journal, local, proof, request, authorization):
 """Exact existing-row bookkeeping, then one recorded release, each behind a fresh guard.

 The locked inventory read must still show the row A bound (exact U0, or its
 stable projection under our own receipt). Every run that releases books the
 exact row first, also on a root-approved resume over our own complete receipt
 (no fresh-receipt shortcut: the receipt's 60 s window is shorter than one
 worst-case guard, so only a new receipt gives guard #2 its full window). The
 booking is check-and-set on the whole inventory and the exact identity, so it
 never mints. Guard #2 must end inside the receipt window. The release-attempt
 record S is written create-only right before the release; a failed write
 leaves the run UNKNOWN with no release. Returns S.
 """
 root, expected, identity, bound = ctx['root'], ctx['expected'], local['identity'], authorization[0]['reservationRow']
 try:rows, digest = resources._inventory(root)
 except Exception:raise Refused('inventory_changed') from None
 row = _classify(rows, expected, identity, _now_ms())
 _need_stop(row != 'foreign', 'reservation_foreign')
 _need_stop(row != 'absent' and _row_matches(row, _row_binding(_own(rows, expected)), bound), 'reservation_row_changed')
 _need(ctx['deadline'] - ctx['clock']() >= _RELEASE_SECONDS, 'budget_insufficient');_guard(proof);_fresh(proof)
 window = ctx['clock']() + _RECEIPT_SECONDS
 booking = {**copy.deepcopy(request), 'expectedInventorySha256': digest, 'observations': [resources._receipt(identity, 'complete')]}
 try:result = environments.reserve_environment(root, booking)
 except environments.NativeEnvironmentError as error:
  # The CAS digest refusal happens before any write: a positive no-effect.
  if str(error) == 'reservation inventory changed during host observation':raise Refused('inventory_changed') from None
  raise _Unknown('reserve_result_unexpected') from None
 except Exception:raise _Unknown('reserve_result_unexpected') from None
 _need_unknown(result == {'ok': True, 'state': 'reserved', 'idempotent': True, 'identity': identity, 'reservation': {'memoryBytes': expected.memory, 'allocationState': 'pending'},
  'nativeActionAllowed': False}, 'reserve_result_unexpected')
 try:_guard(proof, window);_fresh(proof)
 except Refused as refusal:raise _Unknown(refusal.reason) from None
 releasing = _write(journal, RELEASING, _releasing(expected, local, authorization))
 try:result = environments.release_environment(root, identity)
 except Exception:raise _Unknown('release_unknown') from None
 _need_unknown(result == {'ok': True, 'state': 'released', 'identity': identity, 'nativeActionAllowed': False}, 'release_unknown')
 return releasing


def _proof(root, inputs, *, expected=None, runner=None, privileged=None, boundaries=None, clock=time.monotonic):
 """Read-only: mint P/N before closure, or authenticate history after it."""
 _inputs(inputs, 'proof');ctx = _context(root, inputs, expected, runner, privileged, boundaries, clock)
 with private.Directory(attempts.journal_directory(ctx['root'])) as directory:local = _local(ctx, directory)
 if local['chain'][LINK] is not None:
  value = _observe(ctx, local, 'history')[0]
  return _result('closed-history', closure=_summary(local), terminal=value['facts']['terminal'], nextAttempt={'attempt': 2, 'operationId': local['linked'][0]})
 state = _state(_mint(ctx, local))
 return _result('proven', proofSha256=state['P'], factsSha256=state['N'], closure=_summary(local, state['N']),
  actors={'denied': len(state['processes']['denied']), 'zombies': len(state['processes']['zombies']), 'rootCensus': state['processes']['root'] is not None})


def _history(root, inputs, *, expected=None, runner=None, privileged=None, boundaries=None, clock=time.monotonic):
 """Read-only original 7e8 terminal history (ruling R6).

 History-scoped facts only: no actor scan, no namespace, storage or inventory
 lock, never a VM, ledger or libvirt read, and no privileged census. The only
 writes are this module's own local observation receipts.
 """
 _inputs(inputs, 'history');ctx = _context(root, inputs, expected, runner, privileged, boundaries, clock)
 with private.Directory(attempts.journal_directory(ctx['root'])) as directory:local = _local(ctx, directory, history=True)
 facts = _observe(ctx, local, 'history')[0]['facts']
 return _result('history', operationId=ctx['expected'].op, terminal=facts['terminal'], namespace=facts['namespace']['names'], closure=_summary(local))


def _next(error):
 return {'nextAction': error.action, **({'authorizationSha256': error.authorization} if error.authorization else {})}


def _finite(function, *args, **kwargs):
 try:return function(*args, **kwargs)
 except _Unknown as error:return _result('unknown', error.reason, **_next(error))
 except Refused as error:return _result('refused', error.reason, **(_next(error) if error.authorization else {}))
 except Exception:return _result('unknown', 'observation_unknown', nextAction='read-only proof before any further close')


def run_direct(root, action, inputs):
 """Direct TEST-002 entry: fixed production identity, admitted SSH transport only."""
 actions = {'proof': _proof, 'close': _close, 'history': _history}
 return _finite(actions[action], root, inputs) if action in actions else _result('refused', 'inputs_invalid')


def next_attempt(root):
 """Validated attempt-2 custody (opaque) from the durable link chain only."""
 return attempts.current(root)
