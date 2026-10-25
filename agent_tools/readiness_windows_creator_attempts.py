"""Read-only resolver for the reviewed linked attempt after creator 7e8b2dcd.

Original 7e8b2dcd consumed its resource claim and ended terminal before any VM
existed. Its source-owned closure writer appends authorization, release-attempt
(written immediately before the one release), released and generation-link
records to the ORIGINAL journal, then publishes attempt custody with the
unchanged registry retain under an explicit owned attempt root. This reader
never writes or takes the original lock. A partial, empty, malformed or
inconsistent chain refuses with a finite AttemptUnresolved; the original
registry custody is never adopted.
"""
import hashlib
import json
import os
from pathlib import Path
import weakref
from uuid import UUID, uuid5

from . import durable_remote_job as jobs
from . import private_inventory_lock as private
from . import readiness_windows_creator_registry as registry
from . import readiness_windows_managed_create as creator

OP = '7e8b2dcd-63c1-58fc-b382-f64695bacf11'
MACHINE = 'a3aec884-5e5c-47c6-b1c6-378d88045d72'
RID = '142e4db1bbd672d1be706c61f3269ce1770675c8398cc4f88ffb675831f94769'
HOST = 'archlinux'
SCOPE = hashlib.sha256(json.dumps([HOST, MACHINE], separators=(',', ':')).encode()).hexdigest()
AUTHORIZATION, RELEASED, LINK = 'release-authorized:creator-prevm', 'released', 'generation-link:2'
# Durable proof that THIS source attempted the one release (safety review F1).
RELEASE_SUBMITTING = 'release-submitting:creator-prevm'
CAUSE = 'creator_terminal_before_vm'
_ATTEMPTS = weakref.WeakKeyDictionary()


class AttemptUnresolved(ValueError):
 """Finite public reason; never carries record bodies or identities."""
 def __init__(self, reason):
  self.reason = reason
  super().__init__(reason)


def _need(value, reason='attempt_custody_unresolved'):
 if not value:
  raise AttemptUnresolved(reason)


def canonical(value):
 return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False)


def sha(raw):
 return hashlib.sha256(raw).hexdigest()


def _digest(value):
 return type(value) is str and len(value) == 64 and all(c in '0123456789abcdef' for c in value)


def derive(parent_rid, proof_sha):
 """Pure next identity: RID from parent RID + attempt 2 + proof SHA."""
 _need(_digest(parent_rid) and _digest(proof_sha), 'inputs_invalid')
 body = canonical({'attempt': 2, 'parentRecoveryId': parent_rid, 'proofSha256': proof_sha})
 rid = sha(b'windows-managed-creator-attempt-v1\n' + body.encode())
 return rid, str(uuid5(UUID(MACHINE), rid))


def record_name(key):
 return sha(key.encode()) + '.json'


def journal_directory(root):
 return Path(root) / '.rag_index' / 'readiness-resources' / OP


def attempts_parent(root):
 return Path(root) / '.rag_index' / 'windows-managed-creator-attempts' / SCOPE


def _pairs(rows):
 value = {}
 for key, item in rows:
  _need(key not in value, 'record_integrity')
  value[key] = item
 return value


def _read(directory, name):
 """Exact private bytes or None; an empty or unsafe final name refuses."""
 try:
  with private.Snapshot(directory, name) as snapshot:
   raw = snapshot.body
 except FileNotFoundError:
  return None
 except (OSError, ValueError):
  raise AttemptUnresolved('record_integrity') from None
 try:
  value = json.loads(raw, object_pairs_hook=_pairs)
 except (ValueError, UnicodeError):
  raise AttemptUnresolved('record_integrity') from None
 _need(type(value) is dict, 'record_integrity')
 return value, raw


def chain(root):
 """Lock-free original-journal chain: (A, S, R, L) as (value, sha256) or None.

 S (release-submitting) exists only after A, R only after S, L only after R.
 Every nested object is type-checked before use; anything malformed is the
 finite record_integrity, never a raw error.
 """
 try:
  with private.Directory(journal_directory(Path(root).resolve(strict=True))) as held:
   rows = {key: _read(held, record_name(key)) for key in (AUTHORIZATION, RELEASE_SUBMITTING, RELEASED, LINK)}
 except AttemptUnresolved:
  raise
 except (OSError, ValueError):
  raise AttemptUnresolved('record_integrity') from None
 a, s, r, link = (None if rows[k] is None else (rows[k][0], sha(rows[k][1])) for k in (AUTHORIZATION, RELEASE_SUBMITTING, RELEASED, LINK))
 try:
  _validate(a, s, r, link)
 except AttemptUnresolved:
  raise
 except (KeyError, TypeError, AttributeError, ValueError):
  raise AttemptUnresolved('record_integrity') from None
 return {'authorization': a, 'releaseSubmitting': s, 'released': r, 'link': link}


def _validate(a, s, r, link):
 objects = lambda value, *keys: all(type(value.get(key)) is dict for key in keys)
 _need(not (s and not a) and not (r and not s) and not (link and not r), 'record_integrity')
 if a:
  _need(a[0].get('kind') == 'windows-creator-prevm-release-authorization-v1' and a[0].get('operationId') == OP
   and a[0].get('cause') == CAUSE and a[0].get('cleanShutdownClaimed') is False
   and a[0].get('unsubmittedClaimed') is False and _digest(a[0].get('proofSha256')) and _digest(a[0].get('factsSha256'))
   and _digest(a[0].get('reservationIdentitySha256')), 'record_integrity')
 if s:
  _need(s[0].get('kind') == 'windows-creator-prevm-release-submitting-v1' and s[0].get('operationId') == OP and s[0].get('cause') == CAUSE
   and s[0].get('authorizationKey') == AUTHORIZATION and s[0].get('authorizationSha256') == a[1]
   and s[0].get('proofSha256') == a[0]['proofSha256'] and s[0].get('factsSha256') == a[0]['factsSha256']
   and s[0].get('reservationIdentitySha256') == a[0]['reservationIdentitySha256'] and s[0].get('replayAllowed') is False, 'record_integrity')
 if r:
  _need(r[0].get('state') == 'released' and r[0].get('cause') == CAUSE and r[0].get('authorizationKey') == AUTHORIZATION
   and r[0].get('authorizationSha256') == a[1] and r[0].get('proofSha256') == a[0]['proofSha256']
   and r[0].get('factsSha256') == a[0]['factsSha256'] and r[0].get('releaseSubmittingKey') == RELEASE_SUBMITTING
   and r[0].get('releaseSubmittingSha256') == s[1] and r[0].get('cleanShutdownClaimed') is False, 'record_integrity')
 if link:
  value = link[0]
  rid, op = derive(RID, a[0]['proofSha256'])
  _need(objects(value, 'closure', 'parent', 'next'), 'record_integrity')
  _need(value.get('kind') == 'windows-managed-creator-generation-link-v1' and value['closure'].get('authorizationSha256') == a[1]
   and value['closure'].get('releasedSha256') == r[1] and value['closure'].get('proofSha256') == a[0]['proofSha256']
   and value['parent'].get('operationId') == OP and value['parent'].get('recoveryId') == RID
   and _digest(value['parent'].get('registryRecordSha256'))
   and value['next'].get('attempt') == 2 and value['next'].get('recoveryId') == rid
   and value['next'].get('operationId') == op and _digest(value['next'].get('planSha256')) and value.get('replayAllowed') is False
   and value['next'].get('attemptRoot') == '.rag_index/windows-managed-creator-attempts/' + SCOPE + '/' + rid, 'record_integrity')


def _own_row_absent(root):
 """Lock-free: neither the exact original reservation nor any claim in its environment exists.

 A claim re-minted in recovery-<7e8> (for example through the proof-free generic
 route) is ownerless; the link it would hide never resolves.
 """
 with private.Directory(journal_directory(root)) as held:
  prepared = _read(held, record_name('prepared'))
 _need(prepared is not None, 'record_integrity')
 try:
  identity = prepared[0]['reservation']['identity']
  reservation, environment = identity['reservationId'], identity['environment']
 except (KeyError, TypeError):
  raise AttemptUnresolved('record_integrity') from None
 with private.Directory(root / '.rag_index' / 'native-environments') as held:
  value = _read(held, 'reservations.json')
 _need(value is not None and type(value[0].get('reservations')) is list, 'inventory_changed')
 return not any(type(row) is dict and (row.get('id') == reservation or row.get('environment') == environment) for row in value[0]['reservations'])


def _machine_journals(root):
 found = set()
 base = root / '.rag_index' / 'readiness-resources'
 names = os.listdir(base)
 _need(len(names) <= 4096, 'other_machine_journal_present')
 for name in names:
  with private.Directory(base / name) as held:
   prepared = _read(held, record_name('prepared'))
  _need(prepared is not None, 'other_machine_journal_present')
  if prepared[0].get('machineUuid') == MACHINE:
   found.add(name)
 return found


class AttemptCustody:
 """Opaque linked attempt-2 custody; not a DTO, never serialized."""
 __slots__ = ('__weakref__',)

 def __new__(cls, *args, **kwargs):
  raise TypeError('windows_creator_attempt_opaque')

 def __reduce__(self):
  raise TypeError('windows_creator_attempt_opaque')

 def __copy__(self):
  raise TypeError('windows_creator_attempt_opaque')

 def __deepcopy__(self, memo):
  raise TypeError('windows_creator_attempt_opaque')

 def _state(self):
  _need(type(self) is AttemptCustody and self in _ATTEMPTS)
  return _ATTEMPTS[self]

 def guard(self):
  root, link, handle, _ = self._state()
  _need(_resolve(root)[0] == link)
  try:
   return handle.guard()
  except (OSError, ValueError, KeyError, TypeError, AttributeError):
   raise AttemptUnresolved('attempt_custody_unresolved') from None

 def plan(self):
  return json.loads(canonical(self.guard()['plan']))

 def host_binding(self):
  return jobs.MachineBinding.from_dict(self.guard()['hostBinding'])

 def namespace(self):
  return json.loads(json.dumps(self.guard()['namespace']))

 def creator_handle(self):
  self.guard()
  return self._state()[2]

 @property
 def recovery_id(self):
  return self._state()[1]['next']['recoveryId']

 @property
 def operation_id(self):
  return self._state()[1]['next']['operationId']


def _resolve(root):
 """Every refusal is a finite AttemptUnresolved, including missing or unsafe custody paths."""
 try:
  return _resolved(root)
 except AttemptUnresolved:
  raise
 except (OSError, ValueError, KeyError, TypeError, AttributeError):
  raise AttemptUnresolved('attempt_custody_unresolved') from None


def _resolved(root):
 root = Path(root).resolve(strict=True)
 rows = chain(root)
 _need(rows['link'] is not None, 'attempt_custody_unresolved')
 link = rows['link'][0]
 rid, op = link['next']['recoveryId'], link['next']['operationId']
 _need(_own_row_absent(root), 'record_integrity')
 parent = attempts_parent(root)
 entries = os.listdir(parent)
 _need(rid in entries and all(name == rid or name.startswith('.staging-') for name in entries), 'attempt_custody_unresolved')
 with private.Directory(root / '.rag_index' / 'windows-managed-creators' / SCOPE) as held:
  retained = _read(held, 'creator-original.json')
 _need(retained is not None and sha(retained[1]) == link['parent']['registryRecordSha256'])
 original = registry.load(root, retained[0]['plan']['binding'])
 _need(original is not None)
 record = original.guard()
 _need(record == retained[0] and record['plan']['operationId'] == OP and record['plan']['recoveryId'] == RID)
 handle = registry.load(parent / rid, record['plan']['binding'])
 _need(handle is not None)
 current = handle.guard()
 _need(current['plan']['operationId'] == op and current['plan']['recoveryId'] == rid
  and sha(canonical(current['plan']).encode()) == link['next']['planSha256']
  and current['plan']['binding'] == record['plan']['binding']
  and current['namespace'] == record['namespace'] and current['hostBinding'] == record['hostBinding'])
 _need(_machine_journals(root) <= {OP, op}, 'other_machine_journal_present')
 return link, handle, current


def current(root):
 """Validated attempt-2 custody, or AttemptUnresolved. Never initializes anything."""
 link, handle, record = _resolve(root)
 result = object.__new__(AttemptCustody)
 try:
  _ATTEMPTS[result] = (Path(root).resolve(strict=True), link, handle, record)
 except OSError:
  raise AttemptUnresolved('attempt_custody_unresolved') from None
 return result


def creator_handle(root, binding):
 """Post-create resolver: unchanged registry.load unless 7e8 has a durable link.

 Behind the 7e8 link every refusal is a finite AttemptUnresolved.
 """
 handle = registry.load(root, binding)
 if handle is None or handle.guard()['plan']['operationId'] != OP:
  return handle
 if chain(root)['link'] is None:
  return handle
 return current(root).creator_handle()
