"""Read-only legacy GUI inventory; metadata never grants input authority.

Only a source-qualified custody may select the private enrollment. Public
transition transport receipts describe completed sends, not completed GUI
operations. Protected containers remain unresolved until their actual producer
and independent outcome protocols are curated. No credential or framebuffer is
opened, hashed, or returned here; secret-input directories are never entered.
"""
from __future__ import annotations

from contextlib import ExitStack
from copy import deepcopy
import hashlib
import os
from pathlib import Path
import re
import sys
from uuid import UUID

from . import private_inventory_lock as private
from . import readiness_tart_macos_registry as registry
from . import readiness_tart_macos_unlock_qualification as qualification

_EXECUTING_CODE = sys._getframe().f_code
_TOKEN = object()
# These are historical producer families, not VM selection defaults. Every
# directory is confined to the explicitly selected original RUN's custody.
_FAMILIES = (
    r'native-held-source-wake-[0-9a-f-]{36}',
    r'native-public-MacMeta-SuperL-selectall-failure-[0-9]{19}',
    r'native-public-MacMeta-selectall-failure-[0-9]{19}',
    r'native-public-existing-Alt-diagnostic-[0-9]{19}',
    r'native-public-uppercase-failure-[0-9]{19}',
    r'native-state-bound-wake-[0-9a-f-]{36}',
    r'prepared-bounded-Shift-incidents-[0-9a-f-]{36}',
    r'prepared-single-leftshift-[0-9a-f-]{36}',
    r'prepared-single-leftshift-executable-[0-9a-f-]{36}',
    r'protected-UsersGroups-admin-auth-[0-9a-f-]{36}',
    r'protected-agent-log-preparation-admin-auth-[0-9a-f-]{36}',
    r'protected-bootstrap-account-[0-9a-f-]{36}',
    r'protected-continuation-admin-auth-[0-9a-f-]{36}',
    r'protected-ordinary-first-login-[0-9a-f-]{36}',
    r'protected-pinned-bootstrap-admin-auth-[0-9a-f-]{36}',
    r'protected-standard-account-[0-9a-f-]{36}',
    r'protected-state-bound-unlock-[0-9a-f-]{36}',
    r'public-transitions',
)
_INTENT = re.compile(r'([0-9a-f-]{36})\.json')
_TRANSPORT = re.compile(r'([0-9a-f-]{36})-transport-closed\.json')


def _need(value, reason):
    if not value:
        raise qualification.QualificationBlocked(reason)


def _uuid(value):
    _need(type(value) is str, 'macos_legacy_original_invalid')
    try:
        _need(str(UUID(value)) == value, 'macos_legacy_original_invalid')
    except ValueError:
        raise qualification.QualificationBlocked('macos_legacy_original_invalid') from None
    return value


def _family(value):
    _need(type(value) is str and any(re.fullmatch(pattern, value) for pattern in _FAMILIES),
          'macos_legacy_family_unqualified')
    return value


def _metadata(directory):
    """Immediate no-follow metadata only, including opaque private entries."""
    directory.guard(); rows = []
    names = sorted(os.listdir(directory.fd))
    _need(len(names) <= 2048, 'macos_legacy_inventory_overflow')
    for name in names:
        _need(name not in {'.', '..'} and '/' not in name, 'macos_legacy_entry_invalid')
        info = os.stat(name, dir_fd=directory.fd, follow_symlinks=False)
        _need(info.st_uid == os.geteuid(), 'macos_legacy_entry_owner_changed')
        rows.append((name, private._generation(info)))
    _need(names == sorted(os.listdir(directory.fd)), 'macos_legacy_inventory_changed')
    directory.guard()
    return tuple(rows)


def _read_public(directory, name, stack, holders):
    # The caller derives only exact public intent/transport UUID names. This
    # helper cannot open arbitrary JSON, images, credentials or subdirectories.
    _need(_INTENT.fullmatch(name) or _TRANSPORT.fullmatch(name), 'macos_legacy_record_route_invalid')
    held = stack.enter_context(private.Snapshot(directory, name))
    holders.append(held)
    value = qualification._json(held.body)
    return value, held.pin()


def _public_rows(directory, original_run, actor, stack, holders):
    names = set(os.listdir(directory.fd)); originals, transports = {}, {}
    for name in names:
        original = _INTENT.fullmatch(name); transport = _TRANSPORT.fullmatch(name)
        _need(original or transport, 'macos_legacy_public_orphan')
        if original: originals[_uuid(original[1])] = name
        else: transports[_uuid(transport[1])] = name
    _need(set(transports) <= set(originals), 'macos_legacy_public_orphan')
    rows = []
    for operation, name in sorted(originals.items()):
        value, pin = _read_public(directory, name, stack, holders)
        _need(set(value) == {'operationId', 'originalRun', 'child', 'stage', 'state', 'commands'}
              and value['operationId'] == operation and value['originalRun'] == original_run
              and value['child'] == actor and value['state'] == 'unknown'
              and type(value['stage']) is str and re.fullmatch(r'[A-Za-z0-9_.-]{1,160}', value['stage'])
              and type(value['commands']) is list and 1 <= len(value['commands']) <= 256,
              'macos_legacy_public_original_changed')
        # Commands remain private public-source metadata and are not copied to
        # reports. Source/semantic qualification is deliberately still absent.
        row = {'family': 'public-transitions', 'operationId': operation, 'stage': value['stage'],
               'originalRun': original_run, 'actor': dict(actor), 'intentPin': pin,
               'transport': 'unclosed', 'outcome': 'unresolved',
               'blocker': 'original_transport_unclosed'}
        if operation in transports:
            closed, closed_pin = _read_public(directory, transports[operation], stack, holders)
            _need(set(closed) == {'operationId', 'originalRun', 'child', 'state'}
                  and closed['operationId'] == operation and closed['originalRun'] == original_run
                  and closed['child'] == actor
                  and closed['state'] == 'submitted_awaiting_independent_screen_observation',
                  'macos_legacy_transport_changed')
            row.update(transport='closed', transportPin=closed_pin,
                       blocker='independent_source_qualified_outcome_missing')
        rows.append(row)
    _need(names == set(os.listdir(directory.fd)), 'macos_legacy_inventory_changed')
    return rows


def _inspect_selected(directory, containers, original_run, actor, stack):
    """Internal diagnostic scanner. Its result is DATA, never a capability."""
    _uuid(original_run)
    _need(type(actor) is dict and set(actor) == {'pid', 'birth'} and type(actor['pid']) is int
          and actor['pid'] > 0 and type(actor['birth']) is str,
          'macos_legacy_actor_invalid')
    _need(type(containers) is list and 0 < len(containers) <= 64
          and all(type(name) is str for name in containers)
          and len(set(containers)) == len(containers), 'macos_legacy_selection_invalid')
    selected = {_family(name) for name in containers}
    # A new sibling in an already known historical GUI family cannot be hidden
    # by retaining an older selection manifest. No file body is read here.
    actual = {name for name in os.listdir(directory.fd)
              if any(re.fullmatch(pattern, name) for pattern in _FAMILIES)}
    _need(actual == selected, 'macos_legacy_family_inventory_changed')
    rows, listings, holders = [], [], []
    for name in sorted(selected):
        child = stack.enter_context(private.Directory(directory.path / name))
        entries = _metadata(child); listings.append((child, entries))
        if name == 'public-transitions':
            rows.extend(_public_rows(child, original_run, actor, stack, holders))
        else:
            rows.append({'family': name, 'originalRun': original_run, 'transport': 'unclassified',
                         'outcome': 'unresolved', 'blocker': 'legacy_producer_and_outcome_protocol_unqualified',
                         'entryCount': len(entries), 'privateBodiesRead': False})
    return {'schemaVersion': 1, 'originalRun': original_run, 'selectedContainerCount': len(selected),
            'sourceCoverage': 'selected_historical_families_only', 'rows': rows,
            'genericInputAuthority': False, 'idleAuthority': False}, listings, holders


class LegacyGuiInventory:
    """Held diagnostic inventory. No local resolved label mints authority."""
    def __init__(self, *args, **kwargs):
        raise qualification.QualificationBlocked('macos_legacy_inventory_factory_required')

    def guard(self):
        _need(getattr(self, '_token', None) is _TOKEN and not self._closed,
              'macos_legacy_inventory_closed')
        self._custody._operator.guard(); self._source.guard(); self._selection.guard(); self._root.guard()
        for directory, entries in self._listings:
            _need(_metadata(directory) == entries, 'macos_legacy_inventory_changed')
        for holder in self._holders: holder.guard()
        _need({name for name in os.listdir(self._root.fd)
               if any(re.fullmatch(pattern, name) for pattern in _FAMILIES)} == self._names,
              'macos_legacy_family_inventory_changed')

    @property
    def report(self):
        self.guard(); return deepcopy(self._report)

    def require_clear(self):
        self.guard()
        _need(not self._report['rows'], 'macos_legacy_originals_unresolved')
        # Empty metadata never establishes complete source coverage or an
        # independent outcome protocol. Curation is required before exposure.
        raise qualification.QualificationBlocked('macos_legacy_source_coverage_unqualified')

    def close(self):
        if not getattr(self, '_closed', True):
            self._closed = True; self._stack.close()

    def __enter__(self): return self
    def __exit__(self, *_): self.close()


def inspect(custody):
    """Selected private custody only; no public path, classification or flag.

    Enrollment is an immutable *selection*, not adoption or semantic closure.
    Future per-original resolution must authenticate a real native producer;
    this initial inventory deliberately supplies no such resolution authority.
    """
    _need(type(custody) is registry.MacCustody, 'macos_legacy_custody_required')
    custody._operator.guard()
    stack = ExitStack()
    try:
        path = Path(__file__); raw = path.read_bytes()
        _need(_EXECUTING_CODE == compile(raw, __file__, 'exec', dont_inherit=True,
              optimize=sys.flags.optimize), 'macos_legacy_source_changed')
        source = stack.enter_context(registry.PublicProof(path,
            {'generation': list(private._generation(path.lstat())), 'sha256': hashlib.sha256(raw).hexdigest()},
            private_file=False))
        directory = stack.enter_context(private.Directory(custody.lifecycle_root))
        selection = stack.enter_context(private.Snapshot(directory, 'legacy-gui-enrollment.json'))
        value = qualification._json(selection.body)
        _need(set(value) == {'schemaVersion', 'originalRun', 'containers'}
              and type(value['schemaVersion']) is int and value['schemaVersion'] == 1
              and value['originalRun'] == custody.run_intent['operationId'], 'macos_legacy_enrollment_changed')
        report, listings, holders = _inspect_selected(directory, value['containers'], value['originalRun'], custody.actor, stack)
        result = object.__new__(LegacyGuiInventory)
        result._token, result._closed, result._stack, result._custody = _TOKEN, False, stack, custody
        result._source, result._selection, result._root = source, selection, directory
        result._report, result._listings, result._names = report, listings, set(value['containers'])
        result._holders = holders
        result.guard(); return result
    except BaseException:
        stack.close(); raise
