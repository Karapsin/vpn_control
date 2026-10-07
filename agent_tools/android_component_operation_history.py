"""Pure validation of bounded current Android operation history (CLI-005).

Completed entries may expire after 30 minutes or capacity eviction. A historical
terminal receipt remains evidence even when its row is absent from current lists.
This validator grants no native, lease, replay, or installer authority.
"""
import hashlib
import json
import re

CAPACITY=256
MAX_SNAPSHOTS=8
_LONG_MAX=2**63-1
_KEYS=frozenset(('controllerId','id','requestId','operation','phase','final','cancellable',
                 'completedUnits','totalUnits','code','configurationRevision','restartRequired'))
_UUID=re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}')
_OPERATIONS=frozenset(('on', 'off', 'status', 'restart', 'find-best', 'source.show', 'source.set', 'subscriptions.list', 'subscriptions.show', 'subscriptions.add', 'subscriptions.update', 'subscriptions.delete', 'subscriptions.refresh', 'locations.list', 'locations.show', 'locations.add', 'locations.update', 'locations.delete', 'locations.select', 'locations.benchmark', 'locations.import', 'locations.export', 'routing.show', 'routing.set', 'routing.import', 'routing.export', 'routing.apps.list', 'routing.apps.set', 'routing.apps.add', 'routing.apps.remove', 'routing.apps.select-all', 'routing.apps.clear', 'settings.show', 'settings.set', 'settings.apply', 'settings.languages', 'ssh.key.status', 'ssh.key.import', 'stats', 'logs', 'diagnostics.export', 'operations.list', 'operations.status', 'operations.wait', 'operations.cancel', 'updates.status', 'updates.check', 'updates.transport-probe', 'updates.download', 'updates.install', 'updates.cancel', 'updates.dismiss', 'serve', 'gui.show', 'gui.hide', 'quit', 'capabilities'))
_FAILURE_CODES=frozenset(('INVALID_ARGUMENT','NOT_FOUND','AMBIGUOUS_LOCATION','READ_ONLY_SOURCE',
    'BUSY','CONFLICT','UNSUPPORTED','INTERACTION_REQUIRED','PERMISSION_DENIED','PERSISTENCE_FAILED','RUNTIME_FAILED'))


def _raw(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode('utf-8')


def _uuid(value):return type(value)is str and _UUID.fullmatch(value)is not None


def _row(value,owner,revision):
    if (type(value)is not dict or set(value)!=_KEYS or type(value['controllerId'])is not str or value['controllerId']!=owner or
        not _uuid(value['id']) or not _uuid(value['requestId']) or type(value['operation'])is not str or
        value['operation'] not in _OPERATIONS or value['final']is not True or value['cancellable']is not False or
        type(value['configurationRevision'])is not int or not 0<=value['configurationRevision']<=revision or
        type(value['restartRequired'])is not bool):
        raise ValueError('component_history_row_unknown')
    phase=value['phase'];code=value['code']
    if (type(phase)is not str or type(code)is not str or
        not ((phase=='succeeded' and code=='OK') or (phase=='cancelled' and code=='CANCELLED') or
             (phase=='failed' and code in _FAILURE_CODES))):
        raise ValueError('component_history_terminal_unknown')
    for key in ('completedUnits','totalUnits'):
        if value[key]is not None and (type(value[key])is not int or not 0<=value[key]<=_LONG_MAX):
            raise ValueError('component_history_progress_unknown')
    if value['completedUnits']is not None and value['totalUnits']is not None and value['completedUnits']>value['totalUnits']:
        raise ValueError('component_history_progress_unknown')


def validate(snapshots,*,owner,revision,historical_operation):
    """Require repeated equal current lists, independently retain one old receipt.

    Inputs are parsed public operations lists. The caller must first authenticate
    each enclosing CLI response, owner/revision, stream bytes and current device.
    List order is retained in the digest and equality check; expiry during this
    frame is unknown and requires a fresh admission. Missing history is not replay.
    """
    if (not _uuid(owner) or type(revision)is not int or not 0<=revision<=_LONG_MAX or type(snapshots)is not list or
        not 2<=len(snapshots)<=MAX_SNAPSHOTS):raise ValueError('component_history_repeated_lists_required')
    _row(historical_operation,owner,revision)
    historical_raw=_raw(historical_operation);first=None;count=None;present=False
    for entries in snapshots:
        if type(entries)is not list or len(entries)>CAPACITY:raise ValueError('component_history_bounded_list_required')
        ids=set();requests=set()
        for entry in entries:
            _row(entry,owner,revision)
            if entry['id']in ids or entry['requestId']in requests:raise ValueError('component_history_duplicate_identity')
            ids.add(entry['id']);requests.add(entry['requestId'])
            if entry['id']==historical_operation['id'] and _raw(entry)!=historical_raw:
                raise ValueError('component_history_historical_changed')
        current=_raw(entries)
        if first is None:first=current;count=len(entries);present=historical_operation['id']in ids
        elif current!=first:raise ValueError('component_history_current_changed')
    return {'currentLedgerSha256':hashlib.sha256(first).hexdigest(),'currentLedgerCount':count,
            'currentLedgerSnapshots':len(snapshots),'historicalOperationId':historical_operation['id'],
            'historicalOperationSha256':hashlib.sha256(historical_raw).hexdigest(),
            'historicalOperationPresent':present,'replayAllowed':False}
