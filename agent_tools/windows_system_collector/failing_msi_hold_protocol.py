"""Pure, closed records for the finite ordinary-caller/SYSTEM close barrier."""
from __future__ import annotations

import hashlib
import json
from pathlib import PureWindowsPath
import re
import uuid

EMPTY_SHA256 = hashlib.sha256(b'').hexdigest()
RECEIPTS_SHA = '5e2e406b82d4a446ab971f27918b3b0f110e67e3eb8cae971b0bfe4256aa71ec'
COLLECTORS = {
    'update': '7c23f177a701b7e553cccc1fc4ec9de1fadde8991e451050e64e94539da36a8b',
    'tun': 'e8510e0d2fe42a73e7c8a1c5550a18c6292293681fb10472abf2a668f3721135',
}
INPUT_FIELDS = frozenset(('schemaVersion', 'collectorOperationId', 'collectorRoot', 'scope', 'stage',
    'sourceSha', 'systemContractSourceSha256', 'systemWorkerSourceSha256', 'collectorSourceSha256', 'receiptsPath'))
COMMON_FIELDS = frozenset(('schemaVersion', 'ordinaryTaskOperationId', 'collectorOperationId', 'sourceSha',
    'scope', 'stage', 'bootIdentifier', 'ordinaryWorker', 'callerSourcePin', 'collectorRequestSha256',
    'systemActor', 'collectorChild'))
READY_FIELDS = COMMON_FIELDS | {'kind', 'driverKnownResult', 'allOriginalChildrenTerminalAndEof'}
RELEASE_FIELDS = COMMON_FIELDS | {'kind', 'holdReadySha256', 'holdReadyNativeIdentity', 'closure'}
CLOSURE_FIELDS = frozenset(('systemExitCode', 'childExitCode', 'bothChildEof', 'sourceClosing',
    'qgaStdoutSha256', 'qgaStderrSha256', 'childStdoutSha256', 'childStderrSha256', 'systemSourceSha256'))
CLOSE_HOLD_FIELDS = frozenset(('schemaVersion', 'callerSourcePin', 'holdReadyPath', 'releasePath',
    'scope', 'stage', 'sourceSha'))


def require(value, reason):
    if not value:
        raise ValueError(reason)


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False) + '\n').encode('utf-8')


def decode(raw, maximum=8 * 1024 * 1024):
    require(type(raw) is bytes and 0 < len(raw) <= maximum, 'hold-record-byte-bound')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'hold-record-duplicate-field')
            result[key] = value
        return result
    value = json.loads(raw.decode('utf-8', 'strict'), object_pairs_hook=unique)
    require(type(value) is dict, 'hold-record-object')
    return value


def guid(value):
    require(type(value) is str and str(uuid.UUID(value)) == value and uuid.UUID(value).int != 0,
        'hold-canonical-guid')
    return value


def sha(value):
    require(type(value) is str and re.fullmatch('[a-f0-9]{64}', value), 'hold-sha256')
    return value


def path(value):
    require(type(value) is str and 0 < len(value) <= 1000 and not any(ord(c) < 32 for c in value),
        'hold-path-type')
    result = PureWindowsPath(value)
    require(re.fullmatch('[A-Za-z]:', result.drive) and result.root == '\\' and str(result) == value
        and all(p not in {'.', '..'} and ':' not in p and not p.endswith(('.', ' ')) for p in result.parts[1:]),
        'hold-canonical-drive-path')
    return result


def native_identity(value):
    fields = {'volumeSerial', 'fileIndex', 'attributes', 'sizeBytes', 'links', 'creationFileTime', 'lastWriteFileTime'}
    require(type(value) is dict and set(value) == fields, 'hold-native-file-identity')
    for key in fields - {'creationFileTime', 'lastWriteFileTime'}:
        require(type(value[key]) is int and value[key] >= 0, 'hold-native-file-integer')
    for key in ('creationFileTime', 'lastWriteFileTime'):
        require(type(value[key]) is str and re.fullmatch('[0-9]{1,19}', value[key]), 'hold-native-file-time')
    require(value['links'] == 1 and not value['attributes'] & 0x410, 'hold-native-file-type-or-link')
    return value


def source_pin(value):
    require(type(value) is dict and set(value) == {'path', 'nativeIdentity', 'security', 'sha256'},
        'hold-source-pin-schema')
    path(value['path']); native_identity(value['nativeIdentity']); sha(value['sha256'])
    security = value['security']
    require(type(security) is dict and set(security) == {'ownerSid', 'sddl'}
        and all(type(security[k]) is str and 0 < len(security[k]) <= 16384 for k in security),
        'hold-source-pin-security')
    return value


def _stage(scope, stage):
    require(scope in COLLECTORS and ((scope == 'update' and stage in {'terminal-actors', 'returned-cleanup'})
        or (scope == 'tun' and stage == 'off')), 'hold-finite-scope-stage')


def validate_inputs(value, *, ordinary_task_operation_id=None, program_data=None):
    require(type(value) is dict and set(value) == INPUT_FIELDS and type(value['schemaVersion']) is int
        and value['schemaVersion'] == 1, 'hold-closed-input-schema')
    operation = guid(value['collectorOperationId']); root = path(value['collectorRoot'])
    require(root.name == 'system-collector-' + operation and root.parent.name.startswith('VpnControlOrdinaryTask-'),
        'hold-fixed-system-root')
    guid(root.parent.name.removeprefix('VpnControlOrdinaryTask-'))
    require(root.parent.parent.name.casefold() == 'programdata', 'hold-programdata-root')
    if program_data is not None:
        require(root.parent.parent == path(program_data), 'hold-actual-programdata-root')
    if ordinary_task_operation_id is not None:
        guid(ordinary_task_operation_id)
    _stage(value['scope'], value['stage'])
    require(type(value['sourceSha']) is str and re.fullmatch('[a-f0-9]{40}', value['sourceSha']), 'hold-source-sha')
    for key in ('systemContractSourceSha256', 'systemWorkerSourceSha256', 'collectorSourceSha256'):
        sha(value[key])
    require(value['collectorSourceSha256'] == COLLECTORS[value['scope']], 'hold-fixed-collector-source')
    path(value['receiptsPath'])
    return value


def validate_close_hold(value, expected=None):
    require(type(value) is dict and set(value) == CLOSE_HOLD_FIELDS and type(value['schemaVersion']) is int
        and value['schemaVersion'] == 1, 'hold-close-contract-schema')
    source_pin(value['callerSourcePin']); path(value['holdReadyPath']); path(value['releasePath'])
    _stage(value['scope'], value['stage'])
    require(type(value['sourceSha']) is str and re.fullmatch('[a-f0-9]{40}', value['sourceSha']), 'hold-source-sha')
    if expected is not None:
        require(value == expected, 'hold-close-contract-join')
    return value


def _actor(value):
    require(type(value) is dict and set(value) == {'pid', 'birthFileTimeUtc'} and type(value['pid']) is int
        and 0 < value['pid'] < 2**32 and type(value['birthFileTimeUtc']) is str
        and re.fullmatch('[1-9][0-9]{16,19}', value['birthFileTimeUtc']), 'hold-native-actor-generation')


def _common(value):
    require(type(value['schemaVersion']) is int and value['schemaVersion'] == 1, 'hold-record-version')
    for key in ('ordinaryTaskOperationId', 'collectorOperationId', 'bootIdentifier'):
        guid(value[key])
    require(type(value['sourceSha']) is str and re.fullmatch('[a-f0-9]{40}', value['sourceSha']), 'hold-source-sha')
    _stage(value['scope'], value['stage']); source_pin(value['callerSourcePin']); sha(value['collectorRequestSha256'])
    worker = value['ordinaryWorker']
    require(type(worker) is dict and set(worker) == {'pid', 'birthFileTimeUtc', 'image', 'sha256', 'sid', 'sessionId'},
        'hold-ordinary-worker-schema')
    _actor({k: worker[k] for k in ('pid', 'birthFileTimeUtc')}); path(worker['image']); sha(worker['sha256'])
    require(type(worker['sid']) is str and re.fullmatch(r'S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+', worker['sid'])
        and type(worker['sessionId']) is int and worker['sessionId'] > 0, 'hold-ordinary-worker-context')
    _actor(value['systemActor']); _actor(value['collectorChild'])
    require(len({worker['pid'], value['systemActor']['pid'], value['collectorChild']['pid']}) == 3,
        'hold-distinct-original-actors')


def common_from_ready(ready):
    return {key: ready[key] for key in COMMON_FIELDS}


def validate_ready(value, expected=None):
    require(type(value) is dict and set(value) == READY_FIELDS and value.get('kind') == 'caller-collector-close-ready',
        'hold-ready-schema')
    _common(value)
    require(type(value['driverKnownResult']) is int and value['driverKnownResult'] == 0
        and value['allOriginalChildrenTerminalAndEof'] is True, 'hold-ready-known-driver-terminal')
    if expected is not None:
        require(value == expected, 'hold-ready-exact-current-record')
    return value


def validate_release(value, ready=None, ready_sha256=None, ready_native_identity=None):
    require(type(value) is dict and set(value) == RELEASE_FIELDS and value.get('kind') == 'collector-close-release',
        'hold-release-schema')
    _common(value); sha(value['holdReadySha256']); native_identity(value['holdReadyNativeIdentity'])
    closure = value['closure']
    require(type(closure) is dict and set(closure) == CLOSURE_FIELDS, 'hold-release-closure-schema')
    require(type(closure['systemExitCode']) is int and closure['systemExitCode'] == 0
        and type(closure['childExitCode']) is int and closure['childExitCode'] == 0
        and closure['bothChildEof'] is True and closure['sourceClosing'] is True, 'hold-release-known-original-closure')
    for key in CLOSURE_FIELDS - {'systemExitCode', 'childExitCode', 'bothChildEof', 'sourceClosing'}:
        sha(closure[key])
    require(closure['qgaStderrSha256'] == closure['childStderrSha256'] == EMPTY_SHA256,
        'hold-release-empty-original-stderr')
    if ready is not None:
        validate_ready(ready)
        require(common_from_ready(value) == common_from_ready(ready), 'hold-release-current-ready-joins')
    if ready_sha256 is not None:
        require(value['holdReadySha256'] == sha(ready_sha256), 'hold-release-ready-byte-join')
    if ready_native_identity is not None:
        require(value['holdReadyNativeIdentity'] == native_identity(ready_native_identity), 'hold-release-ready-generation-join')
    return value
