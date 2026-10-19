"""One complete actor-collector oracle with the existing declared metadata peers.

Sources are copied byte-for-byte into an owned temporary repository layout.
Only inert /proc and file metadata is observed by the unchanged qualifier.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid

HERE = Path(__file__).parent
BEFORE_SHA = '81f3957f0985c49bb7d9752e63008e0a31c6bdb7be49e4eef29f10b4dbe9be20'
CURRENT_SHA = 'c8365ace8f9162837b4b6f393a90597a59fbfe1bf2728aaeda14ddabb9714a99'
QUALIFIER_SHA = 'bbda64bc87935e65e97835a04a873c3e835f7a5212af85643f4b0e3e28b66dc9'


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _put(path, raw):
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, 'wb', closefd=False) as stream:
            stream.write(raw)
    finally:
        os.close(fd)


def _positive_entry(qualifier_path, source_path, destination):
    """Use exactly the same success oracle for whole before/current bytes."""
    if _sha(qualifier_path.read_bytes()) != QUALIFIER_SHA:
        raise ValueError('namespace_complete_qualifier_pin')
    name = '_native_packet_namespace_qualifier_' + uuid.uuid4().hex
    spec = importlib.util.spec_from_file_location(name, qualifier_path)
    qualifier = importlib.util.module_from_spec(spec)
    sys.modules[name] = qualifier
    spec.loader.exec_module(qualifier)
    assert sys.modules.get(name) is qualifier
    raw = source_path.read_bytes()
    cases = [qualifier.qualify_source(raw, destination, 'positive-observed-timestamps',
        expected_state='qualified', fault='namespace-timestamp')]
    # These are the existing focused status-owner guard oracles. PID is a
    # returned DTO guard control; it is explicitly not native PID evidence.
    controls = {
        'pid-guard-dto': 'collector_actor_closing_changed',
        'start-changed': 'collector_actor_closing_changed',
        'executable-generation': 'collector_actor_closing_changed',
        'namespace-generation': 'collector_actor_closing_changed',
        'namespace-mode': 'collector_actor_closing_changed',
        'fd-generation': 'collector_actor_original_fd_identity',
        'socket-generation': 'collector_actor_closing_changed',
        'process-root-timestamp': 'collector_actor_closing_changed',
    }
    for fault, reason in controls.items():
        cases.append(qualifier.qualify_source(raw, destination, 'refuse-' + fault,
            expected_state='refused', expected_error=reason, fault=fault))
    result = {'schemaVersion': 1, 'samePositiveOracle': True,
        'caseCount': len(cases), 'structuralRefusalCount': len(controls),
        'rawNamespaceTimestampDifferenceCount': len(qualifier.RAW_DIFF),
        'completeNormallyRegisteredQualifier': True,
        'sourceSha256': _sha(raw), 'cases': cases,
        'nativeOrNetworkActions': False,
        'pidNegativeIsReturnedDtoGuardOnly': True,
        'historicalRpcOutcome': 'UNKNOWN', 'replayAllowed': False}
    print(json.dumps(result, sort_keys=True))


def _retained_refusal_entry(qualifier_path, source_path, destination):
    """An identical retained-observation oracle for whole before/current bytes."""
    if _sha(qualifier_path.read_bytes()) != QUALIFIER_SHA:
        raise ValueError('namespace_complete_qualifier_pin')
    name = '_native_packet_refusal_qualifier_' + uuid.uuid4().hex
    spec = importlib.util.spec_from_file_location(name, qualifier_path)
    qualifier = importlib.util.module_from_spec(spec)
    sys.modules[name] = qualifier
    spec.loader.exec_module(qualifier)
    assert sys.modules.get(name) is qualifier
    raw = source_path.read_bytes()
    case = qualifier.qualify_source(raw, destination, 'retained-socket-refusal',
        expected_state='refused', expected_error='collector_actor_closing_changed',
        fault='socket-generation')
    receipt_path = destination / 'retained-socket-refusal/receipt.json'
    receipt = json.loads(receipt_path.read_bytes())
    result = receipt['result']
    assert type(result.get('actorOpening')) is dict, 'refusal must retain actorOpening'
    assert type(result.get('actorClosing')) is dict, 'refusal must retain actorClosing'
    assert result['actorOpening']['pid'] == result['actorClosing']['pid']
    assert result['actorOpening']['startTicks'] == result['actorClosing']['startTicks']
    assert result['actorOpening']['socketFds'] != result['actorClosing']['socketFds']
    assert type(result.get('actorStableProjectionDiff')) is list and result['actorStableProjectionDiff'], 'refusal must retain raw projection diagnostics'
    assert type(result.get('actorIdentityProjectionDiff')) is list and result['actorIdentityProjectionDiff'], 'refusal must retain identity projection diagnostics'
    expected = ['socketFds', 0, 'targetGeneration', 1]
    assert expected in result['actorStableProjectionDiff']
    assert result['actorIdentityProjectionDiff'] == [expected]
    assert receipt['sourceSha256'] == _sha(raw) and receipt['sourceUnmodified'] is True
    assert receipt['partialNamespaceExecution'] is False and receipt['postExecFunctionReplacement'] is False
    assert receipt['allUncontrolledNodesAndLinksUnchanged'] and receipt['allOwnReadonlyDescriptorsClosed']
    print(json.dumps({'schemaVersion': 1, 'sameRetainedRefusalOracle': True,
        'case': case, 'sourceSha256': _sha(raw),
        'refusalReceiptPath': str(receipt_path),
        'refusalReceiptSha256': _sha(receipt_path.read_bytes()),
        'actorOpeningAndClosingRetained': True,
        'rawProjectionDifferenceCount': len(result['actorStableProjectionDiff']),
        'identityProjectionDifferenceCount': len(result['actorIdentityProjectionDiff']),
        'nativeOrNetworkActions': False}, sort_keys=True))


def _one(raw, directory, metadata, mode='positive'):
    directory.mkdir(mode=0o700)
    root = directory / 'repo'
    root.mkdir(mode=0o700)
    staged = {}
    for row in metadata['sources']:
        relative = Path(row['stagePath'])
        if relative.is_absolute() or '..' in relative.parts:
            raise ValueError('namespace_fixture_stage_path')
        source = (HERE / row['fixture']).read_bytes()
        if len(source) != row['bytes'] or _sha(source) != row['sha256']:
            raise ValueError('namespace_fixture_source_pin')
        target = root / relative
        _put(target, source)
        staged[target] = source
    source_path = directory / 'collector.source.py'
    _put(source_path, raw)
    staged[source_path] = raw
    qualifier_path = root / metadata['qualifierStagePath']
    process = subprocess.run([sys.executable, '-B', str(Path(__file__).resolve()),
        '--positive-entry' if mode == 'positive' else '--retained-refusal-entry', str(qualifier_path), str(source_path), str(directory / 'cases')],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=30, check=False, cwd=root)
    result = json.loads(process.stdout) if process.returncode == 0 else None
    unchanged = all(path.read_bytes() == source for path, source in staged.items())
    receipt = {'sourceSha256': _sha(raw), 'exitCode': process.returncode,
        'stdout': process.stdout.decode('utf-8'), 'stderr': process.stderr.decode('utf-8'),
        'result': result, 'sourcesUnchanged': unchanged,
        'normallyRegisteredCompleteQualifier': True,
        'noSourceOrFunctionReplacement': True, 'nativeOrNetworkActions': False,
        'wholeQualifierSha256': _sha(qualifier_path.read_bytes()),
        'ownedIsolatedLayout': True, 'allHostMetadataPeersInert': True}
    (directory / 'process-receipt.json').write_text(json.dumps(receipt, sort_keys=True, indent=2) + '\n')
    return receipt


def run_namespace_pair(before, current, directory):
    if _sha(before) != BEFORE_SHA or _sha(current) != CURRENT_SHA:
        raise ValueError('namespace_whole_collector_pin')
    metadata = json.loads((HERE / 'provenance.json').read_bytes())
    directory = Path(directory).resolve()
    return {'before': _one(before, directory / 'before', metadata),
        'after': _one(current, directory / 'after', metadata)}


def run_retained_refusal_pair(before, current, directory):
    if _sha(before) != BEFORE_SHA or _sha(current) != CURRENT_SHA:
        raise ValueError('namespace_whole_collector_pin')
    metadata = json.loads((HERE / 'provenance.json').read_bytes())
    directory = Path(directory).resolve()
    return {'before': _one(before, directory / 'before', metadata, 'retained-refusal'),
        'after': _one(current, directory / 'after', metadata, 'retained-refusal')}


if __name__ == '__main__':
    if len(sys.argv) != 5 or sys.argv[1] not in ('--positive-entry', '--retained-refusal-entry'):
        raise ValueError('namespace_boundary_entry_arguments')
    entry = _positive_entry if sys.argv[1] == '--positive-entry' else _retained_refusal_entry
    entry(Path(sys.argv[2]), Path(sys.argv[3]), Path(sys.argv[4]))
