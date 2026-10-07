"""Whole retained public consumer, modeled raw history protocol, no native proof.

The exact 8c732 source is loaded inertly; neither prepared_only nor collect/main
is called. Fixed same-owner historical DTO and 158 synthetic read records model
TTL loss without authenticating any real saved operation, device or toolchain.
"""
import ast
import base64
import hashlib
import json
import os
import re
import stat
import types
from pathlib import Path
from .context import BASE
from agent_tools import android_component_operation_history

SOURCE_SHA = '8c732007d817bb84aec5fc2295340da431a3b761a6bbc36611bcdac9e39047c6'
PROVENANCE_SHA = '83634ca04662dd0877cf3b6ddfc8de7647a9902f3e615d096bbc1cc6dd264fb0'


def consumer():
    if hashlib.sha256((BASE/'baseline_caller.provenance.json').read_bytes()).hexdigest() != PROVENANCE_SHA:
        raise ValueError('fixture_provenance_changed')
    path = BASE/'baseline_caller.source'
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != SOURCE_SHA:
        raise ValueError('historical_source_binding_changed')
    # Source-only consumer extraction avoids executing the caller's global
    # sys.path mutation or importing native transport/actor providers.
    names = {'encoded', 'digest', 'archive', 'validate_proof'}
    constants = {'OWNER', 'OPERATION', 'PROOF_SHA', 'CHUNK'}
    tree = ast.parse(raw)
    nodes = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in names
             or isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id in constants for t in n.targets)]
    if len(nodes) != 8:
        raise ValueError('fixture_consumer_source_changed')
    module = types.ModuleType('agent_tools._synthetic_history_consumer')
    module.__file__ = str(path)
    module.__dict__.update(json=json, hashlib=hashlib, stat=stat, re=re, base64=base64,
                           operation_history=android_component_operation_history)
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(path), 'exec'), module.__dict__)
    for name in names:
        function = getattr(module, name)
        if function.__globals__ is not module.__dict__ or function.__code__.co_filename != str(path):
            raise ValueError('fixture_consumer_source_changed')
    return module


class Capture:
    """Portable TempFS durable storage seam; no authority/provider substitution."""
    def __init__(self, root):
        self.path = Path(root)
        self.pins = {}

    def create(self, name, raw):
        if not re.fullmatch('[A-Za-z0-9_.-]{1,150}', name) or type(raw) is not bytes or len(raw) > 1048576:
            raise ValueError('fixture_capture_invalid')
        path = self.path/name
        with path.open('xb') as opened:
            opened.write(raw)
            opened.flush()
            os.fsync(opened.fileno())
        info = path.stat()
        if path.read_bytes() != raw:
            raise ValueError('fixture_capture_changed')
        pin = {'sha256': hashlib.sha256(raw).hexdigest(), 'generation': [info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns]}
        self.pins[name] = pin
        return pin

    def verify(self):
        for name, pin in self.pins.items():
            info = (self.path/name).stat()
            generation = [info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns]
            if generation != pin['generation'] or hashlib.sha256((self.path/name).read_bytes()).hexdigest() != pin['sha256']:
                raise ValueError('fixture_capture_changed')


def proof(owner, rows):
    request = {'schema': 1, 'device': 'android-api29', 'owner': owner, 'revision': 0, 'syntheticProtocol': True}
    records = []
    for index in range(158):
        name = 'component-guard-current-admission.json' if index == 157 else 'component-guard-read-%05d.json'%index
        record = {'syntheticClosingObservation': index}
        if index < 4:
            words = ['status'] if index % 2 == 0 else ['operations', 'list']
            data = {'runtimeRunning': False, 'runtimeObservation': 'stopped'} if words == ['status'] else {'scope': 'android-provider-operations', 'operations': rows}
            reply = {'ok': True, 'final': True, 'code': 'OK', 'controllerId': owner, 'configurationRevision': 0, 'data': data}
            record = {'phase': 'baseline', 'words': words, 'returncode': 0, 'stderrRaw': '', 'stdoutRaw': json.dumps(reply)}
        content = json.dumps({'binding': request, 'phase': 'baseline-read-only', 'installerLeaseGranted': False, 'record': record}, sort_keys=True).encode()
        sha = hashlib.sha256(content).hexdigest()
        records.append({'name': name, 'bytes': len(content), 'sha256': sha, 'pin': {'sha256': sha}, 'rawBase64': base64.b64encode(content).decode()})
    return {'schema': 1, 'kind': 'api29-installer-component-baseline-proof', 'request': request, 'failure': None, 'failureDetail': None,
            'installedLauncherAccepted': False, 'bundledRuntimeAccepted': False, 'acceptanceComplete': False,
            'carrierInitialStdinPin': [1, 2, stat.S_IFIFO|0o600, 1000, 1000, 1, 0, 3, 4],
            'carrierSourceStdinPin': [1, 2, stat.S_IFIFO|0o600, 1000, 1000, 1, 0, 3, 4],
            'admittedFileLimit': [8388608, 8388608], 'originalFileLimit': [-1, -1], 'records': records,
            'baseline': {'state': 'component-installed-baseline-observed', 'phase': 'baseline-read-only', 'owner': owner, 'revision': 0,
                         **{k: False for k in ('installerLeaseGranted', 'guestMutationPerformed', 'installedLauncherAccepted', 'bundledRuntimeAccepted', 'acceptanceComplete', 'replayAllowed')}}}
