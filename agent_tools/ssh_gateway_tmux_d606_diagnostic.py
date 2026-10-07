"""One fixed read-only observation of the original d606 gateway owner.

The original worker namespace is source pinned. No launch, release, signal,
ready-record write, inventory publication, or adoption is available here.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from uuid import uuid4

CORRELATION = 'd606e111-5cb6-4436-97c8-b0c38ad35ed8'
ORIGINAL_SOURCE_SHA256 = '0a78dcdeafa04e58dacaff5262851656e56b2fd6c7abbe62e821c553c3267c0e'
RECORDS = ('intent.json', 'anchor.json', 'release.intent.json', 'release.json',
           'ssh-launch.intent.json', 'child.json', 'ready.json', 'terminal.json',
           'owner.py', 'askpass.py', 'lock', 'stdout.private', 'stderr.private')
LIMIT = 65536
PHASES = ('original_source', 'packet', 'original_status', 'original_history', 'release_binding',
          'child_launch_binding', 'original_child_birth', 'original_tmux_owners', 'original_master_socket',
          'fixed_control_check', 'closing_original_proofs', 'complete')
METHODS = ('complete', 'original_history', 'original_profile', 'fixed_readonly_query',
           'process_identity', 'original_tmux_owners', 'master_socket', 'capture_record', 'status_validation')
KINDS = ('empty', 'authentication_denied', 'host_key_denied', 'connection_timeout',
         'name_lookup_failed', 'identity_permissions', 'unclassified_private_output')

REASONS = ('absent_file_appeared', 'action', 'anchor_binding', 'askpass_changed', 'availability_input', 'boot', 'child_binding', 'child_identity', 'child_parent_changed', 'config_path', 'configured_absence_path', 'configured_absence_schema', 'configured_parent_changed', 'consumed_or_foreign', 'consumed_or_foreign_master', 'correlation', 'create_changed', 'credential', 'credential_changed', 'diagnostic_authority', 'diagnostic_reply', 'directory_changed', 'directory_owner', 'directory_path', 'directory_private', 'duplicate_field', 'effective_config', 'effective_endpoint', 'effective_path', 'external_anchor', 'file_bound', 'file_bytes_changed', 'file_changed', 'file_owner', 'file_private', 'file_read', 'filename', 'filesystem_or_process_unknown', 'fixed_original_packet', 'foreign_master_socket', 'foreign_session', 'foreign_socket', 'home', 'hostkey_alias', 'input_bound', 'intent_binding', 'known_hosts_paths', 'known_hosts_unavailable', 'master_changed', 'master_parent_changed', 'master_path', 'master_path_binding', 'master_socket', 'master_unknown', 'missing_record_or_input', 'none', 'observation_unknown', 'observed_reply', 'original_anchor', 'original_owner_changed', 'original_source_changed', 'packet', 'pane_changed', 'permission_denied', 'pid', 'presence_binding', 'process_birth', 'process_bound', 'process_changed', 'process_dead', 'process_owner', 'process_schema', 'profile', 'profile_changed', 'proof_binding', 'query_bound_or_timeout', 'readonly_query_timeout', 'ready_binding', 'ready_record_missing', 'record', 'record_pin', 'record_schema', 'release_binding', 'release_consumed', 'request', 'socket_path', 'socket_schema', 'source_hash', 'submit_unknown', 'terminal_binding', 'terminal_present', 'terminal_record_missing', 'tmux_owner_changed', 'tmux_socket_changed', 'transport_unknown', 'unknown_reply', 'unsupported_config_directive', 'validation_unknown', 'worker_job', 'worker_source', 'write_failed')


def _need(condition, reason):
    if not condition: raise ValueError(reason)


def _canonical(value): return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
def _sha(raw): return hashlib.sha256(raw).hexdigest()


def _parent(pid):
    _need(type(pid) is int and pid > 0, 'child_identity')
    fd = os.open(f'/proc/{pid}/stat', os.O_RDONLY | os.O_NOFOLLOW)
    try: raw = os.read(fd, 4097)
    finally: os.close(fd)
    _need(len(raw) <= 4096, 'process_bound')
    fields = raw[raw.rfind(b')') + 2:].split()
    _need(len(fields) >= 20 and fields[0] not in (b'Z', b'X'), 'process_dead')
    return int(fields[1])


def _stderr_kind(raw):
    # Only this finite classification can leave the private raw-stream boundary.
    if not raw: return 'empty'
    for marker, kind in ((b'Permission denied', 'authentication_denied'),
                         (b'Host key verification failed', 'host_key_denied'),
                         (b'Connection timed out', 'connection_timeout'),
                         (b'Could not resolve hostname', 'name_lookup_failed'),
                         (b'UNPROTECTED PRIVATE KEY FILE', 'identity_permissions')):
        if marker in raw: return kind
    return 'unclassified_private_output'


def _reason(exc):
    if isinstance(exc, FileNotFoundError):
        name = Path(exc.filename).name if type(exc.filename) is str else ''
        if name == 'ready.json': return 'ready_record_missing'
        if name == 'terminal.json': return 'terminal_record_missing'
        return 'missing_record_or_input'
    if isinstance(exc, PermissionError): return 'permission_denied'
    if isinstance(exc, subprocess.TimeoutExpired): return 'readonly_query_timeout'
    if isinstance(exc, OSError): return 'filesystem_or_process_unknown'
    # Values from the exact original need() calls are fixed identifiers. Never
    # forward arbitrary exception text, private paths, configuration, or logs.
    text = str(exc)
    return text if text in REASONS else 'validation_unknown'


def _method(exc):
    allowed = {'open_history': 'original_history', 'profile': 'original_profile',
               'bounded': 'fixed_readonly_query', 'proc': 'process_identity',
               'owners': 'original_tmux_owners', 'socket_pin': 'master_socket',
               '__init__': 'capture_record', 'status': 'status_validation'}
    result = 'status_validation'; trace = exc.__traceback__
    while trace is not None:
        result = allowed.get(trace.tb_frame.f_code.co_name, result)
        trace = trace.tb_next
    return result


def _validate_response(response, packet, anchor_pin):
    _need(type(response) is dict and set(response) == {'public', 'proof'}, 'diagnostic_reply')
    public, proof = response['public'], response['proof']
    _need(type(public) is dict and type(proof) is dict, 'diagnostic_reply')
    base = {'state', 'phase', 'reason', 'replayAllowed', 'readyPublicationAllowed', 'adoptionAllowed'}
    _need(public.get('phase') in PHASES and public.get('replayAllowed') is False
          and public.get('readyPublicationAllowed') is False and public.get('adoptionAllowed') is False,
          'diagnostic_authority')
    if public.get('state') == 'unknown':
        _need(set(public) == base and proof == {} and public['reason'] in REASONS, 'unknown_reply')
        return
    _need(public.get('state') == 'observed' and set(public) == base | {'originalStatus', 'originalStatusReason',
          'originalStatusMethod', 'clientState', 'readyRecordPresent', 'terminalRecordPresent', 'stderrClassification'}
          and public['phase'] == 'complete' and public['reason'] in ('late_ready_original_child', 'original_child_ready')
          and public['originalStatus'] in ('unknown', 'ready') and public['originalStatusMethod'] in METHODS
          and public['originalStatusReason'] in REASONS
          and public['clientState'] == 'alive_original_child' and type(public['readyRecordPresent']) is bool
          and type(public['terminalRecordPresent']) is bool and public['stderrClassification'] in KINDS, 'observed_reply')
    _need(set(proof) == {'version', 'correlationId', 'originalSourceSha256', 'packetSha256', 'externalAnchorPin',
          'records', 'childProcess', 'paneProcess', 'serverProcess', 'bootId', 'socketGeneration',
          'parentMatchesOriginalPane', 'fixedControlReady', 'controlArgvSha256', 'public'}
          and type(proof['version']) is int and proof['version'] == 1 and proof['correlationId'] == CORRELATION
          and proof['originalSourceSha256'] == ORIGINAL_SOURCE_SHA256 and proof['packetSha256'] == _sha(_canonical(packet))
          and _canonical(proof['externalAnchorPin']) == _canonical(anchor_pin)
          and proof['parentMatchesOriginalPane'] is True and proof['fixedControlReady'] is True
          and _canonical(proof['public']) == _canonical(public), 'proof_binding')
    _need(type(proof['records']) is dict and set(proof['records']) == set(RECORDS), 'record_schema')
    for item in proof['records'].values():
        _need(type(item) is dict and type(item.get('present')) is bool, 'record_schema')
        if item['present']:
            _need(set(item) == {'present', 'size', 'pin'} and type(item['size']) is int and item['size'] >= 0, 'record_schema')
            pin = item['pin']
            _need(type(pin) is dict and set(pin) == {'generation', 'sha256'} and type(pin['generation']) is list
                  and len(pin['generation']) == 9 and all(type(value) is int and value >= 0 for value in pin['generation'])
                  and pin['generation'][6] == item['size'] and re.fullmatch('[0-9a-f]{64}', pin['sha256']), 'record_pin')
        else: _need(set(item) == {'present'}, 'record_schema')
    for key in ('childProcess', 'paneProcess', 'serverProcess'):
        value = proof[key]
        _need(type(value) is dict and set(value) == {'pid', 'startTicks'}
              and all(type(item) is int and item > 0 for item in value.values()), 'process_schema')
    _need(type(proof['socketGeneration']) is list and len(proof['socketGeneration']) == 9
          and all(type(item) is int and item >= 0 for item in proof['socketGeneration']), 'socket_schema')
    _need(public['readyRecordPresent'] == proof['records']['ready.json']['present']
          and public['terminalRecordPresent'] == proof['records']['terminal.json']['present'], 'presence_binding')
    _need(re.fullmatch('[0-9a-f]{64}', proof['controlArgvSha256'])
          and re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', proof['bootId'])
          and not public['terminalRecordPresent']
          and (public['reason'] == 'late_ready_original_child') == (not public['readyRecordPresent']), 'ready_binding')


def _remote(packet, anchor_pin):
    """Gateway entry: only the source-pinned original namespace can supply reads."""
    phase = 'original_source'
    public = {'state': 'unknown', 'phase': phase, 'reason': 'observation_unknown',
              'replayAllowed': False, 'readyPublicationAllowed': False, 'adoptionAllowed': False}
    proof = {}
    try:
        source = globals()['_ORIGIN_SOURCE']
        _need(_sha(source) == ORIGINAL_SOURCE_SHA256, 'original_source_changed')
        ns = {'__name__': 'gateway_original_readonly', '__file__': 'original-held-worker', '_STAGED_SOURCE': source}
        exec(compile(source, 'original-held-worker', 'exec'), ns)
        phase = 'packet'
        raw = ns['packet'](packet)
        _need(raw['correlationId'] == CORRELATION and raw['workerSha256'] == ORIGINAL_SOURCE_SHA256, 'fixed_original_packet')
        phase = 'original_history'
        with ns['Authority']() as authority:
            job, directory, stored, anchor = ns['open_history'](authority, raw, anchor_pin, readonly=True)
            records, metadata = {}, {}
            for name in RECORDS:
                path = job / name
                if os.path.lexists(path):
                    maximum = ns['LIMIT'] if name in ('stdout.private', 'stderr.private') else ns['MAX']
                    item = authority.capture(path, maximum=maximum, private=name != 'askpass.py')
                    records[name] = item
                    metadata[name] = {'present': True, 'size': len(item.body), 'pin': item.pin}
                else:
                    authority.absence(path); metadata[name] = {'present': False}
            phase = 'original_status'
            try:
                original = ns['status'](raw, anchor_pin)
                original_state, original_reason, original_method = original['state'], 'none', 'complete'
            except (OSError, ValueError, TypeError, KeyError, IndexError, subprocess.SubprocessError) as exc:
                original_state, original_reason, original_method = 'unknown', _reason(exc), _method(exc)
            phase = 'release_binding'
            release = records['release.json']; fence = records['release.intent.json']
            gate = ns['value'](release.body)
            _need(set(gate) == {'anchorPin', 'fencePin', 'credentialPin'} and gate['anchorPin'] == anchor_pin
                  and gate['fencePin'] == fence.pin
                  and ns['value'](fence.body) == {'anchorPin': anchor_pin, 'packetSha256': ns['sha'](ns['canonical'](raw))}, 'release_binding')
            phase = 'child_launch_binding'
            child = records['child.json']; launch = records['ssh-launch.intent.json']
            value = ns['value'](child.body)
            _need(set(value) == {'process', 'launchPin', 'bootId'} and value['launchPin'] == launch.pin
                  and value['bootId'] == stored['bootId']
                  and ns['value'](launch.body) == {'releasePin': release.pin, 'argvSha256': stored['profile']['argvSha256']}, 'child_binding')
            phase = 'original_child_birth'
            process = value['process']; _need(ns['proc'](process['pid']) == process, 'master_changed')
            _need(_parent(process['pid']) == anchor['pane']['pid'], 'child_parent_changed')
            phase = 'original_tmux_owners'
            ns['owners'](authority, job, anchor)
            phase = 'original_master_socket'
            socket = ns['socket_pin'](raw)
            _need('terminal.json' not in records, 'terminal_present')
            if 'ready.json' in records:
                _need(ns['value'](records['ready.json'].body) == {
                    'childPin': child.pin, 'releasePin': release.pin, 'socket': socket}, 'ready_binding')
            phase = 'fixed_control_check'
            result = ns['bounded'](ns['check_argv'](stored, job))
            _need(result.returncode == 0 and re.fullmatch(
                (r'Master running \(pid=' + str(process['pid']) + r'\)\r?\n?').encode(), result.stdout + result.stderr), 'master_unknown')
            phase = 'closing_original_proofs'
            authority.guard()
            _need(ns['socket_pin'](raw) == socket and ns['proc'](process['pid']) == process
                  and _parent(process['pid']) == anchor['pane']['pid'], 'original_owner_changed')
            authority.generations()
            late = 'ready.json' not in records and 'terminal.json' not in records
            public = {'state': 'observed', 'phase': 'complete', 'reason': 'late_ready_original_child' if late else 'original_child_ready',
                      'originalStatus': original_state, 'originalStatusReason': original_reason,
                      'originalStatusMethod': original_method, 'clientState': 'alive_original_child',
                      'readyRecordPresent': 'ready.json' in records, 'terminalRecordPresent': 'terminal.json' in records,
                      'stderrClassification': _stderr_kind(records['stderr.private'].body),
                      'replayAllowed': False, 'readyPublicationAllowed': False, 'adoptionAllowed': False}
            proof = {'version': 1, 'correlationId': CORRELATION, 'originalSourceSha256': ORIGINAL_SOURCE_SHA256,
                     'packetSha256': ns['sha'](ns['canonical'](raw)), 'externalAnchorPin': anchor_pin,
                     'records': metadata, 'childProcess': process, 'paneProcess': anchor['pane'], 'serverProcess': anchor['server'],
                     'bootId': stored['bootId'], 'socketGeneration': socket, 'parentMatchesOriginalPane': True,
                     'fixedControlReady': True, 'controlArgvSha256': ns['sha'](ns['canonical'](ns['check_argv'](stored, job))),
                     'public': public}
    except (OSError, ValueError, TypeError, KeyError, IndexError, subprocess.SubprocessError) as exc:
        public['phase'], public['reason'] = phase, _reason(exc)
    return {'public': public, 'proof': proof}


def observe(root):
    """Root invokes this fixed caller once; private proof stays in its capsule."""
    from agent_tools import ssh_gateway_tmux_master_ssh as adapter
    from agent_tools import ssh_gateway_tmux_master as owner
    try:
        with adapter.LocalAuthority(root) as authority:
            job = authority.group() / CORRELATION
            directory = authority.directory(job, True)
            intent = authority.capture(job / 'intent.json'); record = owner.value(intent.body)
            raw = adapter.original_authority(authority, job, CORRELATION, 'status', record)
            anchor = authority.capture(job / 'anchor.json'); observed = owner.value(anchor.body)
            adapter.reply(observed, 'prepare', CORRELATION, raw)
            _need(observed['state'] == 'prepared', 'original_anchor')
            origin = authority.files[Path(owner.__file__).absolute()]
            _need(origin.pin['sha256'] == ORIGINAL_SOURCE_SHA256 == raw['workerSha256'], 'original_source_changed')
            caller = authority.capture(Path(__file__).absolute(), private=False)
            encoded_origin = base64.b64encode(origin.body).decode(); encoded_caller = base64.b64encode(caller.body).decode()
            program = "import base64,json,sys;_ORIGIN_SOURCE=base64.b64decode(" + repr(encoded_origin) + ");__file__='fixed-d606-diagnostic';__name__='fixed_d606_readonly';exec(compile(base64.b64decode(" + repr(encoded_caller) + "),__file__,'exec'));r=json.loads(sys.stdin.buffer.read(262145));assert set(r)=={'packet','anchorPin'};sys.stdout.buffer.write(_canonical(_remote(r['packet'],r['anchorPin'])))"
            argv = adapter.transport.build_ssh_argv(authority.config, authority.outer.alias, 10,
                         command=('/usr/bin/python3', '-I', '-B', '-c', program), ssh_binary='/usr/bin/ssh')
            argv[1:1] = ['-F', '/dev/null', '-o', 'ControlMaster=no', '-o', 'ControlPath=none',
                         '-o', 'ClearAllForwardings=yes', '-o', 'PermitLocalCommand=no', '-o', 'UpdateHostKeys=no']
            name = 'query-diagnostic-' + uuid4().hex
            os.mkdir(name, 0o700, dir_fd=directory.fd); os.fsync(directory.fd)
            capsule = job / name; destination = authority.directory(capsule, True)
            out_fd = os.open('stdout.private', os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=destination.fd)
            err_fd = os.open('stderr.private', os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=destination.fd)
            outcome, code = 'start_error', None
            try:
                with tempfile.TemporaryDirectory(prefix='vpn-d606-diagnostic-askpass-') as temporary:
                    env = None
                    if authority.outer.password is not None:
                        _, env = adapter.transport._askpass_environment(authority.outer.password, Path(temporary))
                    authority.guard(); authority.generations()
                    child = subprocess.Popen([sys.executable, '-I', '-B', '-c', adapter.EXEC, json.dumps(argv)],
                                             stdin=subprocess.PIPE, stdout=out_fd, stderr=err_fd, env=env)
                    try:
                        child.communicate(_canonical({'packet': raw, 'anchorPin': observed['anchorPin']}), timeout=30)
                        code, outcome = child.returncode, 'completed'
                    except subprocess.TimeoutExpired: outcome = 'timeout'; code = child.poll()
            finally:
                os.fsync(out_fd); os.fsync(err_fd); os.fsync(destination.fd)
                os.close(out_fd); os.close(err_fd)
            out = authority.capture(capsule / 'stdout.private', maximum=LIMIT)
            err = authority.capture(capsule / 'stderr.private', maximum=LIMIT)
            owner.create(destination, 'receipt.json', _canonical({'version': 1, 'correlationId': CORRELATION,
                         'outcome': outcome, 'exitCode': code, 'stdout': out.pin, 'stderr': err.pin,
                         'callerSource': caller.pin, 'originalSource': origin.pin, 'intentPin': intent.pin,
                         'anchorPin': anchor.pin, 'argvSha256': _sha(_canonical(argv)), 'replayAllowed': False}))
            authority.guard()
            _need(outcome == 'completed' and code == 0 and len(out.body) < LIMIT and len(err.body) < LIMIT, 'transport_unknown')
            response = owner.value(out.body)
            _validate_response(response, raw, observed['anchorPin'])
            public = response['public']
            pin = owner.create(destination, 'proof.private.json', _canonical(response))
            authority.capture(capsule / 'proof.private.json'); authority.guard(); authority.generations()
            return {**public, 'privateProofPin': pin, 'capsule': name}
    except (OSError, ValueError, TypeError, KeyError, IndexError, subprocess.SubprocessError):
        return {'state': 'unknown', 'phase': 'local_original_authority', 'reason': 'diagnostic_unknown',
                'replayAllowed': False, 'readyPublicationAllowed': False, 'adoptionAllowed': False}
