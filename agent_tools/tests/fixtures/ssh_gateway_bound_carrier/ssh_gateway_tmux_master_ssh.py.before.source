"""Fixed source/config-bound gateway adapter; no arbitrary command or path API.

Creates a separate future owner correlation. It never adopts a control path into
inventory, rewrites configuration, migrates a daemon, or retries uncertain work.
"""
from __future__ import annotations
from contextlib import ExitStack
import base64
import hashlib
import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from uuid import UUID, uuid4

try:
    from . import private_inventory_lock as inventory
    from . import ssh_connection_session as connection
    from . import ssh_transport as transport
    from . import ssh_connection_recovery as recovery
    from . import ssh_recovery_adoption as adoption
    from . import ssh_gateway_tmux_master as owner
except ImportError:  # Existing CLI/MCP top-level module loading.
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from agent_tools import private_inventory_lock as inventory
    from agent_tools import ssh_connection_session as connection
    from agent_tools import ssh_transport as transport
    from agent_tools import ssh_connection_recovery as recovery
    from agent_tools import ssh_recovery_adoption as adoption
    from agent_tools import ssh_gateway_tmux_master as owner


MAX_REPLY = 65536
EXEC = 'import json,os,resource,sys;resource.setrlimit(resource.RLIMIT_FSIZE,(65536,resource.getrlimit(resource.RLIMIT_FSIZE)[1]));a=json.loads(sys.argv[1]);os.execv(a[0],a)'


def require(condition, reason):
    if not condition: raise ValueError(reason)


def canonical(value): return owner.canonical(value)
def digest(raw): return hashlib.sha256(raw).hexdigest()


def correlation(raw):
    require(type(raw) is dict and set(raw) == {'correlationId'}, 'inputs')
    text = raw['correlationId']
    require(type(text) is str and str(UUID(text)) == text, 'correlation')
    return text


def valid_pin(pin):
    require(type(pin) is dict and set(pin) == {'generation', 'sha256'}, 'pin')
    require(type(pin['generation']) is list and len(pin['generation']) == 9
            and all(type(item) is int and item >= 0 for item in pin['generation']), 'pin_generation')
    require(type(pin['sha256']) is str and len(pin['sha256']) == 64
            and all(char in '0123456789abcdef' for char in pin['sha256']), 'pin_digest')


def reply(result, action, corr, raw):
    require(type(result) is dict, 'reply')
    if action == 'availability':
        require(set(result) == {'available', 'reason', 'nativeActionAllowed'}
                and type(result['available']) is bool and result['nativeActionAllowed'] is False
                and result['reason'] == ('available' if result['available'] else 'tmux_unavailable'), 'availability_reply')
        return
    if result == {'state': 'unknown', 'replayAllowed': False}: return
    if action == 'prepare' and result == {'state': 'blocked', 'reason': 'tmux_unavailable',
                                         'nativeActionAllowed': False, 'replayAllowed': False}: return
    require(result.get('correlationId') == corr and result.get('replayAllowed') is False, 'reply_binding')
    state = result.get('state')
    fields = {'state', 'correlationId', 'replayAllowed'}
    if action == 'prepare':
        require(state == 'prepared' and set(result) == fields | {'anchorPin'}, 'prepare_reply')
        valid_pin(result['anchorPin'])
    elif action == 'release': require(state == 'released' and set(result) == fields, 'release_reply')
    elif state == 'prepared': require(set(result) == fields, 'status_reply')
    elif state == 'ended':
        require(set(result) == fields | {'exitCode'} and type(result['exitCode']) is int, 'ended_reply')
    else:
        require(state == 'ready' and set(result) == fields | {'readyPin', 'controlPath', 'recoveryCorrelationId', 'adoptionAllowed'}
                and result['controlPath'] == raw['masterControlPath'] and result['recoveryCorrelationId'] == UUID(corr).hex
                and result['adoptionAllowed'] is False, 'ready_reply')
        valid_pin(result['readyPin'])


def _mark(diagnostic, phase):
    if diagnostic is not None:
        diagnostic['phase'] = phase


class LocalAuthority:
    def __init__(self, root, *, diagnostic=None):
        self.diagnostic = diagnostic
        _mark(diagnostic, 'source')
        self.stack = ExitStack()
        self.presented = inventory.PresentedPath(Path(root).absolute())
        self.root = self.presented.canonical
        self.files, self.directories = {}, {}
        try:
            for module in (owner, transport, connection, inventory, recovery, adoption): self.capture(Path(module.__file__).absolute(), private=False)
            self.capture(Path(__file__).absolute(), private=False)
            _mark(diagnostic, 'config')
            config_path = transport._private_config_path(self.root); self.capture(config_path)
            self.config, self.outer, snapshot = connection._snapshot(self.root, 'archlinux')
            self.snapshot = snapshot
            target = self.config.hosts['archlinux']
            require(target.transport == 'nested' and target.gateway == self.outer.alias
                    and len(transport._route_hosts(self.config.hosts, 'archlinux')) == 2, 'fixed_two_hop_route')
            self.target = target
            _mark(diagnostic, 'authority')
            for item in snapshot['files']:
                captured = self.capture(Path(item['path']), private=False)
                require(captured.pin['sha256'] == item['sha256'], 'credential_source')
            self.guard()
        except BaseException: self.close(); raise

    def directory(self, path, private=False):
        path = Path(path)
        if path not in self.directories:
            self.directories[path] = self.stack.enter_context(inventory.Directory(path))
        if private:
            require(os.fstat(self.directories[path].fd).st_mode & 0o777 == 0o700, 'private_directory')
        return self.directories[path]

    def capture(self, path, **kw):
        path = Path(path)
        if path not in self.files:
            self.files[path] = self.stack.enter_context(owner.Capture(self.directory(path.parent), path.name, **kw))
        return self.files[path]

    def pins(self): return {str(path): captured.pin for path, captured in self.files.items()}

    def guard(self):
        self.presented.guard()
        require(connection._snapshot(self.root, 'archlinux')[2] == self.snapshot, 'local_authority_changed')
        for captured in self.files.values(): captured.guard()
        self.generations()

    def generations(self):
        for captured in self.files.values(): captured.generations()
        for directory in self.directories.values(): directory.guard()
        self.presented.guard()

    def group(self, create=False):
        parent = self.root
        for name in ('.rag_index', 'ssh-gateway-tmux-master'):
            opened = self.directory(parent)
            path = parent / name
            if create and not os.path.lexists(path):
                os.mkdir(name, 0o700, dir_fd=opened.fd); os.fsync(opened.fd)
            self.directory(path, True); parent = path
        return parent

    def close(self): self.stack.close()
    def __enter__(self): return self
    def __exit__(self, *_): self.close()


def packet(authority, corr, target=None):
    target = target or authority.target
    worker = authority.files[Path(owner.__file__).absolute()]
    base = {str(path): captured.pin for path, captured in authority.files.items()}
    return {'version': 1, 'purpose': owner.PURPOSE, 'host': 'archlinux', 'correlationId': corr,
            'localAuthoritySha256': digest(canonical(base)), 'workerSha256': worker.pin['sha256'],
            'configuredControlPath': str(target.remote_control_path),
            'masterControlPath': str(recovery._recovery_socket_path(target, UUID(corr).hex)[1]),
            'profile': target.remote_host_alias, 'configFile': str(target.remote_config_file) if target.remote_config_file else None}


def query(authority, job, action, raw, anchor_pin=None):
    diagnostic = getattr(authority, 'diagnostic', None)
    _mark(diagnostic, 'source')
    worker = authority.files[Path(owner.__file__).absolute()]
    encoded = base64.b64encode(worker.body).decode()
    # All executed remote bytes are the originally held reviewed worker. There
    # are no command, host, path, executable, or transport overrides in inputs.
    program = "import base64;_STAGED_SOURCE=base64.b64decode(" + repr(encoded) + ");__file__='gateway-tmux-staged-source';exec(compile(_STAGED_SOURCE,__file__,'exec'))"
    command = ('python3', '-I', '-B', '-c', program)
    _mark(diagnostic, 'localmaster')
    argv = transport.build_ssh_argv(authority.config, authority.outer.alias, 10,
                                    command=command, ssh_binary='/usr/bin/ssh')
    argv[1:1] = ['-F', '/dev/null', '-o', 'ControlMaster=no', '-o', 'ControlPath=none',
                 '-o', 'ClearAllForwardings=yes', '-o', 'PermitLocalCommand=no', '-o', 'UpdateHostKeys=no']
    request = {'action': action, 'packet': raw}
    if anchor_pin is not None: request['anchorPin'] = anchor_pin
    if action == 'release':
        require(authority.target.password is not None, 'nested_credential_unavailable')
        request['credential'] = authority.target.password
    input_bytes = canonical(request); require(len(input_bytes) <= owner.MAX, 'input_bound')
    _mark(diagnostic, 'authority')
    directory = authority.directory(job, True)
    name = 'query-' + uuid4().hex
    os.mkdir(name, 0o700, dir_fd=directory.fd); os.fsync(directory.fd)
    capsule = job / name; destination = authority.directory(capsule, True)
    out_fd = os.open('stdout.private', os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=destination.fd)
    err_fd = os.open('stderr.private', os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=destination.fd)
    process = None; outcome = 'error'; code = None
    try:
        with tempfile.TemporaryDirectory(prefix='vpn-gateway-owner-askpass-') as askpass:
            env = None
            if authority.outer.password is not None:
                _, env = transport._askpass_environment(authority.outer.password, Path(askpass))
            authority.guard(); authority.generations()
            _mark(diagnostic, 'remotequery')
            process = subprocess.Popen([sys.executable, '-I', '-B', '-c', EXEC, json.dumps(argv)],
                                       stdin=subprocess.PIPE, stdout=out_fd, stderr=err_fd, env=env)
            try:
                process.communicate(input=input_bytes, timeout=30)
                code = process.returncode; outcome = 'completed'
            except subprocess.TimeoutExpired:
                outcome = 'timeout'; code = process.poll()
            os.fsync(out_fd); os.fsync(err_fd); os.fsync(destination.fd)
        out = authority.capture(capsule / 'stdout.private', maximum=MAX_REPLY)
        err = authority.capture(capsule / 'stderr.private', maximum=MAX_REPLY)
        owner.create(destination, 'receipt.json', canonical({'action': action,
                     'packetSha256': digest(canonical(raw)), 'argvSha256': digest(canonical(argv)),
                     'outcome': outcome, 'exitCode': code, 'stdout': out.pin, 'stderr': err.pin, 'replayAllowed': False}))
        authority.guard()
        require(outcome == 'completed' and code == 0 and len(out.body) < MAX_REPLY and len(err.body) < MAX_REPLY, 'transport_unknown')
        _mark(diagnostic, 'parser')
        result = owner.value(out.body)
        require(result.get('replayAllowed') is False or action == 'availability', 'reply')
        return result
    finally:
        os.fsync(out_fd); os.fsync(err_fd); os.close(out_fd); os.close(err_fd)


def operate(root, action, inputs, *, _diagnostic=None):
    """Public root-owned integration surface; inputs contain correlationId only."""
    try:
        require(action in ('availability', 'prepare', 'release', 'status'), 'action')
        corr = str(uuid4()) if action == 'availability' else correlation(inputs)
        if action == 'availability': require(inputs == {}, 'availability_inputs')
        with LocalAuthority(root, diagnostic=_diagnostic) as authority:
            _mark(_diagnostic, 'authority')
            group = authority.group(create=action in ('availability', 'prepare'))
            job = group / corr
            if action in ('availability', 'prepare'):
                require(not os.path.lexists(job), 'consumed_or_foreign')
                parent = authority.directory(group, True)
                os.mkdir(corr, 0o700, dir_fd=parent.fd); os.fsync(parent.fd)
                directory = authority.directory(job, True)
                raw = {} if action == 'availability' else packet(authority, corr)
                record = {'packet': raw, 'authority': authority.pins(), 'action': action,
                          'configBytes': base64.b64encode(authority.files[transport._private_config_path(authority.root)].body).decode()}
                owner.create(directory, 'intent.json', canonical(record)); authority.capture(job / 'intent.json')
                authority.guard()
                result = query(authority, job, action, raw)
                reply(result, action, corr, raw)
                if action == 'availability' or result.get('state') != 'prepared': return result
                owner.create(directory, 'anchor.json', canonical(result)); authority.capture(job / 'anchor.json'); authority.guard()
                return result
            directory = authority.directory(job, True)
            intent = authority.capture(job / 'intent.json'); record = owner.value(intent.body)
            raw = original_authority(authority, job, corr, action, record)
            anchor = authority.capture(job / 'anchor.json'); observed = owner.value(anchor.body)
            reply(observed, 'prepare', corr, raw)
            require(observed['state'] == 'prepared', 'anchor_binding')
            if action == 'release':
                require(not os.path.lexists(job / 'release.intent.json'), 'release_consumed')
                owner.create(directory, 'release.intent.json', canonical({'anchorPin': anchor.pin, 'packetSha256': digest(canonical(raw))}))
                authority.capture(job / 'release.intent.json'); authority.guard()
            result = query(authority, job, action, raw, observed['anchorPin'])
            _mark(_diagnostic, 'parser')
            reply(result, action, corr, raw)
            _mark(_diagnostic, 'authority')
            authority.guard()
            return result
    except (OSError, ValueError, TypeError, KeyError, IndexError, subprocess.SubprocessError):
        if _diagnostic is not None:
            _diagnostic['failed'] = True
        return {'state': 'unknown', 'replayAllowed': False}


def snapshot_pin(capture): return {**capture.pin, 'size': len(capture.body)}


def configured_status_diagnostic(root, inputs):
    """Observe only the original status; finite failure stage grants no action.

    A phase locates the failing boundary, never authenticates that boundary.
    Existing operate() callers and mutation responses remain unchanged.
    """
    diagnostic = {'phase': 'parser'}
    result = operate(root, 'status', inputs, _diagnostic=diagnostic)
    if result.get('state') == 'unknown':
        phase = diagnostic['phase'] if diagnostic.get('failed') else 'remotequery'
        if phase not in ('source', 'config', 'authority', 'localmaster', 'remotequery', 'parser'):
            phase = 'parser'
        return {'state': 'unknown', 'replayAllowed': False,
                'failurePhase': phase, 'nativeActionAllowed': False}
    return {**result, 'nativeActionAllowed': False}


def original_authority(authority, job, corr, action, record):
    require(set(record) == {'packet', 'authority', 'action', 'configBytes'} and record['action'] == 'prepare', 'original_authority')
    original = base64.b64decode(record['configBytes'], validate=True)
    original_config = adoption._validate_candidate(original, authority.root)
    target = original_config.hosts['archlinux']
    config_path = transport._private_config_path(authority.root)
    baseline = record['authority']; current = {str(path): item.pin for path, item in authority.files.items() if path != job / 'intent.json'}
    require(set(baseline) == set(current) and digest(original) == baseline[str(config_path)]['sha256'], 'authority_binding')
    require(all(canonical(pin) == canonical(current[path]) for path, pin in baseline.items() if path != str(config_path)), 'original_sources')
    raw = record['packet']; expected = packet(authority, corr, target)
    expected['localAuthoritySha256'] = digest(canonical(baseline))
    require(canonical(raw) == canonical(expected), 'packet_binding')
    if canonical(baseline[str(config_path)]) == canonical(current[str(config_path)]):
        require(authority.files[config_path].body == original, 'original_config')
        return raw
    # A status observer follows only one separately proven adoption. Release and
    # every effect retain the original inventory fence; this never publishes it.
    require(action == 'status', 'effect_requires_original_config')
    candidate = owner.value(original); candidate['hosts']['archlinux']['remoteControlPath'] = raw['masterControlPath']
    require(authority.files[config_path].body == canonical(candidate) + b'\n', 'adopted_config_bytes')
    route_sha = adoption._route_sha(original, original_config, 'archlinux')
    key = adoption._route_key('archlinux', raw['configuredControlPath'], raw['masterControlPath'], UUID(corr).hex, route_sha)
    parent = authority.root / adoption._RECEIPTS
    lock = authority.capture(parent / inventory.InventoryLock.name)
    require(lock.body == inventory.InventoryLock.body, 'adoption_lock')
    fcntl.flock(lock.fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
    intent = authority.capture(recovery._intent_path(authority.root, 'archlinux', target))
    require(owner.value(intent.body) == recovery._intent_value('archlinux', target, UUID(corr).hex, 'ready', raw['masterControlPath']), 'adoption_intent')
    pending = authority.capture(parent / (key + '.pending.json'))
    terminal = authority.capture(parent / (key + '.adopted.json'))
    value = {'schemaVersion': 1, 'host': 'archlinux', 'oldControlPath': raw['configuredControlPath'],
             'controlPath': raw['masterControlPath'], 'correlationId': UUID(corr).hex, 'routeSha256': route_sha,
             'source': {**baseline[str(config_path)], 'size': len(original)}, 'intent': snapshot_pin(intent),
             'ownershipLock': snapshot_pin(lock)}
    require(canonical(owner.value(pending.body)) == canonical({**value, 'state': 'pending'})
            and canonical(owner.value(terminal.body)) == canonical({**value, 'state': 'adopted', 'adopted': snapshot_pin(authority.files[config_path])}), 'adoption_terminal')
    authority.guard(); authority.generations()
    return raw
