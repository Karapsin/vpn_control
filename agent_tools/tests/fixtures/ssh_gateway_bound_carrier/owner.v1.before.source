"""Fixed gateway-local tmux owner for one NEW foreground nested SSH master.

The existing recovered daemon is never migrated, adopted, signalled or replaced.
Only prepare/release/status are supported; an uncertain fence is never replayed.
This file is staged verbatim and executes on Linux without repository imports.
"""
from __future__ import annotations
from contextlib import ExitStack
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import sys
import time
import tempfile
from uuid import UUID

SSH = '/usr/bin/ssh'
TMUX = '/usr/bin/tmux'
LIMIT = 4096
MAX = 262144
MAX_MASTER_SOCKET_BYTES = 85  # Canonical recovery socket contract.
PURPOSE = 'gateway-tmux-nested-master'


def need(condition, reason):
    if not condition:
        raise ValueError(reason)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def unique(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, 'duplicate_field')
        result[key] = value
    return result


def value(raw):
    result = json.loads(raw, object_pairs_hook=unique)
    need(type(result) is dict, 'record')
    return result


def generation(info):
    return [info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns]


def identity(info):
    return generation(info)[:5]


class Directory:
    def __init__(self, path, private=False):
        self.path = Path(path)
        self.chain = []
        need(self.path.is_absolute() and '..' not in self.path.parts, 'directory_path')
        try:
            fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            self.chain.append((fd, None, identity(os.fstat(fd))))
            for name in self.path.parts[1:]:
                fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                             dir_fd=self.chain[-1][0])
                self.chain.append((fd, name, identity(os.fstat(fd))))
            info = os.fstat(self.fd)
            need(info.st_uid == os.getuid() and not info.st_mode & 0o022, 'directory_owner')
            if private:
                need(stat.S_IMODE(info.st_mode) == 0o700, 'directory_private')
            self.guard()
        except BaseException:
            self.close(); raise

    @property
    def fd(self):
        return self.chain[-1][0]

    def guard(self):
        for index, (fd, name, pin) in enumerate(self.chain):
            named = os.stat('/', follow_symlinks=False) if index == 0 else os.stat(
                name, dir_fd=self.chain[index - 1][0], follow_symlinks=False)
            need(identity(os.fstat(fd)) == pin == identity(named)
                 and stat.S_ISDIR(named.st_mode), 'directory_changed')

    def close(self):
        for fd, _, _ in reversed(self.chain):
            os.close(fd)
        self.chain = []

    def __enter__(self): return self
    def __exit__(self, *_): self.close()


class Capture:
    def __init__(self, directory, name, private=True, maximum=MAX, metadata=False):
        need(Path(name).name == name and name not in ('', '.', '..'), 'filename')
        self.directory, self.name, self.fd = directory, name, -1
        self.metadata = metadata
        directory.guard()
        try:
            self.fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                              dir_fd=directory.fd)
            info = os.fstat(self.fd)
            need(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                 and info.st_nlink == 1 and not info.st_mode & 0o022, 'file_owner')
            if private:
                need(stat.S_IMODE(info.st_mode) in (0o400, 0o600), 'file_private')
            need(metadata or 0 <= info.st_size <= maximum, 'file_bound')
            self.gen = generation(info)
            self.body = None if metadata else os.pread(self.fd, maximum + 1, 0)
            need(metadata or len(self.body) == info.st_size, 'file_read')
            self.pin = {'generation': self.gen, 'sha256': None if metadata else sha(self.body)}
            self.guard()
        except BaseException:
            self.close(); raise

    def generations(self):
        self.directory.guard()
        need(generation(os.fstat(self.fd)) == self.gen == generation(os.stat(
            self.name, dir_fd=self.directory.fd, follow_symlinks=False)), 'file_changed')

    def guard(self):
        self.generations()
        if not self.metadata:
            need(os.pread(self.fd, len(self.body) + 1, 0) == self.body, 'file_bytes_changed')
        self.generations()

    def close(self):
        if self.fd >= 0: os.close(self.fd); self.fd = -1
    def __enter__(self): return self
    def __exit__(self, *_): self.close()


class Authority:
    def __init__(self):
        self.stack = ExitStack()
        self.directories = {}
        self.files = {}
        self.absent = set()

    def directory(self, path, private=False):
        path = Path(path)
        if path not in self.directories:
            self.directories[path] = self.stack.enter_context(Directory(path, private))
        elif private:
            need(stat.S_IMODE(os.fstat(self.directories[path].fd).st_mode) == 0o700, 'directory_private')
        return self.directories[path]

    def capture(self, path, **kw):
        path = Path(path)
        if path not in self.files:
            self.files[path] = self.stack.enter_context(Capture(self.directory(path.parent), path.name, **kw))
        return self.files[path]

    def absence(self, path):
        path = Path(path); self.directory(path.parent)
        self.absent.add(path); self.generations()

    def guard(self):
        for captured in self.files.values(): captured.guard()
        self.generations()

    def generations(self):
        for captured in self.files.values(): captured.generations()
        for directory in self.directories.values(): directory.guard()
        for path in self.absent:
            try: os.stat(path.name, dir_fd=self.directories[path.parent].fd, follow_symlinks=False)
            except FileNotFoundError: continue
            raise ValueError('absent_file_appeared')

    def close(self): self.stack.close()
    def __enter__(self): return self
    def __exit__(self, *_): self.close()


def create(directory, name, raw, mode=0o600):
    directory.guard()
    fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 mode, dir_fd=directory.fd)
    try:
        offset = 0
        while offset < len(raw):
            count = os.write(fd, raw[offset:]); need(count > 0, 'write_failed'); offset += count
        os.fsync(fd)
        pin = generation(os.fstat(fd))
        need(os.pread(fd, len(raw) + 1, 0) == raw and generation(os.fstat(fd)) == pin
             == generation(os.stat(name, dir_fd=directory.fd, follow_symlinks=False)), 'create_changed')
        directory.guard(); os.fsync(directory.fd)
        return {'generation': pin, 'sha256': sha(raw)}
    finally: os.close(fd)


def proc(pid):
    need(type(pid) is int and pid > 0, 'pid')
    raw = Path(f'/proc/{pid}/stat').read_bytes()
    fields = raw[raw.rfind(b')') + 2:].split()
    need(len(fields) >= 20 and fields[0] not in (b'Z', b'X'), 'process_dead')
    status = Path(f'/proc/{pid}/status').read_bytes()
    uid = re.search(rb'^Uid:\s+([0-9]+)\s+', status, re.M)
    need(uid is not None and int(uid[1]) == os.getuid(), 'process_owner')
    ticks = int(fields[19]); need(ticks > 0, 'process_birth')
    need(Path(f'/proc/{pid}/stat').read_bytes().split(b')', 1)[1].split()[19] == fields[19], 'process_changed')
    return {'pid': pid, 'startTicks': ticks}


def boot():
    raw = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    need(str(UUID(raw)) == raw, 'boot')
    return raw


def packet(raw):
    keys = {'version', 'purpose', 'host', 'correlationId', 'localAuthoritySha256',
            'workerSha256', 'profile', 'configFile', 'configuredControlPath', 'masterControlPath'}
    need(type(raw) is dict and set(raw) == keys and type(raw['version']) is int
         and raw['version'] == 1 and raw['purpose'] == PURPOSE and raw['host'] == 'archlinux', 'packet')
    need(type(raw['correlationId']) is str and str(UUID(raw['correlationId'])) == raw['correlationId'], 'correlation')
    for name in ('localAuthoritySha256', 'workerSha256'):
        need(type(raw[name]) is str and re.fullmatch('[0-9a-f]{64}', raw[name]), 'source_hash')
    need(type(raw['profile']) is str and re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', raw['profile']), 'profile')
    config = raw['configFile']
    need(config is None or type(config) is str and Path(config).is_absolute()
         and '..' not in Path(config).parts and not re.search(r'[\x00-\x1f\x7f]', config), 'config_path')
    for name in ('configuredControlPath', 'masterControlPath'):
        path = raw[name]
        need(type(path) is str and Path(path).is_absolute() and '..' not in Path(path).parts
             and not re.search(r'[\x00-\x1f\x7f]', path), 'master_path')
    configured = Path(raw['configuredControlPath'])
    parent = configured.parent
    if configured.name == 'm' and re.fullmatch(r'r-[0-9a-f]{15,16}', parent.name): parent = parent.parent
    expected = parent / ('r-' + UUID(raw['correlationId']).hex[:15]) / 'm'
    need(str(expected) == raw['masterControlPath'] and expected != configured
         and len(os.fsencode(expected)) <= MAX_MASTER_SOCKET_BYTES, 'master_path_binding')
    return raw


def master_path(raw): return Path(packet(raw)['masterControlPath'])


def paths(raw):
    raw = packet(raw)
    home = Path.home()
    need(home.is_absolute() and not home.is_symlink(), 'home')
    base = home / '.vct'
    job = base / UUID(raw['correlationId']).hex[:16]
    need(len(os.fsencode(job / 't')) < 100 and len(os.fsencode(job / 'm')) < 90, 'socket_path')
    return home, base, job


def source_bytes():
    return globals().get('_STAGED_SOURCE') or Path(__file__).read_bytes()


BOUNDED_EXEC = "import json,os,resource,sys;n=int(sys.argv[2]);resource.setrlimit(resource.RLIMIT_FSIZE,(n,resource.getrlimit(resource.RLIMIT_FSIZE)[1]));resource.setrlimit(resource.RLIMIT_CORE,(0,0));a=json.loads(sys.argv[1]);os.execv(a[0],a)"


def bounded(argv, *, maximum=4096):
    # Private durable capsules and a kernel limit bound streams while the child
    # runs. A timed-out query is observed as unknown and is never signalled.
    capsule = Path(tempfile.mkdtemp(prefix='vpn-gateway-owner-query-')).resolve()
    with Directory(capsule, True) as directory:
        out_fd = os.open('stdout.private', os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory.fd)
        err_fd = os.open('stderr.private', os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory.fd)
        outcome, code = 'start_error', None
        failure = None
        try:
            child = subprocess.Popen([sys.executable, '-I', '-B', '-c', BOUNDED_EXEC, json.dumps(argv), str(maximum + 1)],
                                     stdin=subprocess.DEVNULL, stdout=out_fd, stderr=err_fd)
            try: code = child.wait(timeout=5); outcome = 'completed'
            except subprocess.TimeoutExpired: outcome = 'timeout'
        except OSError as exc: failure = exc
        finally:
            os.fsync(out_fd); os.fsync(err_fd); os.fsync(directory.fd)
            os.close(out_fd); os.close(err_fd)
        with Capture(directory, 'stdout.private', maximum=maximum + 1) as out, Capture(directory, 'stderr.private', maximum=maximum + 1) as err:
            create(directory, 'receipt.json', canonical({'argvSha256': sha(canonical(argv)), 'outcome': outcome,
                         'exitCode': code, 'stdout': out.pin, 'stderr': err.pin, 'replayAllowed': False}))
            out.guard(); err.guard(); directory.guard()
            if failure is not None: raise failure
            need(outcome == 'completed' and len(out.body) <= maximum and len(err.body) <= maximum, 'query_bound_or_timeout')
            return subprocess.CompletedProcess(argv, code, out.body, err.body)


def tmux(job, *args):
    return bounded([TMUX, '-f', '/dev/null', '-S', str(job / 't'), *args])


def availability():
    try:
        result = bounded([TMUX, '-V'], maximum=128)
        present = result.returncode == 0 and re.fullmatch(rb'tmux [0-9]+\.[0-9]+[a-z_0-9.-]*\n?', result.stdout) is not None
    except (OSError, ValueError, subprocess.SubprocessError): present = False
    return {'available': present, 'reason': 'available' if present else 'tmux_unavailable', 'nativeActionAllowed': False}


def file_path(text, home):
    need(type(text) is str and text and '%' not in text and not re.search(r'[\x00-\x1f\x7f]', text), 'effective_path')
    if text.startswith('~/'): text = str(home / text[2:])
    result = Path(text)
    need(result.is_absolute() and '..' not in result.parts, 'effective_path')
    return result


def profile(authority, raw):
    home, _, job = paths(raw)
    config = Path(raw['configFile']) if raw['configFile'] is not None else home / '.ssh/config'
    config_capture = authority.capture(config)
    text = config_capture.body.decode('utf-8')
    # No Include/Match exec can hide unpinned files or execute before admission.
    allowed = {'host', 'hostname', 'user', 'port', 'identityfile', 'userknownhostsfile',
               'identitiesonly', 'stricthostkeychecking', 'batchmode', 'controlmaster',
               'controlpath', 'controlpersist', 'addkeystoagent', 'serveraliveinterval',
               'serveralivecountmax', 'loglevel', 'hostkeyalias', 'canonicalizehostname'}
    for line in text.splitlines():
        fields = shlex.split(line, comments=True)
        if fields: need(fields[0].lower().split('=', 1)[0] in allowed, 'unsupported_config_directive')
    result = bounded([SSH, '-F', str(config), '-G', raw['profile']], maximum=MAX)
    need(result.returncode == 0, 'effective_config')
    options = {}
    for line in result.stdout.decode('utf-8').splitlines():
        key, _, rest = line.partition(' ')
        options.setdefault(key, []).append(rest)
    def one(key):
        need(len(options.get(key, [])) == 1, 'effective_config'); return options[key][0]
    hostname, user, port = one('hostname'), one('user'), one('port')
    need(re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.:-]{0,252}', hostname)
         and re.fullmatch('[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}', user)
         and re.fullmatch('[0-9]{1,5}', port) and 1 <= int(port) <= 65535, 'effective_endpoint')
    key = file_path(one('identityfile'), home)
    known_paths = [file_path(text, home) for text in shlex.split(one('userknownhostsfile'))]
    need(1 <= len(known_paths) <= 2 and len(set(known_paths)) == len(known_paths), 'known_hosts_paths')
    key_capture = authority.capture(key, metadata=True)
    known = []
    for path in known_paths:
        if os.path.lexists(path):
            captured = authority.capture(path, private=False); known.append({'path': str(path), 'pin': captured.pin})
        else:
            authority.absence(path); known.append({'path': str(path), 'absent': True})
    need(any('pin' in item for item in known), 'known_hosts_unavailable')
    alias = options.get('hostkeyalias', ['none'])
    need(len(alias) == 1 and (alias[0] == 'none' or re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.:-]{0,252}', alias[0])), 'hostkey_alias')
    argv = [SSH, '-F', '/dev/null', '-M', '-N', '-S', str(master_path(raw)), '-p', port,
            '-l', user, '-i', str(key), '-o', 'ControlMaster=yes', '-o', 'ControlPersist=no',
            '-o', 'ForkAfterAuthentication=no', '-o', 'BatchMode=no', '-o', 'NumberOfPasswordPrompts=1',
            '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=' + ' '.join(shlex.quote(str(path)) for path in known_paths),
            '-o', 'GlobalKnownHostsFile=/dev/null',
            '-o', 'IdentitiesOnly=yes', '-o', 'ClearAllForwardings=yes', '-o', 'PermitLocalCommand=no',
            '-o', 'UpdateHostKeys=no', '-o', 'ConnectTimeout=10', '-o', 'ServerAliveInterval=10',
            '-o', 'ServerAliveCountMax=3']
    if alias[0] != 'none': argv += ['-o', 'HostKeyAlias=' + alias[0]]
    argv += [hostname]
    authority.guard()
    return {'config': {'path': str(config), 'pin': config_capture.pin},
            'key': {'path': str(key), 'pin': key_capture.pin},
            'known': known, 'argv': argv,
            'argvSha256': sha(canonical(argv))}


def configured_absence(authority, raw, recorded=None):
    configured = Path(raw['configuredControlPath'])
    if recorded is None:
        absent = configured
        while not os.path.lexists(absent.parent): absent = absent.parent
        parent = authority.directory(absent.parent)
        record = {'path': str(absent), 'parent': identity(os.fstat(parent.fd))}
    else:
        need(type(recorded) is dict and set(recorded) == {'path', 'parent'}, 'configured_absence_schema')
        absent = Path(recorded['path'])
        need(absent.is_absolute() and '..' not in absent.parts
             and (absent == configured or absent in configured.parents), 'configured_absence_path')
        parent = authority.directory(absent.parent)
        need(identity(os.fstat(parent.fd)) == recorded['parent'], 'configured_parent_changed')
        record = recorded
    authority.absence(absent)
    return record


def open_history(authority, raw, expected=None, readonly=False, blocking=False):
    home, base, job = paths(raw)
    authority.directory(home); authority.directory(base, True); directory = authority.directory(job, True)
    lock = authority.capture(job / 'lock', maximum=0)
    fcntl.flock(lock.fd, (fcntl.LOCK_SH if readonly else fcntl.LOCK_EX) | (0 if blocking else fcntl.LOCK_NB))
    intent = authority.capture(job / 'intent.json')
    stored = value(intent.body)
    need(set(stored) == {'packet', 'profile', 'bootId', 'parent', 'job', 'sourcePin', 'masterParent', 'configuredAbsence'}
         and canonical(stored['packet']) == canonical(raw) and stored['bootId'] == boot()
         and stored['parent'] == identity(os.fstat(authority.directory(base, True).fd))
         and stored['job'] == identity(os.fstat(directory.fd)), 'intent_binding')
    configured_absence(authority, raw, stored['configuredAbsence'])
    master_directory = authority.directory(master_path(raw).parent, True)
    need(identity(os.fstat(master_directory.fd)) == stored['masterParent'], 'master_parent_changed')
    worker = authority.capture(job / 'owner.py')
    need(worker.pin['sha256'] == raw['workerSha256'] and worker.pin == stored['sourcePin'], 'worker_source')
    current = profile(authority, raw)
    need(canonical(current) == canonical(stored['profile']), 'profile_changed')
    if expected is not None:
        anchor = authority.capture(job / 'anchor.json')
        need(canonical(anchor.pin) == canonical(expected), 'external_anchor')
        observed = value(anchor.body)
        need(set(observed) == {'intentPin', 'sourcePin', 'server', 'pane', 'socket', 'session', 'bootId'}
             and observed['intentPin'] == intent.pin and observed['sourcePin'] == worker.pin
             and observed['bootId'] == stored['bootId']
             and observed['session'] == 'vc-' + UUID(raw['correlationId']).hex[:16], 'anchor_binding')
        return job, directory, stored, observed
    return job, directory, stored, None


def owners(authority, job, anchor):
    sock = os.stat('t', dir_fd=authority.directory(job, True).fd, follow_symlinks=False)
    need(stat.S_ISSOCK(sock.st_mode) and sock.st_uid == os.getuid() and not sock.st_mode & 0o077
         and generation(sock) == anchor['socket'], 'tmux_socket_changed')
    need(proc(anchor['server']['pid']) == anchor['server'] and proc(anchor['pane']['pid']) == anchor['pane'], 'tmux_owner_changed')
    listed = tmux(job, 'list-sessions', '-F', '#{session_name}')
    displayed = tmux(job, 'display-message', '-p', '-t', anchor['session'], '#{pid} #{pane_pid}')
    need(listed.returncode == 0 and listed.stdout == (anchor['session'] + '\n').encode()
         and displayed.returncode == 0 and displayed.stdout.strip() ==
         f"{anchor['server']['pid']} {anchor['pane']['pid']}".encode(), 'foreign_session')
    authority.guard()
    need(generation(os.stat('t', dir_fd=authority.directory(job, True).fd, follow_symlinks=False)) == anchor['socket']
         and proc(anchor['server']['pid']) == anchor['server'] and proc(anchor['pane']['pid']) == anchor['pane'], 'tmux_owner_changed')
    authority.generations()


def prepare(raw):
    raw = packet(raw)
    if not availability()['available']:
        return {'state': 'blocked', 'reason': 'tmux_unavailable', 'nativeActionAllowed': False, 'replayAllowed': False}
    home, base, job = paths(raw)
    with Authority() as authority:
        authority.directory(home)
        if not os.path.lexists(base):
            os.mkdir('.vct', 0o700, dir_fd=authority.directory(home).fd); os.fsync(authority.directory(home).fd)
        parent = authority.directory(base, True)
        need(not os.path.lexists(job), 'consumed_or_foreign')
        master = master_path(raw)
        master_base = authority.directory(master.parent.parent, True)
        need(not os.path.lexists(master.parent) and not os.path.lexists(raw['configuredControlPath']), 'consumed_or_foreign_master')
        old_absence = configured_absence(authority, raw)
        resolved = profile(authority, raw)
        source = source_bytes(); need(sha(source) == raw['workerSha256'], 'worker_source')
        authority.guard()
        os.mkdir(job.name, 0o700, dir_fd=parent.fd); os.fsync(parent.fd)
        directory = authority.directory(job, True)
        create(directory, 'lock', b'')
        lock = authority.capture(job / 'lock', maximum=0); fcntl.flock(lock.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        os.mkdir(master.parent.name, 0o700, dir_fd=master_base.fd); os.fsync(master_base.fd)
        master_directory = authority.directory(master.parent, True)
        source_pin = create(directory, 'owner.py', source)
        stored = {'packet': raw, 'profile': resolved, 'bootId': boot(), 'parent': identity(os.fstat(parent.fd)),
                  'job': identity(os.fstat(directory.fd)), 'sourcePin': source_pin, 'masterParent': identity(os.fstat(master_directory.fd)),
                  'configuredAbsence': old_absence}
        intent_pin = create(directory, 'intent.json', canonical(stored))
        authority.capture(job / 'owner.py'); authority.capture(job / 'intent.json')
        need(not os.path.lexists(job / 't') and not os.path.lexists(master), 'foreign_socket')
        authority.guard(); authority.generations()
        name = 'vc-' + UUID(raw['correlationId']).hex[:16]
        command = 'exec ' + shlex.join([sys.executable, '-I', '-B', str(job / 'owner.py'), '_worker', str(job)])
        result = tmux(job, 'new-session', '-d', '-s', name, '-c', str(job), command)
        need(result.returncode == 0, 'submit_unknown')
        result = tmux(job, 'display-message', '-p', '-t', name, '#{pid} #{pane_pid}')
        need(result.returncode == 0 and re.fullmatch(rb'[1-9][0-9]* [1-9][0-9]*\n?', result.stdout), 'submit_unknown')
        server, pane = map(int, result.stdout.split())
        socket = (job / 't').lstat()
        need(stat.S_ISSOCK(socket.st_mode) and socket.st_uid == os.getuid() and not socket.st_mode & 0o077, 'foreign_socket')
        anchor = {'intentPin': intent_pin, 'sourcePin': source_pin, 'server': proc(server), 'pane': proc(pane),
                  'socket': generation(socket), 'session': name, 'bootId': stored['bootId']}
        anchor_pin = create(directory, 'anchor.json', canonical(anchor))
        authority.capture(job / 'anchor.json'); owners(authority, job, anchor)
        return {'state': 'prepared', 'correlationId': raw['correlationId'], 'anchorPin': anchor_pin, 'replayAllowed': False}


def release(raw, anchor_pin, credential):
    raw = packet(raw)
    need(type(credential) is str and 0 < len(credential.encode()) <= 16384 and '\x00' not in credential, 'credential')
    with Authority() as authority:
        job, directory, stored, anchor = open_history(authority, raw, anchor_pin)
        need(not any(os.path.lexists(job / name) for name in ('release.intent.json', 'credential.private', 'release.json')), 'release_consumed')
        owners(authority, job, anchor)
        fence = create(directory, 'release.intent.json', canonical({'anchorPin': anchor_pin, 'packetSha256': sha(canonical(raw))}))
        authority.capture(job / 'release.intent.json'); owners(authority, job, anchor)
        secret_pin = create(directory, 'credential.private', credential.encode())
        # Secret hash/pin remains in private release history, never public output.
        secret = authority.capture(job / 'credential.private', maximum=16384)
        need(secret.pin == secret_pin, 'credential_changed')
        owners(authority, job, anchor); authority.generations()
        create(directory, 'release.json', canonical({'anchorPin': anchor_pin, 'fencePin': fence, 'credentialPin': secret_pin}))
        authority.capture(job / 'release.json'); authority.guard()
        return {'state': 'released', 'correlationId': raw['correlationId'], 'replayAllowed': False}


def check_argv(stored, job):
    # Explicit no-fallback control check, fixed admitted endpoint and socket.
    argv = stored['profile']['argv']
    return [SSH, '-F', '/dev/null', '-S', str(master_path(stored['packet'])), '-o', 'ControlMaster=no',
            '-o', 'ControlPersist=no', '-o', 'ProxyCommand=false', '-O', 'check', argv[-1]]


def socket_pin(raw):
    info = master_path(raw).lstat()
    need(stat.S_ISSOCK(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1
         and not info.st_mode & 0o077, 'master_socket')
    return generation(info)


def status(raw, anchor_pin):
    raw = packet(raw)
    with Authority() as authority:
        job, directory, stored, anchor = open_history(authority, raw, anchor_pin, readonly=True)
        if not os.path.lexists(job / 'release.json'):
            owners(authority, job, anchor)
            return {'state': 'prepared', 'correlationId': raw['correlationId'], 'replayAllowed': False}
        released = authority.capture(job / 'release.json')
        gate = value(released.body)
        fence = authority.capture(job / 'release.intent.json')
        need(set(gate) == {'anchorPin', 'fencePin', 'credentialPin'} and gate['anchorPin'] == anchor_pin
             and gate['fencePin'] == fence.pin and value(fence.body) == {'anchorPin': anchor_pin, 'packetSha256': sha(canonical(raw))}, 'release_binding')
        child = authority.capture(job / 'child.json')
        child_value = value(child.body)
        launch = authority.capture(job / 'ssh-launch.intent.json')
        need(set(child_value) == {'process', 'launchPin', 'bootId'} and child_value['launchPin'] == launch.pin
             and child_value['bootId'] == stored['bootId']
             and value(launch.body) == {'releasePin': released.pin, 'argvSha256': stored['profile']['argvSha256']}, 'child_binding')
        if os.path.lexists(job / 'terminal.json'):
            terminal = authority.capture(job / 'terminal.json')
            terminal_value = value(terminal.body)
            out = authority.capture(job / 'stdout.private', maximum=LIMIT)
            err = authority.capture(job / 'stderr.private', maximum=LIMIT)
            need(set(terminal_value) == {'childPin', 'exitCode', 'stdout', 'stderr'}
                 and type(terminal_value['exitCode']) is int and terminal_value['childPin'] == child.pin
                 and terminal_value['stdout'] == out.pin and terminal_value['stderr'] == err.pin, 'terminal_binding')
            authority.guard()
            # An ended master never authorizes automatically starting another.
            return {'state': 'ended', 'correlationId': raw['correlationId'], 'exitCode': terminal_value['exitCode'], 'replayAllowed': False}
        ready = authority.capture(job / 'ready.json')
        expected = {'childPin': child.pin, 'releasePin': released.pin, 'socket': socket_pin(raw)}
        need(value(ready.body) == expected and proc(child_value['process']['pid']) == child_value['process'], 'master_changed')
        owners(authority, job, anchor)
        result = bounded(check_argv(stored, job))
        need(result.returncode == 0 and re.fullmatch(
            (r'Master running \(pid=' + str(child_value['process']['pid']) + r'\)\r?\n?').encode(), result.stdout + result.stderr), 'master_unknown')
        authority.guard()
        need(socket_pin(raw) == expected['socket'] and proc(child_value['process']['pid']) == child_value['process'], 'master_changed')
        authority.generations()
        return {'state': 'ready', 'correlationId': raw['correlationId'], 'readyPin': ready.pin,
                'controlPath': str(master_path(raw)), 'recoveryCorrelationId': UUID(raw['correlationId']).hex,
                'replayAllowed': False, 'adoptionAllowed': False}


ASKPASS = "#!/usr/bin/env python3\nimport os,pathlib,sys\nsys.stdout.buffer.write(pathlib.Path(os.environ['VPN_CONTROL_TMUX_SECRET']).read_bytes()+b'\\n')\n"
EXEC = "import json,os,resource,sys;resource.setrlimit(resource.RLIMIT_FSIZE,(4096,4096));a=json.loads(sys.argv[1]);os.execv(a[0],a)"


def worker(job):
    """Fixed gated pane: credential never enters tmux input, args or diagnostics."""
    job = Path(job)
    for _ in range(3000):
        if os.path.lexists(job / 'release.json'): break
        time.sleep(.1)
    else: return 72
    with Authority() as authority:
        # Use original packet only to open and validate the external anchor.
        with Directory(job, True) as initial:
            with Capture(initial, 'intent.json') as captured: raw = value(captured.body)['packet']
            with Capture(initial, 'anchor.json') as captured: anchor_pin = captured.pin
        need(paths(raw)[2] == job, 'worker_job')
        job, directory, stored, anchor = open_history(authority, raw, anchor_pin, readonly=True, blocking=True)
        released = authority.capture(job / 'release.json'); gate = value(released.body)
        fence = authority.capture(job / 'release.intent.json')
        secret = authority.capture(job / 'credential.private', maximum=16384)
        need(gate == {'anchorPin': anchor_pin, 'fencePin': fence.pin, 'credentialPin': secret.pin}
             and value(fence.body) == {'anchorPin': anchor_pin, 'packetSha256': sha(canonical(raw))}, 'release_binding')
        need(proc(os.getpid()) == anchor['pane'], 'pane_changed')
        create(directory, 'askpass.py', ASKPASS.encode(), mode=0o700)
        # Askpass executable has a dedicated mode; retain its exact opened bytes.
        helper = authority.capture(job / 'askpass.py', private=False)
        need(helper.body == ASKPASS.encode(), 'askpass_changed')
        launch_pin = create(directory, 'ssh-launch.intent.json', canonical(
            {'releasePin': released.pin, 'argvSha256': stored['profile']['argvSha256']}))
        authority.capture(job / 'ssh-launch.intent.json')
        out_fd = os.open('stdout.private', os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory.fd)
        err_fd = os.open('stderr.private', os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory.fd)
        try:
            environment = os.environ.copy()
            environment.update({'SSH_ASKPASS': str(job / 'askpass.py'), 'SSH_ASKPASS_REQUIRE': 'force',
                                'DISPLAY': 'vpn-control-tmux', 'VPN_CONTROL_TMUX_SECRET': str(job / 'credential.private')})
            environment.pop('SSH_AUTH_SOCK', None)
            owners(authority, job, anchor); need(not os.path.lexists(master_path(raw)), 'foreign_master_socket')
            authority.generations()
            child = subprocess.Popen([sys.executable, '-I', '-B', '-c', EXEC, json.dumps(stored['profile']['argv'])],
                                     stdin=subprocess.DEVNULL, stdout=out_fd, stderr=err_fd, env=environment)
            child_value = {'process': proc(child.pid), 'launchPin': launch_pin, 'bootId': stored['bootId']}
            child_pin = create(directory, 'child.json', canonical(child_value)); authority.capture(job / 'child.json')
            for _ in range(50):
                if os.path.lexists(master_path(raw)) or child.poll() is not None: break
                time.sleep(.1)
            if child.poll() is None and os.path.lexists(master_path(raw)):
                before = socket_pin(raw); result = bounded(check_argv(stored, job))
                if (result.returncode == 0 and result.stdout + result.stderr == f'Master running (pid={child.pid})\n'.encode()
                        and proc(child.pid) == child_value['process'] and socket_pin(raw) == before):
                    authority.guard()
                    create(directory, 'ready.json', canonical({'childPin': child_pin, 'releasePin': released.pin, 'socket': before}))
            # No deadline/restart/signal: an unknown startup remains one original
            # owner. Observe its eventual exit and retain the bounded raw streams.
            fcntl.flock(authority.files[job / 'lock'].fd, fcntl.LOCK_SH)
            code = child.wait()
            os.fsync(out_fd); os.fsync(err_fd)
            out = authority.capture(job / 'stdout.private', maximum=LIMIT)
            err = authority.capture(job / 'stderr.private', maximum=LIMIT)
            authority.guard()
            create(directory, 'terminal.json', canonical({'childPin': child_pin, 'exitCode': code, 'stdout': out.pin, 'stderr': err.pin}))
            # Credentials remain private evidence on uncertain failure. No cleanup
            # action is inferred from pane/master exit; a separate owner may retire.
            return code
        finally:
            os.fsync(out_fd); os.fsync(err_fd); os.fsync(directory.fd)
            os.close(out_fd); os.close(err_fd)


def operate(action, raw, anchor_pin=None, credential=None):
    try:
        need(action in ('availability', 'prepare', 'release', 'status'), 'action')
        if action == 'availability':
            need(raw == {}, 'availability_input'); return availability()
        if action == 'prepare': return prepare(raw)
        if action == 'release': return release(raw, anchor_pin, credential)
        return status(raw, anchor_pin)
    except (OSError, ValueError, TypeError, KeyError, IndexError, subprocess.SubprocessError):
        return {'state': 'unknown', 'replayAllowed': False}


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '_worker':
        try: sys.exit(worker(sys.argv[2]))
        except (OSError, ValueError, TypeError, KeyError, IndexError, subprocess.SubprocessError): sys.exit(74)
    else:
        raw = sys.stdin.buffer.read(MAX + 1)
        try:
            need(len(raw) <= MAX, 'input_bound'); request = value(raw)
            need(set(request) in ({'action', 'packet'}, {'action', 'packet', 'anchorPin'},
                                 {'action', 'packet', 'anchorPin', 'credential'}), 'request')
            result = operate(request['action'], request['packet'], request.get('anchorPin'), request.get('credential'))
        except (OSError, ValueError, TypeError, KeyError): result = {'state': 'unknown', 'replayAllowed': False}
        print(canonical(result).decode())
