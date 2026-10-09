"""One receipt-bound graceful close of the original locally owned SSH master.

A consumed close intent never permits another effect. Status only observes death;
all original and close records stay descriptor-bound until the final decision.
"""
from __future__ import annotations

from contextlib import ExitStack
import fcntl
import json
import os
from pathlib import Path
import re
import selectors
import stat
import subprocess
import time
from typing import Any

from . import private_inventory_lock as inventory
from . import ssh_connection_session as session
from .private_inventory_lock import Directory, PresentedPath, _generation

_ORIGINAL_SOURCE = 'dba4466d09aff57787cb008edcd044bc1cb4c3a22f4325c6a41efebe230a0720'
_TRANSPORT_SOURCE = '6e4e9bfcdf620dab84cec100a4990121198fc95b331e0468adf8b79fb2e9e372'
_INVENTORY_SOURCE = 'd6ce7b228059470b4792c47e4562017235cad26ae6666c2a899dd459887358b8'
_HASH = re.compile(r'[0-9a-f]{64}')
_LIMIT = 4096
_TIMEOUT = 3


def _same(left, right):
    # Canonical JSON equality preserves exact scalar types (True is not 1).
    return session._json(left) == session._json(right)


def _unknown(host):
    return {'state': 'unknown', 'host': host, 'replayAllowed': False}


def _paths(root, host, receipt):
    if (not isinstance(host, str) or not session.transport._ALIAS_RE.fullmatch(host)
            or not isinstance(receipt, str) or not _HASH.fullmatch(receipt)):
        raise ValueError('binding')
    root = Path(root).resolve(strict=True)
    group = root / session._DIR
    leaf = session._sha((str(root) + '\0' + host).encode())[:24]
    prefix = leaf + '.close-' + receipt
    return (root, group, group / leaf, group / (prefix + '.intent.json'),
            group / (prefix + '.stdout.private'), group / (prefix + '.stderr.private'),
            group / (prefix + '.terminal.json'))


class _Capture:
    """An original opened generation, including valid empty private output."""
    def __init__(self, directory, path, private=True, limit=session._MAX):
        self.directory = directory
        self.path = path
        self.fd = -1
        directory.guard()
        try:
            self.fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                              dir_fd=directory.fd)
            info = os.fstat(self.fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or info.st_nlink != 1 or info.st_mode & 0o022
                    or private and stat.S_IMODE(info.st_mode) != 0o600
                    or not 0 <= info.st_size <= limit):
                raise ValueError('unsafe file')
            self.generation = _generation(info)
            self.body = os.pread(self.fd, limit + 1, 0)
            if len(self.body) != info.st_size:
                raise ValueError('incomplete read')
            self.pin = {'sha256': session._sha(self.body), 'fingerprint': session._fp(info)}
            self.guard()
        except BaseException:
            self.close()
            raise

    def value(self):
        value = json.loads(self.body, object_pairs_hook=session._unique)
        if not isinstance(value, dict):
            raise ValueError('record')
        return value

    def guard(self):
        self.directory.guard()
        if (_generation(os.fstat(self.fd)) != self.generation
                or _generation(os.stat(self.path.name, dir_fd=self.directory.fd,
                                       follow_symlinks=False)) != self.generation
                or os.pread(self.fd, len(self.body) + 1, 0) != self.body
                or _generation(os.fstat(self.fd)) != self.generation):
            raise ValueError('captured generation changed')
        self.directory.guard()
        if _generation(os.stat(self.path.name, dir_fd=self.directory.fd,
                               follow_symlinks=False)) != self.generation:
            raise ValueError('named generation changed')

    def generation_guard(self):
        # Final pass performs no byte/config reads that could precede adoption
        # of a changed record; it checks the originally held generation only.
        self.directory.guard()
        if (_generation(os.fstat(self.fd)) != self.generation
                or _generation(os.stat(self.path.name, dir_fd=self.directory.fd,
                                       follow_symlinks=False)) != self.generation):
            raise ValueError('final captured generation changed')

    def close(self):
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def _create(directory, path, value):
    directory.guard()
    session._create(path, value, directory.fd)
    directory.guard()


class _History:
    """Retain every original record and source/config/credential authority."""
    def __init__(self, stack, root, host, receipt, journal):
        self.stack, self.root, self.host = stack, root, host
        self.files = {}
        self.directories = {}
        self.presented = PresentedPath(root)
        for private in (root / '.rag_index', journal.parent, journal):
            session._directory(private)
        self.journal = self.directory(journal)
        self.group = self.directory(journal.parent)
        self.lock = self.capture(journal / 'lock', limit=0)
        fcntl.flock(self.lock.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        for name in ('intent.json', 'child.json', 'anchor.json', 'ready.json',
                     'launch.json', 'startup.json', 'launch.stderr.private'):
            self.capture(journal / name, limit=_LIMIT if name.endswith('.private') else session._MAX)
        self.intent = self.record('intent.json')
        self.ready = self.record('ready.json')
        if session._sha(session._json(self.file('ready.json').pin)) != receipt:
            raise ValueError('original receipt')
        for module, digest in ((session, _ORIGINAL_SOURCE), (session.transport, _TRANSPORT_SOURCE),
                               (inventory, _INVENTORY_SOURCE)):
            source = self.capture(Path(module.__file__).absolute(), private=False)
            if source.pin['sha256'] != digest:
                raise ValueError('frozen source')
        self.helper = self.capture(Path(__file__).absolute(), private=False)
        self.capture(session.transport._private_config_path(root))
        self.config, self.outer, self.authority = session._snapshot(root, host)
        for item in self.authority['files']:
            captured = self.capture(Path(item['path']), private=False)
            if not _same(captured.pin, {'sha256': item['sha256'], 'fingerprint': item['fingerprint']}):
                raise ValueError('credential authority')
        self.path = Path(self.intent['socketPath'])
        self.socket_parent = self.directory(self.path.parent)
        self.validate()
        self.guard()

    def directory(self, path):
        if path not in self.directories:
            self.directories[path] = self.stack.enter_context(Directory(path))
        return self.directories[path]

    def capture(self, path, **kw):
        if path not in self.files:
            self.files[path] = self.stack.enter_context(_Capture(self.directory(path.parent), path, **kw))
        return self.files[path]

    def file(self, name):
        return self.files[self.journal.path / name]

    def record(self, name):
        return self.file(name).value()

    def pins(self):
        return {str(path): captured.pin for path, captured in self.files.items()}

    def validate(self):
        intent, ready = self.intent, self.ready
        if (set(intent) != {'version', 'authority', 'socketPath', 'parentIdentity'}
                or type(intent['version']) is not int or intent['version'] != 1
                or intent['authority'] != self.authority
                or not self.path.is_absolute() or self.path.name != 'm'
                or len(os.fsencode(self.path)) >= 90
                or self.path.parent.parent != Path(session.tempfile.gettempdir()).resolve()
                or session._directory(self.path.parent) != intent['parentIdentity']):
            raise ValueError('original intent')
        child = self.record('child.json')
        if (set(child) != {'intentSha256', 'pid'} or type(child['pid']) is not int
                or child['pid'] <= 0 or child['intentSha256'] != session._sha(session._json(intent))):
            raise ValueError('original child')
        if not _same(self.record('anchor.json'), {'intentPin': self.file('intent.json').pin,
                                         'childPin': self.file('child.json').pin,
                                         'parentIdentity': intent['parentIdentity']}):
            raise ValueError('original anchor')
        master = ready.get('master')
        if (not isinstance(master, dict) or set(master) != {'pid', 'generationSha256'}
                or type(master['pid']) is not int or master['pid'] != child['pid']
                or not isinstance(master['generationSha256'], str)
                or not _HASH.fullmatch(master['generationSha256'])):
            raise ValueError('original birth')
        socket_pin = ready.get('socketFingerprint')
        if (not isinstance(socket_pin, list) or len(socket_pin) != 8
                or any(type(v) is not int for v in socket_pin)
                or not stat.S_ISSOCK(socket_pin[2]) or socket_pin[3] != os.getuid()
                or socket_pin[4] != 1 or socket_pin[2] & 0o077):
            raise ValueError('original socket')
        expected = {'version': 1, 'intentSha256': child['intentSha256'],
                    'childPin': self.file('child.json').pin, 'intentPin': self.file('intent.json').pin,
                    'anchorPin': self.file('anchor.json').pin, 'socketFingerprint': socket_pin,
                    'master': master, 'authoritySha256': session._sha(session._json(self.authority))}
        if not _same(ready, expected):
            raise ValueError('original ready')
        launch = self.record('launch.json')
        if not _same(launch, {'version': 1, 'argvSha256': session._sha(session._json(
                session._launch_argv(self.config, self.outer, self.path))), 'diagnosticLimit': _LIMIT}):
            raise ValueError('original launch')
        startup = self.record('startup.json')
        diagnostic = self.file('launch.stderr.private')
        if (set(startup) != {'version', 'exitCode', 'elapsedMs', 'stderrBytes',
                             'stderrSha256', 'stderrFingerprint'}
                or type(startup['version']) is not int or startup['version'] != 1
                or startup['exitCode'] is not None
                or type(startup['elapsedMs']) is not int or startup['elapsedMs'] < 0
                or type(startup['stderrBytes']) is not int or startup['stderrBytes'] != len(diagnostic.body)
                or startup['stderrSha256'] != diagnostic.pin['sha256']
                or startup['stderrFingerprint'] != diagnostic.pin['fingerprint']):
            raise ValueError('original startup')

    def guard(self):
        self.presented.guard()
        # Read authority first; then recheck every original opened and named
        # generation. Never reopen a record and silently adopt its new bytes.
        if session._snapshot(self.root, self.host)[2] != self.authority:
            raise ValueError('authority changed')
        for captured in self.files.values():
            captured.guard()
        for directory in self.directories.values():
            directory.guard()
        self.final_generations()

    def final_generations(self):
        for captured in self.files.values():
            captured.generation_guard()
        for directory in self.directories.values():
            directory.guard()
        self.presented.guard()

    def live(self):
        proof, path = session._verify(self.root, self.host, self.journal.path,
                                      self.intent, self.ready)
        if proof != self.ready or path != self.path:
            raise ValueError('original master')
        self.guard()

    def exit_argv(self):
        argv = session._check_argv(self.config, self.outer, self.path)
        if argv[-3:] != ['-O', 'check', argv[-1]]:
            raise ValueError('fixed control request')
        return [*argv[:-2], 'exit', argv[-1]]


def _intent(history, root, host, receipt):
    return {'version': 1, 'root': str(root), 'host': host, 'receiptSha256': receipt,
            'sessionSourceSha256': _ORIGINAL_SOURCE, 'transportSourceSha256': _TRANSPORT_SOURCE,
            'helperPin': history.helper.pin, 'authoritySha256': history.ready['authoritySha256'],
            'authority': history.authority, 'pid': history.ready['master']['pid'],
            'pidBirth': history.ready['master']['generationSha256'],
            'socketFingerprint': history.ready['socketFingerprint'], 'socketPath': str(history.path),
            'parentIdentity': history.intent['parentIdentity'], 'historyPins': history.pins(),
            'exitArgvSha256': session._sha(session._json(history.exit_argv()))}


class _Output:
    def __init__(self, directory, path):
        self.directory, self.path = directory, path
        self.fd = os.open(path.name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                          0o600, dir_fd=directory.fd)
        self.body = bytearray()
        self.identity = _generation(os.fstat(self.fd))[:6]
        os.fsync(self.fd)
        os.fsync(directory.fd)

    def append(self, data):
        # Every observed prefix is durable before interpreting an outcome.
        kept = data[:_LIMIT - len(self.body)]
        offset = 0
        while offset < len(kept):
            written = os.write(self.fd, kept[offset:])
            if written <= 0:
                raise OSError('incomplete output write')
            self.body.extend(kept[offset:offset + written])
            offset += written
            os.fsync(self.fd)
        if len(kept) != len(data):
            raise OverflowError('control output limit')

    def pin(self):
        info = os.fstat(self.fd)
        if (_generation(info)[:6] != self.identity or info.st_size != len(self.body)
                or os.pread(self.fd, _LIMIT + 1, 0) != bytes(self.body)
                or _generation(os.stat(self.path.name, dir_fd=self.directory.fd,
                                       follow_symlinks=False)) != _generation(info)):
            raise ValueError('output changed')
        self.directory.guard()
        return {'sha256': session._sha(bytes(self.body)), 'fingerprint': session._fp(info)}

    def close(self):
        os.close(self.fd)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def _collect(history, fence, out, err, value):
    """Bound both live streams; never signal a process or replay a control exit."""
    argv = history.exit_argv()
    process = None
    outcome, code = 'error', None
    try:
        history.live()
        history.guard()
        fence.guard()
        if session._socket(history.path, value['parentIdentity']) != value['socketFingerprint']:
            raise ValueError('socket changed')
        out.pin(); err.pin(); fence.guard()
        history.final_generations()
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
        deadline = time.monotonic() + _TIMEOUT
        with selectors.DefaultSelector() as selector:
            for stream, destination in ((process.stdout, out), (process.stderr, err)):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, destination)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(argv, _TIMEOUT)
                for key, _ in selector.select(remaining):
                    # One extra byte detects overflow without buffering it.
                    data = os.read(key.fileobj.fileno(), _LIMIT - len(key.data.body) + 1)
                    if data:
                        key.data.append(data)
                    else:
                        selector.unregister(key.fileobj)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(argv, _TIMEOUT)
            code = process.wait(timeout=remaining)
            outcome = 'completed'
    except subprocess.TimeoutExpired as error:
        # Usually streams were already durably copied. Preserve partial bytes
        # too if the process boundary supplied them before failing.
        for destination, partial in ((out, error.output), (err, error.stderr)):
            if partial and not destination.body:
                destination.append(partial[:_LIMIT])
        outcome = 'timeout'
    except OverflowError:
        outcome = 'overflow'
    except (OSError, ValueError, subprocess.SubprocessError):
        outcome = 'error'
    finally:
        if process is not None:
            for stream in (process.stdout, process.stderr):
                if stream is not None:
                    stream.close()
            if code is None:
                code = process.poll()
    return outcome, code


def _absence(pid, path, parent):
    if type(pid) is not int or pid <= 0:
        raise ValueError('positive original pid')
    if session._directory(path.parent) != parent or os.path.lexists(path):
        raise ValueError('socket present')
    result = subprocess.run(['/bin/ps', '-p', str(pid), '-o', 'pid='], stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=3, check=False)
    if result.returncode != 1 or result.stdout != b'' or result.stderr != b'':
        raise ValueError('pid present or unknown')
    if session._directory(path.parent) != parent or os.path.lexists(path):
        raise ValueError('absence changed')


def close(root: Path | str, host: str, receipt_sha256: str) -> dict[str, Any]:
    try:
        presented = PresentedPath(Path(root).absolute())
        paths = _paths(root, host, receipt_sha256)
        root, _, journal, intent_path, out_path, err_path, terminal_path = paths
        with ExitStack() as stack:
            history = _History(stack, root, host, receipt_sha256, journal)
            history.presented = presented
            history.guard()
            if os.path.lexists(intent_path):
                return _unknown(host)
            history.live()
            value = _intent(history, root, host, receipt_sha256)
            _create(history.group, intent_path, value)
            fence = history.capture(intent_path)
            if not _same(fence.value(), value):
                raise ValueError('close fence')
            with _Output(history.group, out_path) as out, _Output(history.group, err_path) as err:
                outcome, code = _collect(history, fence, out, err, value)
                terminal = {'version': 1, 'intentPin': fence.pin, 'outcome': outcome,
                            'returnCode': code, 'stdout': out.pin(), 'stderr': err.pin()}
                _create(history.group, terminal_path, terminal)
                terminal_capture = history.capture(terminal_path)
                if not _same(terminal_capture.value(), terminal):
                    raise ValueError('terminal changed')
                history.guard()
                out.pin(); err.pin(); fence.guard(); terminal_capture.guard()
                return {'state': 'exit_sent' if outcome == 'completed' and code == 0 else 'unknown',
                        'host': host, 'receiptSha256': receipt_sha256, 'replayAllowed': False}
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError):
        return _unknown(host)


def status(root: Path | str, host: str, receipt_sha256: str) -> dict[str, Any]:
    try:
        presented = PresentedPath(Path(root).absolute())
        root, _, journal, intent_path, out_path, err_path, terminal_path = _paths(root, host, receipt_sha256)
        with ExitStack() as stack:
            history = _History(stack, root, host, receipt_sha256, journal)
            history.presented = presented
            history.guard()
            expected = _intent(history, root, host, receipt_sha256)
            fence = history.capture(intent_path)
            if not _same(fence.value(), expected):
                raise ValueError('close binding')
            terminal = history.capture(terminal_path)
            out = history.capture(out_path, limit=_LIMIT)
            err = history.capture(err_path, limit=_LIMIT)
            if not _same(terminal.value(), {'version': 1, 'intentPin': fence.pin, 'outcome': 'completed',
                                    'returnCode': 0, 'stdout': out.pin, 'stderr': err.pin}):
                raise ValueError('close terminal')
            _absence(expected['pid'], history.path, expected['parentIdentity'])
            history.guard()
            # Includes original history, output, intent, terminal, source,
            # config, lock, held and named ancestry, after the absence query.
            fence.guard(); terminal.guard(); out.guard(); err.guard()
            history.final_generations()
            if os.path.lexists(history.path):
                raise ValueError('socket reappeared')
            history.socket_parent.guard()
            return {'state': 'closed', 'host': host, 'receiptSha256': receipt_sha256,
                    'replayAllowed': False}
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError):
        return _unknown(host)
