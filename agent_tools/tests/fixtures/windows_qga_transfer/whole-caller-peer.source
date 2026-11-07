"""Execute an entire saved caller against in-memory Linux and RPC peers.

The caller is never rewritten, split, pre-executed, or patched after exec.
Only import/open boundary peers are substituted; no caller globals are seeded.
All host state is synthetic.  This is Python orchestration qualification, not
PowerShell, Windows, native token, or product acceptance.
"""
from __future__ import annotations

import ast
import base64
import builtins
import collections
import contextlib
import hashlib
import io
import json
import os
import pathlib
import posixpath
import socket
import stat
import struct
import subprocess
import sys
import traceback
import types

HERE = pathlib.Path(__file__).resolve().parent
REAL_IMPORT = builtins.__import__


def literals(source):
    """Read fixture declarations without executing any caller namespace."""
    values = {}
    for item in ast.parse(source).body:
        if isinstance(item, ast.Assign) and len(item.targets) == 1 and isinstance(item.targets[0], ast.Name):
            try:
                values[item.targets[0].id] = ast.literal_eval(item.value)
            except (ValueError, TypeError):
                pass
    return values


class PeerWorld:
    def __init__(self, declarations, guest_results):
        self.spec = declarations['SPEC']
        self.setup = declarations['SETUP']
        self.context = declarations['CONTEXT']
        self.root = self.spec['root']
        self.uid = 1000
        self.nodes = {}
        self.fds = {}
        self.next_fd = 20
        self.next_inode = 100
        self.events = []
        self.rpc = []
        self.imports = []
        self.time_now = 100.0
        self.guest_results = list(guest_results)
        self.executions = []
        self.status_counts = collections.Counter()
        self.sockets = []
        self._fixture()
        self.os = self._os_module()
        self.socket = self._socket_module()
        self.time = types.ModuleType('time')
        self.time.monotonic = lambda: self.time_now
        self.time.sleep = self.sleep

    def sleep(self, seconds):
        self.time_now += seconds
        self.events.append(['sleep', seconds])

    def node(self, path, data=b'', *, mode=stat.S_IFREG | 0o600, uid=1000, size=None, ino=None):
        path = str(path)
        self.next_inode += 1
        self.nodes[path] = dict(data=bytearray(data), mode=mode, uid=uid, gid=1000,
                                ino=ino or self.next_inode, size=size, nlink=1)
        return self.nodes[path]

    def info(self, path):
        path = str(path)
        if path not in self.nodes:
            raise FileNotFoundError(path)
        node = self.nodes[path]
        return types.SimpleNamespace(st_dev=17, st_ino=node['ino'], st_mode=node['mode'],
            st_uid=node['uid'], st_gid=node['gid'], st_nlink=node['nlink'],
            st_size=len(node['data']) if node['size'] is None else node['size'],
            st_mtime_ns=123456, st_ctime_ns=123456)

    def generation(self, path):
        s = self.info(path)
        return [s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid, s.st_nlink,
                s.st_size, s.st_mtime_ns, s.st_ctime_ns]

    def structure(self, path):
        return self.generation(path)[:5]

    def jnode(self, path, value):
        return self.node(path, (json.dumps(value, sort_keys=True) + '\n').encode())

    def _fixture(self):
        for path in reversed(list(pathlib.PurePosixPath(self.root).parents)):
            self.node(str(path), mode=stat.S_IFDIR | 0o755, uid=0 if str(path) in ('/', '/home') else self.uid)
        self.node(self.root, mode=stat.S_IFDIR | 0o700)
        for name in ('disk.qcow2', 'uefi-vars.fd'):
            self.node(self.root + '/' + name, b'inert-owned-artifact')
        self.jnode(self.root + '/mutable-artifacts.json', {
            name: self.structure(self.root + '/' + name) for name in ('disk.qcow2', 'uefi-vars.fd')})
        self.qpid, self.tpid = 3823747, 3823746
        self.proc_rows = {}
        for pid, ticks, executable in ((self.qpid, 137277120, 'qemu-inert'), (self.tpid, 137277110, 'swtpm-inert')):
            proc = '/proc/' + str(pid)
            self.node(proc, mode=stat.S_IFDIR | 0o555)
            self.node(proc + '/stat', (str(pid) + ' (inert process) ' + ' '.join(['S'] + ['0'] * 18 + [str(ticks)])).encode())
            raw = executable.encode() + b'\0'
            self.node(proc + '/cmdline', raw)
            self.node(proc + '/exe', b'inert-executable', mode=stat.S_IFREG | 0o755)
            row = dict(pid=pid, startTicks=ticks, argv=[executable], commandSha256=hashlib.sha256(raw).hexdigest(),
                       executableGeneration=self.generation(proc + '/exe'))
            self.proc_rows[pid] = row
        self.jnode(self.root + '/qemu-started.json', self.proc_rows[self.qpid])
        self.jnode(self.root + '/swtpm-started.json', self.proc_rows[self.tpid])
        self.links = {}
        sockrows = ['Num RefCount Protocol Flags Type St Inode Path']
        for index, (name, pid) in enumerate((('qmp.sock', self.qpid), ('qga.sock', self.qpid), ('swtpm.sock', self.tpid)), 1):
            path = self.root + '/' + name
            self.node(path, mode=stat.S_IFSOCK | 0o600)
            self.links[f'/proc/{pid}/fd/{index + 2}'] = f'socket:[{700 + index}]'
            sockrows.append(f'0: 00000002 00000000 00010000 0001 01 {700 + index} {path}')
        self.node('/proc/net/unix', ('\n'.join(sockrows) + '\n').encode())
        for index, name in enumerate(('disk.qcow2', 'uefi-vars.fd'), 10):
            path = f'/proc/{self.qpid}/fd/{index}'
            self.nodes[path] = self.nodes[self.root + '/' + name]
            self.links[path] = self.root + '/' + name
        identities = {}
        self.fdsets = []
        for index, name in enumerate(('firmwareCode', 'installer', 'drivers'), 1):
            fd = 20 + index
            path = f'/proc/{self.qpid}/fd/{fd}'
            self.node(path, size=self.spec['assets'][name]['bytes'])
            self.links[path] = self.spec['assets'][name]['path']
            identities[name] = {'set': index, 'generation': self.generation(path)}
            self.fdsets.append({'fdset-id': index, 'fds': [{'fd': fd, 'opaque': 'asset:' + name}]})
        self.jnode(self.root + '/intent.json', dict(schemaVersion=1, spec=self.spec, setup=self.setup,
            hostBootId=self.context['hostBootId'], rootIdentity=self.structure(self.root), assetIdentities=identities))

    def resolve(self, path, dir_fd=None):
        path = os.fsdecode(path)
        if not path.startswith('/'):
            if dir_fd is None:
                raise AssertionError('relative ambient path refused: ' + path)
            path = posixpath.join(self.fds[dir_fd]['path'], path)
        return posixpath.normpath(path)

    def open_fd(self, path, flags, mode=0o777, *, dir_fd=None):
        path = self.resolve(path, dir_fd)
        if flags & os.O_CREAT:
            if not path.startswith(self.root + '/'):
                raise AssertionError('write outside inert instance: ' + path)
            if path in self.nodes and flags & os.O_EXCL:
                raise FileExistsError(path)
            if path not in self.nodes:
                self.node(path, mode=stat.S_IFREG | mode)
        self.info(path)
        self.next_fd += 1
        self.fds[self.next_fd] = {'path': path, 'offset': 0, 'flags': flags}
        self.events.append(['open', path, flags])
        return self.next_fd

    def close_fd(self, fd):
        self.events.append(['close', fd])
        del self.fds[fd]

    def read_fd(self, fd, size):
        row = self.fds[fd]
        data = self.nodes[row['path']]['data']
        result = bytes(data[row['offset']:row['offset'] + size])
        row['offset'] += len(result)
        return result

    def write_fd(self, fd, data):
        row = self.fds[fd]
        if not row['flags'] & (os.O_WRONLY | os.O_RDWR):
            raise AssertionError('write to inert read-only descriptor')
        node = self.nodes[row['path']]
        start = row['offset']
        node['data'][start:start + len(data)] = data
        row['offset'] += len(data)
        self.events.append(['write', row['path'], len(data)])
        return len(data)

    def builtin_open(self, path, mode='r', *args, **kwargs):
        if mode not in ('r', 'rb'):
            raise AssertionError('unexpected builtins.open mode: ' + mode)
        path = self.resolve(path)
        self.events.append(['builtin-open', path])
        self.info(path)
        raw = bytes(self.nodes[path]['data'])
        return io.BytesIO(raw) if 'b' in mode else io.StringIO(raw.decode())

    def _os_module(self):
        module = types.ModuleType('os')
        for name in ('O_RDONLY', 'O_WRONLY', 'O_RDWR', 'O_DIRECTORY', 'O_NOFOLLOW', 'O_NONBLOCK', 'O_CREAT', 'O_EXCL'):
            setattr(module, name, getattr(os, name))
        module.open = self.open_fd
        module.close = self.close_fd
        module.read = self.read_fd
        module.write = self.write_fd
        module.fsync = lambda fd: self.events.append(['fsync', fd])
        module.geteuid = lambda: self.uid
        module.fsencode = os.fsencode
        module.urandom = lambda count: b'\x01' * count
        module.lstat = lambda path: self.info(self.resolve(path))
        module.stat = lambda path, *, dir_fd=None, follow_symlinks=True: self.info(self.resolve(path, dir_fd))
        module.fstat = lambda fd: self.info(self.fds[fd]['path'])
        module.listdir = lambda path: sorted({p[len(str(path)) + 1:].split('/')[0] for p in self.links if p.startswith(str(path) + '/')})
        module.readlink = lambda path: self.links[str(path)]
        return module

    def _socket_module(self):
        module = types.ModuleType('socket')
        for name in ('AF_UNIX', 'SOCK_STREAM', 'SOL_SOCKET'):
            setattr(module, name, getattr(socket, name))
        module.SO_PEERCRED = 17
        module.socket = lambda *args, **kwargs: PeerSocket(self)
        return module

    def import_peer(self, name, globals=None, locals=None, fromlist=(), level=0):
        self.imports.append({'name': name, 'fromlist': list(fromlist or ()), 'level': level})
        if level:
            raise AssertionError('relative import refused')
        if name in ('os', 'socket', 'time'):
            return getattr(self, name)
        if name in ('subprocess', 'shutil', 'pwd', 'select', 'tempfile'):
            # Present in the real saved namespaces, not called in these flows.
            peer = types.ModuleType(name)
            if name == 'subprocess':
                # Pure stdlib Windows argv serialization only. No process API
                # (Popen/run/call/etc.) exists on the inert imported module.
                peer.list2cmdline = subprocess.list2cmdline
            return peer
        allowed = {'contextlib', 'hashlib', 'io', 'json', 'pathlib', 're', 'stat', 'struct',
                   'sys', 'base64', 'secrets', 'gzip'}
        if name not in allowed:
            raise AssertionError('unqualified import refused: ' + name)
        return REAL_IMPORT(name, globals, locals, fromlist, level)

    def rpc_reply(self, request):
        command = request['execute']
        arguments = request.get('arguments', {})
        self.rpc.append({'command': command, 'arguments': arguments})
        if command == 'guest-sync-delimited':
            return arguments['id']
        if command in ('qmp_capabilities', 'guest-ping'):
            return {}
        if command == 'query-status':
            return {'status': 'running'}
        if command == 'query-fdsets':
            return self.fdsets
        if command == 'guest-get-osinfo':
            return {'pretty-name': 'inert Windows fixture'}
        if command == 'guest-get-users':
            return [{'user': self.setup['user']}]
        if command == 'guest-info':
            return {'version': 'inert', 'supported_commands': []}
        if command == 'guest-exec':
            index = len(self.executions)
            if index >= len(self.guest_results):
                raise AssertionError('unexpected guest-exec, no inert result allocated')
            pid = 9000 + index
            self.executions.append({'pid': pid, 'arguments': arguments, 'result': self.guest_results[index]})
            return {'pid': pid}
        if command == 'guest-exec-status':
            pid = arguments['pid']
            row = next(r for r in self.executions if r['pid'] == pid)
            self.status_counts[pid] += 1
            if self.status_counts[pid] == 1:
                return {'exited': False}
            result = row['result']
            if isinstance(result, dict) and 'exited' in result:
                return result
            return {'exited': True, 'exitcode': 0,
                    'out-data': base64.b64encode(json.dumps(result).encode()).decode(), 'err-data': ''}
        raise AssertionError('unqualified RPC command: ' + command)


class PeerSocket:
    def __init__(self, world):
        self.world = world
        self.buffer = bytearray()
        self.path = None
        self.closed = False
        world.sockets.append(self)

    def settimeout(self, value):
        if value <= 0:
            raise AssertionError('invalid inert timeout')

    def connect(self, path):
        self.path = path
        self.world.info(path)
        if path.endswith('/qmp.sock'):
            self.buffer.extend(b'{"QMP":{}}\n')
        elif not path.endswith('/qga.sock'):
            raise AssertionError('unqualified socket path')

    def getsockopt(self, *args):
        return struct.pack('3i', self.world.qpid, self.world.uid, 1000)

    def makefile(self, *args, **kwargs):
        return self

    def sendall(self, data):
        request = json.loads(data.lstrip(b'\xff'))
        result = self.world.rpc_reply(request)
        response = {'return': result}
        if 'id' in request:
            response['id'] = request['id']
        prefix = b'\xff' if request['execute'] == 'guest-sync-delimited' else b''
        self.buffer.extend(prefix + json.dumps(response).encode() + b'\n')

    def write(self, data):
        self.sendall(data)
        return len(data)

    def recv(self, count):
        result = bytes(self.buffer[:count])
        del self.buffer[:count]
        return result

    def readline(self, count):
        end = self.buffer.find(b'\n') + 1
        if end == 0:
            end = len(self.buffer)
        return self.recv(min(count, end))

    def close(self):
        self.closed = True


def default_guest_results(path):
    declarations = literals(pathlib.Path(path).read_text())
    operation = declarations.get('OPERATION')
    if 'INITIALIZE_SCRIPT' in declarations:
        results = [{'state': 'created', 'principal': 'S-1-5-18'}]
        results.extend({'state': 'staged', 'path': name, 'bytes': len(data),
            'sha256': hashlib.sha256(data).hexdigest(), 'createNew': True} for name, data in declarations['FILES'])
        return results + [{'state': 'qualified', 'operationId': operation, 'productOperation': False}]
    if 'instance_context_nonce' in pathlib.Path(path).read_text():
        return [{'nonce': operation, 'principal': 'S-1-5-18',
                 'explorer': {'sid': 'S-1-5-21-4099058025-2437077614-260217637-1001'}}]
    return [{'state': 'observed', 'operationId': operation, 'readOnly': True, 'productOperation': False}]


def qualify(path, guest_results, expected_guest_exec_count, *, label=None, post_exec=None):
    path = pathlib.Path(path).resolve()
    source = path.read_bytes()
    digest = hashlib.sha256(source).hexdigest()
    world = PeerWorld(literals(source.decode()), guest_results)
    namespace = {'__name__': '__main__', '__file__': str(path)}
    ordinary_builtins = dict(vars(builtins))
    ordinary_builtins['__import__'] = world.import_peer
    ordinary_builtins['open'] = world.builtin_open
    namespace['__builtins__'] = ordinary_builtins
    output, error_output = io.StringIO(), io.StringIO()
    calls, lines = collections.Counter(), set()
    error = None
    post_exec_observations = None

    def trace(frame, event, arg):
        if frame.f_code.co_filename == str(path):
            if event == 'call':
                calls[frame.f_code.co_name] += 1
            elif event == 'line':
                lines.add(frame.f_lineno)
        return trace

    prior_trace = sys.gettrace()
    try:
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(error_output):
            sys.settrace(trace)
            exec(compile(source, str(path), 'exec'), namespace, namespace)
            if post_exec is not None:
                # Call actual pure definitions only after the complete original
                # module flow; never seed globals or replace its definitions.
                original_keys = set(namespace)
                original_functions = {k: v for k, v in namespace.items() if isinstance(v, types.FunctionType)}
                original_builtins = dict(ordinary_builtins)
                post_exec_observations = post_exec(namespace, world)
                assert set(namespace) == original_keys, 'post-exec callback changed namespace keys'
                assert all(namespace[k] is v for k, v in original_functions.items()), 'post-exec callback replaced caller function'
                assert ordinary_builtins.keys() == original_builtins.keys() and all(
                    ordinary_builtins[k] is v for k, v in original_builtins.items()), 'post-exec callback changed builtins'
    except BaseException as caught:
        error = {'class': type(caught).__name__, 'message': str(caught), 'traceback': traceback.format_exc()}
    finally:
        sys.settrace(prior_trace)
    actual_count = len(world.executions)
    assert actual_count == expected_guest_exec_count, (actual_count, expected_guest_exec_count, error)
    assert not world.fds, ('caller leaked inert file handles', world.fds)
    assert all(s.closed for s in world.sockets), 'caller leaked inert sockets'
    try:
        serialized = [json.loads(line) for line in output.getvalue().splitlines()]
    except ValueError:
        serialized = []
    receipt = dict(schemaVersion=1, source=str(path), sourceSha256=digest, sourceBytes=len(source),
        initialGlobals=['__name__', '__file__', '__builtins__'],
        seams=['imported os/socket/time inert modules', 'builtins.open inert read-only files',
               'side-effect imports are trap modules; subprocess exposes only stdlib list2cmdline'],
        sourceUnmodified=True, partialNamespaceExecution=False, postExecFunctionReplacement=False,
        imports=world.imports, functions=dict(calls), coveredLines=sorted(lines),
        guestExecCount=actual_count, guestMutationObservedInInertPeer=actual_count > 0,
        nativeOrNetworkActivity=False, error=error, stdout=output.getvalue(), stderr=error_output.getvalue(),
        postExecObservations=post_exec_observations,
        serialized=serialized, rpc=world.rpc, hostBoundaryEvents=world.events,
        guestExecStatusCounts=dict(world.status_counts), allHandlesClosed=True,
        writes={p: {'bytes': len(n['data']), 'sha256': hashlib.sha256(n['data']).hexdigest(),
                    'base64': base64.b64encode(n['data']).decode()}
                for p,n in world.nodes.items() if p.startswith(world.root + '/') and
                any(e[0] == 'write' and e[1] == p for e in world.events)})
    label = label or path.stem + '-' + digest[:12]
    if '/' in label or label in ('.', '..'):
        raise ValueError('invalid receipt label')
    destination = HERE / 'cases' / label
    destination.mkdir(parents=True, exist_ok=False, mode=0o700)
    (destination / 'caller.py').write_bytes(source)
    (destination / 'receipt.json').write_text(json.dumps(receipt, sort_keys=True, indent=2) + '\n')
    return receipt


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('path')
    parser.add_argument('--guest-results')
    parser.add_argument('--expected-guest-exec-count', type=int)
    parser.add_argument('--label')
    args = parser.parse_args()
    results = json.loads(pathlib.Path(args.guest_results).read_text()) if args.guest_results else default_guest_results(args.path)
    count = args.expected_guest_exec_count if args.expected_guest_exec_count is not None else len(results)
    result = qualify(args.path, results, count, label=args.label)
    print(json.dumps({k: result[k] for k in ('sourceSha256', 'guestExecCount', 'error', 'functions', 'serialized')}, indent=2))
    raise SystemExit(1 if result['error'] else 0)
