"""Finite whole-qualifier receipt-routing pairs with declared inert IO seams."""
from __future__ import annotations

import builtins
import contextlib
import hashlib
import importlib.util
from importlib.machinery import SourceFileLoader
import inspect
import io
import json
import os
from pathlib import Path
import socket
import sys
import types
from unittest import mock


HERE = Path(__file__).parent
OUTER = Path('.runtime/windows-parity-20261019/windows-visual-context/minimum-uac-foundation-v2/outer-preparation-v1')
PINS = {
    'normal': '5611366787f5dc4f69f586ac9c1f6da7978cb76ab11005fdec08f9ed27f99b87',
    'stdout-eof': '5a19d3381c800ac4fd4fcafda0dfa3bc094afcf7250143025d70e95d3ba69db8',
    'dual-eof': '5a19d3381c800ac4fd4fcafda0dfa3bc094afcf7250143025d70e95d3ba69db8',
    'current': '7434e64bc639dcaefb79d25cabc2f6ab1a4e1a9b31735b7cc2b13b116c5a4945',
}
METHODS = {
    'normal': 'test_direct_complete_entry_live_callback_and_control_carriers',
    'stdout-eof': 'test_pending_stdout_eof_waits_for_original_terminal',
    'dual-eof': 'test_pending_dual_eof_waits_for_original_terminal',
}


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _generation(row):
    return (row.st_dev, row.st_ino, row.st_mode, row.st_uid, row.st_gid,
        row.st_nlink, row.st_size, row.st_mtime_ns, row.st_ctime_ns)


def _put(path, raw):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, 'wb', closefd=False) as stream:
            stream.write(raw)
    finally:
        os.close(fd)


def _one(raw, variant, root, live, metadata):
    root.mkdir(mode=0o700)
    staged = {}
    for row in metadata['sources']:
        if 'stagePath' not in row:
            continue
        relative = row['stagePath']
        if relative in live:
            source = live[relative]['raw']
        else:
            source = (HERE / row['fixture']).read_bytes()
            if _sha(source) != row['sha256']:
                raise ValueError('routing_private_fixture_pin:' + relative)
        _put(root / relative, source)
        staged[relative] = source
    for relative, row in live.items():
        if relative not in staged:
            _put(root / relative, row['raw'])
            staged[relative] = row['raw']
    source_path = root / OUTER / 'uac_outer_operator.py'
    _put(source_path, raw)
    staged[str(OUTER / 'uac_outer_operator.py')] = raw
    qualifier_path = root / OUTER / 'qualify_outer_entry.py'
    if _sha(qualifier_path.read_bytes()) != 'ec500429b601e5485f19c4e3eed8e31e237a24117e0036546654d4bd4a060c8e':
        raise ValueError('routing_complete_qualifier_pin')
    old_modules = dict(sys.modules)
    old_packages = {name: dict(vars(module)) for name, module in old_modules.items()
        if name.startswith('agent_tools') and hasattr(module, '__path__')}
    old_path = list(sys.path)
    old_argv = list(sys.argv)
    original_import = builtins.__import__
    original_patch_object = mock.patch.object
    owners = []
    observed_initializers = []
    listeners = []
    mock_peer = types.ModuleType('unittest.mock')
    mock_peer.__dict__.update(vars(mock))

    @contextlib.contextmanager
    def capture_owner(target, initialize):
        # Preserve the authentic oracle's capture list through a trace observer.
        # Its original constructor is never replaced or called twice.
        captured = inspect.getclosurevars(initialize).nonlocals['owners']
        code = target.__init__.__code__
        observed_initializers.append(target.__init__)
        previous = sys.gettrace()
        def trace(frame, event, arg):
            if frame.f_code is code and event == 'return':
                owner = frame.f_locals['self']
                captured.append(owner)
                owners.append(owner)
            if previous is not None:
                previous(frame, event, arg)
            return trace
        sys.settrace(trace)
        try:
            yield
        finally:
            sys.settrace(previous)

    class PatchPeer:
        def __call__(self, *args, **kwargs):
            return mock.patch(*args, **kwargs)
        def object(self, target, attribute, *args, **kwargs):
            if (attribute == '__init__' and isinstance(target, type)
                and target.__module__ == '_uac_outer_whole_entry'):
                if len(args) != 1 or kwargs:
                    raise ValueError('routing_capture_boundary')
                return capture_owner(target, args[0])
            return original_patch_object(target, attribute, *args, **kwargs)
    mock_peer.patch = PatchPeer()

    def imported(name, globals=None, locals=None, fromlist=(), level=0):
        if (name == 'unittest.mock' and globals is not None
            and globals.get('__file__') == str(qualifier_path)):
            return mock_peer
        return original_import(name, globals, locals, fromlist, level)

    class Listener:
        def __init__(self, family, *args, **kwargs):
            if family != socket.AF_UNIX or args or kwargs:
                raise ValueError('routing_unexpected_socket')
            self.closed = False
            self.path = None
            listeners.append(self)
        def bind(self, path):
            self.path = str(path)
        def close(self):
            self.closed = True

    capture = io.StringIO()
    spec = importlib.util.spec_from_file_location('__main__', qualifier_path,
        loader=SourceFileLoader('__main__', str(qualifier_path)))
    module = importlib.util.module_from_spec(spec)
    sys.modules['__main__'] = module
    sys.argv = [str(qualifier_path), 'EntryQualification.' + METHODS[variant]]
    error = None
    exit_code = None
    cleanup_fds = []
    try:
        with mock.patch.object(builtins, '__import__', side_effect=imported), \
             mock.patch.object(socket, 'socket', Listener), \
             contextlib.redirect_stdout(capture), contextlib.redirect_stderr(capture):
            try:
                spec.loader.exec_module(module)
            except SystemExit as exc:
                exit_code = int(exc.code or 0)
            except BaseException as exc:
                error = {'class': type(exc).__name__, 'reason': str(exc)}
        reports = list((root / OUTER).glob('whole-entry-inert-*/*.json'))
        if len(reports) != 1:
            raise ValueError('routing_single_original_report:' + repr(error) + ':' + capture.getvalue())
        report = json.loads(reports[0].read_bytes())
        if len(owners) != 1:
            raise ValueError('routing_original_owner_capture')
        owner = owners[0]
        methods_unchanged = (owner.__class__.__init__ is observed_initializers[0])
        registered = (sys.modules.get(module.engine.__name__) is module.engine
            and sys.modules.get(module.fresh.__name__) is module.fresh
            and sys.modules.get(module.fresh.inert.MODULE.__name__) is module.fresh.inert.MODULE
            and sys.modules.get(owner.prefix.__name__) is owner.prefix)
        # A failed positive oracle stops before its normal outer-descriptor
        # cleanup. All actors here are already-returned inert peers. Release only
        # these owned test resources after retaining the original failure report.
        for reader in owner.streams.values():
            if not reader.closed:
                cleanup_fds.extend(reader._held)
                reader.close_known(terminal=True)
        cleanup_fds.extend(fd for fd, path, row in owner.held.files)
        for fd, path, row in reversed(owner.held.files):
            os.close(fd)
        owner.held.files = []
        closed = []
        for fd in cleanup_fds:
            try:
                os.fstat(fd)
            except OSError as exc:
                if exc.errno == 9:
                    closed.append(fd)
        unchanged = all((root / path).read_bytes() == source for path, source in staged.items())
        return {
            'variant': variant, 'exitCode': exit_code, 'error': error,
            'output': capture.getvalue(), 'report': report,
            'operatorSha256': _sha(raw), 'qualifierSha256': _sha(qualifier_path.read_bytes()),
            'completeNormallyRegisteredNamespaces': registered,
            'originalConstructorUnchanged': methods_unchanged,
            'sourcesUnchanged': unchanged,
            'ownedTestCleanupDescriptors': cleanup_fds,
            'ownedTestCleanupClosedDescriptors': closed,
            'allOwnedFixtureListenersClosed': bool(listeners) and all(item.closed for item in listeners),
            'actualSocketCalls': 0, 'actualRemoteOrNativeActions': False,
            'boundary': 'physical owned source tree, canonical current read inputs, capture-only trace observer, inert unused fixture socket IO; complete authentic qualifier/source functions unchanged',
        }
    finally:
        sys.argv = old_argv
        sys.path[:] = old_path
        for name, package in list(sys.modules.items()):
            if not name.startswith('agent_tools') or not hasattr(package, '__path__'):
                continue
            for key, value in list(vars(package).items()):
                filename = getattr(value, '__file__', '')
                if (isinstance(value, types.ModuleType) and isinstance(filename, str)
                    and (filename.startswith(str(root))
                         or (name == 'agent_tools.tests' and key == 'test_windows_vm_guest'))):
                    if key in old_packages.get(name, {}):
                        setattr(package, key, old_packages[name][key])
                    else:
                        delattr(package, key)
        for name, value in list(sys.modules.items()):
            filename = getattr(value, '__file__', '')
            if name in ('__main__', 'agent_tools.tests.test_windows_vm_guest') or (isinstance(filename, str) and filename.startswith(str(root))) or name.startswith(('_uac_', 'private_uac', 'uac_candidate_inert')):
                if name in old_modules:
                    sys.modules[name] = old_modules[name]
                else:
                    sys.modules.pop(name, None)


def run_routing_pair(before, current, variant, repo_root, directory):
    if variant not in METHODS or _sha(before) != PINS[variant] or _sha(current) != PINS['current']:
        raise ValueError('routing_operator_source_pin')
    metadata = json.loads((HERE / 'provenance.private.json').read_bytes())
    live = {}
    for relative in metadata['liveCanonicalSourcePaths']:
        path = Path(repo_root) / relative
        before_generation = _generation(path.stat())
        raw = path.read_bytes()
        if _generation(path.stat()) != before_generation:
            raise ValueError('routing_current_source_changed')
        live[relative] = {'raw': raw, 'generation': before_generation, 'sha256': _sha(raw)}
    directory = Path(directory).resolve()
    result = {
        'before': _one(before, variant, directory / 'before', live, metadata),
        'after': _one(current, variant, directory / 'after', live, metadata),
    }
    for relative, pin in live.items():
        path = Path(repo_root) / relative
        if _generation(path.stat()) != pin['generation'] or _sha(path.read_bytes()) != pin['sha256']:
            raise ValueError('routing_current_source_changed')
    result['liveCanonicalSourcePins'] = {name: {'sha256': pin['sha256'], 'bytes': len(pin['raw'])} for name, pin in live.items()}
    return result
