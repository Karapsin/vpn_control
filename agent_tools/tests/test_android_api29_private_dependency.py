"""Frozen API29 factories keep their closed historical private dependency.

The real constructor and complete generated receiver run against explicit
synthetic upstream custody. Public CLI/ADB boundaries use real child processes
and loopback sockets; no native history, VM, SSH or private input is accessed.
"""
import hashlib
import json
from pathlib import Path
import socketserver
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from agent_tools import android_api29_current_epoch_diagnostics as epoch
from agent_tools import private_inventory_lock as current_private
from agent_tools.tests import test_android_api29_current_epoch_diagnostics as epoch_tests
from agent_tools.tests.fixtures import historical_source
from agent_tools.tests.fixtures.android_api29_epoch import context as fixture


_BEFORE_SHA = '209a9b4c12896bc444de022c14b356ad5909d61884e151a4e4d09f9a22b97583'
_CLIENT = r'''import json,socket,sys
request=json.loads(sys.stdin.buffer.read(16385))
with socket.create_connection(('127.0.0.1',request.pop('port')),timeout=5)as connection:
 connection.sendall(json.dumps(request).encode()+b'\n');raw=b''
 while not raw.endswith(b'\n'):
  chunk=connection.recv(4096)
  if not chunk:raise SystemExit(3)
  raw+=chunk
  if len(raw)>16384:raise SystemExit(4)
sys.stdout.buffer.write(raw)
'''


class _Receiver(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self):
        self.calls = []; self.ledger = []; self.lock = threading.Lock()
        self.binding = epoch_tests.binding()
        self.terminal = {'ok': True, 'final': True, 'code': 'OK',
            'requestId': self.binding['requestId'], 'controllerId': epoch.OWNER,
            'configurationRevision': 0, 'operationId': epoch_tests.prior.OP,
            'restartRequired': False, 'warnings': [],
            'data': {'content': '[runtime]\nmode=VPN\nvpn_permission_granted=false\nis_vpn_running=false\n'}}
        super().__init__(('127.0.0.1', 0), _Request)
        self.thread = threading.Thread(target=self.serve_forever, daemon=True); self.thread.start()

    def close(self):
        self.shutdown(); self.server_close(); self.thread.join(timeout=5)

    def handle(self, value):
        with self.lock:
            self.calls.append(value)
            words = value['words']
            if value['kind'] == 'cli':
                if words[:2] == ['operations', 'status']:
                    if words != ['operations', 'status', self.terminal['operationId']]: raise ValueError('unexpected fixed operation')
                    return {'returncode': 0, 'stdout': {**self.terminal, 'requestId': 'status-request', 'data': {}}}
                if words not in (['status'], ['operations', 'list']): raise ValueError('unexpected public read')
                return {'returncode': 0, 'stdout': {'ok': True, 'final': True, 'code': 'OK',
                    'controllerId': epoch.OWNER, 'configurationRevision': 0,
                    'data': {'runtimeRunning': False, 'runtimeObservation': 'stopped', 'configuredMode': 'vpn',
                             'operations': self.ledger if words == ['operations', 'list'] else []}}}
            if value['kind'] != 'adb': raise ValueError('unexpected transport')
            uri = 'content://com.kardinal.vpncontrol.control'; transfer = epoch_tests.prior.TRANSFER
            if words == ['call', '--uri', uri, '--method', 'create']:
                return 'Result: Bundle[{id='+transfer+', controllerId='+epoch.OWNER+', requestUri='+uri+'/requests/'+transfer+', resultUri='+uri+'/results/'+transfer+'}]\n'
            if words == ['write', '--uri', uri+'/requests/'+transfer]:
                if value['payload'] != self.binding['requestBytes'] or self.ledger: raise ValueError('duplicate or changed fixed request')
                self.ledger.append({'controllerId': epoch.OWNER, 'id': self.terminal['operationId'],
                    'requestId': self.binding['requestId'], 'operation': 'diagnostics.export', 'phase': 'succeeded',
                    'final': True, 'cancellable': False, 'completedUnits': None, 'totalUnits': None,
                    'code': 'OK', 'configurationRevision': 0, 'restartRequired': False})
                return ''
            if words == ['call', '--uri', uri, '--method', 'status', '--arg', transfer]: return 'Result: Bundle[{state=complete}]\n'
            if words == ['read', '--uri', uri+'/results/'+transfer] and self.ledger: return json.dumps(self.terminal)
            raise ValueError('unexpected fixed content action')


class _Request(socketserver.StreamRequestHandler):
    def handle(self):
        self.connection.settimeout(5); raw = self.rfile.readline(16385)
        if len(raw) > 16384 or not raw.endswith(b'\n'): return
        value = self.server.handle(json.loads(raw))
        self.wfile.write(json.dumps(value).encode()+b'\n')


class HistoricalPrivateDependencyTests(unittest.TestCase):
    def test_whole_original_context_red_and_current_generated_receiver_green(self):
        before = historical_source.load(fixture.BASE/'context_private_pin_before.source', _BEFORE_SHA)
        receiver = _Receiver(); self.addCleanup(receiver.close)
        original_scope = epoch_tests.scope
        children = []
        def call(kind, words, payload=None):
            value = {'port': receiver.server_address[1], 'kind': kind, 'words': words,
                     'payload': None if payload is None else payload.decode('utf-8')}
            child = subprocess.Popen([sys.executable, '-I', '-B', '-c', _CLIENT], stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            children.append(child)
            out, error = child.communicate(json.dumps(value).encode(), timeout=8)
            self.assertEqual(0, child.returncode, error.decode()); self.assertEqual(b'', error)
            return json.loads(out)
        def socket_scope():
            env, ledger, calls, terminal = original_scope()
            env['getter_cli'] = lambda words, owner=None: call('cli', words)
            env['diagnostic_adb'] = lambda words, payload=None: call('adb', words, payload)
            return env, ledger, calls, terminal
        def full_case(context):
            case = epoch_tests.ActualFactoryTests('test_full_prefix_dispatch_tail_source_and_own_ledger')
            try:
                with patch.object(epoch_tests, 'Context', context), patch.object(epoch_tests, 'scope', socket_scope):
                    case.setUp()
                    case.test_full_prefix_dispatch_tail_source_and_own_ledger()
            finally:
                case.doCleanups()
        with self.assertRaisesRegex(ValueError, 'diagnostic_private_source_changed'):
            full_case(before.Context)
        self.assertEqual([], receiver.calls, 'unfixed source refusal must precede any executable/public request')
        full_case(fixture.Context)
        self.assertEqual(1, len(receiver.ledger))
        self.assertEqual(1, sum(row['kind'] == 'adb' and row['words'][0] == 'write' for row in receiver.calls))
        self.assertGreaterEqual(len(children), 10)
        self.assertTrue(all(child.poll() == 0 for child in children))
        self.causal_results = {'before': 'diagnostic_private_source_changed', 'after': 'complete-generated-receiver',
                               'childProcessesClosed': len(children), 'actualFixedRequests': receiver.calls,
                               'ownedOperations': receiver.ledger, 'nativeExecutionAuthority': False}

    def test_archived_helper_has_exact_source_and_both_receipt_bindings(self):
        path = fixture.BASE/'private_inventory_lock.source'
        self.assertEqual(fixture.PRIVATE_SOURCE_SHA, hashlib.sha256(path.read_bytes()).hexdigest())
        self.assertEqual(fixture.PRIVATE_SOURCE_SHA, epoch.old.PRIVATE_SHA)
        self.assertEqual(epoch.OLD_SHA, hashlib.sha256(Path(epoch.old.__file__).read_bytes()).hexdigest())
        with tempfile.TemporaryDirectory() as directory:
            context = fixture.Context(Path(directory), epoch_tests.old_result())
            historical_source.verify(context.private, path, fixture.PRIVATE_SOURCE_SHA)
            self.assertIs(context.private, context.old.private); self.assertIs(context.private, context.epoch.private)
            self.assertIs(context.private, context.old._local_directory.__globals__['private'])
            self.assertIs(context.private, context.epoch._local_directory.__globals__['private'])
            prepared = context.prepare(epoch_tests.CORR)
            self.assertIn(path, prepared['snapshots'])
            self.assertNotIn(Path(current_private.__file__).absolute(), prepared['snapshots'])

    def test_live_helper_is_not_read_or_relabelled_as_historical(self):
        with tempfile.TemporaryDirectory() as directory:
            context = fixture.Context(Path(directory), epoch_tests.old_result())
            snapshot = epoch.availability._snapshot
            def isolated(path):
                if Path(path) == Path(current_private.__file__).absolute():
                    raise AssertionError('live helper cannot supply frozen historical authority')
                return snapshot(path)
            with patch.object(epoch.availability, '_snapshot', side_effect=isolated):
                context.prepare(epoch_tests.CORR)
            self.assertIs(epoch.old.private, current_private, 'production historical constructor remains unchanged')

    def test_archived_source_drift_refuses_before_upstream_or_local_effect(self):
        with tempfile.TemporaryDirectory() as directory:
            context = fixture.Context(Path(directory), epoch_tests.old_result())
            snapshot = epoch.availability._snapshot
            path = fixture.BASE/'private_inventory_lock.source'
            def changed(selected):
                generation, raw = snapshot(selected)
                return (generation, raw+b'\n') if Path(selected) == path else (generation, raw)
            with patch.object(epoch.availability, '_snapshot', side_effect=changed), \
                 patch.object(context.old.historical, 'prepare') as upstream:
                with self.assertRaisesRegex(ValueError, 'diagnostic_private_source_changed'):
                    context.prepare(epoch_tests.CORR)
                upstream.assert_not_called()
            self.assertFalse((Path(directory)/'.rag_index/android-api29-current-epoch-diagnostics').exists())
            wrong = Path(directory)/'wrong.source'; wrong.write_bytes(path.read_bytes()+b'\n')
            with self.assertRaisesRegex(ValueError, 'historical_source_binding_changed'):
                historical_source.load(wrong, fixture.PRIVATE_SOURCE_SHA)


if __name__ == '__main__': unittest.main()
