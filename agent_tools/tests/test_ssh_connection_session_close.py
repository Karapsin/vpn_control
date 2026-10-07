"""Causal close regressions with real temporary files, sockets and child pipes.

Only the control process boundary is redirected to an inert local Python child;
no test sends SSH, a signal, a remote payload, or changes original session files.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import unittest
from types import SimpleNamespace
from unittest import mock

from agent_tools import private_inventory_lock as inventory
from agent_tools import ssh_connection_session as session
from agent_tools import ssh_connection_session_close as close
from agent_tools.tests.test_ssh_connection_session import SessionTests


@unittest.skipUnless(os.name == 'posix', 'POSIX only')
class CloseTests(SessionTests):
    def setUp(self):
        super().setUp()
        # This inert namespace uses the current checked-out helpers as its explicit
        # external ancestors; production keeps its frozen historical hashes.
        patches = [
            mock.patch.object(close, '_ORIGINAL_SOURCE', session._sha(Path(session.__file__).read_bytes())),
            mock.patch.object(close, '_TRANSPORT_SOURCE', session._sha(Path(session.transport.__file__).read_bytes())),
            mock.patch.object(close, '_INVENTORY_SOURCE', session._sha(Path(inventory.__file__).read_bytes())),
        ]
        for patcher in patches: patcher.start(); self.addCleanup(patcher.stop)

    def spawn(self, argv, diagnostic, guard=None):
        # Represent the real immutable launch record omitted by the general
        # session fixture's inert spawn implementation.
        result = super().spawn(argv, diagnostic, guard)
        session._create(diagnostic.parent / 'launch.json', {
            'version': 1, 'argvSha256': session._sha(session._json(argv)), 'diagnosticLimit': 4096})
        return result

    def control(self, ready, script='', remove=True, popen_effect=None):
        path = Path(session.reuse_only_options(self.root, 'archlinux', ready['receiptSha256'])[1])
        actual = subprocess.Popen
        self.controls = getattr(self, 'controls', [])
        self.children = getattr(self, 'children', [])
        def launch(argv, **kw):
            self.controls.append(argv)
            self.assertEqual(argv[-3:], ['-O', 'exit', 'gateway.invalid'])
            self.assertIn('ProxyCommand=false', argv)
            self.assertTrue(close._paths(self.root, 'archlinux', ready['receiptSha256'])[3].exists())
            if popen_effect is not None:
                return popen_effect(argv, **kw)
            if remove:
                self.sockets[0].close(); path.unlink()
            env = dict(os.environ); env.pop('DYLD_INSERT_LIBRARIES', None); kw['env'] = env
            child = actual([sys.executable, '-c', script], **kw)
            self.children.append(child)
            return child
        return mock.patch.object(close.subprocess, 'Popen', side_effect=launch)

    def absence(self, side_effect=None):
        def run(argv, **kw):
            self.assertEqual(argv, ['/bin/ps', '-p', '12345', '-o', 'pid='])
            if side_effect:
                side_effect()
            return SimpleNamespace(returncode=1, stdout=b'', stderr=b'')
        return mock.patch.object(close.subprocess, 'run', side_effect=run)

    def successful_close(self, script="import os;os.write(1,b'original')"):
        ready = self.ready()
        with self.control(ready, script):
            self.assertEqual('exit_sent', close.close(self.root, 'archlinux', ready['receiptSha256'])['state'])
        return ready, close._paths(self.root, 'archlinux', ready['receiptSha256'])

    def test_intent_precedes_single_exit_and_status_requires_positive_absence(self):
        ready, paths = self.successful_close('')
        original = {p.name: p.read_bytes() for p in self.journal().iterdir()}
        with self.absence():
            self.assertEqual('closed', close.status(self.root, 'archlinux', ready['receiptSha256'])['state'])
        self.assertEqual(original, {p.name: p.read_bytes() for p in self.journal().iterdir()})
        self.assertEqual(b'', paths[4].read_bytes()); self.assertEqual(b'', paths[5].read_bytes())
        with mock.patch.object(close.subprocess, 'Popen', side_effect=AssertionError('no replay')):
            self.assertEqual('unknown', close.close(self.root, 'archlinux', ready['receiptSha256'])['state'])
        self.assertEqual(1, len(self.controls))

    def test_config_drift_and_consumed_intent_do_not_replay(self):
        ready = self.ready(); self.config_path.write_bytes(self.config_path.read_bytes() + b' ')
        with mock.patch.object(close.subprocess, 'Popen', side_effect=AssertionError('no effect')):
            self.assertEqual('unknown', close.close(self.root, 'archlinux', ready['receiptSha256'])['state'])

    def test_exit_failure_is_consumed_and_never_replayed(self):
        ready = self.ready()
        with self.control(ready, "import os;os.write(1,b'x');os.write(2,b'y');raise SystemExit(255)"):
            self.assertEqual('unknown', close.close(self.root, 'archlinux', ready['receiptSha256'])['state'])
        paths = close._paths(self.root, 'archlinux', ready['receiptSha256'])
        self.assertEqual(b'x', paths[4].read_bytes()); self.assertEqual(b'y', paths[5].read_bytes())
        with mock.patch.object(close.subprocess, 'Popen', side_effect=AssertionError('no replay')):
            self.assertEqual('unknown', close.close(self.root, 'archlinux', ready['receiptSha256'])['state'])
        with self.absence():
            self.assertEqual('unknown', close.status(self.root, 'archlinux', ready['receiptSha256'])['state'])

    def test_source_or_receipt_alias_rejects_before_effect(self):
        ready = self.ready()
        with mock.patch.object(session, '_source', return_value='b' * 64), mock.patch.object(close.subprocess, 'Popen', side_effect=AssertionError('effect')):
            self.assertEqual('unknown', close.close(self.root, 'archlinux', ready['receiptSha256'])['state'])
        with mock.patch.object(close.subprocess, 'Popen', side_effect=AssertionError('effect')):
            self.assertEqual('unknown', close.close(self.root, 'ARCHlinux', ready['receiptSha256'])['state'])
            self.assertEqual('unknown', close.close(self.root, 'archlinux', 'a' * 64)['state'])

    def test_partial_private_output_write_is_completed_and_pinned(self):
        ready = self.ready(); original = os.write
        def partial(fd, data):
            return original(fd, data[:1]) if len(data) > 1 else original(fd, data)
        with self.control(ready, "import os;os.write(1,b'abc');os.write(2,b'def')"), mock.patch.object(close.os, 'write', side_effect=partial):
            self.assertEqual('exit_sent', close.close(self.root, 'archlinux', ready['receiptSha256'])['state'])
        with self.absence():
            self.assertEqual('closed', close.status(self.root, 'archlinux', ready['receiptSha256'])['state'])

    def test_actual_intent_mutation_after_second_verify_blocks_exit(self):
        ready = self.ready(); original = session._verify; count = [0]
        path = close._paths(self.root, 'archlinux', ready['receiptSha256'])[3]
        def verify(*a, **kw):
            result = original(*a, **kw); count[0] += 1
            if count[0] == 2:
                value = json.loads(path.read_text()); value['pid'] = 999
                path.write_bytes(session._json(value))
            return result
        with mock.patch.object(session, '_verify', side_effect=verify), mock.patch.object(close.subprocess, 'Popen', side_effect=AssertionError('no effect')):
            self.assertEqual('unknown', close.close(self.root, 'archlinux', ready['receiptSha256'])['state'])
        self.assertEqual(2, count[0])

    def test_actual_terminal_mutation_during_absence_blocks_closed(self):
        ready, paths = self.successful_close()
        with self.absence(lambda: paths[6].write_text('{}')):
            self.assertEqual('unknown', close.status(self.root, 'archlinux', ready['receiptSha256'])['state'])

    def test_output_replacement_during_positive_absence_rejected(self):
        ready, paths = self.successful_close()
        with self.absence(lambda: paths[4].write_bytes(b'replaced')):
            self.assertEqual('unknown', close.status(self.root, 'archlinux', ready['receiptSha256'])['state'])

    def test_forged_birth_and_matching_terminal_pin_rejected(self):
        ready, paths = self.successful_close()
        value = json.loads(paths[3].read_text()); value['pidBirth'] = 'b' * 64
        paths[3].write_bytes(session._json(value)); _, pin = session._read(paths[3])
        terminal = json.loads(paths[6].read_text()); terminal['intentPin'] = pin
        paths[6].write_bytes(session._json(terminal))
        with self.absence():
            self.assertEqual('unknown', close.status(self.root, 'archlinux', ready['receiptSha256'])['state'])

    def test_control_output_overflow_unknown_and_durable_bounded(self):
        for stream in (1, 2):
            with self.subTest(stream=stream):
                # Distinct receipt/workspace for each single-attempt fence.
                if stream == 2:
                    self.tearDown(); self.doCleanups(); self.setUp()
                ready = self.ready(); paths = close._paths(self.root, 'archlinux', ready['receiptSha256'])
                with self.control(ready, f"import os;os.write({stream},b'x'*5000)"):
                    self.assertEqual('unknown', close.close(self.root, 'archlinux', ready['receiptSha256'])['state'])
                self.assertEqual(b'x' * 4096, paths[3 + stream].read_bytes())
                terminal = json.loads(paths[6].read_text()); self.assertEqual('overflow', terminal['outcome'])
                self.assertLessEqual(paths[4].stat().st_size, 4096); self.assertLessEqual(paths[5].stat().st_size, 4096)
                for child in self.children: child.wait(timeout=2)

    def test_timeout_partial_output_is_durable_and_never_replayed(self):
        ready = self.ready(); paths = close._paths(self.root, 'archlinux', ready['receiptSha256'])
        script = "import os,time;os.write(1,b'partial-out');os.write(2,b'partial-err');time.sleep(.3)"
        with self.control(ready, script), mock.patch.object(close, '_TIMEOUT', .1):
            self.assertEqual('unknown', close.close(self.root, 'archlinux', ready['receiptSha256'])['state'])
        self.assertEqual(b'partial-out', paths[4].read_bytes()); self.assertEqual(b'partial-err', paths[5].read_bytes())
        self.assertEqual('timeout', json.loads(paths[6].read_text())['outcome'])
        for child in self.children: child.wait(timeout=2)
        with mock.patch.object(close.subprocess, 'Popen', side_effect=AssertionError('no replay')):
            self.assertEqual('unknown', close.close(self.root, 'archlinux', ready['receiptSha256'])['state'])

    def test_timeout_exception_partial_output_retained(self):
        ready = self.ready(); paths = close._paths(self.root, 'archlinux', ready['receiptSha256'])
        def timeout(*a, **kw):
            raise subprocess.TimeoutExpired('inert', 3, output=b'partial-out', stderr=b'partial-err')
        with self.control(ready, popen_effect=timeout):
            self.assertEqual('unknown', close.close(self.root, 'archlinux', ready['receiptSha256'])['state'])
        self.assertEqual(b'partial-out', paths[4].read_bytes()); self.assertEqual(b'partial-err', paths[5].read_bytes())
        self.assertEqual('timeout', json.loads(paths[6].read_text())['outcome'])

    def test_every_original_history_record_mutation_after_absence_rejected(self):
        for name in ('ready.json', 'intent.json', 'child.json', 'anchor.json', 'launch.json', 'startup.json', 'launch.stderr.private', 'lock'):
            with self.subTest(name=name):
                if name != 'ready.json': self.tearDown(); self.doCleanups(); self.setUp()
                ready, _ = self.successful_close()
                target = self.journal() / name
                with self.absence(lambda: target.write_bytes(target.read_bytes())):
                    self.assertEqual('unknown', close.status(self.root, 'archlinux', ready['receiptSha256'])['state'])

    def test_source_config_parent_and_output_exchange_during_absence_rejected(self):
        # Held output descriptor must reject an equal-content named replacement.
        ready, paths = self.successful_close()
        def replace():
            paths[4].rename(paths[4].with_suffix('.old'))
            paths[4].write_bytes(b'original'); paths[4].chmod(0o600)
        with self.absence(replace):
            self.assertEqual('unknown', close.status(self.root, 'archlinux', ready['receiptSha256'])['state'])

    def test_pid_positive_socket_absence_and_terminal_schema_required(self):
        ready, paths = self.successful_close()
        with mock.patch.object(close.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stdout=b'12345\n', stderr=b'')):
            self.assertEqual('unknown', close.status(self.root, 'archlinux', ready['receiptSha256'])['state'])
        terminal = json.loads(paths[6].read_text()); terminal['extra'] = True
        paths[6].write_bytes(session._json(terminal))
        with self.absence():
            self.assertEqual('unknown', close.status(self.root, 'archlinux', ready['receiptSha256'])['state'])

    def test_exact_terminal_types_reject_boolean_success(self):
        ready, paths = self.successful_close()
        terminal = json.loads(paths[6].read_text()); terminal['returnCode'] = False
        paths[6].write_bytes(session._json(terminal))
        with self.absence():
            self.assertEqual('unknown', close.status(self.root, 'archlinux', ready['receiptSha256'])['state'])

    def test_actual_close_fence_equal_content_exchange_blocks_effect(self):
        ready = self.ready(); original = session._verify; count = [0]
        path = close._paths(self.root, 'archlinux', ready['receiptSha256'])[3]
        def verify(*a, **kw):
            result = original(*a, **kw); count[0] += 1
            if count[0] == 2:
                raw = path.read_bytes(); path.rename(path.with_suffix('.old'))
                path.write_bytes(raw); path.chmod(0o600)
            return result
        with mock.patch.object(session, '_verify', side_effect=verify), mock.patch.object(close.subprocess, 'Popen', side_effect=AssertionError('no effect')):
            self.assertEqual('unknown', close.close(self.root, 'archlinux', ready['receiptSha256'])['state'])
        self.assertEqual(2, count[0])

    def test_final_authority_read_exchange_of_close_fence_blocks_effect(self):
        ready = self.ready(); original = session._snapshot
        path = close._paths(self.root, 'archlinux', ready['receiptSha256'])[3]; changed = [False]
        def snapshot(*a, **kw):
            result = original(*a, **kw)
            if path.exists() and not changed[0]:
                changed[0] = True; path.write_bytes(path.read_bytes())
            return result
        with mock.patch.object(session, '_snapshot', side_effect=snapshot), mock.patch.object(close.subprocess, 'Popen', side_effect=AssertionError('no effect')):
            self.assertEqual('unknown', close.close(self.root, 'archlinux', ready['receiptSha256'])['state'])
        self.assertTrue(changed[0])

    def test_absence_config_credential_or_parent_exchange_rejected(self):
        for kind in ('config', 'credential', 'parent'):
            with self.subTest(kind=kind):
                if kind != 'config': self.tearDown(); self.doCleanups(); self.setUp()
                ready, paths = self.successful_close()
                value = json.loads(paths[3].read_text())
                def mutate():
                    if kind == 'config': self.config_path.write_bytes(self.config_path.read_bytes())
                    elif kind == 'credential': self.key.write_bytes(self.key.read_bytes())
                    else:
                        parent = Path(value['socketPath']).parent
                        prior = parent.with_name(parent.name + '-old'); parent.rename(prior)
                        self.parents.append(prior); parent.mkdir(mode=0o700)
                with self.absence(mutate):
                    self.assertEqual('unknown', close.status(self.root, 'archlinux', ready['receiptSha256'])['state'])

    def test_original_launch_or_startup_drift_before_close_rejected(self):
        ready = self.ready(); target = self.journal() / 'startup.json'
        value = json.loads(target.read_text()); value['stderrSha256'] = 'b' * 64
        target.write_bytes(session._json(value))
        with mock.patch.object(close.subprocess, 'Popen', side_effect=AssertionError('no effect')):
            self.assertEqual('unknown', close.close(self.root, 'archlinux', ready['receiptSha256'])['state'])

    def test_final_output_read_mutation_of_original_record_rejected(self):
        ready, paths = self.successful_close(); original = os.pread; mutated = [False]; observed_absence = [False]
        def read(fd, size, offset):
            data = original(fd, size, offset)
            # Mutate an earlier original record during a later output read,
            # proving the final metadata pass closes all original captures.
            if observed_absence[0] and os.fstat(fd).st_ino == paths[5].stat().st_ino and not mutated[0]:
                mutated[0] = True; target = self.journal() / 'launch.json'
                target.write_bytes(target.read_bytes())
            return data
        with self.absence(lambda: observed_absence.__setitem__(0, True)), mock.patch.object(close.os, 'pread', side_effect=read):
            self.assertEqual('unknown', close.status(self.root, 'archlinux', ready['receiptSha256'])['state'])
        self.assertTrue(mutated[0])

    def test_private_journal_ancestry_modes_required(self):
        ready, _ = self.successful_close()
        (self.root / '.rag_index').chmod(0o755)
        with self.absence():
            self.assertEqual('unknown', close.status(self.root, 'archlinux', ready['receiptSha256'])['state'])

    def test_actual_guard_dependency_drift_after_live_proof_blocks_effect(self):
        dependency = self.root / 'inventory-source.py'
        dependency.write_bytes(Path(inventory.__file__).read_bytes()); dependency.chmod(0o600)
        ready = self.ready(); original = session._verify; count = [0]
        def verify(*a, **kw):
            result = original(*a, **kw); count[0] += 1
            if count[0] == 2: dependency.write_bytes(dependency.read_bytes() + b'\n')
            return result
        with mock.patch.object(inventory, '__file__', str(dependency)), mock.patch.object(session, '_verify', side_effect=verify), self.control(ready):
            self.assertEqual('unknown', close.close(self.root, 'archlinux', ready['receiptSha256'])['state'])
        self.assertEqual(2, count[0]); self.assertEqual([], self.controls)

    def test_guard_dependency_drift_during_absence_rejected(self):
        dependency = self.root / 'inventory-source.py'
        dependency.write_bytes(Path(inventory.__file__).read_bytes()); dependency.chmod(0o600)
        with mock.patch.object(inventory, '__file__', str(dependency)):
            ready, _ = self.successful_close()
            with self.absence(lambda: dependency.write_bytes(dependency.read_bytes() + b'\n')):
                self.assertEqual('unknown', close.status(self.root, 'archlinux', ready['receiptSha256'])['state'])


for _name in SessionTests.__dict__:
    if _name.startswith('test_') and _name not in CloseTests.__dict__:
        setattr(CloseTests, _name, None)
del SessionTests
if __name__ == '__main__':
    unittest.main()
