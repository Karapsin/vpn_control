"""Real TempFS/process/pipe bridge checks; no SSH, source copy or Windows VM.

Darwin projects only the Linux PID birth boundary in the detached worker tests.
The actual submitted scripts, gating, journals, fd hashing and child pipes run.
"""
import hashlib
import inspect
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
from unittest.mock import patch

from agent_tools import windows_parallel_vm_prepare_transport as transport
from agent_tools.windows_diagnostic_authority_capture import AuthorityCapture
from agent_tools import ssh_connection_session, ssh_transport
from agent_tools import windows_cp117_bound_absence_completion as authority
from agent_tools import windows_diagnostic_authority_capture as capture_module


PORTABLE_BIRTH = '''def birth(proc, pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return None
    return 1
'''


def portable_birth(proc, pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return None
    return 1


@unittest.skipUnless(os.name == 'posix', 'actual POSIX FD/pipe guards required')
class DurableTransportTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.job = self.root / 'copy-job'
        self.proc = self.root / 'proc'
        self.proc.mkdir()
        self.correlation = str(uuid.uuid4())
        self.children = []
        self.real_popen = subprocess.Popen
        def capture(*args, **kwargs):
            child = self.real_popen(*args, **kwargs)
            self.children.append(child)
            return child
        self.popen_patch = patch.object(transport.subprocess, 'Popen', side_effect=capture)
        self.popen_patch.start()
        self.addCleanup(self.popen_patch.stop)
        self.addCleanup(self.cleanup_children)
        self.native_birth = transport.birth
        self.definitions = transport.remote_definitions().replace(inspect.getsource(transport.birth), PORTABLE_BIRTH)
        self.birth_patch = patch.object(transport, 'birth', side_effect=portable_birth)
        self.birth_patch.start()
        self.addCleanup(self.birth_patch.stop)

    def cleanup_children(self):
        for child in self.children:
            if child.poll() is None:
                child.kill()  # Sole positively owned harmless LOCAL test child.
            child.wait(timeout=2)
            if child.stdin is not None and not child.stdin.closed:
                child.stdin.close()
            if child.stdout is not None and not child.stdout.closed:
                child.stdout.close()

    def submit(self, program, definitions=None):
        return transport.submit(self.job, self.proc, sys.executable, self.correlation,
                                program, definitions or self.definitions)

    def await_file(self, path):
        deadline = time.monotonic() + 3
        while not path.exists() and time.monotonic() < deadline:
            time.sleep(.01)
        self.assertTrue(path.exists(), str(path))

    def finish(self):
        self.children[0].wait(timeout=4)  # Reap actual original local supervisor.

    def program(self, state='prepared', extra=''):
        value = {'state': state, 'correlationId': self.correlation,
                 'nativeGuestStarted': False, 'launchAdmitted': False, 'productAcceptance': False}
        return extra + '\nprint(' + repr(json.dumps(value)) + ')\n'

    def query(self, program):
        return transport.query(self.job, self.proc, self.correlation, transport.digest(program.encode()))

    def test_actual_gated_submit_child_raw_eof_and_same_identity_terminal(self):
        program = self.program()
        started = self.submit(program)
        self.assertEqual(started['state'], 'submitted')
        self.finish()
        result = self.query(program)
        self.assertEqual(result['state'], 'prepared')
        self.assertEqual(result['identity'], started['identity'])
        self.assertTrue(result['terminal']['stdoutEof'])
        self.assertEqual(result['terminal']['exitCode'], 0)
        raw = (self.job / 'stdout.private').read_bytes()
        self.assertEqual(json.loads(raw), result['result'])
        self.assertEqual(hashlib.sha256(raw).hexdigest(), result['terminal']['rawPin']['sha256'])
        self.assertFalse(result['launchAdmitted'])
        child = json.loads((self.job / 'child.json').read_text())
        self.assertEqual(child, result['copyIdentity'])

    def test_running_original_supervisor_retains_actual_prefix_without_terminal(self):
        program = self.program(extra="import os,time;os.write(1,b'PUBLIC_PREFIX');time.sleep(.4)")
        started = self.submit(program)
        self.await_file(self.job / 'child.json')
        deadline = time.monotonic() + 2
        while (self.job / 'stdout.private').stat().st_size == 0 and time.monotonic() < deadline:
            time.sleep(.01)
        result = self.query(program)
        self.assertEqual(result['state'], 'running')
        self.assertEqual(result['identity'], started['identity'])
        self.assertEqual((self.job / 'stdout.private').read_bytes(), b'PUBLIC_PREFIX')
        self.assertFalse((self.job / 'terminal.json').exists())
        self.finish()
        with self.assertRaises(ValueError):
            self.query(program)  # Prefix is not silently ignored when parsing JSON.

    def test_any_existing_submission_blocks_new_uuid_without_popen_or_replay(self):
        program = self.program()
        self.submit(program)
        count = len(self.children)
        with self.assertRaisesRegex(ValueError, 'copy-already-submitted'):
            transport.submit(self.job, self.proc, sys.executable, str(uuid.uuid4()), program, self.definitions)
        self.assertEqual(len(self.children), count)
        self.finish()

    def test_real_overflow_drains_original_copy_then_refuses_prepared(self):
        program = "import os;os.write(1,b'X'*100000)"
        self.submit(program)
        self.finish()
        terminal = json.loads((self.job / 'terminal.json').read_text())
        self.assertTrue(terminal['overflow'])
        self.assertTrue(terminal['stdoutEof'])
        self.assertEqual(terminal['outputBytes'], 100000)
        self.assertEqual((self.job / 'stdout.private').stat().st_size, transport.LIMIT + 1)
        with self.assertRaisesRegex(ValueError, 'job-output'):
            self.query(program)

    def test_named_raw_replacement_rejects_original_terminal(self):
        program = self.program()
        self.submit(program)
        self.finish()
        path = self.job / 'stdout.private'
        raw = path.read_bytes()
        path.rename(self.job / 'original-stdout.private')
        path.write_bytes(raw)
        path.chmod(0o600)
        with self.assertRaisesRegex(ValueError, 'job-raw-terminal'):
            self.query(program)

    def test_foreign_uuid_source_and_unsafe_private_file_refuse(self):
        program = self.program()
        self.submit(program)
        self.finish()
        with self.assertRaisesRegex(ValueError, 'job-intent'):
            transport.query(self.job, self.proc, str(uuid.uuid4()), transport.digest(program.encode()))
        with self.assertRaisesRegex(ValueError, 'job-intent'):
            transport.query(self.job, self.proc, self.correlation, 'a' * 64)
        (self.job / 'terminal.json').chmod(0o644)
        with self.assertRaisesRegex(ValueError, 'job-file'):
            self.query(program)

    def client(self, code):
        evidence = self.root / '.runtime' / 'parity-evidence' / ('client-' + uuid.uuid4().hex)
        evidence.mkdir(parents=True, mode=0o700)
        capture = AuthorityCapture(self.root, evidence.name)
        client = transport.RetainedClient([sys.executable, '-c', code], b'', capture)
        self.addCleanup(lambda: client.capture.close() if client.capture.fd is not None else None)
        self.addCleanup(lambda: os.close(client.raw_fd) if client.raw_fd is not None else None)
        self.addCleanup(client.selector.close)
        return client, evidence

    def test_actual_client_deadline_retains_handle_fsynced_prefix_then_same_eof(self):
        client, evidence = self.client("import os,time;os.write(1,b'PUBLIC_PREFIX');time.sleep(.3)")
        with self.assertRaises(transport.ClientUnknown) as caught:
            client.observe(.08)
        self.assertIs(caught.exception.handle, client)
        self.assertEqual((evidence / 'transport.stdout.private').read_bytes(), b'PUBLIC_PREFIX')
        self.assertIsNone(client.child.poll())
        self.assertFalse(client.eof)
        self.assertEqual(client.observe(2), b'PUBLIC_PREFIX')
        self.assertTrue(client.eof)
        self.assertEqual(client.child.returncode, 0)

    def test_actual_exited_client_held_descendant_pipe_is_unknown_until_real_eof(self):
        code = "import subprocess,sys;subprocess.Popen([sys.executable,'-c','import time;time.sleep(.35)']);print('PUBLIC',flush=True)"
        client, evidence = self.client(code)
        with self.assertRaises(transport.ClientUnknown):
            client.observe(.1)
        self.assertEqual(client.child.poll(), 0)
        self.assertFalse(client.eof)
        self.assertEqual((evidence / 'transport.stdout.private').read_bytes(), b'PUBLIC\n')
        self.assertEqual(client.observe(2), b'PUBLIC\n')
        self.assertTrue(client.eof)

    def test_actual_client_overflow_caps_raw_without_kill_or_false_eof(self):
        client, evidence = self.client("import os,time;os.write(1,b'X'*100000);time.sleep(.5)")
        with self.assertRaises(transport.ClientUnknown) as caught:
            client.observe(2)
        self.assertIs(caught.exception.handle, client)
        self.assertEqual((evidence / 'transport.stdout.private').stat().st_size, transport.LIMIT + 1)
        self.assertIsNone(client.child.poll())
        self.assertFalse(client.eof)

    def test_actual_client_named_leaf_swap_retains_original_prefix_and_observer(self):
        client, evidence = self.client("import os,time;os.write(1,b'PUBLIC_PREFIX');time.sleep(.3)")
        held = evidence.with_name(evidence.name + '-held')
        evidence.rename(held)
        evidence.mkdir(mode=0o700)
        with self.assertRaises(transport.ClientUnknown) as caught:
            client.observe(.08)
        self.assertIs(caught.exception.handle, client)
        self.assertEqual((held / 'transport.stdout.private').read_bytes(), b'PUBLIC_PREFIX')
        self.assertFalse((evidence / 'transport.stdout.private').exists())
        self.assertFalse(client.eof)
        self.assertIsNone(client.child.poll())
        transport.retain_unknown(client.capture, {'state': 'unknown'})
        self.assertEqual(json.loads((held / 'unknown.json').read_text()), {'state': 'unknown'})

    def test_actual_client_raw_name_replacement_refuses_but_original_fd_has_prefix(self):
        client, evidence = self.client("import os,time;os.write(1,b'PUBLIC_PREFIX');time.sleep(.3)")
        path = evidence / 'transport.stdout.private'
        held = evidence / 'original-transport.stdout.private'
        path.rename(held)
        path.write_bytes(b'FOREIGN')
        path.chmod(0o600)
        with self.assertRaises(transport.ClientUnknown) as caught:
            client.observe(.08)
        self.assertIs(caught.exception.handle, client)
        self.assertEqual(held.read_bytes(), b'PUBLIC_PREFIX')
        self.assertEqual(path.read_bytes(), b'FOREIGN')
        self.assertIsNone(client.child.poll())
        trace = json.loads(next(evidence.glob('transport-*.json')).read_text())
        self.assertEqual(trace['rawSha256'], hashlib.sha256(b'PUBLIC_PREFIX').hexdigest())
        self.assertFalse(trace['clientTerminatedForBound'])

    def test_actual_post_child_namespace_refusal_keeps_same_original_raw_and_unknown(self):
        program = self.program(extra='import time;time.sleep(.12)')
        original_guard = inspect.getsource(transport.guard_root)
        injected = original_guard.replace('def guard_root(', 'def actual_guard_root(')
        injected += '''\ndef guard_root(root, fd, root_pin, parents):
    actual_guard_root(root, fd, root_pin, parents)
    if os.path.lexists(Path(root)/'child.json'):
        Path(root).rename(Path(str(root)+'-held'))
        Path(root).mkdir(mode=0o700)
        raise ValueError('measured-post-child-namespace')
'''
        definitions = self.definitions.replace(original_guard, injected)
        self.submit(program, definitions)
        self.finish()
        held = Path(str(self.job) + '-held')
        self.assertEqual(len(self.children), 1)  # Sole supervisor, no resubmission.
        unknown = json.loads((held / 'unknown.json').read_text())
        original = json.loads((held / 'child.json').read_text())
        self.assertEqual(unknown['pid'], original['pid'])
        self.assertEqual(unknown['startTicks'], original['startTicks'])
        self.assertFalse(unknown['stdoutEof'])
        self.assertFalse((held / 'terminal.json').exists())
        self.assertFalse((self.job / 'unknown.json').exists())
        # Gate closed before release: original copy child exits without core effects.
        self.assertEqual((held / 'stdout.private').read_bytes(), b'')

    def retained_source(self):
        leaf = 'windows-parallel-vm-source-read-' + uuid.uuid4().hex
        location = self.root / '.runtime' / 'parity-evidence' / leaf
        location.mkdir(parents=True, mode=0o700)
        report = {'state': 'observed', 'sourceState': 'stopped-observed',
            'source': transport.inventory.SOURCE, 'holderCensusComplete': True, 'sourceHolders': [],
            'cloneAdmitted': False, 'nativeActionAllowed': False,
            'sourceGeneration': [1, 2, stat.S_IFREG | 0o600, 1000, 1000, 1, 10, 1, 1],
            'sourceSha256': 'a' * 64, 'sourceSizeBytes': 10,
            'image': {'format': 'qcow2', 'backingFile': None, 'virtualSizeBytes': 96 * 1024 ** 3},
            'sourceParents': [{'path': str(Path(transport.inventory.SOURCE).parent),
                              'generation': [1, 3, stat.S_IFDIR | 0o700, 1000, 1000]},
                             {'path': transport.inventory.SOURCE_ROOT,
                              'generation': [1, 4, stat.S_IFDIR | 0o700, 1000, 1000]}]}
        for name, raw in (('transport.stdout.private', json.dumps(report).encode()),
                          ('result.json', json.dumps(report).encode()),
                          ('transport.json', json.dumps({'stdoutEof': True, 'exitCode': 0, 'reason': None}).encode())):
            transport.core.immutable_write(location / name, raw)
        (self.root / '.codex').mkdir(mode=0o700)
        transport.core.immutable_write(self.root / '.codex' / 'arch-sudo.local', b'LOCAL_TEST_ONLY')
        transport.core.immutable_write(self.root / '.vm-hosts.local.json', b'{"schemaVersion":1}')
        return leaf

    def test_actual_public_entry_retains_malformed_raw_blocks_repeat_and_never_secret_argv(self):
        leaf = self.retained_source()
        args = []
        def command(config, host, timeout, command):
            args.append(command)
            return [sys.executable, '-c', "import sys;sys.stdin.buffer.read();print('PUBLIC_BAD_JSON')"]
        self.birth_patch.stop()  # Pure generated source must use actual frozen definition.
        with patch.object(authority, '_outer_authority', return_value={'receiptSha256': 'b' * 64}), \
             patch.object(authority, '_verify_outer'), \
             patch.object(ssh_transport, 'load_config', return_value=object()), \
             patch.object(ssh_transport, 'build_ssh_argv', side_effect=command), \
             patch.object(ssh_connection_session, '_pid_generation', side_effect=lambda pid: {'pid': pid, 'generationSha256': 'c' * 64}):
            result = transport.start(self.root, host='archlinux', correlation_id=self.correlation,
                                     source_evidence_leaf=leaf, timeout_seconds=5)
            self.assertEqual(result['state'], 'unknown')
            raw_path = self.root / '.runtime' / 'parity-evidence' / result['evidenceLeaf'] / 'transport.stdout.private'
            self.assertEqual(raw_path.read_bytes(), b'PUBLIC_BAD_JSON\n')
            self.assertNotIn('LOCAL_TEST_ONLY', repr(args))
            count = len(self.children)
            with self.assertRaisesRegex(ValueError, 'copy-already-submitted'):
                transport.start(self.root, host='archlinux', correlation_id=str(uuid.uuid4()),
                                source_evidence_leaf=leaf, timeout_seconds=5)
            self.assertEqual(len(self.children), count)
            self.assertEqual(len(args), 1)

    def test_actual_public_entry_client_birth_unknown_still_collects_original_prefix(self):
        leaf = self.retained_source()
        self.birth_patch.stop()
        with patch.object(authority, '_outer_authority', return_value={'receiptSha256': 'b' * 64}), \
             patch.object(authority, '_verify_outer'), \
             patch.object(ssh_transport, 'load_config', return_value=object()), \
             patch.object(ssh_transport, 'build_ssh_argv', return_value=[sys.executable, '-c', "import sys;sys.stdin.buffer.read();print('PUBLIC_PREFIX')"]), \
             patch.object(ssh_connection_session, '_pid_generation', side_effect=ValueError('native-birth-boundary')):
            result = transport.start(self.root, host='archlinux', correlation_id=self.correlation,
                                     source_evidence_leaf=leaf, timeout_seconds=5)
        self.assertEqual(result['state'], 'unknown')
        path = self.root / '.runtime' / 'parity-evidence' / result['evidenceLeaf']
        self.assertEqual((path / 'transport.stdout.private').read_bytes(), b'PUBLIC_PREFIX\n')
        self.assertEqual(json.loads((path / 'client.json').read_text()), {'identity': None})

    def test_actual_source_receipt_drift_after_plan_refuses_before_any_submission(self):
        leaf = self.retained_source()
        self.birth_patch.stop()
        from agent_tools import windows_vm_virt_firmware_install as credential
        original = credential._read_credential
        def mutate(root):
            secret = original(root)
            path = self.root / '.runtime' / 'parity-evidence' / leaf / 'transport.stdout.private'
            raw = path.read_bytes()
            path.write_bytes(raw + b' ')
            return secret
        with patch.object(authority, '_outer_authority', return_value={'receiptSha256': 'b' * 64}), \
             patch.object(authority, '_verify_outer'), \
             patch.object(ssh_transport, 'load_config', return_value=object()), \
             patch.object(ssh_transport, 'build_ssh_argv', return_value=['not-executed']), \
             patch.object(credential, '_read_credential', side_effect=mutate):
            with self.assertRaisesRegex(ValueError, 'dispatch-generation'):
                transport.start(self.root, host='archlinux', correlation_id=self.correlation,
                                source_evidence_leaf=leaf, timeout_seconds=5)
        self.assertEqual(self.children, [])
        self.assertFalse((self.root / '.runtime' / 'windows-parallel-vm-copy-intent.json').exists())

    def test_actual_public_entry_configuration_drift_retains_raw_and_unknown(self):
        leaf = self.retained_source()
        self.birth_patch.stop()
        def command(config, host, timeout, command):
            return [sys.executable, '-c', 'import sys,time;sys.stdin.buffer.read();time.sleep(.03);print("PUBLIC_PREFIX")']
        def mutate_identity(pid):
            path = self.root / '.vm-hosts.local.json'
            path.write_bytes(path.read_bytes() + b' ')
            return {'pid': pid, 'generationSha256': 'c' * 64}
        with patch.object(authority, '_outer_authority', return_value={'receiptSha256': 'b' * 64}), \
             patch.object(authority, '_verify_outer'), \
             patch.object(ssh_transport, 'load_config', return_value=object()), \
             patch.object(ssh_transport, 'build_ssh_argv', side_effect=command), \
             patch.object(ssh_connection_session, '_pid_generation', side_effect=mutate_identity):
            result = transport.start(self.root, host='archlinux', correlation_id=self.correlation,
                                     source_evidence_leaf=leaf, timeout_seconds=5)
        self.assertEqual(result['state'], 'unknown')
        path = self.root / '.runtime' / 'parity-evidence' / result['evidenceLeaf']
        self.assertEqual((path / 'transport.stdout.private').read_bytes(), b'PUBLIC_PREFIX\n')
        self.assertFalse(result['launchAdmitted'])

    def test_actual_capture_dependency_drift_refuses_before_submission(self):
        leaf = self.retained_source()
        self.birth_patch.stop()
        from agent_tools import windows_vm_virt_firmware_install as credential
        original = credential._read_credential
        dependency = self.root / 'capture-dependency.py'
        dependency.write_bytes(Path(capture_module.__file__).read_bytes())
        def mutate(root):
            secret = original(root)
            with dependency.open('ab') as output:
                output.write(b'\n# measured source generation drift\n')
            return secret
        with patch.object(capture_module, '__file__', str(dependency)), \
             patch.object(authority, '_outer_authority', return_value={'receiptSha256': 'b' * 64}), \
             patch.object(authority, '_verify_outer'), \
             patch.object(ssh_transport, 'load_config', return_value=object()), \
             patch.object(ssh_transport, 'build_ssh_argv', return_value=[sys.executable, '-c', "import sys;sys.stdin.buffer.read();print('PUBLIC_PREFIX')"]), \
             patch.object(ssh_connection_session, '_pid_generation', side_effect=lambda pid: {'pid': pid, 'generationSha256': 'c' * 64}), \
             patch.object(credential, '_read_credential', side_effect=mutate):
            with self.assertRaisesRegex(ValueError, 'dispatch-generation'):
                transport.start(self.root, host='archlinux', correlation_id=self.correlation,
                                source_evidence_leaf=leaf, timeout_seconds=5)
        self.assertEqual(self.children, [])
        self.assertFalse((self.root / '.runtime' / 'windows-parallel-vm-copy-intent.json').exists())

    def postpopen_refusal(self, selector_factory):
        leaf = self.retained_source()
        self.birth_patch.stop()
        before = set(transport.HANDLES)
        with patch.object(authority, '_outer_authority', return_value={'receiptSha256': 'b' * 64}), \
             patch.object(authority, '_verify_outer'), \
             patch.object(ssh_transport, 'load_config', return_value=object()), \
             patch.object(ssh_transport, 'build_ssh_argv', return_value=[sys.executable, '-c', "import os,time;os.write(1,b'PUBLIC_PREFIX');time.sleep(.4)"]), \
             patch.object(ssh_connection_session, '_pid_generation', side_effect=lambda pid: {'pid': pid, 'generationSha256': 'c' * 64}), \
             patch.object(transport.selectors, 'DefaultSelector', side_effect=selector_factory):
            result = transport.start(self.root, host='archlinux', correlation_id=self.correlation,
                                     source_evidence_leaf=leaf, timeout_seconds=5)
        self.assertEqual(result['state'], 'unknown')
        self.assertEqual(result['originalTransportPid'], self.children[0].pid)
        self.assertEqual(set(transport.HANDLES) - before, {result['evidenceLeaf']})
        handle = transport.HANDLES[result['evidenceLeaf']]
        self.assertIs(handle.child, self.children[0])
        path = self.root / '.runtime' / 'parity-evidence' / result['evidenceLeaf']
        self.assertEqual((path / 'transport.stdout.private').read_bytes(), b'PUBLIC_PREFIX')
        self.assertIsNone(handle.child.poll())
        self.assertFalse(handle.eof)
        self.assertEqual(json.loads((path / 'result.json').read_bytes())['state'], 'unknown')
        self.addCleanup(lambda: transport.HANDLES.pop(result['evidenceLeaf'], None))
        self.addCleanup(handle.capture.close)
        self.addCleanup(lambda: os.close(handle.raw_fd))
        self.addCleanup(lambda: handle.selector.close() if handle.selector is not None else None)

    def test_actual_postpopen_selector_error_retains_original_child_prefix_unknown(self):
        def unavailable():
            raise OSError('local-fixture-selector')
        self.postpopen_refusal(unavailable)

    def test_actual_postpopen_register_error_also_retains_original_handle_and_prefix(self):
        original = transport.selectors.DefaultSelector
        class Refusal:
            def __init__(self):
                self.actual = original()
            def register(self, *args):
                raise RuntimeError('local-fixture-register')
            def close(self):
                self.actual.close()
        self.postpopen_refusal(Refusal)

    def test_generated_fixed_builder_compiles_exact_core_without_native_action(self):
        plan = {'templateRoot': str(transport.core.TEMPLATE_ROOT),
                'guestRoots': list(transport.inventory.DESTINATIONS),
                'sourcePin': {'generation': [1, 2, stat.S_IFREG | 0o600, 1000, 1000, 1, 10, 1, 1],
                              'sha256': 'a' * 64,
                              'parents': [{'path': str(Path(transport.inventory.SOURCE).parent),
                                           'generation': [1, 3, stat.S_IFDIR | 0o700, 1000, 1000]},
                                          {'path': transport.inventory.SOURCE_ROOT,
                                           'generation': [1, 4, stat.S_IFDIR | 0o700, 1000, 1000]}]}}
        for action in ('start', 'status'):
            with patch.object(transport, 'birth', self.native_birth):
                generated = transport.remote_program(plan, self.correlation, action)
            compile(generated, 'fixed bridge', 'exec')
            self.assertIn('prepare_core', generated if action == 'start' else transport.core.remote_program(plan, self.correlation))
            self.assertIn(str(transport.JOB_ROOT), generated)
            self.assertNotIn('force-share', generated)
            self.assertNotIn('password', generated)

    def test_forged_incomplete_or_wrong_action_producer_cannot_claim_prepared(self):
        leaf = self.retained_source()
        plan = transport.core.build_plan(self.root, leaf)
        expected = transport.digest(transport.core.remote_program(plan, self.correlation).encode())
        identity = {'schemaVersion': 1, 'correlationId': self.correlation,
                    'programSha256': expected, 'pid': 10, 'startTicks': 1,
                    'supervisorSha256': 'b' * 64}
        incomplete = {'state': 'prepared', 'identity': identity,
                      'nativeGuestStarted': False, 'launchAdmitted': False, 'productAcceptance': False}
        for action, code in (('start', 'action-state'), ('status', 'prepared-source-binding')):
            with self.subTest(action=action), self.assertRaisesRegex(ValueError, code):
                transport.validate_result(incomplete, plan, self.correlation, action)
        identity['schemaVersion'] = True
        incomplete['state'] = 'running'
        with self.assertRaisesRegex(ValueError, 'transport-original-identity'):
            transport.validate_result(incomplete, plan, self.correlation, 'status')


if __name__ == '__main__':
    unittest.main()
