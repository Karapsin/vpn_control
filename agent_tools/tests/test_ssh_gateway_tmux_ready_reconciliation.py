"""Original late-ready master, real inert transport and local publication races."""
import importlib
import importlib.util
import base64
import hashlib
import json
import os
from pathlib import Path
import shlex
import stat
import subprocess
import tempfile
import time
import unittest
from unittest import mock

from agent_tools import ssh_gateway_tmux_d606_diagnostic as diagnostic
from agent_tools import ssh_gateway_tmux_master as owner, ssh_gateway_tmux_master_ssh as adapter
from agent_tools import ssh_connection_recovery as recovery, ssh_recovery_adoption as adoption
from agent_tools import ssh_expired_recovery_retirement as retirement
from agent_tools.tests import test_ssh_gateway_tmux_d606_diagnostic as fixtures
from agent_tools.tests import test_ssh_gateway_tmux_master as master_fixtures
from agent_tools.tests.test_ssh_expired_recovery_retirement import absence

try: reconciliation = importlib.import_module('agent_tools.ssh_gateway_tmux_ready_reconciliation')
except ModuleNotFoundError: reconciliation = None


_LATE_DELAY = "time.sleep(6.1)\nassert '-M' in args"
_ENTRY_MARKER = '# fixture-owned late-ready pre-entry delay'
_BEFORE = Path(__file__).parent / 'fixtures/ssh_late_ready_handshake/ready.before.source'
_PROVENANCE = Path(__file__).parent / 'fixtures/ssh_late_ready_handshake/provenance.json'
_BEFORE_SHA = '7adb04b07af9bfc18d72a685f48da8bd0c2a5104cd4ef35217a39cab0377ba77'
_ENTRY_WAIT_SECONDS = 8
_SOCKET_WAIT_SECONDS = 8
_SSH_SERVING_SECONDS = 10  # Unchanged finite FAKE_SSH post-bind lifetime.
_ADAPTER_QUERY_SECONDS = 30
_CLEANUP_SECONDS = _ENTRY_WAIT_SECONDS + _SOCKET_WAIT_SECONDS + _SSH_SERVING_SECONDS + 4
# The server starts inside prepare, before either30s adapter query returns.
_TMUX_LIFETIME_SECONDS = 2 * _ADAPTER_QUERY_SECONDS + _CLEANUP_SECONDS


def _late_ready_tmux_source(source):
    old = 'time.monotonic()-start<12'
    actual = 'time.monotonic()-start<' + str(_TMUX_LIFETIME_SECONDS)
    if source.count(old) == 1 and actual not in source: return source.replace(old, actual)
    if source.count(actual) == 1 and old not in source: return source
    raise ValueError('late-ready-fixture-tmux-lifetime')


def _fixture_write(path, raw):
    pending = path.with_name(path.name + '.pending')
    if os.path.lexists(path): raise ValueError('late-ready-fixture-existing-file')
    fd = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'wb', closefd=False) as stream:
            stream.write(raw); stream.flush(); os.fsync(fd)
    finally:
        os.close(fd)
    os.rename(pending, path)


def _fixture_read(path, maximum=65536):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not (stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
                and before.st_nlink == 1 and not before.st_mode & 0o077
                and 0 <= before.st_size <= maximum):
            raise ValueError('late-ready-fixture-file')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(maximum + 1)
        if (len(raw) != before.st_size or owner.generation(before) != owner.generation(os.fstat(fd))
                or owner.generation(before) != owner.generation(path.lstat())):
            raise ValueError('late-ready-fixture-generation')
        return raw
    finally:
        os.close(fd)


def _entry_value(raw, nonce, master):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value: raise ValueError('late-ready-fixture-duplicate-entry')
            value[key] = item
        return value
    if type(raw) is not bytes or len(raw) > 4096: raise ValueError('late-ready-fixture-entry-bound')
    value = json.loads(raw, object_pairs_hook=unique)
    if (type(value) is not dict or set(value) != {'nonce', 'pid', 'socket'}
            or value['nonce'] != nonce or value['socket'] != str(master)
            or type(value['pid']) is not int or value['pid'] <= 0):
        raise ValueError('late-ready-fixture-entry')
    return value


def _late_ready_ssh_source(source, directory, nonce, pre_entry_delay):
    if (source.count(_LATE_DELAY) != 1 or type(nonce) is not str
            or len(nonce) != 32 or any(c not in '0123456789abcdef' for c in nonce)
            or type(pre_entry_delay) not in (int, float) or not 0 <= pre_entry_delay <= 3):
        raise ValueError('late-ready-fixture-source')
    prelude = (
        "_late_directory=pathlib.Path(" + repr(str(directory)) + ")\n"
        "_late_deadline=time.monotonic()+" + str(_ADAPTER_QUERY_SECONDS) + "\n"
        "while not (_late_directory/'released').exists():\n"
        " if time.monotonic()>=_late_deadline:raise RuntimeError('FIXTURE_RELEASE_RETURN_TIMEOUT')\n"
        " time.sleep(.01)\n"
        "assert (_late_directory/'released').read_bytes()==" + repr(nonce.encode()) + "\n"
        + _ENTRY_MARKER + "\n"
        "time.sleep(" + repr(pre_entry_delay) + ")\n"
        "_late_raw=json.dumps({'nonce':" + repr(nonce) + ",'pid':os.getpid(),'socket':str(path)},sort_keys=True).encode()\n"
        "assert not os.path.lexists(_late_directory/'entered.json')\n"
        "_late_fd=os.open(_late_directory/'entered.pending',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)\n"
        "try:\n"
        " with os.fdopen(_late_fd,'wb',closefd=False) as _late_stream:\n"
        "  _late_stream.write(_late_raw);_late_stream.flush();os.fsync(_late_fd)\n"
        "finally:os.close(_late_fd)\n"
        "os.rename(_late_directory/'entered.pending',_late_directory/'entered.json')\n"
    )
    return source.replace(_LATE_DELAY, prelude + _LATE_DELAY)


def _late_ready_diagnostic(case, phase):
    """Capture only this inert fixture's finite child records before cleanup."""
    result = {'phase': phase, 'records': {}}
    job = owner.paths(case.request)[2]
    for name in ('child.json', 'terminal.json', 'stdout.private', 'stderr.private'):
        try:
            raw = _fixture_read(job / name)
        except FileNotFoundError:
            result['records'][name] = {'present': False}
        except (OSError, ValueError) as error:
            result['records'][name] = {'captureError': type(error).__name__}
        else:
            result['records'][name] = {'present': True, 'bytes': len(raw),
                                      'sha256': hashlib.sha256(raw).hexdigest(),
                                      'snapshotBase64Chunks': [base64.b64encode(raw[offset:offset + 8192]).decode('ascii')
                                                               for offset in range(0, len(raw), 8192)],
                                      'boundedSnapshotComplete': True, 'producerEOFObserved': False,
                                      'prefix': raw[:2048].decode('utf-8', errors='backslashreplace'),
                                      'prefixTruncated': len(raw) > 2048}
    case._late_ready_failure_evidence = result
    return json.dumps(result, sort_keys=True, indent=2)


class ReadyReconciliationTests(fixtures.DiagnosticCallerTests):
    _late_ready_pre_entry_delay_seconds = 0

    def finish(self):
        # Only this case's genuine inert stop sentinel; no signals or PID scan.
        try:
            job = owner.paths(self.request)[2]; master = owner.master_path(self.request)
            if master.parent.exists(): (master.parent / 'inert-stop').touch()
            deadline = time.monotonic() + _CLEANUP_SECONDS
            while (job / 't').exists() and time.monotonic() < deadline: time.sleep(.02)
            self.assertFalse((job / 't').exists(), _late_ready_diagnostic(self, 'finite-cleanup') if (job / 't').exists() else None)
        except (OSError, ValueError):
            raise AssertionError('late-ready fixture cleanup could not establish its owned endpoint closure')
        finally:
            # The fake-tmux manager publishes its done record after unlinking t.
            # Always await the inherited registry closure before temp removal; a
            # registry failure retains the home and chains any assertion above.
            super().finish()

    def setUp(self):
        super().setUp()
        self.launcher.stop()
        def launch(argv, **kwargs):
            ssh=argv;command=shlex.split(ssh[-1])
            self.assertIn(command[0], ('python3','/usr/bin/python3'))
            self.assertEqual('gateway.invalid',ssh[-2]);self.assertNotIn('inert-secret',' '.join(ssh))
            kwargs.pop('preexec_fn',None)
            return self.original_popen([os.sys.executable,'-I','-B','-c',command[4],*command[5:]],**kwargs)
        patch=mock.patch.object(diagnostic.subprocess,'Popen',side_effect=launch);patch.start();self.addCleanup(patch.stop)
        config=adapter.transport.load_config(self.controller);self.target=config.hosts['archlinux']
        (self.controller/'.rag_index').mkdir(mode=0o700)
        old='a'*32;oldpath=str(recovery._recovery_socket_path(self.target,old)[1])
        recovery._create_intent(self.controller,'archlinux',self.target,old,oldpath)
        recovery._update_intent(self.controller,'archlinux',self.target,old,'ready',oldpath)
        pins=retirement.authority(self.controller,'archlinux',old)
        with mock.patch.object(retirement,'_observe',return_value=absence(self.target,old)):
            self.assertEqual('retired',retirement.retire(self.controller,'archlinux',old,**pins)['state'])
        self.retired=next((self.controller/recovery._INTENT_DIRECTORY).glob('.retired-*.intent.json'))
        self.retired_bytes=self.retired.read_bytes()
        entry_directory = self.home / 'late-ready-fixture'; entry_directory.mkdir(mode=0o700)
        nonce = os.urandom(16).hex()
        self.tmux.write_text(_late_ready_tmux_source(self.tmux.read_text()))
        source = self.ssh.read_text().replace("assert '-M' in args", _LATE_DELAY)
        self.ssh.write_text(_late_ready_ssh_source(source, entry_directory, nonce,
                                                 self._late_ready_pre_entry_delay_seconds))
        self.prepare_adapter();self.assertEqual('released',adapter.operate(self.controller,'release',self.request_inputs)['state'])
        _fixture_write(entry_directory / 'released', nonce.encode())
        entry_deadline = time.monotonic() + _ENTRY_WAIT_SECONDS
        while not (entry_directory / 'entered.json').exists() and time.monotonic() < entry_deadline: time.sleep(.02)
        if not (entry_directory / 'entered.json').exists(): self.fail(_late_ready_diagnostic(self, 'child-entry'))
        entry = _entry_value(_fixture_read(entry_directory / 'entered.json', 4096), nonce, owner.master_path(self.request))
        deadline=time.monotonic()+_SOCKET_WAIT_SECONDS
        while not owner.master_path(self.request).exists() and time.monotonic()<deadline:time.sleep(.02)
        socket_ready = owner.master_path(self.request).is_socket()
        self.assertTrue(socket_ready, _late_ready_diagnostic(self, 'socket-readiness') if not socket_ready else None)
        self.assertEqual(entry['pid'], json.loads(_fixture_read(owner.paths(self.request)[2] / 'child.json'))['process']['pid'])
        self.assertEqual('unknown',adapter.operate(self.controller,'status',self.request_inputs)['state'])
        result=diagnostic.observe(self.controller);self.assertEqual('observed',result['state'],result)
        self.job=self.controller/'.rag_index/ssh-gateway-tmux-master'/diagnostic.CORRELATION
        self.historical=self.job/result['capsule'];self.historical_digest=owner.sha((self.historical/'proof.private.json').read_bytes())
        if reconciliation is not None:
            self.publisher=self.controller/'reviewed-publisher.py';self.publisher.write_bytes(Path(reconciliation.__file__).read_bytes());self.publisher.chmod(0o600)
            for patch in (mock.patch.object(reconciliation,'HISTORICAL_CAPSULE',self.historical.name),
                          mock.patch.object(reconciliation,'HISTORICAL_PROOF_SHA256',self.historical_digest),
                          mock.patch.object(reconciliation,'HISTORICAL_PROOF_GENERATION',owner.generation((self.historical/'proof.private.json').stat())),
                          mock.patch.object(reconciliation,'DIAGNOSTIC_SOURCE_SHA256',owner.sha(self.caller.read_bytes())),
                          mock.patch.object(reconciliation,'__file__',str(self.publisher))):
                patch.start();self.addCleanup(patch.stop)
        self.canonical=recovery._intent_path(self.controller,'archlinux',self.target)

    def publish(self):
        if reconciliation is None:return adapter.operate(self.controller,'status',self.request_inputs)
        return reconciliation.publish(self.controller)

    def test_real_late_ready_reconciles_into_exact_existing_adoption_flow(self):
        result=self.publish();self.assertEqual('published',result['state'],result)
        expected=recovery._intent_value('archlinux',self.target,diagnostic.CORRELATION.replace('-',''),'ready',self.request['masterControlPath'])
        self.assertEqual(expected,json.loads(self.canonical.read_bytes()))
        self.assertEqual(self.retired_bytes,self.retired.read_bytes())
        remote_job=owner.paths(self.request)[2];self.assertFalse((remote_job/'ready.json').exists())
        self.assertEqual('unknown',adapter.operate(self.controller,'status',self.request_inputs)['state'])
        with mock.patch.object(recovery,'_socket_state',side_effect=['absent','ready']):
            adopted=adoption.adopt(self.controller,'archlinux')
        self.assertEqual('ready',adopted['state'],adopted)
        self.assertNotIn('inert-secret',json.dumps(result))

    def test_consumed_publication_observes_without_queries_or_replay(self):
        self.assertEqual('published',self.publish()['state'])
        with mock.patch.object(diagnostic,'observe',side_effect=AssertionError('no remote replay')):
            self.assertEqual('published',self.publish()['state'])

    def test_second_fresh_read_config_history_source_and_original_proof_races(self):
        actual=diagnostic.observe;calls=[]
        def read(root):
            result=actual(root);calls.append(1)
            if len(calls)==2:self.retired.write_bytes(self.retired.read_bytes())
            return result
        with mock.patch.object(diagnostic,'observe',side_effect=read):self.assertEqual('unknown',self.publish()['state'])
        self.assertFalse(self.canonical.exists())
        with mock.patch.object(diagnostic,'observe',side_effect=AssertionError('consumed')):
            self.assertEqual('unknown',self.publish()['state'])

    def test_same_byte_config_exchange_after_fresh_read_is_rejected(self):
        actual=diagnostic.observe
        def read(root):
            result=actual(root);self.config.write_bytes(self.config.read_bytes());return result
        with mock.patch.object(diagnostic,'observe',side_effect=read):self.assertEqual('unknown',self.publish()['state'])
        self.assertFalse(self.canonical.exists())

    def test_source_exchange_after_fresh_read_is_rejected(self):
        actual=diagnostic.observe
        def read(root):
            result=actual(root);self.publisher.write_bytes(self.publisher.read_bytes());return result
        with mock.patch.object(diagnostic,'observe',side_effect=read):self.assertEqual('unknown',self.publish()['state'])
        self.assertFalse(self.canonical.exists())

    def test_historical_proof_same_byte_generation_exchange_blocks_before_fence(self):
        path=self.historical/'proof.private.json';path.write_bytes(path.read_bytes())
        with mock.patch.object(diagnostic,'observe',side_effect=AssertionError('no query')):
            self.assertEqual('unknown',self.publish()['state'])
        self.assertFalse((self.job/'.reconciliation.pending.json').exists())

    def test_original_job_parent_exchange_after_fresh_read_is_rejected(self):
        actual=diagnostic.observe;old=self.job.with_name('original-old')
        def read(root):
            result=actual(root);self.job.rename(old);self.job.mkdir(mode=0o700);return result
        with mock.patch.object(diagnostic,'observe',side_effect=read):self.assertEqual('unknown',self.publish()['state'])
        self.assertFalse(self.canonical.exists())
        self.job.rmdir();old.rename(self.job)

    def test_foreign_canonical_symlink_is_never_overwritten(self):
        foreign=self.controller/'foreign';foreign.write_bytes(b'foreign');foreign.chmod(0o600)
        self.canonical.symlink_to(foreign)
        self.assertEqual('unknown',self.publish()['state'])
        self.assertEqual(b'foreign',foreign.read_bytes());self.assertTrue(self.canonical.is_symlink())

    def test_pending_last_body_read_rewrite_rejects_before_canonical_create(self):
        actual=os.pread;changed=[]
        def read(fd,*args):
            result=actual(fd,*args)
            pending=self.job/'.reconciliation.pending.json'
            completed=list(self.job.glob('query-diagnostic-*/proof.private.json'))
            if not changed and len(completed)>=3 and pending.exists() and os.fstat(fd).st_ino==pending.stat().st_ino:
                changed.append(1);pending.write_bytes(b'{}')
            return result
        with mock.patch.object(os,'pread',side_effect=read):self.assertEqual('unknown',self.publish()['state'])
        self.assertTrue(changed);self.assertFalse(self.canonical.exists())

    def test_post_create_guard_failure_preserves_unknown_without_replay(self):
        actual=owner.create
        def create(directory,name,*args,**kwargs):
            pin=actual(directory,name,*args,**kwargs)
            if name==self.canonical.name:self.config.write_bytes(self.config.read_bytes())
            return pin
        with mock.patch.object(owner,'create',side_effect=create):self.assertEqual('unknown',self.publish()['state'])
        self.assertTrue(self.canonical.exists());self.assertFalse((self.job/'.reconciliation.published.json').exists())
        with mock.patch.object(diagnostic,'observe',side_effect=AssertionError('no replay')):
            self.assertEqual('unknown',self.publish()['state'])


@unittest.skipUnless(os.name == 'posix', 'POSIX inert process/socket fixture')
class LateReadyHandshakeRegressionTests(unittest.TestCase):
    def test_bounded_diagnostic_snapshot_preserves_full_bytes_without_producer_eof(self):
        with tempfile.TemporaryDirectory(prefix='vct-late-diagnostic-', dir='/tmp') as directory:
            root = Path(directory).resolve(); payload = bytes(range(256)) * 32
            _fixture_write(root / 'stderr.private', payload)
            case = type('OwnedInertDiagnostic', (), {'request': None})()
            with mock.patch.object(owner, 'paths', return_value=(None, None, root)):
                rendered = _late_ready_diagnostic(case, 'owned-unit-snapshot')
            record = json.loads(rendered)['records']['stderr.private']
            self.assertEqual(payload, b''.join(base64.b64decode(value, validate=True) for value in record['snapshotBase64Chunks']))
            self.assertEqual(hashlib.sha256(payload).hexdigest(), record['sha256'])
            self.assertTrue(record['boundedSnapshotComplete']); self.assertFalse(record['producerEOFObserved'])
            self.assertTrue(record['prefixTruncated'])
            self.assertTrue(all(len(line.encode()) <= 16384 for line in rendered.splitlines()))

    def test_entry_acknowledgement_keeps_exact_nonce_pid_socket_and_shape(self):
        nonce = 'a' * 32; master = Path('/tmp/owned-inert-entry/m')
        value = {'nonce': nonce, 'pid': os.getpid(), 'socket': str(master)}
        self.assertEqual(value, _entry_value(json.dumps(value).encode(), nonce, master))
        for key, replacement in (('nonce', 'b' * 32), ('pid', True), ('pid', 0), ('socket', '/tmp/foreign/m'), ('extra', True)):
            with self.subTest(field=key, value=replacement), self.assertRaises(ValueError):
                _entry_value(json.dumps({**value, key: replacement}).encode(), nonce, master)
        with self.assertRaises(ValueError):
            _entry_value(b'{"nonce":"a","nonce":"a","pid":1,"socket":"m"}', nonce, master)

    def test_fixture_record_reads_refuse_symlinks_and_oversized_bytes(self):
        with tempfile.TemporaryDirectory(prefix='vct-late-record-', dir='/tmp') as directory:
            root = Path(directory).resolve(); target = root / 'target'
            _fixture_write(target, b'owned-inert-record')
            self.assertEqual(b'owned-inert-record', _fixture_read(target))
            link = root / 'link'; link.symlink_to(target)
            with self.assertRaises(OSError): _fixture_read(link)
            target.write_bytes(b'x' * 65537)
            with self.assertRaises(ValueError): _fixture_read(target)

    def _controlled(self, case, *, before):
        from agent_tools.tests.ssh_gateway_historical_fixture import archived
        with archived():
            return self._controlled_archived(case,before=before)

    def _controlled_archived(self, case, *, before):
        """The same real three-second pre-entry phase precedes the real6.1s delay."""
        actual_write, actual_operate = Path.write_text, adapter.operate
        actual_registry_finish = master_fixtures.FixtureChildren.finish
        changed, server_changed, registry_finished = [], [], []

        def registry_finish(registry, *args, **kwargs):
            registry_finished.append(registry)
            return actual_registry_finish(registry, *args, **kwargs)

        def write(path, text, *args, **kwargs):
            if path == getattr(case, 'tmux', None) and 'time.monotonic()-start<12' in text:
                server_changed.append(True)
                # Both controlled variants receive the same derived lifetime.
                text = _late_ready_tmux_source(text)
            if before and path == getattr(case, 'ssh', None) and _LATE_DELAY in text:
                self.assertEqual(1, text.count(_LATE_DELAY)); changed.append(True)
                gate = case.home / 'controlled-release-returned'
                prelude = (
                    "_controlled_gate=pathlib.Path(" + repr(str(gate)) + ")\n"
                    "_controlled_deadline=time.monotonic()+" + str(_ADAPTER_QUERY_SECONDS) + "\n"
                    "while not _controlled_gate.exists():\n"
                    " if time.monotonic()>=_controlled_deadline:raise RuntimeError('CONTROLLED_RELEASE_RETURN_TIMEOUT')\n"
                    " time.sleep(.01)\n"
                    "time.sleep(3)\n"
                )
                text = text.replace(_LATE_DELAY, prelude + _LATE_DELAY)
            return actual_write(path, text, *args, **kwargs)

        def operate(root, action, *args, **kwargs):
            result = actual_operate(root, action, *args, **kwargs)
            if before and root == getattr(case, 'controller', None) and action == 'release' and result.get('state') == 'released':
                _fixture_write(case.home / 'controlled-release-returned', b'owned controlled fixture')
            return result

        case._late_ready_pre_entry_delay_seconds = 3
        with mock.patch.object(Path, 'write_text', write), mock.patch.object(adapter, 'operate', operate), \
             mock.patch.dict(case.setUp.__globals__, {'adapter':adapter,'diagnostic':diagnostic}), \
             mock.patch.object(master_fixtures.FixtureChildren, 'finish', registry_finish):
            result = unittest.TestResult(); case.run(result)
        self.assertEqual([True] if before else [], changed)
        self.assertEqual([True], server_changed)
        # Archived (inherited) and current (delegating) cleanup each await only
        # their own original registry once before the owned temp home is removed.
        self.assertEqual([case.fixture_registry], registry_finished)
        return result

    def test_actual_preserved_setup_socket_assertion_red_then_handshake_green(self):
        provenance_fd = os.open(_PROVENANCE, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(provenance_fd)
            self.assertTrue(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1)
            self.assertLessEqual(info.st_size, 4096)
            with os.fdopen(provenance_fd, 'rb', closefd=False) as stream: provenance_raw = stream.read(4097)
            self.assertEqual(info.st_size, len(provenance_raw))
            self.assertEqual(owner.generation(info), owner.generation(os.fstat(provenance_fd)))
            self.assertEqual(owner.generation(info), owner.generation(_PROVENANCE.lstat()))
            provenance = json.loads(provenance_raw)
        finally:
            os.close(provenance_fd)
        self.assertEqual(_BEFORE_SHA, provenance['sourceSha256'])
        self.assertEqual(9921, provenance['sourceBytes'])
        fd = os.open(_BEFORE, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            opened = os.fstat(fd)
            self.assertTrue(stat.S_ISREG(opened.st_mode) and opened.st_uid == os.getuid() and opened.st_nlink == 1)
            with os.fdopen(fd, 'rb', closefd=False) as stream: raw = stream.read(9922)
            self.assertEqual(9921, len(raw)); self.assertEqual(_BEFORE_SHA, hashlib.sha256(raw).hexdigest())
            self.assertEqual(owner.generation(opened), owner.generation(os.fstat(fd)))
            self.assertEqual(owner.generation(opened), owner.generation(_BEFORE.lstat()))
            with tempfile.TemporaryDirectory(prefix='vct-late-before-', dir='/tmp') as directory:
                path = Path(directory).resolve() / 'ready_before.py'; path.write_bytes(raw); path.chmod(0o600)
                spec = importlib.util.spec_from_file_location('_actual_late_ready_before', path)
                self.assertIsNotNone(spec); self.assertIsNotNone(spec.loader)
                module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
                # Only the archived external fake-SSH representation changed:
                # its old launcher decoded a JSON wrapper, while the immutable
                # carrier now passes the already-guarded SSH argv directly.
                # Target command bytes and real child/socket behavior stay exact.
                from types import SimpleNamespace
                def legacy_fake_json(raw,*args,**kwargs):
                    if type(raw)is str and raw.startswith(('python3 -I -B -c ','/usr/bin/python3 -I -B -c ')):
                        return ['/usr/bin/ssh','gateway.invalid',raw]
                    return json.loads(raw,*args,**kwargs)
                module.json=SimpleNamespace(loads=legacy_fake_json,dumps=json.dumps)
                name = 'test_real_late_ready_reconciles_into_exact_existing_adoption_flow'
                old = self._controlled(module.ReadyReconciliationTests(name), before=True)
                self.assertEqual((1, 1, 0, 0), (old.testsRun, len(old.failures), len(old.errors), len(old.skipped)),
                                 ''.join(text for _, text in old.failures + old.errors))
                self.assertIn(str(path) + '\", line 46, in setUp', old.failures[0][1])
                self.assertIn('AssertionError: False is not true', old.failures[0][1])
                self.assertEqual(raw, path.read_bytes())
                current = self._controlled(ReadyReconciliationTests(name), before=False)
                self.assertEqual((1, 0, 0, 0), (current.testsRun, len(current.failures), len(current.errors), len(current.skipped)),
                                 ''.join(text for _, text in current.failures + current.errors))
            self.assertEqual(owner.generation(opened), owner.generation(os.fstat(fd)))
            self.assertEqual(owner.generation(opened), owner.generation(_BEFORE.lstat()))
            os.lseek(fd, 0, os.SEEK_SET); self.assertEqual(raw, os.read(fd, 9922))
        finally:
            os.close(fd)


for _name in dir(ReadyReconciliationTests):
    if _name.startswith('test_') and _name not in ReadyReconciliationTests.__dict__:setattr(ReadyReconciliationTests,_name,None)
del _name
