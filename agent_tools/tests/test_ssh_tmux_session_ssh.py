"""Inert fixed transport/driver checks; no SSH, tmux, clone, or package execution."""
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import socket
import types
import inspect
import textwrap
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

from agent_tools import ssh_tmux_session_ssh as adapter
from agent_tools import ssh_tmux_session as session
from agent_tools import linux_package_fixture_build as build

ROOT = Path(__file__).resolve().parents[2]


def pin(number=1, digest='a' * 64):
    return {'generation': [1, number, 33152, os.getuid(), os.getgid(), 1, 1, 1, 1], 'sha256': digest}


class Remote:
    def __init__(self):
        self.calls = []; self.builds = 0; self.release_loss = False; self.stage_loss = False
        self.collect_loss = False; self.ready = False; self.archive = b''; self.response_extra = False

    def query(self, program, payload, *, job=None, guard=None):
        if guard: guard()
        self.calls.append((program, payload))
        if program == adapter._AVAILABILITY:
            return {'available': True, 'reason': 'available', 'nativeActionAllowed': False}
        req = payload['request']; corr = req['correlationId']
        if program == adapter._STAGE:
            if self.stage_loss: raise adapter.AdapterError('transport_unknown')
            return {'state': 'staged', 'correlationId': corr, 'stagePin': pin(1)}
        action = payload['action']
        if action == 'prepare':
            return {'state': 'prepared', 'correlationId': corr, 'anchorPin': pin(2),
                    'replayAllowed': False, 'artifactVerification': 'required'}
        if action == 'release':
            self.builds += 1
            if self.release_loss: raise adapter.AdapterError('transport_unknown')
            return {'state': 'released', 'correlationId': corr, 'replayAllowed': False, 'artifactVerification': 'required'}
        if action == 'status':
            result = {'state': 'terminal' if self.ready else 'running', 'correlationId': corr,
                      'replayAllowed': False, 'artifactVerification': 'required'}
            if self.ready: result.update(exitCode=0, terminalPin=pin(3))
            if self.response_extra: result['stderr'] = 'private secret'
            return result
        if action == 'collect':
            offset = payload['offset']
            if self.collect_loss and offset > 0:
                self.collect_loss = False; raise adapter.AdapterError('transport_unknown')
            result_pin = pin(4, hashlib.sha256(self.archive).hexdigest()); result_pin['generation'][5] = len(self.archive)
            if payload['resultPin'] is not None: assert payload['resultPin'] == result_pin
            return {'offset': offset, 'totalBytes': len(self.archive),
                    'chunkBase64': base64.b64encode(self.archive[offset:offset + payload['limit']]).decode(),
                    'resultSha256': result_pin['sha256'], 'resultPin': result_pin,
                    'artifactVerification': 'required', 'replayAllowed': False}
        raise AssertionError(action)


@unittest.skipUnless(os.name == 'posix', 'POSIX private authority')
class DriverTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir='/tmp'); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.root.chmod(0o700)
        tools = self.root / 'agent_tools'; tools.mkdir()
        for name in ('linux_package_fixture_build.py', 'ssh_tmux_session.py'):
            shutil.copyfile(ROOT / 'agent_tools' / name, tools / name)
        key = self.root / 'key'; key.write_bytes(b'private key'); key.chmod(0o600)
        known = self.root / 'known'; known.write_bytes(b'known host'); known.chmod(0o600)
        config = {'schemaVersion': 1, 'hosts': {'archlinux': {'host': 'fixture', 'port': 22, 'user': 'owner',
                  'identityFile': str(key), 'knownHostsFile': str(known)}}}
        (self.root / '.vm-hosts.local.json').write_text(json.dumps(config)); (self.root / '.vm-hosts.local.json').chmod(0o600)
        self.req = {'sourceSha': 'd32f719a08db57e5d40ce2bf77e0d7c5b42de557', 'baseVersion': '2.1.19',
                    'targetVersion': '2.2.2', 'correlationId': 'da8fd22e-6d2d-4cc5-8fb8-6aae90946f47'}
        self.remote = Remote(); self.driver = adapter.TmuxArchDriver(self.root)
        self.query = mock.patch.object(self.driver, '_query', side_effect=self.remote.query); self.query.start(); self.addCleanup(self.query.stop)
        self.admission = mock.patch.object(build, '_source_preflight'); self.admission.start(); self.addCleanup(self.admission.stop)

    def start(self):
        return build.start(self.root, self.req, driver=self.driver, admission=lambda *args: {'state': 'ready'})

    def job(self): return self.root / build._JOURNAL / self.req['correlationId']

    def archive(self):
        files = {}; fingerprint = 'b' * 64; code = 'c' * 64
        for family, types in (('default', ('deb', 'rpm', 'arch-bundle')), ('arch', ('arch-bundle',))):
            builds = []
            for label, version in (('base', '2.1.19'), ('target', '2.2.2')):
                assets = []
                for typ in types:
                    name = label + '-' + typ + '.pkg'; body = (family + label + typ).encode() * 16000
                    path = family + '/packages/' + label + '/' + name; files[path] = body
                    assets.append({'packageType': typ, 'fileName': name, 'sizeBytes': len(body), 'sha256': hashlib.sha256(body).hexdigest()})
                builds.append({'label': label, 'version': version, 'sourceFingerprint': fingerprint, 'codeFingerprint': code, 'assets': assets})
            files[family + '/snapshot.json'] = json.dumps({'sourceHead': self.req['sourceSha'], 'sourceFingerprint': fingerprint}).encode()
            files[family + '/build-plan.json'] = json.dumps({'sourceFingerprint': fingerprint, 'packageFamily': family}).encode()
            files[family + '/fixture-receipt.json'] = json.dumps({'sourceFingerprint': fingerprint, 'testOnly': True,
                    'productionTrustChanged': False, 'builds': builds, 'manifest': {'assets': builds[1]['assets']}}).encode()
            for stage in ('base', 'target'):
                for phase in ('runtime-prep', 'gradle', 'packaging'):
                    name = f'linux-package-{family}-{self.req["correlationId"]}-{phase}-{stage}.json'
                    files['.rag_index/build-timings/' + name] = json.dumps({'schemaVersion': 1, 'sourceSha': self.req['sourceSha'],
                         'pipelineId': 'linux-package-' + family, 'runId': self.req['correlationId'], 'hostAlias': 'archlinux',
                         'phase': phase, 'startedMonotonicNs': 1, 'finishedMonotonicNs': 2}).encode()
        out = io.BytesIO()
        with tarfile.open(fileobj=out, mode='w') as tar:
            for name, body in files.items():
                info = tarfile.TarInfo(name); info.size = len(body); tar.addfile(info, io.BytesIO(body))
        self.remote.archive = out.getvalue(); self.remote.ready = True

    def test_coordinator_injected_driver_retains_authority_before_release(self):
        self.assertEqual('submitted', self.start()['state'])
        self.assertTrue((self.job() / 'tmux-anchor.json').is_file())
        self.assertTrue((self.job() / 'tmux-release-intent.json').is_file())
        self.assertEqual(1, self.remote.builds)
        for _ in range(2): self.assertEqual('running', build.status(self.root, {'correlationId': self.req['correlationId']}, driver=self.driver)['state'])
        self.assertEqual('unknown', self.start()['state']); self.assertEqual(1, self.remote.builds)

    def test_missing_claim_cannot_direct_submit(self):
        with self.assertRaises(adapter.AdapterError): self.driver.submit(self.req)
        self.assertEqual([], self.remote.calls)

    def test_partial_stage_loss_preserves_claim_intent_no_reclone(self):
        self.remote.stage_loss = True
        self.assertEqual('unknown', self.start()['state'])
        self.assertTrue((self.job() / 'tmux-adapter-intent.json').is_file())
        self.assertFalse((self.job() / 'tmux-anchor.json').exists())
        self.remote.stage_loss = False; self.assertEqual('unknown', self.start()['state'])
        self.assertEqual(1, sum(p == adapter._STAGE for p, unused in self.remote.calls))
        self.assertEqual(0, self.remote.builds)

    def test_lost_release_response_new_driver_observes_no_resubmit(self):
        self.remote.release_loss = True; self.assertEqual('unknown', self.start()['state'])
        fresh = adapter.TmuxArchDriver(self.root)
        with mock.patch.object(fresh, '_query', side_effect=self.remote.query):
            self.assertEqual('running', fresh.status(self.req)['state'])
            with self.assertRaises(FileExistsError): fresh.release(self.req)
        self.assertEqual(1, self.remote.builds)

    def test_same_byte_claim_exchange_blocks_every_transport(self):
        self.start(); claim = self.root / build._JOURNAL / 'archlinux.claim'
        new = claim.with_suffix('.new'); shutil.copyfile(claim, new); new.chmod(0o600); new.replace(claim)
        count = len(self.remote.calls)
        self.assertEqual('unknown', self.driver.status(self.req)['state'])
        self.assertEqual(count, len(self.remote.calls))

    def test_reviewed_timeout_repair_overlay_passes_exact_tools_gate(self):
        # This specific producer delta has independent causal review 245b9910.
        with mock.patch.object(self.driver, '_transport', side_effect=AssertionError('No transport')) as transport:
            tools = self.driver._tools()
        self.assertEqual('874b7be8d70e917553d466ed2b8ad71419dec5f21bfd3092060f16180c284cf5',
                         tools['linux_package_fixture_build.py']['pin']['sha256'])
        transport.assert_not_called()
        self.assertEqual([], self.remote.calls)

    def test_unreviewed_producer_replacement_refuses_before_transport(self):
        path = self.root / 'agent_tools/linux_package_fixture_build.py'
        path.write_bytes(path.read_bytes() + b'\n')
        with mock.patch.object(self.driver, '_transport', side_effect=AssertionError('No transport')) as transport:
            with self.assertRaisesRegex(adapter.AdapterError, 'unreviewed_tool_source'):
                self.driver._tools()
        transport.assert_not_called()
        self.assertEqual([], self.remote.calls)

    def test_tool_and_configuration_drift_are_not_adopted(self):
        self.start(); path = self.root / 'agent_tools/ssh_tmux_session.py'; path.write_bytes(path.read_bytes() + b'\n')
        self.assertEqual('unknown', self.driver.status(self.req)['state'])
        self.assertEqual(1, self.remote.builds)

    def test_readonly_dependency_unavailable_consumes_no_build_claim(self):
        with mock.patch.object(self.driver, 'availability', return_value={'available': False, 'reason': 'tmux_unavailable', 'nativeActionAllowed': False}), \
             mock.patch.object(build, 'preflight', return_value={'state': 'ready'}):
            result = self.driver.preflight(self.req)
        self.assertEqual('blocked', result['state']); self.assertFalse((self.root / build._JOURNAL / 'archlinux.claim').exists())
        self.assertEqual([], self.remote.calls)

    def test_status_does_not_download_or_expose_forged_fields(self):
        self.start(); self.archive()
        self.assertEqual('unknown', self.driver.status(self.req)['state'])
        self.assertFalse((self.job() / 'chunks').exists())
        self.remote.response_extra = True; result = self.driver.status(self.req)
        self.assertNotIn('secret', json.dumps(result)); self.assertNotIn('remoteTerminal', result)
        self.assertFalse(any(p == adapter._ACTION and raw['action'] == 'collect' for p, raw in self.remote.calls))

    def test_interrupted_collection_resumes_immutable_chunks_without_rebuild(self):
        self.start(); self.archive(); self.remote.collect_loss = True
        self.assertGreater(len(self.remote.archive), 1024**2)
        with mock.patch.object(build.FixedArchDriver, 'collect', return_value={'state': 'ready'}) as registered:
            with self.assertRaises(adapter.AdapterError): self.driver.collect_existing(self.req)
            registered.assert_not_called()
            self.assertTrue((self.job() / 'chunks/000000000000.bin').exists())
            self.assertEqual('ready', self.driver.collect_existing(self.req)['state'])
            self.assertEqual(1, registered.call_count)
        self.assertEqual(1, self.remote.builds)
        self.assertEqual('ready', self.driver.status(self.req)['state'])

    def test_local_assembly_interruption_retains_attempt_and_resumes_no_rebuild(self):
        self.start(); self.archive(); original = session.read; failed = False
        def interrupted(path, *args, **kwargs):
            nonlocal failed
            if path.parent.name == 'chunks' and path.name == '000001048576.bin' and any(self.job().glob('archive-attempt-*')) and not failed:
                failed = True; raise adapter.AdapterError('lost_local_assembly')
            return original(path, *args, **kwargs)
        with mock.patch.object(session, 'read', side_effect=interrupted), mock.patch.object(build.FixedArchDriver, 'collect', return_value={'state': 'ready'}):
            with self.assertRaisesRegex(adapter.AdapterError, 'lost_local_assembly'): self.driver.collect_existing(self.req)
            self.assertFalse((self.job() / 'result.tar').exists()); partial = list(self.job().glob('archive-attempt-*'))
            self.assertEqual(1, len(partial)); partial_pin = adapter.file_pin(partial[0], session.MAX_RESULT)
            self.assertEqual('ready', self.driver.collect_existing(self.req)['state'])
            self.assertEqual(partial_pin, adapter.file_pin(partial[0], session.MAX_RESULT))
        self.assertEqual(1, self.remote.builds)

    def test_local_extraction_interruption_retains_attempt_and_resumes_no_rebuild(self):
        self.start(); self.archive(); original = adapter.file_pin; failed = False
        def interrupted(path, maximum):
            nonlocal failed
            if any(part.startswith('output-attempt-') for part in path.parts) and not failed:
                failed = True; raise adapter.AdapterError('lost_local_extraction')
            return original(path, maximum)
        with mock.patch.object(adapter, 'file_pin', side_effect=interrupted), mock.patch.object(build.FixedArchDriver, 'collect', return_value={'state': 'ready'}):
            with self.assertRaisesRegex(adapter.AdapterError, 'lost_local_extraction'): self.driver.collect_existing(self.req)
            self.assertFalse((self.job() / 'output').exists()); partial = list(self.job().glob('output-attempt-*'))
            self.assertEqual(1, len(partial)); old_files = {str(p.relative_to(partial[0])): p.read_bytes() for p in partial[0].rglob('*') if p.is_file()}
            self.assertEqual('ready', self.driver.collect_existing(self.req)['state'])
            self.assertEqual(old_files, {str(p.relative_to(partial[0])): p.read_bytes() for p in partial[0].rglob('*') if p.is_file()})
        self.assertEqual(1, self.remote.builds)

    def test_result_authority_publication_loss_resumes_without_adopting_partial(self):
        self.start(); self.archive(); original = adapter.rename_complete; failed = False
        def interrupted(source, target):
            nonlocal failed
            if target.name == 'result-authority' and not failed:
                failed = True; raise adapter.AdapterError('lost_authority_publication')
            return original(source, target)
        with mock.patch.object(adapter, 'rename_complete', side_effect=interrupted), mock.patch.object(build.FixedArchDriver, 'collect', return_value={'state': 'ready'}):
            with self.assertRaisesRegex(adapter.AdapterError, 'lost_authority_publication'): self.driver.collect_existing(self.req)
            self.assertFalse((self.job() / 'result-authority').exists())
            self.assertEqual(1, len(list(self.job().glob('result-authority-attempt-*'))))
            self.assertEqual('ready', self.driver.collect_existing(self.req)['state'])
        self.assertEqual(1, self.remote.builds)

    def test_original_fixed_partial_archive_recovery_wedge_is_causal(self):
        self.start(); self.archive()
        source = textwrap.dedent(inspect.getsource(adapter.TmuxArchDriver.collect_existing))
        original = 'temporary_archive = job / ("archive-attempt-" + str(uuid4()) + ".tar")'
        self.assertEqual(1, source.count(original))
        source = source.replace(original, 'temporary_archive = archive').replace('rename_complete(temporary_archive, archive)', 'pass')
        namespace = dict(adapter.__dict__); exec(compile(source, 'inert-original-fixed-archive', 'exec'), namespace)
        broken = types.MethodType(namespace['collect_existing'], self.driver)
        read = session.read; failed = False
        def interrupt(path, *args, **kwargs):
            nonlocal failed
            if path.parent.name == 'chunks' and path.name == '000001048576.bin' and (self.job() / 'result.tar').exists() and not failed:
                failed = True; raise adapter.AdapterError('inert_disconnect')
            return read(path, *args, **kwargs)
        with mock.patch.object(session, 'read', side_effect=interrupt):
            with self.assertRaisesRegex(adapter.AdapterError, 'inert_disconnect'): broken(self.req)
            self.assertTrue((self.job() / 'result.tar').exists())
            with self.assertRaisesRegex(adapter.AdapterError, 'local_archive_changed'): broken(self.req)
        self.assertEqual(1, self.remote.builds)

    def test_completed_extraction_promotion_loss_before_ready_is_recoverable(self):
        self.start(); self.archive(); write = session.write_once; failed = False
        def interrupt(path, raw):
            nonlocal failed
            if path.name == 'tmux-output-ready.json' and not failed:
                failed = True; raise adapter.AdapterError('lost_ready_response')
            return write(path, raw)
        with mock.patch.object(session, 'write_once', side_effect=interrupt), mock.patch.object(build.FixedArchDriver, 'collect', return_value={'state': 'ready'}):
            with self.assertRaisesRegex(adapter.AdapterError, 'lost_ready_response'): self.driver.collect_existing(self.req)
            self.assertTrue((self.job() / 'output/tmux-extraction-complete.json').is_file())
            self.assertEqual('ready', self.driver.collect_existing(self.req)['state'])
        self.assertEqual(1, self.remote.builds)

    def test_same_byte_result_record_replacement_refused_before_new_query(self):
        self.start(); self.archive(); self.remote.collect_loss = True
        with self.assertRaises(adapter.AdapterError): self.driver.collect_existing(self.req)
        record = self.job() / 'result-authority/record.json'; replacement = record.with_name('replacement')
        replacement.write_bytes(record.read_bytes()); replacement.chmod(0o600); replacement.replace(record)
        count = len(self.remote.calls)
        with self.assertRaisesRegex(adapter.AdapterError, 'result_authority_changed'): self.driver.collect_existing(self.req)
        self.assertEqual(count, len(self.remote.calls)); self.assertEqual(1, self.remote.builds)

    def test_public_operations_have_exact_request_types_and_use_coordinator_claim(self):
        with mock.patch.object(adapter, 'TmuxArchDriver', return_value=self.driver), mock.patch.object(build, 'preflight', return_value={'state': 'ready'}):
            self.assertTrue(adapter.operate(self.root, 'availability', {})['available'])
            with self.assertRaises(adapter.AdapterError): adapter.operate(self.root, 'availability', {'command': 'sh'})
            self.assertEqual('ready', adapter.operate(self.root, 'preflight', self.req)['state'])
            self.assertEqual('submitted', adapter.operate(self.root, 'start', self.req)['state'])
            self.assertEqual('running', adapter.operate(self.root, 'status', {'correlationId': self.req['correlationId']})['state'])
            with self.assertRaises(adapter.AdapterError): adapter.operate(self.root, 'status', self.req)
            with self.assertRaises(adapter.AdapterError): adapter.operate(self.root, 'exec', {'command': 'sh'})
        self.assertEqual(1, self.remote.builds)

    def test_archive_traversal_rejected_before_registration(self):
        self.start(); self.remote.ready = True; out = io.BytesIO()
        with tarfile.open(fileobj=out, mode='w') as tar:
            info = tarfile.TarInfo('../foreign'); info.size = 1; tar.addfile(info, io.BytesIO(b'x'))
        self.remote.archive = out.getvalue()
        with mock.patch.object(build.FixedArchDriver, 'collect') as registered:
            with self.assertRaisesRegex(adapter.AdapterError, 'unsafe_archive'): self.driver.collect_existing(self.req)
            registered.assert_not_called()
        self.assertFalse((self.job().parent / 'foreign').exists())

    def test_actual_query_exit255_retains_private_streams_and_finite_failure(self):
        self.query.stop()
        driver = self.driver
        class Process:
            returncode = 255
            def __init__(self, argv, **kwargs):
                self.out = kwargs['stdout']; self.err = kwargs['stderr']
            def communicate(self, **kwargs):
                self.out.write(b'{"available":true}'); self.err.write(b'private transport secret')
        with mock.patch.object(adapter.subprocess, 'Popen', Process):
            with self.assertRaisesRegex(adapter.AdapterError, '^transport_unknown$'): driver.availability()
        capsule = next((self.root / '.rag_index').glob('tmux-query-*'))
        self.assertEqual(b'private transport secret', (capsule / 'stderr').read_bytes())
        value = json.loads((capsule / 'receipt.json').read_bytes())
        self.assertEqual(255, value['exitCode']); self.assertFalse(value['replayAllowed'])
        self.assertNotIn('secret', json.dumps(value))
        self.assertEqual(0o600, (capsule / 'stderr').stat().st_mode & 0o777)

    def test_actual_query_timeout_kills_only_owned_client_retains_partial_chunks(self):
        self.query.stop(); events = []
        class Process:
            returncode = None
            def __init__(self, argv, **kwargs): self.out = kwargs['stdout']; self.err = kwargs['stderr']
            def communicate(self, **kwargs):
                self.out.write(b'partial'); self.err.write(b'private timeout marker')
                raise subprocess.TimeoutExpired('owned-client', 95)
            def kill(self): events.append('owned-client-kill')
            def wait(self, timeout): self.returncode = -9; events.append(('wait', timeout))
        with mock.patch.object(adapter.subprocess, 'Popen', Process):
            with self.assertRaisesRegex(adapter.AdapterError, '^transport_unknown$'): self.driver.availability()
        self.assertEqual(['owned-client-kill', ('wait', 2)], events)
        capsule = next((self.root / '.rag_index').glob('tmux-query-*'))
        value = json.loads((capsule / 'receipt.json').read_bytes())
        self.assertTrue(value['timedOut']); self.assertEqual(b'partial', (capsule / 'stdout').read_bytes())

    def test_actual_generated_stage_action_imports_fixed_overlay_no_foreground_build(self):
        remote = self.root / 'remote'; remote.mkdir(mode=0o700)
        original_path = Path
        def translated(value='.', *args):
            return remote if str(value) == adapter.REMOTE_ROOT else original_path(value, *args)
        translated.home = original_path.home
        commands = []; sockets = []
        original_read = Path.read_text
        def process_stat(path, *args, **kwargs):
            if str(path) in ('/proc/100/stat', '/proc/200/stat'):
                return path.name + ' (owned) S ' + '0 ' * 18 + '1100\n'
            return original_read(path, *args, **kwargs)
        def native(args, **kwargs):
            commands.append(args)
            if args[:2] == ['git', 'clone']:
                source = original_path(args[-1]); source.mkdir(); (source / 'agent_tools').mkdir()
                return subprocess.CompletedProcess(args, 0, b'', b'')
            if args[0] == 'git':
                return subprocess.CompletedProcess(args, 0, (self.req['sourceSha'] + '\n').encode() if args[-1] == 'HEAD' else b'', b'')
            if args == ['tmux', '-V']: return subprocess.CompletedProcess(args, 0, b'tmux 3.4\n', b'')
            if 'new-session' in args:
                sock = socket.socket(socket.AF_UNIX); sock.bind(str(remote / self.req['correlationId'] / 'tmux.sock'))
                os.chmod(remote / self.req['correlationId'] / 'tmux.sock', 0o600); sockets.append(sock)
                return subprocess.CompletedProcess(args, 0, b'', b'')
            if 'display-message' in args: return subprocess.CompletedProcess(args, 0, b'100 200\n', b'')
            if 'list-sessions' in args: return subprocess.CompletedProcess(args, 0, ('vpn-build-' + self.req['correlationId'] + '\n').encode(), b'')
            raise AssertionError('unapproved native command: ' + repr(args))
        def generated(program, payload):
            output = io.StringIO(); previous = list(sys.path)
            try:
                with mock.patch('pathlib.Path', translated), mock.patch.object(Path, 'read_text', process_stat), \
                     mock.patch('subprocess.run', side_effect=native), mock.patch.object(sys, 'stdin', types.SimpleNamespace(buffer=io.BytesIO(session.canonical(payload)))), \
                     mock.patch.object(sys, 'stdout', output):
                    exec(compile(program, 'fixed-generated-tmux-remote', 'exec'), {})
                return json.loads(output.getvalue())
            finally: sys.path[:] = previous
        tools = self.driver._tools()
        payload = {'request': adapter.purpose(self.req), 'build': base64.b64encode(tools['linux_package_fixture_build.py']['raw']).decode(),
                   'tool': base64.b64encode(tools['ssh_tmux_session.py']['raw']).decode()}
        try:
            stage = generated(adapter._STAGE, payload)
            self.assertEqual('staged', stage['state'])
            job = remote / self.req['correlationId']
            self.assertFalse((job / 'tmux-launch.json').exists())
            with self.assertRaises(FileExistsError): generated(adapter._STAGE, payload)
            action = {'action': 'prepare', 'request': payload['request'], 'stagePin': stage['stagePin']}
            prepared = generated(adapter._ACTION, action)
            self.assertEqual('prepared', prepared['state']); self.assertFalse((job / 'release.json').exists())
            action.update(action='release', anchorPin=prepared['anchorPin'])
            self.assertEqual('released', generated(adapter._ACTION, action)['state'])
            action['action'] = 'status'; self.assertEqual('running', generated(adapter._ACTION, action)['state'])
            ready = job / 'stage-ready.json'; swapped = job / 'replacement'; swapped.write_bytes(ready.read_bytes()); swapped.chmod(0o600); swapped.replace(ready)
            with self.assertRaises(SystemExit) as failure: generated(adapter._ACTION, action)
            self.assertEqual(33, failure.exception.code)
            self.assertEqual(1, sum('new-session' in args for args in commands))
            self.assertFalse(any('--remote-run' in args for args in commands))
        finally:
            for sock in sockets: sock.close()

    def test_fixed_programs_actual_transport_newline_guard_and_import_context(self):
        config = adapter.ssh_transport.load_config(self.root)
        for program in (adapter._AVAILABILITY, adapter._STAGE, adapter._ACTION):
            with self.assertRaises(adapter.ssh_transport.SshConfigError):
                adapter.ssh_transport.build_ssh_argv(config, 'archlinux', 10, command=['python3', '-c', program])
            argv = adapter.ssh_transport.build_ssh_argv(config, 'archlinux', 10, command=adapter.command(program))
            self.assertNotIn('\n', argv[-1]); self.assertLess(len(argv[-1]), 30000)
            compile(adapter.command(program)[-1], 'flat-fixed-program', 'exec')
        with self.assertRaises(adapter.AdapterError): adapter.command('import os;os.system("foreign")')
        result = subprocess.run([sys.executable, '-I', '-B', '-c', f'import sys;sys.path.insert(0,{str(ROOT)!r});from agent_tools.ssh_tmux_session_ssh import TOOL_SHA;print(TOOL_SHA)'],
                                cwd='/tmp', capture_output=True, check=False)
        self.assertEqual(0, result.returncode); self.assertEqual(adapter.TOOL_SHA, result.stdout.decode().strip())


if __name__ == '__main__': unittest.main()
