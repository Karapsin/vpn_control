"""Owner publication racing status/reconcile observations; owned local files only, no SSH, VM or network."""
import hashlib
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import tempfile
import types
import unittest
import uuid
from unittest import mock

SOURCE_ROOT = Path(__file__).resolve().parents[2]
BEFORE = Path(__file__).parent / 'fixtures/ssh_program_status_terminal_race/ssh_program_execution.py.before.source'
PROVENANCE = Path(__file__).parent / 'fixtures/ssh_program_status_terminal_race/provenance.json'


@unittest.skipUnless(os.name == 'posix', 'owned local original publisher')
class StatusTerminalArrivalTests(unittest.TestCase):
    def setUp(self):
        from agent_tools import ssh_program_execution
        self.current = ssh_program_execution
        temporary = tempfile.TemporaryDirectory(dir=Path('/tmp').resolve())
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve(); self.root.chmod(0o700)

    def before(self):
        raw = BEFORE.read_bytes(); provenance = json.loads(PROVENANCE.read_bytes()); pin = provenance['files'][BEFORE.name]
        self.assertEqual(('agent_tools/ssh_program_execution.py', pin['sha256']), (pin['path'], hashlib.sha256(raw).hexdigest())); self.assertIs(False, provenance['nativeFailureClaimed'])
        name = 'agent_tools._status_terminal_race_before_' + uuid.uuid4().hex
        module = types.ModuleType(name); module.__file__ = str(BEFORE); module.__package__ = 'agent_tools'
        sys.modules[name] = module; self.addCleanup(sys.modules.pop, name, None)
        exec(compile(raw, str(BEFORE), 'exec'), module.__dict__)
        return module

    def request(self, operation):
        return {'operationId':operation,'program':{'language':'python3','source':"print('ARRIVED ONCE')\n",'args':[],'cwd':'/',
                'targetContext':{'kind':'ssh','uid':1000,'principal':'fixture','home':'/inert/fixture','bootId':'00000000-0000-0000-0000-000000000000'}}}

    def layout(self, durable=False, pid=424242):
        # The owner's state just before its publication: no terminal or receipt.
        # The default pid only meets a mocked lookup; a real lookup and os.kill get a reaped() pid.
        owner = self.current; operation = str(uuid.uuid4())
        directory = owner._directory(self.root, operation, create=True); request = {'host':'explicit-peer',**self.request(operation)}
        intent = {'schemaVersion':2,'privateConnectionPins':{},'operationId':operation,'request':request,
                  'requestSha256':hashlib.sha256(owner._json(request)).hexdigest(),'sourcePins':{},'connectionPins':{},
                  'sourceRoot':str(SOURCE_ROOT),'transport':'inline','originalArgvSha256':'a'*64,
                  'originalCommandBounds':{'wholeArgvBytes':40,'maxArgumentBytes':20,'limitBytes':60000},**({'durableProtocol':1} if durable else {})}
        owner._save(directory, 'intent.json', intent); streams = {}
        for name, raw in [('stdout', b'ARRIVED ONCE\n'), ('stderr', b'')]:
            owner._bytes(directory, name + '.private', raw)
            streams[name] = {'bytes':len(raw),'receivedBytes':len(raw),'receivedSha256':hashlib.sha256(raw).hexdigest(),
                             'retainedSha256':hashlib.sha256(raw).hexdigest(),'eof':True}
        capture = {'complete':True,'eof':{'stdout':True,'stderr':True},'returnCode':0,**({'remoteDurable':True} if durable else {})}
        terminal = owner._public(intent, 'terminal', exitCode=0, capture=capture, streams=streams,
                                 **({'durableProtocol':1,'remoteOperationId':operation} if durable else {}))
        actor = {'pid':pid,'uid':os.getuid(),'sessionId':pid,'birthSha256':'b'*64}
        owner._save(directory, 'owner.json', {'operationId':operation,'actor':actor})
        if durable: owner._save(directory, 'remote-admission.json', {'operationId':operation,'inert':True})
        return directory, intent, terminal, actor

    def publish(self, directory, terminal, receipt=True, **changes):
        # The owner's order: terminal.json, then its exact closing receipt.
        self.current._save(directory, 'terminal.json', terminal)
        if receipt:
            self.current._save(directory, 'owner-closed.json', {'operationId':directory.name,'sourceClosing':True,
                'terminalSha256':hashlib.sha256((directory / 'terminal.json').read_bytes()).hexdigest(),**changes})

    def snapshot(self, directory):
        return {path.name:(path.read_bytes(), self.current.closure.generation(path.stat())) for path in directory.iterdir()}

    def replace(self, path):
        fresh = path.with_name('replacement-' + uuid.uuid4().hex); fresh.write_bytes(path.read_bytes()); fresh.chmod(0o600); fresh.replace(path)

    def reaped(self):
        # A genuinely gone pid, never a fixed number: one owned inert child, exited and reaped.
        child = subprocess.Popen([sys.executable, '-I', '-c', ''], stdin=subprocess.DEVNULL); child.wait(timeout=60); return child.pid

    def publisher(self, operation):
        # The unchanged owner: whole worker plus worker-command closing receipt
        # in an owned source session, held before it publishes anything. Only
        # the configured credential/argv boundary is one inert local child.
        owner = self.current; directory = owner._directory(self.root, operation, create=True)
        body = ("from pathlib import Path\nimport sys,hashlib\nfrom unittest import mock\n"
                "source=Path(" + repr(str(SOURCE_ROOT)) + ")\nroot=Path(" + repr(str(self.root)) + ")\n"
                "sys.path.insert(0,str(source))\nfrom agent_tools import source_module_loader as loader\n"
                "with loader.request_scope(source/'agent_tools'):\n"
                " owner=loader.adapter(source/'agent_tools','ssh_program_execution')\n module=owner._module;context=owner._session\n"
                " request={'host':'explicit-peer',**" + repr(self.request(operation)) + "}\n operation=request['operationId']\n"
                " argv=[sys.executable,'-I','-B','-c',request['program']['source']]\n"
                " pins={str(Path(name).relative_to(source)):{'sha256':item[2],'originalGeneration':list(item[1])} for name,item in context.held.files.items()}\n"
                " intent={'schemaVersion':2,'privateConnectionPins':{},'operationId':operation,'request':request,'requestSha256':hashlib.sha256(module._json(request)).hexdigest(),'sourcePins':pins,'connectionPins':{},'sourceRoot':str(source),'transport':'inline','originalArgvSha256':module.transport.argv_sha256(argv),'originalCommandBounds':module._command_bounds(argv)}\n"
                " directory=module._directory(root,operation)\n module._save(directory,'intent.json',intent)\n"
                " sys.stdout.buffer.write(b'I');sys.stdout.buffer.flush()\n assert sys.stdin.buffer.read(1)==b'B'\n"
                " with mock.patch.object(module,'_hold_connection',return_value=(None,{})),mock.patch.object(module.transport,'build_ssh_argv',return_value=argv) as build:\n"
                "  module.worker(root,operation,source_context=context)\n  assert build.call_count==1\n"
                " context.guard()\n")
        owner._bytes(directory, 'worker.py', body.encode())
        child = subprocess.Popen(owner._worker_command(directory / 'worker.py', body.encode(), self.root, operation),
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 env={key:value for key, value in os.environ.items() if not key.startswith('DYLD_')})
        # A failed test closes the held gate unreleased; the owner then exits unpublished.
        self.addCleanup(lambda: child.returncode is None and child.communicate(timeout=120))
        owner._save(directory, 'owner.json', {'operationId':operation,'actor':owner.keeper.actor(child.pid)})
        ready, _, _ = select.select([child.stdout], [], [], 120)
        self.assertEqual(b'I', child.stdout.read(1) if ready else b'', 'original owner did not publish its intent')
        self.assertFalse((directory / 'terminal.json').exists())
        return directory, child

    def test_actual_owner_exit_during_status_owner_observation_before_red_current_green(self):
        for owner, fixed in [(self.before(), False), (self.current, True)]:
            with self.subTest(fixed=fixed):
                operation = str(uuid.uuid4()); directory, child = self.publisher(operation)
                real = owner.keeper.actor; exited = {}
                def observed(pid):
                    # Release the held original owner during this exact liveness
                    # observation, wait for its actual exit, then observe it.
                    exited['output'] = child.communicate(b'B', timeout=120); exited['records'] = self.snapshot(directory)
                    return real(pid)
                with mock.patch.object(owner.keeper, 'actor', side_effect=observed) as lookup:
                    result = owner.status(self.root, 'explicit-peer', {'operationId':operation})
                self.assertEqual(1, lookup.call_count); self.assertEqual(0, child.returncode, exited['output'][1].decode(errors='replace'))
                self.assertEqual(b'', exited['output'][0]); self.assertEqual(exited['records'], self.snapshot(directory))
                raw = (directory / 'terminal.json').read_bytes(); published = json.loads(raw)
                self.assertEqual({'operationId':operation,'terminalSha256':hashlib.sha256(raw).hexdigest(),'sourceClosing':True},
                                 json.loads((directory / 'owner-closed.json').read_bytes()))
                def terminal_oracle(): self.assertEqual(published, result)
                if fixed: terminal_oracle()
                else:
                    with self.assertRaises(AssertionError): terminal_oracle()
                    self.assertEqual(('unknown', 'original_owner_terminal_unproved'), (result['state'], result['reason']))
                # The same records were complete: a later observation reads them.
                self.assertEqual(published, owner.status(self.root, 'explicit-peer', {'operationId':operation}))

    def test_status_reads_terminal_published_while_owner_pid_names_another_process(self):
        # The reused-pid branch: the lookup succeeds, but for another process birth.
        for owner, fixed in [(self.before(), False), (self.current, True)]:
            with self.subTest(fixed=fixed):
                directory, intent, terminal, actor = self.layout(); arrived = {}
                def reused(pid):
                    # The owner published its terminal and exact receipt once and exited; its pid was reused.
                    if not arrived: self.publish(directory, terminal); arrived['records'] = self.snapshot(directory)
                    return {**actor, 'birthSha256':'c'*64}
                with mock.patch.object(owner.keeper, 'actor', side_effect=reused) as lookup:
                    result = owner.status(self.root, 'explicit-peer', {'operationId':intent['operationId']})
                self.assertEqual((1, arrived['records']), (lookup.call_count, self.snapshot(directory)))
                self.assertEqual(terminal if fixed else owner._public(intent, 'unknown', reason='original_owner_terminal_unproved'), result)

    def test_reconcile_hands_terminal_published_during_owner_observation_to_status(self):
        before = self.before()
        for case in ['verified', 'receipt-missing', 'receipt-binding', 'unknown-terminal']:
            for owner, fixed in [(before, False), (self.current, True)]:
                with self.subTest(case=case, fixed=fixed):
                    network = types.SimpleNamespace(guard=mock.Mock(side_effect=AssertionError('network reconciliation started')))
                    directory, intent, terminal, actor = self.layout(durable=True); arrived = {}
                    if case == 'unknown-terminal': terminal = self.current._public(intent, 'unknown', reason='original_remote_execution_unverified', remoteOperationId=intent['operationId'],
                                                                                    durableProtocol=1, streams={}, capture=None, nextAction='reconcile_original')
                    def replaced(pid):
                        # The owner published once and exited; its pid now names another process.
                        if not arrived:
                            self.publish(directory, terminal, receipt=case != 'receipt-missing', **({'terminalSha256':'0'*64} if case == 'receipt-binding' else {}))
                            arrived['records'] = self.snapshot(directory)
                        return {**actor, 'birthSha256':'c'*64}
                    reconciled = lambda: owner.reconcile(self.root, 'explicit-peer', {'operationId':intent['operationId']}, source_context=network)
                    with mock.patch.object(owner.keeper, 'actor', side_effect=replaced) as lookup:
                        # The beforeimage reconciled every arrival over the network; an unknown terminal still is.
                        if not fixed or case == 'unknown-terminal':
                            with self.assertRaisesRegex(AssertionError, 'network reconciliation started'): reconciled()
                        # status() keeps the exact closing receipt binding for an arrived terminal.
                        elif case == 'receipt-binding':
                            with self.assertRaisesRegex(ValueError, 'program_source_closing_binding'): reconciled()
                        else: self.assertEqual(terminal if case == 'verified' else self.current._public(intent, 'unknown', reason='original_source_closing_unproved'), reconciled())
                    self.assertEqual((2 if fixed and case == 'receipt-missing' else 1, 1 if not fixed or case == 'unknown-terminal' else 0), (lookup.call_count, network.guard.call_count))
                    self.assertEqual(([], arrived['records']), (list(directory.glob('reconciliation-*')), self.snapshot(directory)))

    def test_reconcile_hands_terminal_to_status_when_publishing_owner_pid_is_gone(self):
        # The exited-pid branch: the real lookup fails for a reaped owner pid and os.kill reports it gone.
        for owner, fixed in [(self.before(), False), (self.current, True)]:
            with self.subTest(fixed=fixed):
                network = types.SimpleNamespace(guard=mock.Mock(side_effect=AssertionError('network reconciliation started')))
                directory, intent, terminal, actor = self.layout(durable=True, pid=self.reaped()); real = owner.keeper.actor; arrived = {}
                def gone(pid):
                    # The owner published its terminal and exact receipt once, then exited.
                    if not arrived: self.publish(directory, terminal); arrived['records'] = self.snapshot(directory)
                    return real(pid)
                reconciled = lambda: owner.reconcile(self.root, 'explicit-peer', {'operationId':intent['operationId']}, source_context=network)
                with mock.patch.object(owner.keeper, 'actor', side_effect=gone) as lookup, mock.patch.object(os, 'kill', wraps=os.kill) as probe:
                    # The beforeimage reconciled this arrival over the network.
                    if not fixed:
                        with self.assertRaisesRegex(AssertionError, 'network reconciliation started'): reconciled()
                    else: self.assertEqual(terminal, reconciled())
                self.assertEqual((1, 1, 0 if fixed else 1), (lookup.call_count, probe.call_args_list.count(mock.call(actor['pid'], 0)), network.guard.call_count))
                self.assertEqual(([], arrived['records']), (list(directory.glob('reconciliation-*')), self.snapshot(directory)))

    def test_owner_exit_keeps_unproved_absence_and_every_terminal_guard(self):
        # A dead owner that never published stays UNKNOWN in both sources.
        for owner in [self.before(), self.current]:
            directory, intent, terminal, actor = self.layout(); records = self.snapshot(directory)
            with mock.patch.object(owner.keeper, 'actor', side_effect=ValueError('actor')) as lookup:
                result = owner.status(self.root, 'explicit-peer', {'operationId':intent['operationId']})
            self.assertEqual(1, lookup.call_count); self.assertEqual(records, self.snapshot(directory))
            self.assertEqual(owner._public(intent, 'unknown', reason='original_owner_terminal_unproved'), result)
            with mock.patch.object(owner.keeper, 'actor', return_value=actor):
                self.assertEqual(owner._public(intent, 'pending', reason='original_owner_not_yet_observed'),
                                 owner.status(self.root, 'explicit-peer', {'operationId':intent['operationId']}))
        cases = ['verified', 'unknown-terminal', 'receipt-missing', 'receipt-binding', 'public-binding', 'partial-eof', 'stream-sha', 'owner-replaced']
        for case in cases:
            with self.subTest(case=case):
                directory, intent, terminal, actor = self.layout(); arrived = {}
                if case == 'unknown-terminal': terminal = self.current._public(intent, 'unknown', reason='original_execution_unverified', capture=None, streams={})
                if case == 'public-binding': terminal['sourceSha256'] = 'f'*64
                if case == 'partial-eof': terminal['capture']['eof']['stderr'] = False
                if case == 'stream-sha': terminal['streams']['stdout']['retainedSha256'] = '0'*64
                def exited(pid):
                    # One publication; a later lookup observes the same exited owner.
                    if not arrived:
                        self.publish(directory, terminal, receipt=case != 'receipt-missing', **({'terminalSha256':'0'*64} if case == 'receipt-binding' else {}))
                        if case == 'owner-replaced': self.replace(directory / 'owner.json')
                        arrived['records'] = self.snapshot(directory)
                    raise ValueError('actor')
                observe = lambda: self.current.status(self.root, 'explicit-peer', {'operationId':intent['operationId']})
                with mock.patch.object(self.current.keeper, 'actor', side_effect=exited) as lookup:
                    if case in ('verified', 'unknown-terminal'):
                        self.assertEqual(terminal, observe()); self.assertEqual(1, lookup.call_count)
                        self.assertEqual(arrived['records'], self.snapshot(directory))
                    elif case == 'receipt-missing':
                        result = observe(); self.assertEqual(2, lookup.call_count)
                        self.assertEqual(self.current._public(intent, 'unknown', reason='original_source_closing_unproved'), result)
                    else:
                        expected = {'receipt-binding':'program_source_closing_binding','public-binding':'program_terminal_binding','partial-eof':'program_terminal_capture',
                                    'stream-sha':'Artifact bytes/generation drift','owner-replaced':'Final file FD/name generation drift'}[case]
                        with self.assertRaisesRegex(ValueError, expected): observe()


if __name__ == '__main__':
    unittest.main()
