"""Real detached same-original credential-only owners and private Unix sockets."""
import hashlib
import inspect
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import uuid
from agent_tools import readiness_windows_login as login
from agent_tools import readiness_windows_login_continuation as continuation


@unittest.skipUnless(sys.platform.startswith('linux'), 'Linux retained-owner native process protocol')
class CredentialContinuationExecution(unittest.TestCase):
    def setUp(self):
        original_reasons = getattr(login, 'LOGIN_PUBLIC_REASONS', None)
        login.LOGIN_PUBLIC_REASONS = {'instance_login_screen_unrecognized', 'instance_login_entry_unknown'}
        self.addCleanup(lambda: setattr(login, 'LOGIN_PUBLIC_REASONS', original_reasons) if original_reasons is not None else delattr(login, 'LOGIN_PUBLIC_REASONS'))
        self.temporary = tempfile.TemporaryDirectory(dir=Path('/tmp').resolve())
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        (self.root / 'intent.json').write_text('{"owned":"controlled"}\n')
        (self.root / 'intent.json').chmod(0o600)
        self.operation = str(uuid.uuid4())
        self.identity = {'hostBoot': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                         'expected': {'actor': {'pid': 123, 'startTicks': 456}, 'hostBoot': 'controlled', 'controlConnection': 'controlled', 'boot': 'controlled', 'console': 1, 'logon': 123, 'user': 'recovery'},
                         'profile': {'password': {'width': 320, 'height': 200, 'crops': [{'rect': [0, 0, 1, 1], 'sha256': hashlib.sha256(b'AAA').hexdigest()}]}, 'lockscreen': {}}, 'account': 'SID',
                         'user': 'recovery', 'machine': 'controlled'}
        self.received = []
        self.first = threading.Event()
        self.release = threading.Event()
        self.done = threading.Event()
        self.errors = []
        self.listener = socket.socket(socket.AF_UNIX)
        self.channel = self.root / 'monitor.sock'
        self.listener.bind(str(self.channel))
        self.listener.listen(1)
        self.listener.settimeout(5)
        self.addCleanup(self.listener.close)
        def peer():
            try:
                client, _ = self.listener.accept()
                with client:
                    stream = client.makefile('rwb', buffering=0)
                    while True:
                        row = stream.readline()
                        if not row:
                            break
                        value = json.loads(row)
                        if set(value) != {'keys', 'hold-time'}:
                            raise ValueError('finite-private-channel')
                        self.received.append(1)
                        self.first.set()
                        if len(self.received) == 1:
                            self.release.wait(3)
                        stream.write(b'{"return":{}}\n')
            except (OSError, ValueError) as error:
                self.errors.append(type(error).__name__)
            finally:
                self.done.set()
        self.worker = threading.Thread(target=peer, daemon=True)
        self.worker.start()
        self.addCleanup(self.release.set)
        self.make_original()

    def common(self):
        source = 'import os,sys,json,time,fcntl,socket,hashlib,re\nfrom pathlib import Path\n'
        source += login._publication_source() + '\n'
        for helper in (login.PrivateInputUnknown, login.private_keys, login.enter_private, login._ProtectedOwner):
            source += inspect.getsource(helper) + '\n'
        source += "LOGIN_PUBLIC_REASONS={'instance_login_screen_unrecognized','instance_login_entry_unknown'}\n"
        source += 'root=Path(' + repr(str(self.root)) + ');operation=' + repr(self.operation) + '\n'
        source += "lock=os.open(root/'intent.json',os.O_RDONLY|os.O_NOFOLLOW);fcntl.flock(lock,fcntl.LOCK_EX)\n"
        return source

    def spawn(self, source, payload=b''):
        path = self.root / ('caller-' + uuid.uuid4().hex + '.py')
        path.write_text(source)
        path.chmod(0o600)
        digest = hashlib.sha256(source.encode()).hexdigest()
        child = subprocess.Popen([sys.executable, '-I', '-B', str(path), digest], stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        child.stdin.write(payload)
        child.stdin.close()
        child.stdin = None
        self.addCleanup(lambda: child.poll() is None and child.kill())
        return child, digest

    def make_original(self):
        source = self.common() + 'identity=' + repr(self.identity) + '\n'
        source += "owner=_ProtectedOwner(root,operation,identity,sys.argv[1],sys.argv[1]);owner.lock=lock\n"
        source += "value=owner.start(lock,[],sys.stdin.buffer,wait_seconds=2)\nif type(value)is dict:print(json.dumps(value));sys.exit()\n"
        source += "for phase in ('wake','dismiss'):\n value={'operationId':operation,'phase':phase,'expected':identity['expected'],'replayAllowed':False}\n if phase=='dismiss':value['profile']=identity['profile']['lockscreen']\n owner._save('.unused',{}) if False else None\n prefix=owner.prefix;owner.prefix='login-preparation-'+operation+'-'+phase\n owner._save('.intent.json',value);owner.prefix=prefix;owner.phase(phase)\n"
        source += "owner.finish({'state':'blocked','operationId':operation,'reason':'instance_login_screen_unrecognized'});os._exit(0)\n"
        child, self.original_sha = self.spawn(source, b'\x00\x00\x00\x03A!9')
        out, err = child.communicate(timeout=4)
        self.assertEqual(0, child.returncode, err)
        self.assertIn(b'instance_login_screen_unrecognized', out)
        self.original_terminal = (self.root / ('login-owner-' + self.operation + '.terminal.json')).read_bytes()
        lock = os.open(self.root / 'intent.json', os.O_RDONLY)
        try:
            import fcntl
            fcntl.flock(lock, fcntl.LOCK_EX)
            self.capability = continuation._original_phase(self.root, self.operation, self.identity, self.original_sha, lock)
        finally:
            os.close(lock)
        self.profile = {'password': {'width': 320, 'height': 200, 'crops': [{'rect': [0, 0, 1, 1], 'sha256': hashlib.sha256(b'AAA').hexdigest()}]}, 'lockscreen': {}}
        self.capability['continuationRelation'] = continuation._phase_identity(self.operation)
        self.capability['continuationProfileSha256'] = hashlib.sha256(
            json.dumps(self.profile, sort_keys=True, separators=(',', ':')).encode()).hexdigest()

    def continuation_source(self, extra='', module=continuation):
        source = self.common()
        source += '_OriginalProtectedOwner=_ProtectedOwner\nCONTINUATION_CAPABILITY=' + repr(self.capability) + '\n'
        for helper in (module._phase_identity, module._original_phase, module._CredentialContinuationOwner):
            source += inspect.getsource(helper) + '\n'
        identity = {**self.identity, 'profile': self.profile}
        source += 'identity=' + repr(identity) + '\n'
        source += "owner=_CredentialContinuationOwner(root,operation,identity,sys.argv[1],sys.argv[1]);owner.lock=lock\n"
        source += "existing=owner.existing()\nif existing is not None:print(json.dumps(existing));sys.exit()\n"
        source += "value=owner.start(lock,[],sys.stdin.buffer,wait_seconds=3)\nif type(value)is dict:print(json.dumps(value));sys.exit()\nsecret=value\n"
        source += extra + '\n'
        source += "admission={'operationId':operation,'expected':identity['expected'],'profile':identity['profile'],'account':identity['account'],'replayAllowed':False}\nprefix=owner.prefix;owner.prefix='login-credential-'+operation;owner._save('.intent.json',admission);owner.prefix=prefix\n"
        source += 'client=socket.socket(socket.AF_UNIX);client.connect(' + repr(str(self.channel)) + ')\n'
        source += "def send(value):\n client.sendall(json.dumps(value).encode()+b'\\n');answer=client.recv(4096)\n if answer!=b'{\"return\":{}}\\n':raise ValueError('finite')\n"
        source += "enter_private(secret,send,owner.guard);client.close();owner.phase('credential')\n"
        source += "terminal={'operationId':operation,'state':'ready','boot':'controlled','account':'SID','console':1,'logon':123,'settingsChanged':False,'replayAllowed':False}\nprefix=owner.prefix;owner.prefix='login-credential-'+operation;owner._save('.terminal.json',terminal);owner.prefix=prefix\n"
        source += "owner.finish({'operationId':operation,'login':{'state':'ready'},'sessionFacts':{'boot':'controlled','expectedSid':'SID','ordinary':True,'tokenSid':'SID','console':1,'session':{'User':'recovery','State':0,'Flags':1,'Logon':123},'explorers':[{'SessionId':1}]}});os._exit(0)\n"
        return source

    def test_original_refuses_before_red_then_once_detached_credential_only_green(self):
        observer = login._ProtectedOwner(self.root, self.operation, self.identity, self.original_sha, self.original_sha)
        self.assertEqual('blocked', observer.existing()['packet']['state'])
        with self.assertRaises(AssertionError):
            self.assertEqual(4, len(self.received))
        source = self.continuation_source()
        child, digest = self.spawn(source, b'\x00\x00\x00\x03A!9')
        self.assertTrue(self.first.wait(3))
        child.kill()
        child.communicate(timeout=3)
        self.release.set()
        self.assertTrue(self.done.wait(4))
        terminal = self.root / ('login-owner-' + self.operation + '-credential-continuation.terminal.json')
        limit = time.monotonic() + 3
        while not terminal.exists() and time.monotonic() < limit:
            time.sleep(.02)
        self.assertTrue(terminal.exists())
        self.assertEqual([], self.errors)
        self.assertEqual(4, len(self.received))
        self.assertEqual(self.original_terminal, (self.root / ('login-owner-' + self.operation + '.terminal.json')).read_bytes())
        # Same original/source now observes; it never reads another payload or forks.
        repeated, _ = self.spawn(source)
        out, err = repeated.communicate(timeout=3)
        self.assertEqual(0, repeated.returncode, err)
        self.assertIn(b'owner-terminal', out)
        self.assertEqual(4, len(self.received))
        value = json.loads(terminal.read_bytes())
        self.assertEqual(digest, value['admission']['sourceSha256'])
        for path in self.root.glob('*.json'):
            self.assertNotIn(b'A!9', path.read_bytes())
            self.assertNotIn(b'qcode', path.read_bytes())

    def full_flow_source(self, module=continuation):
        source = self.continuation_source(module=module)
        source = source[:source.index("admission={'operationId'")]
        source += 'client=socket.socket(socket.AF_UNIX);client.connect(' + repr(str(self.channel)) + ')\n'
        for helper in (login.ppm, login.screen_gate, login.wait_known_field, login._login_flow,
                       module._credential_only_screen, module._credential_only_flow):
            source += inspect.getsource(helper) + '\n'
        source += "_original_login_flow=_login_flow\nprepare_screen=_credential_only_screen\n"
        source += "OPERATION=operation;LOGIN_MODE='login-submit';LOGIN_SID='SID';SETUP={'user':'recovery'};SPEC={'deploymentId':'controlled'}\n"
        source += 'LOGIN_PROFILE=' + repr(self.profile) + ';LOGIN_EXPECTED=' + repr(self.identity['expected']) + '\n'
        source += "LOGIN_ACCOUNT_SCRIPT='public-fixed-account';LOGIN_OWNER_SECRET=secret;LOGIN_OWNER_PHASE=owner.phase;SESSION_SCRIPT='public-fixed-session'\n"
        source += "fresh={'machine':'controlled','boot':'controlled','expectedSid':'SID','ordinary':True,'tokenSid':'SID','console':1,'session':{'SessionId':1,'User':'recovery','Flags':0,'State':0,'Logon':123},'explorers':[]}\n"
        source += "def save(name,value):\n prefix=owner.prefix;owner.prefix=name\n try:owner._save('',value)\n finally:owner.prefix=prefix\n"
        source += "def script(label,program):\n if label.startswith('login-account'):return {'name':'recovery','sid':'SID','enabled':True,'loginKeyboard':'00000409'}\n if label.startswith('login-after'):return {**fresh,'session':{**fresh['session'],'Flags':1},'explorers':[{'SessionId':1}]}\n return fresh\n"
        source += "def monitor(command,arguments):\n if command=='screendump':\n  path=Path(arguments['filename']);path.write_bytes(b'P6\\n320 200\\n255\\n'+b'A'*(320*200*3));path.chmod(0o600);return {}\n if command!='send-key':raise ValueError('unexpected-public-input')\n client.sendall(json.dumps(arguments).encode()+b'\\n');answer=client.recv(4096)\n if answer!=b'{\"return\":{}}\\n':raise ValueError('finite')\n"
        source += "before={'actor':LOGIN_EXPECTED['actor'],'hostBoot':LOGIN_EXPECTED['hostBoot'],'controlConnection':LOGIN_EXPECTED['controlConnection'],'operationId':operation}\n"
        source += "try:\n packet={**before,**_credential_only_flow(root,lambda name:json.loads((root/name).read_bytes()),save,monitor,owner.guard,script,fresh,before)}\n client.close();owner.finish(packet)\nexcept BaseException as error:\n import traceback\n diagnostic={'class':type(error).__name__,'frames':[{'function':row.name,'line':row.lineno}for row in traceback.extract_tb(error.__traceback__)]}\n path=root/'causal-harness-diagnostic.json';path.write_text(json.dumps(diagnostic));path.chmod(0o600)\n if type(error)is ValueError and str(error)=='instance_login_continuation_phase_changed':\n  path=root/'causal-phase-failure.json';path.write_text('{\"reason\":\"instance_login_continuation_phase_changed\"}');path.chmod(0o600)\n raise\nos._exit(0)\n"
        return source

    def test_complete_original_login_flow_publishes_linked_ready_after_phase_observations(self):
        import types
        fixture = Path(__file__).parent / 'fixtures/windows_login_continuation_phase_closure'
        raw = (fixture / 'before.source').read_bytes()
        self.assertEqual(json.loads((fixture / 'provenance.json').read_bytes())['sourceSha256'], hashlib.sha256(raw).hexdigest())
        before = types.ModuleType('agent_tools._credential_continuation_phase_before')
        before.__package__ = 'agent_tools'; before.__file__ = str(fixture / 'before.source')
        sys.modules[before.__name__] = before
        self.addCleanup(lambda: sys.modules.pop(before.__name__, None))
        exec(compile(raw, before.__file__, 'exec'), before.__dict__)
        self.release.set()
        child,before_sha=self.spawn(self.full_flow_source(before),b'\x00\x00\x00\x03A!9')
        out,err=child.communicate(timeout=5)
        # Parent exit races its final guard; durable owner/phase receipts are authority.
        self.assertTrue(self.done.wait(2))
        self.assertEqual(4,len(self.received),(self.root/'causal-harness-diagnostic.json').read_text()if (self.root/'causal-harness-diagnostic.json').exists()else'no finite diagnostic')
        self.assertFalse((self.root/('login-owner-'+self.operation+'-credential-continuation.terminal.json')).exists())
        self.assertEqual({'reason':'instance_login_continuation_phase_changed'},json.loads((self.root/'causal-phase-failure.json').read_bytes()))
        self.assertEqual(self.original_terminal,(self.root/('login-owner-'+self.operation+'.terminal.json')).read_bytes())
        from unittest import mock
        descriptor=os.open(self.root/'intent.json',os.O_RDONLY)
        try:
            import fcntl
            fcntl.flock(descriptor,fcntl.LOCK_EX)
            with mock.patch.object(continuation,'CONTINUATION_CAPABILITY',self.capability,create=True):
                observer=continuation._CredentialContinuationOwner(self.root,self.operation,{**self.identity,'profile':self.profile},before_sha,before_sha)
                observer.lock=descriptor
                self.assertEqual('unknown',observer.existing()['state'])
        finally:os.close(descriptor)
        self.worker.join(); self.listener.close(); self.temporary.cleanup(); self.setUp()
        self.release.set()
        child, continued_sha = self.spawn(self.full_flow_source(), b'\x00\x00\x00\x03A!9')
        out, err = child.communicate(timeout=5)
        self.assertEqual(0, child.returncode, err)
        self.assertIn(b'owner-terminal', out)
        self.assertFalse((self.root/'causal-phase-failure.json').exists())
        self.assertTrue(self.done.wait(2))
        self.assertEqual(4, len(self.received))
        self.assertEqual(self.original_terminal, (self.root / ('login-owner-' + self.operation + '.terminal.json')).read_bytes())
        for phase in ('wake', 'dismiss'):
            value = json.loads((self.root / ('login-preparation-' + self.operation + '-' + phase + '.terminal.json')).read_bytes())
            self.assertEqual('ready-observed', value['state'])
        linked_identity={**self.identity,'profile':self.profile,'continuationRelation':continuation._phase_identity(self.operation),
                         'continuationOriginalSha256':continuation._identity_digest(self.capability)}
        approval={self.operation:{'sourceSha256':self.original_sha,'identitySha256':continuation._identity_digest(self.identity),
                                  'continuation':{'sourceSha256':continued_sha,'identitySha256':continuation._identity_digest(linked_identity)}}}
        lock=os.open(self.root/'intent.json',os.O_RDONLY)
        try:
            import fcntl
            fcntl.flock(lock,fcntl.LOCK_EX)
            next_owner=login._ProtectedOwner(self.root,str(uuid.uuid4()),self.identity,'a'*64,'a'*64,approval)
            next_owner.lock=lock;next_owner.block_prior()
            linked_terminal=self.root/('login-owner-'+self.operation+'-credential-continuation.terminal.json')
            retained=linked_terminal.with_suffix('.retained');linked_terminal.rename(retained)
            with self.assertRaisesRegex(ValueError,'instance_login_prior_owner_unresolved'):next_owner.block_prior()
            retained.rename(linked_terminal)
            approval[self.operation]['continuation']['identitySha256']='0'*64
            with self.assertRaisesRegex(ValueError,'instance_login_prior_source_untrusted'):next_owner.block_prior()
        finally:os.close(lock)
        self.assertEqual(4,len(self.received))

    def test_truncated_payload_never_admits_continuation(self):
        child, _ = self.spawn(self.continuation_source(), b'\x00\x00\x00\x03A')
        child.communicate(timeout=3)
        self.assertNotEqual(0, child.returncode)
        self.assertFalse((self.root / ('login-owner-' + self.operation + '-credential-continuation.intent.json')).exists())
        self.assertEqual([], self.received)

    def test_dead_admitted_continuation_stays_unknown_and_never_reforks(self):
        source = self.continuation_source('os._exit(70)')
        child, _ = self.spawn(source, b'\x00\x00\x00\x03A!9')
        child.communicate(timeout=4)
        repeated, _ = self.spawn(source)
        out, err = repeated.communicate(timeout=3)
        self.assertEqual(0, repeated.returncode, err)
        self.assertIn(b'unknown', out)
        self.assertEqual([], self.received)

    def test_replaced_lock_or_changed_original_barrier_prevents_input(self):
        source = self.continuation_source("replacement=root/'replacement';replacement.write_bytes((root/'intent.json').read_bytes());replacement.chmod(0o600);os.replace(replacement,root/'intent.json')")
        child, _ = self.spawn(source, b'\x00\x00\x00\x03A!9')
        child.communicate(timeout=4)
        time.sleep(.1)
        self.assertEqual([], self.received)


class CredentialContinuationWrapper(unittest.TestCase):
    def setUp(self):
        from agent_tools.tests.test_native_vm_spec import request
        from types import SimpleNamespace
        self.temporary = tempfile.TemporaryDirectory(dir=Path('/tmp').resolve())
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        self.operation = str(uuid.uuid4())
        (self.root / '.runtime').mkdir(mode=0o755)
        self.directory = self.root / '.runtime/readiness-windows-login' / self.operation
        self.directory.parent.mkdir(mode=0o700)
        self.directory.mkdir(mode=0o700)
        binding = {'provider': 'raw-qemu-windows', 'spec': request(),
                   'setup': {'imageName': 'Windows 11 Pro', 'locale': 'en-US', 'user': 'recovery', 'administrator': 'recoveryadmin'},
                   'context': {'hostBootId': str(uuid.uuid4()), 'pending': []},
                   'uri': None, 'domain': None, 'xmlSha256': None}
        self.sid = 'S-1-5-21-1-2-3-1000'
        self.expected = {'actor': {'pid': 123, 'startTicks': 456}, 'hostBoot': binding['context']['hostBootId'],
                         'controlConnection': 'controlled', 'boot': 'controlled', 'console': 1, 'logon': 123, 'user': 'recovery'}
        self.profile = {'password': {'width': 320, 'height': 200, 'crops': [{'rect': [0, 0, 1, 1], 'sha256': 'a' * 64}]},
                        'lockscreen': {'width': 320, 'height': 200, 'crops': [{'rect': [0, 0, 1, 1], 'sha256': 'b' * 64}]}}
        self.identity = {'operationId': self.operation, 'binding': binding, 'expectedSid': self.sid,
                         'profile': self.profile, 'expected': self.expected}
        self.backend = SimpleNamespace(root=self.root, binding=binding, machine=binding['spec']['deploymentId'], expected_sid=self.sid, _guard=lambda: None)
        self.source = login.program(binding, 'login-submit', self.operation, expected_sid=self.sid,
                                    profile=self.profile, expected=self.expected)
        self.original = continuation._AuthenticatedOriginal(self.source, self.identity, lambda: None)
        remote_identity = {'expected': self.expected, 'profile': self.profile, 'account': self.sid,
                           'machine': binding['spec']['deploymentId'], 'hostBoot': binding['context']['hostBootId'], 'user': 'recovery'}
        self.capability = {'schemaVersion': 1, 'operationId': self.operation,
                           'originalSourceSha256': hashlib.sha256(self.source).hexdigest(), 'originalIdentity': remote_identity,
                           'root': [1, 2, 3, 4, 5], 'lock': list(range(9)), 'records': {},
                           'wholeAttemptUnsubmitted': False, 'credentialOnly': True, 'replayAllowed': False,
                           'continuationRelation': continuation._phase_identity(self.operation),
                           'continuationProfileSha256': continuation._identity_digest(self.profile)}
        self.credential = self.root / 'controlled.secret'
        self.marker = b'CONTROLLED_PRIVATE_A!9'
        self.credential.write_bytes(self.marker)
        self.credential.chmod(0o600)
        self.reply = {'state': 'owner-terminal', 'operationId': self.operation, 'loginState': 'ready',
                      'boot': 'controlled', 'account': self.sid, 'console': 1, 'logon': 123, 'replayAllowed': False}

    def execute(self, effect=None, *, module=continuation, budget=30, prepare_delay=0, credential_path=None, **options):
        from contextlib import contextmanager
        from types import SimpleNamespace
        from unittest import mock
        from agent_tools import ssh_transport, ssh_dispatch_retry
        @contextmanager
        def admission(*args, **kwargs):
            yield SimpleNamespace()
        def run(root, host, carrier, **kwargs):
            self.assertEqual(continuation._phase_identity(self.operation)['carrierOperationId'], carrier)
            with kwargs['admission_factory'](root, host, carrier, deadline=kwargs['deadline']) as ctx:
                return kwargs['submit'](kwargs['build'](ctx, 1))
        def transport(*args, **kwargs):
            if callable(effect):return effect(kwargs)
            if isinstance(effect, BaseException):raise effect
            return subprocess.CompletedProcess(args[0], 0, json.dumps(self.reply).encode(), b'')
        def build(*args, **kwargs):
            if prepare_delay:time.sleep(prepare_delay)
            return ['ssh', 'controlled']
        with mock.patch.object(module, '_observe_authenticated', return_value=self.capability), \
                mock.patch.object(ssh_transport, 'admitted_transport', admission), \
                mock.patch.object(ssh_transport, 'load_config', return_value={}), \
                mock.patch.object(ssh_transport, 'build_ssh_argv', side_effect=build), \
                mock.patch('agent_tools.ssh_dispatch_admission.add_dispatch_guard'), \
                mock.patch.object(ssh_dispatch_retry, 'run_original', side_effect=run), \
                mock.patch.object(ssh_transport, 'run_ssh', side_effect=transport):
            authenticated = module._AuthenticatedOriginal(self.source, self.identity, lambda: None)
            return module._execute_authenticated(self.backend, authenticated, self.profile,
                    str(self.credential if credential_path is None else credential_path), time.monotonic() + budget, **options)

    def assert_private_not_retained(self):
        for path in self.directory.iterdir():
            self.assertNotIn(self.marker, path.read_bytes())
            self.assertNotIn(b'CONTROLLED_PRIVATE', path.read_bytes())

    def test_once_phase_relation_and_repeat_observes_without_reopening_secret(self):
        from unittest import mock
        result = self.execute()
        relation = continuation._phase_identity(self.operation)
        self.assertEqual(relation['carrierOperationId'], result['carrierOperationId'])
        self.assertEqual(self.operation, result['originalOperationId'])
        self.assertEqual('credential-only-1', result['phaseId'])
        self.assertEqual('ready', result['historicalPhaseResult']['loginState'])
        with mock.patch('agent_tools.private_credential_file.SecretFile', side_effect=AssertionError('private reopen')):
            observed = self.execute(status_only=True)
        self.assertEqual('ready', observed['historicalPhaseResult']['loginState'])
        self.assert_private_not_retained()

    def test_lost_ack_echo_overflow_and_private_exception_are_finite(self):
        value = self.execute(TimeoutError(self.marker.decode()))
        self.assertEqual('unknown', value['state'])
        self.assertNotIn(self.marker.decode(), str(value))
        self.assert_private_not_retained()
        # Repeating an accepted/uncertain phase is status-only even without an explicit flag.
        def status(kwargs):
            self.assertEqual(b'', kwargs['input'])
            return subprocess.CompletedProcess([], 0, json.dumps({'state': 'owner-unknown', 'operationId': self.operation, 'replayAllowed': False}).encode(), b'')
        self.assertEqual('owner-unknown', self.execute(status)['historicalPhaseResult']['state'])

    def test_status_deadline_preserves_already_accepted_phase(self):
        import types
        fixture=Path(__file__).parent/'fixtures/windows_login_continuation_status_deadline'
        raw=(fixture/'before.source').read_bytes()
        self.assertEqual(json.loads((fixture/'provenance.json').read_bytes())['sourceSha256'],hashlib.sha256(raw).hexdigest())
        before=types.ModuleType('agent_tools._credential_continuation_deadline_before')
        before.__package__='agent_tools';before.__file__=str(fixture/'before.source');sys.modules[before.__name__]=before
        self.addCleanup(lambda:sys.modules.pop(before.__name__,None))
        exec(compile(raw,before.__file__,'exec'),before.__dict__)
        self.assertEqual('ready',self.execute(module=before)['historicalPhaseResult']['loginState'])
        self.assertEqual('carrier-unsubmitted',self.execute(module=before,budget=.2,prepare_delay=.3,status_only=True)['state'])
        for path in self.directory.iterdir():path.unlink()
        self.assertEqual('ready',self.execute()['historicalPhaseResult']['loginState'])
        value=self.execute(budget=.2,prepare_delay=.3,status_only=True)
        self.assertNotEqual('carrier-unsubmitted',value['state'])
        self.assertEqual('original_phase_observation_deadline',value['reason'])

    def test_expired_prelaunch_proof_is_carrier_only_and_no_target_call(self):
        target_calls=[]
        def target(kwargs):target_calls.append(1);raise AssertionError('must not dispatch')
        value=self.execute(target,budget=.2,prepare_delay=.3)
        self.assertEqual([],target_calls)
        self.assertEqual('carrier-unsubmitted',value['state'])
        self.assertEqual(self.operation,value['originalOperationId'])
        self.assertFalse(value['originalWakeDismissUnsubmitted'])
        self.assertFalse(value['targetExecutableStarted'])
        self.assertFalse(value['targetChildHandleReturned'])
        self.assertFalse(value['privateInputSubmitted'])
        self.assert_private_not_retained()

    def test_overflow_and_malformed_private_replies_are_finite(self):
        result=self.execute(lambda kwargs:subprocess.CompletedProcess([],0,b'x'*262145,b''))
        self.assertEqual('credential_phase_submission_unresolved',result['reason'])
        self.assert_private_not_retained()
        # Existing phase is observation-only; malformed replies grant no new effect.
        result=self.execute(lambda kwargs:subprocess.CompletedProcess([],0,b'{broken',b''))
        self.assertEqual('private_reply_rejected',result['reason'])
        self.assert_private_not_retained()

    def test_unavailable_whole_before_stuck_red_then_same_phase_correct_handle_green(self):
        import types
        from unittest import mock
        fixture=Path(__file__).parent/'fixtures/windows_login_continuation_credential_availability'
        raw=(fixture/'before.source').read_bytes()
        self.assertEqual(json.loads((fixture/'provenance.json').read_bytes())['sourceSha256'],hashlib.sha256(raw).hexdigest())
        before=types.ModuleType('agent_tools._credential_continuation_availability_before')
        before.__package__='agent_tools';before.__file__=str(fixture/'before.source');sys.modules[before.__name__]=before
        self.addCleanup(lambda:sys.modules.pop(before.__name__,None))
        exec(compile(raw,before.__file__,'exec'),before.__dict__)
        private_calls=[]
        def target(kwargs):
            if kwargs['input']:private_calls.append(1);reply=self.reply
            else:reply={'state':'owner-unknown','operationId':self.operation,'replayAllowed':False}
            return subprocess.CompletedProcess([],0,json.dumps(reply).encode(),b'')
        missing=self.root/'unavailable.secret'
        self.assertEqual('credential_unavailable',self.execute(target,module=before,credential_path=missing)['reason'])
        self.assertEqual('owner-unknown',self.execute(target,module=before)['historicalPhaseResult']['state'])
        self.assertEqual([],private_calls)
        for path in self.directory.iterdir():path.unlink()
        unavailable=self.execute(target,credential_path=missing)
        self.assertEqual('credential_unavailable',unavailable['reason']);self.assertTrue(unavailable['carrierUnsubmitted'])
        proof=next(self.directory.glob('credential-continuation-submit-*.unsubmitted.json'))
        data=json.loads(proof.read_bytes());self.assertFalse(data['originalWakeDismissUnsubmitted']);self.assertFalse(data['privateInputSubmitted'])
        # Explicit observation must never open input even while a safe retry exists.
        with mock.patch('agent_tools.private_credential_file.SecretFile',side_effect=AssertionError('status reopened secret')):
            self.assertEqual('owner-unknown',self.execute(target,status_only=True)['historicalPhaseResult']['state'])
        self.assertEqual('ready',self.execute(target)['historicalPhaseResult']['loginState'])
        self.assertEqual([1],private_calls)
        with mock.patch('agent_tools.private_credential_file.SecretFile',side_effect=AssertionError('accepted phase reopened secret')):
            self.assertEqual('owner-unknown',self.execute(target)['historicalPhaseResult']['state'])
        self.assertEqual([1],private_calls)
        self.assert_private_not_retained()

    def test_retry_requires_fresh_remote_phase_absence_before_private_open(self):
        from unittest import mock
        self.assertEqual('credential_unavailable',self.execute(credential_path=self.root/'missing.secret')['reason'])
        with mock.patch('agent_tools.private_credential_file.SecretFile',side_effect=AssertionError('private open before barrier')), \
                mock.patch.object(continuation,'_observe_authenticated',side_effect=ValueError('existing remote owner')):
            # execute() owns its own observation patch, so exercise the real wrapper directly.
            value=continuation._execute_authenticated(self.backend,self.original,self.profile,str(self.credential),time.monotonic()+30)
        self.assertEqual('original_phase_barrier_unresolved',value['reason'])
        self.assertFalse(value['replayAllowed'])

    def test_private_reply_echo_never_written_or_hashed(self):
        result = self.execute(lambda kwargs: subprocess.CompletedProcess([], 0, self.marker, b''))
        self.assertEqual('private_reply_rejected', result['reason'])
        self.assert_private_not_retained()

    def test_whole_before_json_roundtrip_refusal_red_then_current_status_green(self):
        import types
        fixture = Path(__file__).parent / 'fixtures/windows_login_continuation_canonical'
        raw = (fixture / 'before.source').read_bytes()
        self.assertEqual(json.loads((fixture / 'provenance.json').read_bytes())['sourceSha256'], hashlib.sha256(raw).hexdigest())
        before = types.ModuleType('agent_tools._credential_continuation_canonical_before')
        before.__package__ = 'agent_tools'; before.__file__ = str(fixture / 'before.source')
        sys.modules[before.__name__] = before
        self.addCleanup(lambda: sys.modules.pop(before.__name__, None))
        exec(compile(raw, before.__file__, 'exec'), before.__dict__)
        self.assertEqual('ready', self.execute(module=before)['historicalPhaseResult']['loginState'])
        with self.assertRaisesRegex(ValueError, 'original_source_untrusted'):
            self.execute(module=before, status_only=True)
        # Only this test's /tmp journal is reset, never a submitted real owner.
        for path in self.directory.iterdir():path.unlink()
        self.assertEqual('ready', self.execute()['historicalPhaseResult']['loginState'])
        self.assertEqual('ready', self.execute(status_only=True)['historicalPhaseResult']['loginState'])

    def test_private_artifact_inode_swap_before_red_then_full_generation_green(self):
        import types
        from agent_tools.native_review_source_closure import _Held
        fixture=Path(__file__).parent/'fixtures/windows_login_continuation_private_custody'
        raw=(fixture/'before.source').read_bytes()
        self.assertEqual(json.loads((fixture/'provenance.json').read_bytes())['sourceSha256'],hashlib.sha256(raw).hexdigest())
        before=types.ModuleType('agent_tools._credential_continuation_private_custody_before')
        before.__package__='agent_tools';before.__file__=str(fixture/'before.source');sys.modules[before.__name__]=before
        self.addCleanup(lambda:sys.modules.pop(before.__name__,None))
        exec(compile(raw,before.__file__,'exec'),before.__dict__)
        path=self.directory/'public-custody.json';body=b'{"public":"controlled"}'
        path.write_bytes(body);path.chmod(0o600)
        class SwapHeld(_Held):
            def read(self,name,digest,gen=None,**options):
                replacement=Path(name+'.replacement');replacement.write_bytes(Path(name).read_bytes());replacement.chmod(0o600)
                os.replace(replacement,name)
                return super().read(name,digest,gen,**options)
        held=SwapHeld()
        try:self.assertEqual(body,before._public_file(path,held))
        finally:held.close()
        held=SwapHeld()
        try:
            with self.assertRaises(ValueError):continuation._public_file(path,held)
        finally:held.close()

    def test_prior_continuation_approval_requires_both_whole_original_and_linked_callers(self):
        from agent_tools.native_review_source_closure import _Held
        login._retain_local(self.directory,'credential.intent.json',{'identity':self.identity,'callerSha256':hashlib.sha256(self.source).hexdigest(),'replayAllowed':False})
        login._retain_local(self.directory,'login-submit-original.py',self.source)
        self.execute()
        held=_Held()
        try:
            approved=login._approved_predecessors(self.backend,str(uuid.uuid4()),held)
            self.assertIn('continuation',approved[self.operation])
        finally:held.close()
        caller=next(self.directory.glob('credential-continuation-submit-*.py'))
        caller.write_bytes(caller.read_bytes()+b'\n')
        held=_Held()
        try:
            with self.assertRaisesRegex(ValueError,'windows_login_prior_source_untrusted'):
                login._approved_predecessors(self.backend,str(uuid.uuid4()),held)
        finally:held.close()

    def test_source_capsule_requires_whole_canonical_producer_and_rejects_float_schema(self):
        from agent_tools.native_review_source_closure import _Held
        own = Path(login.__file__).read_bytes()
        login._retain_local(self.directory, 'credential.intent.json', {
            'identity': self.identity, 'callerSha256': hashlib.sha256(self.source).hexdigest(), 'replayAllowed': False})
        continuation.retain_producer_capsule(self.directory, self.identity, self.source, own)
        held = _Held()
        try:
            authenticated = continuation.authenticate_original(self.backend, self.operation, held)
            self.assertEqual(self.source, authenticated.source)
        finally:held.close()
        capsule_path = self.directory / 'credential.producer-capsule.json'
        capsule = json.loads(capsule_path.read_bytes());capsule['schemaVersion'] = 1.0
        capsule_path.write_text(json.dumps(capsule));capsule_path.chmod(0o600)
        held = _Held()
        try:
            with self.assertRaisesRegex(ValueError, 'original_source_untrusted'):
                continuation.authenticate_original(self.backend, self.operation, held)
        finally:held.close()


class CredentialOnlyPublicGuards(unittest.TestCase):
    def test_asleep_or_unrecognized_field_never_wakes_or_dismisses(self):
        from unittest import mock
        raw=b'P6\n320 200\n255\n'+b'\0'*(320*200*3)
        profile={'password':{'width':320,'height':200,'crops':[{'rect':[0,0,1,1],'sha256':hashlib.sha256(b'AAA').hexdigest()}]},'lockscreen':{}}
        scope={'wait_known_field':login.wait_known_field}
        exec(inspect.getsource(continuation._credential_only_screen),scope)
        def forbidden(*args):raise AssertionError('public input or journal must not occur')
        with mock.patch('time.monotonic',side_effect=[0,6]),self.assertRaisesRegex(ValueError,'^instance_login_screen_unrecognized$'):
            scope['_credential_only_screen'](lambda:raw,forbidden,lambda:None,forbidden,forbidden,forbidden,'operation',profile,{})

    def test_changed_ordinary_sid_session_or_lock_state_stops_before_original_flow(self):
        expected={'boot':'controlled','console':1,'logon':123,'user':'recovery'}
        fresh={'ordinary':True,'expectedSid':'SID','tokenSid':'SID','boot':'controlled','console':1,
               'session':{'User':'recovery','Flags':0,'State':0,'Logon':123}}
        calls=[];scope={'LOGIN_SID':'SID','LOGIN_EXPECTED':expected,'_original_login_flow':lambda *args:calls.append(1)}
        exec(inspect.getsource(continuation._credential_only_flow),scope)
        import copy
        for key,value in [('ordinary',False),('expectedSid','OTHER'),('tokenSid','OTHER'),('boot','changed'),('console',2)]:
            changed=copy.deepcopy(fresh);changed[key]=value
            with self.subTest(field=key),self.assertRaisesRegex(ValueError,'instance_login_continuation_session_changed'):
                scope['_credential_only_flow'](None,None,None,None,None,None,changed,None)
        for key,value in [('User','administrator'),('Flags',1),('State',1),('Logon',124)]:
            changed=copy.deepcopy(fresh);changed['session'][key]=value
            with self.subTest(field=key),self.assertRaisesRegex(ValueError,'instance_login_continuation_session_changed'):
                scope['_credential_only_flow'](None,None,None,None,None,None,changed,None)
        self.assertEqual([],calls)
        scope['_credential_only_flow'](None,None,None,None,None,None,fresh,None)
        self.assertEqual([1],calls)




class PrimaryLaunchPreparation(unittest.TestCase):
    setUp = CredentialContinuationWrapper.setUp

    def execute(self, *, module=login, missing=False, status_only=False, barrier_error=False):
        from contextlib import contextmanager
        from types import SimpleNamespace
        from unittest import mock
        from agent_tools import ssh_transport, ssh_dispatch_retry
        @contextmanager
        def admission(*args, **kwargs):
            yield SimpleNamespace(revalidate=lambda:None)
        def run(root,host,operation,**kwargs):
            self.assertEqual(self.operation,operation)
            with kwargs['admission_factory'](root,host,operation,deadline=kwargs['deadline'])as ctx:
                return kwargs['submit'](kwargs['build'](ctx,1))
        def target(*args,**kwargs):
            payload=kwargs.get('input'); self.private_calls.append(bool(payload))
            value=self.reply if payload else {'state':'owner-unknown','operationId':self.operation,'replayAllowed':False}
            return subprocess.CompletedProcess([],0,json.dumps(value).encode(),b'')
        patches=[mock.patch.object(ssh_transport,'admitted_transport',admission),
                 mock.patch.object(ssh_transport,'load_config',return_value={}),
                 mock.patch.object(ssh_transport,'build_ssh_argv',return_value=['ssh','controlled']),
                 mock.patch('agent_tools.ssh_dispatch_admission.add_dispatch_guard'),
                 mock.patch.object(ssh_dispatch_retry,'run_original',side_effect=run),
                 mock.patch.object(ssh_transport,'run_ssh',side_effect=target),
                 mock.patch.object(continuation,'observe_launch_absence',side_effect=ValueError('remote original owner exists')if barrier_error else None,return_value={'controlled':'same full lock/account/session'})]
        if module is not login:patches.append(mock.patch.object(continuation,'retain_producer_capsule'))
        from contextlib import ExitStack
        with ExitStack()as stack:
            for patch in patches:stack.enter_context(patch)
            return module.execute(self.backend,self.operation,self.profile,self.expected,
                                  str(self.root/'MISSING'if missing else self.credential),time.monotonic()+30,status_only=status_only)

    def test_complete_before_unavailable_stuck_red_current_same_original_retry_green(self):
        import types
        from unittest import mock
        fixture=Path(__file__).parent/'fixtures/windows_login_launch_credential_availability'
        raw=(fixture/'before.source').read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),json.loads((fixture/'provenance.json').read_bytes())['sourceSha256'])
        before=types.ModuleType('agent_tools._login_launch_unavailable_before');before.__package__='agent_tools';before.__file__=str(fixture/'before.source')
        sys.modules[before.__name__]=before;self.addCleanup(lambda:sys.modules.pop(before.__name__,None));exec(compile(raw,before.__file__,'exec'),before.__dict__)
        self.private_calls=[]
        self.assertEqual('credential_unavailable',self.execute(module=before,missing=True)['reason'])
        self.assertEqual('original_owner_unknown',self.execute(module=before)['reason']);self.assertEqual([False],self.private_calls)
        for path in self.directory.iterdir():path.unlink()
        self.private_calls=[]
        value=self.execute(missing=True);self.assertTrue(value['protectedOwnerLaunchUnsubmitted'])
        self.assertEqual([],self.private_calls)
        proof=json.loads(next(self.directory.glob('login-submit-*.unsubmitted.json')).read_bytes())
        self.assertFalse(proof['privateInputPassedTransport']);self.assertFalse(proof['protectedOwnerLaunchStarted']);self.assertTrue(proof['allGuiPhasesUnsubmitted'])
        with mock.patch('agent_tools.private_credential_file.SecretFile',side_effect=AssertionError('status read secret')):
            self.assertEqual('original_owner_unknown',self.execute(status_only=True)['reason'])
        self.assertEqual('ready',self.execute()['login']['state']);self.assertEqual([False,True],self.private_calls)
        with mock.patch('agent_tools.private_credential_file.SecretFile',side_effect=AssertionError('accepted owner reopened secret')):
            self.assertEqual('original_owner_unknown',self.execute()['reason'])
        self.assertEqual([False,True,False],self.private_calls)
        for path in self.directory.iterdir():
            raw=path.read_bytes();self.assertNotIn(self.marker,raw);self.assertNotIn(hashlib.sha256(self.marker).hexdigest().encode(),raw)

    def test_existing_remote_phase_or_missing_local_proof_never_opens_secret(self):
        from unittest import mock
        self.private_calls=[];self.execute(missing=True)
        with mock.patch('agent_tools.private_credential_file.SecretFile',side_effect=AssertionError('secret before remote absence')):
            self.assertEqual('original_launch_barrier_unresolved',self.execute(barrier_error=True)['reason'])
        self.assertEqual([],self.private_calls)
        next(self.directory.glob('login-submit-*.unsubmitted.json')).unlink()
        with mock.patch('agent_tools.private_credential_file.SecretFile',side_effect=AssertionError('missing proof reopened secret')):
            self.assertEqual('original_owner_unknown',self.execute()['reason'])
        self.assertEqual([False],self.private_calls)

    def test_retry_has_finite_bound_and_original_claim_survives_binding_dictionary_order(self):
        self.private_calls=[]
        for _ in range(3):self.assertEqual('credential_unavailable',self.execute(missing=True)['reason'])
        self.assertEqual('original_owner_unknown',self.execute()['reason']);self.assertEqual([False],self.private_calls)
        for path in self.directory.iterdir():path.unlink()
        self.private_calls=[];self.execute(missing=True)
        self.backend.binding=json.loads(json.dumps(self.backend.binding,sort_keys=True))
        self.assertEqual('ready',self.execute()['login']['state']);self.assertEqual([True],self.private_calls)

    def test_actual_root_flock_and_fresh_native_account_session_barrier_negative_phases(self):
        import fcntl
        from unittest import mock
        root=self.root/'remote-owned';root.mkdir(mode=0o700);(root/'intent.json').write_text('{}');(root/'intent.json').chmod(0o600)
        lock=os.open(root/'intent.json',os.O_RDONLY);self.addCleanup(lambda:os.close(lock));fcntl.flock(lock,fcntl.LOCK_EX)
        fresh={'machine':self.backend.machine,'boot':self.expected['boot'],'expectedSid':self.sid,'ordinary':True,'console':1,'tokenSid':self.sid,
               'session':{'User':'recovery','Logon':123,'Flags':0,'State':0}}
        account={'name':'recovery','sid':self.sid,'enabled':True,'loginKeyboard':'00000409'}
        values={'_ProtectedOwner':login._ProtectedOwner,'LOGIN_LAUNCH_LOCK':lock,'ORIGINAL_LAUNCH_SHA':'a'*64,
                'OPERATION':self.operation,'LOGIN_EXPECTED':self.expected,'LOGIN_PROFILE':self.profile,'LOGIN_SID':self.sid,
                'SPEC':self.backend.binding['spec'],'SETUP':self.backend.binding['setup'],'CONTEXT':self.backend.binding['context'],'LOGIN_ACCOUNT_SCRIPT':'fixedpublicaccount'}
        before={k:self.expected[k]for k in ('actor','hostBoot','controlConnection')}
        def run(current=fresh):
            with mock.patch.dict(continuation.__dict__,values):
                return continuation._launch_absence_flow(root,lambda *_:self.fail('receipt read'),lambda *_:self.fail('save effect'),
                       lambda *_:self.fail('monitor effect'),lambda:None,lambda *_:account,current,before)
        capability=run()['login']['capability'];self.assertTrue(capability['ownerAndAllInputPhasesAbsent']);self.assertEqual(login._ProtectedOwner(root,self.operation,{},'a'*64,'a'*64)._pin(os.fstat(lock)),capability['lock'])
        for name in ('login-owner-'+self.operation+'.intent.json','login-preparation-'+self.operation+'-wake.intent.json',
                     'login-preparation-'+self.operation+'-dismiss.intent.json','login-credential-'+self.operation+'.intent.json',
                     'login-wake-'+self.operation+'.intent.json','login-dismiss-'+self.operation+'.intent.json',
                     'login-owner-'+self.operation+'-credential-continuation.intent.json',
                     'login-owner-'+self.operation+'-credential-continuation.phase-credential.terminal.json',
                     'login-owner-'+self.operation+'.phase-credential.terminal.json',
                     'login-credential-'+self.operation+'.terminal.json'):
            with self.subTest(name=name):
                path=root/name;path.write_text('{}');path.chmod(0o600)
                try:
                    with self.assertRaisesRegex(ValueError,'launch_barrier_unresolved'):run()
                finally:path.unlink()
        for changed in ({**fresh,'ordinary':False},{**fresh,'expectedSid':'S-1-5-21-9-9-9-1000'},
                        {**fresh,'boot':'changed'},{**fresh,'console':2},{**fresh,'tokenSid':'wrong'},
                        {**fresh,'session':{**fresh['session'],'Logon':124}}):
            with self.assertRaisesRegex(ValueError,'launch_barrier_unresolved'):run(changed)
        replacement=root/'replacement';replacement.write_text('{}');replacement.chmod(0o600);os.replace(replacement,root/'intent.json')
        with self.assertRaisesRegex(ValueError,'launch_barrier_unresolved'):run()

    def test_generated_barrier_has_no_owner_launch_route_and_fixed_readonly_flow(self):
        import ast
        source=continuation.launch_absence_program(self.source)
        tree=ast.parse(source);assignments={node.targets[0].id:ast.literal_eval(node.value)for node in tree.body if isinstance(node,ast.Assign)and len(node.targets)==1 and isinstance(node.targets[0],ast.Name)and node.targets[0].id in {'MODE','LOGIN_MODE'}}
        self.assertEqual({'MODE':'login-probe','LOGIN_MODE':'login-probe'},assignments)
        self.assertEqual(0,sum(isinstance(n,ast.Call)and isinstance(n.func,ast.Name)and n.func.id in {'monitor','save','enter_private','private_keys'}for n in ast.walk(ast.parse(inspect.getsource(continuation._launch_absence_flow)))))


if __name__ == '__main__':
    unittest.main()
