"""Explicit credential-only continuation of an authenticated original login owner.

Builders are pure. A capability describes an observed phase barrier and never
asserts that earlier wake/dismiss effects were unsubmitted.
"""
from __future__ import annotations
import ast
import hashlib
import inspect
import json
from . import readiness_windows_login as login

_EXECUTING_CODE = inspect.currentframe().f_code
_OriginalProtectedOwner = login._ProtectedOwner


class _PhaseObservationDeadline(ValueError):
    pass


def _original_phase(root, operation, identity, original_sha, lock, credential=None):
    """Observe a terminal original and its exact phase chain under its held lock."""
    import os
    original = _OriginalProtectedOwner(root, operation, identity, original_sha, original_sha)
    original.lock = lock
    outcome = original.existing()
    if outcome is None or outcome.get('state') != 'terminal' or outcome['packet'] != {
        'state': 'blocked', 'operationId': operation,
        'reason': 'instance_login_screen_unrecognized', 'replayAllowed': False,
    }:
        raise ValueError('instance_login_continuation_original_unresolved')
    owner = original._read('.owner.json')
    if original._birth(owner['pid']) == owner['birth']:
        raise ValueError('instance_login_continuation_original_running')
    records = {}
    def record(name, expected=None):
        previous = original.prefix
        original.prefix = name
        try:
            value = original._read('')
            pin = original._pin(os.lstat(root / name))
            if expected is not None and not original._same(value, expected):
                raise ValueError('instance_login_continuation_phase_changed')
            records[name] = {'record': value, 'generation': pin}
            return value
        finally:
            original.prefix = previous
    for suffix in ('.intent.json', '.owner.json', '.terminal.json'):
        record(original.prefix + suffix)
    # Newly appended ready observations are valid only after this continuation's
    # exact credential admission and source-owned ready receipt. They never turn
    # the immutable original blocked owner into an unsubmitted attempt.
    credential_name = 'login-credential-' + operation + '.intent.json'
    credential_exists = os.path.lexists(root / credential_name)
    if credential_exists:
        if credential is None:
            raise ValueError('instance_login_continuation_credential_exists')
        record(credential_name, credential)
        records.pop(credential_name)
    terminal_name = 'login-credential-' + operation + '.terminal.json'
    credential_ready = os.path.lexists(root / terminal_name)
    expected = identity['expected']
    ready = {'operationId': operation, 'state': 'ready', 'boot': expected['boot'],
             'account': identity['account'], 'console': expected['console'],
             'logon': expected['logon'], 'settingsChanged': False, 'replayAllowed': False}
    if credential_ready:
        if not credential_exists or credential is None:
            raise ValueError('instance_login_continuation_credential_exists')
        record(terminal_name, ready)
        records.pop(terminal_name)
    for phase in ('wake', 'dismiss'):
        prefix = 'login-preparation-' + operation + '-' + phase
        admitted = root / (prefix + '.intent.json')
        owner_phase = original.prefix + '.phase-' + phase + '.terminal.json'
        if os.path.lexists(admitted):
            expected_phase = {'operationId': operation, 'phase': phase,
                              'expected': identity['expected'], 'replayAllowed': False}
            if phase == 'dismiss':
                expected_phase['profile'] = identity['profile']['lockscreen']
            record(admitted.name, expected_phase)
            record(owner_phase, {'operationId': operation, 'sourceSha256': original_sha,
                                 'phase': phase, 'state': 'submitted', 'replayAllowed': False})
        elif os.path.lexists(root / owner_phase):
            raise ValueError('instance_login_continuation_phase_changed')
        terminal = prefix + '.terminal.json'
        if os.path.lexists(root / terminal):
            if not credential_ready or not os.path.lexists(admitted):
                raise ValueError('instance_login_continuation_phase_changed')
            record(terminal, {**ready, 'phase': phase, 'state': 'ready-observed'})
            records.pop(terminal)
    # This phase belongs to the original owner, never to the continuation.
    if os.path.lexists(root / (original.prefix + '.phase-credential.terminal.json')):
        raise ValueError('instance_login_continuation_credential_exists')
    original.guard(False)
    return {'schemaVersion': 1, 'operationId': operation,
            'originalSourceSha256': original_sha, 'originalIdentity': identity,
            'root': original.intent['root'], 'lock': original.intent['lock'],
            'records': records, 'wholeAttemptUnsubmitted': False,
            'credentialOnly': True, 'replayAllowed': False}


class _CredentialContinuationOwner(_OriginalProtectedOwner):
    """A separate once fence for one credential-only phase of the same UUID."""
    def __init__(self, root, operation, identity, source_sha, original_sha, approved=None):
        capsule = CONTINUATION_CAPABILITY
        if capsule['operationId'] != operation or capsule['credentialOnly'] is not True:
            raise ValueError('instance_login_continuation_identity')
        public = dict(identity)
        public['continuationRelation'] = _phase_identity(operation)
        public['continuationOriginalSha256'] = hashlib.sha256(
            json.dumps(capsule, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        super().__init__(root, operation, public, source_sha, original_sha, approved)
        self.prefix = 'login-owner-' + operation + '-credential-continuation'
    def _original(self, allow_credential=False):
        credential = None
        if allow_credential:
            credential = {'operationId': self.operation, 'expected': self.identity['expected'],
                          'profile': self.identity['profile'], 'account': self.identity['account'],
                          'replayAllowed': False}
        capsule = CONTINUATION_CAPABILITY
        actual = _original_phase(self.root, self.operation, capsule['originalIdentity'],
                                 capsule['originalSourceSha256'], self.lock, credential)
        actual['continuationRelation'] = _phase_identity(self.operation)
        actual['continuationProfileSha256'] = hashlib.sha256(json.dumps(self.identity['profile'], sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        if not self._same(actual, capsule):
            raise ValueError('instance_login_continuation_barrier_changed')
    def guard(self, deadline=True):
        import os
        super().guard(deadline)
        if self.intent is None:
            return
        admitted = os.path.lexists(self.root / (self.prefix + '.intent.json'))
        if admitted and not self._same(self._read('.intent.json'), self.intent):
            raise ValueError('instance_login_continuation_identity')
        self._original(admitted)
    def block_prior(self):
        import os
        self._original(False)
        original_prefix = 'login-owner-' + self.operation
        names = list(self.root.iterdir())
        if len(names) > 8192:
            raise ValueError('instance_login_history_bound')
        allowed = {original_prefix + '.intent.json'}
        for path in names:
            if path.name.startswith('login-owner-') and path.name.endswith('.intent.json') and path.name not in allowed:
                raise ValueError('instance_login_continuation_other_owner')
            if path.name.startswith(('login-wake-', 'login-dismiss-')) and path.name.endswith('.intent.json'):
                raise ValueError('instance_login_legacy_original_unresolved')
            if path.name.startswith(('login-credential-', 'login-preparation-')) and path.name.endswith('.intent.json'):
                prefix = 'login-preparation-' + self.operation + '-'
                if path.name not in {prefix + 'wake.intent.json', prefix + 'dismiss.intent.json'}:
                    raise ValueError('instance_login_continuation_other_owner')


def _credential_only_screen(shot, monitor, guard, save, read, exists, operation, profile, expected):
    if type(profile) is not dict or set(profile) != {'password', 'lockscreen'}:
        raise ValueError('instance_login_screen_profile')
    # Pure observation: no pointer event, Return, dismissal or preparation journal.
    wait_known_field(shot, profile['password'], guard)


def _credential_only_flow(root, read, save, monitor, guard, script, fresh, before):
    row = fresh.get('session', {})
    if (fresh.get('ordinary') is not True or fresh.get('expectedSid') != LOGIN_SID or
            fresh.get('tokenSid') != LOGIN_SID or row.get('Flags') != 0 or row.get('State') != 0 or
            fresh.get('boot') != LOGIN_EXPECTED['boot'] or fresh.get('console') != LOGIN_EXPECTED['console'] or
            row.get('Logon') != LOGIN_EXPECTED['logon'] or row.get('User') != LOGIN_EXPECTED['user']):
        raise ValueError('instance_login_continuation_session_changed')
    return _original_login_flow(root, read, save, monitor, guard, script, fresh, before)


def credential_program(original_source, capability, profile, *, status_only=False):
    """Build from a separately authenticated complete original packet.

    This low-level builder performs no authority admission. Public callers must
    authenticate the original complete producer capsule before invoking it.
    """
    if type(original_source) is not bytes or type(status_only) is not bool:
        raise ValueError('windows_login_continuation_source')
    # Stable literal order survives the durable JSON claim round trip.
    capability = json.loads(json.dumps(capability, sort_keys=True, separators=(',', ':')))
    profile = json.loads(json.dumps(profile, sort_keys=True, separators=(',', ':')))
    digest = hashlib.sha256(original_source).hexdigest()
    if capability.get('originalSourceSha256') != digest or capability.get('continuationProfileSha256') != hashlib.sha256(json.dumps(profile, sort_keys=True, separators=(',', ':')).encode()).hexdigest():
        raise ValueError('windows_login_continuation_source')
    tree = ast.parse(original_source)
    assignments = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            try:
                assignments[node.targets[0].id] = ast.literal_eval(node.value)
            except (ValueError, TypeError):
                pass
    identity = capability['originalIdentity']
    if (assignments.get('OPERATION') != capability['operationId'] or assignments.get('LOGIN_MODE') != 'login-submit' or
            assignments.get('MODE') != 'login-submit' or assignments.get('LOGIN_PROFILE') != identity['profile'] or
            assignments.get('LOGIN_EXPECTED') != identity['expected'] or assignments.get('LOGIN_SID') != identity['account']):
        raise ValueError('windows_login_continuation_source')
    source = original_source.decode()
    if not source.endswith('\n_main()\n'):
        raise ValueError('windows_login_continuation_source')
    # The original full body remains present; overrides are finite and explicit.
    source = source[:-len('_main()\n')]
    source += '\nCONTINUATION_CAPABILITY=' + repr(capability) + '\n'
    source += 'LOGIN_PROFILE=' + repr(profile) + '\n'
    source += '_OriginalProtectedOwner=_ProtectedOwner\n_original_login_flow=_login_flow\n'
    for helper in (_phase_identity, _original_phase, _CredentialContinuationOwner, _credential_only_screen, _credential_only_flow):
        source += inspect.getsource(helper) + '\n'
    source += '_ProtectedOwner=_CredentialContinuationOwner\nprepare_screen=_credential_only_screen\n_login_flow=_credential_only_flow\n'
    if status_only:
        source += "MODE='login-status'\nLOGIN_MODE='login-status'\n"
    # Include new finite reasons without allowing arbitrary exception text.
    reasons = sorted({node.value for node in ast.walk(ast.parse(source)) if isinstance(node, ast.Constant)
                      and type(node.value) is str and __import__('re').fullmatch('instance_[a-z_]{1,64}', node.value)})
    source += 'LOGIN_PUBLIC_REASONS=' + repr(reasons) + '\n_main()\n'
    compile(source, 'fixed credential-only original Windows continuation', 'exec')
    return source.encode()


def observation_program(original_source, profile):
    """Observe the credential barrier under an actual exclusive original lock."""
    import textwrap
    if type(original_source) is not bytes:
        raise ValueError('windows_login_continuation_source')
    tree = ast.parse(original_source)
    original_main = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == '_main')
    source = original_source.decode()
    if not source.endswith('\n_main()\n'):
        raise ValueError('windows_login_continuation_source')
    source = source[:-len('_main()\n')]
    source += '\n_OriginalProtectedOwner=_ProtectedOwner\n' + inspect.getsource(_phase_identity) + '\n' + inspect.getsource(_original_phase) + '\n'
    source += 'ORIGINAL_CONTINUATION_SHA=' + repr(hashlib.sha256(original_source).hexdigest()) + '\n'
    source += 'CONTINUATION_NEW_PROFILE=' + repr(profile) + '\n'
    source += "def _observe():\n    import fcntl\n    root=pathlib.Path(SPEC['root']);held=[];parents=[];pins=[]\n"
    names = {'require', 'generation', 'structure', 'chain', 'closing', 'private', 'read',
             'birth', 'process', 'owns', 'instance_intent', 'epoch'}
    for node in original_main.body:
        if isinstance(node, ast.FunctionDef) and node.name in names:
            source += textwrap.indent(textwrap.dedent(ast.get_source_segment(original_source.decode(), node)), '    ') + '\n'
    source += """
    lock=None
    try:
        epoch();chain();q=read('qemu-started.json');t=read('swtpm-started.json')
        require(q==LOGIN_EXPECTED['actor'],'instance_login_continuation_actor_changed');process(q);process(t)
        owns(q['pid'],root/'disk.qcow2');owns(q['pid'],root/'uefi-vars.fd');owns(q['pid'],root/'qmp.sock',True);owns(t['pid'],root/'swtpm.sock',True)
        lock=os.open(root/'intent.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK);limit=time.monotonic()+5
        while True:
            try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);break
            except BlockingIOError:require(time.monotonic()<limit,'instance_operator_busy');time.sleep(.05)
        require(not os.path.lexists(root/('login-owner-'+OPERATION+'-credential-continuation.intent.json')),'instance_login_continuation_already_admitted')
        identity={'expected':LOGIN_EXPECTED,'profile':LOGIN_PROFILE,'account':LOGIN_SID,'machine':SPEC['deploymentId'],'hostBoot':CONTEXT['hostBootId'],'user':SETUP['user']}
        capsule=_original_phase(root,OPERATION,identity,ORIGINAL_CONTINUATION_SHA,lock)
        capsule['continuationRelation']=_phase_identity(OPERATION)
        capsule['continuationProfileSha256']=hashlib.sha256(json.dumps(CONTINUATION_NEW_PROFILE,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        process(q);process(t);epoch();closing()
        return {'state':'credential-continuation-observed','operationId':OPERATION,'capability':capsule,'hostOnly':True,'vmRequests':0,'inputAuthority':False,'wholeAttemptUnsubmittedAuthority':False}
    finally:
        if lock is not None:os.close(lock)
        for fd in reversed(held):os.close(fd)
print(json.dumps(_observe(),sort_keys=True))
"""
    compile(source, 'fixed original credential-phase observation', 'exec')
    return source.encode()


def _exact(left, right):
    if type(left) is not type(right):return False
    if type(left) is dict:return set(left) == set(right) and all(_exact(left[key], right[key]) for key in left)
    if type(left) is list:return len(left) == len(right) and all(_exact(a, b) for a, b in zip(left, right))
    return left == right


def _load(raw):
    def pairs(rows):
        value = {}
        for key, item in rows:
            if key in value:raise ValueError('windows_login_continuation_duplicate_key')
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=pairs)


def _journal(root, operation, held):
    import os
    import stat
    directory = root / '.runtime/readiness-windows-login' / operation
    for path, mode in ((root / '.runtime', None), (directory.parent, 0o700), (directory, 0o700)):
        fd = held.directory(str(path)); info = os.fstat(fd)
        if info.st_uid != os.geteuid() or info.st_mode & 0o022 or (mode is not None and stat.S_IMODE(info.st_mode) != mode):
            raise ValueError('windows_login_continuation_artifact')
    return directory


def _identity_digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def _public_file(path, held, limit=1048576):
    import os
    import stat
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        row = os.fstat(fd)
        if (not stat.S_ISREG(row.st_mode) or row.st_uid != os.geteuid() or
                stat.S_IMODE(row.st_mode) != 0o600 or row.st_nlink != 1 or not 0 < row.st_size <= limit):
            raise ValueError('windows_login_continuation_artifact')
        raw = os.read(fd, limit + 1)
        if len(raw) != row.st_size:
            raise ValueError('windows_login_continuation_artifact')
        pin = (row.st_dev, row.st_ino, row.st_mode, row.st_uid, row.st_gid,
               row.st_nlink, row.st_size, row.st_mtime_ns, row.st_ctime_ns)
        return held.read(str(path), hashlib.sha256(raw).hexdigest(), pin, max_bytes=limit)
    finally:
        os.close(fd)


def retain_producer_capsule(directory, identity, caller, producer):
    """Retain full canonical input before any private input is opened."""
    from pathlib import Path
    if producer != Path(login.__file__).read_bytes() or login._EXECUTING_CODE != compile(
            producer, str(Path(login.__file__)), 'exec', dont_inherit=True):
        raise ValueError('windows_login_continuation_producer_changed')
    canonical = login.program(identity['binding'], 'login-submit', identity['operationId'],
                              expected_sid=identity['expectedSid'], profile=identity['profile'], expected=identity['expected'])
    if not login._terminal_source_matches(caller, canonical):
        raise ValueError('windows_login_continuation_producer_changed')
    capsule = {'schemaVersion': 1, 'identitySha256': _identity_digest(identity),
               'callerSha256': hashlib.sha256(caller).hexdigest(),
               'producerSha256': hashlib.sha256(producer).hexdigest(),
               'sourceAuthority': 'complete-canonical-producer', 'privateInputPresent': False}
    for name, value in (('credential.caller.source', caller), ('credential.producer.source', producer),
                        ('credential.producer-capsule.json', capsule)):
        try:
            login._retain_local(directory, name, value)
        except FileExistsError:
            from .native_review_source_closure import _Held
            held = _Held()
            try:
                raw = _public_file(Path(directory) / name, held)
                expected = value if type(value) is bytes else (json.dumps(value, sort_keys=True) + '\n').encode()
                if raw != expected:
                    raise ValueError('windows_login_continuation_producer_changed')
                held.finish(); held.final_identity_pass()
            finally:
                held.close()


class _AuthenticatedOriginal:
    """Internal source authority; no public caller SHA override exists."""
    def __init__(self, source, identity, guard):
        self.source, self.identity, self.guard = source, identity, guard


def authenticate_original(backend, operation, held):
    """Accept a complete live-canonical producer capsule, never caller JSON alone."""
    from pathlib import Path
    from uuid import UUID
    if type(operation) is not str or str(UUID(operation)) != operation:
        raise ValueError('windows_login_continuation_identity')
    directory = _journal(backend.root, operation, held)
    intent = _load(_public_file(directory / 'credential.intent.json', held, 65536))
    identity = intent.get('identity')
    if (set(intent) != {'identity', 'callerSha256', 'replayAllowed'} or intent['replayAllowed'] is not False or
            type(identity) is not dict or set(identity) != {'operationId', 'binding', 'expectedSid', 'profile', 'expected'} or
            identity['operationId'] != operation or identity['binding'] != backend.binding or identity['expectedSid'] != backend.expected_sid):
        raise ValueError('windows_login_continuation_original_changed')
    capsule = _load(_public_file(directory / 'credential.producer-capsule.json', held, 65536))
    caller = _public_file(directory / 'credential.caller.source', held)
    producer = _public_file(directory / 'credential.producer.source', held)
    expected = {'schemaVersion': 1, 'identitySha256': _identity_digest(identity),
                'callerSha256': hashlib.sha256(caller).hexdigest(),
                'producerSha256': hashlib.sha256(producer).hexdigest(),
                'sourceAuthority': 'complete-canonical-producer', 'privateInputPresent': False}
    if (not _exact(capsule, expected) or intent['callerSha256'] != expected['callerSha256'] or
            producer != Path(login.__file__).read_bytes() or
            login._EXECUTING_CODE != compile(producer, str(Path(login.__file__)), 'exec', dont_inherit=True)):
        raise ValueError('windows_login_continuation_original_source_untrusted')
    canonical = login.program(identity['binding'], 'login-submit', operation, expected_sid=identity['expectedSid'],
                              profile=identity['profile'], expected=identity['expected'])
    if not login._terminal_source_matches(caller, canonical):
        raise ValueError('windows_login_continuation_original_source_untrusted')
    def guard():
        backend._guard(); held.finish(); held.final_identity_pass()
    guard()
    return _AuthenticatedOriginal(caller, identity, guard)


def _phase_identity(operation):
    from uuid import UUID, uuid5
    return {'originalOperationId': operation, 'phaseId': 'credential-only-1',
            'carrierOperationId': str(uuid5(UUID(operation), 'credential-only-1'))}


def _sanitize_phase_reply(value, operation, expected, sid, reasons):
    if type(value) is not dict or value.get('operationId') != operation or value.get('replayAllowed') is not False:
        raise ValueError('windows_login_continuation_reply')
    state = value.get('state')
    if state == 'blocked' and set(value) == {'state', 'operationId', 'reason', 'replayAllowed'} and value['reason'] in reasons:
        return value
    if state in {'owner-running', 'owner-unknown'} and set(value) == {'state', 'operationId', 'replayAllowed'}:
        return value
    if (state == 'owner-terminal' and set(value) == {'state', 'operationId', 'loginState', 'boot', 'account', 'console', 'logon', 'replayAllowed'} and
            value['loginState'] in {'ready', 'credential-submitted', 'credential-submission-unresolved'} and
            value['boot'] == expected['boot'] and value['account'] == sid and
            type(value['console']) is int and type(value['logon']) is int):
        return value
    raise ValueError('windows_login_continuation_reply')


def _reasons(source):
    values = None
    for node in ast.parse(source).body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) and node.targets[0].id == 'LOGIN_PUBLIC_REASONS':
            values = ast.literal_eval(node.value)
    if type(values) is not list:
        raise ValueError('windows_login_continuation_reasons')
    return set(values)


def _observe_authenticated(backend, original, profile, deadline, held):
    """Read-only host barrier; no protected payload or provider request."""
    import base64
    import subprocess
    import time
    from uuid import UUID, uuid5
    from . import readiness, ssh_transport as transport
    operation = original.identity['operationId']
    carrier = str(uuid5(UUID(operation), 'credential-only-observe'))
    original.guard()
    with transport.admitted_transport(backend.root, backend.binding['spec']['host'], carrier, deadline=deadline,
            requirements=readiness.Requirements(frozenset({'transport'}), frozenset({'reconnect'}))):
        original.guard()
        source = observation_program(original.source, profile)
        command = ['python3', '-I', '-B', '-c', 'import base64;exec(base64.b64decode(' + repr(base64.b64encode(source).decode()) + '))']
        argv = transport.build_ssh_argv(transport.load_config(backend.root), backend.binding['spec']['host'], command=command)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ValueError('windows_login_continuation_deadline')
        try:
            result = transport.run_ssh(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       timeout=min(100, remaining), check=False)
        except transport.SubmittedResultReadinessChanged as error:
            result = error.take_submitted_result()
        if result.returncode or result.stderr or len(result.stdout) > 131072:
            raise ValueError('windows_login_continuation_observation_unresolved')
        value = json.loads(result.stdout, object_pairs_hook=transport._reject_duplicate_keys)
        if (type(value) is not dict or set(value) != {'state', 'operationId', 'capability', 'hostOnly', 'vmRequests', 'inputAuthority', 'wholeAttemptUnsubmittedAuthority'} or
                value['state'] != 'credential-continuation-observed' or value['operationId'] != operation or
                value['hostOnly'] is not True or type(value['vmRequests']) is not int or value['vmRequests'] != 0 or
                value['inputAuthority'] is not False or value['wholeAttemptUnsubmittedAuthority'] is not False):
            raise ValueError('windows_login_continuation_reply')
        capability = value['capability']
        original.guard(); held.finish(); held.final_identity_pass()
        # Full remote shape and every original generation are rechecked by the
        # credential owner under its same exclusive lock, before admission.
        return capability


def _execute_authenticated(backend, original, profile, credential_file, deadline, *, status_only=False):
    """Internal reviewed-source route; public entry authenticates its capsule."""
    import base64
    import math
    import os
    import subprocess
    import time
    from contextlib import contextmanager
    from pathlib import Path
    from uuid import uuid4
    from . import readiness, ssh_transport as transport, ssh_dispatch_admission, ssh_dispatch_retry
    from .private_credential_file import SecretFile
    from .native_review_source_closure import _Held
    if type(original) is not _AuthenticatedOriginal or type(status_only) is not bool or not math.isfinite(deadline) or deadline <= time.monotonic():
        raise ValueError('windows_login_continuation_identity')
    requested_status_only = status_only
    operation = original.identity['operationId']; relation = _phase_identity(operation)
    carrier = relation['carrierOperationId']; directory = backend.root / '.runtime/readiness-windows-login' / operation
    held = _Held(); secret = None; private = None
    def guard():
        original.guard(); held.finish(); held.final_identity_pass()
    try:
        source_path = Path(__file__)
        own_source = source_path.read_bytes()
        if _EXECUTING_CODE != compile(own_source, str(source_path), 'exec', dont_inherit=True):
            raise ValueError('windows_login_continuation_producer_changed')
        held.read(str(source_path), hashlib.sha256(own_source).hexdigest(), max_bytes=1048576)
        directory = _journal(backend.root, operation, held)
        phase_intent = directory / 'credential-continuation.intent.json'
        if os.path.lexists(phase_intent):
            claim = _load(_public_file(phase_intent, held, 131072))
            if (set(claim) != {'relation', 'originalSourceSha256', 'capability', 'profile', 'callerSha256', 'replayAllowed'} or
                    claim['relation'] != relation or claim['originalSourceSha256'] != hashlib.sha256(original.source).hexdigest() or
                    claim['replayAllowed'] is not False):
                raise ValueError('windows_login_continuation_original_changed')
            profile = claim['profile']; capability = claim['capability']; submit_sha = claim['callerSha256']; status_only = True
            if hashlib.sha256(credential_program(original.source, capability, profile)).hexdigest() != submit_sha:
                raise ValueError('windows_login_continuation_original_source_untrusted')
            if not requested_status_only and _proved_preparation_unsubmitted(directory, relation, claim, capability, own_source, held):
                # One preparation attempt per call, only after a fresh exclusive
                # remote barrier proves this fixed phase has never been admitted.
                try:fresh_capability = _observe_authenticated(backend, original, profile, deadline, held)
                except BaseException:
                    return {**relation, 'state': 'unknown', 'reason': 'original_phase_barrier_unresolved', 'replayAllowed': False}
                if not _exact(fresh_capability, capability):
                    raise ValueError('windows_login_continuation_barrier_changed')
                status_only = False
        else:
            if status_only:
                return {**relation, 'state': 'unknown', 'reason': 'original_phase_submission_unknown', 'replayAllowed': False}
            capability = _observe_authenticated(backend, original, profile, deadline, held)
            source = credential_program(original.source, capability, profile)
            submit_sha = hashlib.sha256(source).hexdigest()
            claim = {'relation': relation, 'originalSourceSha256': hashlib.sha256(original.source).hexdigest(),
                     'capability': capability, 'profile': profile, 'callerSha256': submit_sha, 'replayAllowed': False}
            try:
                login._retain_local(directory, phase_intent.name, claim)
            except FileExistsError:
                return _execute_authenticated(backend, original, profile, credential_file, deadline, status_only=True)
            _public_file(phase_intent, held, 131072)
        source = credential_program(original.source, capability, profile, status_only=status_only)
        if not status_only and hashlib.sha256(source).hexdigest() != submit_sha:
            raise ValueError('windows_login_continuation_source')
        label = 'credential-continuation-' + ('status-' if status_only else 'submit-') + uuid4().hex
        login._retain_local(directory, label + '.py', source)
        held.read(str(directory / (label + '.py')), hashlib.sha256(source).hexdigest(), max_bytes=1048576)
        if not status_only:
            try:
                secret = SecretFile(credential_file); private = secret.text.encode('ascii'); login.private_keys(private); secret.guard()
            except BaseException:
                guard()
                _persist_carrier_unsubmitted(directory, label, relation, claim, capability, source, own_source, 'credential_unavailable')
                return {**relation, 'state': 'blocked', 'reason': 'credential_unavailable', 'carrierUnsubmitted': True, 'originalWakeDismissUnsubmitted': False, 'replayAllowed': False}
        intent_raw = (json.dumps(claim, sort_keys=True) + '\n').encode(); intent_sha = hashlib.sha256(intent_raw).hexdigest()
        consumed = [False]
        command = ['python3', '-I', '-B', '-c', 'import base64;exec(base64.b64decode(' + repr(base64.b64encode(source).decode()) + '))',
                   hashlib.sha256(source).hexdigest(), submit_sha]
        @contextmanager
        def factory(root, host, owner, *, deadline):
            with transport.admitted_transport(root, host, owner, deadline=deadline,
                    requirements=readiness.Requirements(frozenset({'transport'}), frozenset({'reconnect'}))) as admission:
                guard(); ssh_dispatch_admission.add_dispatch_guard(admission, guard); yield admission
        def build(admission, attempt):
            guard()
            return transport.build_ssh_argv(transport.load_config(backend.root), backend.binding['spec']['host'],
                    command=command + [str(min(180, max(0, deadline-time.monotonic()))), '{}'])
        def submit(argv):
            guard()
            if secret is not None:secret.guard()
            remaining = deadline-time.monotonic()
            if remaining <= 0:
                if not status_only and not consumed[0]:raise login._LoginDeadlineUnsubmitted('windows_login_continuation_deadline')
                raise _PhaseObservationDeadline('windows_login_continuation_observation_deadline')
            try:
                result = transport.run_ssh(argv, input=(len(private).to_bytes(4, 'big') + private) if private is not None else b'',
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=min(100, remaining), check=False)
            except (transport.PrelaunchReadinessRefusal, transport.StagedExecutionUnsubmitted):raise
            except BaseException:consumed[0] = True; raise
            consumed[0] = True; return result
        def prove_carrier_unsubmitted(proof, attempt):
            if status_only or consumed[0]:return None
            guard()
            if _public_file(phase_intent, held, 131072) != intent_raw:return None
            return intent_sha
        try:
            if status_only:
                with factory(backend.root, backend.binding['spec']['host'], carrier, deadline=deadline) as admission:
                    result = submit(build(admission, 1))
            else:
                result = ssh_dispatch_retry.run_original(backend.root, backend.binding['spec']['host'], carrier,
                        build=build, submit=submit, prove_operation_unsubmitted=prove_carrier_unsubmitted,
                        deadline=deadline, admission_factory=factory)
        except _PhaseObservationDeadline:
            return {**relation, 'state': 'blocked', 'reason': 'original_phase_observation_deadline', 'replayAllowed': False}
        except login._LoginDeadlineUnsubmitted:
            guard()
            return _persist_carrier_unsubmitted(directory, label, relation, claim, capability, source, own_source, 'deadline_before_submission')
        except BaseException as error:
            if type(error) is transport.SubmittedResultReadinessChanged:result = error.take_submitted_result()
            else:return {**relation, 'state': 'unknown', 'reason': 'credential_phase_submission_unresolved', 'replayAllowed': False}
        if private and (private in result.stdout or private in result.stderr):
            return {**relation, 'state': 'unknown', 'reason': 'private_reply_rejected', 'replayAllowed': False}
        if result.returncode or result.stderr or len(result.stdout) > 262144:
            return {**relation, 'state': 'unknown', 'reason': 'credential_phase_submission_unresolved', 'replayAllowed': False}
        try:
            value = json.loads(result.stdout, object_pairs_hook=transport._reject_duplicate_keys)
            value = _sanitize_phase_reply(value, operation, original.identity['expected'], original.identity['expectedSid'], _reasons(source))
        except BaseException:
            return {**relation, 'state': 'unknown', 'reason': 'private_reply_rejected', 'replayAllowed': False}
        guard()
        receipt = {**relation, 'state': 'observed', 'historicalPhaseResult': value,
                   'currentDesktopVerified': False, 'replayAllowed': False}
        login._retain_local(directory, label + '.result.json', receipt)
        return receipt
    finally:
        private = None
        if secret is not None:secret.close()
        held.close()


def continue_original(backend, operation, profile, credential_file, deadline, *, status_only=False):
    """Public internal component route: authenticate full original source first."""
    from .native_review_source_closure import _Held
    held = _Held()
    try:
        original = authenticate_original(backend, operation, held)
        return _execute_authenticated(backend, original, profile, credential_file, deadline, status_only=status_only)
    finally:
        held.close()


def _persist_carrier_unsubmitted(directory, label, relation, claim, capability, source, publisher, reason):
    if reason not in {'credential_unavailable', 'deadline_before_submission'}:
        raise ValueError('windows_login_continuation_unsubmitted_reason')
    from .native_review_source_closure import _Held
    held = _Held()
    try:
        try:login._retain_local(directory, 'credential-continuation.publisher.source', publisher)
        except FileExistsError:
            if _public_file(directory / 'credential-continuation.publisher.source', held) != publisher:
                raise ValueError('windows_login_continuation_unsubmitted_source_changed')
        proof = {**relation, 'state': 'carrier-unsubmitted', 'reason': reason,
                 'phaseIntentSha256': hashlib.sha256((json.dumps(claim, sort_keys=True) + '\n').encode()).hexdigest(), 'originalBarrierSha256': _identity_digest(capability),
                 'preparedCallerSha256': hashlib.sha256(source).hexdigest(),
                 'publisherSha256': hashlib.sha256(publisher).hexdigest(),
                 'targetExecutableStarted': False, 'targetChildHandleReturned': False,
                 'privateInputSubmitted': False, 'originalWakeDismissUnsubmitted': False, 'replayAllowed': False}
        login._retain_local(directory, label + '.unsubmitted.json', proof)
        held.finish(); held.final_identity_pass()
        return proof
    finally:held.close()


def _proved_preparation_unsubmitted(directory, relation, claim, capability, publisher, held):
    """Every prior submit packet needs its own positive no-dispatch receipt."""
    packets = sorted(directory.glob('credential-continuation-submit-*.py'))
    if len(packets) > 64:raise ValueError('windows_login_continuation_preparation_history_bound')
    if len(packets) >= 3:return False
    if not packets:return False
    publisher_path = directory / 'credential-continuation.publisher.source'
    import os
    if not os.path.lexists(publisher_path) or _public_file(publisher_path, held) != publisher:
        return False
    expected = {**relation, 'state': 'carrier-unsubmitted', 'reason': None,
                'phaseIntentSha256': hashlib.sha256((json.dumps(claim, sort_keys=True) + '\n').encode()).hexdigest(), 'originalBarrierSha256': _identity_digest(capability),
                'preparedCallerSha256': claim['callerSha256'], 'publisherSha256': hashlib.sha256(publisher).hexdigest(),
                'targetExecutableStarted': False, 'targetChildHandleReturned': False,
                'privateInputSubmitted': False, 'originalWakeDismissUnsubmitted': False, 'replayAllowed': False}
    for packet in packets:
        if hashlib.sha256(_public_file(packet, held)).hexdigest() != claim['callerSha256']:
            return False
        proof_path = packet.with_suffix('.unsubmitted.json')
        if not os.path.lexists(proof_path):
            return False
        proof = _load(_public_file(proof_path, held, 131072))
        if proof.get('reason') not in {'credential_unavailable', 'deadline_before_submission'}:
            return False
        expected['reason'] = proof['reason']
        if not _exact(proof, expected):
            return False
    return True


def _launch_absence_flow(root, read, save, monitor, guard, script, fresh, before):
    """A fresh native account/session barrier, without owner or GUI admission."""
    import os
    def need(ok):
        if not ok:raise ValueError('instance_login_launch_barrier_unresolved')
    owner = _ProtectedOwner(root, OPERATION, {}, ORIGINAL_LAUNCH_SHA, ORIGINAL_LAUNCH_SHA)
    lock = LOGIN_LAUNCH_LOCK
    pinned = owner._pin(os.fstat(lock)); named = owner._pin(os.lstat(root/'intent.json'))
    need(pinned == named and pinned[5] == 1 and not pinned[2] & 0o077)
    names = [p.name for p in root.iterdir()]; need(len(names) <= 8192)
    prefixes = ('login-owner-'+OPERATION, 'login-preparation-'+OPERATION+'-',
                'login-credential-'+OPERATION, 'login-wake-'+OPERATION, 'login-dismiss-'+OPERATION)
    need(not any(name.startswith(prefixes) for name in names))
    need(before['actor'] == LOGIN_EXPECTED['actor'] and before['hostBoot'] == LOGIN_EXPECTED['hostBoot'] and
         before['controlConnection'] == LOGIN_EXPECTED['controlConnection'])
    row = fresh['session']
    need(fresh['machine'].lower() == SPEC['deploymentId'] and fresh['boot'] == LOGIN_EXPECTED['boot'] and
         fresh['expectedSid'] == LOGIN_SID and fresh['ordinary'] is True and
         fresh['console'] == LOGIN_EXPECTED['console'] and row['Logon'] == LOGIN_EXPECTED['logon'] and
         row['User'] == LOGIN_EXPECTED['user'] and (not row['User'] or fresh['tokenSid'] == LOGIN_SID))
    account = script('login-account-'+os.urandom(6).hex(), LOGIN_ACCOUNT_SCRIPT)
    need(account['name'].casefold() == SETUP['user'].casefold() and account['sid'] == LOGIN_SID and
         account['enabled'] is True and account['loginKeyboard'] == '00000409')
    guard()
    need(owner._pin(os.fstat(lock)) == pinned and owner._pin(os.lstat(root/'intent.json')) == pinned)
    need(not any(p.name.startswith(prefixes) for p in root.iterdir()))
    public = {'expected': LOGIN_EXPECTED, 'profile': LOGIN_PROFILE, 'account': LOGIN_SID,
              'machine': SPEC['deploymentId'], 'hostBoot': CONTEXT['hostBootId'], 'user': SETUP['user']}
    capability = {'schemaVersion': 1, 'operationId': OPERATION, 'identity': public,
                  'originalSourceSha256': ORIGINAL_LAUNCH_SHA, 'root': owner._root_pin(), 'lock': pinned,
                  'session': {'boot': fresh['boot'], 'console': fresh['console'], 'tokenSid': fresh['tokenSid'],
                              'user': row['User'], 'logon': row['Logon'], 'flags': row['Flags'], 'state': row['State']},
                  'account': account, 'ownerAndAllInputPhasesAbsent': True, 'inputAuthority': False}
    return {'login': {'state': 'launch-absence-observed', 'capability': capability}, 'sessionFacts': fresh}


def launch_absence_program(original_source):
    """Pure complete-caller derivative; only native read-only WTS/account calls."""
    if type(original_source) is not bytes or not original_source.endswith(b'\n_main()\n'):
        raise ValueError('windows_login_launch_source')
    source = original_source.decode()
    tree = ast.parse(source)
    assignments = {node.targets[0].id: node for node in tree.body if isinstance(node, ast.Assign) and
                   len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)}
    for name in ('LOGIN_MODE', 'MODE'):
        node = assignments[name]
        if ast.literal_eval(node.value) != 'login-submit':raise ValueError('windows_login_launch_source')
        literal = ast.get_source_segment(source, node)
        if source.count(literal) != 1:raise ValueError('windows_login_launch_source')
        source = source.replace(literal, name+"='login-probe'", 1)
    marker = '            result.update(_login_flow(root,read,save,monitor,vm_guard,script,fresh,result))'
    if source.count(marker) != 1:raise ValueError('windows_login_launch_source')
    source = source.replace(marker, "            globals()['LOGIN_LAUNCH_LOCK']=lock\n"+marker, 1)
    source = source[:-len('_main()\n')]
    source += '\nORIGINAL_LAUNCH_SHA='+repr(hashlib.sha256(original_source).hexdigest())+'\n'
    source += inspect.getsource(_launch_absence_flow)+'\n_login_flow=_launch_absence_flow\n_main()\n'
    compile(source, 'fixed original protected-owner launch absence', 'exec')
    return source.encode()


def observe_launch_absence(backend, original, deadline, held):
    """Observe only; never accepts a payload, input profile override or power action."""
    import base64, subprocess, time
    from uuid import UUID, uuid5
    from . import readiness, ssh_transport as transport
    operation = original.identity['operationId']; original.guard()
    carrier = str(uuid5(UUID(operation), 'protected-owner-launch-observe'))
    source = launch_absence_program(original.source)
    directory = _journal(backend.root, operation, held)
    from uuid import uuid4
    path = directory/('login-launch-observe-'+uuid4().hex+'.py')
    login._retain_local(directory, path.name, source); _public_file(path, held)
    with transport.admitted_transport(backend.root, backend.binding['spec']['host'], carrier, deadline=deadline,
            requirements=readiness.Requirements(frozenset({'transport'}), frozenset({'reconnect'}))):
        original.guard()
        command = ['python3','-I','-B','-c','import base64;exec(base64.b64decode('+repr(base64.b64encode(source).decode())+'))']
        argv = transport.build_ssh_argv(transport.load_config(backend.root), backend.binding['spec']['host'], command=command)
        remaining = deadline-time.monotonic()
        if remaining <= 0:raise ValueError('windows_login_launch_deadline')
        try:result = transport.run_ssh(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=min(100,remaining), check=False)
        except transport.SubmittedResultReadinessChanged as error:result = error.take_submitted_result()
        if result.returncode or result.stderr or len(result.stdout)>262144:raise ValueError('windows_login_launch_observation_unresolved')
        value = _load(result.stdout); observed = value.get('login') if type(value) is dict else None
        if (value.get('operationId') != operation or value.get('state') != 'observed' or type(observed) is not dict or
                set(observed) != {'state','capability'} or observed['state'] != 'launch-absence-observed'):
            raise ValueError('windows_login_launch_observation_unresolved')
        capability = observed['capability']
        public = {'expected':original.identity['expected'],'profile':original.identity['profile'],'account':original.identity['expectedSid'],
                  'machine':backend.machine,'hostBoot':backend.binding['context']['hostBootId'],'user':backend.binding['setup']['user']}
        if (type(capability) is not dict or set(capability) != {'schemaVersion','operationId','identity','originalSourceSha256','root','lock','session','account','ownerAndAllInputPhasesAbsent','inputAuthority'} or
                type(capability['schemaVersion']) is not int or capability['schemaVersion'] != 1 or capability['operationId'] != operation or
                not _exact(capability['identity'],public) or capability['originalSourceSha256'] != hashlib.sha256(original.source).hexdigest() or
                capability['ownerAndAllInputPhasesAbsent'] is not True or capability['inputAuthority'] is not False):
            raise ValueError('windows_login_launch_observation_unresolved')
        original.guard(); held.finish(); held.final_identity_pass()
        return capability


def persist_launch_unsubmitted(directory, label, claim, barrier, source, producer, reason):
    """Called only before run_ssh ever receives this protected owner payload."""
    if reason not in {'credential_unavailable','deadline_before_submission'}:raise ValueError('windows_login_launch_unsubmitted_reason')
    from pathlib import Path
    own_path=Path(__file__);observer_producer=own_path.read_bytes()
    if _EXECUTING_CODE!=compile(observer_producer,str(own_path),'exec',dont_inherit=True):raise ValueError('windows_login_launch_producer_changed')
    try:login._retain_local(directory,'credential.launch-producer.source',observer_producer)
    except FileExistsError:
        from .native_review_source_closure import _Held
        held=_Held()
        try:
            if _public_file(directory/'credential.launch-producer.source',held)!=observer_producer:raise ValueError('windows_login_launch_producer_changed')
            held.finish();held.final_identity_pass()
        finally:held.close()
    proof = {'schemaVersion':1,'operationId':claim['identity']['operationId'],'state':'protected-owner-launch-unsubmitted','reason':reason,
             'barrierProducerSha256':hashlib.sha256(observer_producer).hexdigest(),
             'intentSha256':hashlib.sha256((json.dumps(claim,sort_keys=True)+'\n').encode()).hexdigest(),
             'barrierSha256':_identity_digest(barrier),'callerSha256':hashlib.sha256(source).hexdigest(),
             'producerSha256':hashlib.sha256(producer).hexdigest(),'protectedOwnerLaunchStarted':False,
             'privateInputPassedTransport':False,'allGuiPhasesUnsubmitted':True,'replayAllowed':False}
    login._retain_local(directory,label+'.unsubmitted.json',proof)
    return proof


def proved_launch_unsubmitted(directory, claim, producer, held):
    """No legacy absence inference: all retained submit packets need typed receipts."""
    import os
    barrier_path=directory/'credential.launch-barrier.json'
    if not os.path.lexists(barrier_path):return None
    barrier=_load(_public_file(barrier_path,held,131072))
    from pathlib import Path
    observer_path=directory/'credential.launch-producer.source'
    if not os.path.lexists(observer_path):return None
    observer_producer=Path(__file__).read_bytes()
    if _public_file(observer_path,held)!=observer_producer:return None
    packets=sorted(directory.glob('login-submit-*.py'))
    if not 1<=len(packets)<3:return None
    expected={'schemaVersion':1,'operationId':claim['identity']['operationId'],'state':'protected-owner-launch-unsubmitted','reason':None,
              'barrierProducerSha256':hashlib.sha256(observer_producer).hexdigest(),
              'intentSha256':hashlib.sha256((json.dumps(claim,sort_keys=True)+'\n').encode()).hexdigest(),
              'barrierSha256':_identity_digest(barrier),'callerSha256':claim['callerSha256'],
              'producerSha256':hashlib.sha256(producer).hexdigest(),'protectedOwnerLaunchStarted':False,
              'privateInputPassedTransport':False,'allGuiPhasesUnsubmitted':True,'replayAllowed':False}
    for packet in packets:
        if hashlib.sha256(_public_file(packet,held)).hexdigest()!=claim['callerSha256']:return None
        receipt=packet.with_suffix('.unsubmitted.json')
        if not os.path.lexists(receipt):return None
        proof=_load(_public_file(receipt,held,131072))
        if proof.get('reason')not in {'credential_unavailable','deadline_before_submission'}:return None
        expected['reason']=proof['reason']
        if not _exact(proof,expected):return None
    return barrier
