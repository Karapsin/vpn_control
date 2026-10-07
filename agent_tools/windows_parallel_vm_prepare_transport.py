"""One fixed durable Windows template-copy submission and original-job status.

The copy core is reused verbatim. There is no guest launch, command/path selector,
retry, adoption or signal operation. A timed-out SSH submission retains its actual
handle; the detached remote supervisor owns and reaps the original gated copy.
"""
from __future__ import annotations

import base64
import hashlib
import inspect
import json
import os
from pathlib import Path
import re
import select
import selectors
import stat
import subprocess
import time
import uuid

from . import windows_parallel_vm_prepare as core
from . import windows_parallel_vm_source_inventory as inventory

JOB_ROOT = Path('/home/kardinal/vpn-control-windows-parallel-vm-copy-20261005')
LIMIT = 65536
HANDLES = {}


def need(value, reason):
    if not value:
        raise ValueError(reason)


def canonical(value):
    need(type(value) is str and str(uuid.UUID(value)) == value, 'correlation')
    return value


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def private_file(root_fd, name, raw):
    need(re.fullmatch(r'[a-z-]+\.(json|py|private)', name), 'job-role')
    fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=root_fd)
    try:
        offset = 0
        while offset < len(raw):
            count = os.write(fd, raw[offset:])
            need(count > 0, 'job-write')
            offset += count
        os.fsync(fd)
        pin = inventory.generation(os.fstat(fd))
    finally:
        os.close(fd)
    os.fsync(root_fd)
    return {'generation': pin, 'sha256': digest(raw)}


def journal(root_fd, name, value):
    return private_file(root_fd, name, (json.dumps(value, sort_keys=True) + '\n').encode())


def read_private(root_fd, name, expected_uid, limit=LIMIT + 1):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=root_fd)
    try:
        before = inventory.generation(os.fstat(fd))
        need(stat.S_ISREG(before[2]) and stat.S_IMODE(before[2]) == 0o600
             and before[3] == expected_uid and before[5] == 1 and before[6] <= limit, 'job-file')
        raw = bytearray()
        while len(raw) <= limit:
            block = os.read(fd, min(4096, limit + 1 - len(raw)))
            if not block:
                break
            raw.extend(block)
        need(len(raw) == before[6] and inventory.generation(os.fstat(fd)) == before
             == inventory.generation(os.stat(name, dir_fd=root_fd, follow_symlinks=False)), 'job-file-generation')
        return bytes(raw), {'generation': before, 'sha256': digest(raw)}
    finally:
        os.close(fd)


def guard_root(root, fd, root_pin, parents):
    need(os.path.realpath(root) == str(root) and inventory.parent_identity(os.fstat(fd)) == root_pin
         == inventory.parent_identity(root.lstat()), 'job-root-generation')
    for path, pin in parents:
        need(inventory.parent_identity(path.lstat()) == pin, 'job-parent-generation')


def birth(proc, pid):
    return inventory.process_birth(proc, pid)


def wait_birth(proc, child):
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        value = birth(proc, child.pid)
        if type(value) is int and value > 0:
            return value
        need(child.poll() is None, 'job-exited-before-birth')
        time.sleep(.01)
    raise ValueError('job-birth-unknown')


def worker_source(program):
    compile(program, 'fixed preparation core', 'exec')
    return "import sys\nif sys.stdin.buffer.read(3)!=b'GO\\n':raise SystemExit(3)\nexec(compile(" + repr(program) + ", 'fixed preparation core', 'exec'))\n"


def collect_copy(child, raw_fd):
    """Keep the same child until real stdout EOF/exit; never kill or restart.

    Stored bytes are bounded. Overflow is still drained without allocation, so
    the original child can terminate and report an honest UNKNOWN receipt.
    """
    selector = selectors.DefaultSelector()
    selector.register(child.stdout, selectors.EVENT_READ)
    total, retained, eof = 0, 0, False
    try:
        while not eof:
            for key, _ in selector.select(.1):
                block = os.read(key.fileobj.fileno(), 4096)
                if not block:
                    eof = True
                    break
                total += len(block)
                prefix = block[:max(0, LIMIT + 1 - retained)]
                if prefix:
                    offset = 0
                    while offset < len(prefix):
                        count = os.write(raw_fd, prefix[offset:])
                        need(count > 0, 'job-raw-write')
                        offset += count
                    retained += len(prefix)
                    os.fsync(raw_fd)
        code = child.wait()
        os.fsync(raw_fd)
        return {'exitCode': code, 'stdoutEof': eof, 'outputBytes': total,
                'retainedBytes': retained, 'overflow': total > LIMIT}
    finally:
        selector.close()


def supervise(root, root_pin, parents, proc, python, correlation, program_sha, supervisor_birth):
    """Detached owner of the original gated copy process and its raw pipe."""
    root, proc = Path(root), Path(proc)
    parents = [(Path(path), pin) for path, pin in parents]
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    child = None
    raw_fd = None
    try:
        guard_root(root, directory, root_pin, parents)
        need(birth(proc, os.getpid()) == supervisor_birth, 'supervisor-birth')
        worker, worker_pin = read_private(directory, 'worker.py', os.geteuid(), 262144)
        intent_raw, _ = read_private(directory, 'intent.json', os.geteuid())
        intent = json.loads(intent_raw)
        need(intent['correlationId'] == correlation and intent['programSha256'] == program_sha
             and worker_pin == intent['workerPin'], 'worker-intent')
        raw_fd = os.open('stdout.private', os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=directory)
        os.fsync(raw_fd)
        os.fsync(directory)
        # Public source travels as an argument; no named staged-file reread
        # between validated bytes and execution, and no credential in argv.
        child = subprocess.Popen([python, '-I', '-u', '-c', worker.decode()], stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                 start_new_session=True, close_fds=True)
        ticks = wait_birth(proc, child)
        identity = {'correlationId': correlation, 'pid': child.pid, 'startTicks': ticks,
                    'programSha256': program_sha, 'workerPin': worker_pin}
        journal(directory, 'child.json', identity)
        guard_root(root, directory, root_pin, parents)
        child.stdin.write(b'GO\n')
        child.stdin.close()
        outcome = collect_copy(child, raw_fd)
        # Original held FD survives namespace replacement; publication cannot
        # grant a prepared result through a different named namespace.
        raw_pin = inventory.generation(os.fstat(raw_fd))
        os.lseek(raw_fd, 0, os.SEEK_SET)
        raw = os.read(raw_fd, LIMIT + 2)
        outcome.update(identity)
        outcome['rawPin'] = {'generation': raw_pin, 'sha256': digest(raw)}
        guard_root(root, directory, root_pin, parents)
        need(raw_pin == inventory.generation(os.stat('stdout.private', dir_fd=directory,
                                                    follow_symlinks=False)), 'job-raw-generation')
        journal(directory, 'terminal.json', outcome)
    except BaseException as error:
        reason = str(error) if isinstance(error, ValueError) and re.fullmatch(r'[a-z-]{1,80}', str(error)) else type(error).__name__
        # No terminal/EOF is fabricated on observation failure. The original
        # child is neither signalled nor replayed. Closing stdin before GO
        # lets the positively owned gate refuse without performing a copy.
        if child is not None and child.stdin is not None and not child.stdin.closed:
            child.stdin.close()
        try:
            if raw_fd is not None:
                os.fsync(raw_fd)
            journal(directory, 'unknown.json', {'state': 'unknown', 'reason': reason,
                'correlationId': correlation, 'pid': child.pid if child else None,
                'startTicks': birth(proc, child.pid) if child else None, 'stdoutEof': False})
        except (OSError, ValueError):
            # Even an unavailable refusal journal is no licence to abandon
            # the original post-submission observer. Status remains unknown.
            pass
        # Stay the original child's observer instead of abandoning a live
        # pipe after a post-submission failure; no second result publication.
        if child is not None and raw_fd is not None:
            try:
                collect_copy(child, raw_fd)
            except BaseException:
                # A second pipe/storage refusal does not authorize dropping
                # the original observer or closing a live child's pipe.
                while child.poll() is None:
                    time.sleep(.2)
    finally:
        if raw_fd is not None:
            os.close(raw_fd)
        os.close(directory)


def remote_definitions():
    header = 'from pathlib import Path\nimport os,stat,subprocess,time,json,hashlib,re,selectors,uuid\nfrom types import SimpleNamespace\n'
    header += 'FIELDS=' + repr(inventory.FIELDS) + '\nLIMIT=' + repr(LIMIT) + '\n'
    for fn in (inventory.generation, inventory.parent_identity, inventory.parent_pins,
               inventory.process_birth, inventory.holder_census):
        header += inspect.getsource(fn) + '\n'
    header += 'inventory=SimpleNamespace(generation=generation,parent_identity=parent_identity,parent_pins=parent_pins,process_birth=process_birth,holder_census=holder_census)\n'
    for fn in (need, canonical, digest, private_file, journal, read_private, guard_root, birth,
               wait_birth, worker_source, collect_copy, supervise):
        header += inspect.getsource(fn) + '\n'
    return header


def submit(root, proc, python, correlation, program, definitions):
    """Internal fixed-scope bootstrap. Existing namespace always refuses replay."""
    canonical(correlation)
    need(not os.path.lexists(root), 'copy-already-submitted')
    parents = inventory.parent_pins(root, root.parent)
    root.mkdir(mode=0o700)
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    child = None
    ticks = None
    try:
        root_pin = inventory.parent_identity(os.fstat(directory))
        guard_root(root, directory, root_pin, parents)
        worker_pin = private_file(directory, 'worker.py', worker_source(program).encode())
        intent = {'schemaVersion': 1, 'correlationId': correlation, 'programSha256': digest(program.encode()),
                  'workerPin': worker_pin, 'rootGeneration': root_pin,
                  'parents': [{'path': str(p), 'generation': pin} for p, pin in parents]}
        journal(directory, 'intent.json', intent)
        # Supervisor waits for its own durable identity before it creates the
        # gated copy child. All source commands are fixed generated definitions.
        supervisor = definitions + "\nimport sys\nif sys.stdin.buffer.readline(64).strip()!=b'GO':raise SystemExit(3)\nsupervise(" + repr(str(root)) + "," + repr(root_pin) + "," + repr([(str(p), pin) for p, pin in parents]) + "," + repr(str(proc)) + "," + repr(python) + "," + repr(correlation) + "," + repr(intent['programSha256']) + ",int(sys.stdin.buffer.readline(64)))\n"
        private_file(directory, 'supervisor.py', supervisor.encode())
        child = subprocess.Popen([python, '-I', '-u', '-c', supervisor], stdin=subprocess.PIPE,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                 start_new_session=True, close_fds=True)
        ticks = wait_birth(proc, child)
        started = {'schemaVersion': 1, 'correlationId': correlation, 'pid': child.pid,
                   'startTicks': ticks, 'programSha256': intent['programSha256'],
                   'supervisorSha256': digest(supervisor.encode())}
        journal(directory, 'supervisor.json', started)
        guard_root(root, directory, root_pin, parents)
        child.stdin.write(b'GO\n' + str(ticks).encode() + b'\n')
        child.stdin.close()
        return {'state': 'submitted', 'identity': started, 'nativeGuestStarted': False,
                'launchAdmitted': False, 'productAcceptance': False}
    except BaseException:
        if child is not None and child.stdin is not None and not child.stdin.closed:
            child.stdin.close()
        journal(directory, 'submission-unknown.json', {'state': 'unknown', 'correlationId': correlation,
            'pid': child.pid if child else None, 'startTicks': ticks, 'replayAllowed': False})
        return {'state': 'unknown', 'reason': 'submission-unknown', 'correlationId': correlation,
                'pid': child.pid if child else None, 'startTicks': ticks, 'nativeGuestStarted': False,
                'launchAdmitted': False, 'productAcceptance': False}
    finally:
        os.close(directory)


def query(root, proc, correlation, program_sha):
    """Read only, same original identity; no named-file job adoption."""
    canonical(correlation)
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        root_pin = inventory.parent_identity(os.fstat(directory))
        need(stat.S_IMODE(root_pin[2]) == 0o700 and root_pin[3] == os.geteuid(), 'job-root')
        intent_raw, intent_pin = read_private(directory, 'intent.json', os.geteuid())
        intent = json.loads(intent_raw)
        need(type(intent.get('schemaVersion')) is int and intent['schemaVersion'] == 1
             and intent['correlationId'] == correlation and intent['programSha256'] == program_sha
             and intent['rootGeneration'] == root_pin, 'job-intent')
        parents = [(Path(row['path']), row['generation']) for row in intent['parents']]
        guard_root(root, directory, root_pin, parents)
        worker, worker_pin = read_private(directory, 'worker.py', os.geteuid(), 262144)
        need(worker_pin == intent['workerPin'], 'job-worker-generation')
        started_raw, started_pin = read_private(directory, 'supervisor.json', os.geteuid())
        started = json.loads(started_raw)
        need(started['correlationId'] == correlation and started['programSha256'] == program_sha
             and type(started['pid']) is int and started['pid'] > 0
             and type(started['startTicks']) is int and started['startTicks'] > 0, 'job-original-identity')
        supervisor, _ = read_private(directory, 'supervisor.py', os.geteuid(), 262144)
        need(digest(supervisor) == started['supervisorSha256'], 'job-supervisor-source')
        observed = birth(proc, started['pid'])
        if observed is not None:
            need(observed == started['startTicks'], 'supervisor-pid-reused')
            for name, pin in (('intent.json', intent_pin), ('supervisor.json', started_pin)):
                need(read_private(directory, name, os.geteuid())[1] == pin, 'job-closing-generation')
            guard_root(root, directory, root_pin, parents)
            if os.path.lexists(root / 'unknown.json'):
                unknown_raw, _ = read_private(directory, 'unknown.json', os.geteuid())
                need(json.loads(unknown_raw).get('correlationId') == correlation, 'job-unknown-correlation')
                return {'state': 'unknown', 'identity': started, 'reason': 'original-observer-unknown',
                        'originalSupervisorAlive': True, 'nativeGuestStarted': False,
                        'launchAdmitted': False, 'productAcceptance': False}
            return {'state': 'running', 'identity': started, 'nativeGuestStarted': False,
                    'launchAdmitted': False, 'productAcceptance': False}
        terminal_raw, terminal_pin = read_private(directory, 'terminal.json', os.geteuid())
        terminal = json.loads(terminal_raw)
        child_raw, child_pin = read_private(directory, 'child.json', os.geteuid())
        child = json.loads(child_raw)
        need(child['correlationId'] == correlation and child['programSha256'] == program_sha
             and child['workerPin'] == worker_pin and type(child['pid']) is int and child['pid'] > 0
             and type(child['startTicks']) is int and child['startTicks'] > 0, 'job-child-identity')
        need(all(terminal.get(k) == child[k] for k in child) and terminal.get('stdoutEof') is True
             and type(terminal.get('exitCode')) is int and type(terminal.get('overflow')) is bool
             and type(terminal.get('outputBytes')) is int and terminal['outputBytes'] >= 0
             and type(terminal.get('retainedBytes')) is int
             and terminal['retainedBytes'] == min(terminal['outputBytes'], LIMIT + 1)
             and terminal['overflow'] == (terminal['outputBytes'] > LIMIT), 'job-terminal')
        need(birth(proc, child['pid']) is None, 'job-child-not-absent')
        raw, raw_pin = read_private(directory, 'stdout.private', os.geteuid())
        need(raw_pin == terminal['rawPin'] and len(raw) == terminal['retainedBytes'], 'job-raw-terminal')
        fd = os.open('stdout.private', os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
        try:
            census = inventory.holder_census(proc, tuple(raw_pin['generation'][:2]), (os.getpid(), str(fd)),
                                             time.monotonic() + 30, str(root / 'stdout.private'))
            need(census['complete'] and not census['holders'] and not census['argvUsers'], 'job-raw-writers')
        finally:
            os.close(fd)
        # Close every producer receipt after census, before classifying bytes.
        for name, pin in (('intent.json', intent_pin), ('supervisor.json', started_pin),
                          ('child.json', child_pin), ('terminal.json', terminal_pin),
                          ('stdout.private', raw_pin)):
            need(read_private(directory, name, os.geteuid())[1] == pin, 'job-closing-generation')
        guard_root(root, directory, root_pin, parents)
        value = json.loads(raw) if terminal['exitCode'] == 0 and not terminal['overflow'] else {}
        need(type(value) is dict and value.get('nativeGuestStarted') is False
             and value.get('launchAdmitted') is False and value.get('productAcceptance') is False, 'job-output')
        return {'state': value.get('state') if value.get('state') in ('prepared', 'unknown') else 'unknown',
                'identity': started, 'copyIdentity': child, 'terminal': terminal, 'result': value,
                'nativeGuestStarted': False, 'launchAdmitted': False, 'productAcceptance': False}
    finally:
        os.close(directory)


def remote_program(plan, correlation, action):
    canonical(correlation)
    need(action in ('start', 'status'), 'action')
    program = core.remote_program(plan, correlation)
    definitions = remote_definitions()
    for fn in (submit, query):
        definitions += inspect.getsource(fn) + '\n'
    call = ('submit(Path(' + repr(str(JOB_ROOT)) + '),Path("/proc"),"/usr/bin/python3",'
            + repr(correlation) + ',' + repr(program) + ',' + repr(remote_definitions()) + ')') if action == 'start' else (
            'query(Path(' + repr(str(JOB_ROOT)) + '),Path("/proc"),' + repr(correlation) + ',' + repr(digest(program.encode())) + ')')
    source = definitions + '\nos.environ["PATH"]="/usr/bin:/bin"\ntry:\n need(os.geteuid()==0,"privilege-required")\n value=' + call + '\nexcept Exception:\n value={"state":"unknown","reason":"copy-bootstrap-or-status","nativeGuestStarted":False,"launchAdmitted":False,"productAcceptance":False}\nprint(json.dumps(value,sort_keys=True))\n'
    compile(source, 'fixed copy bridge', 'exec')
    return source


class ClientUnknown(ValueError):
    def __init__(self, reason, handle):
        super().__init__(reason)
        self.handle = handle


class RetainedClient:
    """A single actual SSH process, original raw FD and observed pipe EOF."""
    def __init__(self, argv, secret, capture):
        self.capture = capture
        self.raw_fd = os.open('transport.stdout.private', os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                              0o600, dir_fd=capture.fd)
        self.raw = bytearray()
        self.eof = False
        self.child = None
        self.selector = None
        self.initialization_unknown = False
        self.fallback_readiness = False
        self.child = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                      stderr=subprocess.DEVNULL)
        try:
            self.selector = selectors.DefaultSelector()
            self.selector.register(self.child.stdout, selectors.EVENT_READ)
            self.child.stdin.write(secret)
            self.child.stdin.close()
        except BaseException as error:
            self.initialization_unknown = True
            self.fallback_readiness = True
            try:
                if self.child.stdin is not None and not self.child.stdin.closed:
                    self.child.stdin.close()
            except BaseException:
                pass
            raise ClientUnknown('client-initialization-unknown', self) from error

    def ready(self, remaining):
        if self.fallback_readiness:
            readable, _, _ = select.select([self.child.stdout], [], [], remaining)
            return readable
        return [key.fileobj for key, _ in self.selector.select(remaining)]

    def observe(self, seconds):
        deadline = time.monotonic() + seconds
        reason = None
        try:
            while not self.eof:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    reason = 'client-deadline'
                    break
                if len(self.raw) > LIMIT:
                    reason = 'client-overflow'
                    break
                for pipe in self.ready(min(.1, remaining)):
                    block = os.read(pipe.fileno(), min(4096, LIMIT + 1 - len(self.raw)))
                    if not block:
                        self.eof = True
                        break
                    self.raw.extend(block)
                    offset = 0
                    while offset < len(block):
                        count = os.write(self.raw_fd, block[offset:])
                        need(count > 0, 'client-raw-write')
                        offset += count
                    os.fsync(self.raw_fd)
            code = self.child.poll()
            if reason is None and code is None:
                try:
                    code = self.child.wait(timeout=max(.001, deadline - time.monotonic()))
                except subprocess.TimeoutExpired:
                    reason = 'client-deadline'
            if reason is None and code != 0:
                reason = 'client-nonzero'
            need(inventory.generation(os.fstat(self.raw_fd)) == inventory.generation(os.stat(
                'transport.stdout.private', dir_fd=self.capture.fd, follow_symlinks=False)), 'client-raw-generation')
        except (OSError, ValueError):
            reason = 'client-observation-unknown'
            code = self.child.poll()
        os.fsync(self.raw_fd)
        try:
            self.capture.create('transport-' + uuid.uuid4().hex + '.json', json.dumps({
                'pid': self.child.pid, 'stdoutEof': self.eof, 'exitCode': code, 'reason': reason,
                'retainedBytes': len(self.raw), 'rawGeneration': inventory.generation(os.fstat(self.raw_fd)),
                'rawSha256': digest(self.raw), 'clientTerminatedForBound': False}, sort_keys=True).encode())
        except (OSError, ValueError) as error:
            raise ClientUnknown('client-journal-unknown', self) from error
        if reason is not None:
            raise ClientUnknown(reason, self)
        return bytes(self.raw)

    def close_terminal(self):
        need(self.eof and self.child.poll() is not None, 'client-not-terminal')
        self.child.stdout.close()
        if self.selector is not None:
            self.selector.close()
        os.close(self.raw_fd)
        self.raw_fd = None
        self.capture.close()


def validate_result(value, plan, correlation, action):
    need(type(value) is dict and value.get('state') in ('submitted', 'running', 'prepared', 'unknown')
         and all(value.get(k) is False for k in ('nativeGuestStarted', 'launchAdmitted', 'productAcceptance')),
         'transport-envelope')
    if value['state'] == 'unknown':
        return value
    need((action == 'start' and value['state'] == 'submitted')
         or (action == 'status' and value['state'] in ('running', 'prepared')), 'action-state')
    expected = digest(core.remote_program(plan, correlation).encode())
    identity = value.get('identity')
    need(type(identity) is dict and type(identity.get('schemaVersion')) is int and identity['schemaVersion'] == 1
         and identity.get('correlationId') == correlation and identity.get('programSha256') == expected
         and type(identity.get('pid')) is int and identity['pid'] > 0
         and type(identity.get('startTicks')) is int and identity['startTicks'] > 0
         and re.fullmatch(r'[0-9a-f]{64}', identity.get('supervisorSha256', '')), 'transport-original-identity')
    need(value['state'] != 'submitted' or action == 'start', 'status-cannot-submit')
    if value['state'] == 'prepared':
        result = value.get('result')
        need(type(result) is dict and result.get('state') == 'prepared'
             and result.get('correlationId') == correlation
             and result.get('template') == str(core.TEMPLATE_ROOT / 'template.qcow2')
             and result.get('templateSha256') == plan['sourcePin']['sha256']
             and all(result.get(k) is False for k in ('nativeGuestStarted', 'launchAdmitted', 'productAcceptance')),
             'prepared-source-binding')
        overlays = result.get('overlays')
        need(type(overlays) is list and len(overlays) == 2
             and all(type(row) is dict for row in overlays)
             and [row.get('path') for row in overlays] == [str(Path(p) / 'disk.qcow2') for p in inventory.DESTINATIONS],
             'prepared-overlay-binding')
        template = result.get('templateGeneration')
        need(type(template) is list and len(template) == 9 and all(type(v) is int and v >= 0 for v in template)
             and stat.S_ISREG(template[2]) and stat.S_IMODE(template[2]) == 0o440 and template[3] == 0
             and template[4] == plan['sourcePin']['generation'][4] and template[5] == 1
             and template[6] == plan['sourcePin']['generation'][6]
             and result.get('ordinaryQemuReadAccessConfigured') is True, 'prepared-template-generation')
        for row in overlays:
            image, guest = row.get('generation'), row.get('guestGeneration')
            need(type(image) is list and len(image) == 9 and all(type(v) is int and v >= 0 for v in image)
                 and stat.S_ISREG(image[2]) and stat.S_IMODE(image[2]) == 0o600
                 and image[3:5] == plan['sourcePin']['generation'][3:5] and image[5] == 1 and image[6] > 0
                 and type(guest) is list and len(guest) == 5 and all(type(v) is int and v >= 0 for v in guest)
                 and stat.S_ISDIR(guest[2]) and stat.S_IMODE(guest[2]) == 0o700
                 and guest[3:5] == image[3:5], 'prepared-overlay-generation')
    return value


def retain_unknown(capture, value):
    """Original directory FD also retains refusal after a named-leaf swap."""
    try:
        capture.create('result.json', json.dumps(value, sort_keys=True).encode())
    except (OSError, ValueError):
        core.record_at(capture.fd, 'unknown.json', value)


def _dispatch(root, host, correlation, source_leaf, action, timeout_seconds):
    from . import ssh_transport, windows_credential_probe_ssh as launcher
    from . import windows_cp117_bound_absence_completion as authority
    from . import windows_vm_virt_firmware_install as credential
    from . import ssh_connection_session as connection
    from . import windows_diagnostic_authority_capture as fd_capture
    need(host == inventory.HOST and type(timeout_seconds) is int and 5 <= timeout_seconds <= 60, 'inputs')
    canonical(correlation)
    root = Path(root).resolve(strict=True)
    plan = core.build_plan(root, source_leaf)
    outer = authority._outer_authority(root)
    config_pin = inventory.config_metadata(root)
    modules = [Path(__file__), Path(core.__file__), Path(core.baseline.__file__), Path(inventory.__file__),
               Path(ssh_transport.__file__), Path(launcher.__file__), Path(authority.__file__), Path(credential.__file__)]
    modules.extend((Path(connection.__file__), Path(fd_capture.__file__)))
    pins = {str(path): authority._read_bound_file(path) for path in modules}
    marker = root / '.runtime' / 'windows-parallel-vm-copy-intent.json'
    intent = {'correlationId': correlation, 'sourceLeaf': source_leaf, 'plan': plan, 'toolSources': pins}
    if action == 'status':
        _, prior = authority._read_bound_file(marker, private=True, retain_bytes=True)
        need(json.loads(prior) == intent, 'original-local-intent')
    else:
        need(not os.path.lexists(marker), 'copy-already-submitted')
    program = remote_program(plan, correlation, action)
    wrapper = "import sys,subprocess,base64\nsecret=sys.stdin.buffer.read(513)\nif not 1<=len(secret)<=512 or b'\\0' in secret:raise SystemExit(2)\nif not secret.endswith(b'\\n'):secret+=b'\\n'\np=subprocess.Popen(['/usr/bin/sudo','-S','-p','','--','/usr/bin/python3','-c',base64.b64decode(" + repr(base64.b64encode(program.encode()).decode()) + ").decode()],stdin=subprocess.PIPE,stdout=sys.stdout.buffer,stderr=subprocess.DEVNULL)\np.stdin.write(secret);p.stdin.close();secret=None\nraise SystemExit(p.wait())\n"
    need(len(wrapper.encode()) < 120000, 'bootstrap-size')
    config = ssh_transport.load_config(root)
    argv = ssh_transport.build_ssh_argv(config, host, timeout_seconds, command=launcher._remote_command(wrapper))
    credential_pin = inventory.credential_metadata(root)
    secret = credential._read_credential(root)
    need(credential_pin == inventory.credential_metadata(root), 'credential-generation')
    authority._verify_outer(root, {'outerAuthority': outer})
    need(pins == {str(path): authority._read_bound_file(path) for path in modules}
         and config_pin == inventory.config_metadata(root)
         and core.build_plan(root, source_leaf) == plan, 'dispatch-generation')
    if action == 'start':
        core.immutable_write(marker, (json.dumps(intent, sort_keys=True) + '\n').encode())
    leaf = 'windows-parallel-vm-copy-' + action + '-' + uuid.uuid4().hex
    evidence = root / '.runtime' / 'parity-evidence' / leaf
    evidence.mkdir(mode=0o700)
    capture = fd_capture.AuthorityCapture(root, leaf)
    capture.create('request.json', json.dumps({**intent, 'action': action, 'configPin': config_pin,
        'outerAuthority': outer, 'remoteProgramSha256': digest(program.encode())}, sort_keys=True).encode())
    capture.create('remote.py', program.encode())
    handle = None
    try:
        handle = RetainedClient(argv, secret, capture)
        HANDLES[leaf] = handle
        secret = None
        try:
            client_identity = connection._pid_generation(handle.child.pid)
        except (OSError, ValueError):
            client_identity = None
        capture.create('client.json', json.dumps({'identity': client_identity}, sort_keys=True).encode())
        raw = handle.observe(timeout_seconds)
        authority._verify_outer(root, {'outerAuthority': outer})
        need(pins == {str(path): authority._read_bound_file(path) for path in modules}
             and config_pin == inventory.config_metadata(root)
             and core.build_plan(root, source_leaf) == plan, 'closing-generation')
        need(client_identity is not None, 'client-birth-unknown')
        if handle.child.poll() is None:
            need(connection._pid_generation(handle.child.pid) == client_identity, 'client-generation')
        value = validate_result(json.loads(raw), plan, correlation, action)
        retain_unknown(capture, value)
        handle.close_terminal()
        HANDLES.pop(leaf)
        return {**value, 'evidenceLeaf': leaf, 'originalTransportPid': handle.child.pid}
    except ClientUnknown as error:
        handle = error.handle
        HANDLES[leaf] = handle
        if handle.initialization_unknown:
            # Capture only the original already-created pipe, bounded; an
            # initialization refusal always remains UNKNOWN even after EOF.
            try:
                capture.create('client.json', json.dumps({'identity': connection._pid_generation(
                    handle.child.pid)}, sort_keys=True).encode())
            except (OSError, ValueError):
                pass
            try:
                handle.observe(min(.2, timeout_seconds))
            except (OSError, ValueError):
                pass
        value = {'state': 'unknown', 'reason': str(error), 'evidenceLeaf': leaf,
                 'originalTransportPid': handle.child.pid, 'replayAllowed': False,
                 'nativeGuestStarted': False, 'launchAdmitted': False, 'productAcceptance': False}
        retain_unknown(capture, value)
        return value
    except BaseException:
        if handle is not None and not handle.eof and not handle.raw:
            # A journal/provenance refusal after submission has the same
            # original bounded raw capture obligation as initialization.
            try:
                handle.observe(min(.2, timeout_seconds))
            except BaseException:
                pass
        value = {'state': 'unknown', 'reason': 'copy-output-or-authority', 'evidenceLeaf': leaf,
                 'originalTransportPid': handle.child.pid if handle else None,
                 'replayAllowed': False, 'nativeGuestStarted': False, 'launchAdmitted': False,
                 'productAcceptance': False}
        retain_unknown(capture, value)
        if handle is not None and handle.eof and handle.child.poll() is not None:
            handle.close_terminal()
            HANDLES.pop(leaf, None)
        return value
    finally:
        secret = None


def start(root, *, host, correlation_id, source_evidence_leaf, timeout_seconds=60):
    return _dispatch(root, host, correlation_id, source_evidence_leaf, 'start', timeout_seconds)


def status(root, *, host, correlation_id, timeout_seconds=60):
    from . import windows_cp117_bound_absence_completion as authority
    root = Path(root).resolve(strict=True)
    _, raw = authority._read_bound_file(root / '.runtime' / 'windows-parallel-vm-copy-intent.json',
                                        private=True, retain_bytes=True)
    intent = json.loads(raw)
    need(intent['correlationId'] == canonical(correlation_id), 'original-local-correlation')
    return _dispatch(root, host, correlation_id, intent['sourceLeaf'], 'status', timeout_seconds)
