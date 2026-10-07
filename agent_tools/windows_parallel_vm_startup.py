"""Future-only fixed Windows launch startup, using the existing detached job.

No dispatch, credentials, adoption, process signal or current-job modification.
Bootstrap completion is separate from initial access and original worker terminal.
"""
from __future__ import annotations
import hashlib
import inspect
import json
import os
import stat
from pathlib import Path
import re
from . import windows_parallel_vm_launch as launch
from . import windows_parallel_vm_prepare_transport as transport

inventory = transport.inventory
from .windows_parallel_vm_prepare_transport import canonical, need, read_private, guard_root, birth, digest, journal

BASE_ROOT = '/home/kardinal/vpn-control-windows-parallel-startup-'
INITIAL_LIMIT = 65536


def startup_read(root, proc, correlation, program_sha, base_sha, expected_worker_sha, supervisor_definitions, python):
    """Bounded same-original observation; no journal or authority mutation."""
    canonical(correlation)
    need(re.fullmatch('[0-9a-f]{64}', program_sha) and re.fullmatch('[0-9a-f]{64}', base_sha)
         and re.fullmatch('[0-9a-f]{64}', expected_worker_sha)
         and type(supervisor_definitions) is str and len(supervisor_definitions.encode()) <= 262144, 'startup-source')
    root, proc = Path(root), Path(proc)
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        root_pin = inventory.parent_identity(os.fstat(directory))
        need(stat.S_IMODE(root_pin[2]) == 0o700 and root_pin[3] == os.geteuid(), 'startup-root')
        raw, intent_pin = read_private(directory, 'intent.json', os.geteuid())
        intent = json.loads(raw)
        need(intent.get('schemaVersion') == 1 and type(intent['schemaVersion']) is int
             and intent.get('correlationId') == correlation and intent.get('programSha256') == program_sha
             and intent.get('rootGeneration') == root_pin, 'startup-intent')
        parents = [(Path(row['path']), row['generation']) for row in intent['parents']]
        need(parents == inventory.parent_pins(root, root.parent), 'startup-factory-parents')
        guard_root(root, directory, root_pin, parents)
        worker, worker_pin = read_private(directory, 'worker.py', os.geteuid(), 262144)
        need(digest(worker) == expected_worker_sha, 'startup-factory-worker-source')
        need(worker_pin == intent['workerPin'], 'startup-worker-source')
        supervisor_raw, supervisor_pin = read_private(directory, 'supervisor.json', os.geteuid())
        supervisor = json.loads(supervisor_raw)
        need(supervisor.get('correlationId') == correlation and supervisor.get('programSha256') == program_sha
             and type(supervisor.get('pid')) is int and supervisor['pid'] > 0
             and type(supervisor.get('startTicks')) is int and supervisor['startTicks'] > 0, 'startup-supervisor')
        supervisor_source, source_pin = read_private(directory, 'supervisor.py', os.geteuid(), 262144)
        expected_supervisor = startup_supervisor_source(root, root_pin, parents, proc, python,
                                                       correlation, program_sha, supervisor_definitions)
        need(supervisor_source == expected_supervisor.encode(), 'startup-factory-supervisor-source')
        need(digest(supervisor_source) == supervisor.get('supervisorSha256'), 'startup-supervisor-source')
        live = birth(proc, supervisor['pid'])
        need(live is None or live == supervisor['startTicks'], 'startup-supervisor-reused')
        pins = [('intent.json', intent_pin), ('worker.py', worker_pin),
                ('supervisor.json', supervisor_pin), ('supervisor.py', source_pin)]
        result = {'state':'unknown', 'correlationId':correlation, 'reason':'startup-observation-unavailable',
                  'originalSupervisorAlive':live is not None, 'workerTerminal':False,
                  'bootstrapTransportEofObserved':False, 'launchAdmitted':False,
                  'guestAccessAdmitted':False, 'productAcceptance':False, 'replayAllowed':False}
        try:
            initial_raw, initial_pin = read_private(directory, 'initial.json', os.geteuid(), INITIAL_LIMIT)
        except FileNotFoundError:
            initial_raw = None
        if initial_raw is not None:
            initial = json.loads(initial_raw)
            startup_initial_schema(initial, correlation, program_sha, base_sha, worker_pin)
            child_raw, child_pin = read_private(directory, 'child.json', os.geteuid())
            child = json.loads(child_raw)
            need(all(child.get(k) == initial[k] for k in ('correlationId','pid','startTicks','programSha256','workerPin')),
                 'startup-original-child')
            observed = birth(proc, child['pid'])
            need(observed is None or observed == child['startTicks'], 'startup-child-reused')
            pins += [('initial.json', initial_pin), ('child.json', child_pin)]
            result.update(state='initial-observed', initialObservation=initial['observation'],
                          initialPin=initial_pin, originalWorker=child)
        # Terminal is intentionally not inferred from initial payload, PID absence,
        # bootstrap EOF, or a missing file. Existing supervisor owns terminal capture.
        for name, pin in pins:
            need(read_private(directory, name, os.geteuid(), INITIAL_LIMIT if name=='initial.json' else 262144)[1] == pin,
                 'startup-closing-source')
        for name, pin in pins:
            need(inventory.generation(os.stat(name,dir_fd=directory,follow_symlinks=False)) == pin['generation'],
                 'startup-final-generation')
        guard_root(root, directory, root_pin, parents)
        return result
    finally:
        os.close(directory)


def startup_supervisor_source(root, root_pin, parents, proc, python, correlation, program_sha, definitions):
    """Reproduce existing submit's supervisor from independently frozen factory inputs."""
    return definitions + "\nimport sys\nif sys.stdin.buffer.readline(64).strip()!=b'GO':raise SystemExit(3)\nsupervise(" + repr(str(root)) + "," + repr(root_pin) + "," + repr([(str(p), pin) for p, pin in parents]) + "," + repr(str(proc)) + "," + repr(python) + "," + repr(correlation) + "," + repr(program_sha) + ",int(sys.stdin.buffer.readline(64)))\n"


def startup_initial_schema(value, correlation, program_sha, base_sha, worker_pin):
    fields = {'schemaVersion','correlationId','programSha256','baseProgramSha256','workerPin','pid','startTicks','observation'}
    need(type(value) is dict and set(value) == fields and type(value['schemaVersion']) is int
         and value['schemaVersion'] == 1 and value['correlationId'] == correlation
         and value['programSha256'] == program_sha and value['baseProgramSha256'] == base_sha
         and value['workerPin'] == worker_pin and type(value['pid']) is int and value['pid'] > 0
         and type(value['startTicks']) is int and value['startTicks'] > 0, 'startup-initial-binding')
    observed = value['observation']
    if type(observed) is dict and observed.get('state') == 'unknown':
        need(set(observed) <= {'state','reason','nativeGuestStarted','productAcceptance','replayAllowed','originalPids','identities'}
             and observed.get('reason') in ('pair-launch-or-access','secondary-repair-or-access','startup-publication-refused')
             and type(observed.get('originalPids')) is list
             and all(type(pid) is int and pid > 0 for pid in observed['originalPids']), 'startup-unknown-shape')
    elif type(observed) is dict and observed.get('state') == 'access-ready':
        need(set(observed) == {'state','correlationId','guests','journal','nativeGuestStarted','guestAccessVerified','installedProductVerified','productAcceptance','replayAllowed'}
             and observed.get('guestAccessVerified') is True and observed.get('installedProductVerified') is False
             and type(observed.get('guests')) is list and 1 <= len(observed['guests']) <= 2, 'startup-access-shape')
    need(type(observed) is dict and observed.get('state') in ('unknown','access-ready')
         and (observed.get('state') != 'access-ready' or observed.get('correlationId') == correlation)
         and observed.get('productAcceptance') is False and observed.get('replayAllowed') is False
         and type(observed.get('nativeGuestStarted')) is bool, 'startup-initial-observation')
    need(len(json.dumps(value, sort_keys=True).encode()) <= INITIAL_LIMIT, 'startup-initial-bound')


def startup_publish(root, proc, correlation, base_sha, observation):
    """The original gated worker publishes once, before its unchanged wait phase."""
    root, proc = Path(root), Path(proc)
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        raw, intent_pin = read_private(directory, 'intent.json', os.geteuid())
        intent = json.loads(raw)
        root_pin = inventory.parent_identity(os.fstat(directory))
        need(root_pin == intent['rootGeneration'] and intent['correlationId'] == correlation, 'startup-publish-intent')
        parents = [(Path(row['path']), row['generation']) for row in intent['parents']]
        guard_root(root, directory, root_pin, parents)
        worker, worker_pin = read_private(directory, 'worker.py', os.geteuid(), 262144)
        need(worker_pin == intent['workerPin'], 'startup-publish-source')
        child_raw, child_pin = read_private(directory, 'child.json', os.geteuid())
        child = json.loads(child_raw)
        need(child['pid'] == os.getpid() and child['startTicks'] == birth(proc, os.getpid())
             and child['correlationId'] == correlation and child['programSha256'] == intent['programSha256']
             and child['workerPin'] == worker_pin, 'startup-publish-original')
        value = {'schemaVersion':1, 'correlationId':correlation, 'programSha256':intent['programSha256'],
                 'baseProgramSha256':base_sha, 'workerPin':worker_pin, 'pid':child['pid'],
                 'startTicks':child['startTicks'], 'observation':observation}
        startup_initial_schema(value, correlation, intent['programSha256'], base_sha, worker_pin)
        for name, pin in [('intent.json',intent_pin),('worker.py',worker_pin),('child.json',child_pin)]:
            need(read_private(directory,name,os.geteuid(),262144)[1] == pin, 'startup-publish-closing')
        guard_root(root, directory, root_pin, parents)
        initial_pin = journal(directory, 'initial.json', value)
        need(read_private(directory,'initial.json',os.geteuid(),INITIAL_LIMIT)[1] == initial_pin,
             'startup-publish-result')
        for name, pin in [('intent.json',intent_pin),('worker.py',worker_pin),('child.json',child_pin),('initial.json',initial_pin)]:
            need(inventory.generation(os.stat(name,dir_fd=directory,follow_symlinks=False)) == pin['generation'],
                 'startup-publish-final-generation')
        guard_root(root, directory, root_pin, parents)
    finally:
        os.close(directory)


def _definitions():
    return transport.remote_definitions() + '\nINITIAL_LIMIT=' + repr(INITIAL_LIMIT) + '\n' + '\n'.join(
        inspect.getsource(fn) for fn in (startup_supervisor_source, startup_initial_schema, startup_publish, startup_read))


def _worker_program(base_program, correlation, root):
    """Internal decorator; public factories always supply the fixed launch producer."""
    transport.canonical(correlation)
    marker = 'print(json.dumps(value,sort_keys=True),flush=True)'
    if base_program.count(marker) != 1:
        raise ValueError('startup-fixed-publication')
    base_sha = hashlib.sha256(base_program.encode()).hexdigest()
    injected = """try:
 startup_publish(Path(ROOT),Path('/proc'),CORRELATION,BASE_SHA,value)
except BaseException:
 value={'state':'unknown','reason':'startup-publication-refused','nativeGuestStarted':bool(run and run['handles']),'productAcceptance':False,'replayAllowed':False,'originalPids':[child.pid for child in run['handles']] if run else []}
""".replace('ROOT',repr(str(root))).replace('CORRELATION',repr(correlation)).replace('BASE_SHA',repr(base_sha))
    stripped = base_program.replace('from __future__ import annotations\n','',1)
    program = 'from __future__ import annotations\n' + _definitions() + '\n' + stripped.replace(marker,injected+marker)
    compile(program, 'fixed Windows detached startup worker', 'exec')
    return program, base_sha


def launch_start_program(prepared, observed, correlation):
    """Generate only; the native scheduler owns actual one-shot dispatch."""
    transport.canonical(correlation)
    prepared, observed = json.loads(json.dumps([prepared, observed], sort_keys=True, allow_nan=False))
    root = BASE_ROOT + correlation
    worker, _ = _worker_program(launch.launch_program(prepared, observed, correlation), correlation, root)
    definitions = transport.remote_definitions()
    return definitions + inspect.getsource(transport.submit) + '\nprint(json.dumps(submit(Path(' + repr(root) + "),Path('/proc'),'/usr/bin/python3'," + repr(correlation) + ',' + repr(worker) + ',' + repr(definitions) + '),sort_keys=True),flush=True)\n'


def launch_status_program(prepared, observed, correlation):
    transport.canonical(correlation)
    prepared, observed = json.loads(json.dumps([prepared, observed], sort_keys=True, allow_nan=False))
    root = BASE_ROOT + correlation
    worker, base_sha = _worker_program(launch.launch_program(prepared, observed, correlation), correlation, root)
    expected_worker = hashlib.sha256(transport.worker_source(worker).encode()).hexdigest()
    return _definitions() + '\nprint(json.dumps(startup_read(Path(' + repr(root) + "),Path('/proc')," + repr(correlation) + ',' + repr(hashlib.sha256(worker.encode()).hexdigest()) + ',' + repr(base_sha) + ',' + repr(expected_worker) + ',' + repr(transport.remote_definitions()) + ",'/usr/bin/python3'),sort_keys=True),flush=True)\n"
