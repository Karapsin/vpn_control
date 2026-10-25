"""Source-owned Linux process admission; unknown ordinary work prevents power.

Only public static units from the owned pristine image are enrolled. Runtime
checks close their original file generations before reading any changed bytes.
An active service main process grants no exemption to its descendants.
"""
import inspect

UNITS = {
    'systemd-journald.service': ('/usr/lib/systemd/systemd-journald', None),
    'multipathd.service': ('/usr/sbin/multipathd', None),
    'systemd-udevd.service': ('/usr/bin/udevadm', None),
    'systemd-resolved.service': ('/usr/lib/systemd/systemd-resolved', 'systemd-resolve'),
    'systemd-timesyncd.service': ('/usr/lib/systemd/systemd-timesyncd', 'systemd-timesync'),
    'systemd-networkd.service': ('/usr/lib/systemd/systemd-networkd', 'systemd-network'),
    'cron.service': ('/usr/sbin/cron', None),
    'dbus.service': ('/usr/bin/dbus-daemon', 'messagebus'),
    'polkit.service': ('/usr/lib/polkit-1/polkitd', 'polkitd'),
    'systemd-logind.service': ('/usr/lib/systemd/systemd-logind', None),
    'ssh.service': ('/usr/sbin/sshd', None),
    'qemu-guest-agent.service': ('/usr/sbin/qemu-ga', None),
    'udisks2.service': ('/usr/libexec/udisks2/udisksd', None),
    'unattended-upgrades.service': ('/usr/bin/python3.12', None),
    'rsyslog.service': ('/usr/sbin/rsyslogd', 'syslog'),
    'getty@tty1.service': ('/usr/sbin/agetty', None),
    'serial-getty@ttyS0.service': ('/usr/sbin/agetty', None),
    'ModemManager.service': ('/usr/sbin/ModemManager', None),
    'user@1000.service': ('/usr/lib/systemd/systemd', 'recovery'),
}
EXECUTABLES = frozenset({value[0] for value in UNITS.values()} | {
    '/usr/lib/systemd/systemd', '/usr/lib/systemd/systemd-executor', '/usr/bin/sudo', '/usr/sbin/sshd', '/usr/bin/python3.12'})


def _idle_need(value, reason):
    if not value:
        raise ValueError(reason)


def _idle_generation(info):
    return [info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns]


def _idle_public_file(path):
    import pathlib, stat
    path = pathlib.Path(path)
    _idle_need(path.is_absolute() and path == path.resolve(strict=True), 'idle_public_path')
    for parent in path.parents:
        info = parent.stat()
        _idle_need(info.st_uid == 0 and not info.st_mode & 0o022, 'idle_public_owner')
    info = path.stat()
    _idle_need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022 and info.st_nlink == 1,
               'idle_public_owner')
    return _idle_generation(info)


def _idle_unit(unit):
    import subprocess, pathlib
    _idle_need(unit in IDLE_UNITS, 'idle_unit_unrecognized')
    result = subprocess.run(['systemctl', 'show', unit, '-p', 'MainPID', '-p', 'FragmentPath', '-p', 'ActiveState', '-p', 'SubState', '-p', 'LoadState'],
                            capture_output=True, text=True, timeout=3)
    _idle_need(not result.returncode and len(result.stdout.encode()) <= 65536 and len(result.stderr.encode()) <= 65536, 'idle_unit_visibility')
    fields = {}
    for row in result.stdout.splitlines():
        key, separator, value = row.partition('=')
        _idle_need(separator and key not in fields, 'idle_unit_visibility')
        fields[key] = value
    _idle_need(set(fields) == {'MainPID', 'FragmentPath', 'ActiveState', 'SubState', 'LoadState'}
               and fields['MainPID'].isdigit(), 'idle_unit_visibility')
    if fields['LoadState'] == 'not-found':
        _idle_need(fields['FragmentPath'] == '' and fields['MainPID'] == '0', 'idle_unit_visibility')
        return fields, None, None
    expected = unit.replace('@1000', '@').replace('@tty1', '@').replace('@ttyS0', '@')
    path = pathlib.Path(fields['FragmentPath'])
    _idle_need(fields['LoadState'] == 'loaded' and path.name == expected
               and path.parent == pathlib.Path('/usr/lib/systemd/system'), 'idle_unit_unrecognized')
    return fields, str(path), _idle_public_file(path)


def _idle_baseline(previous=None):
    import pathlib, hashlib, pwd
    if previous is not None:
        _idle_need(type(previous) is dict and set(previous) == {'schemaVersion', 'machineId', 'units', 'executables'}
                   and previous['schemaVersion'] == 1 and type(previous['schemaVersion']) is int
                   and previous['machineId'] == pathlib.Path('/etc/machine-id').read_text().strip()
                   and set(previous['units']) <= set(IDLE_UNITS)
                   and set(previous['executables']) <= set(IDLE_EXECUTABLES), 'idle_baseline_changed')
    units = {}
    for name in sorted(IDLE_UNITS):
        fields, path, generation = _idle_unit(name)
        if previous is not None and name in previous['units']:
            original = previous['units'][name]
            if original is None:
                _idle_need(path is None, 'idle_unit_changed')
            else:
                _idle_need(original['fragment'] == path and original['generation'] == generation
                           and original['executable'] == IDLE_UNITS[name][0], 'idle_unit_changed')
            units[name] = original
        elif path is None:
            units[name] = None
        else:
            source = pathlib.Path(path).read_bytes()
            _idle_need(len(source) <= 131072 and _idle_public_file(path) == generation, 'idle_unit_changed')
            executable, username = IDLE_UNITS[name]
            uid = 0 if username is None else pwd.getpwnam(username).pw_uid
            _idle_need(type(uid) is int and uid >= 0 and (name != 'user@1000.service' or uid == 1000), 'idle_service_account')
            units[name] = {'fragment': path, 'generation': generation, 'sha256': hashlib.sha256(source).hexdigest(),
                           'executable': executable, 'uid': uid}
    executables = {}
    for path in sorted(IDLE_EXECUTABLES):
        generation = _idle_public_file(path)
        if previous is not None and path in previous['executables']:
            _idle_need(previous['executables'][path] == generation, 'idle_executable_changed')
        executables[path] = generation
    return {'schemaVersion': 1, 'machineId': pathlib.Path('/etc/machine-id').read_text().strip(),
            'units': units, 'executables': executables}


def _idle_cgroup(raw):
    units = {part for line in raw.splitlines() for part in line.split('/') if part.endswith('.service')}
    return next(iter(units)) if len(units) == 1 else None


def _idle_process(path):
    import os
    raw = (path / 'stat').read_text(); tail = raw.rsplit(')', 1)[1].split()
    status = {}
    for row in (path / 'status').read_text().splitlines():
        key, separator, value = row.partition(':')
        _idle_need(separator and key not in status, 'idle_process_visibility'); status[key] = value
    _idle_need('Kthread' in status and len(tail) >= 20, 'idle_process_visibility')
    if status['Kthread'].strip() == '1' or tail[0] == 'Z':
        return None
    uids = [int(value) for value in status['Uid'].split()]
    _idle_need(len(uids) == 4, 'idle_process_visibility')
    executable = os.readlink(path / 'exe')
    row = {'pid': int(path.name), 'birth': int(tail[19]), 'parent': int(tail[1]), 'uids': uids,
           'exe': executable, 'exeGeneration': _idle_generation((path / 'exe').stat()),
           'unit': _idle_cgroup((path / 'cgroup').read_text()), 'name': status['Name'].strip()}
    after = (path / 'stat').read_text().rsplit(')', 1)[1].split()
    _idle_need(after[19] == tail[19] and after[1] == tail[1], 'idle_process_changed')
    return row


def _idle_projection(baseline):
    import pathlib, os
    if baseline is None:
        return {'complete': False, 'unknown': [{'state': 'unknown', 'reason': 'process_baseline_unavailable'}]}
    _idle_need(type(baseline) is dict and set(baseline) == {'schemaVersion', 'machineId', 'units', 'executables'}
               and type(baseline['schemaVersion']) is int and baseline['schemaVersion'] == 1
               and baseline['machineId'] == pathlib.Path('/etc/machine-id').read_text().strip()
               and set(baseline['units']) == set(IDLE_UNITS)
               and set(baseline['executables']) == set(IDLE_EXECUTABLES), 'idle_baseline_changed')
    for path, generation in baseline['executables'].items():
        _idle_need(_idle_public_file(path) == generation, 'idle_executable_changed')
    units = {}
    for name, original in baseline['units'].items():
        fields, path, generation = _idle_unit(name)
        if original is None:
            _idle_need(path is None, 'idle_unit_changed')
        else:
            # Changed bytes may contain private input. Never read or hash them.
            _idle_need(type(original) is dict and set(original) == {'fragment', 'generation', 'sha256', 'executable', 'uid'}
                       and original['fragment'] == path and original['generation'] == generation
                       and original['executable'] == IDLE_UNITS[name][0]
                       and type(original['uid']) is int and original['uid'] >= 0, 'idle_unit_changed')
            units[name] = (fields, original)
    processes = {}; complete = True
    for path in pathlib.Path('/proc').iterdir():
        if not path.name.isdigit():
            continue
        _idle_need(len(processes) < 4096, 'idle_process_overflow')
        try:
            row = _idle_process(path)
            if row is not None:
                processes[row['pid']] = row
        except FileNotFoundError:
            continue
        except (OSError, ValueError, KeyError, IndexError):
            complete = False
    def matches(row, executable, uids):
        return row is not None and row['exe'] == executable and row['uids'] == uids and row['exeGeneration'] == baseline['executables'][executable]
    admitted = set()
    init = processes.get(1)
    if matches(init, '/usr/lib/systemd/systemd', [0] * 4) and init['parent'] == 0:
        admitted.add(1)
    else:
        complete = False
    for name, (fields, original) in units.items():
        pid = int(fields['MainPID']); row = processes.get(pid)
        if not pid:
            continue
        if (fields['ActiveState'] == 'active' and fields['SubState'] == 'running' and row is not None
                and row['unit'] == name and matches(row, original['executable'], [original['uid']] * 4)):
            if name == 'unattended-upgrades.service':
                command = (pathlib.Path('/proc') / str(pid) / 'cmdline').read_bytes()
                if command != b'/usr/bin/python3\0/usr/share/unattended-upgrades/unattended-upgrade-shutdown\0--wait-for-signal\0':
                    continue
            admitted.add(pid)
    # This exact source runs as root through the configured ordinary SSH
    # account. Only its closed kernel ancestry is transport, never siblings.
    probe = processes.get(os.getpid())
    probe_ok = matches(probe, '/usr/bin/python3.12', [0] * 4)
    chain = []
    cursor = probe
    roles = [('/usr/bin/sudo', [1000, 0, 0, 0]), ('/usr/sbin/sshd', [1000] * 4), ('/usr/sbin/sshd', [0] * 4)]
    for executable, uids in roles:
        cursor = None if cursor is None else processes.get(cursor['parent'])
        probe_ok = probe_ok and matches(cursor, executable, uids)
        if cursor is not None:
            chain.append(cursor['pid'])
    ssh_main = int(units['ssh.service'][0]['MainPID']) if 'ssh.service' in units else 0
    probe_ok = probe_ok and cursor is not None and cursor['parent'] == ssh_main and ssh_main in admitted
    if probe_ok:
        admitted.update([os.getpid(), *chain])
    else:
        complete = False
    user = int(units['user@1000.service'][0]['MainPID']) if 'user@1000.service' in units else 0
    pam = [row for row in processes.values() if row['parent'] == user and row['name'] == '(sd-pam)']
    if user in admitted and len(pam) == 1 and matches(pam[0], '/usr/lib/systemd/systemd-executor', [1000] * 4):
        admitted.add(pam[0]['pid'])
    elif pam:
        complete = False
    for pid, row in processes.items():
        try:
            current = _idle_process(pathlib.Path('/proc') / str(pid))
            if current != row:
                complete = False
        except FileNotFoundError:
            continue
        except (OSError, ValueError, KeyError, IndexError):
            complete = False
    unknown = [{'state': 'unknown', 'reason': 'unmanaged_process', 'pid': row['pid'], 'birth': row['birth']}
               for pid, row in sorted(processes.items()) if pid not in admitted]
    return {'complete': complete, 'unknown': unknown}


def source():
    """Build only; no file inspection or enrollment effects in the coordinator."""
    functions = (_idle_need, _idle_generation, _idle_public_file, _idle_unit, _idle_baseline,
                 _idle_cgroup, _idle_process, _idle_projection)
    return ('IDLE_UNITS=' + repr(UNITS) + '\nIDLE_EXECUTABLES=' + repr(tuple(sorted(EXECUTABLES))) + '\n'
            + '\n'.join(inspect.getsource(function) for function in functions))


def _legacy_main():
    import hashlib, json, os, pathlib, sys, types, uuid
    module = types.ModuleType('fixed_qemu_legacy_observer');sys.modules[module.__name__] = module
    exec(compile(OWNER, '<fixed-qemu-legacy-observer>', 'exec'), module.__dict__)
    module.owner_source = lambda: OWNER
    _need = module._need
    _need(os.geteuid() == 1000 and pathlib.Path('/etc/machine-id').read_text().strip() == MACHINE_ID, 'legacy_guest_identity')
    known = {}; rows = []
    for packet in PACKETS:
        _need(type(packet) is dict and set(packet) in ({'remoteRoot', 'generation', 'binding', 'operationId', 'requestSha256', 'ownerSourceSha256'}, {'remoteRoot', 'generation', 'binding', 'operationId', 'requestSha256', 'ownerSourceSha256', 'collectedTerminal'}), 'legacy_packet')
        operation = str(uuid.UUID(packet['operationId']))
        _need(operation == packet['operationId'] and packet['remoteRoot'] == '/tmp/vpn-control-program-1000-' + operation
              and packet['ownerSourceSha256'] == hashlib.sha256(OWNER).hexdigest() and packet['remoteRoot'] not in known, 'legacy_packet')
        original = module.MachineBinding.from_dict(packet['binding'])
        _need(original.account == '1000' and original.target == TARGET and original.machine == MACHINE, 'legacy_binding')
        known[packet['remoteRoot']] = packet
    roots = {str(path) for path in pathlib.Path('/tmp').glob('vpn-control-program-*')}
    if roots - set(known):
        print(json.dumps({'complete': False, 'jobs': [{'state': 'unknown', 'reason': 'unadmitted_legacy_namespace'}]}));return
    for root, packet in known.items():
        original = module.MachineBinding.from_dict(packet['binding'])
        if root not in roots:
            # Only a source-collected terminal can retire an original /tmp
            # root after a real boot change; missing process is no job proof.
            terminal = packet.get('collectedTerminal')
            _need(type(terminal) is dict and terminal.get('state') == 'terminal'
                  and terminal.get('operationId') == packet['operationId'] and terminal.get('binding') == packet['binding']
                  and terminal['terminal']['programSha256'] == packet['requestSha256']
                  and terminal['terminal']['streamsClosed'] is True
                  and module.current_binding(TARGET, MACHINE).boot != original.boot, 'legacy_collected_absence')
            try:
                pathlib.Path(root).lstat()
            except FileNotFoundError:
                rows.append({**terminal, 'collection': packet});continue
            raise ValueError('legacy_collected_reappeared')
        generation = packet['generation']
        _need(type(generation) is list and len(generation) == 2 and all(type(n) is int and n > 0 for n in generation), 'legacy_generation')
        state = module.observe(root, packet['operationId'], original, generation=tuple(generation))
        intent = module._intent(pathlib.Path(root) / packet['operationId'], packet['operationId'], original)
        _need(intent['programSha256'] == packet['requestSha256'], 'legacy_program_changed')
        if state['state'] == 'terminal':
            module.collect(root, packet['operationId'], original, generation=tuple(generation))
            state = {**state, 'collection': {**packet, 'collectedTerminal': state}}
        rows.append(state)
    print(json.dumps({'complete': True, 'jobs': rows}))


def legacy_program(packets, *, target, machine, actual_machine_id):
    from . import durable_remote_job
    import json
    if type(packets) is not list or len(packets) > 128:
        raise ValueError('legacy_packets')
    # Round-trip only typed public packet data; no caller source or command.
    packets = json.loads(json.dumps(packets, sort_keys=True, allow_nan=False))
    return ('OWNER=' + repr(durable_remote_job.owner_source()) + '\nPACKETS=' + repr(packets)
            + '\nTARGET=' + repr(target) + '\nMACHINE=' + repr(machine) + '\nMACHINE_ID=' + repr(actual_machine_id)
            + '\n' + inspect.getsource(_legacy_main) + '\n_legacy_main()\n')
