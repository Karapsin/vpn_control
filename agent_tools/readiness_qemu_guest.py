"""Fixed read-only guest facts for owned headless QEMU recovery fixtures."""
import inspect


def _guest_facts():
    import json, os, pathlib, subprocess
    if os.geteuid() != 0:
        raise ValueError('idle_privilege')
    def run(argv):
        value = subprocess.run(argv, text=True, capture_output=True, timeout=5)
        if value.returncode or len(value.stdout.encode()) > 262144 or len(value.stderr.encode()) > 65536:
            raise ValueError('idle_visibility')
        return value.stdout
    processes = []
    blocked = []
    for path in pathlib.Path('/proc').iterdir():
        if not path.name.isdigit():
            continue
        try:
            name = (path / 'comm').read_text().strip()
            command = (path / 'cmdline').read_bytes()
            if len(command) > 65536:
                raise ValueError('process_visibility')
        except FileNotFoundError:
            continue
        processes.append(int(path.name))
        product = any(word.startswith((b'com.kardinal.vpncontrol.', b'/opt/vpn-control/')) for word in command.split(b'\0'))
        if name in {'apt', 'apt-get', 'dpkg', 'msiexec', 'sing-box', 'vpn-control', 'vpncontrol'} or product:
            blocked.append('installer' if name in {'apt', 'apt-get', 'dpkg', 'msiexec'} else 'protected_runtime')
    jobs = run(['systemctl', 'list-jobs', '--no-legend', '--plain'])
    cloud = run(['cloud-init', 'status'])
    sessions = run(['loginctl', 'list-sessions', '--no-legend', '--no-pager'])
    foreign = []
    ordinary = []
    for line in sessions.splitlines():
        fields = line.split()
        if len(fields) < 3 or not fields[0].isalnum() or not fields[1].isdigit():
            raise ValueError('session_visibility')
        details = run(['loginctl', 'show-session', fields[0], '--property=User', '--property=Name', '--property=Remote', '--property=Service'])
        parsed = {}
        for row in details.splitlines():
            key, separator, value = row.partition('=')
            if not separator or key in parsed or key not in {'User', 'Name', 'Remote', 'Service'}:
                raise ValueError('session_visibility')
            parsed[key] = value
        if set(parsed) != {'User', 'Name', 'Remote', 'Service'} or parsed['User'] != fields[1] or parsed['Name'] != fields[2]:
            raise ValueError('session_visibility')
        if parsed == {'User': '1000', 'Name': 'recovery', 'Remote': 'yes', 'Service': 'sshd'}:
            ordinary.append(fields[0])
        else:
            foreign.append(fields[0])
    if len(ordinary) != 1:
        foreign.append('competing_or_missing_operator')
    baseline = _idle_baseline(IDLE_BASELINE) if IDLE_ENROLL else IDLE_BASELINE
    try:
        process_projection = _idle_projection(baseline)
    except (OSError, ValueError, TypeError, KeyError):
        process_projection = {'complete': False, 'unknown': [{'state': 'unknown', 'reason': 'process_visibility_unavailable'}]}
    legacy = {'complete': False, 'jobs': [{'state': 'unknown', 'reason': 'legacy_visibility_unavailable'}]}
    if LEGACY_COMMAND is not None:
        response = subprocess.run(['runuser', '--user', 'recovery', '--', *LEGACY_COMMAND],
                                  input=LEGACY_PAYLOAD, capture_output=True, timeout=10)
        if response.returncode == 0 and len(response.stdout) <= 262144 and len(response.stderr) <= 65536:
            candidate = json.loads(response.stdout)
            if (type(candidate) is dict and set(candidate) == {'complete', 'jobs'} and type(candidate['complete']) is bool
                    and type(candidate['jobs']) is list and len(candidate['jobs']) <= 1024
                    and all(type(row) is dict and type(row.get('state')) is str for row in candidate['jobs'])):
                legacy = candidate
    registered = []
    jobroot = pathlib.Path('/var/tmp/vc-recovery-jobs')
    complete = False
    if JOBS_COMMAND is None:
        # Only the new, never-enrolled fixture may prove this namespace absent.
        complete = not jobroot.exists() and not jobroot.is_symlink()
    else:
        response = subprocess.run(['runuser', '--user', 'recovery', '--', *JOBS_COMMAND],
                                  input=JOBS_PAYLOAD, capture_output=True, timeout=10)
        if response.returncode == 0 and len(response.stdout) <= 262144 and len(response.stderr) <= 65536:
            try:
                projection = json.loads(response.stdout)
            except (ValueError, TypeError):
                projection = None
            if (type(projection) is dict and set(projection) == {'visibilityComplete', 'jobs', 'idle'}
                    and projection['visibilityComplete'] is True and type(projection['jobs']) is list
                    and len(projection['jobs']) <= 1024 and all(type(row) is dict and type(row.get('state')) is str for row in projection['jobs'])
                    and projection['idle'] == all(row['state'] == 'terminal' for row in projection['jobs'])):
                registered = projection['jobs']; complete = True
    if not complete:
        registered = [{'state': 'unknown', 'reason': 'canonical_job_visibility_unavailable'}]
    print(json.dumps({'bootId': pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                      'machineId': pathlib.Path('/etc/machine-id').read_text().strip(),
                      'account': os.environ.get('SUDO_USER'), 'originalUid': os.environ.get('SUDO_UID'),
                      'processCount': len(processes), 'protectedOrInstallerProcesses': sorted(set(blocked)),
                      'systemdJobs': jobs.splitlines(), 'cloudInit': cloud.strip(),
                      'foreignSessions': foreign, 'registeredJobs': registered, 'jobVisibilityComplete': complete and process_projection['complete'] and legacy['complete'],
                      'idleBaselineCandidate': baseline if IDLE_ENROLL else None,
                      'idleLegacyCandidate': [row.get('collection') for row in legacy['jobs']] if IDLE_ENROLL else None,
                      'unknownOrRunningJobs': (process_projection['unknown'] + [row for row in legacy['jobs'] if row.get('state') != 'terminal']
                                               + [row for row in registered if row.get('state') != 'terminal'])}))


def program(namespace=None, idle_context=None, *, enroll_idle=False):
    """Build only; no transport, login, lock, power action or file mutation."""
    from . import readiness_qemu_jobs, readiness_qemu_idle
    command, payload = (None, None) if namespace is None else readiness_qemu_jobs.stdin_command(readiness_qemu_jobs.observe_program(namespace))
    baseline = None if idle_context is None else idle_context['baseline']
    legacy_command, legacy_payload = (None, None)
    if idle_context is not None:
        legacy_command, legacy_payload = readiness_qemu_jobs.stdin_command(readiness_qemu_idle.legacy_program(
            idle_context['legacyJobs'], target=idle_context['target'], machine=idle_context['machine'],
            actual_machine_id=idle_context['actualMachineId']))
    return (readiness_qemu_idle.source() + '\nIDLE_BASELINE=' + repr(baseline) + '\nIDLE_ENROLL=' + repr(enroll_idle)
            + '\nLEGACY_COMMAND=' + repr(legacy_command) + '\nLEGACY_PAYLOAD=' + repr(legacy_payload)
            + '\nJOBS_COMMAND=' + repr(command) + '\nJOBS_PAYLOAD=' + repr(payload) + '\n'
            + inspect.getsource(_guest_facts) + '\n_guest_facts()\n')
