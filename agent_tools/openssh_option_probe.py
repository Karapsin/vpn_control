"""Bounded local OpenSSH option parsing for two actual-parser unit tests.

This is not a transport runner. Only config-free ``ssh -G`` queries without
payloads or executable config hooks are admitted. A timeout's cause is unknown;
retry is safe here because the original local parser has already been reaped.
"""
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import sys


_ATTEMPT_TIMEOUT_SECONDS = 5
_MAX_ATTEMPTS = 2
_VALUE_FLAGS = {'-F', '-S', '-p', '-l', '-i', '-o'}
_BOOL_OPTIONS = {
    'BatchMode': {'yes', 'no'},
    'StrictHostKeyChecking': {'yes'},
    'IdentitiesOnly': {'yes'},
    'ControlMaster': {'yes', 'no'},
    'ControlPersist': {'no'},
    'ClearAllForwardings': {'yes'},
    'ForkAfterAuthentication': {'no'},
    'UpdateHostKeys': {'no'},
    'ProxyCommand': {'false'},
}
_NUMBER_OPTIONS = {
    'ConnectTimeout', 'NumberOfPasswordPrompts',
    'ServerAliveInterval', 'ServerAliveCountMax',
}


def _query(argv):
    if (type(argv) not in (list, tuple) or len(argv) < 5
            or any(type(x) is not str or not x or any(ord(c) < 32 for c in x) for x in argv)):
        raise ValueError('unsafe-local-openssh-option-query')
    command = tuple(argv)
    executable = Path(command[0])
    if not executable.is_absolute() or executable.name.lower() not in {'ssh', 'ssh.exe'}:
        raise ValueError('unsafe-local-openssh-option-query')
    # Exactly one final destination: -G after a destination is a remote payload.
    destination = command[-1]
    if destination.startswith('-') or any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.:-' for c in destination):
        raise ValueError('unsafe-local-openssh-option-query')
    index = 1
    configs = 0
    dumps = 0
    while index < len(command) - 1:
        flag = command[index]
        if flag in {'-G', '-N', '-T'}:
            dumps += flag == '-G'
            index += 1
            continue
        if flag not in _VALUE_FLAGS or index + 1 >= len(command) - 1:
            raise ValueError('unsafe-local-openssh-option-query')
        value = command[index + 1]
        if flag == '-F':
            configs += 1
            if value != '/dev/null':
                raise ValueError('unsafe-local-openssh-option-query')
        elif flag == '-p':
            if not value.isascii() or not value.isdecimal() or not 1 <= int(value) <= 65535:
                raise ValueError('unsafe-local-openssh-option-query')
        elif flag == '-o':
            key, separator, setting = value.partition('=')
            allowed = (separator and (
                key in _BOOL_OPTIONS and setting in _BOOL_OPTIONS[key]
                or key in _NUMBER_OPTIONS and setting.isascii() and setting.isdecimal()
                or key == 'UserKnownHostsFile' and bool(setting)
            ))
            if not allowed:
                raise ValueError('unsafe-local-openssh-option-query')
        elif value.startswith('-'):
            raise ValueError('unsafe-local-openssh-option-query')
        index += 2
    if configs != 1 or dumps != 1:
        raise ValueError('unsafe-local-openssh-option-query')
    return command


def run_option_probe(argv):
    """Return CompletedProcess with original ``timeout_attempts`` attached.

    Two unchanged five-second attempts cap parser execution at ten seconds.
    ``subprocess.run`` kills and waits for its own child before raising timeout;
    no successor is submitted until that cleanup returns. Other errors propagate.
    Original TimeoutExpired objects retain command/deadline/partial byte streams;
    their streams also enter the test runner's retained stderr as base64.
    """
    command = _query(argv)
    timeouts = []
    for attempt in range(1, _MAX_ATTEMPTS + 1):
        try:
            result = subprocess.run(command, stdin=subprocess.DEVNULL,
                                    capture_output=True, check=True,
                                    timeout=_ATTEMPT_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired as error:
            timeouts.append(error)
            error.timeout_attempts = tuple(timeouts)
            record = {
                'event': 'local-openssh-option-parser-timeout',
                'attempt': attempt,
                'timeoutSeconds': error.timeout,
                'querySha256': hashlib.sha256(json.dumps(command).encode()).hexdigest(),
                'stdoutBase64': base64.b64encode(error.stdout or b'').decode(),
                'stderrBase64': base64.b64encode(error.stderr or b'').decode(),
                'originalChildReaped': True,
                'cause': 'unknown',
            }
            print(json.dumps(record, sort_keys=True), file=sys.stderr, flush=True)
            if attempt == _MAX_ATTEMPTS:
                raise
        except subprocess.CalledProcessError as error:
            error.timeout_attempts = tuple(timeouts)
            raise
        else:
            result.timeout_attempts = tuple(timeouts)
            return result
