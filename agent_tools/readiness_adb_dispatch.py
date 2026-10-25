"""Fixed PATH adapter for children of one original Android admission.

Every ADB process reopens that admission, observes its original session and lease,
and targets its qualified daemon explicitly. This adapter cannot recover a guest,
change the selected endpoint, start a daemon, or admit a successor operation.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import sys

from . import readiness
from . import readiness_entrypoints as entry
from . import private_inventory_lock as private


_SOURCE = Path(__file__).absolute()
_RAW, _GENERATION, _DIGEST = entry.policies._capture(_SOURCE)
if sys._getframe().f_code != compile(_RAW, __file__, 'exec', dont_inherit=True, optimize=sys.flags.optimize):
    raise ValueError('adb_dispatch_executing_source_mismatch')


def _guard():
    _, generation, digest = entry.policies._capture(_SOURCE)
    if (generation, digest) != (_GENERATION, _DIGEST):
        raise ValueError('adb_dispatch_source_changed')


def _arguments(arguments, binding):
    """Accept ordinary client flags while retaining the original daemon/device."""
    arguments = list(arguments)
    remaining = []
    while arguments and arguments[0].startswith('-'):
        option = arguments.pop(0)
        if option == '-s':
            if not arguments or arguments.pop(0) != binding['serial']:
                raise ValueError('adb_dispatch_target_mismatch')
        elif option == '-suppress-kill-server':
            remaining.append(option)
        elif option in {'-H', '-P', '-L', '-t', '-d', '-e', '-a'} or option.startswith(('-H', '-P', '-L', '-s', '-t')):
            raise ValueError('adb_dispatch_endpoint_override')
        else:
            raise ValueError('adb_dispatch_option_unqualified')
    if not arguments or arguments[0] in {'start-server', 'kill-server', 'server', 'nodaemon', 'fork-server', 'attach', 'detach'}:
        raise ValueError('adb_dispatch_lifecycle_forbidden')
    return [*remaining, *arguments]


def dispatch(root, operation, arguments):
    """Observe once immediately before replacing this client with trusted ADB."""
    _guard()
    record = entry.check_persisted(root, operation)
    binding = record['binding']
    if set(binding) != {'adb', 'serial', 'avd', 'serverPort'}:
        raise ValueError('adb_dispatch_binding_invalid')
    tail = _arguments(arguments, binding)
    _guard()
    environment = dict(os.environ)
    environment['ANDROID_ADB_SERVER_PORT'] = str(binding['serverPort'])
    environment['ADB_SERVER_SOCKET'] = 'tcp:127.0.0.1:' + str(binding['serverPort'])
    argv = [binding['adb'], '-H127.0.0.1', '-P' + str(binding['serverPort']), '-s', binding['serial'], *tail]
    os.execve(binding['adb'], argv, environment)


def _wrapper(root, operation):
    return ('#!' + sys.executable + ' -I\n' +
            'import sys\nfrom pathlib import Path\n' +
            'sys.path.insert(0,' + repr(str(_SOURCE.parent.parent)) + ')\n' +
            'from agent_tools.readiness_adb_dispatch import main\n' +
            'raise SystemExit(main(root=Path(' + repr(str(root)) + '),operation=' + repr(operation) + '))\n').encode()


def environment(admission, base=None):
    """Create one protected fixed wrapper, never replace original admission."""
    admission.revalidate()
    if admission.family != 'android':
        raise ValueError('adb_dispatch_binding_invalid')
    try:
        entry.persist(admission)
    except FileExistsError:
        entry.check_persisted(admission.root, admission.operation_identity)
    directory = entry._receipt_directory(admission.root)
    for name in (admission.operation_identity, 'bin'):
        with private.Directory(directory) as held:
            try:
                os.mkdir(name, 0o700, dir_fd=held.fd)
            except FileExistsError:
                pass
            info = os.stat(name, dir_fd=held.fd, follow_symlinks=False)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise ValueError('adb_dispatch_wrapper_unsafe')
            held.guard()
        directory = directory / name
    body = _wrapper(admission.root, admission.operation_identity)
    with readiness.RecoveryJournal(directory).locked(), private.Directory(directory) as held:
        try:
            fd = os.open('adb', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o700, dir_fd=held.fd)
        except FileExistsError:
            original, _, _ = entry.policies._capture(directory / 'adb')
            info = os.stat('adb', dir_fd=held.fd, follow_symlinks=False)
            if (original != body or not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) != 0o700 or info.st_nlink != 1):
                raise ValueError('adb_dispatch_wrapper_changed')
        else:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(body); stream.flush(); os.fsync(stream.fileno())
            os.fsync(held.fd)
        held.guard()
    _guard(); admission.revalidate()
    result = dict(os.environ if base is None else base)
    result.pop('DYLD_INSERT_LIBRARIES', None)
    result['PATH'] = str(directory) + os.pathsep + result.get('PATH', os.defpath)
    result['ANDROID_ADB_SERVER_PORT'] = str(admission.binding['serverPort'])
    result['ADB_SERVER_SOCKET'] = 'tcp:127.0.0.1:' + str(admission.binding['serverPort'])
    return result


def main(argv=None, *, root, operation):
    try:
        dispatch(root, operation, sys.argv[1:] if argv is None else argv)
    except (readiness.ReadinessBlocked, ValueError, OSError):
        # No raw executable/server text: it could contain private input.
        print(json.dumps({'ok': False, 'reason': 'original_adb_admission_blocked', 'operationId': operation}), file=sys.stderr)
        return 2
    return 0
