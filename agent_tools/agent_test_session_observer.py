"""Unrouted prototype: bounded metadata around one admitted test session cleanup.

This observer never signals processes and grants no cleanup or native authority.
It retains process generations before an existing owner performs its cleanup;
only fixed command roles can enter the result, never argv, environment or paths.
"""
from __future__ import annotations

import ctypes
from dataclasses import dataclass, field
import errno
import hashlib
import os
from pathlib import Path
import stat
import subprocess
import sys
import time
from types import MappingProxyType


class SessionObservationBlocked(ValueError):
    pass


_REASONS = frozenset({
    'session_observer_source_changed', 'session_process_catalogue_incomplete',
    'session_platform_unsupported', 'session_member_visibility_incomplete',
    'session_member_changed', 'session_owner_not_live', 'session_owner_not_exclusive',
    'session_observation_identity_invalid', 'session_owner_changed',
    'session_observation_deadline', 'session_owner_generation_changed',
    'session_membership_changed',
})
_EXECUTING_CODE = sys._getframe().f_code
_PATH = Path(__file__).absolute()
_STAT = _PATH.stat(follow_symlinks=False)
_SOURCE = _PATH.read_bytes()
_ISSUER = object()
_LIMIT = 65536


def _generation(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _guard_source():
    info = _PATH.stat(follow_symlinks=False)
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
            _generation(info) != _generation(_STAT) or _PATH.read_bytes() != _SOURCE or
            compile(_SOURCE, str(_PATH), 'exec') != _EXECUTING_CODE):
        raise SessionObservationBlocked('session_observer_source_changed')


def _role(raw):
    # comm is used only as an input to this finite projection; it is never emitted.
    value = raw.decode('ascii', 'ignore').lower()
    if value.startswith(('python', 'pypy')):
        return 'python'
    return value if value in ('sh', 'bash', 'zsh', 'dash', 'sleep', 'ssh', 'tmux') else 'other'


class _Bsd(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint32) for name in
        ('flags', 'status', 'xstatus', 'pid', 'ppid', 'uid', 'gid', 'ruid', 'rgid', 'svuid', 'svgid', 'reserved')] + [
        ('comm', ctypes.c_char * 16), ('name', ctypes.c_char * 32)] + [
        (name, ctypes.c_uint32) for name in ('nfiles', 'pgid', 'pjobc', 'tdev', 'tpgid')] + [
        ('nice', ctypes.c_int32), ('start_seconds', ctypes.c_uint64), ('start_microseconds', ctypes.c_uint64)]


def _darwin():
    value = ctypes.CDLL('/usr/lib/libproc.dylib', use_errno=True)
    value.proc_listallpids.argtypes = [ctypes.c_void_p, ctypes.c_int]
    value.proc_listallpids.restype = ctypes.c_int
    value.proc_pidinfo.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int]
    value.proc_pidinfo.restype = ctypes.c_int
    return value


def _pids():
    if sys.platform == 'darwin':
        native = _darwin()
        count = native.proc_listallpids(None, 0)
        if not 0 < count < _LIMIT - 256:
            raise SessionObservationBlocked('session_process_catalogue_incomplete')
        values = (ctypes.c_int * (count + 256))()
        actual = native.proc_listallpids(values, ctypes.sizeof(values))
        if not 0 < actual < len(values):
            raise SessionObservationBlocked('session_process_catalogue_incomplete')
        result = [int(pid) for pid in values[:actual] if pid > 0]
    elif sys.platform.startswith('linux'):
        result = [int(path.name) for path in Path('/proc').iterdir() if path.name.isdecimal()]
    else:
        raise SessionObservationBlocked('session_platform_unsupported')
    if len(result) >= _LIMIT or len(result) != len(set(result)):
        raise SessionObservationBlocked('session_process_catalogue_incomplete')
    return sorted(result)


def _identity(pid):
    try:
        sid, pgid = os.getsid(pid), os.getpgid(pid)
        if sys.platform == 'darwin':
            info = _Bsd()
            if _darwin().proc_pidinfo(pid, 3, 0, ctypes.byref(info), ctypes.sizeof(info)) != ctypes.sizeof(info):
                if ctypes.get_errno() == errno.ESRCH:
                    return None
                raise SessionObservationBlocked('session_member_visibility_incomplete')
            if info.pid != pid or info.pgid != pgid:
                raise SessionObservationBlocked('session_member_changed')
            birth = 'darwin:%d:%d' % (info.start_seconds, info.start_microseconds)
            ppid, uid, role = int(info.ppid), int(info.uid), _role(info.comm)
        elif sys.platform.startswith('linux'):
            directory = Path('/proc') / str(pid)
            raw = (directory / 'stat').read_bytes()
            left, right = raw.find(b'('), raw.rfind(b')')
            fields = raw[right + 2:].split()
            if (left < 1 or right <= left or int(raw[:left]) != pid or len(fields) < 20 or
                    int(fields[2]) != pgid or int(fields[3]) != sid):
                raise SessionObservationBlocked('session_member_changed')
            birth = 'linux:' + fields[19].decode('ascii')
            ppid, uid, role = int(fields[1]), directory.stat().st_uid, _role(raw[left + 1:right])
        else:
            raise SessionObservationBlocked('session_platform_unsupported')
        if (os.getsid(pid), os.getpgid(pid)) != (sid, pgid):
            raise SessionObservationBlocked('session_member_changed')
        return {'pid': pid, 'birth': birth, 'ppid': ppid, 'uid': uid,
                'sid': sid, 'pgid': pgid, 'role': role}
    except (ProcessLookupError, FileNotFoundError):
        return None
    except OSError as error:
        if error.errno == errno.ESRCH:
            return None
        raise SessionObservationBlocked('session_member_visibility_incomplete') from None


@dataclass(frozen=True, repr=False)
class OwnedSession:
    _issuer: object = field(repr=False)
    _process: subprocess.Popen = field(repr=False)
    _original: object = field(repr=False)


def admit(process):
    """Called immediately after this caller creates its new-session Popen."""
    _guard_source()
    if type(process) is not subprocess.Popen or process.poll() is not None:
        raise SessionObservationBlocked('session_owner_not_live')
    original = _identity(process.pid)
    if (original is None or original['ppid'] != os.getpid() or original['uid'] != os.geteuid() or
            (original['sid'], original['pgid']) != (process.pid, process.pid)):
        raise SessionObservationBlocked('session_owner_not_exclusive')
    _guard_source()
    return OwnedSession(_ISSUER, process, MappingProxyType(original))


def admission_record(owner):
    """Public finite metadata; the Popen and its argv remain private."""
    _guard_source()
    if type(owner) is not OwnedSession or owner._issuer is not _ISSUER:
        raise SessionObservationBlocked('session_observation_identity_invalid')
    return {'state': 'admitted', 'original': dict(owner._original),
            'observerSourceSha256': hashlib.sha256(_SOURCE).hexdigest(), 'cleanupAuthority': False}


def refusal(error):
    """Exception values never enter reports unless they match a fixed reason."""
    if (type(error) is SessionObservationBlocked and len(error.args) == 1 and
            type(error.args[0]) is str and error.args[0] in _REASONS):
        return {'state': 'incomplete', 'reason': error.args[0], 'cleanupAuthority': False}
    return {'state': 'incomplete', 'reason': 'session_observation_unavailable', 'cleanupAuthority': False}


def snapshot(owner, phase):
    """One stable two-pass snapshot. Metadata only, no signal/cleanup authority."""
    _guard_source()
    if type(owner) is not OwnedSession or owner._issuer is not _ISSUER or phase not in ('before_cleanup', 'after_cleanup'):
        raise SessionObservationBlocked('session_observation_identity_invalid')
    original, process = owner._original, owner._process
    if process.pid != original['pid']:
        raise SessionObservationBlocked('session_owner_changed')

    deadline = time.monotonic() + 5

    def members():
        root = _identity(original['pid'])
        if root is not None and root['birth'] != original['birth']:
            raise SessionObservationBlocked('session_owner_generation_changed')
        result = []
        for pid in _pids():
            if time.monotonic() >= deadline:
                raise SessionObservationBlocked('session_observation_deadline')
            try:
                if os.getsid(pid) != original['sid']:
                    continue
            except ProcessLookupError:
                continue
            except OSError:
                raise SessionObservationBlocked('session_member_visibility_incomplete') from None
            value = _identity(pid)
            if value is None:
                continue
            if value['sid'] != original['sid'] or value['uid'] != original['uid']:
                raise SessionObservationBlocked('session_member_changed')
            result.append(value)
        return result

    first, second = members(), members()
    if first != second:
        raise SessionObservationBlocked('session_membership_changed')
    _guard_source()
    return {'schemaVersion': 1, 'phase': phase, 'observedNs': time.time_ns(),
            'observerSourceSha256': hashlib.sha256(_SOURCE).hexdigest(),
            'original': dict(original), 'members': first, 'visibilityComplete': True,
            'memberAssociation': 'current_kernel_session_membership',
            'memberOwnershipEstablished': False,
            'cleanupAuthority': False, 'sourceAttributionAvailable': False}
