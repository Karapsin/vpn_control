"""Source-owned zero-argument ROOT guest diagnostic, not idle authority.

Installation must capture this file and tart_macos_probe.py into one fixed helper
with diagnostic_source(). Importing either file performs no native observation.
The helper has no argument/stdin/command/path API, changes no settings, and emits
no unexpected executable path, argv, signing identifier, digest or exception.

Apple primary interfaces:
https://github.com/apple-oss-distributions/xnu/blob/main/libsyscall/wrappers/libproc/libproc.h
https://developer.apple.com/documentation/security/seccodecheckvalidity(_:_:_:)
https://developer.apple.com/documentation/security/secstaticcodecheckvalidity(_:_:_:)
https://developer.apple.com/documentation/security/seccodecopyguestwithattributes(_:_:_:_:)

Apple validation is provenance only. No signature, parent PID, waiting process,
zero CPU observation or familiar launchd label establishes absence of queued work.
Loaded service, sealed-volume and installer activity collectors are still needed.
"""
from __future__ import annotations

import ctypes as C
import json
import os
from pathlib import Path
import re
import stat
import sys
from uuid import UUID

_EXECUTING_CODE = sys._getframe().f_code
_MAX_PROCESSES = 65535
_CODE = frozenset({'apple_valid', 'not_apple_valid', 'identity_changed', 'unavailable'})
_ACTIVITY = frozenset({'tracked_clean_idle_exit', 'tracked_clean', 'tracked_dirty',
                       'launch_in_progress', 'untracked', 'unavailable', 'identity_changed'})
_PROTECTED = re.compile(r'(sing.?box|vpn.?control|openvpn|wireguard|tailscaled|zerotier|charon|strongswan|pppd)', re.I)
_INSTALLER = re.compile(r'^(installer|installd|system_installd|softwareupdated|softwareupdate|osinstallersetupd|osinstaller|startosinstall|installassistant|packagekit)$', re.I)


class CensusUnavailable(ValueError):
    """Finite reason only."""


def _need(value, reason):
    if not value:
        raise CensusUnavailable(reason)


def _identity(machine, uid):
    try:
        _need(type(machine) is str and str(UUID(machine)) == machine,
              'macos_census_target_invalid')
    except (ValueError, TypeError, AttributeError):
        raise CensusUnavailable('macos_census_target_invalid') from None
    _need(type(uid) is int and 501 <= uid < 2**32-1, 'macos_census_account_invalid')


def dirty_posture(flags):
    """Interpret proc_get_dirty GET flags, never enable/clear tracking.

    A zero flag is UNTRACKED, not clean. Even tracked clean idle-exit state
    authenticates only a kernel observation; source/service custody is separate.
    """
    if type(flags) is not int or flags < 0 or flags & ~15:
        return 'unavailable'
    if not flags & 1:
        return 'untracked' if flags == 0 else 'unavailable'
    if flags & 8: return 'launch_in_progress'
    if flags & 4: return 'tracked_dirty'
    return 'tracked_clean_idle_exit' if flags & 2 else 'tracked_clean'


class Native:
    """Read-only libproc + Security getters. Opened only after target admission."""
    def __init__(self, probe):
        self.base = probe
        self.cf = probe.cf
        self.security = C.CDLL('/System/Library/Frameworks/Security.framework/Security')
        fn = probe._fn
        fn(probe.proc, 'proc_get_dirty', C.c_int, [C.c_int, C.POINTER(C.c_uint32)])
        fn(self.cf, 'CFNumberCreate', C.c_void_p, [C.c_void_p, C.c_long, C.c_void_p])
        fn(self.cf, 'CFDictionaryCreate', C.c_void_p,
           [C.c_void_p, C.POINTER(C.c_void_p), C.POINTER(C.c_void_p), C.c_long, C.c_void_p, C.c_void_p])
        fn(self.security, 'SecRequirementCreateWithString', C.c_int32,
           [C.c_void_p, C.c_uint32, C.POINTER(C.c_void_p)])
        fn(self.security, 'SecCodeCopyGuestWithAttributes', C.c_int32,
           [C.c_void_p, C.c_void_p, C.c_uint32, C.POINTER(C.c_void_p)])
        fn(self.security, 'SecCodeCheckValidity', C.c_int32, [C.c_void_p, C.c_uint32, C.c_void_p])
        fn(self.security, 'SecCodeCopyStaticCode', C.c_int32,
           [C.c_void_p, C.c_uint32, C.POINTER(C.c_void_p)])
        fn(self.security, 'SecStaticCodeCheckValidity', C.c_int32,
           [C.c_void_p, C.c_uint32, C.c_void_p])

    def process(self, pid):
        # Use the exact primary-header struct already captured with the probe.
        bsd_class = globals().get('__bsd_class__')
        if bsd_class is None:
            from .tart_macos_probe import _Bsd as bsd_class
        info = bsd_class()
        _need(self.base.proc.proc_pidinfo(pid, 3, 0, C.byref(info), C.sizeof(info)) == C.sizeof(info)
              and info.pid == pid and info.start_seconds > 0 and info.start_microseconds < 1000000,
              'macos_census_process_unavailable')
        return (int(info.pid), int(info.uid), int(info.ppid),
                int(info.start_seconds), int(info.start_microseconds))

    def snapshot(self):
        total = self.base.proc.proc_listallpids(None, 0)
        _need(0 < total < _MAX_PROCESSES, 'macos_census_process_unavailable')
        capacity = min(total + 256, _MAX_PROCESSES + 1)
        buffer = (C.c_int * capacity)()
        count = self.base.proc.proc_listallpids(buffer, C.sizeof(buffer))
        _need(0 < count < capacity, 'macos_census_process_unavailable')
        result = {}
        for pid in buffer[:count]:
            if pid == 0:
                continue  # kernel_task has no user-process executable.
            _need(pid > 0 and pid not in result, 'macos_census_process_unavailable')
            actor = self.process(pid)
            path = C.create_string_buffer(4096)
            size = self.base.proc.proc_pidpath(pid, path, len(path))
            _need(0 < size < len(path), 'macos_census_process_unavailable')
            # Private memory only. Do not return path, hash, length or argv.
            actual = path.value.decode('utf-8', 'strict')
            _need(actual.startswith('/'), 'macos_census_process_unavailable')
            role = ('protected_runtime' if _PROTECTED.search(actual) else
                    'installer' if _INSTALLER.fullmatch(actual.rsplit('/', 1)[-1]) else 'unmanaged')
            _need(self.process(pid) == actor, 'macos_census_process_changed')
            result[pid] = (actor, role)
        return result

    def activity(self, actor):
        if self.process(actor[0]) != actor:
            return 'identity_changed'
        flags = C.c_uint32()
        if self.base.proc.proc_get_dirty(actor[0], C.byref(flags)) != 0:
            return 'unavailable'
        return dirty_posture(flags.value) if self.process(actor[0]) == actor else 'identity_changed'

    def code(self, actor):
        pid = actor[0]
        _need(self.process(pid) == actor, 'macos_census_process_changed')
        number = dictionary = text = None
        requirement = C.c_void_p(); dynamic = C.c_void_p(); static_code = C.c_void_p()
        result = 'unavailable'
        try:
            number_value = C.c_int32(pid)
            number = self.cf.CFNumberCreate(None, 3, C.byref(number_value))  # kCFNumberSInt32Type
            key = C.c_void_p.in_dll(self.security, 'kSecGuestAttributePid').value
            keys = (C.c_void_p * 1)(key); values = (C.c_void_p * 1)(number)
            key_callbacks = C.addressof(C.c_byte.in_dll(self.cf, 'kCFTypeDictionaryKeyCallBacks'))
            value_callbacks = C.addressof(C.c_byte.in_dll(self.cf, 'kCFTypeDictionaryValueCallBacks'))
            _need(number and key, 'macos_census_code_unavailable')
            dictionary = self.cf.CFDictionaryCreate(None, keys, values, 1, key_callbacks, value_callbacks)
            text = self.cf.CFStringCreateWithCString(None, b'anchor apple', 0x08000100)
            _need(dictionary and text, 'macos_census_code_unavailable')
            if self.security.SecRequirementCreateWithString(text, 0, C.byref(requirement)) != 0:
                return 'unavailable'
            if self.security.SecCodeCopyGuestWithAttributes(None, dictionary, 0, C.byref(dynamic)) != 0:
                return 'unavailable'
            if not requirement.value or not dynamic.value:
                return 'unavailable'
            if self.security.SecCodeCheckValidity(dynamic, 0, requirement) != 0:
                result = 'not_apple_valid'
            elif self.security.SecCodeCopyStaticCode(dynamic, 0, C.byref(static_code)) != 0 or not static_code.value:
                result = 'unavailable'
            elif self.security.SecStaticCodeCheckValidity(static_code, 1, requirement) != 0:
                result = 'not_apple_valid'  # kSecCSCheckAllArchitectures = 1 << 0
            else:
                result = 'apple_valid'
        finally:
            for ref in (static_code.value, dynamic.value, requirement.value, text, dictionary, number):
                if ref:
                    self.cf.CFRelease(ref)
        return result if self.process(pid) == actor else 'identity_changed'


def _sample(native, observer):
    rows = []
    snapshot = native.snapshot()
    _need(type(snapshot) is dict and 0 < len(snapshot) <= _MAX_PROCESSES,
          'macos_census_process_unavailable')
    for pid, (actor, role) in sorted(snapshot.items()):
        _need(type(actor) is tuple and len(actor) == 5 and all(type(v) is int for v in actor)
              and actor[0] == pid and pid > 0 and actor[1] >= 0 and actor[2] >= 0
              and actor[3] > 0 and 0 <= actor[4] < 1000000
              and role in {'protected_runtime', 'installer', 'unmanaged'},
              'macos_census_process_unavailable')
        code = native.code(actor)
        _need(type(code) is str and code in _CODE, 'macos_census_code_unavailable')
        activity = native.activity(actor)
        _need(type(activity) is str and activity in _ACTIVITY, 'macos_census_activity_unavailable')
        rows.append({'pid': pid, 'uid': actor[1], 'ppid': actor[2],
                     'birth': f'darwin:{actor[3]}:{actor[4]}', 'code': code, 'activity': activity,
                     'role': 'verified_probe' if pid == observer else role})
    _need(sum(row['pid'] == observer and row['uid'] == 0 for row in rows) == 1,
          'macos_census_observer_changed')
    return rows


def _collect(base, native, machine, uid, observer):
    """Internal controlled-getter seam; no caller-supplied success flags."""
    _identity(machine, uid)
    _need(base.machine() == machine, 'macos_census_target_changed')
    boot, boot_time = base.boot()
    first = _sample(native, observer)
    second = _sample(native, observer)
    _need(base.machine() == machine and base.boot() == (boot, boot_time), 'macos_census_target_changed')
    complete = first == second and all(row['code'] != 'identity_changed' and row['activity'] != 'identity_changed' for row in first)
    return {'schemaVersion': 1, 'machine': machine, 'boot': boot, 'ordinaryUid': uid,
            'observerUid': 0, 'first': first, 'second': second, 'processIdentityComplete': complete,
            'nativeQualified': False, 'nativeIdle': False,
            'missingEvidence': ['loaded_service_custody', 'sealed_system_volume',
                                'installer_and_update_activity', 'durable_namespaces',
                                'host_reservations_lifecycle_operators']}


def collect(machine, uid):
    _identity(machine, uid)
    _need(sys.platform == 'darwin' and os.geteuid() == 0, 'macos_census_guest_root_required')
    probe_class = globals().get('__probe_class__')
    if probe_class is None:
        from .tart_macos_probe import Native as probe_class
    base = probe_class()
    _need(base.machine() == machine, 'macos_census_target_changed')
    return _collect(base, Native(base), machine, uid, os.getpid())


def main():
    try:
        _need(len(sys.argv) == 1, 'macos_census_arguments_forbidden')
        value = collect(globals().get('__expected_machine__'), globals().get('__expected_uid__'))
    except (CensusUnavailable, OSError, ValueError, TypeError, UnicodeError, AttributeError):
        # No native exception text, PID/path/argv values or derived data escapes.
        value = {'state': 'blocked', 'reason': 'macos_census_unavailable'}
        print(json.dumps(value, sort_keys=True)); return 3
    output = json.dumps(value, sort_keys=True)
    if len(output.encode('utf-8')) > 2 * 1024 * 1024:
        print('{"reason":"macos_census_overflow","state":"blocked"}'); return 3
    print(output); return 0


def diagnostic_source(machine, uid):
    """Capture fixed known files for installer review; does not execute a getter.

    The installed helper must be root-owned, immutable to ordinary users and
    admitted by source custody. No default target and no CLI target override.
    """
    _identity(machine, uid)
    def read(name):
        path = Path(__file__).with_name(name)
        fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
        try:
            before = os.fstat(fd)
            _need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= 262144,
                  'macos_census_source_unavailable')
            value = os.read(fd, before.st_size + 1)
            _need(len(value) == before.st_size and os.fstat(fd) == before,
                  'macos_census_source_changed')
            return value.decode('utf-8', 'strict')
        finally:
            os.close(fd)
    probe = read('tart_macos_probe.py'); own = read('tart_macos_idle_collector.py')
    _need(_EXECUTING_CODE == compile(own, str(Path(__file__)), 'exec', dont_inherit=True),
          'macos_census_source_changed')
    # Both namespaces keep __main__ dormant. The fixed entrypoint alone runs.
    return ('import sys\n'
            + '_probe={"__name__":"_fixed_guest_probe"}\n'
            + 'exec(compile(' + repr(probe) + ',"<fixed-macos-probe>","exec"),_probe)\n'
            + '_census={"__name__":"_fixed_guest_census","__probe_class__":_probe["Native"],'
            + '"__bsd_class__":_probe["_Bsd"],"__expected_machine__":' + repr(machine)
            + ',"__expected_uid__":' + repr(uid) + '}\n'
            + 'exec(compile(' + repr(own) + ',"<fixed-macos-census>","exec"),_census)\n'
            + 'raise SystemExit(_census["main"]())\n').encode('utf-8')


if __name__ == '__main__':
    raise SystemExit(main())
