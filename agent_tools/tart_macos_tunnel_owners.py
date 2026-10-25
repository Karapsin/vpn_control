"""GET-only Ventura kernel-control FD holders inside one selected Mac guest.

This identifies current holders, not original creators or absence of historical
FD transfer. Provider purpose/activity still requires independent qualification.
No socket/control connection, ioctl, network settings or signals to another
process exist here. Import opens no frameworks or observes coordinator sockets.

Exact primary ABI: Apple xnu-8792.81.2 bsd/sys/proc_info.h SHA256
c514bb767a149abec1b138da0b425c2944f621996e4ce53cdfbbae2fb8a103a3,
bsd/net/if_utun.h e357bcf6b21ea9e45dce2673e8d35e763e850dd501a5b8e650e14e909a57a8fb.
kern_control.c fills kcsi_name/unit from the connected control; if_utun.c
assigns pcb->utun_unit = sac->sc_unit and interface unit utun_unit-1.
https://github.com/apple-oss-distributions/xnu/blob/xnu-8792.81.2/bsd/sys/proc_info.h
https://github.com/apple-oss-distributions/xnu/blob/xnu-8792.81.2/bsd/kern/kern_control.c
https://github.com/apple-oss-distributions/xnu/blob/xnu-8792.81.2/bsd/net/if_utun.c
"""
from __future__ import annotations

import ctypes as C
import os
from pathlib import Path
import re
import stat
import sys
from uuid import UUID
if os.name == 'posix':
    import pwd
else:
    pwd = None

_EXECUTING_CODE = sys._getframe().f_code
_FILES = ('tart_macos_probe.py', 'tart_macos_idle_collector.py',
          'tart_macos_network_census.py', 'tart_macos_tunnel_owners.py')
_MAX_PROCESSES = 2048
_MAX_FDS = 65536
_MAX_TOTAL_FDS = 262144
_UTUN = re.compile(rb'utun(0|[1-9][0-9]*)\Z')
_CONTROL = b'com.apple.net.utun_control'


class OwnershipUnavailable(ValueError):
    pass


def need(value, reason):
    if not value:raise OwnershipUnavailable(reason)


class _Fd(C.Structure):
    _fields_ = [('number', C.c_int32), ('kind', C.c_uint32)]


def parse_socket(raw):
    """Exact Ventura socket_fdinfo layout; all raw fields remain private."""
    need(type(raw) is bytes and len(raw) == 792, 'macos_socket_abi_unqualified')
    def integer(offset, size, signed=False):
        return int.from_bytes(raw[offset:offset + size], 'little', signed=signed)
    family, kind = integer(184, 4, True), integer(256, 4, True)
    need(0 <= family <= 255 and 0 <= kind <= 7, 'macos_socket_record_invalid')
    socket, pcb = integer(160, 8), integer(168, 8)
    need(socket != 0, 'macos_socket_generation_unavailable')
    if kind != 6:return (socket, pcb, family, kind, None, None, None)
    need(family == 32, 'macos_control_family_invalid') # AF_SYSTEM
    field = raw[288:384];end = field.find(b'\0')
    need(end > 0, 'macos_control_record_invalid')
    name = field[:end] # Never serialize unknown control names or derivatives.
    control_id, unit, state = integer(264, 4), integer(284, 4), integer(192, 2)
    need(control_id > 0, 'macos_control_record_invalid')
    if name == _CONTROL:
        need(0 < unit <= 65536 and state & 2 and not state & (4 | 8),
             'macos_tunnel_control_unstable')
    return (socket, pcb, family, kind, name, unit, state)


class NativeHolders:
    def __init__(self, base, processes):
        need(sys.platform == 'darwin' and sys.byteorder == 'little', 'macos_socket_platform_unqualified')
        self.base, self.processes = base, processes
        base._fn(base.proc, 'proc_pidfdinfo', C.c_int, [C.c_int, C.c_int, C.c_int, C.c_void_p, C.c_int])

    def platform(self):
        buffer = C.create_string_buffer(128);size = C.c_size_t(len(buffer))
        need(self.base.lib.sysctlbyname(b'kern.osrelease', buffer, C.byref(size), None, 0) == 0
             and 1 < size.value <= len(buffer) and re.fullmatch(rb'22\.[0-9]+\.[0-9]+', buffer.value),
             'macos_socket_kernel_abi_unqualified')

    def fds(self, actor):
        need(self.processes.process(actor[0]) == actor, 'macos_fd_owner_changed')
        C.set_errno(0)
        size = self.base.proc.proc_pidinfo(actor[0], 1, 0, None, 0) # PROC_PIDLISTFDS
        need(0 <= size <= _MAX_FDS * C.sizeof(_Fd) and size % C.sizeof(_Fd) == 0
             and (size != 0 or C.get_errno() == 0), 'macos_fd_visibility_unavailable')
        capacity = min(size // C.sizeof(_Fd) + 64, _MAX_FDS + 1)
        buffer = (_Fd * capacity)();C.set_errno(0)
        count = self.base.proc.proc_pidinfo(actor[0], 1, 0, buffer, C.sizeof(buffer))
        need(0 <= count < C.sizeof(buffer) and count % C.sizeof(_Fd) == 0
             and (count != 0 or C.get_errno() == 0), 'macos_fd_visibility_unavailable')
        rows = tuple(sorted((row.number, row.kind) for row in buffer[:count // C.sizeof(_Fd)]))
        need(len({number for number, _ in rows}) == len(rows)
             and all(number >= 0 and 0 <= kind <= 16 for number, kind in rows), 'macos_fd_record_invalid')
        need(self.processes.process(actor[0]) == actor, 'macos_fd_owner_changed')
        return rows

    def socket(self, actor, fd):
        need(self.processes.process(actor[0]) == actor, 'macos_fd_owner_changed')
        buffer = C.create_string_buffer(792)
        need(self.base.proc.proc_pidfdinfo(actor[0], fd, 3, buffer, len(buffer)) == len(buffer),
             'macos_socket_visibility_unavailable') # PROC_PIDFDSOCKETINFO
        result = parse_socket(buffer.raw)
        need(self.processes.process(actor[0]) == actor, 'macos_fd_owner_changed')
        return result

    def actor(self, actor):
        before = self.fds(actor)
        first = {number: self.socket(actor, number) for number, kind in before if kind == 2}
        after = self.fds(actor)
        need(before == after, 'macos_fd_table_changed')
        second = {number: self.socket(actor, number) for number, kind in after if kind == 2}
        need(first == second, 'macos_socket_generation_changed')
        need(self.processes.process(actor[0]) == actor, 'macos_fd_owner_changed')
        return len(before), first


def join(interfaces, holders):
    """Correlate exact kernel unit mapping, never turn a holder into idle proof."""
    active = {name for name, flags, _, _ in interfaces if _UTUN.fullmatch(name) and flags & 0x41}
    controls = {};tokens = {};blockers = set();reports = []
    for actor, sockets in holders:
        for fd, value in sockets.items():
            socket, pcb, family, kind, control, unit, state = value
            if control != _CONTROL:continue
            interface = b'utun' + str(unit - 1).encode('ascii')
            controls.setdefault(interface, []).append((actor, fd))
            tokens.setdefault((socket, pcb), []).append((actor, fd))
    if any(len(rows) != 1 for rows in controls.values()):blockers.add('duplicate_or_shared_tunnel_holder')
    if any(len(rows) != 1 for rows in tokens.values()):blockers.add('duplicate_or_shared_socket_generation')
    for name in active:
        rows = controls.get(name, [])
        if len(rows) != 1:blockers.add('active_tunnel_holder_unresolved')
    if set(controls) - active:blockers.add('control_interface_state_unjoined')
    counts = {}
    for name in active:
        rows = controls.get(name, [])
        if len(rows) == 1:counts[rows[0][0]] = counts.get(rows[0][0], 0) + 1
    for actor, count in sorted(counts.items()):
        reports.append({'pid': actor[0], 'uid': actor[1], 'ppid': actor[2],
                        'birth': f'darwin:{actor[3]}:{actor[4]}', 'matchedTunnelCount': count})
    return {'activeUtunCount': len(active), 'currentHolderVisibilityComplete': not blockers,
            'holders': reports, 'blockers': sorted(blockers),
            'ownershipScope': 'current_fd_holders_only', 'creatorAndTransferVisibility': 'unavailable',
            'providerActivityQualified': False}


def _inputs(machine, boot, uid, principal, agent):
    try:valid = type(machine) is str and str(UUID(machine)) == machine and type(boot) is str and str(UUID(boot)) == boot
    except (ValueError, TypeError, AttributeError):valid = False
    need(valid and type(uid) is int and uid >= 501 and type(principal) is str and principal
         and type(agent) is tuple and len(agent) == 5 and all(type(item) is int for item in agent)
         and agent[0] > 0 and agent[1] == uid and agent[2] == 1 and agent[3] > 0 and 0 <= agent[4] < 1000000,
         'macos_tunnel_target_invalid')


def collect(base, processes, network, native, *, machine, boot, uid, principal, agent):
    _inputs(machine, boot, uid, principal, agent)
    def target():
        need(pwd is not None and os.geteuid() == uid and pwd.getpwuid(uid).pw_name == principal,
             'macos_tunnel_account_changed')
        need(base.machine() == machine and base.boot()[0] == boot and processes.process(os.getppid()) == agent,
             'macos_tunnel_target_changed')
    target();native.platform();interfaces = network.interfaces();first = processes.snapshot()
    need(type(first) is dict and 0 < len(first) <= _MAX_PROCESSES, 'macos_tunnel_process_visibility_unavailable')
    holders = [];unavailable = [];total = 0
    for actor, _ in first.values():
        try:
            count, sockets = native.actor(actor);total += count
            need(total <= _MAX_TOTAL_FDS, 'macos_tunnel_fd_overflow')
            holders.append((actor, sockets))
        except OwnershipUnavailable as error:
            # Exact reason allowlist below; never render arbitrary exceptions.
            reason = error.args[0] if len(error.args) == 1 else None
            if reason not in {'macos_fd_owner_changed', 'macos_fd_visibility_unavailable', 'macos_fd_record_invalid',
                    'macos_socket_visibility_unavailable', 'macos_socket_abi_unqualified', 'macos_socket_record_invalid',
                    'macos_socket_generation_unavailable', 'macos_control_family_invalid', 'macos_control_record_invalid',
                    'macos_tunnel_control_unstable', 'macos_fd_table_changed', 'macos_socket_generation_changed'}:
                raise OwnershipUnavailable('macos_tunnel_owner_evidence_unavailable') from None
            unavailable.append({'pid': actor[0], 'uid': actor[1], 'birth': f'darwin:{actor[3]}:{actor[4]}', 'reason': reason})
    target();need(first == processes.snapshot() and interfaces == network.interfaces(), 'macos_tunnel_snapshot_changed')
    result = join(interfaces, holders)
    if unavailable:
        result['currentHolderVisibilityComplete'] = False
        result['blockers'] = sorted(set(result['blockers']) | {'process_fd_visibility_incomplete'})
    result['unavailableActors'] = unavailable
    return {'schemaVersion': 1, 'state': 'diagnostic', 'machine': machine, 'boot': boot, 'uid': uid,
            'nativeQualified': False, 'idleAuthority': False, 'tunnelOwners': result}


def source(*, machine, boot, uid, principal, agent):
    _inputs(machine, boot, uid, principal, agent)
    need(os.name == 'posix' and hasattr(os, 'O_NOFOLLOW'), 'macos_tunnel_source_unavailable')
    captured = {}
    for name in _FILES:
        path = Path(__file__).with_name(name);fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            before = os.fstat(fd);need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= 262144,
                                      'macos_tunnel_source_unavailable')
            raw = os.read(fd, before.st_size + 1);after = os.fstat(fd)
            fields = ('st_dev','st_ino','st_mode','st_nlink','st_uid','st_gid','st_size','st_mtime_ns','st_ctime_ns')
            need(len(raw) == before.st_size and all(getattr(before, key) == getattr(after, key) for key in fields),
                 'macos_tunnel_source_changed');captured[name] = raw
        finally:os.close(fd)
    need(_EXECUTING_CODE == compile(captured[_FILES[-1]], __file__, 'exec', dont_inherit=True), 'macos_tunnel_source_changed')
    config = dict(machine=machine, boot=boot, uid=uid, principal=principal, agent=agent)
    text = 'import json,sys,types\n_modules=[]\n'
    for name in _FILES:
        text += '_m=types.ModuleType(' + repr('_fixed_tunnel_' + name[:-3]) + ');sys.modules[_m.__name__]=_m\n'
        text += 'exec(compile(' + repr(captured[name]) + ',' + repr('<fixed-' + name + '>') + ',"exec"),_m.__dict__)\n_modules.append(_m)\n'
    text += ('_modules[1].__dict__["__bsd_class__"]=_modules[0]._Bsd\n'
        'try:\n'
        ' _modules[3].need(sys.platform=="darwin" and len(sys.argv)==1,"macos_tunnel_guest_required")\n'
        ' import signal;signal.signal(signal.SIGALRM,signal.SIG_DFL);signal.alarm(60)\n'
        ' _base=_modules[0].Native();_processes=_modules[1].Native(_base)\n'
        ' _network=_modules[2].NativeNetwork(_base);_native=_modules[3].NativeHolders(_base,_processes)\n'
        ' _result=_modules[3].collect(_base,_processes,_network,_native,**' + repr(config) + ')\n'
        'except Exception:\n _result={"state":"blocked","reason":"macos_tunnel_owners_unavailable"}\n'
        'if len(json.dumps(_result).encode("utf-8"))>2097152:_result={"state":"blocked","reason":"macos_tunnel_owners_overflow"}\n'
        'print(json.dumps(_result,sort_keys=True))\nraise SystemExit(0 if _result.get("state")=="diagnostic" else 3)\n')
    need(len(text) <= 262144, 'macos_tunnel_source_overflow');return text.encode('utf-8')
