"""Fixed GET-only protected-network evidence inside the selected Mac guest.

Importing this module opens no framework and observes no coordinator network.
Service identifiers, interface names, addresses and configuration stay private
memory. This component supplies evidence, not lifecycle or idle authority.

Apple primary declarations: ifaddrs.h, net/if.h, net/if_dl.h, net/if_types.h,
SCPreferences.h, SCNetworkConfiguration.h and SCNetworkConnection.h. The last
API is applied only to PPP services. NETunnelProviderManager preferences are
app-scoped and deliberately supply no all-guest absence claim here.
https://developer.apple.com/documentation/systemconfiguration/scnetworkconnectiongetstatus(_:)
https://developer.apple.com/documentation/networkextension/netunnelprovidermanager/loadallfrompreferences(completionhandler:)
"""
from __future__ import annotations

import ctypes as C
import os
from pathlib import Path
import re
import stat
import sys
import uuid
if os.name == 'posix':
    import pwd
else:
    pwd = None

_EXECUTING_CODE = sys._getframe().f_code
_MAX = 4096


class NetworkUnavailable(ValueError):
    """Finite reason only; never attach a native value or exception."""


def need(value, reason):
    if not value:raise NetworkUnavailable(reason)


class _Sockaddr(C.Structure):
    _fields_ = [('length', C.c_ubyte), ('family', C.c_ubyte)]


class _Ifaddrs(C.Structure):
    pass


_Ifaddrs._fields_ = [('next', C.POINTER(_Ifaddrs)), ('name', C.c_char_p),
    ('flags', C.c_uint), ('address', C.POINTER(_Sockaddr)),
    ('netmask', C.c_void_p), ('destination', C.c_void_p), ('data', C.c_void_p)]


def _generation(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_uid,
            info.st_gid, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


class NativeNetwork:
    """Only fixed native read entrypoints; initialized by a guest-only caller."""
    def __init__(self, base):
        need(sys.platform == 'darwin', 'macos_network_guest_required')
        self.base = base
        fn = base._fn
        fn(base.lib, 'getifaddrs', C.c_int, [C.POINTER(C.POINTER(_Ifaddrs))])
        fn(base.lib, 'freeifaddrs', None, [C.POINTER(_Ifaddrs)])
        fn(base.cf, 'CFRetain', C.c_void_p, [C.c_void_p])
        fn(base.cf, 'CFGetTypeID', C.c_ulong, [C.c_void_p])
        fn(base.cf, 'CFArrayGetTypeID', C.c_ulong, [])
        fn(base.cf, 'CFArrayGetCount', C.c_long, [C.c_void_p])
        fn(base.cf, 'CFArrayGetValueAtIndex', C.c_void_p, [C.c_void_p, C.c_long])
        for name, result, args in (
            ('SCPreferencesCreate', C.c_void_p, [C.c_void_p, C.c_void_p, C.c_void_p]),
            ('SCNetworkServiceCopyAll', C.c_void_p, [C.c_void_p]),
            ('SCNetworkServiceGetTypeID', C.c_ulong, []),
            ('SCNetworkServiceGetServiceID', C.c_void_p, [C.c_void_p]),
            ('SCNetworkServiceGetInterface', C.c_void_p, [C.c_void_p]),
            ('SCNetworkServiceGetEnabled', C.c_ubyte, [C.c_void_p]),
            ('SCNetworkInterfaceGetTypeID', C.c_ulong, []),
            ('SCNetworkInterfaceGetInterfaceType', C.c_void_p, [C.c_void_p]),
            ('SCNetworkInterfaceGetBSDName', C.c_void_p, [C.c_void_p]),
            ('SCNetworkInterfaceGetInterface', C.c_void_p, [C.c_void_p]),
            ('SCNetworkConnectionCreateWithServiceID', C.c_void_p,
             [C.c_void_p, C.c_void_p, C.c_void_p, C.c_void_p]),
            ('SCNetworkConnectionGetStatus', C.c_int32, [C.c_void_p]),
        ):
            fn(base.sc, name, result, args)

    def interfaces(self):
        """Complete bounded linked list; names and addresses never escape."""
        head = C.POINTER(_Ifaddrs)()
        rows = {};seen = set()
        try:
            need(self.base.lib.getifaddrs(C.byref(head)) == 0 and bool(head),
                 'macos_network_interfaces_unavailable')
            node = head
            while node:
                address = C.addressof(node.contents)
                need(address not in seen and len(seen) < _MAX,
                     'macos_network_interfaces_invalid')
                seen.add(address);row = node.contents
                name = row.name
                need(type(name) is bytes and 0 < len(name) <= 15
                     and all(32 < item < 127 for item in name),
                     'macos_network_interfaces_invalid')
                item = rows.setdefault(name, [int(row.flags), None, set()])
                need(item[0] == row.flags, 'macos_network_interfaces_changed')
                if row.address:
                    header = row.address.contents
                    need(header.length >= 2, 'macos_network_interfaces_invalid')
                    item[2].add(int(header.family))
                    if header.family == 18: # AF_LINK; sockaddr_dl fixed prefix
                        need(header.length >= 8, 'macos_network_interfaces_invalid')
                        link = C.string_at(row.address, 8)
                        need(link[5] == len(name) and header.length >= 8 + len(name),
                             'macos_network_interfaces_invalid')
                        need(item[1] is None or item[1] == link[4],
                             'macos_network_interfaces_changed')
                        item[1] = int(link[4])
                node = row.next
            need(rows and all(item[1] is not None for item in rows.values()),
                 'macos_network_link_visibility_unavailable')
            return tuple(sorted((name, flags, kind, tuple(sorted(families)))
                for name, (flags, kind, families) in rows.items()))
        finally:
            if head:self.base.lib.freeifaddrs(head)

    def _text(self, borrowed, *, optional=False):
        if not borrowed and optional:return None
        need(borrowed, 'macos_network_service_invalid')
        value = self.base.value(self.base.cf.CFRetain(borrowed))
        need(type(value) is str and 0 < len(value) <= 512,
             'macos_network_service_invalid')
        return value

    def services(self):
        """Public SC service graph; callbacks, credentials and writes absent."""
        name = self.base.cf.CFStringCreateWithCString(None, b'vpn-control-readonly-network-census', 0x08000100)
        need(name, 'macos_network_services_unavailable')
        preferences = array = None
        try:
            preferences = self.base.sc.SCPreferencesCreate(None, name, None)
            need(preferences, 'macos_network_services_unavailable')
            array = self.base.sc.SCNetworkServiceCopyAll(preferences)
            need(array and self.base.cf.CFGetTypeID(array) == self.base.cf.CFArrayGetTypeID(),
                 'macos_network_services_unavailable')
            count = self.base.cf.CFArrayGetCount(array)
            need(0 <= count <= _MAX, 'macos_network_services_invalid')
            rows = [];identities = set()
            for index in range(count):
                service = self.base.cf.CFArrayGetValueAtIndex(array, index)
                need(service and self.base.cf.CFGetTypeID(service) == self.base.sc.SCNetworkServiceGetTypeID(),
                     'macos_network_service_invalid')
                identity_ref = self.base.sc.SCNetworkServiceGetServiceID(service)
                identity = self._text(identity_ref)
                need(identity not in identities, 'macos_network_services_invalid')
                identities.add(identity)
                enabled = self.base.sc.SCNetworkServiceGetEnabled(service)
                need(enabled in (0, 1), 'macos_network_service_invalid')
                stack = [];seen = set();interface = self.base.sc.SCNetworkServiceGetInterface(service)
                while interface:
                    need(interface not in seen and len(seen) < 16
                         and self.base.cf.CFGetTypeID(interface) == self.base.sc.SCNetworkInterfaceGetTypeID(),
                         'macos_network_service_invalid')
                    seen.add(interface)
                    kind = self._text(self.base.sc.SCNetworkInterfaceGetInterfaceType(interface))
                    bsd = self._text(self.base.sc.SCNetworkInterfaceGetBSDName(interface), optional=True)
                    stack.append((kind, bsd))
                    interface = self.base.sc.SCNetworkInterfaceGetInterface(interface)
                need(stack, 'macos_network_service_invalid')
                status = None
                if any(kind == 'PPP' for kind, _ in stack):
                    connection = self.base.sc.SCNetworkConnectionCreateWithServiceID(None, identity_ref, None, None)
                    need(connection, 'macos_network_connection_unavailable')
                    try:status = self.base.sc.SCNetworkConnectionGetStatus(connection)
                    finally:self.base.cf.CFRelease(connection)
                    need(status in {-1, 0, 1, 2, 3}, 'macos_network_connection_invalid')
                rows.append((identity, bool(enabled), tuple(stack), status))
            return tuple(sorted(rows))
        finally:
            if array:self.base.cf.CFRelease(array)
            if preferences:self.base.cf.CFRelease(preferences)
            self.base.cf.CFRelease(name)

    def snapshot(self):
        return self.interfaces(), self.services()


_PHYSICAL_SERVICE_TYPES = frozenset({'Ethernet', 'IEEE80211', 'FireWire', 'Bluetooth',
    'BluetoothPAN', 'VLAN', 'Bond', 'Bridge', 'Loopback'})
_TUNNEL_TYPES = frozenset({0x17, 0x1c, 0x37, 0x38, 0x39, 0xf4})
_NON_TUNNEL_LINK_TYPES = frozenset({0x6, 0x18, 0x87, 0x88, 0x90, 0xd1})
_TUNNEL_NAME = re.compile(rb'(?:utun|tun|tap|ppp|ipsec|gif|stf)\d+\Z')


def review(first, second):
    """Evidence is complete only for two equal full native snapshots.

    No interface name, service ID, address, subtype or unknown string is emitted.
    A clear result is a network component fact; whole-process/provider visibility
    must independently exclude protected runtimes before any idle admission.
    """
    need(type(first) is tuple and len(first) == 2 and type(second) is tuple and len(second) == 2,
         'macos_network_snapshot_invalid')
    need(first == second, 'macos_network_snapshot_changed')
    interfaces, services = first
    need(type(interfaces) is tuple and 0 < len(interfaces) <= _MAX
         and type(services) is tuple and len(services) <= _MAX,
         'macos_network_snapshot_invalid')
    reasons = set();tunnels = ppp = active = unsupported = 0
    active_tunnels = addressed_tunnels = inactive_tunnels = unknown_links = 0
    names = set()
    for row in interfaces:
        need(type(row) is tuple and len(row) == 4, 'macos_network_snapshot_invalid')
        name, flags, kind, families = row
        need(type(name) is bytes and 0 < len(name) <= 15 and name not in names
             and type(flags) is int and 0 <= flags <= 0xffffffff and type(kind) is int and 0 <= kind <= 255
             and type(families) is tuple and all(type(value) is int and 0 <= value <= 255 for value in families),
             'macos_network_snapshot_invalid')
        names.add(name)
        if kind in _TUNNEL_TYPES or flags & 0x10 or _TUNNEL_NAME.fullmatch(name):
            tunnels += 1;reasons.add('kernel_tunnel_activity_unqualified')
            # Finite GET facts only. Even a down, unaddressed tunnel retains
            # its blocker until that exact kernel role is natively qualified.
            allocated = bool(flags & 0x41) # IFF_UP | IFF_RUNNING
            addressed = any(family in {2, 30} for family in families) # AF_INET | AF_INET6
            active_tunnels += int(allocated);addressed_tunnels += int(addressed)
            inactive_tunnels += int(not allocated and not addressed)
        elif kind not in _NON_TUNNEL_LINK_TYPES:
            unknown_links += 1;reasons.add('kernel_interface_role_unqualified')
    seen = set()
    for row in services:
        need(type(row) is tuple and len(row) == 4, 'macos_network_snapshot_invalid')
        identity, enabled, stack, status = row
        need(type(identity) is str and identity and identity not in seen and type(enabled) is bool
             and type(stack) is tuple and 0 < len(stack) <= 16
             and all(type(value) is tuple and len(value) == 2 and type(value[0]) is str
                 and (value[1] is None or type(value[1]) is str) for value in stack),
             'macos_network_snapshot_invalid')
        seen.add(identity)
        kinds = [kind for kind, _ in stack]
        need(all(type(kind) is str for kind in kinds), 'macos_network_snapshot_invalid')
        if 'PPP' in kinds:
            ppp += 1
            need(type(status) is int and status in {-1, 0, 1, 2, 3}, 'macos_network_snapshot_invalid')
            if status == -1:reasons.add('sc_connection_status_unavailable')
            elif status != 0:
                active += 1;reasons.add('sc_connection_active')
        elif any(kind not in _PHYSICAL_SERVICE_TYPES for kind in kinds):
            unsupported += 1;reasons.add('sc_provider_activity_unqualified')
        else:
            need(status is None, 'macos_network_snapshot_invalid')
    return {'visibilityComplete': True, 'activityClear': not reasons,
            'interfaceCount': len(interfaces), 'tunnelCount': tunnels,
            'activeKernelTunnelCount': active_tunnels, 'addressedKernelTunnelCount': addressed_tunnels,
            'downUnaddressedKernelTunnelCount': inactive_tunnels, 'unknownKernelLinkCount': unknown_links,
            'serviceCount': len(services), 'pppServiceCount': ppp,
            'activeConnectionCount': active, 'unsupportedProviderCount': unsupported,
            'blockers': sorted(reasons)}


def collect(base, native, *, machine, boot, uid, principal):
    need(type(machine) is str and str(uuid.UUID(machine)) == machine
         and type(boot) is str and str(uuid.UUID(boot)) == boot
         and type(uid) is int and uid >= 501 and type(principal) is str and principal,
         'macos_network_target_invalid')
    def target():
        need(pwd is not None and os.geteuid() == uid and pwd.getpwuid(uid).pw_name == principal,
             'macos_network_account_changed')
        need(base.machine() == machine and base.boot()[0] == boot, 'macos_network_target_changed')
    target();first = native.snapshot();target();second = native.snapshot();target()
    return {'schemaVersion': 1, 'state': 'diagnostic', 'machine': machine, 'boot': boot, 'uid': uid,
            'nativeQualified': False, 'idleAuthority': False, 'network': review(first, second)}


def diagnostic_source(*, machine, boot, uid, principal):
    """Fixed ordinary guest GET packet; no arbitrary command/source API."""
    need(os.name == 'posix' and hasattr(os, 'O_NOFOLLOW'), 'macos_network_source_unavailable')
    need(type(machine) is str and str(uuid.UUID(machine)) == machine
         and type(boot) is str and str(uuid.UUID(boot)) == boot
         and type(uid) is int and uid >= 501 and type(principal) is str and principal,
         'macos_network_target_invalid')
    captured = {}
    for name in ('tart_macos_probe.py', 'tart_macos_network_census.py'):
        path = Path(__file__).with_name(name);fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            before = os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= 262144,
                 'macos_network_source_unavailable')
            raw = os.read(fd, before.st_size + 1)
            need(len(raw) == before.st_size and _generation(os.fstat(fd)) == _generation(before),
                 'macos_network_source_changed')
            captured[name] = raw.decode('utf-8', 'strict')
        finally:os.close(fd)
    need(_EXECUTING_CODE == compile(captured['tart_macos_network_census.py'], str(Path(__file__)), 'exec', dont_inherit=True),
         'macos_network_source_changed')
    config = {'machine': machine, 'boot': boot, 'uid': uid, 'principal': principal}
    return ('import json,sys,types\n'
        '_probe=types.ModuleType("_network_fixed_probe");sys.modules[_probe.__name__]=_probe\n'
        + 'exec(compile(' + repr(captured['tart_macos_probe.py']) + ',"<fixed-probe>","exec"),_probe.__dict__)\n'
        + '_network=types.ModuleType("_network_fixed_getter");sys.modules[_network.__name__]=_network\n'
        + 'exec(compile(' + repr(captured['tart_macos_network_census.py']) + ',"<fixed-network>","exec"),_network.__dict__)\n'
        + 'try:\n _network.need(sys.platform=="darwin" and len(sys.argv)==1,"macos_network_guest_required")\n'
        + ' _base=_probe.Native();_native=_network.NativeNetwork(_base)\n'
        + ' _result=_network.collect(_base,_native,**' + repr(config) + ')\n'
        + 'except Exception:\n _result={"state":"blocked","reason":"macos_network_getter_unavailable"}\n'
        + 'print(json.dumps(_result,sort_keys=True))\n'
        + 'raise SystemExit(0 if _result.get("state")=="diagnostic" else 3)\n').encode('utf-8')
