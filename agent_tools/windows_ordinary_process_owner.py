"""Retained Windows3.13 ordinary native child owner.

Native admission and whole-owner qualification are required before each new run.

No action occurs on import. The PS parent must authenticate and hold the Python
interpreter/runtime, this script, request and every declared input BEFORE Python
executes. This owner independently repeats native token/boot/file admission.
Reconnect reads existing event files; it never starts this main() again.
"""
from __future__ import annotations

import argparse
import base64
import ctypes
from ctypes import wintypes as W
import hashlib
import json
import os
from pathlib import Path, PureWindowsPath
import struct
import subprocess
import sys
import threading
import time
import types
import uuid
if os.name == "nt":
    import winreg
else:
    winreg = None


# Equal to the planner's tables; regenerated after every leaf edit.
_POSTBOOT_ENTRY_SOURCES = {'sourceRoles': {'sha256': '20935673ed2dcc58c6a2214136dda371782a76e4084b46fa611088fafd7c601b', 'sizeBytes': 6945}, 'postbootAction': {'sha256': '8eb8d4d694dd5b4b62fa86410ddb5e5810542be7a9753d1ac3a55b6ffa9f8771', 'sizeBytes': 29231}, 'prebootAction': {'sha256': '6c6e73890c0502ef983ea9155087a98f3c3a643f116d2ae813c05b7b2f17d18e', 'sizeBytes': 9455}, 'startupCollector': {'sha256': '3f8f198fde10df843c69a2c1ead1beb05ed59f4d26c097dece6448f5f40d1723', 'sizeBytes': 2875}}
_POSTBOOT_ACTION_PHASES = {"windows-preboot-reboot": "preboot-reboot", "windows-postboot-final": "postboot-final"}

DOCUMENT_RESPONSIVE_CASE = (
    "windows_document_responsive_cli_cases.py",
    "f02bd180210568a7219f33bd22e7c72d8fde5dbab560ce2b6a5803de21338705",
)

DOCUMENT_RESPONSIVE_SOURCES = {
    "casesPath": ("windows_document_responsive_cases.py", "750bf3925e867c7560fd869ce523b9fd95ca7d7d51de451bb208b771ae8995a5"),
    "runtimeStagesPath": ("windows_lifecycle_runtime_stages.py", "0b6b6c7c4c261a8996c140661b7631fb234115ed215e3d3a4a72fd60e25e676e"),
    "fixtureWorkerPath": ("windows_document_gated_https_fixture.py", "205a1bdd79fa3c2d0df3d3f3cf4746132ed78d09500d4947a4ab6bb177f63e9c"),
    "socksSourcePath": ("socks_http_fixture.py", "50239b25bb1c63e7c86baaea8683f188426e87d6a1c6090b505c38d567e70210"),
    "httpsSourcePath": ("https_subscription_relay_fixture.py", "e62f262d9703eb63c0eeca9b823eaae9d1a5780aefdedadf8aebe211492651d4"),
}

DOCUMENT_RESPONSIVE_FIELDS = {"schemaVersion", "casesPath", "runtimeStagesPath",
    "fixtureWorkerPath", "socksSourcePath", "httpsSourcePath", "certificatePath",
    "privateKeyPath", "trustStorePath", "contexts", "largeRoutingInputPath"}

# The CLI case modules whose every child is a serve owner, a completed public call, the
# console helper or a stream client bound to the one serve, all through this owner: a
# case oracle failure there is a known failure the owner closes (close_known_failure).
KNOWN_FAILURE_ACTIONS = frozenset({"disconnected-cli-config", "streaming-client-interrupt"})
KNOWN_FAILURE_EXIT_SECONDS = 120

_PROTECTED_OS_PATHS = frozenset({
    r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    r"C:\Windows\System32\msiexec.exe",
})
_PROTECTED_OS_OWNER = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
_PROTECTED_OS_WRITERS = frozenset({_PROTECTED_OS_OWNER, "SY", "BA", "S-1-5-18", "S-1-5-32-544"})
_PROTECTED_OS_READ_MASK = 0xA01200A9
_PROTECTED_OS_RIGHTS = {
    "FA": 0x001F01FF, "FR": 0x00120089, "FW": 0x00120116, "FX": 0x001200A0,
    "GA": 0x10000000, "GR": 0x80000000, "GW": 0x40000000, "GX": 0x20000000,
    "RC": 0x00020000, "SD": 0x00010000, "WD": 0x00040000, "WO": 0x00080000,
}
_PROTECTED_OS_SID_ALIASES = frozenset({
    "SY", "BA", "BU", "AC", "WD", "AU", "AN", "IU", "SU", "LS", "NS", "NU",
    "RD", "RC", "OW", "CO", "CG",
})


def _protected_os_security(security):
    """Accept a finite common-ACE protected OS owner/DACL policy, not a fixture ACL."""
    if (type(security) is not dict or set(security) != {"ownerSid", "sddl"}
            or security["ownerSid"] != _PROTECTED_OS_OWNER
            or type(security["sddl"]) is not str or len(security["sddl"]) > 16384):
        return False
    prefix = "O:" + _PROTECTED_OS_OWNER + "D:"
    if not security["sddl"].startswith(prefix):
        return False
    dacl = security["sddl"][len(prefix):]
    start = dacl.find("(")
    if start < 0 or not dacl.endswith(")"):
        return False  # Reject null and empty DACLs, and non-common ACE grammars.
    flags, seen = dacl[:start], set()
    while flags:
        flag = next((v for v in ("AI", "AR", "P") if flags.startswith(v)), None)
        if flag is None or flag in seen:
            return False
        seen.add(flag)
        flags = flags[len(flag):]
    if "P" not in seen:
        return False
    for ace in dacl[start:-1].split(")"):
        if not ace.startswith("("):
            return False
        fields = ace[1:].split(";")
        if len(fields) != 6:
            return False
        kind, flags, rights, object_guid, inherited_guid, trustee = fields
        if (kind not in {"A", "D"} or object_guid or inherited_guid
                or len(flags) % 2 or len(set(flags[i:i + 2] for i in range(0, len(flags), 2)))
                != len(flags) // 2 or any(flags[i:i + 2] not in {"OI", "CI", "NP", "IO", "ID"}
                    for i in range(0, len(flags), 2))):
            return False
        if trustee not in _PROTECTED_OS_SID_ALIASES:
            parts = trustee.split("-")
            if (not 4 <= len(parts) <= 18 or parts[:2] != ["S", "1"]
                    or any(not item.isascii() or not item.isdecimal()
                           or (len(item) > 1 and item[0] == "0") for item in parts[2:])
                    or len(parts[2]) > 15 or any(len(item) > 10 for item in parts[3:])
                    or int(parts[2]) > 0xFFFFFFFFFFFF
                    or any(int(item) > 0xFFFFFFFF for item in parts[3:])):
                return False
        if rights.startswith("0x"):
            if (not 1 <= len(rights[2:]) <= 8
                    or any(c not in "0123456789abcdefABCDEF" for c in rights[2:])):
                return False
            mask = int(rights[2:], 16)
        else:
            if not rights or len(rights) % 2:
                return False
            mask = 0
            for i in range(0, len(rights), 2):
                value = _PROTECTED_OS_RIGHTS.get(rights[i:i + 2])
                if value is None:
                    return False
                mask |= value
        if kind == "A" and trustee not in _PROTECTED_OS_WRITERS and mask & ~_PROTECTED_OS_READ_MASK:
            return False
    return True

class Refused(RuntimeError):
    pass


def require(value, code):
    if not value:
        raise Refused(code)


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=False) + "\n").encode("utf-8", "strict")


# A failure record keeps names and numbers only, never a message, argument, path or local value.
FAILURE_FRAMES = 12


def failure_detail(error):
    """What failed and where, finite and private-safe, for every park and known-failure record.

    The exception class, an OS error's winerror and errno, and the innermost FAILURE_FRAMES frames
    outside the standard library as "<file basename>:<line>", outermost first. On the guest those
    are the agent_tools modules this owner runs and the held harness. Its cause (explicit, else the
    error it was raised while handling) is recorded the same way, one level deep. A parked value that
    is not an exception, such as a state dict, records its type only. This never raises: a record it
    could not build names only the class, so the park or event it belongs to is still written.
    """
    def record(value):
        result = {"errorClass": type(value).__name__, "winerror": None, "errno": None, "frames": []}
        if isinstance(value, BaseException):
            for name in ("winerror", "errno"):
                code = getattr(value, name, None)
                result[name] = code if type(code) is int else None
            frames, trace = [], value.__traceback__
            while trace is not None:
                module = trace.tb_frame.f_globals.get("__name__")
                source = trace.tb_frame.f_code.co_filename
                if (type(module) is str and module.partition(".")[0] not in sys.stdlib_module_names
                        and type(source) is str and not source.startswith("<")):
                    frames.append("%s:%s" % (PureWindowsPath(source).name, trace.tb_lineno))
                trace = trace.tb_next
            result["frames"] = frames[-FAILURE_FRAMES:]
        return result
    if error is None:
        return None
    try:
        detail = record(error)
        cause = None
        if isinstance(error, BaseException):
            cause = error.__cause__ if error.__cause__ is not None else (
                None if error.__suppress_context__ else error.__context__)
        detail["cause"] = record(cause) if cause is not None else None
        return detail
    except Exception as failure:
        return {"errorClass": type(error).__name__, "detailUnavailable": type(failure).__name__}


def _unreadable(error):
    raise error


def absolute(value):
    require(type(value) is str and "\0" not in value and len(value) <= 1000,
            "absolute-path-type")
    path = PureWindowsPath(value)
    require(len(path.drive) == 2 and path.drive[1] == ":" and path.root == "\\"
            and not any(part in {".", ".."} or part.endswith((".", " "))
                        for part in path.parts[1:]) and str(path) == value,
            "absolute-drive-path-required")
    return Path(value)


class Info(ctypes.Structure):
    _fields_ = [("attributes", W.DWORD), ("creation", W.FILETIME),
                ("access", W.FILETIME), ("write", W.FILETIME),
                ("volume", W.DWORD), ("size_high", W.DWORD),
                ("size_low", W.DWORD), ("links", W.DWORD),
                ("index_high", W.DWORD), ("index_low", W.DWORD)]


def filetime(value):
    return value.dwHighDateTime << 32 | value.dwLowDateTime


class Native:
    def __init__(self):
        require(os.name == "nt" and struct.calcsize("P") == 8, "windows-amd64-required")
        self.k = ctypes.WinDLL("kernel32", use_last_error=True)
        self.a = ctypes.WinDLL("advapi32", use_last_error=True)
        self.n = ctypes.WinDLL("ntdll", use_last_error=True)
        self.k.GetCurrentProcess.restype = W.HANDLE
        self.k.CreateFileW.argtypes = (W.LPCWSTR, W.DWORD, W.DWORD, W.LPVOID,
                                      W.DWORD, W.DWORD, W.HANDLE)
        self.k.CreateFileW.restype = W.HANDLE
        self.k.GetFileInformationByHandle.argtypes = (W.HANDLE, ctypes.POINTER(Info))
        self.k.SetFilePointerEx.argtypes = (W.HANDLE, ctypes.c_longlong,
                                           ctypes.POINTER(ctypes.c_longlong), W.DWORD)
        self.k.ReadFile.argtypes = (W.HANDLE, W.LPVOID, W.DWORD,
                                   ctypes.POINTER(W.DWORD), W.LPVOID)
        self.k.GetProcessTimes.argtypes = (W.HANDLE, ctypes.POINTER(W.FILETIME),
                                          ctypes.POINTER(W.FILETIME),
                                          ctypes.POINTER(W.FILETIME),
                                          ctypes.POINTER(W.FILETIME))
        self.k.CloseHandle.argtypes = (W.HANDLE,)
        self.k.LocalFree.argtypes = (W.HANDLE,)
        self.a.OpenProcessToken.argtypes = (W.HANDLE, W.DWORD, ctypes.POINTER(W.HANDLE))
        self.a.GetTokenInformation.argtypes = (W.HANDLE, ctypes.c_int, W.LPVOID,
                                              W.DWORD, ctypes.POINTER(W.DWORD))
        self.a.ConvertSidToStringSidW.argtypes = (W.LPVOID, ctypes.POINTER(W.LPWSTR))
        self.a.GetSecurityInfo.argtypes = (W.HANDLE, ctypes.c_int, W.DWORD,
            ctypes.POINTER(W.LPVOID), ctypes.POINTER(W.LPVOID), ctypes.POINTER(W.LPVOID),
            ctypes.POINTER(W.LPVOID), ctypes.POINTER(W.LPVOID))
        self.a.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = (
            W.LPVOID, W.DWORD, W.DWORD, ctypes.POINTER(W.LPWSTR), ctypes.POINTER(W.DWORD))
        self.n.NtQuerySystemInformation.argtypes = (ctypes.c_int, W.LPVOID,
                                                   W.ULONG, ctypes.POINTER(W.ULONG))
        self.n.NtQuerySystemInformation.restype = ctypes.c_long

    def sid(self, pointer):
        text = W.LPWSTR()
        require(self.a.ConvertSidToStringSidW(pointer, ctypes.byref(text)), "sid-conversion")
        try:
            return text.value
        finally:
            self.k.LocalFree(ctypes.cast(text, W.HANDLE))

    def token(self):
        token = W.HANDLE()
        require(self.a.OpenProcessToken(self.k.GetCurrentProcess(), 8, ctypes.byref(token)),
                "token-open")
        try:
            def info(kind):
                needed = W.DWORD()
                self.a.GetTokenInformation(token, kind, None, 0, ctypes.byref(needed))
                require(0 < needed.value <= 65536, "token-information-bound")
                buffer = ctypes.create_string_buffer(needed.value)
                require(self.a.GetTokenInformation(token, kind, buffer, len(buffer),
                                                   ctypes.byref(needed)), "token-information")
                return buffer
            user = info(1)
            user_sid = self.sid(ctypes.cast(user, ctypes.POINTER(W.LPVOID))[0])
            groups = info(2)
            class Group(ctypes.Structure):
                _fields_ = [("sid", W.LPVOID), ("attributes", W.DWORD)]
            class Groups(ctypes.Structure):
                _fields_ = [("count", W.DWORD), ("first", Group)]
            count = struct.unpack_from("<I", groups.raw)[0]
            offset, stride = Groups.first.offset, ctypes.sizeof(Group)
            require(count <= 256 and offset + count * stride <= len(groups), "token-groups-shape")
            admin_member = admin_enabled = False
            for index in range(count):
                entry = Group.from_buffer(groups, offset + index * stride)
                if self.sid(entry.sid) == "S-1-5-32-544":
                    admin_member = True
                    admin_enabled = bool(entry.attributes & 4 and not entry.attributes & 16)
            scalar = lambda kind: struct.unpack_from("<I", info(kind).raw)[0]
            return {"sid": user_sid, "sessionId": scalar(12), "elevation": scalar(20),
                    "elevationType": scalar(18), "administratorMember": admin_member,
                    "administratorEnabled": admin_enabled}
        finally:
            self.k.CloseHandle(token)

    def boot_identifier(self):
        # SYSTEM_BOOT_ENVIRONMENT_INFORMATION begins with native GUID.
        # This private ABI must first be qualified on the actual Windows build.
        # AMD64 typed struct is GUID(16), FIRMWARE_TYPE(4), padding(4), flags(8).
        buffer = ctypes.create_string_buffer(32)
        needed = W.ULONG()
        status = self.n.NtQuerySystemInformation(90, buffer, len(buffer), ctypes.byref(needed))
        require(status == 0 and needed.value == len(buffer), "native-boot-identifier")
        identifier = uuid.UUID(bytes_le=buffer.raw[:16])
        require(identifier.int != 0, "native-boot-identifier-zero")
        return str(identifier)

    def birth(self, handle):
        values = [W.FILETIME() for _ in range(4)]
        require(self.k.GetProcessTimes(W.HANDLE(handle), *(ctypes.byref(v) for v in values)),
                "original-process-handle-times")
        return str(filetime(values[0]))

    def identity(self, handle, directory=False):
        info = Info()
        require(self.k.GetFileInformationByHandle(handle, ctypes.byref(info)), "native-file-information")
        require(not info.attributes & 0x400 and bool(info.attributes & 0x10) == directory,
                "native-file-type-or-reparse")
        if not directory:
            require(info.links == 1, "native-file-hardlink")
        result = {"volumeSerial": info.volume, "fileIndex": info.index_high << 32 | info.index_low,
                  "attributes": info.attributes}
        if not directory:
            result.update(sizeBytes=info.size_high << 32 | info.size_low, links=info.links,
                          creationFileTime=str(filetime(info.creation)),
                          lastWriteFileTime=str(filetime(info.write)))
        return result

    def protected_os_identity(self, handle, path):
        # Windows-serviced OS files may have hardlinks; this role is never generic.
        require(type(path) is str and path in _PROTECTED_OS_PATHS, "protected-os-path")
        info = Info()
        require(self.k.GetFileInformationByHandle(handle, ctypes.byref(info)), "native-file-information")
        require(not info.attributes & (0x400 | 0x10), "native-file-type-or-reparse")
        require(info.links > 0, "protected-os-positive-links")
        require(_protected_os_security(self.security(handle)), "protected-os-writer-policy")
        return {"volumeSerial": info.volume, "fileIndex": info.index_high << 32 | info.index_low,
                "attributes": info.attributes, "sizeBytes": info.size_high << 32 | info.size_low,
                "links": info.links, "creationFileTime": str(filetime(info.creation)),
                "lastWriteFileTime": str(filetime(info.write))}

    def read_blocks(self, handle):
        # Native custody handles do not consume a CRT fd for every runtime file.
        # Large complete inventories must not depend on the default CRT fd cap.
        require(self.k.SetFilePointerEx(handle, 0, None, 0), "held-file-seek")
        buffer = ctypes.create_string_buffer(131072)
        while True:
            count = W.DWORD()
            require(self.k.ReadFile(handle, buffer, len(buffer), ctypes.byref(count), None),
                    "held-file-read")
            require(count.value <= len(buffer), "held-file-read-count")
            if count.value == 0:
                return
            yield buffer.raw[:count.value]

    def security(self, handle):
        owner, descriptor = W.LPVOID(), W.LPVOID()
        code = self.a.GetSecurityInfo(handle, 1, 5, ctypes.byref(owner), None, None, None,
                                      ctypes.byref(descriptor))
        require(code == 0 and descriptor.value and owner.value, "native-security-information")
        try:
            text, length = W.LPWSTR(), W.DWORD()
            require(self.a.ConvertSecurityDescriptorToStringSecurityDescriptorW(
                descriptor, 1, 5, ctypes.byref(text), ctypes.byref(length)), "native-security-sddl")
            try:
                return {"ownerSid": self.sid(owner), "sddl": text.value}
            finally:
                self.k.LocalFree(ctypes.cast(text, W.HANDLE))
        finally:
            self.k.LocalFree(descriptor)


class Pin:
    def __init__(self, native, record, directory=False):
        self.native, self.record = native, record
        self.path, self.directory = absolute(record["path"]), directory
        self.handle = native.k.CreateFileW(str(self.path), 0x20080 if directory else 0x80020000,
                                           3 if directory else 1, None, 3, 0x02200000, None)
        require(self.handle != ctypes.c_void_p(-1).value, "pin-open")
        self.current()
        if not directory:
            self.digest()

    def current(self):
        identity, argument = self.native.identity, self.directory
        if not self.directory and self.record["path"] in _PROTECTED_OS_PATHS:
            identity, argument = self.native.protected_os_identity, self.record["path"]
        require(identity(self.handle, argument) == self.record["nativeIdentity"],
                "pin-native-identity-changed")
        require(self.native.security(self.handle) == self.record["security"], "pin-security-changed")
        # Reopen lexical path too: held old inode alone is not namespace evidence.
        named = self.native.k.CreateFileW(str(self.path), 0x20080, 3, None, 3, 0x02200000, None)
        require(named != ctypes.c_void_p(-1).value, "pin-named-open")
        try:
            require(identity(named, argument) == self.record["nativeIdentity"]
                    and self.native.security(named) == self.record["security"], "pin-namespace-changed")
        finally:
            self.native.k.CloseHandle(named)

    def digest(self, return_bytes=False, maximum=8 * 1024 * 1024):
        self.current()
        digest, total, blocks = hashlib.sha256(), 0, []
        for block in self.native.read_blocks(self.handle):
            total += len(block)
            digest.update(block)
            if return_bytes:
                require(total <= maximum, "held-source-bound")
                blocks.append(block)
        require(total == self.record["nativeIdentity"]["sizeBytes"]
                and digest.hexdigest() == self.record["sha256"], "pin-digest-changed")
        self.current()
        return b"".join(blocks) if return_bytes else digest.hexdigest()

    def close(self):
        self.native.k.CloseHandle(self.handle)


class Child:
    def __init__(self, owner, label, argv, *, new_console=False, owned_desktop=None):
        require(type(new_console) is bool, "explicit-child-console-mode")
        require(owned_desktop is None or not new_console, "owned-desktop-console-conflict")
        if owned_desktop is not None:
            require(getattr(owned_desktop, "owner", None) is owner
                    and any(held is owned_desktop for held in getattr(owner, "no_tray_desktop_leases", ())),
                    "owned-desktop-lease-not-held")
        self.owned_desktop = owned_desktop
        self.new_console = new_console
        self.owner, self.label, self.argv = owner, label, tuple(argv)
        self.process = None
        self.pid = self.birth = None
        self.streams, self.threads, self.eof = {}, {}, {"stdout": False, "stderr": False}
        self.errors, self.pending_chunks, self.counts = {}, {}, {"stdout": 0, "stderr": 0}
        self.digests = {name: hashlib.sha256() for name in self.eof}
        self.terminal = None
        owner.guard()
        line = subprocess.list2cmdline(self.argv)
        require(len(line.encode("utf-16le")) // 2 + 1 <= 32767, "windows-command-length")
        require(len(encoded({"path": self.argv[0], "arg": list(self.argv[1:])})) <= 60000,
                "json-command-bound")
        self.ordinal = len(owner.children)
        owner.children.append(self)  # Custody exists BEFORE native submission.
        owner.event("child-intent", {"child": self.ordinal, "label": label, "argv": list(argv),
            "consoleCreation": "new" if new_console else "none"})
        for name in self.eof:
            path = owner.root / f"child-{self.ordinal:04d}.{name}.raw"
            self.streams[name] = path.open("xb", buffering=0)
        try:
            startup_info = None
            if owned_desktop is not None:
                startup_info = owned_desktop.startup_info(owner, label, self.argv)
                require(type(startup_info) is subprocess.STARTUPINFO
                        and startup_info.lpAttributeList == {"handle_list": [int(owned_desktop.handle)]},
                        "owned-desktop-exact-startup-info")
            # Retain the Popen object BEFORE its constructor can obtain a native
            # child handle, including an exception after CreateProcess succeeds.
            self.process = subprocess.Popen.__new__(subprocess.Popen)
            subprocess.Popen.__init__(self.process, self.argv, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=owner.root,
                env=owner.environment, creationflags=(subprocess.CREATE_NEW_CONSOLE if new_console
                    else subprocess.CREATE_NO_WINDOW), close_fds=True, startupinfo=startup_info)
            self.pid = self.process.pid
            for name in self.eof:
                thread = threading.Thread(target=self._pump, args=(name,),
                                          name=f"raw-{self.ordinal}-{name}", daemon=False)
                self.threads[name] = thread
                thread.start()
            self.birth = owner.native.birth(int(self.process._handle))
            owner.event("child-started", {"child": self.ordinal, "pid": self.pid,
                         "birthFileTimeUtc": self.birth, "originalHandleRetained": True,
                         "consoleCreation": "new" if new_console else "none"})
            if owned_desktop is not None:
                owned_desktop.child_started(self)
        except BaseException as error:
            if self.process is not None:
                owner.park("post-start-admission-unknown", error)
            owner.event("child-no-process", {"child": self.ordinal, "errorClass": type(error).__name__,
                                             "failure": failure_detail(error)})
            raise

    def _pump(self, name):
        pipe, output = getattr(self.process, name), self.streams[name]
        try:
            while True:
                remaining = self.owner.raw_limit - self.counts[name]
                block = os.read(pipe.fileno(), min(65536, max(1, remaining + 1)))
                if not block:
                    output.flush()
                    os.fsync(output.fileno())
                    self.eof[name] = True
                    return
                self.pending_chunks[name] = block
                offset = 0
                while offset < len(block):
                    written = output.write(block[offset:])
                    require(written is not None and written > 0, "raw-write-zero")
                    self.digests[name].update(block[offset:offset + written])
                    self.counts[name] += written
                    offset += written
                    self.pending_chunks[name] = block[offset:]
                self.pending_chunks.pop(name, None)
                if self.counts[name] > self.owner.raw_limit:
                    raise Refused("raw-stream-bound-retained")
        except BaseException as error:
            # Retain original pipe, file and unwritten chunk in this namespace.
            # Never claim EOF, close a live pipe, or restart this reader/child.
            self.errors[name] = {"errorClass": type(error).__name__, "message": str(error), "error": error}

    def observe(self):
        if self.terminal is not None:
            return self.terminal
        if self.errors:
            # The park records the first failed stream's own error; every stream's entry stays on this child.
            self.owner.park("raw-capture-unknown", list(self.errors.values())[0]["error"])
        code = self.process.poll()
        if code is None or not all(self.eof.values()):
            return None
        for thread in self.threads.values():
            thread.join()
        self.owner.guard()
        self.terminal = {"child": self.ordinal, "pid": self.pid, "birthFileTimeUtc": self.birth,
                         "exitCode": code, "eof": dict(self.eof), "counts": dict(self.counts),
                         "sha256": {name: value.hexdigest() for name, value in self.digests.items()},
                         "sourceClosing": True, "originalHandleRetained": True}
        self.owner.event("child-terminal", self.terminal)
        for stream in self.streams.values():
            stream.close()
        for name in self.eof:
            getattr(self.process, name).close()
        return self.terminal

    def wait(self, notice_seconds=30):
        notice_at = time.monotonic() + notice_seconds
        while self.observe() is None:
            if time.monotonic() >= notice_at:
                self.owner.event("child-pending", {"child": self.ordinal, "pid": self.pid,
                    "birthFileTimeUtc": self.birth, "eof": dict(self.eof), "counts": dict(self.counts),
                    "originalHandleRetained": True, "replayAllowed": False})
                notice_at = time.monotonic() + notice_seconds
            time.sleep(0.1)
        return self.terminal

    def completed(self):
        terminal = self.wait()
        values = [(self.owner.root / f"child-{self.ordinal:04d}.{name}.raw").read_bytes()
                  for name in ("stdout", "stderr")]
        return subprocess.CompletedProcess(self.argv, terminal["exitCode"],
                                           *(value.decode("utf-8", "strict") for value in values))


class Owner:
    def __init__(self, request, request_pin):
        self.request, self.native = request, Native()
        require(type(request) is dict and request.get("schemaVersion") == 1, "owner-schema-version")
        self.children, self.pins, self.events = [], [], 0
        self.root = absolute(request["operationRoot"])
        self.operation = str(uuid.UUID(request["operationId"]))
        require(self.operation == request["operationId"], "operation-uuid")
        self.raw_limit = request["rawStreamLimitBytes"]
        require(type(self.raw_limit) is int and 4096 <= self.raw_limit <= 64 * 1024 * 1024,
                "raw-stream-resource-bound")
        require(sys.version_info[:3] == (3, 13, 15), "admitted-python-version")
        runtime = request["pythonRuntime"]
        require(runtime["version"] == "3.13.15" and runtime["architecture"] == "amd64"
                and absolute(runtime["interpreterPath"]) == absolute(runtime["root"]) / "python.exe"
                and str(Path(sys.executable)).casefold() == runtime["interpreterPath"].casefold(),
                "interpreter-runtime-role-binding")
        runtime_trees = [tree for tree in request["treePins"]
                         if tree.get("role") == "python-runtime"
                         and absolute(tree["root"]) == absolute(runtime["root"])]
        require(len(runtime_trees) == 1 and {"python.exe", "python313.dll", "Lib/os.py",
                "Lib/subprocess.py", "Lib/threading.py", "Lib/json/__init__.py",
                "Lib/ctypes/__init__.py", "DLLs/_ctypes.pyd"} <= set(runtime_trees[0]["files"]),
                "complete-python-runtime-role-required")
        self.environment = dict(os.environ)
        for name in ("DISPLAY", "WAYLAND_DISPLAY", "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS",
                     "JDK_JAVA_OPTIONS", "PYTHONPATH", "PYTHONHOME"):
            self.environment.pop(name, None)
        self.environment["PYTHONDONTWRITEBYTECODE"] = "1"
        self.by_path = {}
        self.guard_context()
        self.pins.append(request_pin)
        for record in request["directoryPins"]:
            self.pins.append(Pin(self.native, record, directory=True))
        for record in request["filePins"]:
            pin = Pin(self.native, record)
            require(str(pin.path).casefold() not in self.by_path, "duplicate-file-pin")
            self.by_path[str(pin.path).casefold()] = pin
            self.pins.append(pin)
        require(str(Path(sys.executable)).casefold() in self.by_path
                and str(Path(__file__)).casefold() in self.by_path, "owner-interpreter-source-pins")
        # Explicit complete tree closure, not listed-file checks only.
        self.guard()
        self.event("owner-started", {"operationId": self.operation, "pid": os.getpid(),
            "birthFileTimeUtc": self.native.birth(self.native.k.GetCurrentProcess()),
            "context": request["context"], "sourceClosing": True})

    def guard_context(self):
        context = self.request["context"]
        require(self.native.token() == {"sid": context["ordinarySid"],
            "sessionId": context["ordinarySessionId"], "elevation": 0, "elevationType": 1,
            "administratorMember": False, "administratorEnabled": False}, "ordinary-native-token")
        require(self.native.boot_identifier() == context["bootIdentifier"], "guest-boot-generation")
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography", 0,
                            winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
            require(winreg.QueryValueEx(key, "MachineGuid")[0].casefold() ==
                    context["machineGuid"].casefold(), "guest-machine-generation")
        require(os.environ.get("USERPROFILE", "").casefold() == context["profileRoot"].casefold()
                and os.environ.get("LOCALAPPDATA", "").casefold() ==
                context["localAppData"].casefold(), "ordinary-profile-context")

    def guard(self):
        self.guard_context()
        for pin in self.pins:
            pin.current()
        for tree in self.request["treePins"]:
            root = absolute(tree["root"])
            actual = set()
            for directory, directories, files in os.walk(root, followlinks=False):
                for name in [*directories, *files]:
                    value = Path(directory) / name
                    require(not value.lstat().st_file_attributes & 0x400, "tree-reparse")
                actual.update((Path(directory) / name).relative_to(root).as_posix() for name in files)
            require(actual == set(tree["files"]), "complete-tree-membership-changed")
            require(all(str(root / PureWindowsPath(name)).casefold() in self.by_path
                        for name in actual), "complete-tree-file-pin-missing")

    def event(self, kind, value):
        try:
            require(self.events < 8192, "event-count-bound")
            data = encoded({"schemaVersion": 1, "operationId": self.operation,
                            "ordinal": self.events, "kind": kind, "value": value})
            require(len(data) <= 256 * 1024, "event-byte-bound")
            path = self.root / f"event-{self.events:06d}-{kind}.json"
            self.events += 1
            with path.open("xb", buffering=0) as output:
                offset = 0
                while offset < len(data):
                    count = output.write(data[offset:])
                    require(count is not None and count > 0, "event-write-zero")
                    offset += count
                os.fsync(output.fileno())
        except BaseException as error:
            self.park("event-journal-unknown", error)

    def park(self, reason, error=None):
        # No exception unwinding and no cleanup of live or uncertain children.
        self.parked = {"reason": reason, "error": error, "children": self.children}
        try:
            data = encoded({"schemaVersion": 1, "operationId": self.operation,
                "state": "unknown", "reason": reason,
                "errorClass": type(error).__name__ if error is not None else None,
                "failure": failure_detail(error),
                "children": [{"ordinal": child.ordinal, "pid": child.pid,
                    "birthFileTimeUtc": child.birth, "eof": child.eof} for child in self.children],
                "originalNamespaceRetained": True, "replayAllowed": False})
            with (self.root / "owner-parked.json").open("xb", buffering=0) as output:
                output.write(data)
                os.fsync(output.fileno())
        except BaseException as park_error:
            self.park_write_error = park_error
        while True:
            # Preserve primary objects even when a status write failed. No retry
            # of the failed mutation, assertion sequence, source or child occurs.
            time.sleep(1)

    def child(self, label, argv, *, new_console=False, owned_desktop=None):
        require(str(absolute(argv[0])).casefold() in self.by_path, "child-executable-not-pinned")
        return Child(self, label, argv, new_console=new_console, owned_desktop=owned_desktop)

    def module(self, path, name):
        pin = self.by_path[str(absolute(path)).casefold()]
        module = types.ModuleType(name)
        module.__file__ = str(pin.path)
        module.__package__ = ""
        require(name not in sys.modules, "private-import-name-already-present")
        sys.modules[name] = module  # Registration precedes class/introspection execution.
        exec(compile(pin.digest(True), str(pin.path), "exec"), module.__dict__)
        return module

    def installer_child(self, label, arguments, log_path, kind):
        log = absolute(log_path)
        require(log.parent == self.root and not log.exists(), "create-only-installer-log")
        terminal = self.child(label, arguments).wait()
        if not log.is_file() or log.lstat().st_file_attributes & 0x400:
            self.park("installer-log-closing-unknown")
        # Open original log read-only without writer/delete sharing before
        # closing receipt; another active writer is an explicit UNKNOWN.
        log_handle = self.native.k.CreateFileW(str(log), 0x80020000, 1, None, 3, 0x02200000, None)
        if log_handle == ctypes.c_void_p(-1).value:
            self.park("installer-log-still-owned-or-unavailable")
        self.log_handles = [*getattr(self, "log_handles", []), log_handle]
        log_identity = self.native.identity(log_handle)
        require(log_identity["sizeBytes"] <= 64 * 1024 * 1024, "installer-log-bound")
        log_digest = hashlib.sha256()
        for block in self.native.read_blocks(log_handle):
            log_digest.update(block)
        self.event(kind, {"terminal": terminal, "installedAdmissionComplete": False,
                   "rebootRequired": terminal["exitCode"] == 3010,
                   "logNativeIdentity": log_identity, "logSha256": log_digest.hexdigest(),
                   "logSecurity": self.native.security(log_handle)})
        return terminal

    def invoke(self, workspace, *arguments, timeout=30):
        # timeout is an observer notice, never subprocess.run(timeout=...).
        del timeout
        return self.child("public-cli", [self.request["cliPath"], "--state-dir",
                                         str(workspace), *arguments]).completed()

    def validate_responsive_work(self):
        """Closed optional document form, checked against original held pins."""
        self.guard()
        require(self.request["action"] == "document-acceptance", "responsive-only-document-action")
        document = self.request["documentAcceptance"]
        require(type(document) is dict and set(document) == {"schemaVersion", "clientPath",
                "windowsPath", "racePath", "largeRoutingInputPath", "spoolTempParent",
                "contexts", "endpointPinBeforeObservation"}
                and type(document["schemaVersion"]) is int and document["schemaVersion"] == 1
                and document["endpointPinBeforeObservation"] is None,
                "responsive-document-input-schema")
        contexts = document["contexts"]
        require(type(contexts) is list and len(contexts) == 52
                and all(type(value) is str for value in contexts) and len(set(contexts)) == 52
                and all(str(uuid.UUID(value)) == value for value in contexts)
                and self.operation not in contexts, "responsive-document-context-schema")
        work = self.request["responsiveWork"]
        require(type(work) is dict and set(work) == DOCUMENT_RESPONSIVE_FIELDS
                and type(work["schemaVersion"]) is int and work["schemaVersion"] == 1,
                "responsive-finite-input-schema")
        work_contexts = work["contexts"]
        require(type(work_contexts) is list and len(work_contexts) == 2
                and all(type(value) is str for value in work_contexts)
                and len(set(work_contexts)) == 2
                and all(str(uuid.UUID(value)) == value for value in work_contexts)
                and not set(work_contexts).intersection(contexts)
                and self.operation not in work_contexts, "responsive-disjoint-canonical-contexts")
        paths = {key: absolute(work[key]) for key in DOCUMENT_RESPONSIVE_FIELDS
                 - {"schemaVersion", "contexts"}}
        keys = {key: str(value).casefold() for key, value in paths.items()}
        modules = [absolute(self.request["casesPath"]),
                   *(absolute(document[key]) for key in ("clientPath", "windowsPath", "racePath"))]
        other = {str(value).casefold() for value in
                 (*modules, absolute(self.request["cliPath"]), absolute(self.request["harnessPath"]))}
        require(len(other) == 6 and len(set(keys.values())) == 9
                and not set(keys.values()).intersection(other)
                and set(keys.values()) | other <= set(self.by_path), "responsive-distinct-held-role-paths")
        require(keys["largeRoutingInputPath"] == str(absolute(document["largeRoutingInputPath"])).casefold(),
                "responsive-same-document-large-input")
        case = self.by_path[str(modules[0]).casefold()]
        require(case.path.name == DOCUMENT_RESPONSIVE_CASE[0]
                and case.record["sha256"] == DOCUMENT_RESPONSIVE_CASE[1],
                "responsive-fixed-document-cases-source")
        for key, (name, digest) in DOCUMENT_RESPONSIVE_SOURCES.items():
            pin = self.by_path[keys[key]]
            require(pin.path.name == name and pin.record["sha256"] == digest,
                    "responsive-fixed-producer-source-" + key)
        distinct = set(keys.values()) | other
        identities = [(self.by_path[key].record["nativeIdentity"]["volumeSerial"],
                       self.by_path[key].record["nativeIdentity"]["fileIndex"]) for key in distinct]
        require(len(set(identities)) == len(distinct), "responsive-native-role-alias")
        large = self.by_path[keys["largeRoutingInputPath"]]
        require(10 * 1024 * 1024 < large.record["nativeIdentity"]["sizeBytes"] <= 64 * 1024 * 1024,
                "responsive-document-large-input-size")
        for key in distinct:
            self.by_path[key].digest()
        self.guard()

    def run(self):
        action = self.request["action"]
        require("responsiveWork" not in self.request or action == "document-acceptance",
                "responsive-only-document-action")
        if action in _POSTBOOT_ACTION_PHASES:
            require(not hasattr(self, "postboot_dispatch"), "one-original-fixed-postboot-dispatch")
            self.postboot_dispatch = {"action": action, "stage": "binding"}
            config = self.request["postbootAcceptance"]
            require(type(config) is dict and config.get("phase") == _POSTBOOT_ACTION_PHASES[action],
                    "same-fixed-postboot-action-phase")
            roles = config["sourceRoles"]
            loaded = {}
            for role, expected in _POSTBOOT_ENTRY_SOURCES.items():
                source_path = roles[role]
                pin = self.by_path[str(absolute(source_path)).casefold()]
                pin.current()
                require(pin.record["sha256"] == expected["sha256"]
                        and pin.record["nativeIdentity"]["sizeBytes"] == expected["sizeBytes"]
                        and hashlib.sha256(pin.digest(True)).hexdigest() == expected["sha256"],
                        "held-fixed-postboot-entry-source-" + role)
                if role != "startupCollector":
                    loaded[role] = self.module(source_path, "_owned_fixed_" + role)
                pin.current()
            self.postboot_module = loaded["postbootAction"]
            self.postboot_dispatch["stage"] = "entered-original-action"
            # Both end with a known result the owner finishes: the preboot leaves no child
            # of its own, and nothing here reboots.
            if action == "windows-preboot-reboot":
                return loaded["prebootAction"].run_preboot(self, config, loaded["sourceRoles"], self.postboot_module)
            return self.postboot_module.run_postboot(self, config, loaded["sourceRoles"])
        if action == "qualification":
            terminal = self.child(action, self.request["qualificationArgv"]).wait()
            self.event("qualification-result", {"terminal": terminal, "productOperation": False,
                       "fullWindowsAcceptance": False})
            return 0 if terminal["exitCode"] == self.request["expectedExitCode"] else 1
        if action == "msi-reset":
            # Setup only: remove the exact registered product by its code, then the install below.
            code = self.request["uninstallProductCode"]
            require(type(code) is str and len(code) == 38 and code[0] + code[-1] == "{}"
                    and str(uuid.UUID(code[1:-1])).upper() == code[1:-1], "exact-uninstall-product-code")
            terminal = self.installer_child("msi-uninstall", [r"C:\Windows\System32\msiexec.exe", "/x", code,
                "/qn", "/norestart", "REBOOT=ReallySuppress", "MSIRESTARTMANAGERCONTROL=Disable", "/L*v",
                self.request["uninstallLogPath"]], self.request["uninstallLogPath"], "uninstaller-result")
            if terminal["exitCode"] != 0:
                return 1
            # Files the removal left would be recorded as part of the base installed beside them.
            # Empty folders hold nothing the installed-tree digest counts; an unreadable one is not a pass.
            folder = absolute(self.request["uninstallRoot"])
            left = 0
            if os.path.lexists(folder):
                for _, _, names in os.walk(folder, onerror=_unreadable):
                    left += len(names)
            if left:
                self.event("uninstall-left-files", {"files": left})
                return 1
        if action in {"msi-install", "msi-reset"}:
            arguments = [r"C:\Windows\System32\msiexec.exe", "/i", self.request["msiPath"],
                         "/qn", "/norestart", "/L*v", self.request["installerLogPath"]]
            require(str(absolute(self.request["msiPath"])).casefold() in self.by_path,
                    "exact-msi-file-pin-required")
            terminal = self.installer_child("msi-install", arguments, self.request["installerLogPath"],
                                            "installer-result")
            return 0 if terminal["exitCode"] == 0 else 1
        if action in {"windows-public-update", "windows-proxy-lifecycle"}:
            driver_path = str(Path(__file__).with_name("windows_ordinary_dedicated_driver.py"))
            pin = self.by_path[str(absolute(driver_path)).casefold()]
            require(pin.record["sha256"] == "24a2ae0562be6a009ad621e0c9ff2e6507f97dfa5d3233d042ea15f50da8a3c9",
                    "held-fixed-dedicated-driver-source")
            driver = self.module(driver_path, "_owned_fixed_dedicated_driver")
            return driver.run(self, action)
        require(action in {"baseline-source-mode", "fixed-source-mode", "disconnected-cli-config",
                           "streaming-client-interrupt", "document-acceptance"}, "owner-action")
        workspace = absolute(self.request["workspace"])
        require(workspace.parent == self.root and not workspace.exists(), "fresh-isolated-workspace")
        launcher = self.request["cliPath"]
        cases = None
        if action == "document-acceptance":
            if "responsiveWork" in self.request:
                self.validate_responsive_work()
            else:
                case_pin = self.by_path[str(absolute(self.request["casesPath"])).casefold()]
                require(case_pin.path.name != DOCUMENT_RESPONSIVE_CASE[0]
                        and case_pin.record["sha256"] != DOCUMENT_RESPONSIVE_CASE[1],
                        "responsive-cases-require-responsive-work")
            cases = self.module(self.request["casesPath"], "_owned_native_document_acceptance")
        for label, argv, text in (("help", ["--help"], "Usage:"),
                                  ("version", ["--version"], self.request["productVersion"])):
            value = self.child(label, [launcher, "--state-dir", str(workspace), *argv]).completed()
            require(value.returncode == 0 and value.stderr == "" and text in value.stdout,
                    "static-public-launcher-probe")
        require(not workspace.exists(), "static-launch-created-owner-state")
        if action == "document-acceptance":
            if "responsiveWork" in self.request:
                self.validate_responsive_work()
            cases.configure_launch(self, workspace)
        serve = self.child("serve", [launcher, "--state-dir", str(workspace), "serve"])
        if "responsiveWork" in self.request:
            # The scoped trust options reach only this serve: no later child ever inherits them.
            self.environment.pop("JAVA_TOOL_OPTIONS", None)
        identity = None
        ready_until = time.monotonic() + 30
        while time.monotonic() < ready_until:
            require(serve.process.poll() is None, "original-serve-ended-before-readiness")
            status = self.invoke(workspace, "--json", "status")
            if status.returncode == 0:
                body = json.loads(status.stdout)
                require(status.stderr == "" and body["schemaVersion"] == 1
                        and body["code"] == "OK" and body["final"] is True
                        and body["data"]["runtimeRunning"] is False, "fresh-owner-status")
                identity = body["controllerId"]
                require(type(identity) is str and bool(identity), "owner-controller-id")
                break
            require(status.returncode == 2 and json.loads(status.stdout)["code"] == "UNAVAILABLE",
                    "unexpected-owner-readiness-failure")
            time.sleep(0.1)
        if identity is None:
            self.park("original-serve-readiness-unknown")
        module_name = ("_owned_native_source_mode_cases" if action in
                       {"baseline-source-mode", "fixed-source-mode"} else
                       "_owned_native_" + action.replace("-", "_"))
        if cases is None:
            cases = self.module(self.request["casesPath"], module_name)
        result = None
        if action == "baseline-source-mode":
            result = cases.baseline_cases(workspace, identity, self.invoke, self.event)
        elif action == "fixed-source-mode":
            harness = self.module(self.request["harnessPath"], "_owned_pinned_package_cli_harness")
            cases.fixed_full_cases(workspace, identity, self.invoke, harness.__dict__)
        else:
            harness = self.module(self.request["harnessPath"], "_owned_pinned_package_cli_harness")
            try:
                cases.run(self, workspace, identity, harness.__dict__)
            except (AssertionError, RuntimeError) as error:
                # A case oracle fails only after the child it checked exited, so in these actions
                # no child process the owner started has an open outcome, and the product answers
                # a quit BUSY while a mutation is in flight: the owner closes its children and the
                # job ends 1. Any other error or action keeps every child for the park.
                if action in KNOWN_FAILURE_ACTIONS and isinstance(error, AssertionError):
                    close_known_failure(self, workspace, identity, serve, error)
                # A document case module that defines close_known owns its finite oracle failures: it
                # releases its own observers and names the owner still running only when no socket,
                # relay, held fixture or other child is uncertain. Otherwise every original stays for the park.
                closing = getattr(cases, "close_known", None) if action == "document-acceptance" else None
                known = closing(self, error, serve, identity) if closing is not None else None
                if known is not None:
                    close_known_failure(self, workspace, known[1], known[0], error)
                raise
        reopened = getattr(self, "document_reopened_owner", None) if action == "document-acceptance" else None
        if reopened is not None:
            # A cold case quit the original serve through the same public quit and opened the same workspace
            # once more, by a serve or by the installed GUI: that owner is the one this action closes.
            require(serve.terminal is not None and serve.terminal["exitCode"] == 0
                    and reopened["child"] in self.children and reopened["child"].terminal is None
                    and reopened["controllerId"] != identity and type(reopened["controllerId"]) is str,
                    "document-reopened-owner")
            serve, identity = reopened["child"], reopened["controllerId"]
        safe_quit_status = self.invoke(workspace, "--json", "--controller-id", identity, "status")
        status = json.loads(safe_quit_status.stdout)
        require(safe_quit_status.returncode == 0 and safe_quit_status.stderr == ""
                and status["schemaVersion"] == 1 and status["code"] == "OK" and status["ok"] is True
                and status["final"] is True and status["controllerId"] == identity
                and status["data"]["runtimeRunning"] is False,
                "safe-pinned-disconnected-quit-admission")
        quit_result = self.invoke(workspace, "--json", "--controller-id", identity, "quit")
        quit_body = json.loads(quit_result.stdout)
        require(quit_result.returncode == 0 and quit_result.stderr == ""
                and quit_body["controllerId"] == identity and quit_body["final"] is True,
                "explicit-pinned-quit-not-acknowledged")
        if reopened is not None and reopened.get("gui") is True:
            # The installed GUI ends with its own controller: it gets the closing's 120 s, then the owner parks.
            serve_terminal = _await_known_exit(self, serve, None, "document-gui-owner-exit-unknown")
        else:
            serve_terminal = serve.wait()
        require(serve_terminal["exitCode"] == 0, "original-serve-exit-not-zero")
        if reopened is not None and reopened.get("gui") is True:
            # The GUI's own controller is its child, not the owner's: it releases the endpoint as it ends.
            released_until = time.monotonic() + 30
            while (workspace / "activation.port").exists() and time.monotonic() < released_until:
                time.sleep(0.2)
        require(not (workspace / "activation.port").exists(), "original-owner-endpoint-not-released")
        if result is not None:
            cases.assert_fixed_behavior(result)  # Authentic baseline RED AFTER retained witness/known cleanup.
        return 0

    def finish(self, code, error=None):
        hold = getattr(self, "caller_collection_hold", None)
        if hold is not None and getattr(hold, "state", None) != "released":
            self.park("original-caller-collector-hold-not-released", error)
        if any(child.terminal is None for child in self.children):
            self.park("unfinished-child-at-scenario-boundary", error)
        self.guard()
        for pin in self.pins:
            if not pin.directory:
                pin.digest()
        self.event("owner-terminal", {"exitCode": code, "errorClass": type(error).__name__ if error else None,
            "failure": failure_detail(error) if error else None,
            "allOriginalChildrenTerminalAndEof": True, "sourceClosing": True,
            "fullWindowsAcceptance": False})
        for pin in reversed(self.pins):
            pin.close()
        for log_handle in getattr(self, "log_handles", []):
            self.native.k.CloseHandle(log_handle)


def _known_envelope(result):
    """The JSON envelope of one completed public call, or None."""
    try:
        body = json.loads(result.stdout)
    except ValueError:
        return None
    return body if type(body) is dict and result.stderr == "" else None


def _await_known_exit(owner, child, error, reason):
    until = time.monotonic() + KNOWN_FAILURE_EXIT_SECONDS
    while True:
        terminal = child.observe()
        if terminal is not None:
            return terminal
        if time.monotonic() >= until:
            owner.park(reason, error)
        time.sleep(0.1)


def _quit_known_serve(owner, child, identity, error):
    """The journaled public quit a pass sends, to the controller of this serve's own workspace.

    The primary serve's controller is the one the owner admitted; a second serve a case
    started is named by status, which never starts an owner. Sent once, never replayed.
    """
    workspace = Path(child.argv[2])
    bound = ("--controller-id", identity) if identity is not None else ()
    status = owner.invoke(workspace, "--json", *bound, "status")
    body = _known_envelope(status)
    if not (status.returncode == 0 and body is not None and body.get("schemaVersion") == 1
            and body.get("code") == "OK" and body.get("ok") is True and body.get("final") is True
            and type(body.get("controllerId")) is str and body["controllerId"] != ""
            and (identity is None or body["controllerId"] == identity)
            and type(body.get("data")) is dict and body["data"].get("runtimeRunning") is False):
        owner.park("known-failure-quit-admission", error)
    controller = body["controllerId"]
    owner.event("known-failure-quit-intent", {"child": child.ordinal, "pid": child.pid,
        "birthFileTimeUtc": child.birth, "controllerId": controller, "replayAllowed": False})
    result = owner.invoke(workspace, "--json", "--controller-id", controller, "quit")
    body = _known_envelope(result)
    if not (result.returncode == 0 and body is not None and body.get("controllerId") == controller
            and body.get("final") is True):
        owner.park("known-failure-quit-not-acknowledged", error)
    terminal = _await_known_exit(owner, child, error, "known-failure-serve-exit-unknown")
    owner.event("known-failure-serve-closed", {"child": child.ordinal, "controllerId": controller,
        "terminal": terminal, "endpointReleased": not (workspace / "activation.port").exists()})


def close_known_failure(owner, workspace, identity, serve, error):
    """Close what the owner started after a case oracle failed; the caller then exits 1.

    The reboot actions retire their children the same way. No child process has an open
    outcome here, and the product answers a quit BUSY while any mutation is in flight. A
    read-only operation still pending, such as an admitted --async diagnostics export whose
    report stays in the owner's memory, ends with its owner. Each serve owner ends by the
    journaled public quit to its own controller, the quit a pass sends. A serve a case already
    sent a quit, whatever that quit answered, is never sent another: the closing only waits
    for its exit. A stream client is bound to the one serve's controller and only polls it,
    never starting or rebinding an owner (DesktopCliStream), so it ends by its own known close
    once that owner is gone; a child that already exited is collected. Nothing is killed,
    signalled or replayed. Any other live child (a public call, the console helper), a quit
    that is refused or not acknowledged, or a child that does not exit in time parks, keeping
    every original.
    """
    try:
        cli, reason = owner.request["cliPath"], str(error)[:120]
        serves, streams, ended = [], [], []
        for child in owner.children:
            if child.terminal is not None:
                continue
            argv, console = tuple(child.argv), getattr(child, "new_console", False) is True
            if child.process.poll() is not None:
                ended.append(child)
            elif (not console and len(argv) == 4 and argv[:2] == (cli, "--state-dir") and argv[3] == "serve"
                    and Path(argv[2]).parent == owner.root and (child is serve) == (argv[2] == str(workspace))):
                serves.append(child)
            elif (console and child.label.startswith("stream-")
                    and argv[:5] == (cli, "--state-dir", str(workspace), "--controller-id", identity)):
                streams.append(child)
            else:
                owner.park("known-failure-child-outcome-open", error)
        # Every quit a case sent went through this owner, so its custody names it, and its answer
        # may have been unknown (TIMEOUT, OUTCOME_UNKNOWN): that serve is awaited, never quit again.
        # Only a quit sent after a serve started can have reached it: a workspace reopened by a later
        # serve, after its first owner was quit, is quit like any other.
        case_quits = {}
        for child in owner.children:
            argv = tuple(child.argv)
            if len(argv) > 3 and argv[:2] == (cli, "--state-dir") and argv[-1] == "quit":
                case_quits.setdefault(argv[2].casefold(), []).append(child.ordinal)

        def quits_after(child):
            return [ordinal for ordinal in case_quits.get(child.argv[2].casefold(), ()) if ordinal > child.ordinal]
        awaited = [child for child in serves if quits_after(child)]
        serves = [child for child in serves if not quits_after(child)]
        serves.sort(key=lambda child: child is serve)  # A case's second serve first, the one the streams poll last.
        owner.event("known-failure-closing", {"action": owner.request["action"], "reason": reason,
            "errorClass": type(error).__name__, "failure": failure_detail(error),
            "quit": [child.ordinal for child in serves],
            "caseQuit": [child.ordinal for child in awaited],
            "ownClose": [child.ordinal for child in streams], "exited": [child.ordinal for child in ended],
            "replayAllowed": False})
        for child in ended:
            _await_known_exit(owner, child, error, "known-failure-exited-child-eof-unknown")
        for child in awaited:
            terminal = _await_known_exit(owner, child, error, "known-failure-case-quit-exit-unknown")
            owner.event("known-failure-serve-closed", {"child": child.ordinal, "controllerId": None,
                "caseQuitChildren": quits_after(child), "terminal": terminal,
                "endpointReleased": not (Path(child.argv[2]) / "activation.port").exists()})
        for child in serves:
            _quit_known_serve(owner, child, identity if child is serve else None, error)
        for child in streams:
            _await_known_exit(owner, child, error, "known-failure-stream-exit-unknown")
        require(all(child.terminal is not None for child in owner.children), "known-failure-all-children-terminal")
        owner.event("known-failure-closed", {"action": owner.request["action"], "reason": reason,
            "children": [{"child": child.ordinal, "label": child.label, "exitCode": child.terminal["exitCode"]}
                         for child in (*ended, *awaited, *serves, *streams)],
            "replayAllowed": False, "nativeAcceptanceComplete": False})
    except Exception as closing:
        owner.park("known-failure-closing-unknown", closing)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--request", required=True)
    parser.add_argument("--request-sha256", required=True)
    parser.add_argument("--request-pin-base64", required=True)
    args = parser.parse_args()
    # The PS parent holds this request's native file handle/identity across this
    # initial read; the worker immediately repins the same request from filePins.
    native = Native()
    request_record = json.loads(base64.b64decode(args.request_pin_base64, validate=True))
    require(request_record["path"] == args.request and request_record["sha256"] == args.request_sha256,
            "parent-request-pin-arguments")
    request_pin = Pin(native, request_record)
    raw = request_pin.digest(True, maximum=4 * 1024 * 1024)
    request = json.loads(raw)
    owner = Owner(request, request_pin)
    try:
        result = owner.run()
    except BaseException as error:
        if any(child.terminal is None for child in owner.children):
            owner.park("scenario-failure-with-retained-child", error)
        try:
            owner.finish(1, error)
        except BaseException as closing_error:
            owner.park("failure-closing-unknown", closing_error)
        return 1
    try:
        owner.finish(result)
    except BaseException as closing_error:
        owner.park("terminal-closing-unknown", closing_error)
    return result


if __name__ == "__main__":
    raise SystemExit(main())
