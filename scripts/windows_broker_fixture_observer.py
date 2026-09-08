#!/usr/bin/env python3
"""Read-only process observations for an explicitly identified Windows fixture.

This is test tooling, never an installer or a source of product admission authority.
It cannot launch, stop, elevate, or resume a process. Native APIs load only when the
Windows adapter is constructed, so the decision regressions run on every host.
"""

from __future__ import annotations

import argparse
from contextlib import ExitStack
import ctypes
from ctypes import wintypes
import hashlib
import json
import ntpath
from pathlib import Path
import re
import sys


def select_runtime(children, expected):
    # Console plumbing can be another direct child. Only the captured runtime
    # identity selects the runtime; every auxiliary observation remains visible.
    matches = [child for child in children if child["pid"] == expected["pid"]]
    if len(matches) != 1:
        raise ValueError("Missing or duplicate retained runtime identity")
    child = matches[0]
    if child["creationFileTime"] != expected["creationFileTime"] or child["sha256"] != expected["sha256"]:
        raise ValueError("Retained runtime generation/image differs")
    return child


def classify_retained_process(expected_creation, times, wait, image):
    actual = times()
    if actual["creationFileTime"] != expected_creation:
        return {"originalAbsent": True, "reason": "different-generation", "times": actual}
    state = wait()
    if state == 0:
        return {"originalAbsent": True, "reason": "same-handle-signaled", "times": actual}
    if state != 258:
        raise ValueError("Process wait state is unknown")
    return {"originalAbsent": False, "reason": "same-generation-live", "times": actual, "actual": image()}


def same_path(left, right):
    return ntpath.normcase(ntpath.normpath(left)) == ntpath.normcase(ntpath.normpath(right))


def observe_exit(expected, native):
    """Use one retained handle per generation; errors never certify disappearance."""
    results = []
    for item in expected:
        record = {"pid": item["pid"], "creationFileTime": item["creationFileTime"]}
        try:
            with native.open_process(item["pid"], 0x101000) as process:
                record.update(classify_retained_process(item["creationFileTime"], process.times,
                                                       process.wait, process.describe))
        except OSError as error:
            record.update(originalAbsent=None, errorType=type(error).__name__,
                          winerror=getattr(error, "winerror", None))
            # Only a failed OpenProcess can establish this PID does not exist.
            if isinstance(error, ProcessAbsent):
                record.update(originalAbsent=True, reason="open-process-absent")
        except (ValueError, KeyError) as error:
            record.update(originalAbsent=None, errorType=type(error).__name__)
        results.append(record)
    return results


def observe_ready(request, native):
    """Inspect the supplied helper and exact child, recording auxiliary children."""
    with ExitStack() as held:
        owner = held.enter_context(native.open_process(request["owner"]["pid"], 0x101000))
        owner_record = owner.describe()
        require_identity(owner_record, request["owner"])
        if owner.wait() != 258 or owner_record["token"]["elevated"] != 0:
            raise ValueError("Expected running ordinary owner")
        helper = held.enter_context(native.open_process(request["helper"]["pid"], 0x101410))
        helper_record = helper.describe()
        require_identity(helper_record, request["helper"])
        if helper.wait() != 258 or helper_record["token"]["elevated"] != 1:
            raise ValueError("Expected running elevated helper")
        if helper_record["token"]["sid"] != owner_record["token"]["sid"]:
            raise ValueError("Expected the admitted original owner token")
        modules = helper.modules()
        if modules != helper.modules():
            raise ValueError("Loaded module inventory changed during observation")
        for module in modules:
            module.update(native.file_identity(module["path"]))
        children = []
        for entry in native.processes():
            if entry["parentPid"] != request["helper"]["pid"]:
                continue
            process = held.enter_context(native.open_process(entry["pid"], 0x101000))
            child = process.describe()
            child.update(entry)
            child.update(native.file_identity(child["image"]))
            if process.wait() != 258:
                raise ValueError("A captured child exited during observation")
            if entry["pid"] == request["runtime"]["pid"]:
                child["threadObservations"] = native.threads(entry["pid"])
            children.append(child)
        selected = select_runtime(children, request["runtime"])
        if owner.wait() != 258 or helper.wait() != 258:
            raise ValueError("Owner or helper exited during observation")
        return {"owner": owner_record, "helper": helper_record, "runtime": selected,
                "auxiliaryChildren": [child for child in children if child is not selected],
                "modules": modules, "moduleInventoryStable": True, "readOnly": True}


def require_identity(actual, expected):
    if actual["creationFileTime"] != expected["creationFileTime"]:
        raise ValueError("Process generation differs")
    if not same_path(actual["image"], expected["image"]) or actual["sha256"] != expected["sha256"]:
        raise ValueError("Process image differs")
    if actual["token"]["sid"] != expected["sid"]:
        raise ValueError("Process token differs")


class ProcessAbsent(OSError):
    """Only WindowsNative.open_process constructs this after native error87."""


class WindowsNative:
    def __init__(self):
        if sys.platform != "win32":
            raise OSError("Windows native observation is unavailable on this host")
        self.k = ctypes.WinDLL("kernel32", use_last_error=True)
        self.a = ctypes.WinDLL("advapi32", use_last_error=True)
        self.p = ctypes.WinDLL("psapi", use_last_error=True)
        self.n = ctypes.WinDLL("ntdll", use_last_error=True)
        self.close = self.api(self.k, "CloseHandle", wintypes.BOOL, [wintypes.HANDLE])
        self.open = self.api(self.k, "OpenProcess", wintypes.HANDLE,
                             [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD])
        self.get_times = self.api(self.k, "GetProcessTimes", wintypes.BOOL,
                                 [wintypes.HANDLE] + [ctypes.POINTER(ctypes.c_ulonglong)] * 4)
        self.wait_for = self.api(self.k, "WaitForSingleObject", wintypes.DWORD,
                                [wintypes.HANDLE, wintypes.DWORD])

    @staticmethod
    def api(library, name, result, arguments):
        function = getattr(library, name)
        function.restype, function.argtypes = result, arguments
        return function

    @staticmethod
    def check(value):
        if not value:
            raise ctypes.WinError(ctypes.get_last_error())

    @staticmethod
    def file_identity(path):
        with open(path, "rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        return {"sha256": digest, "sizeBytes": Path(path).stat().st_size}

    def open_process(self, pid, access):
        handle = self.open(access, False, pid)
        if not handle:
            code = ctypes.get_last_error()
            if code == 87:
                raise ProcessAbsent("OpenProcess reports no process for this PID")
            raise ctypes.WinError(code)
        return ProcessPin(self, handle)

    def token(self, process):
        handle = wintypes.HANDLE()
        open_token = self.api(self.a, "OpenProcessToken", wintypes.BOOL,
                             [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)])
        query = self.api(self.a, "GetTokenInformation", wintypes.BOOL,
                         [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
                          ctypes.POINTER(wintypes.DWORD)])
        convert = self.api(self.a, "ConvertSidToStringSidW", wintypes.BOOL,
                           [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)])
        free = self.api(self.k, "LocalFree", ctypes.c_void_p, [ctypes.c_void_p])
        self.check(open_token(process, 8, ctypes.byref(handle)))
        try:
            needed = wintypes.DWORD()
            query(handle, 1, None, 0, ctypes.byref(needed))
            if not ctypes.sizeof(ctypes.c_void_p) <= needed.value <= 65536:
                raise ValueError("Token query bounds")
            data = ctypes.create_string_buffer(needed.value)
            self.check(query(handle, 1, data, len(data), ctypes.byref(needed)))
            sid = wintypes.LPWSTR()
            self.check(convert(ctypes.c_void_p.from_buffer(data).value, ctypes.byref(sid)))
            try:
                result = {"sid": sid.value}
            finally:
                if free(ctypes.cast(sid, ctypes.c_void_p)):
                    raise OSError("LocalFree failed")
            for name, kind in [("elevationType", 18), ("elevated", 20), ("sessionId", 12)]:
                value = wintypes.DWORD()
                self.check(query(handle, kind, ctypes.byref(value), 4, ctypes.byref(needed)))
                if needed.value != 4:
                    raise ValueError("Token scalar query bounds")
                result[name] = value.value
            return result
        finally:
            self.check(self.close(handle))

    def snapshot(self, flags, entry_type, first_name, next_name):
        create = self.api(self.k, "CreateToolhelp32Snapshot", wintypes.HANDLE,
                          [wintypes.DWORD, wintypes.DWORD])
        first = self.api(self.k, first_name, wintypes.BOOL,
                         [wintypes.HANDLE, ctypes.POINTER(entry_type)])
        following = self.api(self.k, next_name, wintypes.BOOL,
                             [wintypes.HANDLE, ctypes.POINTER(entry_type)])
        handle = create(flags, 0)
        if handle == ctypes.c_void_p(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            entry = entry_type()
            entry.size = ctypes.sizeof(entry)
            success = first(handle, ctypes.byref(entry))
            while success:
                yield entry
                success = following(handle, ctypes.byref(entry))
            if ctypes.get_last_error() != 18:
                raise ctypes.WinError(ctypes.get_last_error())
        finally:
            self.check(self.close(handle))

    def processes(self):
        class Entry(ctypes.Structure):
            _fields_ = [("size", wintypes.DWORD), ("usage", wintypes.DWORD),
                        ("pid", wintypes.DWORD), ("heap", ctypes.c_size_t),
                        ("module", wintypes.DWORD), ("threads", wintypes.DWORD),
                        ("parentPid", wintypes.DWORD), ("priority", wintypes.LONG),
                        ("flags", wintypes.DWORD), ("name", wintypes.WCHAR * 260)]
        return [{"pid": entry.pid, "parentPid": entry.parentPid, "name": entry.name}
                for entry in self.snapshot(2, Entry, "Process32FirstW", "Process32NextW")]

    def threads(self, pid):
        class Entry(ctypes.Structure):
            _fields_ = [("size", wintypes.DWORD), ("usage", wintypes.DWORD),
                        ("tid", wintypes.DWORD), ("pid", wintypes.DWORD),
                        ("priority", wintypes.LONG), ("delta", wintypes.LONG),
                        ("flags", wintypes.DWORD)]
        open_thread = self.api(self.k, "OpenThread", wintypes.HANDLE,
                               [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD])
        process_id = self.api(self.k, "GetProcessIdOfThread", wintypes.DWORD, [wintypes.HANDLE])
        thread_id = self.api(self.k, "GetThreadId", wintypes.DWORD, [wintypes.HANDLE])
        times = self.api(self.k, "GetThreadTimes", wintypes.BOOL,
                         [wintypes.HANDLE] + [ctypes.POINTER(ctypes.c_ulonglong)] * 4)
        query = self.api(self.n, "NtQueryInformationThread", wintypes.LONG,
                         [wintypes.HANDLE, wintypes.ULONG, ctypes.c_void_p, wintypes.ULONG,
                          ctypes.POINTER(wintypes.ULONG)])
        result = []
        for entry in self.snapshot(4, Entry, "Thread32First", "Thread32Next"):
            if entry.pid != pid:
                continue
            handle = open_thread(0x840, False, entry.tid)
            self.check(handle)
            try:
                if process_id(handle) != pid or thread_id(handle) != entry.tid:
                    raise ValueError("Retained thread identity differs")
                observed = [ctypes.c_ulonglong() for _ in range(4)]
                self.check(times(handle, *[ctypes.byref(value) for value in observed]))
                count, returned = wintypes.ULONG(), wintypes.ULONG()
                status = query(handle, 35, ctypes.byref(count), 4, ctypes.byref(returned))
                result.append({"tid": entry.tid, "creationFileTime": observed[0].value,
                               "kernelTime100ns": observed[2].value, "userTime100ns": observed[3].value,
                               "queryStatus": status & 0xffffffff, "returnedBytes": returned.value,
                               "suspendCount": count.value if status >= 0 and returned.value in (0, 4) else None})
            finally:
                self.check(self.close(handle))
        return result


class ProcessPin:
    def __init__(self, native, handle):
        self.native, self.handle = native, handle

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.native.check(self.native.close(self.handle))
        self.handle = None

    def times(self):
        values = [ctypes.c_ulonglong() for _ in range(4)]
        self.native.check(self.native.get_times(self.handle, *[ctypes.byref(value) for value in values]))
        return dict(zip(["creationFileTime", "exitFileTime", "kernelTime100ns", "userTime100ns"],
                        [value.value for value in values]))

    def wait(self):
        return self.native.wait_for(self.handle, 0)

    def describe(self):
        query = self.native.api(self.native.k, "QueryFullProcessImageNameW", wintypes.BOOL,
                                [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR,
                                 ctypes.POINTER(wintypes.DWORD)])
        text = ctypes.create_unicode_buffer(32768)
        length = wintypes.DWORD(len(text))
        self.native.check(query(self.handle, 0, text, ctypes.byref(length)))
        if not 0 < length.value < len(text):
            raise ValueError("Process image query bounds")
        return {"image": text.value, **self.times(), "token": self.native.token(self.handle),
                **self.native.file_identity(text.value)}

    def modules(self):
        enum = self.native.api(self.native.p, "EnumProcessModulesEx", wintypes.BOOL,
                               [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
                                ctypes.POINTER(wintypes.DWORD), wintypes.DWORD])
        name = self.native.api(self.native.p, "GetModuleFileNameExW", wintypes.DWORD,
                               [wintypes.HANDLE, wintypes.HMODULE, wintypes.LPWSTR, wintypes.DWORD])
        slots, needed = (wintypes.HMODULE * 4096)(), wintypes.DWORD()
        self.native.check(enum(self.handle, slots, ctypes.sizeof(slots), ctypes.byref(needed), 3))
        if needed.value > ctypes.sizeof(slots) or needed.value % ctypes.sizeof(wintypes.HMODULE):
            raise ValueError("Module inventory bounds")
        result = []
        for index in range(needed.value // ctypes.sizeof(wintypes.HMODULE)):
            text = ctypes.create_unicode_buffer(32768)
            count = name(self.handle, slots[index], text, len(text))
            if not 0 < count < len(text) - 1:
                raise OSError("Module path query unavailable")
            result.append({"base": int(slots[index]), "path": text.value})
        return result


def read_request(path):
    with open(path, "rb") as stream:
        raw = stream.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        raise ValueError("Observation metadata exceeds its bound")
    request = json.loads(raw.decode("utf-8"))
    if request.get("operation") not in {"ready", "exit"}:
        raise ValueError("A fixed read-only observation operation is required")
    identities = request.get("processes", []) if request["operation"] == "exit" else [request[key] for key in ("owner", "helper", "runtime")]
    if not 0 < len(identities) <= 128:
        raise ValueError("Observation identity count is invalid")
    for identity in identities:
        if type(identity["pid"]) is not int or not 0 < identity["pid"] <= 0xffffffff:
            raise ValueError("Positive native PID required")
        if type(identity["creationFileTime"]) is not int or not 0 < identity["creationFileTime"] < 2**64:
            raise ValueError("Native creation identity required")
        if request["operation"] == "ready" and not re.fullmatch(r"[a-f0-9]{64}", identity["sha256"]):
            raise ValueError("Exact captured image digest required")
    return request


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request", type=Path, required=True)
    args = parser.parse_args()
    request = read_request(args.request)
    native = WindowsNative()
    if request["operation"] == "ready":
        result = observe_ready(request, native)
        success = True
    else:
        result = {"processes": observe_exit(request["processes"], native), "readOnly": True}
        success = all(item["originalAbsent"] is True for item in result["processes"])
    print(json.dumps(result), flush=True)
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
