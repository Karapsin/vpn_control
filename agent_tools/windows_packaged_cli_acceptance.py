"""Fixed installed CP117 disconnected public-CLI acceptance adapter.

This is a direct guest adapter, not an SSH dispatcher or an artifact registry.
The coordinator must first admit its sole CP117 guest/resource/lease and obtain
the expected inventories from verified package and Python artifacts. ``prepare``
is data-only. ``start`` is Windows-only and never installs missing prerequisites.
The unchanged public harness owns its fresh temporary workspaces and children.
Observation always uses the original retained process handle; unknown is not a
permission to start another run. Full Windows, GUI, VPN and update acceptance
are deliberately not projected from this disconnected harness.
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import selectors
import stat
import struct
import subprocess
import time
from typing import Any, Mapping
import uuid
import weakref

SID = "S-1-5-21-2404255130-2183793310-3766671872-1002"
INSTALL_ROOT = Path(r"C:\Users\vpncp117\AppData\Local\vpn-control")
PYTHON_ROOT = Path(r"C:\Users\vpncp117\AppData\Local\Programs\Python\Python313")
TASK_ROOT = Path(r"C:\Users\vpncp117\AppData\Local\VpnControl\mcp-installed-cli")
HARNESS_FILES = ("test_packaged_cli.py", "windows_install_admission_diagnostic.py")
SCOPE = "installed-windows-disconnected-public-cli-v1"
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_SOURCE = re.compile(r"[0-9a-f]{40}\Z")
_VERSION = re.compile(r"(?:[1-9]|1[0-9])\.(?:0|[1-9]|1[0-9])\.(?:0|[1-9]|1[0-9])\Z")
_MAX_STREAM = 4 * 1024 * 1024


@dataclass(frozen=True)
class _NativeStartAdmission:
    """Process-local evidence minted only by the complete native start path."""
    process: Any
    birth: int
    intent_bytes: bytes
    argv: tuple[str, ...]
    pins: tuple[Any, ...]
    trees: tuple[tuple[Path, frozenset[str]], ...]


# A JSON intent, constructor argument or caller bool cannot populate this map.
# Do not serialize it or accept an admission object through an MCP request.
_NATIVE_STARTS: weakref.WeakKeyDictionary = weakref.WeakKeyDictionary()


class AcceptanceError(ValueError):
    """An admission or retained observation is unsafe or incomplete."""


class PostSubmissionUnknown(AcceptanceError):
    """Retain the original observer when even durable UNKNOWN capture refuses.

    Callers must keep ``run`` alive; this exception never permits another start.
    """
    def __init__(self, run: "RetainedRun"):
        super().__init__("post-submission-retention-unknown")
        self.run = run


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise AcceptanceError(code)


def _generation(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _parent(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)


def _ordinary(info: os.stat_result, directory: bool = False) -> bool:
    return ((stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
            and not stat.S_ISLNK(info.st_mode)
            and not (getattr(info, "st_file_attributes", 0) & 0x400))


def _parents(path: Path) -> dict[Path, tuple[int, ...]]:
    result = {}
    for parent in path.parents:
        info = parent.lstat()
        _require(_ordinary(info, True), "parent-reparse-or-type")
        result[parent] = _parent(info)
    return result


def _open_read(path: Path) -> int:
    if os.name != "nt":
        return os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    # Open the reparse point itself and deny concurrent writers/deletion. Keep
    # the resulting handle held for the whole admitted harness execution.
    import msvcrt
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                  wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE)
    kernel.CreateFileW.restype = wintypes.HANDLE
    handle = kernel.CreateFileW(str(path), 0x80000000, 1, None, 3, 0x00200000, None)
    _require(handle != ctypes.c_void_p(-1).value, "file-open-unavailable")
    try:
        return msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
    except Exception:
        kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
        kernel.CloseHandle(handle)
        raise


@dataclass
class FilePin:
    path: Path
    fd: int
    generation: tuple[int, ...]
    parents: dict[Path, tuple[int, ...]]
    sha256: str
    size: int

    def current(self) -> None:
        _require(_generation(os.fstat(self.fd)) == self.generation
                 and _generation(self.path.lstat()) == self.generation,
                 "file-generation-changed")
        for path, expected in self.parents.items():
            _require(_parent(path.lstat()) == expected and _ordinary(path.lstat(), True),
                     "parent-generation-changed")

    def bytes(self, maximum: int) -> bytes:
        _require(self.size <= maximum, "source-size")
        self.current()
        os.lseek(self.fd, 0, os.SEEK_SET)
        chunks = []
        remaining = self.size
        while remaining:
            block = os.read(self.fd, min(131072, remaining))
            _require(bool(block), "source-short-read")
            chunks.append(block)
            remaining -= len(block)
        _require(not os.read(self.fd, 1), "source-trailing-bytes")
        data = b"".join(chunks)
        _require(hashlib.sha256(data).hexdigest() == self.sha256, "source-digest-changed")
        self.current()
        return data

    def close(self) -> None:
        os.close(self.fd)


def _pin(path: Path, expected: Mapping[str, Any], maximum: int = 512 * 1024 * 1024) -> FilePin:
    _require(isinstance(expected, Mapping) and set(expected) == {"sha256", "sizeBytes"}
             and isinstance(expected["sha256"], str) and bool(_SHA.fullmatch(expected["sha256"]))
             and type(expected["sizeBytes"]) is int and 0 <= expected["sizeBytes"] <= maximum,
             "file-inventory-schema")
    parents = _parents(path)
    named = path.lstat()
    _require(_ordinary(named) and named.st_nlink == 1 and named.st_size == expected["sizeBytes"],
             "file-type-link-size")
    fd = _open_read(path)
    try:
        opened = os.fstat(fd)
        _require(_ordinary(opened) and opened.st_nlink == 1
                 and _generation(opened) == _generation(named), "file-open-generation")
        digest = hashlib.sha256()
        count = 0
        while block := os.read(fd, 131072):
            count += len(block)
            _require(count <= maximum, "file-size-limit")
            digest.update(block)
        _require(count == expected["sizeBytes"] and digest.hexdigest() == expected["sha256"],
                 "file-digest")
        pin = FilePin(path, fd, _generation(opened), parents, digest.hexdigest(), count)
        pin.current()
        return pin
    except Exception:
        os.close(fd)
        raise


def _inventory(value: Any) -> dict[str, dict[str, Any]]:
    _require(isinstance(value, dict) and 1 <= len(value) <= 8192, "inventory-count")
    result = {}
    folded = set()
    for name, identity in value.items():
        _require(isinstance(name, str) and bool(name) and "\\" not in name and ":" not in name
                 and len(name) <= 240 and not any(x in name for x in ("\x00", "//")), "inventory-path")
        parts = PurePosixPath(name).parts
        _require(not name.startswith("/") and all(x not in {".", ".."} and not x.endswith((".", " "))
                 for x in parts) and str(PurePosixPath(name)) == name, "inventory-path")
        reserved = {"CON", "PRN", "AUX", "NUL"} | {prefix + str(i) for prefix in ("COM", "LPT") for i in range(1, 10)}
        _require(not any(x.split(".", 1)[0].upper() in reserved for x in parts), "inventory-device-path")
        _require(name.casefold() not in folded, "inventory-case-alias")
        folded.add(name.casefold())
        _require(isinstance(identity, dict) and set(identity) == {"sha256", "sizeBytes"}
                 and isinstance(identity["sha256"], str) and bool(_SHA.fullmatch(identity["sha256"]))
                 and type(identity["sizeBytes"]) is int and 0 <= identity["sizeBytes"] <= 512 * 1024 * 1024,
                 "inventory-identity")
        result[name] = dict(identity)
    return result


def prepare(request: Mapping[str, Any]) -> dict[str, Any]:
    """Validate a coordinator-owned expected inventory; never grant execution."""
    required = {"correlationId", "sourceSha", "sourceFingerprint", "packageArtifactId", "productVersion",
                "productCode", "sessionId", "installedFiles", "pythonFiles", "harnessFiles"}
    _require(isinstance(request, Mapping) and set(request) == required, "request-schema")
    corr = request["correlationId"]
    _require(isinstance(corr, str) and str(uuid.UUID(corr)) == corr, "correlation")
    _require(isinstance(request["sourceSha"], str) and bool(_SOURCE.fullmatch(request["sourceSha"]))
             and isinstance(request["sourceFingerprint"], str) and bool(_SHA.fullmatch(request["sourceFingerprint"]))
             and isinstance(request["packageArtifactId"], str)
             and bool(re.fullmatch(r"sha256-[0-9a-f]{64}", request["packageArtifactId"])), "package-provenance")
    _require(isinstance(request["productVersion"], str) and bool(_VERSION.fullmatch(request["productVersion"])), "version")
    _require(isinstance(request["productCode"], str)
             and bool(re.fullmatch(r"\{[0-9A-F]{8}-(?:[0-9A-F]{4}-){3}[0-9A-F]{12}\}", request["productCode"])), "product-code")
    _require(type(request["sessionId"]) is int and 1 <= request["sessionId"] <= 65535, "session")
    inventories = {key: _inventory(request[key]) for key in ("installedFiles", "pythonFiles", "harnessFiles")}
    required_files = {"vpn-control.exe", "vpn-control-cli.exe", "app/vpn-control.cfg", "app/vpn-control-cli.cfg",
                      "app/desktopApp-" + request["productVersion"] + ".jar", "runtime/bin/java.exe",
                      "app/native/windows-amd64/vpn-control-install-helper.exe",
                      "app/native/windows-amd64/vpn-control-vpn-broker.exe"}
    _require(required_files <= inventories["installedFiles"].keys(), "installed-image-incomplete")
    _require({"python.exe", "python313.dll"} <= inventories["pythonFiles"].keys(), "guest-python-prerequisite")
    _require(set(inventories["harnessFiles"]) == set(HARNESS_FILES), "harness-source-closure")
    _require(sum(len(items) for items in inventories.values()) <= 4096, "held-inventory-resource-limit")
    return {**dict(request), **inventories, "scope": SCOPE, "architecture": "amd64",
            "nativeActionAllowed": False, "fullWindowsAcceptance": False,
            "externalAdmissionRequired": ["sole-CP117-generation", "resource", "campaign-lease",
                                          "verified-package-registry-and-inventory", "verified-guest-python-inventory",
                                          "guest-interpreter-descriptor-capacity"]}


def _tree(root: Path) -> set[str]:
    _require(_ordinary(root.lstat(), True), "tree-root")
    result = set()
    for directory, names, files in os.walk(root, followlinks=False):
        for name in names:
            _require(_ordinary((Path(directory) / name).lstat(), True), "tree-directory-reparse")
        for name in files:
            item = Path(directory) / name
            _require(_ordinary(item.lstat()), "tree-file-reparse")
            result.add(item.relative_to(root).as_posix())
            _require(len(result) <= 8192, "tree-limit")
    return result


def _amd64(pin: FilePin) -> None:
    os.lseek(pin.fd, 0, os.SEEK_SET)
    head = os.read(pin.fd, 64)
    _require(len(head) == 64 and head[:2] == b"MZ", "pe-header")
    offset = struct.unpack_from("<I", head, 60)[0]
    _require(64 <= offset <= min(pin.size - 6, 1024 * 1024), "pe-offset")
    os.lseek(pin.fd, offset, os.SEEK_SET)
    native = os.read(pin.fd, 6)
    _require(native == b"PE\0\0\x64\x86", "pe-not-amd64")
    pin.current()


def _native_owner(expected_session: int) -> dict[str, Any]:
    _require(os.name == "nt", "windows-native-required")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    token = wintypes.HANDLE()
    advapi.OpenProcessToken.argtypes = (wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE))
    advapi.GetTokenInformation.argtypes = (wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID,
                                         wintypes.DWORD, ctypes.POINTER(wintypes.DWORD))
    _require(bool(advapi.OpenProcessToken(kernel.GetCurrentProcess(), 8, ctypes.byref(token))), "token-open")
    try:
        def info(kind: int) -> bytes:
            size = wintypes.DWORD()
            advapi.GetTokenInformation(token, kind, None, 0, ctypes.byref(size))
            _require(0 < size.value <= 65536, "token-size")
            buffer = ctypes.create_string_buffer(size.value)
            _require(bool(advapi.GetTokenInformation(token, kind, buffer, size, ctypes.byref(size))), "token-read")
            return buffer
        user = info(1)
        sid_pointer = ctypes.cast(user, ctypes.POINTER(ctypes.c_void_p))[0]
        text = wintypes.LPWSTR()
        advapi.ConvertSidToStringSidW.argtypes = (ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR))
        _require(bool(advapi.ConvertSidToStringSidW(sid_pointer, ctypes.byref(text))), "token-sid")
        try:
            sid = text.value
        finally:
            kernel.LocalFree.argtypes = (ctypes.c_void_p,)
            kernel.LocalFree(ctypes.cast(text, ctypes.c_void_p))
        session = struct.unpack("<I", info(12).raw[:4])[0]
        elevated = struct.unpack("<I", info(20).raw[:4])[0]
        _require(sid == SID and session == expected_session and elevated == 0, "ordinary-original-user-required")
        return {"sid": sid, "sessionId": session, "elevated": False}
    finally:
        kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
        kernel.CloseHandle(token)


def _private_mkdir(path: Path) -> None:
    if os.name != "nt":
        path.mkdir(mode=0o700)
        return
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    descriptor = ctypes.c_void_p()
    advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = (
        wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.DWORD))
    sddl = "O:" + SID + "D:P(A;OICI;FA;;;" + SID + ")(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
    _require(bool(advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, ctypes.byref(descriptor), None)), "private-acl-build")
    class Attributes(ctypes.Structure):
        _fields_ = [("length", wintypes.DWORD), ("descriptor", ctypes.c_void_p), ("inherit", wintypes.BOOL)]
    attrs = Attributes(ctypes.sizeof(Attributes), descriptor, False)
    kernel.CreateDirectoryW.argtypes = (wintypes.LPCWSTR, ctypes.POINTER(Attributes))
    try:
        _require(bool(kernel.CreateDirectoryW(str(path), ctypes.byref(attrs))), "private-directory-create")
    finally:
        kernel.LocalFree.argtypes = (ctypes.c_void_p,)
        kernel.LocalFree(descriptor)


def _write_new(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(fd)
    finally:
        os.close(fd)


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _build_argv(python: Path, harness: Path, launcher: Path, version: str) -> tuple[str, ...]:
    # -E ignores Python environment injection while preserving the script's
    # directory for its fixed admission-diagnostic sibling import.
    return (str(python), "-E", "-s", "-B", str(harness), "--launcher", str(launcher), "--expected-version", version)


def _birth(process: subprocess.Popen[bytes]) -> int | None:
    if os.name == "nt":
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.GetProcessTimes.argtypes = (wintypes.HANDLE, ctypes.POINTER(wintypes.FILETIME),
            ctypes.POINTER(wintypes.FILETIME), ctypes.POINTER(wintypes.FILETIME), ctypes.POINTER(wintypes.FILETIME))
        creation, exit_time, kernel_time, user_time = (wintypes.FILETIME() for _ in range(4))
        if kernel.GetProcessTimes(wintypes.HANDLE(process._handle), ctypes.byref(creation), ctypes.byref(exit_time),
                                  ctypes.byref(kernel_time), ctypes.byref(user_time)):
            return (creation.dwHighDateTime << 32) | creation.dwLowDateTime
    elif Path("/proc", str(process.pid), "stat").exists():
        text = Path("/proc", str(process.pid), "stat").read_text()
        return int(text[text.rfind(")") + 2:].split()[19])
    return None


def _raw_files(directory: Path) -> dict[str, Any]:
    outputs = {}
    try:
        for name in ("stdout", "stderr"):
            fd = os.open(directory / (name + ".private"), os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
            outputs[name] = os.fdopen(fd, "wb")
        return outputs
    except Exception:
        for stream in outputs.values():
            stream.close()
        raise


class RetainedRun:
    """Own one original harness handle and its unsealed stdout/stderr readers."""
    def __init__(self, process: subprocess.Popen[bytes] | None, directory: Path, intent: Mapping[str, Any], pins: list[FilePin],
                 trees: Mapping[Path, set[str]] | None = None, outputs: dict[str, Any] | None = None):
        self.process, self.directory, self.intent, self.pins = None, directory, json.loads(_json_bytes(intent)), list(pins)
        self.trees = {path: set(names) for path, names in (trees or {}).items()}
        self.parents = _parents(directory / "placeholder")
        self.birth = None
        self.admission_failure = False
        self.eof = {"stdout": False, "stderr": False}
        self.outputs = outputs if outputs is not None else _raw_files(directory)
        self.counts = {"stdout": 0, "stderr": 0}
        self.digests = {name: hashlib.sha256() for name in self.eof}
        self.sealed = None
        self.limit_exceeded = False
        self.selector = None
        if os.name != "nt":
            self.selector = selectors.DefaultSelector()
        if process is not None:
            self._attach(process)

    def _attach(self, process: subprocess.Popen[bytes]) -> None:
        # The data guards, private output descriptors and observer are prepared
        # before native submission. Assign the original handle first so any
        # subsequent birth/pipe/journal refusal still exposes that same owner.
        _require(self.process is None, "original-child-already-attached")
        self.process = process
        self.birth = _birth(process)
        if self.selector is not None:
            for name in self.eof:
                pipe = getattr(process, name)
                os.set_blocking(pipe.fileno(), False)
                self.selector.register(pipe, selectors.EVENT_READ, name)
        _write_new(self.directory / "submitted.json", _json_bytes({"pid": process.pid, "birth": self.birth,
                                                               "originalHandleRetained": True}))

    def _ready(self) -> list[str]:
        if self.selector is not None:
            return [key.data for key, _ in self.selector.select(0.025)]
        import msvcrt
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.PeekNamedPipe.argtypes = (wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD,
                                         wintypes.LPVOID, ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID)
        ready = []
        for name in self.eof:
            if self.eof[name]:
                continue
            available = wintypes.DWORD()
            handle = msvcrt.get_osfhandle(getattr(self.process, name).fileno())
            if kernel.PeekNamedPipe(handle, None, 0, None, ctypes.byref(available), None):
                if available.value:
                    ready.append(name)
            elif ctypes.get_last_error() == 109:
                # Broken pipe after PeekNamedPipe has no queued bytes: native
                # EOF, not an os.read error or inferred process-exit EOF.
                self.eof[name] = True
            else:
                raise AcceptanceError("pipe-observation-unknown")
        if not ready:
            time.sleep(0.025)
        return ready

    def observe(self, timeout_seconds: float = 30) -> dict[str, Any]:
        _require(type(timeout_seconds) in {int, float} and 0 < timeout_seconds <= 1200, "observation-duration")
        if self.sealed is not None:
            return json.loads(_json_bytes(self.sealed))
        if self.limit_exceeded:
            return self._snapshot("unknown", "raw-stream-limit", None)
        deadline = time.monotonic() + timeout_seconds
        reason = "observation-deadline"
        try:
            while time.monotonic() < deadline:
                for name in self._ready():
                    block = os.read(getattr(self.process, name).fileno(), 65536)
                    if not block:
                        self.eof[name] = True
                        if self.selector is not None:
                            self.selector.unregister(getattr(self.process, name))
                        continue
                    self.outputs[name].write(block)
                    self.counts[name] += len(block)
                    self.digests[name].update(block)
                    if self.counts[name] > _MAX_STREAM:
                        self.limit_exceeded = True
                        reason = "raw-stream-limit"
                        break
                if reason == "raw-stream-limit":
                    break
                if all(self.eof.values()) and self.process.poll() is not None:
                    return self._finish()
        except AcceptanceError as error:
            if str(error) != "pipe-observation-unknown":
                raise
            reason = "pipe-observation-unknown"
        except OSError:
            reason = "pipe-observation-unknown"
        if self.admission_failure and reason == "observation-deadline":
            reason = "post-submission-admission-unknown"
        return self._snapshot("unknown", reason, None)

    def _snapshot(self, state: str, reason: str, exit_code: int | None) -> dict[str, Any]:
        raw = {}
        for path, expected in self.parents.items():
            _require(_parent(path.lstat()) == expected and _ordinary(path.lstat(), True), "output-parent-drift")
        for name, stream in self.outputs.items():
            stream.flush()
            os.fsync(stream.fileno())
            path = self.directory / (name + ".private")
            opened = os.fstat(stream.fileno())
            _require(_ordinary(opened) and opened.st_nlink == 1
                     and _generation(path.lstat()) == _generation(opened)
                     and opened.st_size <= _MAX_STREAM + 65536, "raw-output-drift")
            if os.name != "nt":
                _require(opened.st_uid == os.getuid() and stat.S_IMODE(opened.st_mode) == 0o600,
                         "raw-private-owner")
            os.lseek(stream.fileno(), 0, os.SEEK_SET)
            chunks = []
            remaining = opened.st_size
            while remaining:
                chunk = os.read(stream.fileno(), min(65536, remaining))
                _require(bool(chunk), "raw-output-short-read")
                chunks.append(chunk)
                remaining -= len(chunk)
            data = b"".join(chunks)
            os.lseek(stream.fileno(), 0, os.SEEK_END)
            _require(_generation(os.fstat(stream.fileno())) == _generation(opened)
                     and _generation(path.lstat()) == _generation(opened)
                     and len(data) == self.counts[name]
                     and hashlib.sha256(data).hexdigest() == self.digests[name].hexdigest(), "raw-output-drift")
            raw[name] = {"sizeBytes": len(data), "sha256": hashlib.sha256(data).hexdigest(), "eof": self.eof[name]}
        record = {"schemaVersion": 1, "scope": SCOPE, "correlationId": self.intent["correlationId"],
                  "intentSha256": hashlib.sha256(_json_bytes(self.intent)).hexdigest(),
                  "sourceSha": self.intent.get("sourceSha"), "sourceFingerprint": self.intent.get("sourceFingerprint"),
                  "packageArtifactId": self.intent.get("packageArtifactId"), "productVersion": self.intent.get("productVersion"),
                  "state": state, "reason": reason, "pid": self.process.pid, "birth": self.birth,
                  "exitCode": exit_code, "originalHandleRetained": True, "raw": raw,
                  "replayAllowed": False, "fullWindowsAcceptance": False}
        # Every observation is immutable; partial raw is a captured prefix and
        # may grow later. It is never reused as terminal EOF evidence.
        _write_new(self.directory / ("observation-" + str(uuid.uuid4()) + ".json"), _json_bytes(record))
        return record

    def _finish(self) -> dict[str, Any]:
        if self.admission_failure:
            # EOF may be genuinely observed, but failed admission never seals
            # acceptance or releases the original process/pipes/pins for replay.
            return self._snapshot("unknown", "post-submission-admission-unknown", None)
        reason = "harness-terminal"
        current = True
        try:
            for pin in self.pins:
                pin.current()
            for root, expected in self.trees.items():
                _require(_tree(root) == expected, "terminal-tree-inventory-mismatch")
        except (AcceptanceError, OSError):
            current = False
            reason = "source-or-image-drift"
        code = self.process.poll()
        if self.birth is None and current:
            reason = "process-birth-unknown"
        certificate = _NATIVE_STARTS.get(self)
        admitted = (certificate is not None and certificate.process is self.process
                    and type(self.birth) is int and self.birth > 0 and self.birth == certificate.birth
                    and certificate.intent_bytes == _json_bytes(self.intent)
                    and certificate.argv == tuple(self.process.args)
                    and len(self.pins) == len(certificate.pins)
                    and all(actual is expected for actual, expected in zip(self.pins, certificate.pins))
                    and dict(certificate.trees) == {path: frozenset(names) for path, names in self.trees.items()})
        if not admitted and current:
            reason = "local-collector-only"
        passed = code == 0 and self.birth is not None and current and admitted
        record = self._snapshot("passed" if passed else ("failed" if current and self.birth is not None and admitted else "unknown"), reason, code)
        _write_new(self.directory / "terminal.json", _json_bytes(record))
        self.sealed = record
        for pin in self.pins:
            pin.close()
        for stream in self.outputs.values():
            stream.close()
        for name in self.eof:
            getattr(self.process, name).close()
        if self.selector is not None:
            self.selector.close()
        _NATIVE_STARTS.pop(self, None)
        return json.loads(_json_bytes(record))


def _read_record(path: Path, maximum: int = 65536) -> tuple[dict[str, Any], FilePin]:
    """Read a retained private receipt without an expected digest from argv."""
    parents = _parents(path)
    named = path.lstat()
    _require(_ordinary(named) and named.st_nlink == 1 and 0 < named.st_size <= maximum, "receipt-type-size")
    if os.name != "nt":
        _require(named.st_uid == os.getuid() and stat.S_IMODE(named.st_mode) == 0o600, "receipt-private-owner")
    fd = _open_read(path)
    try:
        opened = os.fstat(fd)
        _require(_generation(opened) == _generation(named), "receipt-open-generation")
        data = bytearray()
        while len(data) <= maximum:
            block = os.read(fd, min(65536, maximum + 1 - len(data)))
            if not block:
                break
            data.extend(block)
        _require(len(data) == opened.st_size, "receipt-read-size")
        pin = FilePin(path, fd, _generation(opened), parents, hashlib.sha256(data).hexdigest(), len(data))
        pin.current()
        value = json.loads(data)
        _require(isinstance(value, dict), "receipt-schema")
        return value, pin
    except Exception:
        os.close(fd)
        raise


def _retained_status(directory: Path, correlation: str) -> dict[str, Any]:
    """A terminal receipt is usable only with its current complete raw files."""
    if not (directory / "terminal.json").exists():
        return {"state": "unknown", "reason": "original-handle-observation-required",
                "correlationId": correlation, "replayAllowed": False, "fullWindowsAcceptance": False}
    pins = []
    try:
        record, pin = _read_record(directory / "terminal.json")
        pins.append(pin)
        _require(set(record) == {"schemaVersion", "scope", "correlationId", "state", "reason", "pid", "birth",
                 "exitCode", "originalHandleRetained", "raw", "replayAllowed", "fullWindowsAcceptance",
                 "intentSha256", "sourceSha", "sourceFingerprint", "packageArtifactId", "productVersion"}
                 and type(record["schemaVersion"]) is int and record["schemaVersion"] == 1
                 and record["scope"] == SCOPE and record["correlationId"] == correlation
                 and record["replayAllowed"] is False and record["fullWindowsAcceptance"] is False
                 and record["originalHandleRetained"] is True
                 and type(record["pid"]) is int and record["pid"] > 0
                 and type(record["exitCode"]) is int and record["state"] in {"passed", "failed", "unknown"}, "terminal-schema")
        intent, intent_pin = _read_record(directory / "intent.json", 2 * 1024 * 1024)
        pins.append(intent_pin)
        _require(intent_pin.sha256 == record["intentSha256"] and intent.get("correlationId") == correlation,
                 "terminal-intent-binding")
        for field in ("sourceSha", "sourceFingerprint", "packageArtifactId", "productVersion"):
            _require(record[field] == intent.get(field), "terminal-provenance-binding")
        _require(isinstance(record["raw"], dict) and set(record["raw"]) == {"stdout", "stderr"}, "terminal-raw-schema")
        for name, raw in record["raw"].items():
            _require(isinstance(raw, dict) and set(raw) == {"sizeBytes", "sha256", "eof"}
                     and raw["eof"] is True, "terminal-raw-eof")
            pins.append(_pin(directory / (name + ".private"), {key: raw[key] for key in ("sizeBytes", "sha256")}, _MAX_STREAM + 65536))
        if record["state"] == "passed":
            _require(record["exitCode"] == 0 and type(record["birth"]) is int and record["birth"] > 0,
                     "terminal-passing-identity")
            fields = {key: intent[key] for key in ("correlationId", "sourceSha", "sourceFingerprint", "packageArtifactId",
                "productVersion", "productCode", "sessionId", "installedFiles", "pythonFiles", "harnessFiles")}
            prepare(fields)
            _require(intent.get("scope") == SCOPE and intent.get("owner", {}).get("sid") == SID
                     and intent.get("owner", {}).get("elevated") is False, "terminal-original-owner-binding")
        for pin in pins:
            pin.current()
        return record
    finally:
        for pin in pins:
            pin.close()


def status(correlation: str) -> dict[str, Any]:
    """Read the fixed retained correlation; never discover or launch a child."""
    _require(isinstance(correlation, str) and str(uuid.UUID(correlation)) == correlation, "correlation")
    return _retained_status(TASK_ROOT / correlation, correlation)


def start(request: Mapping[str, Any], source_directory: Path) -> RetainedRun:
    """Run only the fixed installed guest harness after coordinator admission.

    ``source_directory`` is constructor wiring for the two sealed transferred
    source files, never a public command/path selector. Missing guest Python is
    a prerequisite failure. Keep the returned object alive and observe it until
    both EOFs and the exact original child terminate; do not restart on timeout.
    """
    plan = prepare(request)
    _require(isinstance(source_directory, Path) and source_directory.is_absolute(), "constructor-source-directory")
    owner = _native_owner(plan["sessionId"])
    pins: list[FilePin] = []
    outputs: dict[str, Any] = {}
    process = None
    run = None
    try:
        for root, key in ((INSTALL_ROOT, "installedFiles"), (PYTHON_ROOT, "pythonFiles"),
                          (source_directory, "harnessFiles")):
            _require(_tree(root) == set(plan[key]), "tree-inventory-mismatch")
            for name, identity in plan[key].items():
                pins.append(_pin(root / name, identity))
        for pin in pins:
            if pin.path in {INSTALL_ROOT / "vpn-control.exe", INSTALL_ROOT / "vpn-control-cli.exe",
                            PYTHON_ROOT / "python.exe", PYTHON_ROOT / "python313.dll",
                            INSTALL_ROOT / "runtime/bin/java.exe",
                            INSTALL_ROOT / "app/native/windows-amd64/vpn-control-install-helper.exe",
                            INSTALL_ROOT / "app/native/windows-amd64/vpn-control-vpn-broker.exe"}:
                _amd64(pin)
        # A native MSI registry read independently establishes installed version
        # and location. An extracted image alone does not satisfy this adapter.
        msi = ctypes.WinDLL("msi", use_last_error=True)
        msi.MsiGetProductInfoW.argtypes = (wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD))
        for field, expected in (("VersionString", plan["productVersion"]), ("InstallLocation", str(INSTALL_ROOT))):
            buffer = ctypes.create_unicode_buffer(32768)
            size = wintypes.DWORD(len(buffer))
            _require(msi.MsiGetProductInfoW(plan["productCode"], field, buffer, ctypes.byref(size)) == 0,
                     "installed-product-readback")
            _require(buffer.value.rstrip("\\").casefold() == expected.rstrip("\\").casefold(), "installed-product-mismatch")
        # Parent is pre-created by the reviewed native operator. Only this new
        # correlation child is created; an existing child always refuses replay.
        _parents(TASK_ROOT / "placeholder")
        leaf = TASK_ROOT / plan["correlationId"]
        _private_mkdir(leaf)
        stage, temporary = leaf / "sources", leaf / "temporary"
        _private_mkdir(stage)
        _private_mkdir(temporary)
        for pin in pins:
            if pin.path.parent == source_directory:
                _write_new(stage / pin.path.name, pin.bytes(512 * 1024))
        argv = _build_argv(PYTHON_ROOT / "python.exe", stage / HARNESS_FILES[0],
                           INSTALL_ROOT / "vpn-control-cli.exe", plan["productVersion"])
        environment = dict(os.environ)
        for key in ("PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "JAVA_HOME", "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS"):
            environment.pop(key, None)
        environment.update(TEMP=str(temporary), TMP=str(temporary), TMPDIR=str(temporary))
        intent = {**plan, "owner": owner, "argv": list(argv)}
        _write_new(leaf / "intent.json", _json_bytes(intent))
        pins.append(_pin(leaf / "intent.json", {"sha256": hashlib.sha256(_json_bytes(intent)).hexdigest(),
                                               "sizeBytes": len(_json_bytes(intent))}, 2 * 1024 * 1024))
        for pin in pins:
            pin.current()
        for root, key in ((INSTALL_ROOT, "installedFiles"), (PYTHON_ROOT, "pythonFiles"),
                          (source_directory, "harnessFiles")):
            _require(_tree(root) == set(plan[key]), "closing-tree-inventory-mismatch")
        trees = {root: set(plan[key]) for root, key in ((INSTALL_ROOT, "installedFiles"),
            (PYTHON_ROOT, "pythonFiles"), (source_directory, "harnessFiles"))}
        trees[stage] = set(HARNESS_FILES)
        for name in HARNESS_FILES:
            pins.append(_pin(stage / name, plan["harnessFiles"][name], 512 * 1024))
        outputs = _raw_files(leaf)
        run = RetainedRun(None, leaf, intent, pins, trees, outputs)
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, env=environment, cwd=stage)
        run._attach(process)
        # Recheck the actual native original user and complete held closure
        # before minting the process-local producer admission. Constructor
        # callers and JSON observations never create this evidence.
        _require(_native_owner(plan["sessionId"]) == owner, "closing-native-owner-changed")
        _require(type(run.birth) is int and run.birth > 0, "native-child-birth-unknown")
        for pin in pins:
            pin.current()
        for root, expected in trees.items():
            _require(_tree(root) == expected, "submitted-tree-inventory-mismatch")
        _NATIVE_STARTS[run] = _NativeStartAdmission(process, run.birth, _json_bytes(intent),
            argv, tuple(pins), tuple((path, frozenset(names)) for path, names in trees.items()))
        return run
    except Exception as error:
        if process is not None:
            # One path covers attachment and every post-Popen source, token,
            # birth, manifest and tree refusal. The prepared collector owns
            # the original child even when submission journaling failed.
            run.admission_failure = True
            _NATIVE_STARTS.pop(run, None)
            try:
                _write_new(leaf / "submission-unknown.json", _json_bytes({"state": "unknown", "pid": process.pid,
                    "birth": run.birth, "correlationId": plan["correlationId"], "replayAllowed": False}))
                run.observe(.25)
            except Exception:
                # An unsafe output namespace must still refuse durability, but
                # the exception exposes the same observer without closing its
                # held resources or substituting a new process.
                raise PostSubmissionUnknown(run) from error
            return run
        if run is not None and run.selector is not None:
            run.selector.close()
        for stream in outputs.values():
            stream.flush()
            os.fsync(stream.fileno())
            stream.close()
        for pin in pins:
            pin.close()
        raise
