"""Kernel move-trace classifier for a disposable Arch package rollback.

The trace comes from a guest inotify watch on `/opt`. It must show the
original installed image leaving, a different staged replacement arriving,
that replacement being removed, and the original inode returning in order.
"""
from __future__ import annotations

import ctypes
import json
import os
from pathlib import Path
import struct
import stat
import subprocess
import sys
import threading
import time
from typing import Any, Mapping
import uuid


MOVED_FROM = 0x40
MOVED_TO = 0x80
DELETE = 0x200


class MoveTrace:
    """Record only bounded `/opt` kernel move/delete events in the guest."""

    def __init__(self, directory: Path = Path("/opt")):
        if directory != Path("/opt"):
            raise ValueError("Arch rollback trace directory is fixed")
        self.library = ctypes.CDLL("libc.so.6", use_errno=True)
        self.fd = self.library.inotify_init1(0x800 | 0x80000)  # NONBLOCK | CLOEXEC
        if self.fd < 0:
            raise OSError(ctypes.get_errno(), "inotify_init1")
        watch = self.library.inotify_add_watch(self.fd, b"/opt", MOVED_FROM | MOVED_TO | DELETE)
        if watch < 0:
            os.close(self.fd)
            raise OSError(ctypes.get_errno(), "inotify_add_watch")
        self.names = {name: self._identity(directory / name) for name in os.listdir(directory)}
        self.initial = dict(self.names)
        self.pending: dict[int, str | None] = {}
        self.events: list[dict[str, Any]] = []
        self.running = True
        self.thread = threading.Thread(target=self._observe, daemon=True)
        self.thread.start()

    @staticmethod
    def _identity(path: Path) -> str | None:
        try:
            info = path.lstat()
            return f"{info.st_dev}:{info.st_ino}"
        except OSError:
            return None

    def _observe(self) -> None:
        while self.running:
            try:
                raw = os.read(self.fd, 65536)
            except BlockingIOError:
                time.sleep(0.01)
                continue
            except OSError:
                break
            offset = 0
            while offset + 16 <= len(raw):
                _, mask, cookie, length = struct.unpack_from("iIII", raw, offset)
                offset += 16
                if offset + length > len(raw):
                    self.running = False
                    break
                name = raw[offset:offset + length].split(b"\0", 1)[0].decode("utf-8", "replace")
                offset += length
                event: dict[str, Any] = {"timeNs": time.time_ns(), "mask": mask,
                                         "cookie": cookie, "name": name}
                if mask & MOVED_FROM:
                    event["objectId"] = self.names.pop(name, None)
                    self.pending[cookie] = event["objectId"]
                elif mask & MOVED_TO:
                    event["objectId"] = self.pending.pop(cookie, None)
                    if event["objectId"] is None:
                        event["objectId"] = self._identity(Path("/opt") / name)
                    self.names[name] = event["objectId"]
                elif mask & DELETE:
                    event["objectId"] = self.names.pop(name, None)
                if len(self.events) < 4096:
                    self.events.append(event)
                else:
                    self.running = False
                    break

    def close(self) -> dict[str, Any]:
        time.sleep(0.25)
        self.running = False
        self.thread.join(timeout=2)
        os.close(self.fd)
        if len(self.events) >= 4096:
            raise ValueError("Arch rollback kernel trace exceeded bound")
        return {"initial": self.initial, "final": dict(self.names), "events": list(self.events)}


def classify_move_trace(trace: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(trace, Mapping) or set(trace) != {"initial", "final", "events"}:
        return {"inodeTraceMatched": False}
    initial, final, events = trace["initial"], trace["final"], trace["events"]
    if (not isinstance(initial, Mapping) or not isinstance(final, Mapping)
            or not isinstance(events, list) or len(events) > 4096):
        return {"inodeTraceMatched": False}
    old = initial.get("vpn-control")
    if not isinstance(old, str) or not old or final.get("vpn-control") != old:
        return {"inodeTraceMatched": False}
    selected = []
    for index, event in enumerate(events):
        if isinstance(event, Mapping) and event.get("name") == "vpn-control":
            if (type(event.get("mask")) is not int or type(event.get("cookie")) is not int
                    or not isinstance(event.get("objectId"), str)):
                return {"inodeTraceMatched": False}
            selected.append((index, event))
    if len(selected) != 4:
        return {"inodeTraceMatched": False}
    (_, left), (_, replacement), (_, removed), (_, restored) = selected
    new = replacement["objectId"]
    valid = (left["mask"] & MOVED_FROM and left["objectId"] == old and left["cookie"] > 0
             and replacement["mask"] & MOVED_TO and new != old and new
             and replacement["cookie"] > 0 and replacement["cookie"] != left["cookie"]
             and removed["mask"] & DELETE and removed["objectId"] == new and removed["cookie"] == 0
             and restored["mask"] & MOVED_TO and restored["objectId"] == old
             and restored["cookie"] > 0 and restored["cookie"] != replacement["cookie"])
    return {"inodeTraceMatched": bool(valid), "originalObjectId": old if valid else None,
            "replacementObjectId": new if valid else None}


def _evidence_path(stdout: str) -> Path:
    decoder = json.JSONDecoder()
    try:
        first, _ = decoder.raw_decode(stdout.lstrip())
    except ValueError as error:
        raise ValueError("Arch rollback harness evidence path is absent") from error
    raw = first.get("evidence") if isinstance(first, Mapping) else None
    if (not isinstance(raw, str) or not raw.startswith("/tmp/vpn-public-install-evidence-")
            or "/" in raw[len("/tmp/vpn-public-install-evidence-"):]):
        raise ValueError("Arch rollback harness evidence path is unsafe")
    path = Path(raw)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError("Arch rollback evidence directory is unsafe")
    return path


def _accepted(evidence: Path) -> dict[str, Any]:
    matches = []
    for path in evidence.glob("cli-*.json"):
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_size > 65536:
            raise ValueError("Arch rollback public envelope is unsafe")
        value = json.loads(path.read_bytes())
        if value.get("code") == "ACCEPTED" and value.get("data", {}).get("handoffReady") is True:
            matches.append(value)
    if len(matches) != 1:
        raise ValueError("Arch rollback accepted handoff is ambiguous")
    return matches[0]


def _protected(job_id: str) -> dict[str, Any]:
    if str(uuid.UUID(job_id)) != job_id:
        raise ValueError("Arch rollback protected job is invalid")
    path = Path("/var/lib/vpn-control-install-jobs") / job_id / "status.json"
    for parent in (Path("/var"), Path("/var/lib"), Path("/var/lib/vpn-control-install-jobs"), path.parent):
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError("Arch rollback protected receipt ancestry is unsafe")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
                or info.st_mode & 0o022 or info.st_size > 4096):
            raise ValueError("Arch rollback protected receipt is unsafe")
        result = json.loads(os.read(fd, 4097))
    finally:
        os.close(fd)
    if (result.get("version") != 1 or result.get("jobId") != job_id
            or result.get("phase") != "FAILED" or result.get("code") != "RUNTIME_FAILED"):
        raise ValueError("Arch rollback did not reach expected protected terminal failure")
    return result


def _recover_owner(evidence: Path, accepted: Mapping[str, Any], protected: Mapping[str, Any],
                   runner: Any = subprocess.run) -> dict[str, Any]:
    launcher = "/opt/vpn-control/bin/vpn-control"
    workspace = evidence / "workspace"
    log = evidence / "rollback-recovery-owner.log"
    with log.open("wb") as output:
        owner = subprocess.Popen([launcher, "--state-dir", str(workspace), "serve"],
                                 stdin=subprocess.DEVNULL, stdout=output, stderr=output,
                                 start_new_session=True)
    try:
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline and not (workspace / "activation.port").exists():
            if owner.poll() is not None:
                raise ValueError("Arch rollback recovery owner exited")
            time.sleep(0.1)
        if not (workspace / "activation.port").exists():
            raise ValueError("Arch rollback recovery owner did not activate")
        result = runner([launcher, "--state-dir", str(workspace), "--json", "operations", "status",
                         accepted["operationId"]], capture_output=True, text=True, timeout=90, check=False)
        if result.returncode != 1 or len(result.stdout) > 65536:
            raise ValueError("Arch rollback new owner did not report terminal failure")
        public = json.loads(result.stdout)
        data = public.get("data", {})
        if (public.get("schemaVersion") != 1 or public.get("ok") is not False
                or public.get("code") != "RUNTIME_FAILED" or public.get("final") is not True
                or public.get("operationId") != accepted.get("operationId")
                or public.get("controllerId") == accepted.get("controllerId")
                or data.get("jobId") != protected.get("jobId")
                or data.get("originControllerId") != accepted.get("controllerId")
                or data.get("originRequestId") != accepted.get("requestId")):
            raise ValueError("Arch rollback new owner correlation differs")
        return public
    finally:
        quit_result = runner([launcher, "--state-dir", str(workspace), "--json", "quit"],
                             capture_output=True, text=True, timeout=60, check=False)
        if quit_result.returncode != 0:
            raise ValueError("Arch rollback recovery owner did not quit publicly")
        owner.wait(timeout=30)
        if owner.returncode != 0:
            raise ValueError("Arch rollback recovery owner did not exit cleanly")
