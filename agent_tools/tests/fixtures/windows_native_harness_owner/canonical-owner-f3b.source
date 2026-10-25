"""Internal POSIX durable execution owner for fixed, trusted Python adapters.

This is not a public command API. An adapter owns its reviewed ``Program`` and
machine admission; callers must not turn user input into program source. No
credentials, caller environment or interactive input are accepted. Streams are
private and are never included in status or exception messages.

Copy ``owner_source()`` to the admitted remote host and use these same functions
there. Submit once using a pre-recorded operation UUID, then reconnect through
``observe``/``collect``. A consumed admission without a terminal receipt is never
replayed. Missing records only prove non-submission on the same verified private
root; replacing or losing that root invalidates that proof. The caller must pin
its root generation across connections. There is deliberately no kill API.

Capability: POSIX Linux and Darwin process generations. Other platforms refuse
before admission. Native SSH, Windows and provider acceptance remain separate.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import stat
import subprocess
import sys
import time
import threading
import uuid
from typing import Any

MAX_PROGRAM_BYTES = 8 * 1024 * 1024
MAX_STREAM_BYTES = 4 * 1024 * 1024
MAX_RECORD_BYTES = 16_384
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_HEX = re.compile(r"[0-9a-f]{64}\Z")


class DurableJobError(ValueError):
    """Finite public reason only; never attach a raw private exception."""


def _need(condition: bool, reason: str) -> None:
    if not condition:
        raise DurableJobError(reason)


def _uuid(value: str) -> str:
    try:
        _need(type(value) is str and str(uuid.UUID(value)) == value, "operation_identity_invalid")
    except (ValueError, AttributeError, TypeError):
        raise DurableJobError("operation_identity_invalid") from None
    return value


def _token(value: str) -> str:
    _need(type(value) is str and bool(_TOKEN.fullmatch(value)), "binding_invalid")
    return value


@dataclass(frozen=True)
class MachineBinding:
    target: str
    machine: str
    boot: str
    account: str

    def __post_init__(self) -> None:
        for value in asdict(self).values():
            _token(value)

    @classmethod
    def from_dict(cls, value: dict[str, str]) -> "MachineBinding":
        _need(type(value) is dict and set(value) == {"target", "machine", "boot", "account"}, "binding_invalid")
        return cls(**value)


@dataclass(frozen=True)
class Program:
    """Trusted adapter-owned source; private input must use a separate channel."""
    purpose: str
    source: bytes
    stream_limit: int = 1024 * 1024

    def __post_init__(self) -> None:
        _token(self.purpose)
        _need(type(self.source) is bytes and 0 < len(self.source) <= MAX_PROGRAM_BYTES, "program_invalid")
        _need(type(self.stream_limit) is int and 1 <= self.stream_limit <= MAX_STREAM_BYTES, "stream_limit_invalid")
        try:
            compile(self.source, "fixed-purpose-program", "exec")
        except (SyntaxError, ValueError, UnicodeError):
            raise DurableJobError("program_invalid") from None

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.source).hexdigest()


def _boot() -> str:
    if sys.platform.startswith("linux"):
        try:
            return _token(Path("/proc/sys/kernel/random/boot_id").read_text().strip())
        except (OSError, ValueError):
            raise DurableJobError("boot_identity_unavailable") from None
    if sys.platform == "darwin":
        try:
            result = subprocess.run(["/usr/sbin/sysctl", "-n", "kern.bootsessionuuid"],
                                    capture_output=True, timeout=3, check=True)
            return _token(result.stdout.decode("ascii").strip())
        except (OSError, ValueError, subprocess.SubprocessError):
            raise DurableJobError("boot_identity_unavailable") from None
    raise DurableJobError("platform_unsupported")


def current_binding(target: str, machine: str) -> MachineBinding:
    """``machine`` must come from the coordinator's trusted target admission."""
    _need(os.name == "posix", "platform_unsupported")
    return MachineBinding(target, machine, _boot(), str(os.geteuid()))


def _birth(pid: int) -> str | None:
    if sys.platform.startswith("linux"):
        try:
            tail = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
            return None if tail[0] == "Z" else "linux:" + str(int(tail[19]))
        except (OSError, IndexError, ValueError):
            return None
    if sys.platform == "darwin":
        try:
            # proc_bsdinfo, XNU sys/proc_info.h. Kernel start microseconds are
            # required; ps/lstart's one-second resolution cannot prevent reuse.
            import ctypes
            class BsdInfo(ctypes.Structure):
                _fields_ = [("head", ctypes.c_uint32 * 12), ("comm", ctypes.c_char * 16),
                            ("name", ctypes.c_char * 32), ("tail", ctypes.c_uint32 * 6),
                            ("seconds", ctypes.c_uint64), ("microseconds", ctypes.c_uint64)]
            library = ctypes.CDLL("/usr/lib/libproc.dylib")
            function = library.proc_pidinfo
            function.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int]
            function.restype = ctypes.c_int
            info = BsdInfo()
            count = function(pid, 3, 0, ctypes.byref(info), ctypes.sizeof(info))
            if count != ctypes.sizeof(info) or info.head[3] != pid or info.head[1] == 5:
                return None
            return f"darwin:{info.seconds}:{info.microseconds}"
        except (OSError, ValueError, AttributeError):
            return None
    return None


def _private(path: Path, *, directory: bool) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError:
        raise DurableJobError("private_state_unavailable") from None
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    _need(expected(info.st_mode) and info.st_uid == os.geteuid()
          and stat.S_IMODE(info.st_mode) == (0o700 if directory else 0o600)
          and (directory or info.st_nlink == 1), "private_state_unsafe")
    return info


def _root(path: Path | str, generation: tuple[int, int] | None = None) -> Path:
    path = Path(path)
    _need(path.is_absolute() and ".." not in path.parts, "root_invalid")
    info = _private(path, directory=True)
    _need(path.resolve() == path, "root_invalid")
    if generation is not None:
        _need(tuple(generation) == (info.st_dev, info.st_ino), "root_generation_changed")
    return path


def root_generation(path: Path | str) -> tuple[int, int]:
    """Pin durably outside the transport before the first submission."""
    path = _root(path)
    info = path.stat()
    return info.st_dev, info.st_ino


def _sync_directory(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _create(path: Path, raw: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    _sync_directory(path.parent)


def _publish(path: Path, value: dict[str, Any]) -> None:
    temp = path.with_name(path.name + "." + str(uuid.uuid4()) + ".tmp")
    _create(temp, json.dumps(value, sort_keys=True, separators=(",", ":")).encode())
    # Receipt names are single-writer; link creates them without replacing a
    # pre-existing terminal receipt or adopting an unrelated file.
    os.link(temp, path, follow_symlinks=False)
    temp.unlink()
    _sync_directory(path.parent)


def _read(path: Path, limit: int) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        _need(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
              and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1
              and info.st_size <= limit, "private_state_unsafe")
        raw = stream.read(limit + 1)
    _need(len(raw) <= limit, "private_state_oversized")
    return raw


def _record(path: Path) -> dict[str, Any]:
    try:
        def pairs(rows: list[tuple[str, Any]]) -> dict[str, Any]:
            value: dict[str, Any] = {}
            for key, item in rows:
                _need(key not in value, "record_invalid")
                value[key] = item
            return value
        value = json.loads(_read(path, MAX_RECORD_BYTES), object_pairs_hook=pairs)
        _need(type(value) is dict, "record_invalid")
        return value
    except (OSError, ValueError, UnicodeError):
        raise DurableJobError("record_unavailable") from None


def _binding_live(binding: MachineBinding) -> None:
    _need(binding.account == str(os.geteuid()), "account_changed")
    _need(binding.boot == _boot(), "boot_changed")


def _intent(path: Path, operation_id: str, binding: MachineBinding) -> dict[str, Any]:
    value = _record(path / "intent.json")
    _need(set(value) == {"schemaVersion", "operationId", "binding", "purpose", "programSha256", "streamLimit", "generation"}
          and value["schemaVersion"] == 1 and value["operationId"] == operation_id,
          "intent_invalid")
    actual = MachineBinding.from_dict(value["binding"])
    _need(actual == binding, "operation_binding_mismatch")
    _token(value["purpose"])
    _uuid(value["generation"])
    _need(type(value["programSha256"]) is str and bool(_HEX.fullmatch(value["programSha256"])), "intent_invalid")
    _need(type(value["streamLimit"]) is int and 1 <= value["streamLimit"] <= MAX_STREAM_BYTES, "intent_invalid")
    return value


def _base(operation_id: str, state: str, reason: str) -> dict[str, Any]:
    return {"schemaVersion": 1, "operationId": operation_id, "state": state,
            "reason": reason, "replayAllowed": False}


def _correlate(value: dict[str, Any], intent: dict[str, Any]) -> None:
    _need(value.get("operationId") == intent["operationId"] and value.get("generation") == intent["generation"]
          and value.get("binding") == intent["binding"] and value.get("programSha256") == intent["programSha256"],
          "owner_identity_mismatch")


def _owner_identity(owner: dict[str, Any]) -> dict[str, Any]:
    _need(set(owner) == {"operationId", "generation", "binding", "programSha256", "owner"}, "owner_identity_invalid")
    identity = owner.get("owner")
    _need(type(identity) is dict and set(identity) == {"pid", "birth"} and type(identity["pid"]) is int
          and identity["pid"] > 0 and type(identity["birth"]) is str and len(identity["birth"]) <= 128,
          "owner_identity_invalid")
    return identity


def observe(root: Path | str, operation_id: str, binding: MachineBinding, *,
            generation: tuple[int, int]) -> dict[str, Any]:
    """Read-only status. A new connection must retain the same root generation."""
    operation_id = _uuid(operation_id)
    try:
        root = _root(root, generation)
        job = root / operation_id
        if not job.exists() and not job.is_symlink():
            _binding_live(binding)
            return _base(operation_id, "unsubmitted", "admission_absent")
        _private(job, directory=True)
        intent = _intent(job, operation_id, binding)
        receipt = job / "terminal.json"
        if receipt.exists() or receipt.is_symlink():
            value = _record(receipt)
            _correlate(value, intent)
            _need(set(value) == {"operationId", "generation", "binding", "programSha256", "owner",
                                 "exitCode", "streamsClosed", "stdout", "stderr"}
                  and type(value.get("exitCode")) is int and value.get("streamsClosed") is True,
                  "terminal_invalid")
            owner = _record(job / "owner.json")
            _correlate(owner, intent)
            _owner_identity(owner)
            _need(value.get("owner") == owner.get("owner"), "owner_identity_mismatch")
            for name in ("stdout", "stderr"):
                stream = value.get(name)
                _need(type(stream) is dict and set(stream) == {"overflow", "retainedBytes", "totalBytes", "sha256"}
                      and type(stream.get("overflow")) is bool
                      and type(stream.get("retainedBytes")) is int and 0 <= stream["retainedBytes"] <= intent["streamLimit"]
                      and type(stream.get("totalBytes")) is int and stream["totalBytes"] >= stream["retainedBytes"]
                      and type(stream.get("sha256")) is str and bool(_HEX.fullmatch(stream["sha256"])), "terminal_invalid")
            result = _base(operation_id, "unknown" if value["stdout"]["overflow"] or value["stderr"]["overflow"] else "terminal",
                           "output_overflow" if value["stdout"]["overflow"] or value["stderr"]["overflow"] else "correlated_terminal")
            result.update(binding=intent["binding"], owner=value["owner"], terminal=value)
            return result
        _binding_live(binding)
        owner = _record(job / "owner.json")
        _correlate(owner, intent)
        identity = _owner_identity(owner)
        if _birth(identity["pid"]) == identity["birth"]:
            result = _base(operation_id, "running", "original_owner_running")
            result.update(binding=intent["binding"], owner=identity)
            return result
        return _base(operation_id, "unknown", "original_owner_missing")
    except (OSError, DurableJobError) as error:
        reason = str(error) if isinstance(error, DurableJobError) else "observation_unavailable"
        return _base(operation_id, "unknown", reason)


def submit(root: Path | str, operation_id: str, binding: MachineBinding, program: Program, *,
           generation: tuple[int, int]) -> dict[str, Any]:
    """Admit at most once. Duplicate submission only observes the original job.

    Any failure after create-only directory admission consumes the operation;
    even a lost owner launch is UNKNOWN. A subsequent caller may only observe.
    """
    operation_id = _uuid(operation_id)
    root = _root(root, generation)
    _binding_live(binding)
    job = root / operation_id
    try:
        job.mkdir(mode=0o700)
    except FileExistsError:
        result = observe(root, operation_id, binding, generation=generation)
        try:
            original = _intent(job, operation_id, binding)
            _need(original["purpose"] == program.purpose and original["programSha256"] == program.digest
                  and original["streamLimit"] == program.stream_limit, "operation_program_mismatch")
        except (OSError, DurableJobError):
            return _base(operation_id, "unknown", "operation_admission_conflict")
        return result
    try:
        _sync_directory(root)
        intent = {"schemaVersion": 1, "operationId": operation_id, "binding": asdict(binding),
                  "purpose": program.purpose, "programSha256": program.digest,
                  "streamLimit": program.stream_limit, "generation": str(uuid.uuid4())}
        _publish(job / "intent.json", intent)
        _create(job / "program.py", program.source)
        _create(job / "owner.py", owner_source())
        # Everything is durably admitted before one launch; no SSH/client file
        # descriptor survives in the detached owner or its child.
        process = subprocess.Popen([sys.executable, "-I", "-B", str(job / "owner.py"), "--own", str(job)],
                                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                   close_fds=True, start_new_session=True, env={"PATH": os.defpath})
        # Reap the short-lived process if already terminal. Long-running owners
        # belong to the OS, not the submitting connection. Popen deliberately
        # must not be used as a context manager (which waits on disconnect).
        # A daemon reaper retains this same Popen handle without tying the
        # detached job's lifetime to the submitting client/server.
        try:
            threading.Thread(target=process.wait, daemon=True, name="durable-job-reaper").start()
        except RuntimeError:
            # Failed thread creation must not lose or replace the original
            # process. Waiting is safe although this exceptional path is slow.
            process.wait()
    except (OSError, DurableJobError):
        return _base(operation_id, "unknown", "admission_consumed")
    return observe(root, operation_id, binding, generation=generation)


def collect(root: Path | str, operation_id: str, binding: MachineBinding, *,
            generation: tuple[int, int]) -> tuple[dict[str, Any], bytes, bytes]:
    """Collect complete private streams only after the original terminal receipt."""
    status = observe(root, operation_id, binding, generation=generation)
    _need(status["state"] == "terminal", "collection_not_terminal")
    job = _root(root, generation) / _uuid(operation_id)
    streams: list[bytes] = []
    for name in ("stdout", "stderr"):
        try:
            raw = _read(job / (name + ".bin"), MAX_STREAM_BYTES)
        except OSError:
            raise DurableJobError("stream_unavailable") from None
        expected = status["terminal"][name]
        _need(len(raw) == expected["retainedBytes"] == expected["totalBytes"]
              and hashlib.sha256(raw).hexdigest() == expected["sha256"], "stream_integrity_mismatch")
        streams.append(raw)
    return status, streams[0], streams[1]


def owner_source() -> bytes:
    """Self-contained source snapshot for saved-script transfer, never argv."""
    return Path(__file__).read_bytes()


def _own(job: Path) -> int:
    """Detached single owner. Errors disclose no source, inputs or raw streams."""
    os.umask(0o077)
    try:
        _private(job, directory=True)
        original = _record(job / "intent.json")
        binding = MachineBinding.from_dict(original["binding"])
        intent = _intent(job, job.name, binding)
        _binding_live(binding)
        source = _read(job / "program.py", MAX_PROGRAM_BYTES)
        _need(hashlib.sha256(source).hexdigest() == intent["programSha256"], "program_integrity_mismatch")
        birth = _birth(os.getpid())
        _need(birth is not None, "owner_generation_unavailable")
        identity = {"pid": os.getpid(), "birth": birth}
        correlation = {key: intent[key] for key in ("operationId", "binding", "programSha256", "generation")}
        _publish(job / "owner.json", {**correlation, "owner": identity})
        # This create-only child launch fence also protects against accidental
        # second owner invocation, including after owner/client death.
        _create(job / "child-admission", b"consumed\n")
        files = {name: os.fdopen(os.open(job / (name + ".bin"), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), "wb")
                 for name in ("stdout", "stderr")}
        counts = {name: {"retainedBytes": 0, "totalBytes": 0, "sha256": hashlib.sha256()} for name in files}
        # Snapshot source is transferred privately through stdin; it is never
        # placed in argv and the payload sees EOF. No inherited environment.
        bootstrap = "import sys; s=sys.stdin.buffer.read(); exec(compile(s,'fixed-purpose-program','exec'),{'__name__':'__main__'})"
        child = subprocess.Popen([sys.executable, "-I", "-B", "-c", bootstrap], stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True,
                                 start_new_session=True, env={"PATH": os.defpath})
        assert child.stdin is not None and child.stdout is not None and child.stderr is not None
        child.stdin.write(source)
        child.stdin.close()
        selector = selectors.DefaultSelector()
        selector.register(child.stdout, selectors.EVENT_READ, "stdout")
        selector.register(child.stderr, selectors.EVENT_READ, "stderr")
        while selector.get_map():
            for key, _ in selector.select(timeout=1):
                chunk = os.read(key.fileobj.fileno(), 65536)
                name = key.data
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                row = counts[name]
                row["totalBytes"] += len(chunk)
                retained = chunk[:max(0, intent["streamLimit"] - row["retainedBytes"])]
                files[name].write(retained)
                row["retainedBytes"] += len(retained)
                row["sha256"].update(retained)
        selector.close()
        code = child.wait()
        for stream in files.values():
            stream.flush()
            os.fsync(stream.fileno())
            stream.close()
        output = {name: {**row, "sha256": row["sha256"].hexdigest(),
                         "overflow": row["totalBytes"] > row["retainedBytes"]} for name, row in counts.items()}
        _publish(job / "terminal.json", {**correlation, "owner": identity, "exitCode": code,
                                       "streamsClosed": True, **output})
        return 0
    except Exception:
        # No terminal assertion is made after an uncertain launch or incomplete
        # collection; the consumed admission remains UNKNOWN for reconciliation.
        return 70


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--own":
        raise SystemExit(_own(Path(sys.argv[2])))
    raise SystemExit(64)
