"""Fixed source-only preparation for two independent Windows disposable guests.

No guest start, installer, SSH-session repair, product workspace or CP117 action.
The public plan reads one retained source observation. The internal runner is
also the local direct-flow seam; remote registration belongs to the MCP owner.
Partial namespaces and original read-lock handles survive unknown outcomes.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import inspect
import json
import os
from pathlib import Path
import re
import selectors
import stat
import subprocess
import time
import textwrap
import uuid

from . import native_vm_baseline as baseline
from . import windows_parallel_vm_source_inventory as inventory

TEMPLATE_ROOT = Path("/home/kardinal/vpn-control-windows-parallel-vm-template-20261005")
DISK_RESERVE = 43 * 1024 ** 3  # 32 GiB overlays, 3 GiB packages/metadata, 8 GiB spare.
RAW_LIMIT = 65536


def need(value, reason):
    if not value:
        raise ValueError(reason)


def immutable_write(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as output:
            output.write(raw)
            output.flush()
            os.fsync(fd)
    finally:
        os.close(fd)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def record(path, value):
    immutable_write(path, (json.dumps(value, sort_keys=True) + "\n").encode())


def record_at(directory_fd, name, value):
    """Keep the original journal reachable after a named namespace refusal."""
    need(re.fullmatch(r"[a-z-]+\.json", name), "receipt-role")
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory_fd)
    try:
        with os.fdopen(fd, "wb", closefd=False) as output:
            output.write((json.dumps(value, sort_keys=True) + "\n").encode())
            output.flush()
            os.fsync(fd)
    finally:
        os.close(fd)
    os.fsync(directory_fd)


@dataclass(frozen=True)
class Scope:
    source: Path
    source_root: Path
    template_root: Path
    guests: tuple[Path, Path]
    proc: Path
    qemu_img: str
    qemu_io: str


def fixed_scope():
    return Scope(Path(inventory.SOURCE), Path(inventory.SOURCE_ROOT), TEMPLATE_ROOT,
                 tuple(Path(p) for p in inventory.DESTINATIONS), Path("/proc"),
                 "/usr/bin/qemu-img", "/usr/bin/qemu-io")


def build_plan(root, evidence_leaf):
    """Read historical pins, not historical live availability or clone authority."""
    from . import windows_cp117_bound_absence_completion as authority
    need(isinstance(evidence_leaf, str)
         and re.fullmatch(r"windows-parallel-vm-source-read-[0-9a-f]{32}", evidence_leaf), "source-leaf")
    root = Path(root).resolve(strict=True)
    path = root / ".runtime" / "parity-evidence" / evidence_leaf
    expected = inventory.parent_pins(path / "transport.stdout.private", root)
    raw_pin, raw = authority._read_bound_file(path / "transport.stdout.private", private=True, retain_bytes=True)
    report = json.loads(raw)
    result_pin, result = authority._read_bound_file(path / "result.json", private=True, retain_bytes=True)
    need(json.loads(result) == report, "source-retained-result")
    trace_pin, trace = authority._read_bound_file(path / "transport.json", private=True, retain_bytes=True)
    trace = json.loads(trace)
    need(type(trace) is dict and trace.get("stdoutEof") is True and type(trace.get("exitCode")) is int
         and trace["exitCode"] == 0 and trace.get("reason") is None, "source-retained-transport")
    need(type(report) is dict and report.get("state") == "observed" and report.get("sourceState") == "stopped-observed"
         and report.get("source") == inventory.SOURCE and report.get("holderCensusComplete") is True
         and report.get("sourceHolders") == [] and report.get("cloneAdmitted") is False
         and report.get("nativeActionAllowed") is False, "source-retained-envelope")
    pin = source_pin(report)
    for parent, identity in expected:
        need(inventory.parent_identity(parent.lstat()) == identity, "source-retained-ancestry")
    return {"schemaVersion": 1, "scope": "windows-parallel-vm-template-and-two-overlays",
            "sourcePin": pin, "sourceEvidence": {"leaf": evidence_leaf, "raw": raw_pin,
                "result": result_pin, "transport": trace_pin},
            "templateRoot": str(TEMPLATE_ROOT), "guestRoots": list(inventory.DESTINATIONS),
            "minimumDiskBytes": pin["generation"][6] + DISK_RESERVE,
            "nativeGuestStarted": False, "launchAdmitted": False, "productAcceptance": False}


def source_pin(report):
    generation = report.get("sourceGeneration")
    digest = report.get("sourceSha256")
    need(type(generation) is list and len(generation) == 9 and all(type(v) is int and v >= 0 for v in generation)
         and stat.S_ISREG(generation[2]) and generation[5] == 1 and 0 < generation[6] <= 120 * 1024 ** 3,
         "source-pin-generation")
    need(type(digest) is str and re.fullmatch(r"[0-9a-f]{64}", digest), "source-pin-hash")
    need(report.get("sourceSizeBytes") == generation[6]
         and report.get("image") == {"format": "qcow2", "backingFile": None, "virtualSizeBytes": 96 * 1024 ** 3},
         "source-pin-image")
    parents = report.get("sourceParents")
    need(type(parents) is list and 1 <= len(parents) <= 8, "source-pin-parents")
    for row in parents:
        need(type(row) is dict and set(row) == {"path", "generation"} and type(row["path"]) is str
             and type(row["generation"]) is list and len(row["generation"]) == 5
             and all(type(v) is int and v >= 0 for v in row["generation"])
             and stat.S_ISDIR(row["generation"][2]) and not row["generation"][2] & 0o022,
             "source-pin-parent")
    return {"generation": generation, "sha256": digest, "parents": parents}


class LockUnknown(ValueError):
    def __init__(self, reason, lock):
        super().__init__(reason)
        self.lock = lock


class ReadLock:
    """Original qemu-io handle and fsynced bounded raw, never process adoption."""
    def __init__(self, binary, source, evidence):
        need(source.is_absolute() and re.fullmatch(r"/[A-Za-z0-9._/-]+", str(source)), "lock-source-path")
        self.argv = [binary, "--image-opts", "-r",
                     "driver=qcow2,file.driver=file,file.filename=" + str(source) + ",file.locking=on"]
        self.raw_path = evidence / "read-lock.stdout.private"
        self.raw_fd = os.open(self.raw_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        self.raw_identity = inventory.generation(os.fstat(self.raw_fd))[:6]
        self.raw = bytearray()
        self.child = None
        self.selector = selectors.DefaultSelector()
        self.ready = False
        self.eof = False
        self.birth = None
        try:
            self.child = subprocess.Popen(self.argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                          stderr=subprocess.STDOUT)
            self.birth = inventory.process_birth(Path("/proc"), self.child.pid)
            record(evidence / "read-lock.started.json", {"pid": self.child.pid, "startTicks": self.birth,
                "argvSha256": hashlib.sha256(json.dumps(self.argv).encode()).hexdigest(), "readOnly": True})
            self.selector.register(self.child.stdout, selectors.EVENT_READ)
            self.child.stdin.write(b"info\n")
            self.child.stdin.flush()
        except BaseException as error:
            self.best_effort_flush()
            if self.child is not None:
                raise LockUnknown("read-lock-submission-unknown", self) from error
            self.dispose()
            raise

    def flush(self):
        held, named = os.fstat(self.raw_fd), self.raw_path.lstat()
        need(inventory.generation(held)[:6] == self.raw_identity == inventory.generation(named)[:6]
             and held.st_nlink == 1, "read-lock-raw-generation")
        os.fsync(self.raw_fd)

    def best_effort_flush(self):
        # An unsafe named namespace cannot erase the original held FD/process
        # from the exception. Keep its original bytes even on guard refusal.
        try:
            os.fsync(self.raw_fd)
        except (OSError, TypeError):
            pass

    def append(self, raw):
        self.raw.extend(raw)
        remaining = memoryview(raw)
        while remaining:
            written = os.write(self.raw_fd, remaining)
            need(written > 0, "read-lock-raw-short-write")
            remaining = remaining[written:]
        self.flush()

    def observe(self, timeout=5):
        deadline = time.monotonic() + timeout
        try:
            while time.monotonic() < deadline:
                for key, _ in self.selector.select(min(.1, max(0, deadline - time.monotonic()))):
                    raw = os.read(key.fileobj.fileno(), min(4096, RAW_LIMIT + 1 - len(self.raw)))
                    if not raw:
                        self.eof = True
                        break
                    self.append(raw)
                    need(len(self.raw) <= RAW_LIMIT, "read-lock-output-limit")
                if b"format name: qcow2" in self.raw and b"qemu-io> " in self.raw and self.child.poll() is None:
                    self.ready = True
                    return self
                if self.eof or self.child.poll() is not None:
                    break
            raise ValueError("read-lock-readiness-unknown")
        except BaseException as error:
            self.best_effort_flush()
            raise LockUnknown("read-lock-observation-unknown", self) from error

    def close(self):
        # Cleanup only the original positively created read-only utility. No
        # kill or restart and no EOF claim on timeout; callers retain the handle.
        try:
            if self.child.poll() is None:
                self.child.stdin.write(b"quit\n")
                self.child.stdin.flush()
            deadline = time.monotonic() + 3
            while not self.eof and time.monotonic() < deadline:
                for key, _ in self.selector.select(.1):
                    raw = os.read(key.fileobj.fileno(), min(4096, RAW_LIMIT + 1 - len(self.raw)))
                    if not raw:
                        self.eof = True
                        break
                    self.append(raw)
                    need(len(self.raw) <= RAW_LIMIT, "read-lock-output-limit")
            code = self.child.wait(timeout=max(.001, deadline - time.monotonic()))
            need(self.eof and code == 0, "read-lock-close-unknown")
            self.flush()
            record(self.raw_path.parent / "read-lock.terminal.json", {"pid": self.child.pid,
                "startTicks": self.birth, "stdoutEof": True, "exitCode": code,
                "rawBytes": len(self.raw), "rawSha256": hashlib.sha256(self.raw).hexdigest()})
            self.dispose()
        except BaseException as error:
            self.best_effort_flush()
            raise LockUnknown("read-lock-close-unknown", self) from error

    def dispose(self):
        self.selector.close()
        if self.child is not None:
            for stream in (self.child.stdin, self.child.stdout):
                if stream is not None and not stream.closed:
                    stream.close()
        if self.raw_fd is not None:
            os.close(self.raw_fd)
            self.raw_fd = None


def prove_write_exclusion(scope, evidence):
    """Test only new task-owned scratch; never writable-open the source disk."""
    scratch = evidence / "locking-scratch.qcow2"
    result = subprocess.run([scope.qemu_img, "create", "-f", "qcow2", str(scratch), "8M"],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=15, check=False)
    immutable_write(evidence / "locking-scratch-create.stdout.private", result.stdout)
    need(result.returncode == 0 and scratch.is_file(), "locking-scratch-create")
    before = inventory.generation(scratch.lstat())
    lock = ReadLock(scope.qemu_io, scratch, evidence).observe()
    try:
        opts = "driver=qcow2,file.driver=file,file.filename=" + str(scratch) + ",file.locking=on"
        writer = subprocess.run([scope.qemu_io, "--image-opts", "-c", "info", opts],
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=5, check=False)
        immutable_write(evidence / "locking-write-open.stdout.private", writer.stdout)
        need(writer.returncode != 0 and b'Failed to get "write" lock' in writer.stdout
             and inventory.generation(scratch.lstat()) == before, "write-exclusion-unproved")
        record(evidence / "write-exclusion.json", {"readerPid": lock.child.pid,
            "writerExitCode": writer.returncode, "sourceWritableOpenAttempted": False,
            "scratchGeneration": before, "readOnlyLockApplied": True})
    finally:
        lock.close()
    return True


def close_source(scope, fd, pin, lock, deadline):
    parents = [(Path(row["path"]), row["generation"]) for row in pin["parents"]]
    need(inventory.parent_pins(scope.source, scope.source_root) == parents, "source-pin-parent-drift")
    inventory.verify_source(scope.source, fd, pin["generation"], parents)
    census = inventory.holder_census(scope.proc, tuple(pin["generation"][:2]),
                                    (os.getpid(), str(fd)), deadline, str(scope.source))
    allowed = []
    if lock is not None:
        need(lock.ready and lock.child.poll() is None, "source-lock-lost")
        birth = inventory.process_birth(scope.proc, lock.child.pid)
        need(type(birth) is int and birth > 0, "source-lock-birth")
        if lock.birth is None:
            lock.birth = birth
        need(birth == lock.birth, "source-lock-birth-changed")
        allowed = [row for row in census["holders"] if row["pid"] == lock.child.pid and row["startTicks"] == birth]
        need(bool(allowed), "source-lock-fd-unproved")
    need(census["holders"] == allowed and not census["argvUsers"], "foreign-source-holder")
    return census


def close_outputs(scope, template_fd, sealed, overlays, overlay_fds, guest_fds):
    """Pure final group closure after every metadata producer has finished."""
    template = scope.template_root / "template.qcow2"
    need(inventory.generation(os.fstat(template_fd)) == sealed == inventory.generation(template.lstat()),
         "template-closing-generation")
    for row, fd, (guest_fd, guest_pin), guest in zip(overlays, overlay_fds, guest_fds, scope.guests):
        named = Path(row["path"]).lstat()
        held = os.fstat(fd)
        need(inventory.generation(held) == row["generation"] == inventory.generation(named)
             and stat.S_ISREG(held.st_mode) and stat.S_IMODE(held.st_mode) == 0o600
             and held.st_nlink == 1, "overlay-closing-generation")
        need(held.st_uid == guest_pin[3] and held.st_gid == guest_pin[4], "overlay-closing-owner")
        need(os.path.realpath(guest) == str(guest)
             and inventory.parent_identity(os.fstat(guest_fd)) == guest_pin
             == inventory.parent_identity(guest.lstat()) and stat.S_IMODE(guest_pin[2]) == 0o700,
             "guest-closing-generation")


def prepare_core(scope, pin, correlation_id, *, disk_reserve=DISK_RESERVE):
    """Same concrete copy/overlay runner for local proof and eventual fixed MCP.

    Scope/path projection is an internal test seam. The public builder has no
    path selector. Native transport/GO remains outside this unregistered core.
    """
    need(str(uuid.UUID(correlation_id)) == correlation_id, "correlation")
    source_pin({"sourceGeneration": pin["generation"], "sourceSha256": pin["sha256"],
                "sourceSizeBytes": pin["generation"][6], "sourceParents": pin["parents"],
                "image": {"format": "qcow2", "backingFile": None, "virtualSizeBytes": 96 * 1024 ** 3}})
    need(pin["generation"][3] == scope.source_root.lstat().st_uid, "source-owner")
    need(not scope.template_root.exists() and not scope.template_root.is_symlink(), "template-exists")
    need(all(not os.path.lexists(path) for path in scope.guests), "guest-exists")
    need(os.path.realpath(scope.template_root.parent) == str(scope.template_root.parent), "template-parent")
    available = os.statvfs(scope.template_root.parent)
    need(available.f_bavail * available.f_frsize >= pin["generation"][6] + disk_reserve, "copy-disk-budget")
    fd = os.open(scope.source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    lock = None
    template_fd = None
    overlay_fds = []
    guest_fds = []
    evidence_fd = None
    namespace_pin = None
    evidence_pin = None
    namespace_created = False
    stage = "source-admission"
    def guard_namespace():
        need(os.path.realpath(scope.template_root) == str(scope.template_root)
             and inventory.parent_identity(scope.template_root.lstat()) == namespace_pin
             and inventory.parent_identity(evidence.lstat()) == evidence_pin
             and inventory.parent_identity(os.fstat(evidence_fd)) == evidence_pin,
             "preparation-namespace-changed")
    try:
        census = close_source(scope, fd, pin, None, time.monotonic() + 30)
        inventory.namespace_facts(scope.proc, tuple(str(p) for p in scope.guests), inventory.PORTS, inventory.MACS, census)
        baseline.QemuProvider.inspect_flat_qcow2(scope.source)
        scope.template_root.mkdir(mode=0o700)
        namespace_created = True
        evidence = scope.template_root / "evidence"
        evidence.mkdir(mode=0o700)
        namespace_pin = inventory.parent_identity(scope.template_root.lstat())
        evidence_pin = inventory.parent_identity(evidence.lstat())
        evidence_fd = os.open(evidence, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        guard_namespace()
        record_at(evidence_fd, "intent.json", {"correlationId": correlation_id, "source": str(scope.source),
            "sourcePin": pin, "template": str(scope.template_root / "template.qcow2"),
            "guests": [str(p) for p in scope.guests], "nativeGuestStarted": False})
        record_at(evidence_fd, "started.json", {"pid": os.getpid(),
            "startTicks": inventory.process_birth(scope.proc, os.getpid()), "correlationId": correlation_id})
        stage = "write-exclusion"
        lock_evidence = evidence / "scratch-proof"
        lock_evidence.mkdir(mode=0o700)
        prove_write_exclusion(scope, lock_evidence)
        stage = "source-lock"
        source_lock_evidence = evidence / "source-lock"
        source_lock_evidence.mkdir(mode=0o700)
        lock = ReadLock(scope.qemu_io, scope.source, source_lock_evidence).observe()
        close_source(scope, fd, pin, lock, time.monotonic() + 30)
        stage = "copy"
        template = scope.template_root / "template.qcow2"
        guard_namespace()
        # Use the actual shared checked copy primitive, not a fork of its loop.
        baseline.QemuProvider.copy(None, scope.source, template)
        guard_namespace()
        close_source(scope, fd, pin, lock, time.monotonic() + 30)
        guard_namespace()
        baseline.QemuProvider.inspect_flat_qcow2(template)
        template_fd = os.open(template, os.O_RDONLY | os.O_NOFOLLOW)
        copied = inventory.generation(os.fstat(template_fd))
        digest = inventory.hash_source(template_fd, copied[6], time.monotonic() + 240)
        need(digest == pin["sha256"] and copied[6] == pin["generation"][6], "copied-source-hash")
        need(inventory.generation(os.fstat(template_fd)) == copied == inventory.generation(template.lstat()), "copied-generation")
        close_source(scope, fd, pin, lock, time.monotonic() + 30)
        lock.close()
        lock = None
        # Root owns the sealed template; the source user's group can read it
        # for ordinary QEMU use. No permission of the borrowed source changes.
        os.chown(template, os.getuid(), pin["generation"][4])
        template.chmod(0o440)
        os.chown(scope.template_root, os.getuid(), pin["generation"][4])
        scope.template_root.chmod(0o750)
        changed_namespace = inventory.parent_identity(scope.template_root.lstat())
        need(changed_namespace[:2] == namespace_pin[:2], "preparation-namespace-changed")
        namespace_pin = changed_namespace
        guard_namespace()
        sealed = inventory.generation(template.lstat())
        need(sealed[:2] == copied[:2] and sealed[5:8] == copied[5:8], "template-seal-generation")
        stage = "overlays"
        census = close_source(scope, fd, pin, None, time.monotonic() + 30)
        inventory.namespace_facts(scope.proc, tuple(str(p) for p in scope.guests), inventory.PORTS, inventory.MACS, census)
        overlays = []
        def fixed_runner(argv):
            need(argv[:6] == ("qemu-img", "create", "-f", "qcow2", "-F", "qcow2")
                 and argv[6:8] == ("-b", str(template)), "overlay-command")
            result = subprocess.run((scope.qemu_img, *argv[1:]), stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, timeout=30, check=False)
            immutable_write(evidence / ("overlay-" + str(len(overlays)) + ".stdout.private"), result.stdout)
            need(result.returncode == 0, "overlay-create")
        provider = object.__new__(baseline.QemuProvider)
        provider.runner = fixed_runner
        for guest in scope.guests:
            guard_namespace()
            guest.mkdir(mode=0o700)
            guest_fd = os.open(guest, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            guest_fds.append((guest_fd, None))
            overlay = guest / "disk.qcow2"
            provider.overlay(template, overlay)
            result = subprocess.run([scope.qemu_img, "info", "--output=json", str(overlay)],
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=15, check=False)
            immutable_write(evidence / ("overlay-" + str(len(overlays)) + ".info.private"), result.stdout)
            metadata = json.loads(result.stdout)
            need(result.returncode == 0 and metadata.get("format") == "qcow2"
                 and metadata.get("full-backing-filename") == str(template)
                 and metadata.get("backing-filename-format") == "qcow2", "overlay-identity")
            os.chown(overlay, pin["generation"][3], pin["generation"][4])
            overlay.chmod(0o600)
            os.chown(guest, pin["generation"][3], pin["generation"][4])
            guest_pin = inventory.parent_identity(os.fstat(guest_fd))
            guest_fds[-1] = (guest_fd, guest_pin)
            need(guest_pin[3:] == pin["generation"][3:5], "guest-owner")
            overlay_fd = os.open(overlay, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            overlay_fds.append(overlay_fd)
            overlays.append({"path": str(overlay), "generation": inventory.generation(os.fstat(overlay_fd)),
                             "guestGeneration": guest_pin})
        # Native metadata reads finish before the final pure held/named group
        # check, so a later producer cannot invalidate an earlier overlay.
        stage = "overlay-closing"
        for index, row in enumerate(overlays):
            result = subprocess.run([scope.qemu_img, "info", "--output=json", row["path"]],
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=15, check=False)
            immutable_write(evidence / ("overlay-closing-" + str(index) + ".info.private"), result.stdout)
            metadata = json.loads(result.stdout)
            need(result.returncode == 0 and metadata.get("format") == "qcow2"
                 and metadata.get("full-backing-filename") == str(template)
                 and metadata.get("backing-filename-format") == "qcow2", "overlay-closing-backing")
        need(stat.S_IMODE(template.lstat().st_mode) == 0o440 and template.lstat().st_nlink == 1
             and inventory.generation(template.lstat()) == sealed,
             "template-unsealed")
        close_source(scope, fd, pin, None, time.monotonic() + 30)
        guard_namespace()
        close_outputs(scope, template_fd, sealed, overlays, overlay_fds, guest_fds)
        result = {"state": "prepared", "correlationId": correlation_id,
            "template": str(template), "templateSha256": digest, "templateGeneration": sealed,
            "overlays": overlays, "nativeGuestStarted": False, "launchAdmitted": False,
            "productAcceptance": False, "ordinaryQemuReadAccessConfigured": True}
        record_at(evidence_fd, "result.json", result)
        guard_namespace()
        return result
    except BaseException as error:
        if namespace_created and evidence_fd is not None:
            reason = str(error) if isinstance(error, ValueError) and re.fullmatch(r"[a-z-]{1,80}", str(error)) else type(error).__name__
            record_at(evidence_fd, "unknown.json", {"state": "unknown",
                "phase": stage, "reason": reason, "correlationId": correlation_id,
                "nativeGuestStarted": False, "launchAdmitted": False, "productAcceptance": False})
        raise
    finally:
        os.close(fd)
        try:
            if lock is not None:
                lock.close()
        finally:
            if evidence_fd is not None:
                os.close(evidence_fd)
            if template_fd is not None:
                os.close(template_fd)
            for overlay_fd in overlay_fds:
                os.close(overlay_fd)
            for guest_fd, _ in guest_fds:
                os.close(guest_fd)


def remote_program(plan, correlation_id):
    """Fixed exact shared primitives/core, not a second implementation.

    The MCP owner transports this reviewed public source using the authorized
    private sudo input mechanism. No native invocation is performed here.
    """
    need(type(plan) is dict and plan.get("templateRoot") == str(TEMPLATE_ROOT)
         and plan.get("guestRoots") == list(inventory.DESTINATIONS), "plan-scope")
    need(str(uuid.UUID(correlation_id)) == correlation_id, "correlation")
    pin = plan["sourcePin"]
    # The historical source read is a pin, never current live availability.
    source_pin({"sourceGeneration": pin["generation"], "sourceSha256": pin["sha256"],
        "sourceSizeBytes": pin["generation"][6], "sourceParents": pin["parents"],
        "image": {"format": "qcow2", "backingFile": None, "virtualSizeBytes": 96 * 1024 ** 3}})
    imports = "from __future__ import annotations\nfrom dataclasses import dataclass\nfrom pathlib import Path\nfrom types import SimpleNamespace\nimport os,stat,subprocess,time,json,hashlib,re,selectors,uuid\n"
    selected = (inventory.generation, inventory.parent_identity, inventory.parent_pins,
                inventory.verify_source, inventory.process_birth, inventory.holder_census,
                inventory.tcp_conflicts, inventory.namespace_facts, inventory.hash_source)
    constants = {"FIELDS": inventory.FIELDS, "DISK_RESERVE": DISK_RESERVE, "RAW_LIMIT": RAW_LIMIT,
                 "TEMPLATE_ROOT": str(TEMPLATE_ROOT)}
    body = imports + "\n".join(name + "=" + repr(value) for name, value in constants.items()) + "\nTEMPLATE_ROOT=Path(TEMPLATE_ROOT)\n"
    body += inspect.getsource(need) + "\n" + "\n".join(inspect.getsource(fn) for fn in selected)
    body += "\ninventory=SimpleNamespace(" + ",".join(fn.__name__ + "=" + fn.__name__ for fn in selected)
    body += ",SOURCE=" + repr(inventory.SOURCE) + ",SOURCE_ROOT=" + repr(inventory.SOURCE_ROOT)
    body += ",DESTINATIONS=" + repr(inventory.DESTINATIONS) + ",PORTS=" + repr(inventory.PORTS) + ",MACS=" + repr(inventory.MACS) + ")\n"
    body += inspect.getsource(baseline.VmBaselineError) + "\n" + inspect.getsource(baseline._need) + "\n_CHUNK=1048576\n"
    for method in (baseline.QemuProvider.inspect_flat_qcow2, baseline.QemuProvider.copy, baseline.QemuProvider.overlay):
        source = textwrap.dedent(inspect.getsource(method))
        if source.startswith("@staticmethod\n"):
            source = source[len("@staticmethod\n"):]
        body += source + "\n"
    body += "baseline=SimpleNamespace(QemuProvider=type('QemuProvider',(),{'inspect_flat_qcow2':staticmethod(inspect_flat_qcow2),'copy':copy,'overlay':overlay}))\n"
    for obj in (immutable_write, record, record_at, Scope, fixed_scope, source_pin, LockUnknown, ReadLock,
                prove_write_exclusion, close_source, close_outputs, prepare_core):
        body += inspect.getsource(obj) + "\n"
    body += "\nos.environ['PATH']='/usr/bin:/bin'\ntry:\n need(os.geteuid()==0,'privilege-required')\n"
    body += " need(type(inventory.process_birth(Path('/proc'),os.getpid())) is int,'original-job-birth')\n"
    body += " value=prepare_core(fixed_scope()," + repr(pin) + "," + repr(correlation_id) + ")\n"
    body += "except Exception as error:\n value={'state':'unknown','reason':str(error) if isinstance(error,ValueError) and re.fullmatch(r'[a-z-]{1,80}',str(error)) else type(error).__name__,'nativeGuestStarted':False,'launchAdmitted':False,'productAcceptance':False}\nprint(json.dumps(value,sort_keys=True))\n"
    compile(body, "fixed Windows source preparation", "exec")
    return body
